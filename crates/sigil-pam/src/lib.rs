use pamsm::{pam_module, Pam, PamError, PamFlag, PamLibExt, PamServiceModule};
use sigil_ipc::{read_response_sync, write_request_sync, IpcRequest};
use std::ffi::{CStr, CString};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;
use zeroize::Zeroize;

struct SigilPam;

/// Minimum non-system UID per distribution standard.
const UID_MIN: u32 = 1000;
const NOBODY_UID: u32 = 65534;

/// Retrieves the target UID from the PAM context, filtering out system accounts.
/// Uses thread-safe getpwnam_r to guarantee safety in multi-threaded PAM environments.
fn get_target_uid(pamh: &Pam) -> Option<u32> {
    let user = match pamh.get_cached_user() {
        Ok(Some(u)) => u.to_string_lossy().into_owned(),
        _ => return None,
    };

    let c_user = CString::new(user).ok()?;

    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let mut buf = vec![0 as libc::c_char; 2048];

    let ret = unsafe {
        libc::getpwnam_r(
            c_user.as_ptr(),
            &mut pwd,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };

    if ret != 0 || result.is_null() {
        return None;
    }

    let uid = pwd.pw_uid;

    // Strict system account filter
    if uid < UID_MIN || uid == NOBODY_UID {
        return None;
    }

    Some(uid)
}

/// Emits an audit message to the system authentication syslog facility.
fn log_pam(msg: &str) {
    if let Ok(c_msg) = CString::new(format!("pam_sigil: {}", msg)) {
        unsafe {
            libc::syslog(
                libc::LOG_AUTH | libc::LOG_INFO,
                c"%s".as_ptr(),
                c_msg.as_ptr(),
            );
        }
    }
}

/// Connects to the user's sigil native socket. If `wait` is true, polls with backoff
/// to accommodate user session socket creation during cold boot or first login.
fn connect_to_socket(uid: u32, wait: bool) -> Option<UnixStream> {
    let socket_path = PathBuf::from(format!("/run/user/{}/sigil/native.sock", uid));
    let timeout = if wait {
        Duration::from_millis(2500)
    } else {
        Duration::ZERO
    };
    let start = std::time::Instant::now();

    loop {
        if socket_path.exists() {
            if let Ok(stream) = UnixStream::connect(&socket_path) {
                let _ = stream.set_read_timeout(Some(Duration::from_millis(3000)));
                let _ = stream.set_write_timeout(Some(Duration::from_millis(3000)));
                return Some(stream);
            }
        }
        if start.elapsed() >= timeout {
            return None;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// Stashes the authenticated password in the PAM handle data context so that
/// downstream hooks (such as `open_session` or `setcred`) can retrieve it even
/// if intermediate modules or display managers clear `PAM_AUTHTOK`.
fn stash_password_if_present(pamh: &Pam) {
    if let Ok(Some(tok)) = pamh.get_cached_authtok() {
        let bytes = tok.to_bytes_with_nul().to_vec();
        let _ = pamh.send_bytes("sigil_authtok", bytes, None);
    }
}

/// Retrieves the plaintext authentication token either directly from PAM cached authtok
/// or from our cross-hook PAM handle stash.
fn get_target_password(pamh: &Pam) -> Option<String> {
    if let Ok(Some(tok)) = pamh.get_cached_authtok() {
        let s = tok.to_string_lossy().into_owned();
        if !s.is_empty() {
            return Some(s);
        }
    }
    if let Ok(bytes) = pamh.retrieve_bytes("sigil_authtok") {
        if let Ok(cstr) = CStr::from_bytes_until_nul(&bytes) {
            let s = cstr.to_string_lossy().into_owned();
            if !s.is_empty() {
                return Some(s);
            }
        }
    }
    None
}

/// Attempts to unlock the sigil vault by sending the password directly to the
/// daemon's native Unix domain socket in volatile memory.
fn unlock_via_socket(pamh: &Pam, wait: bool) -> PamError {
    let uid = match get_target_uid(pamh) {
        Some(u) => u,
        None => return PamError::SUCCESS,
    };

    let mut authtok = match get_target_password(pamh) {
        Some(tok) => tok,
        None => return PamError::SUCCESS,
    };

    let mut stream = match connect_to_socket(uid, wait) {
        Some(s) => s,
        None => {
            if wait {
                log_pam(&format!("timed out waiting for native socket for uid {}", uid));
            }
            authtok.zeroize();
            return PamError::SUCCESS;
        }
    };

    let req = IpcRequest::UnlockWithPassword {
        password: authtok.clone(),
    };
    authtok.zeroize();

    if write_request_sync(&mut stream, &req).is_ok() {
        if let Ok(resp) = read_response_sync(&mut stream) {
            match resp {
                sigil_ipc::IpcResponse::Success => {
                    log_pam(&format!("vault transparently unlocked for uid {}", uid));
                }
                sigil_ipc::IpcResponse::Desynced => {
                    log_pam(&format!("vault credentials desynchronized for uid {}", uid));
                }
                other => {
                    log_pam(&format!("vault unlock response: {:?} for uid {}", other, uid));
                }
            }
        }
    }

    PamError::SUCCESS
}

/// Cascades password changes to the sigil vault over the native socket during chauthtok.
fn rekey_via_socket(pamh: &Pam) -> PamError {
    let uid = match get_target_uid(pamh) {
        Some(u) => u,
        None => return PamError::SUCCESS,
    };

    let mut old_authtok = match pamh.get_cached_oldauthtok() {
        Ok(Some(tok)) => tok.to_string_lossy().into_owned(),
        _ => String::new(),
    };

    let mut new_authtok = match pamh.get_cached_authtok() {
        Ok(Some(tok)) => tok.to_string_lossy().into_owned(),
        _ => String::new(),
    };

    if new_authtok.is_empty() {
        old_authtok.zeroize();
        new_authtok.zeroize();
        return PamError::SUCCESS;
    }

    let mut stream = match connect_to_socket(uid, true) {
        Some(s) => s,
        None => {
            log_pam(&format!("chauthtok: timed out waiting for socket for uid {}", uid));
            old_authtok.zeroize();
            new_authtok.zeroize();
            return PamError::SUCCESS;
        }
    };

    if !old_authtok.is_empty() {
        let req = IpcRequest::RotateSlotPassword {
            old_password: old_authtok.clone(),
            new_password: new_authtok.clone(),
        };
        old_authtok.zeroize();
        new_authtok.zeroize();

        if write_request_sync(&mut stream, &req).is_ok() {
            if let Ok(resp) = read_response_sync(&mut stream) {
                log_pam(&format!("chauthtok: slot rotation result: {:?} for uid {}", resp, uid));
            }
        }
    } else {
        // Old password not provided (e.g. root changed password via `sudo passwd`)
        old_authtok.zeroize();
        new_authtok.zeroize();
    }

    PamError::SUCCESS
}

impl PamServiceModule for SigilPam {
    fn authenticate(pamh: Pam, _flags: PamFlag, _args: Vec<String>) -> PamError {
        stash_password_if_present(&pamh);
        // Fast path: if the user session/daemon is already active (e.g. screen locker), unlock immediately
        unlock_via_socket(&pamh, false);
        PamError::SUCCESS
    }

    fn setcred(pamh: Pam, flags: PamFlag, _args: Vec<String>) -> PamError {
        match flags {
            PamFlag::DELETE_CRED => {}
            _ => {
                // Screen lockers (e.g. tessera-lock) commit credentials via pam_setcred
                unlock_via_socket(&pamh, false);
            }
        }
        PamError::SUCCESS
    }

    fn open_session(pamh: Pam, _flags: PamFlag, _args: Vec<String>) -> PamError {
        // Cold-boot login: pam_systemd has just set up /run/user/<uid>, wait for socket activation
        unlock_via_socket(&pamh, true);
        PamError::SUCCESS
    }

    fn close_session(_pamh: Pam, _flags: PamFlag, _args: Vec<String>) -> PamError {
        PamError::SUCCESS
    }

    fn chauthtok(pamh: Pam, _flags: PamFlag, _args: Vec<String>) -> PamError {
        rekey_via_socket(&pamh);
        PamError::SUCCESS
    }
}

pam_module!(SigilPam);
