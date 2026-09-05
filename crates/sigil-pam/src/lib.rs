use pamsm::{pam_module, Pam, PamError, PamFlag, PamLibExt, PamServiceModule};
use sigil_ipc::{read_response_sync, write_request_sync, IpcRequest};
use std::ffi::CString;
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

/// Connects to the user's sigil native socket with a safety timeout.
fn connect_to_socket(uid: u32) -> Option<UnixStream> {
    let socket_path = PathBuf::from(format!("/run/user/{}/sigil/native.sock", uid));
    if !socket_path.exists() {
        return None;
    }

    let stream = UnixStream::connect(&socket_path).ok()?;
    let _ = stream.set_read_timeout(Some(Duration::from_millis(3000)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(3000)));
    Some(stream)
}

/// Attempts to unlock the sigil vault by sending the password directly to the
/// daemon's native Unix domain socket in volatile memory.
fn unlock_via_socket(pamh: &Pam) -> PamError {
    let uid = match get_target_uid(pamh) {
        Some(u) => u,
        None => return PamError::SUCCESS,
    };

    let mut authtok = match pamh.get_cached_authtok() {
        Ok(Some(tok)) => tok.to_string_lossy().into_owned(),
        _ => return PamError::SUCCESS,
    };

    if authtok.is_empty() {
        authtok.zeroize();
        return PamError::SUCCESS;
    }

    let mut stream = match connect_to_socket(uid) {
        Some(s) => s,
        None => {
            authtok.zeroize();
            return PamError::SUCCESS;
        }
    };

    let req = IpcRequest::UnlockWithPassword {
        password: authtok.clone(),
    };
    authtok.zeroize();

    if write_request_sync(&mut stream, &req).is_ok() {
        let _ = read_response_sync(&mut stream);
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

    let mut stream = match connect_to_socket(uid) {
        Some(s) => s,
        None => {
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
            let _ = read_response_sync(&mut stream);
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
        unlock_via_socket(&pamh);
        PamError::SUCCESS
    }

    fn setcred(pamh: Pam, flags: PamFlag, _args: Vec<String>) -> PamError {
        match flags {
            PamFlag::DELETE_CRED => {}
            _ => {
                unlock_via_socket(&pamh);
            }
        }
        PamError::SUCCESS
    }

    fn open_session(pamh: Pam, _flags: PamFlag, _args: Vec<String>) -> PamError {
        unlock_via_socket(&pamh);
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
