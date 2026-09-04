use pamsm::{pam_module, Pam, PamError, PamFlag, PamLibExt, PamServiceModule};
use sigil_ipc::{read_response_sync, write_request_sync, IpcRequest};
use std::ffi::CString;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;
use zeroize::Zeroize;

struct SigilPam;

/// Attempts to unlock the sigil vault by sending the password directly to the
/// daemon's native Unix domain socket in memory.
///
/// Under no circumstances does this function write passwords to the filesystem.
/// All memory buffers containing authentication tokens are zeroized upon completion.
fn unlock_via_socket(pamh: &Pam) -> PamError {
    let user = match pamh.get_cached_user() {
        Ok(Some(u)) => u.to_string_lossy().into_owned(),
        _ => return PamError::SUCCESS,
    };

    let mut authtok = match pamh.get_cached_authtok() {
        Ok(Some(tok)) => tok.to_string_lossy().into_owned(),
        _ => return PamError::SUCCESS,
    };

    if authtok.is_empty() {
        authtok.zeroize();
        return PamError::SUCCESS;
    }

    let c_user = match CString::new(user) {
        Ok(c) => c,
        Err(_) => {
            authtok.zeroize();
            return PamError::SUCCESS;
        }
    };

    let passwd = unsafe { libc::getpwnam(c_user.as_ptr()) };
    if passwd.is_null() {
        authtok.zeroize();
        return PamError::SUCCESS;
    }

    let uid = unsafe { (*passwd).pw_uid };

    // Native IPC socket path: /run/user/<uid>/sigil/native.sock
    let socket_path = PathBuf::from(format!("/run/user/{}/sigil/native.sock", uid));

    if !socket_path.exists() {
        authtok.zeroize();
        return PamError::SUCCESS;
    }

    let mut stream = match UnixStream::connect(&socket_path) {
        Ok(s) => s,
        Err(_) => {
            authtok.zeroize();
            return PamError::SUCCESS;
        }
    };

    // Protect against blocking PAM login if daemon is busy/slow
    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));

    let req = IpcRequest::UnlockWithPassword {
        password: authtok.clone(),
    };
    authtok.zeroize();

    if write_request_sync(&mut stream, &req).is_ok() {
        let _ = read_response_sync(&mut stream);
    }

    PamError::SUCCESS
}

impl PamServiceModule for SigilPam {
    fn authenticate(pamh: Pam, _flags: PamFlag, _args: Vec<String>) -> PamError {
        // Screensavers (e.g. swaylock) perform authentication to unlock screen.
        // We attempt direct socket unlock here.
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
}

pam_module!(SigilPam);
