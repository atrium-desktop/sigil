use crate::error::{IpcError, IpcResult};
use std::os::unix::io::AsRawFd;

/// Checks that the peer connected to the Unix socket belongs to the same UID.
#[cfg(target_os = "linux")]
pub fn check_peer_credentials<S: AsRawFd>(stream: &S) -> IpcResult<()> {
    let fd = stream.as_raw_fd();
    let mut ucred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;

    let res = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut ucred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };

    if res != 0 {
        return Err(IpcError::AccessDenied(
            "Failed to retrieve SO_PEERCRED from socket".into(),
        ));
    }

    let my_uid = unsafe { libc::getuid() };
    // Allowed peer credentials:
    // 1. Same user (ucred.uid == my_uid): Standard intra-user IPC.
    // 2. Root (ucred.uid == 0): Display managers, login, and PAM modules (greetd, sddm, login)
    //    executing pam_sigil on behalf of the user during session lifecycle events.
    if ucred.uid != my_uid && ucred.uid != 0 {
        return Err(IpcError::AccessDenied(format!(
            "Peer UID {} does not match daemon UID {} (and is not root)",
            ucred.uid, my_uid
        )));
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn check_peer_credentials<S: AsRawFd>(_stream: &S) -> IpcResult<()> {
    Ok(())
}
