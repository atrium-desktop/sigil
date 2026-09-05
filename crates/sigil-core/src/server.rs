use crate::domain::{Namespace, Purpose, Result, SigilError, Subject};
use crate::service::SigilService;
use sigil_ipc::{check_peer_credentials, read_request, write_response, IpcRequest, IpcResponse};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use tokio::net::{UnixListener, UnixStream};
use tracing::{debug, error, info};
use zeroize::Zeroize;

fn get_systemd_listener() -> Option<UnixListener> {
    if let Ok(pid_str) = std::env::var("LISTEN_PID") {
        if let Ok(pid) = pid_str.parse::<u32>() {
            if pid != std::process::id() {
                return None;
            }
        }
    }
    if let Ok(fds_str) = std::env::var("LISTEN_FDS") {
        if let Ok(fds) = fds_str.parse::<usize>() {
            if fds >= 1 {
                // SD_LISTEN_FDS_START is 3
                let raw_fd = 3;
                unsafe {
                    use std::os::unix::io::FromRawFd;
                    let std_listener = std::os::unix::net::UnixListener::from_raw_fd(raw_fd);
                    std_listener.set_nonblocking(true).ok()?;
                    return UnixListener::from_std(std_listener).ok();
                }
            }
        }
    }
    None
}

pub struct NativeIpcServer {
    socket_path: PathBuf,
    service: SigilService,
}

impl NativeIpcServer {
    pub fn new(socket_path: PathBuf, service: SigilService) -> Self {
        Self {
            socket_path,
            service,
        }
    }

    pub async fn run(self) -> Result<()> {
        let listener = if let Some(l) = get_systemd_listener() {
            info!("Native IPC server adopting systemd socket activation on fd 3");
            l
        } else {
            if let Some(parent) = self.socket_path.parent() {
                if !parent.exists() {
                    fs::create_dir_all(parent)?;
                    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
                }
            }

            if self.socket_path.exists() {
                let _ = fs::remove_file(&self.socket_path);
            }

            let l = UnixListener::bind(&self.socket_path)?;
            fs::set_permissions(&self.socket_path, fs::Permissions::from_mode(0o600))?;
            info!(
                "Native IPC server listening on {}",
                self.socket_path.display()
            );
            l
        };

        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let service = self.service.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, service).await {
                            debug!("IPC connection error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Error accepting IPC connection: {}", e);
                }
            }
        }
    }
}

async fn handle_connection(mut stream: UnixStream, service: SigilService) -> Result<()> {
    if let Err(e) = check_peer_credentials(&stream) {
        let resp = IpcResponse::AccessDenied(e.to_string());
        let _ = write_response(&mut stream, &resp).await;
        return Err(SigilError::AccessDenied(e.to_string()));
    }

    loop {
        let req = match read_request(&mut stream).await {
            Ok(r) => r,
            Err(sigil_ipc::IpcError::Io(ref e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                break;
            }
            Err(e) => return Err(SigilError::InvalidRequest(e.to_string())),
        };

        let resp = match req {
            IpcRequest::Ping => IpcResponse::Success,
            IpcRequest::GetLockStatus => {
                let status = service.lock_state().await;
                IpcResponse::LockStatus(status)
            }
            IpcRequest::Lock => match service.lock().await {
                Ok(_) => IpcResponse::Success,
                Err(e) => IpcResponse::Error(e.to_string()),
            },
            IpcRequest::UnlockWithPassword { mut password } => {
                let res = service.unlock_with_password(&password).await;
                password.zeroize();
                match res {
                    Ok(_) => IpcResponse::Success,
                    Err(SigilError::AuthenticationRequired(ref msg)) if msg.contains("desynchronized") => {
                        IpcResponse::Desynced
                    }
                    Err(e) => IpcResponse::Error(e.to_string()),
                }
            }
            IpcRequest::RotateSlotPassword {
                mut old_password,
                mut new_password,
            } => {
                let res = service.rotate_password(&old_password, &new_password).await;
                old_password.zeroize();
                new_password.zeroize();
                match res {
                    Ok(_) => IpcResponse::Success,
                    Err(e) => IpcResponse::Error(e.to_string()),
                }
            }
            IpcRequest::RecoverAndSyncWithCurrentPassword {
                mut recovery_secret,
                mut new_system_password,
            } => {
                let res = service
                    .recover_and_sync(&recovery_secret, &new_system_password)
                    .await;
                recovery_secret.zeroize();
                new_system_password.zeroize();
                match res {
                    Ok(_) => IpcResponse::Success,
                    Err(e) => IpcResponse::Error(e.to_string()),
                }
            }
            IpcRequest::GetApplicationSecret {
                namespace,
                subject,
                purpose,
            } => {
                match service
                    .derive_app_secret(
                        &Namespace::new(namespace),
                        &Subject::new(subject),
                        &Purpose::new(purpose),
                    )
                    .await
                {
                    Ok(secret) => IpcResponse::Secret(secret.as_slice().to_vec()),
                    Err(SigilError::Locked) => IpcResponse::Locked,
                    Err(e) => IpcResponse::Error(e.to_string()),
                }
            }
        };

        let _ = write_response(&mut stream, &resp).await;
    }

    Ok(())
}
