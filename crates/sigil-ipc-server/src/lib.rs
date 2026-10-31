use sigil_ipc::{check_peer_credentials, read_request, write_response, IpcRequest, IpcResponse};
use sigil_vault::{Namespace, Purpose, Result, SigilError, SigilService, Subject};
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
            Err(sigil_ipc::IpcError::Io(ref e))
                if e.kind() == std::io::ErrorKind::UnexpectedEof =>
            {
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
                    Err(SigilError::AuthenticationRequired(ref msg))
                        if msg.contains("desynchronized") =>
                    {
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
            IpcRequest::EnrollRecoveryKey { mut recovery_key } => {
                let res = service.enroll_recovery_key(&recovery_key).await;
                recovery_key.zeroize();
                match res {
                    Ok(_) => IpcResponse::Success,
                    Err(SigilError::Locked) => IpcResponse::Locked,
                    Err(e) => IpcResponse::Error(e.to_string()),
                }
            }
            IpcRequest::UnlockWithRecoveryKey { mut recovery_key } => {
                let res = service.unlock_with_recovery_key(&recovery_key).await;
                recovery_key.zeroize();
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
                    Ok(secret) => IpcResponse::Secret(secret),
                    Err(SigilError::Locked) => IpcResponse::Locked,
                    Err(e) => IpcResponse::Error(e.to_string()),
                }
            }
        };

        let _ = write_response(&mut stream, &resp).await;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_ipc::{read_response, write_request, IpcRequest, IpcResponse};
    use sigil_vault::{FileVaultStore, LockState, SigilService};
    use tokio::net::UnixStream;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_native_ipc_server_flow() {
        let temp_dir =
            std::env::temp_dir().join(format!("sigil_ipc_server_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);

        let sock_path = temp_dir.join("native.sock");
        let store = FileVaultStore::new(temp_dir.clone());
        store.initialize_with_password("test-pass").unwrap();
        let service = SigilService::new(store.clone());
        service.unlock_with_password("test-pass").await.unwrap();

        let server = NativeIpcServer::new(sock_path.clone(), service.clone());
        tokio::spawn(async move {
            let _ = server.run().await;
        });

        // Wait for socket to be ready
        for _ in 0..50 {
            if sock_path.exists() {
                break;
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }

        let mut stream = UnixStream::connect(&sock_path).await.unwrap();

        // Ping
        write_request(&mut stream, &IpcRequest::Ping).await.unwrap();
        let resp = read_response(&mut stream).await.unwrap();
        assert!(matches!(resp, IpcResponse::Success));

        // GetLockStatus
        write_request(&mut stream, &IpcRequest::GetLockStatus)
            .await
            .unwrap();
        let resp = read_response(&mut stream).await.unwrap();
        assert!(matches!(resp, IpcResponse::LockStatus(LockState::Unlocked)));

        // GetApplicationSecret
        write_request(
            &mut stream,
            &IpcRequest::GetApplicationSecret {
                namespace: "atrium.portal.Secret/v1".into(),
                subject: "org.mozilla.Firefox".into(),
                purpose: "master-secret".into(),
            },
        )
        .await
        .unwrap();
        let resp = read_response(&mut stream).await.unwrap();
        assert!(matches!(resp, IpcResponse::Secret(_)));

        // Lock
        write_request(&mut stream, &IpcRequest::Lock).await.unwrap();
        let resp = read_response(&mut stream).await.unwrap();
        assert!(matches!(resp, IpcResponse::Success));

        // GetLockStatus -> Locked
        write_request(&mut stream, &IpcRequest::GetLockStatus)
            .await
            .unwrap();
        let resp = read_response(&mut stream).await.unwrap();
        assert!(matches!(resp, IpcResponse::LockStatus(LockState::Locked)));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
