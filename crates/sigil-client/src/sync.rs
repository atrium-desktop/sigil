use crate::error::{ClientError, Result};
use sigil_ipc::{
    default_socket_path, read_response_sync, socket_path_for_uid, write_request_sync, IpcRequest,
    IpcResponse, LockState, SecretBytes,
};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct SigilSyncClient {
    socket_path: PathBuf,
}

impl SigilSyncClient {
    /// Creates a synchronous client targeting the specified socket path.
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    /// Creates a client connecting to the default `$XDG_RUNTIME_DIR/sigil/native.sock`.
    pub fn connect_default() -> Self {
        Self::new(default_socket_path())
    }

    /// Creates a client connecting to `/run/user/<uid>/sigil/native.sock`.
    pub fn connect_for_uid(uid: u32) -> Self {
        Self::new(socket_path_for_uid(uid))
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    fn open_stream(&self) -> Result<UnixStream> {
        UnixStream::connect(&self.socket_path)
            .map_err(|e| ClientError::ConnectionFailed(self.socket_path.clone(), e))
    }

    /// Pings the sigil daemon.
    pub fn ping(&self) -> Result<()> {
        let mut stream = self.open_stream()?;
        write_request_sync(&mut stream, &IpcRequest::Ping)?;
        match read_response_sync(&mut stream)? {
            IpcResponse::Success => Ok(()),
            IpcResponse::Error(e) => Err(ClientError::DaemonError(e)),
            IpcResponse::AccessDenied(e) => Err(ClientError::AccessDenied(e)),
            other => Err(ClientError::DaemonError(format!(
                "Unexpected response: {:?}",
                other
            ))),
        }
    }

    /// Queries the current lock status of the credential service.
    pub fn get_lock_status(&self) -> Result<LockState> {
        let mut stream = self.open_stream()?;
        write_request_sync(&mut stream, &IpcRequest::GetLockStatus)?;
        match read_response_sync(&mut stream)? {
            IpcResponse::LockStatus(status) => Ok(status),
            IpcResponse::Error(e) => Err(ClientError::DaemonError(e)),
            IpcResponse::AccessDenied(e) => Err(ClientError::AccessDenied(e)),
            other => Err(ClientError::DaemonError(format!(
                "Unexpected response: {:?}",
                other
            ))),
        }
    }

    /// Checks if the credential service is locked.
    pub fn is_locked(&self) -> Result<bool> {
        let status = self.get_lock_status()?;
        Ok(status != LockState::Unlocked)
    }

    /// Retrieves / derives an application secret for a specific namespace, subject, and purpose.
    pub fn get_application_secret(
        &self,
        namespace: &str,
        subject: &str,
        purpose: &str,
    ) -> Result<SecretBytes> {
        let mut stream = self.open_stream()?;
        let req = IpcRequest::GetApplicationSecret {
            namespace: namespace.to_string(),
            subject: subject.to_string(),
            purpose: purpose.to_string(),
        };

        write_request_sync(&mut stream, &req)?;
        match read_response_sync(&mut stream)? {
            IpcResponse::Secret(secret) => Ok(secret),
            IpcResponse::Locked => Err(ClientError::Locked),
            IpcResponse::Cancelled => Err(ClientError::Cancelled),
            IpcResponse::AccessDenied(e) => Err(ClientError::AccessDenied(e)),
            IpcResponse::Error(e) => Err(ClientError::DaemonError(e)),
            other => Err(ClientError::DaemonError(format!(
                "Unexpected response: {:?}",
                other
            ))),
        }
    }

    /// Locks the credential service.
    pub fn lock(&self) -> Result<()> {
        let mut stream = self.open_stream()?;
        write_request_sync(&mut stream, &IpcRequest::Lock)?;
        match read_response_sync(&mut stream)? {
            IpcResponse::Success => Ok(()),
            IpcResponse::Error(e) => Err(ClientError::DaemonError(e)),
            IpcResponse::AccessDenied(e) => Err(ClientError::AccessDenied(e)),
            other => Err(ClientError::DaemonError(format!(
                "Unexpected response: {:?}",
                other
            ))),
        }
    }

    /// Unlocks the credential service with a password over secure native IPC.
    pub fn unlock_with_password(&self, password: &str) -> Result<()> {
        let mut stream = self.open_stream()?;
        write_request_sync(
            &mut stream,
            &IpcRequest::UnlockWithPassword {
                password: password.to_string(),
            },
        )?;
        match read_response_sync(&mut stream)? {
            IpcResponse::Success => Ok(()),
            IpcResponse::Desynced => Err(ClientError::Desynced),
            IpcResponse::Error(e) => Err(ClientError::DaemonError(e)),
            IpcResponse::AccessDenied(e) => Err(ClientError::AccessDenied(e)),
            other => Err(ClientError::DaemonError(format!(
                "Unexpected response: {:?}",
                other
            ))),
        }
    }

    /// Rotates the primary password slot (Slot 0) during password change.
    pub fn rotate_password(&self, old_password: &str, new_password: &str) -> Result<()> {
        let mut stream = self.open_stream()?;
        write_request_sync(
            &mut stream,
            &IpcRequest::RotateSlotPassword {
                old_password: old_password.to_string(),
                new_password: new_password.to_string(),
            },
        )?;
        match read_response_sync(&mut stream)? {
            IpcResponse::Success => Ok(()),
            IpcResponse::Error(e) => Err(ClientError::DaemonError(e)),
            IpcResponse::AccessDenied(e) => Err(ClientError::AccessDenied(e)),
            other => Err(ClientError::DaemonError(format!(
                "Unexpected response: {:?}",
                other
            ))),
        }
    }

    /// Recovers and re-synchronizes the vault using a recovery secret and the current session password.
    pub fn recover_and_sync(&self, recovery_secret: &str, new_system_password: &str) -> Result<()> {
        let mut stream = self.open_stream()?;
        write_request_sync(
            &mut stream,
            &IpcRequest::RecoverAndSyncWithCurrentPassword {
                recovery_secret: recovery_secret.to_string(),
                new_system_password: new_system_password.to_string(),
            },
        )?;
        match read_response_sync(&mut stream)? {
            IpcResponse::Success => Ok(()),
            IpcResponse::Error(e) => Err(ClientError::DaemonError(e)),
            IpcResponse::AccessDenied(e) => Err(ClientError::AccessDenied(e)),
            other => Err(ClientError::DaemonError(format!(
                "Unexpected response: {:?}",
                other
            ))),
        }
    }

    /// Enrolls an emergency recovery key into Slot 1 while the vault is unlocked.
    pub fn enroll_recovery_key(&self, recovery_key: &str) -> Result<()> {
        let mut stream = self.open_stream()?;
        write_request_sync(
            &mut stream,
            &IpcRequest::EnrollRecoveryKey {
                recovery_key: recovery_key.to_string(),
            },
        )?;
        match read_response_sync(&mut stream)? {
            IpcResponse::Success => Ok(()),
            IpcResponse::Locked => Err(ClientError::Locked),
            IpcResponse::Error(e) => Err(ClientError::DaemonError(e)),
            IpcResponse::AccessDenied(e) => Err(ClientError::AccessDenied(e)),
            other => Err(ClientError::DaemonError(format!(
                "Unexpected response: {:?}",
                other
            ))),
        }
    }

    /// Unlocks the vault using the emergency recovery key from Slot 1.
    pub fn unlock_with_recovery_key(&self, recovery_key: &str) -> Result<()> {
        let mut stream = self.open_stream()?;
        write_request_sync(
            &mut stream,
            &IpcRequest::UnlockWithRecoveryKey {
                recovery_key: recovery_key.to_string(),
            },
        )?;
        match read_response_sync(&mut stream)? {
            IpcResponse::Success => Ok(()),
            IpcResponse::Error(e) => Err(ClientError::DaemonError(e)),
            IpcResponse::AccessDenied(e) => Err(ClientError::AccessDenied(e)),
            other => Err(ClientError::DaemonError(format!(
                "Unexpected response: {:?}",
                other
            ))),
        }
    }
}
