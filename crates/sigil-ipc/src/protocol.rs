use serde::{Deserialize, Serialize};
use std::fmt;
use std::ops::Deref;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Protected secret-bearing memory container.
///
/// Implements `Zeroize` and `ZeroizeOnDrop` so secret bytes are zeroed out when dropped.
/// Explicitly avoids leaking contents in `Debug` and `Display` formatters.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn from_slice(slice: &[u8]) -> Self {
        Self(slice.to_vec())
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn expose_secret(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for SecretBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes([redacted; {} bytes])", self.0.len())
    }
}

impl fmt::Display for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[redacted; {} bytes]", self.0.len())
    }
}

/// Service lock state on wire protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LockState {
    Uninitialized,
    Locked,
    Unlocked,
    Desynced,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PromptResponse {
    pub password: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum IpcRequest {
    /// Retrieve/derive an application secret for a given namespace, subject, and purpose
    GetApplicationSecret {
        namespace: String,
        subject: String,
        purpose: String,
    },
    /// Query the current lock status of the credential service
    GetLockStatus,
    /// Lock the vault, clearing in-memory keys
    Lock,
    /// Unlock the vault using a password provided over IPC (e.g. from PAM or prompter).
    /// If the vault is uninitialized, performs zero-touch automated provisioning.
    UnlockWithPassword { password: String },
    /// Rotate the primary password slot (Slot 0) when the user modifies their OS password.
    RotateSlotPassword {
        old_password: String,
        new_password: String,
    },
    /// Self-healing re-synchronization invoked after an out-of-band/admin password reset.
    RecoverAndSyncWithCurrentPassword {
        recovery_secret: String,
        new_system_password: String,
    },
    /// Ping the daemon to test connectivity
    Ping,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum IpcResponse {
    /// Success with raw 32-byte secret payload protected by ZeroizeOnDrop
    Secret(SecretBytes),
    /// Current lock state
    LockStatus(LockState),
    /// Operation succeeded without payload
    Success,
    /// Operation failed because the service is locked
    Locked,
    /// Operation failed because the vault credentials are desynchronized
    Desynced,
    /// Operation cancelled by user or timeout
    Cancelled,
    /// Access denied (caller UID mismatch or permission issue)
    AccessDenied(String),
    /// Internal error or invalid argument
    Error(String),
}
