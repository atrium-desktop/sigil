use serde::{Deserialize, Serialize};
pub use sigil_types::{LockState, PromptResponse, SecretBytes};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Enrolls an emergency recovery key into Slot 1 while the vault is unlocked.
    EnrollRecoveryKey { recovery_key: String },
    /// Unlocks the vault using the emergency recovery key from Slot 1.
    UnlockWithRecoveryKey { recovery_key: String },
    /// Ping the daemon to test connectivity
    Ping,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
