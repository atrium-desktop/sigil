# Native IPC Protocol Reference

## Overview

The native IPC interface is a private, high-performance, kernel-authenticated transport between `sigil`, desktop platform components (e.g. `xdg-desktop-portal-atrium`), the authentication layer (`pam_sigil.so`), and the user prompt agent (`sigil-prompter`).

## Socket Location & Systemd Activation

- **Default Path**: `$XDG_RUNTIME_DIR/sigil/native.sock` (typically `/run/user/<uid>/sigil/native.sock`)
- **Permissions**: Mode `0600` (strictly restricted to the session user UID)
- **Parent Directory**: Mode `0700`
- **Socket Activation**: Managed by `/usr/lib/systemd/user/sigil.socket`. Connecting to this socket automatically launches `sigil.service` on-demand if not already running, completely eliminating login race conditions.

## Transport & Framing

Communication occurs over a Unix Domain Socket with 4-byte big-endian length-prefixed JSON frames:

```text
+-------------------+-----------------------------------------+
| Length (4 bytes)  | Payload (JSON encoded UTF-8 bytes)      |
| uint32_be         |                                         |
+-------------------+-----------------------------------------+
```

Maximum frame size is bounded to 64 KiB for safety. All buffers handling password payloads implement `zeroize::Zeroize` and are wiped from memory immediately upon transmission or receipt.

## Authentication (SO_PEERCRED)

Upon receiving a connection, the `sigil` daemon queries `getsockopt(..., SOL_SOCKET, SO_PEERCRED, ...)` on Linux:
- The caller's effective UID MUST match the daemon's effective UID.
- In `pam_sigil.so`, system accounts (`uid < 1000`) are bypassed immediately.
- Cross-user connections receive an `AccessDenied` response and are closed immediately.

---

## Protocol Messages

### Requests (`IpcRequest`)

```rust
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum IpcRequest {
    /// Ping the daemon to test connectivity
    Ping,

    /// Query current lock status (Uninitialized, Locked, Unlocked, Desynced)
    GetLockStatus,

    /// Explicitly lock the vault and zeroize in-memory keys
    Lock,

    /// Unlock the vault using a password provided over IPC.
    /// If the vault is uninitialized, the daemon performs zero-touch
    /// auto-provisioning, creating the vault and transitioning to Unlocked.
    UnlockWithPassword {
        password: String,
    },

    /// Rotate the primary password slot (Slot 0) when the user modifies their OS password.
    /// Invoked transparently by pam_sigil.so during pam_sm_chauthtok.
    RotateSlotPassword {
        old_password: String,
        new_password: String,
    },

    /// Self-healing re-synchronization invoked after an out-of-band/admin password reset.
    /// Unwraps the VolumeKey using a known recovery secret or previous password,
    /// then rewrenches Slot 0 with the user's current session password.
    RecoverAndSyncWithCurrentPassword {
        recovery_secret: String,
        new_system_password: String,
    },

    /// Retrieve / derive an application-scoped secret (used by XDG Desktop Portal)
    GetApplicationSecret {
        namespace: String,
        subject: String,
        purpose: String,
    },
}
```

### Responses (`IpcResponse`)

```rust
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum IpcResponse {
    /// Operation succeeded without payload
    Success,

    /// Current lock status
    LockStatus(LockState),

    /// 32-byte derived secret payload
    Secret(Vec<u8>),

    /// Operation failed because the service is locked
    Locked,

    /// Operation failed because system password has desynchronized
    Desynced,

    /// Operation cancelled by user or prompt timeout
    Cancelled,

    /// Access denied (caller UID mismatch or permission issue)
    AccessDenied(String),

    /// Internal error or invalid argument
    Error(String),
}
```

---

## Lock States (`LockState`)

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LockState {
    /// Vault files do not exist yet. UnlockWithPassword will auto-provision.
    Uninitialized,

    /// Vault is sealed. VolumeKey is zeroized in memory.
    Locked,

    /// Vault is active and VolumeKey is loaded in secure memory.
    Unlocked,

    /// System password was changed out-of-band (e.g. admin reset).
    /// Vault requires recovery verification to re-synchronize Slot 0.
    Desynced,
}
```
