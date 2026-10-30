# Subsystem Architecture: Sigil System Blueprint

- Status: Living Blueprint
- Scope: workspace/topology, architecture/subsystems, security/memory, lifecycle/pam
- Maintainers: Sigil Architecture & Security Working Group

---

## 1. System Overview & Monorepo Topology

`sigil` is a secure, industrial-grade desktop session credential infrastructure daemon implemented in Rust.
It unifies two distinct desktop security paradigms:
1. **Host Collaboration**: Full freedesktop.org `org.freedesktop.secrets` Secret Service API compatibility for native desktop applications (browsers, Git credential helpers, developer tools).
2. **Zero-Trust Sandboxing**: Isolated mathematical secret derivation for sandboxed applications via `org.freedesktop.portal.Secret` (Flatpak, Snap).

```text
                      Native Desktop Applications                 Sandboxed Flatpak / Snap Apps
                                │                                                │
                                ▼                                                ▼
                     org.freedesktop.secrets                           org.freedesktop.portal.Secret
                                │                                                │
                                ▼                                                ▼
                  ┌───────────────────────────┐                         xdg-desktop-portal
                  │           sigil           │                                  │
                  │                           │                                  ▼
                  │  Secret Service adapter   │                         xdg-desktop-portal-atrium
                  │             │             │                                  │
                  │             ▼             │                                  ▼ (sigil-client)
                  │        sigil-core         │                       Unix Domain Socket (SO_PEERCRED)
                  │  (crypto / store / state) │                       /run/user/<uid>/sigil/native.sock
                  │             │             │                                  │
                  │             ▼             │◄─────────────────────────────────┤
                  │  native IPC server/socket │◄─── pam_sigil.so (login/lock/chauthtok)
                  └─────────────┬─────────────┘
                                │
                                ▼
                     systemd-logind system bus
                     (Lock & Active=false signals)
```

---

## 2. Crate Decomposition & Responsibilities

The workspace is organized into seven specialized crates across four concentric layers:

```text
sigil/
├── Cargo.toml
├── Cargo.lock
│
├── crates/
│   ├── sigil-core/           # Unified engine: domain models, crypto primitives, envelope store, state machine & IPC server
│   ├── sigil-ipc/            # Lightweight, decoupled wire protocol, framing codecs & peer credential checks
│   ├── sigil-client/         # Async Rust SDK for desktop components (portal backend, prompter)
│   ├── sigil-secret-service/ # D-Bus org.freedesktop.secrets protocol adapter
│   ├── sigil/                # Daemon assembly, process hardening, logind listener
│   ├── sigil-prompter/       # Native prompt agent for emergency recovery and unlock dialogs (via Optics)
│   └── sigil-pam/            # Hardened, zero-disk, zero-crypto-dependency PAM module
```

### `crates/sigil-core` (Layer 2)
The core engine and persistence layer:
- **`crypto`**: XChaCha20-Poly1305 AEAD symmetric encryption, Argon2id KDF for password derivation, clean-break HKDF-SHA256 for domain-separated subkeys, and Diffie-Hellman 1024-bit session key negotiation.
- **`store`**: Envelope Multi-Slot Storage (v2 format). The encrypted vault payload is protected by a 256-bit `VolumeKey` stored in independent envelope key slots (`vault.meta`, `vault.slots/`, `vault.data`). Updates are atomic using atomic file rename semantics.
- **`service`**: Thread-safe daemon state machine (`Unlocked`, `Locked`, `Uninitialized`). Manages key eviction, auto-provisioning, password rotation, and collection/item CRUD operations.
- **`server`**: `NativeIpcServer` hosting the Unix domain socket endpoint at `/run/user/<uid>/sigil/native.sock`.

### `crates/sigil-ipc` (Layer 1)
Lightweight wire framing and IPC codecs:
- **Wire Codecs**: Zero-allocation binary framing (`sigil-wire-v2`) with 4-byte length prefix.
- **Security Primitives**: Kernel-level `SO_PEERCRED` extraction verifying peer PID, UID, and GID. Enforces that only matching UID callers access the socket.
- **Payloads**: Request and response enumerations covering Ping, Status, Unlock, Lock, DerivePortalSecret, and RotatePassword.

### `crates/sigil-client` (Layer 3)
Async Rust client library:
- Connects to `/run/user/<uid>/sigil/native.sock`.
- Provides idiomatic async methods for desktop services and portals (`derive_portal_secret`, `query_status`, `unlock`).

### `crates/sigil-secret-service` (Layer 3)
Secret Service D-Bus adapter:
- Implements freedesktop.org Secret Service specification over `zbus`.
- Translates D-Bus object paths (`/org/freedesktop/secrets/collection/...`) and method calls into `sigil-core` operations.
- Handles standard session negotiation (Plain and DH-AES algorithms).

### `crates/sigil` (Layer 4)
The host daemon binary:
- **Process Hardening**: Explicitly disables core dumps and ptrace attachments (`PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`).
- **Lifecycle Integration**: Subscribes to `org.freedesktop.login1` signals (`Session.Lock` and `Active=false`) to instantly zeroize master keys upon lock or fast user switching.
- **Startup Coordination**: Listens on systemd user socket activation (`sigil.socket`).

### `crates/sigil-prompter` (Layer 4)
Interactive dialog agent:
- Rendered using companion GUI engine **Optics** (`flux`, `iris`, `lens`).
- Invoked when user input is required in GUI sessions (e.g., initial master passphrase entry or recovery unlock).

### `crates/sigil-pam` (Layer 4)
Pluggable Authentication Module (`pam_sigil.so`):
- **Zero-Disk, Zero-Crypto**: Contains no cryptographic libraries and never touches disk.
- **Authentication**: Bypasses system accounts (`uid < 1000`). Passes login passphrase directly over the Unix socket in memory.
- **Auto-Provisioning**: On first login, triggers zero-friction initial vault generation.
- **Password Rotation**: During `pam_sm_chauthtok`, captures old and new passphrases to execute an $O(1)$ envelope slot rotation.

---

## 3. Data Flow & Security Lifecycles

### 3.1 First-Use Auto-Provisioning
1. User logs in via display manager (GDM, SDDM, greetd).
2. `pam_sigil.so` receives authentication token in `pam_sm_authenticate`.
3. PAM forwards token to `/run/user/<uid>/sigil/native.sock`.
4. If daemon state is `Uninitialized`, `sigil-core` generates a cryptographically random 256-bit `VolumeKey`, wraps it with the user's login password via Argon2id into Key Slot 0, initializes the empty vault, and sets state to `Unlocked`.
5. Zero friction: the user never sees an unlock prompt.

### 3.2 Decrypt-on-Demand
1. Application queries secret item via `org.freedesktop.secrets`.
2. Daemon checks session state (`Unlocked`).
3. Vault payload is read; only the requested secret item is decrypted into memory.
4. Payload is encrypted with the client's negotiated D-Bus session key and returned.
5. In-memory decrypted buffer implements `Zeroize` and is immediately cleared on drop.

### 3.3 Session Lock & Seat Eviction
1. User locks screen or seat becomes inactive (`Active=false`).
2. `sigil` daemon receives `org.freedesktop.login1` signal.
3. Master `VolumeKey` and cached state are zeroized in memory. State transitions to `Locked`.
4. Subsequent secret queries block or return locked errors until re-unlocked via PAM or prompter.
