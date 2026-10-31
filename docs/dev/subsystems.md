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
│   ├── sigil-types/          # Layer 0: Ubiquitous domain types, safe memory wrappers (SecretBytes, LockState)
│   ├── sigil-crypto/         # Layer 1: Authenticated modern vault crypto (XChaCha20Poly1305, Argon2id, HKDF, LockedKeyBox)
│   ├── sigil-vault/          # Layer 2: Envelope multi-slot store (FileVaultStore) & lifecycle engine (SigilService)
│   ├── sigil-ipc/            # Layer 2: Wire protocol framing, codecs, SO_PEERCRED & socket path locator
│   ├── sigil-ipc-server/     # Layer 3: Native IPC Unix domain socket listener & systemd socket activation
│   ├── sigil-dbus-secrets/   # Layer 3: D-Bus org.freedesktop.secrets protocol adapter (encapsulates DH/AES-CBC session crypto)
│   ├── sigil-client/         # Layer 3: Rust client SDK with dual async/sync APIs
│   ├── sigil/                # Layer 4: Host daemon assembly, process hardening, logind listener
│   ├── sigil-prompter/       # Layer 4: Optics GUI unlock dialog (pure sync, zero Tokio dependency)
│   └── sigil-pam/            # Layer 4: Hardened PAM authentication module pam_sigil.so (pure sync, zero crypto, zero Tokio)
```

### `crates/sigil-types` (Layer 0)
The foundational domain language:
- **Safe Memory Containers**: `SecretBytes` (`#[zeroize(drop)]`, redacted Debug and Display).
- **Domain State**: `LockState` (`Uninitialized`, `Locked`, `Unlocked`, `Desynced`).
- **Domain Identifiers**: `Namespace`, `Subject`, `Purpose`, `CredentialId`, `CredentialMetadata`.
- **Zero I/O Guarantee**: Zero socket, network, or asynchronous runtime dependencies.

### `crates/sigil-crypto` (Layer 1)
Modern vault cryptography:
- **Envelope Authenticated Cipher**: Constant-time `XChaCha20-Poly1305` AEAD symmetric encryption.
- **Key Derivation**: `Argon2id` parameter encoding, decoding, and salt generation.
- **Domain-Separated Subkeys**: `HKDF-SHA256` for portal application secret derivation and per-item AEAD envelope key derivation.
- **Memory Hardening**: `LockedKeyBox` leveraging `libc::mmap`, `libc::mlock`, and `libc::madvise(..., MADV_DONTDUMP)`.

### `crates/sigil-vault` (Layer 2)
The vault engine and persistence layer:
- **`store`**: Envelope Multi-Slot Storage (v2 format). The encrypted vault payload is protected by a 256-bit `VolumeKey` stored in independent envelope key slots (`vault.meta`, `vault.slots/`, `vault.data`). Updates are atomic using atomic file replace semantics (`atomic_replace`).
- **`service`**: Thread-safe daemon state machine (`Unlocked`, `Locked`, `Uninitialized`, `Desynced`). Manages key eviction, auto-provisioning, password rotation, recovery sync, and collection/item CRUD operations.

### `crates/sigil-ipc` (Layer 2)
Lightweight wire framing and IPC codecs:
- **Wire Codecs**: Zero-allocation binary framing (`sigil-wire-v2`) with 8-byte header and length prefix.
- **Security Primitives**: Kernel-level `SO_PEERCRED` extraction verifying peer PID, UID, and GID. Enforces that only matching UID callers or root access the socket.
- **Socket Path Locator**: Canonical `default_socket_path()`, `socket_path_for_uid(uid)`, and `resolve_socket_path()`.
- **Feature-Gated Runtime**: Default `async` with optional pure `sync` profile eliminating Tokio from synchronous consumers.

### `crates/sigil-ipc-server` (Layer 3)
Native Unix domain socket server:
- Hosts the native socket endpoint at `/run/user/<uid>/sigil/native.sock`.
- Adopts systemd socket activation on file descriptor 3 (`LISTEN_FDS`).
- Enforces `SO_PEERCRED` checks on every connection and dispatches to `SigilService`.

### `crates/sigil-dbus-secrets` (Layer 3)
Secret Service D-Bus adapter:
- Implements freedesktop.org Secret Service specification over `zbus`.
- Translates D-Bus object paths (`/org/freedesktop/secrets/collection/...`) and method calls into `sigil-vault` operations.
- Encapsulates legacy RFC 2631 Diffie-Hellman (1024-bit MODP) and AES-128-CBC session negotiation.

### `crates/sigil-client` (Layer 3)
Rust client library with dual APIs:
- **`SigilClient`**: Async client for asynchronous daemons and portal backends.
- **`SigilSyncClient`**: Pure synchronous client for CLI tools, PAM, and GUI prompters without Tokio runtime dependencies.

### `crates/sigil` (Layer 4)
The host daemon binary:
- **Process Hardening**: Explicitly disables core dumps and ptrace attachments (`PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`, `mlockall`).
- **Lifecycle Integration**: Subscribes to `org.freedesktop.login1` signals (`Session.Lock` and `Active=false`) to instantly zeroize master keys upon lock or fast user switching.
- **Startup Coordination**: Mounts `sigil-ipc-server` and `sigil-dbus-secrets` over the unified `SigilService`.

### `crates/sigil-prompter` (Layer 4)
Interactive dialog agent:
- Rendered using companion GUI engine **Optics** (`flux`, `iris`, `lens`).
- Invoked when user input is required in GUI sessions (e.g., initial master passphrase entry or recovery unlock).
- Pure synchronous execution with zero Tokio dependency.

### `crates/sigil-pam` (Layer 4)
Pluggable Authentication Module (`pam_sigil.so`):
- **Zero-Disk, Zero-Crypto, Zero-Tokio**: Contains no cryptographic libraries, no asynchronous runtimes, and never touches disk.
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
