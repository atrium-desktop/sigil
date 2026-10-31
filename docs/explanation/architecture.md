# Architecture

`sigil` is an uncompromising, industrial-grade desktop session credential infrastructure daemon.
It provides a fully compliant `org.freedesktop.secrets` Secret Service API implementation alongside a hardened, private native IPC interface for trusted desktop components (such as `xdg-desktop-portal-atrium`, `pam_sigil`, and `sigil-prompter`).

## Design Philosophy: Zero-Friction, Zero-Compromise

Historically, desktop credential management forced a trade-off between user friction (constant popups, separate passwords, manual CLI initializations) and security compromises (plaintext keyfiles, resident secrets during away-from-desk, desynchronization upon password change).

`sigil` eliminates this dichotomy through five core architectural pillars:
1. **Dual-Sovereign Architecture**: Decouples sandboxed zero-trust application isolation (stateless mathematical HKDF derivation via `org.freedesktop.portal.Secret`) from native host collaboration (per-item AEAD credential broker via `org.freedesktop.secrets`).
2. **Envelope Multi-Slot Storage**: The vault payload is encrypted by a dedicated, immutable 256-bit `VolumeKey`, which is sealed into independent key slots (system login password, recovery paper key, TPM2 enclaves). Password changes are instant $O(1)$ operations and completely isolated from application secret stability.
3. **Decrypt-on-Demand & Zero Plaintext Resident Memory**: Plaintext secrets are never bulk-loaded into process memory. Credentials are decrypted on the stack strictly when queried and zeroized immediately upon transmission.
4. **Race-Free Socket Activation**: Managed via systemd user socket activation (`sigil.socket`), eliminating chicken-and-egg timing races between PAM and daemon startup.
5. **Session-Bound Key Eviction & Zero-Allocation IPC**: Dual-trigger logind monitoring clears sensitive keys on screen lock, seat deactivation (`Active=false`), and user switching. Native IPC utilizes fixed-size stack buffers (`sigil-wire-v2`) eliminating heap fragmentation.

```text
                      Native Desktop Apps                         Sandboxed Flatpak / Snap Apps
                               │                                                │
                               ▼                                                ▼
                    org.freedesktop.secrets                           org.freedesktop.portal.Secret
                               │                                                │
                               ▼                                                ▼
                 ┌───────────────────────────┐                         xdg-desktop-portal
                 │           sigil           │                                  │
                 │                           │                                  ▼
                 │    sigil-dbus-secrets     │                         xdg-desktop-portal-atrium
                 │             │             │                                  │
                 │             ▼             │                                  ▼ (sigil-client)
                 │        sigil-vault        │                       Unix Socket (SO_PEERCRED)
                 │  (store / state machine)  │                       /run/user/<uid>/sigil/native.sock
                 │             │             │                                  │
                 │             ▼             │◄─────────────────────────────────┤
                 │     sigil-ipc-server      │◄─── pam_sigil.so (login/lock/chauthtok)
                 └─────────────┬─────────────┘
                               │
                               ▼
                    systemd-logind system bus
                    (Lock & Active=false monitoring)
```

---

## Workspace Layout

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
│
├── docs/
└── systemd/
    ├── sigil.service         # User-level systemd service
    └── sigil.socket          # User-level socket activation unit
```

---

## Core Components and Responsibilities

### `sigil-types` (Layer 0)
The bedrock domain types:
- `SecretBytes`: Memory-safe zeroize-on-drop byte container.
- `LockState`: Service lock state machine variants.
- Strongly typed domain identifiers: `Namespace`, `Subject`, `Purpose`, `CredentialId`, `CredentialMetadata`.

### `sigil-crypto` (Layer 1)
Modern, constant-time vault cryptography:
- `XChaCha20-Poly1305`: Authenticated symmetric encryption for envelope slots and records.
- `Argon2id`: Memory-hard password-based key derivation.
- `HKDF-SHA256`: Cryptographic subkey derivation for portal apps and item keys.
- `LockedKeyBox`: Memory-locked, non-dumpable memory page container (`mlock`, `MADV_DONTDUMP`).

### `sigil-vault` (Layer 2)
The vault storage and state machine engine:
- `FileVaultStore`: Multi-slot envelope persistence (`vault.meta`, `vault.slots/`, `vault.data`) with atomic replacement (`atomic_replace`).
- `SigilService`: Lifecycle state machine (`Uninitialized`, `Locked`, `Unlocked`, `Desynced`), auto-provisioning, password rotation, and item CRUD.

### `sigil-ipc-server` (Layer 3)
Inbound Native IPC server:
- Listens on `/run/user/<uid>/sigil/native.sock` or adopts systemd socket activation (`LISTEN_FDS`).
- Verifies caller UID via kernel `SO_PEERCRED` checks.

### `sigil-dbus-secrets` (Layer 3)
Inbound Secret Service D-Bus adapter:
- Implements `org.freedesktop.secrets` specification (`Collection`, `Item`, `Session`, `Prompt`).
- Encapsulates legacy RFC 2631 Diffie-Hellman and AES-128-CBC session negotiation.

### `sigil-client` (Layer 3)
Native IPC client library providing both async (`SigilClient`) and synchronous (`SigilSyncClient`) APIs.

### `sigil-pam` (Layer 4)
Pluggable Authentication Module (`pam_sigil.so`):
- Bypasses system accounts (`uid < 1000`). Forwards authentication tokens over `/run/user/<uid>/sigil/native.sock` in memory.
- Pure synchronous execution with zero cryptographic dependencies and zero Tokio runtime.

### `sigil` (Layer 4)
Host daemon assembly:
- Enforces process hardening: `PR_SET_DUMPABLE = 0`, `RLIMIT_CORE = 0`, and opportunistic `mlockall`.
- Subscribes to `org.freedesktop.login1` signals (`Session.Lock`, `Active=false`) to instantly wipe master keys in memory.
- Binds `sigil-ipc-server` and `sigil-dbus-secrets` to `SigilService`.
