# Architecture

`sigil` is an uncompromising, industrial-grade desktop session credential infrastructure daemon.
It provides a fully compliant `org.freedesktop.secrets` Secret Service API implementation alongside a hardened, private native IPC interface for trusted desktop components (such as `xdg-desktop-portal-atrium`, `pam_sigil`, and `sigil-prompter`).

## Design Philosophy: Zero-Friction, Zero-Compromise

Historically, desktop credential management forced a trade-off between user friction (constant popups, separate passwords, manual CLI initializations) and security compromises (plaintext keyfiles, resident secrets during away-from-desk, desynchronization upon password change).

`sigil` eliminates this dichotomy through four core architectural pillars:
1. **Envelope Multi-Slot Storage**: The vault payload is encrypted by a dedicated 256-bit `VolumeKey`, which is sealed into independent key slots (system login password, recovery paper key, TPM2 enclaves). Password changes are instant and isolated from bulk data.
2. **Race-Free Socket Activation**: Managed via systemd user socket activation (`sigil.socket`), eliminating chicken-and-egg timing races between PAM and daemon startup.
3. **Session-Bound Key Eviction**: Dual-trigger logind monitoring clears sensitive keys on screen lock, seat deactivation (`Active=false`), and user switching.
4. **Self-Healing Synchronization**: Native `pam_sm_chauthtok` hooks and recovery prompt channels gracefully absorb both user and administrator password resets.

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
                 │  Secret Service adapter   │                         xdg-desktop-portal-atrium
                 │             │             │                                  │
                 │             ▼             │                                  ▼ (sigil-client)
                 │        sigil-core         │                       Unix Socket (SO_PEERCRED)
                 │  (crypto / store / state) │                       /run/user/<uid>/sigil/native.sock
                 │             │             │                                  │
                 │             ▼             │◄─────────────────────────────────┤
                 │  native IPC server/socket │◄─── pam_sigil.so (login/lock/chauthtok)
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
│   ├── sigil-core/           # Unified engine: domain models, crypto primitives, envelope store, state machine & IPC server
│   ├── sigil-ipc/            # Lightweight, decoupled wire protocol, framing codecs & peer credential checks
│   ├── sigil-client/         # Async Rust SDK for desktop components (portal backend, prompter)
│   ├── sigil-secret-service/ # D-Bus org.freedesktop.secrets protocol adapter
│   ├── sigil/                # Daemon assembly, process hardening, logind listener
│   ├── sigil-prompter/       # Native prompt agent for emergency recovery and unlock dialogs
│   └── sigil-pam/            # Hardened, zero-disk, zero-crypto-dependency PAM module (auth, setcred, session, chauthtok)
│
├── docs/
└── systemd/
    ├── sigil.service         # User-level systemd service
    └── sigil.socket          # User-level socket activation unit
```

---

## Core Components and Responsibilities

### `sigil-core`
Consolidates the core domain, cryptographic engine, envelope persistence, and service orchestration:
- **`domain`**: Strongly typed domain identifiers (`CredentialId`, `Namespace`, `Subject`, `Purpose`, `SecretBytes`, `LockState`, `SigilError`).
- **`crypto`**: XChaCha20-Poly1305 AEAD, Argon2id KDF, HKDF domain separation, and ephemeral Diffie-Hellman session derivation.
- **`store`**: Envelope Multi-Slot Storage (v2 format): `vault.meta`, `vault.slots/`, `vault.data`, atomic file replacement.
- **`service`**: State machine, lock/unlock lifecycle, zero-touch provisioning, and password rotation.
- **`server`**: `NativeIpcServer` hosting the Unix domain socket.

### `sigil-pam`
- **Authentication & Session (`pam_sm_authenticate` / `pam_sm_setcred` / `pam_sm_open_session`)**:
  Bypasses system accounts (`uid < 1000`). Forwards authentication tokens over `/run/user/<uid>/sigil/native.sock` in memory. If the vault is uninitialized, triggers instant first-login auto-provisioning.
- **Password Stack (`pam_sm_chauthtok`)**:
  Captures both old and new authentication tokens during password changes and issues `RotateSlotPassword`. If old credentials are unavailable (admin reset), tags the vault for self-healing recovery without corrupting state.

### `sigil` (Daemon Assembly)
- Enforces runtime isolation: sets `PR_SET_DUMPABLE = 0` and `RLIMIT_CORE = 0`.
- Subscribes to `org.freedesktop.login1` system bus signals:
  - `Session.Lock`: Destroys the in-memory `VolumeKey` and wipes decrypted items via `zeroize::Zeroize`.
  - `Active=false`: Evicts keys immediately upon fast user switching or seat deactivation.
- Re-registers transparently upon subsequent PAM unlock events.
