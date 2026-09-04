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
                 │       sigil-service       │                       Unix Socket (SO_PEERCRED)
                 │       │           │       │                       /run/user/<uid>/sigil/native.sock
                 │       ▼           ▼       │                                  │
                 │     crypto      store     │◄─────────────────────────────────┤
                 │                           │                                  │
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
│   ├── sigil-domain/         # Pure domain entities, value objects, SecretBytes, error models (#![forbid(unsafe_code)])
│   ├── sigil-crypto/         # XChaCha20-Poly1305, Argon2id, HKDF-SHA256, DH-IETF-1024
│   ├── sigil-store/          # Envelope multi-slot vault persistence, atomic transactions
│   ├── sigil-service/        # Core service state machine, slot rotation, policy, collections
│   ├── sigil-ipc/            # Framed Unix socket protocol, SO_PEERCRED verification, lifecycle requests
│   ├── sigil-client/         # Async Rust SDK for desktop components (portal backend, prompter)
│   ├── sigil-secret-service/ # D-Bus org.freedesktop.secrets protocol adapter
│   ├── sigil/                # Daemon assembly, process hardening, logind listener
│   ├── sigil-prompter/       # Native prompt agent for emergency recovery and unlock dialogs
│   └── sigil-pam/            # Hardened, zero-disk PAM module (auth, setcred, session, chauthtok)
│
├── docs/
└── systemd/
    ├── sigil.service         # User-level systemd service
    └── sigil.socket          # User-level socket activation unit
```

---

## Core Components and Responsibilities

### `sigil-store`
Implements the v2 Envelope Storage format:
- `vault.meta`: Maintains vault UUID, active slot indices, and desync status.
- `vault.slots/`: Individual wrapped representations of the master `VolumeKey`.
- `vault.data`: XChaCha20-Poly1305 encrypted JSON payload.
All mutations use atomic file replacement (`write_temp` -> `fsync` -> `rename` -> `fsync_dir`).

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
