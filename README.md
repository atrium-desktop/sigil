# sigil

`sigil` is an industrial-grade, zero-friction implementation of the
[`org.freedesktop.secrets`](https://specifications.freedesktop.org/secret-service/latest/)
Secret Service specification and XDG Desktop Portal Secret backend for modern Linux desktops (Atrium, Tessera, Hyprland, Sway, River).

It provides a transparent, zero-touch credential lifecycle matching macOS Keychain quality:
- **Zero-Touch Provisioning**: Initialized automatically on first user login via PAM. No CLI commands, no configuration dialogs.
- **Envelope Multi-Slot Storage**: 256-bit CSPRNG `VolumeKey` protects bulk data; user passwords wrap the key in independent slots (`vault.slots/`).
- **Race-Free Socket Activation**: Managed via `sigil.socket` on `%t/sigil/native.sock`. Eliminates cold-boot timing races.
- **Away-from-Desk Memory Zeroization**: Monitored via systemd-logind. Screen lock or fast user switching (`Active=false`) instantly wipes keys in RAM using `zeroize::Zeroize`.
- **Self-Healing Password Synchronization**: Catches `passwd` changes via `pam_sm_chauthtok` to atomically re-encrypt Slot 0. Administrator resets automatically trigger self-healing recovery prompts on next access.

---

## Architecture Overview

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
                │   (XChaCha20)  (Envelope) │                                  │
                │                           │                                  ▼
                │  native IPC server/socket │◄────────────────── pam_sigil.so (auth, session, chauthtok)
                └─────────────┬─────────────┘
                              │
                              ▼
                   systemd-logind system bus
                   (Lock & Active=false monitoring)
```

---

## Quick Start

### 1. Build from Source

```bash
cargo build --release
```

Binaries produced:
- `target/release/sigil`: Core infrastructure daemon
- `target/release/sigil-prompter`: Native GUI unlock & recovery prompter
- `target/release/libpam_sigil.so`: Zero-disk PAM pass-through and password sync module

### 2. Install Binaries and Units

```bash
# Install binaries
sudo install -m 0755 target/release/sigil /usr/bin/
sudo install -m 0755 target/release/sigil-prompter /usr/bin/
sudo install -m 0755 target/release/libpam_sigil.so /usr/lib/security/pam_sigil.so

# Install systemd user units (system-wide for all users)
sudo install -m 0644 systemd/user/sigil.service /usr/lib/systemd/user/
sudo install -m 0644 systemd/user/sigil.socket /usr/lib/systemd/user/
sudo install -m 0644 dbus/org.freedesktop.secrets.service /usr/share/dbus-1/services/

# Enable socket activation in user session
systemctl --user daemon-reload
systemctl --user enable --now sigil.socket
```

### 3. Pre-flight: Clean Conflicting Providers

Only one daemon can own `org.freedesktop.secrets` on the user session bus:

```bash
# Mask legacy keyrings
systemctl --user mask gnome-keyring-daemon.service gnome-keyring-daemon.socket
systemctl --user mask kwallet5.service kwalletd5.service

# Remove stale D-Bus service files if present
rm -f ~/.local/share/dbus-1/services/org.freedesktop.secrets.service
```

### 4. PAM Integration (Transparent Lifecycle)

Add `pam_sigil.so` to your system authentication and password stacks:

#### Login & Session (`/etc/pam.d/system-login` or `/etc/pam.d/login`)
```pam
# Authenticate & capture token in memory
auth       sufficient   pam_unix.so try_first_pass nullok
auth       required     pam_deny.so

# Password changes: cascade rotation to Slot 0
password   sufficient   pam_unix.so sha512 shadow try_first_pass use_authtok
password   optional     pam_sigil.so

# Session: connect to socket-activated sigil after pam_systemd
session    required     pam_systemd.so
session    optional     pam_sigil.so
```

#### Screen Locker (`/etc/pam.d/tessera-lock`, `/etc/pam.d/swaylock`, or `/etc/pam.d/hyprlock`)
```pam
#%PAM-1.0
auth       sufficient   pam_unix.so try_first_pass
auth       optional     pam_sigil.so
account    include      system-login
session    optional     pam_sigil.so
```

---

## Verification & Standard CLI Tooling

`sigil` strictly implements the Freedesktop Secret Service standard. You can query, store, and inspect credentials using the standard `secret-tool` utility:

```bash
# Store a credential
secret-tool store --label="Test Secret" service test user alice

# Lookup the credential
secret-tool lookup service test user alice

# Clear the credential
secret-tool clear service test user alice
```

Verify service status on D-Bus:
```bash
busctl --user status org.freedesktop.secrets
```

---

## Security Model

| Security Layer | Implementation Mechanism |
|---|---|
| **At-Rest Bulk Encryption** | XChaCha20-Poly1305 with random 256-bit `VolumeKey` |
| **Slot Key Wrapping** | Argon2id (64 MiB RAM, 3 iterations, 4 lanes) |
| **In-Transit Wire** | Diffie-Hellman Key Exchange (`dh-ietf1024-sha256-aes128-cbc-pkcs7`) |
| **In-Memory Hardening** | `ZeroizeOnDrop`, `PR_SET_DUMPABLE = 0`, and `RLIMIT_CORE = 0` |
| **Away-from-Desk Eviction** | Systemd-logind `Lock` signal & `Active=false` property zeroization |
| **IPC Isolation** | Kernel-level `SO_PEERCRED` UID equality and system account filtering |

---

## Documentation

- **[ADR-0001: Zero-Compromise Memory-First Security Architecture](docs/adr/0001-zero-compromise-memory-first-security-architecture.md)**
- **[ADR-0002: Industrial-Grade Zero-Friction Desktop Lifecycle](docs/adr/0002-industrial-grade-zero-friction-desktop-lifecycle-and-envelope-vault.md)**
- **[Architecture Guide](docs/explanation/architecture.md)**
- **[Threat Model](docs/explanation/threat-model.md)**
- **[Vault Lifecycle & Recovery](docs/how-to/vault-lifecycle.md)**
- **[Desktop & Compositor Setup](docs/how-to/desktop-setup.md)**
- **[Packaging Guide](docs/how-to/packaging-guide.md)**
- **[Storage Format Reference](docs/reference/storage-format.md)**
- **[Native IPC Reference](docs/reference/native-ipc.md)**

---

## License

Licensed under the [MIT License](LICENSE).
