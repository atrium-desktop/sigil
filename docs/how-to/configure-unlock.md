# How to Configure Industrial Zero-Friction Vault Unlock

Under the Envelope Multi-Slot Architecture (ADR-0002), `sigil` achieves zero-friction, transparent credential unlocking using your system login password. You never need to compromise security with unencrypted keyfiles or endure separate password prompts.

---

## Architecture Setup

### 1. Build & Install the PAM Module

```bash
cargo build --release -p sigil-pam
# Install to system PAM security module path
sudo install -m 0755 target/release/libpam_sigil.so /usr/lib/security/pam_sigil.so
```

### 2. Configure Systemd User Socket Activation

Socket activation guarantees the native IPC socket is available before PAM executes, eliminating chicken-and-egg startup races.

Create `/usr/lib/systemd/user/sigil.socket`:

```ini
[Unit]
Description=Sigil Credential Service Native Activation Socket
Before=sockets.target

[Socket]
ListenStream=%t/sigil/native.sock
SocketMode=0600
DirectoryMode=0700

[Install]
WantedBy=sockets.target
```

Enable the socket across user sessions:
```bash
systemctl --user enable sigil.socket
```

---

## PAM Phase Architecture & Module Placement

`pam_sigil.so` integrates into three distinct PAM facilities (`auth`, `session`, `password`), each fulfilling an explicit lifecycle role. Understanding each phase guarantees zero-race, leak-free execution:

| PAM Phase | Hook Function | Where to Configure | Purpose & Mechanism |
| :--- | :--- | :--- | :--- |
| **`auth`** | `pam_sm_authenticate` / `pam_sm_setcred` | `/etc/pam.d/system-login`, `/etc/pam.d/greetd`, Screen Lockers | **1. Login Managers**: Stashes authenticated password into PAM handle context with cryptographic zeroization callbacks (0ms fast probe skips if socket is unmounted).<br>**2. Screen Lockers**: Direct fast-path unlock while compositor is paused. |
| **`session`** | `pam_sm_open_session` / `pam_sm_close_session` | `/etc/pam.d/system-login`, `/etc/pam.d/greetd` (**must follow `pam_systemd.so`**) | **Cold-Boot Unlock**: Retrieves stashed password, connects to native socket over exponential backoff, wakes `sigil.service` via socket activation, and **immediately wipes** stashed memory via `wipe_stashed_password`. |
| **`password`** | `pam_sm_chauthtok` | `/etc/pam.d/system-login`, `/etc/pam.d/passwd` | **Slot Rekeying**: Intercepts password changes, sends `RotateSlotPassword` IPC, and atomically re-wraps Slot 0 with the new Argon2id key. |
| **`account`** | *None* | *Do not include* | Not applicable. `sigil` does not enforce account access expiration. |

---

## Production Configuration Recipes

### 1. Display Manager / Login Stack (`/etc/pam.d/greetd` or `/etc/pam.d/system-login`)

When configuring a display manager such as **Greetd**, ensure `pam_sigil.so` is present in `auth`, `session`, and `password`:

```pam
#%PAM-1.0

# 1. Authentication
# Capture the authenticated password into PAM handle context
auth       [success=1 default=ignore]  pam_unix.so try_first_pass nullok
auth       default=die                 pam_deny.so
auth       optional                    pam_sigil.so

# 2. Account verification
account    required                    pam_unix.so

# 3. Password synchronization (propagates `passwd` changes to Slot 0)
password   sufficient                  pam_unix.so sha512 shadow try_first_pass use_authtok
password   optional                    pam_sigil.so

# 4. Session management
# CRITICAL: pam_sigil.so MUST be placed AFTER pam_systemd.so so that
# /run/user/<uid> and sigil.socket are already established!
session    required                    pam_systemd.so
session    optional                    pam_sigil.so
```

> [!IMPORTANT]
> In the `session` group, `pam_sigil.so` **must follow `pam_systemd.so`**. `pam_systemd` is responsible for mounting `/run/user/<uid>` and instantiating the user systemd manager. Placing `pam_sigil.so` before it will cause the socket connection to fail.

### 2. Screen Locker Stack (`/etc/pam.d/tessera-lock`, `/etc/pam.d/swaylock`, or `/etc/pam.d/hyprlock`)

Screen lockers unlock an active desktop session where the daemon and socket are already running in memory:

```pam
#%PAM-1.0
# Fast-path: authenticate triggers pam_sigil.so which unlocks native.sock immediately
auth       sufficient   pam_unix.so try_first_pass
auth       optional     pam_sigil.so
account    include      system-login
```

When you enter your password to dismiss the screen lock, `pam_sigil.so` transmits the verified token directly across `/run/user/<uid>/sigil/native.sock` in volatile memory before the compositor reveals the desktop.

---

## Multi-User & System Account Protections

`pam_sigil.so` enforces industrial isolation:
- **System Accounts Bypassed**: Accounts with `UID < 1000` or `UID == 65534` (e.g. `systemd-coredump`, `cron`, `nobody`) are skipped immediately without socket access.
- **Kernel UID Isolation & PAM Authorization**: Every IPC connection is verified via `SO_PEERCRED`. Only the target user (`ucred.uid == my_uid`) and authorized system login hosts (root / UID 0 executing PAM) can access the native socket; cross-user access is strictly denied.
- **Transient Memory Zeroization**: PAM stashed credentials carry cryptographic memory zeroization callbacks and are immediately wiped after `open_session`.
- **Session Eviction**: When a user switches seats or locks the workstation, `sigil` intercepts logind's `Lock` and `Active=false` properties and immediately zeroes out `VolumeKey` and all cached decrypted secrets in RAM.

---

## Headless / Container Deployments

For automated CI, containers, or headless IoT systems where no PAM or graphical seat exists, supply the vault password via command-line argument, password file, or environment variable:

### Method 1: Systemd Credential File (Recommended for Production)

```ini
# ~/.config/systemd/user/sigil.service.d/override.conf
[Service]
LoadCredential=vault_password:/etc/credstore/vault.key
ExecStart=
ExecStart=/usr/bin/sigil --password-file %d/vault_password
```

### Method 2: Environment Variable

```ini
# ~/.config/systemd/user/sigil.service.d/override.conf [Service]
Environment="SIGIL_PASSWORD=your_device_provisioning_key"
```

The daemon automatically detects the key, provisions or unlocks Slot 0, and securely zeroizes (`zeroize::Zeroize`) the password buffer in memory immediately after initialization.

See [CLI Reference](../reference/cli.md) for full configuration options.
