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

## PAM Stack Integration

To enable transparent first-login provisioning, screen unlock, and password change cascade synchronization, add `pam_sigil.so` to your PAM stacks.

### 1. Login Stack (`/etc/pam.d/system-login` or `/etc/pam.d/login`)

```pam
# 1. Standard authentication
auth       sufficient   pam_unix.so try_first_pass nullok
auth       required     pam_deny.so

# 2. Account verification
account    required     pam_unix.so

# 3. Password changes (synchronizes Slot 0)
password   sufficient   pam_unix.so sha512 shadow try_first_pass use_authtok
password   optional     pam_sigil.so

# 4. Session management (must be after pam_systemd creates /run/user/<uid>)
session    required     pam_systemd.so
session    optional     pam_sigil.so
```

### 2. Screen Locker Stack (`/etc/pam.d/tessera-lock`, `/etc/pam.d/swaylock`, or `/etc/pam.d/hyprlock`)

```pam
#%PAM-1.0
auth       sufficient   pam_unix.so try_first_pass
auth       optional     pam_sigil.so
account    include      system-login
session    optional     pam_sigil.so
```

When you unlock your screen, PAM transmits the verified password over `/run/user/<uid>/sigil/native.sock` in memory. `sigil` unwraps the `VolumeKey` and restores unlocked operation before the compositor unlocks the display.

---

## Multi-User & System Account Protections

`pam_sigil.so` enforces industrial isolation:
- **System Accounts Bypassed**: Accounts with `UID < 1000` or `UID == 65534` (e.g. `systemd-coredump`, `cron`, `nobody`) are skipped immediately without socket access.
- **Kernel UID Equality**: Every IPC connection is verified via `SO_PEERCRED`. Cross-user access is impossible.
- **Session Eviction**: When a user switches seats or locks the workstation, `sigil` intercepts logind's `Lock` and `Active=false` properties and immediately zeroes out `VolumeKey` and all cached decrypted secrets in RAM.

---

## Headless / Container Deployments

For automated CI, containers, or headless IoT systems where no PAM or graphical seat exists, supply the vault password via environment variable:

```ini
# ~/.config/systemd/user/sigil.service [Service]
Environment="SIGIL_PASSWORD=your_device_provisioning_key"
```

The daemon detects the environment variable, provisions or unlocks Slot 0 automatically, and securely zeroes the environment buffer in memory.
