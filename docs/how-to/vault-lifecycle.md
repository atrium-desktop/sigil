# Vault Lifecycle & Key Management Guide

This guide covers operational procedures for managing `sigil` vaults throughout their lifecycle: zero-touch provisioning, envelope key slot management, password synchronization, backup, and emergency disaster recovery.

---

## 1. Vault Architecture Overview

Under the Envelope Multi-Slot Architecture (ADR-0002), all vault data resides in `$XDG_DATA_HOME/sigil` (typically `~/.local/share/sigil`):

```text
~/.local/share/sigil/
├── vault.meta              # Manifest, active slots, and desync indicators (mode 0600)
├── vault.data              # Bulk payload encrypted by 256-bit VolumeKey (mode 0600)
└── vault.slots/            # Authentication key slots (mode 0700)
    ├── slot-0.kdf          # Slot 0 (Login password) Argon2id parameters
    ├── slot-0.enc          # Slot 0 wrapped VolumeKey ciphertext
    ├── slot-1.kdf          # Slot 1 (Emergency Recovery Key) KDF parameters
    └── slot-1.enc          # Slot 1 wrapped VolumeKey ciphertext
```

Raw unencrypted keyfiles (`vault.key`) are deprecated and disallowed in desktop profiles to guarantee defense in depth.

---

## 2. Vault Provisioning

### Zero-Touch Desktop Provisioning (Standard)
In a standard desktop environment, **no manual CLI initialization is required**:
1. When you first log into your user account, `pam_sigil.so` contacts the socket-activated daemon over the native IPC socket in memory.
2. The daemon automatically generates a cryptographically secure 256-bit `VolumeKey`, derives a slot key from your login password, seals the key into `vault.slots/slot-0.enc`, and creates an empty `vault.data`.
3. Your vault is immediately unlocked and ready.

### Headless / Container Provisioning
For headless server environments where PAM is not configured, provision or unlock the vault by injecting `SIGIL_PASSWORD` via systemd:
```ini
# ~/.config/systemd/user/sigil.service [Service]
Environment="SIGIL_PASSWORD=your_device_passphrase"
```
The daemon provisions Slot 0 on startup and immediately wipes the password from memory.

---

## 3. Emergency Recovery and Disaster Preparedness

Under the envelope multi-slot model, you can maintain backup resilience in two complementary ways:
1. **Encrypted Archive Backup**: Safely backup `~/.local/share/sigil/`. Because all bulk data is encrypted by the `VolumeKey` and the `VolumeKey` is sealed with Argon2id, the archive is safe for off-site cold storage.
2. **Self-Healing Recovery**: If an administrator changes your system password without your old password, `sigil-prompter` will prompt you for your previous password on next secret access and automatically re-seal Slot 0 with your current session password.

---

## 4. Changing Passwords and Synchronization

### Automatic Desktop Synchronization
When you change your user password using `passwd` in a terminal or through the desktop control center:
1. `pam_sigil.so` hooks into the PAM `password` stack (`pam_sm_chauthtok`).
2. It captures the old and new passwords and instructs `sigil` to re-encrypt `slot-0.enc`.
3. Bulk credential data (`vault.data`) is never modified or rewritten. The operation completes in milliseconds.

### Self-Healing After Admin Password Reset
If a system administrator forces a password change via `sudo passwd <user>` without your old password:
1. On next login, `sigil` detects that the system password cannot unlock Slot 0, setting the vault to `LockState::Desynced`.
2. The first time a browser or application requests a secret, `sigil-prompter` displays the self-healing dialog:
   > *"Your system password was reset. Please enter your previous password or Emergency Recovery Key to re-synchronize."*
3. Enter your previous password or Slot 1 Recovery Key.
4. `sigil` unwraps the `VolumeKey`, re-encrypts Slot 0 with your new session password, and clears the desynchronization state.

---

## 5. Backup & Disaster Recovery

### Safe Backup
Because `vault.data` and all slots in `vault.slots/` are strongly encrypted with 256-bit keys and Argon2id, you can safely archive the entire vault directory:

```bash
# Create a consistent, encrypted backup
tar -czvf sigil-vault-backup-$(date +%F).tar.gz -C ~/.local/share/sigil .
```

This backup is safe for remote or cloud storage; without the Slot 0 password or Slot 1 recovery key, the archive cannot be decrypted.

### Restoring from Backup
```bash
systemctl --user stop sigil.service sigil.socket
mkdir -p ~/.local/share/sigil
tar -xzvf sigil-vault-backup-YYYY-MM-DD.tar.gz -C ~/.local/share/sigil
chmod 700 ~/.local/share/sigil ~/.local/share/sigil/vault.slots
chmod 600 ~/.local/share/sigil/* ~/.local/share/sigil/vault.slots/*
systemctl --user start sigil.socket
```
On your next login or screen unlock, PAM will immediately resume transparent unlocking.
