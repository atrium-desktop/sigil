# Vault Lifecycle & Key Management Guide

This guide covers complete operational procedures for managing `sigil` vaults throughout their lifecycle: initialization, re-keying, mode migration, backup, and disaster recovery.

---

## 1. Vault Storage Structure

By default, `sigil` stores vault data in `$XDG_DATA_HOME/sigil` (typically `~/.local/share/sigil`):

```text
~/.local/share/sigil/
├── vault.enc   # XChaCha20-Poly1305 encrypted JSON payload (mode 0600)
├── vault.salt  # 32-byte cryptographic random salt (mode 0600)
└── vault.kdf   # Argon2id parameters (m_cost, t_cost, p_cost)
```

In keyfile mode, `vault.key` (32-byte raw key in hex) replaces `vault.salt` and `vault.kdf`.

---

## 2. Vault Initialization

### Password Mode (Default / Recommended)
```bash
# Initialize vault with an interactive master password
sigil-cli init
```
This prompts for a new password, generates a fresh 32-byte salt, writes `vault.salt` and `vault.kdf`, and creates an empty encrypted `vault.enc`.

### Keyfile Mode (For Full-Disk Encryption)
```bash
# Initialize vault without a password (uses random 256-bit vault.key)
sigil-cli init --no-password
```

---

## 3. Changing Vault Passwords

To prevent data corruption or half-written states, `sigil-cli` implements a two-phase staged re-keying protocol:

```bash
# Step 1: Stop the background service to avoid concurrent file modifications
systemctl --user stop sigil.service

# Step 2: Run change-password
sigil-cli change-password
# Prompts for current password, then new password (with confirmation)

# Step 3: Restart the background service
systemctl --user start sigil.service
```

The tool writes `.next` staged files, synchronizes buffers with `fsync`, and atomically replaces `vault.enc` and `vault.salt`.

---

## 4. Switching Vault Modes

### From Password Mode to Keyfile Mode
```bash
systemctl --user stop sigil.service
sigil-cli clear-password
systemctl --user start sigil.service
```

### From Keyfile Mode to Password Mode
```bash
systemctl --user stop sigil.service
sigil-cli set-password
systemctl --user start sigil.service
```

---

## 5. Backup & Disaster Recovery

### Safe Backup
To create a complete, consistent backup of your encrypted vault:

```bash
# Vault files are fully self-contained encrypted archives
tar -czvf sigil-vault-backup-$(date +%F).tar.gz -C ~/.local/share/sigil .
```

*Security note*: In password mode, `sigil-vault-backup-*.tar.gz` can be safely archived or synced off-site: it cannot be decrypted without your Argon2id passphrase.

### Restoring from Backup
```bash
systemctl --user stop sigil.service
mkdir -p ~/.local/share/sigil
tar -xzvf sigil-vault-backup-YYYY-MM-DD.tar.gz -C ~/.local/share/sigil
chmod 700 ~/.local/share/sigil
chmod 600 ~/.local/share/sigil/*
systemctl --user start sigil.service
```

---

## 6. Emergency Reset

If you have forgotten your password or wish to wipe all credentials:

```bash
systemctl --user stop sigil.service
sigil-cli reset
# Prompts for explicit confirmation before erasing files permanently
```
To bypass interactive confirmation in automated environments:
```bash
sigil-cli reset --force
```
