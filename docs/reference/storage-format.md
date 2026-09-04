# Storage Format Reference

## Overview

Sigil uses an **Envelope Encryption Architecture** inspired by modern cryptographic filesystems (such as LUKS2 and systemd-homed). The vault's encrypted payload (`vault.data`) is encrypted by a high-entropy, 256-bit symmetric **VolumeKey**. This VolumeKey is never stored in plaintext; instead, it is wrapped by one or more **Key Slots** in `vault.slots/`.

This architecture provides critical industrial guarantees:
- **Instant Password Rotation**: Changing credentials only updates a tiny (~64 byte) slot file, without touching or re-encrypting the bulk vault data.
- **Multiple Unlock Factors**: Multiple independent slots (e.g. system password, emergency recovery paper key, TPM2 enclave policy) can unlock the same vault.
- **Zero Plaintext Compromise**: Unencrypted keyfiles (`vault.key`) are deprecated and disallowed in desktop configurations.

## Location & Files

All persistent state lives in `$SIGIL_DATA_DIR` (defaults to `$XDG_DATA_HOME/sigil/` or `~/.local/share/sigil/`). Directory permissions are strictly enforced to `0700`.

```text
~/.local/share/sigil/
├── vault.meta              # Manifest, format version, UUID, and slot table (0600)
├── vault.data              # Bulk payload encrypted by VolumeKey (0600)
└── vault.slots/            # Authentication key slot directory (0700)
    ├── slot-0.kdf          # Slot 0 (Login password) Argon2id parameters & salt
    ├── slot-0.enc          # Slot 0 wrapped VolumeKey ciphertext
    ├── slot-1.kdf          # Slot 1 (Emergency Recovery Key) KDF parameters & salt
    ├── slot-1.enc          # Slot 1 wrapped VolumeKey ciphertext
    └── slot-2.tpm2         # Slot 2 (Optional TPM2 PCR/Policy authorization blob)
```

---

## 1. `vault.meta` Schema

Stored as a JSON document (mode `0600`):

```json
{
  "version": 2,
  "vault_uuid": "f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
  "created_at": 1772928000,
  "modified_at": 1772928000,
  "active_slots": [0, 1],
  "desync_detected": false
}
```

- `version`: Storage format version (current: `2`).
- `vault_uuid`: Unique identifier for the vault instance across devices.
- `active_slots`: List of slot indices currently populated and valid.
- `desync_detected`: Set to `true` when PAM detects a password change that bypassed `slot-0` update (e.g., admin reset). Triggers self-healing on next access.

---

## 2. Authentication Key Slots (`vault.slots/`)

Each slot wraps the same 256-bit `VolumeKey` using independent cryptographic keys.

### Slot 0: Primary Login Password

- **`slot-0.kdf`**:
  ```json
  {
    "version": 2,
    "slot_type": "password",
    "kdf": "argon2id",
    "m_cost": 65536,
    "t_cost": 3,
    "p_cost": 4,
    "salt_hex": "e2f47c8d910a3b4c5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d"
  }
  ```
- **`slot-0.enc`**:
  ```text
  +-------------------+-----------------------------------------+
  | Nonce (24 bytes)  | Ciphertext + Poly1305 Tag (16 bytes)    |
  | (XChaCha20 nonce) | (Encrypted 32-byte VolumeKey)           |
  +-------------------+-----------------------------------------+
  ```
  Total size: 24 (nonce) + 32 (VolumeKey) + 16 (tag) = 72 bytes.

### Slot 1: Emergency Recovery Key (Paper Key)

- Formatted as a high-entropy Base32/BIP-39 mnemonic string suitable for paper backup.
- Wrapped similarly to Slot 0 using Argon2id with maximum memory hardening.

---

## 3. `vault.data` Structure (Bulk Data)

The bulk encrypted vault contains all collections, items, secrets, and metadata.

```text
+-------------------+-----------------------------------------+
| Nonce (24 bytes)  | Ciphertext + Poly1305 Tag (16 bytes)    |
| (XChaCha20 nonce) | (Encrypted JSON-serialized VaultPayload)|
+-------------------+-----------------------------------------+
```

### Decrypted `VaultPayload` Schema

```json
{
  "version": 2,
  "collections": [
    {
      "id": "login",
      "label": "Login",
      "items": [
        {
          "id": "item_98765432",
          "label": "GitHub Personal Access Token",
          "attributes": {
            "xdg:schema": "org.freedesktop.Secret.Generic",
            "service": "github.com",
            "account": "user@example.com"
          },
          "secret": [103, 104, 112, 95, ...],
          "content_type": "text/plain",
          "created_at": 1772928000,
          "modified_at": 1772928000
        }
      ]
    }
  ]
}
```

---

## Atomic Update Guarantee

All writes to `vault.meta`, `vault.slots/`, and `vault.data` strictly employ atomic temporary staging:

1. Write content to `<filename>.tmp.<pid>` with mode `0600`.
2. Issue `fsync()` on the open file descriptor to ensure physical storage commit.
3. Perform atomic replacement via `libc::rename()`.
4. Issue `fsync()` on the parent directory.

Under sudden power loss or system crash, the on-disk state is guaranteed to either remain intact at the previous committed version or complete fully.

---

## Legacy Format Migration (Format v1 -> v2)

When `sigil` encounters an unmigrated single-file vault (`vault.enc` + `vault.kdf` + `vault.salt` from Format v1):
1. The daemon decrypts the v1 data using the user-supplied password.
2. It generates a fresh 256-bit `VolumeKey` via CSPRNG.
3. It writes the data into `vault.data` encrypted with `VolumeKey`.
4. It packages the user password into `slot-0.kdf` and `slot-0.enc`.
5. It writes `vault.meta` with `version: 2`.
6. It unlinks the deprecated v1 files atomically.
