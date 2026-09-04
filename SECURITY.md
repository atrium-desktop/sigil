# Security Model & Formal Posture

`sigil` is a security-critical desktop credential infrastructure daemon implementing the Freedesktop Secret Service standard and XDG Desktop Portal Secret backend.

---

## 1. Threat Model & Mitigations

| Threat Vector | Mitigation Strategy | Security Invariant |
|---|---|---|
| **Stolen Drive / Offline Filesystem Extraction** | Vault bulk data (`vault.data`) encrypted with 256-bit `VolumeKey` via XChaCha20-Poly1305. The `VolumeKey` is sealed in `slot-0.enc` with Argon2id (64 MiB RAM, 3 iterations, 4 lanes). | Computationally intractable brute force; zero plaintext keys stored on disk. |
| **Tampering / Bit-Flipping Attacks** | Poly1305 AEAD authentication tags on both slots and bulk ciphertext. | Any byte modification triggers hard cryptographic authentication failure. |
| **Away-from-Desk / Cold-Boot Memory Inspection** | Logind dual-trigger listener: `Session.Lock` and `Active=false` immediately zeroize the `VolumeKey` and wipe in-memory secret caches. | Keys eradicated from physical RAM during screen lock, seat change, or sleep. |
| **Process Snooping & Core Dump Theft** | Process hardening on startup: `PR_SET_DUMPABLE = 0`, `RLIMIT_CORE = 0`, and opportunistic `mlockall(MCL_CURRENT \| MCL_FUTURE)`. | Non-root processes cannot read `/proc/$PID/mem` or trigger core dumps. |
| **Multi-User / Local Cross-Tenant Snooping** | Runtime socket restricted to `/run/user/<uid>/sigil/native.sock` (`0600` on `0700` parent). Kernel `SO_PEERCRED` strictly enforced. | Cross-user IPC attempts rejected immediately by kernel credentials. |
| **System Daemon Credential Interception** | `pam_sigil.so` enforces a strict system account boundary (`UID < 1000` and `UID == 65534` bypassed). | System background processes generate zero credential transit. |
| **Secret Exfiltration Over Session D-Bus Wire** | Mandatory Diffie-Hellman session key exchange (`dh-ietf1024-sha256-aes128-cbc-pkcs7`). Plaintext secrets never cross the wire unencrypted. | Snooping the session bus yields only ciphertext. |
| **Cross-Sandbox Flatpak/Snap Leakage** | Portal requests routed through `xdg-desktop-portal-atrium`. Application keys derived via HKDF-SHA256 keyed to `(namespace, app_id, purpose)`. | Applications receive mathematically orthogonal secrets. |
| **Password Change Desynchronization** | `pam_sm_chauthtok` captures password change events and re-encrypts Slot 0. Administrator resets trigger `LockState::Desynced` self-healing. | Zero password lockouts, zero lost credentials. |

---

## 2. Cryptographic Specifications

### Envelope Vault at Rest (Format v2)

```text
~/.local/share/sigil/
├── vault.meta              # Manifest and status flags (mode 0600)
├── vault.data              # Bulk payload encrypted by 256-bit VolumeKey (mode 0600)
└── vault.slots/            # Independent authentication key slots (mode 0700)
    ├── slot-0.kdf          # Slot 0: Argon2id KDF parameters and salt
    └── slot-0.enc          # Slot 0: Wrapped 256-bit VolumeKey
```

| Component | Cryptographic Primitive | Parameters | Source |
|---|---|---|---|
| **VolumeKey** | Symmetric CSPRNG | 256 bits (32 bytes) | `rand::rngs::OsRng` / `getrandom` |
| **Slot 0 Wrapping** | XChaCha20-Poly1305 | 192-bit nonce, 128-bit Poly1305 tag | `chacha20poly1305` |
| **Key Derivation (Slot 0)** | Argon2id | 64 MiB RAM, 3 iterations, 4 lanes, 32-byte salt | `argon2` |
| **Bulk Data Encryption** | XChaCha20-Poly1305 | 192-bit nonce per atomic save | `chacha20poly1305` |
| **Portal Secret Derivation** | HKDF-SHA256 | Domain-separated `(namespace, subject, purpose)` | `hkdf` / `sha2` |

---

## 3. Memory Safety & Lifetime Guarantees

All sensitive memory containers (`MasterKey`, `SecretBytes`, `ItemRecord`, temporary password buffers) implement `zeroize::Zeroize` and `zeroize::ZeroizeOnDrop`.

1. **Deterministic Eviction**: Memory buffers holding plaintext authentication tokens in `pam_sigil` and `sigil` are wiped immediately after the cryptographic operation completes.
2. **Anti-Paging (`mlockall`)**: The daemon attempts to lock all mapped memory pages into physical RAM using `libc::mlockall(MCL_CURRENT | MCL_FUTURE)` to prevent sensitive secrets from being swapped to disk.
3. **Redacted Debug Formatting**: `SecretBytes` and `MasterKey` redact their raw byte contents in standard `Debug` and `Display` implementations.

---

## 4. Trust Boundaries & Non-Claims

1. **Root / Kernel Compromise**: An attacker with root capabilities or kernel exploit access can inspect arbitrary user-space process memory while the vault is actively unlocked.
2. **Compromised Wayland Compositor / Display Manager**: An attacker controlling the Wayland compositor process can inspect graphical input events before they reach PAM or the prompt agent.
3. **Active Hardware Bus Interposer**: Attacking active DDR bus lines with physical hardware while the user is actively working and the machine is unlocked is outside user-space software guarantees.
