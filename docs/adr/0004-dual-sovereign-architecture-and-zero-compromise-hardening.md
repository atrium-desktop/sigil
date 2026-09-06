# ADR-0004: Dual-Sovereign Architecture: Decoupled Stateless Portal Derivation, Zero-Allocation Wire Protocol, and Per-Item Keyring Vault

- **Status**: Accepted
- **Date**: 2026-09-08
- **Authors**: Sigil & Atrium Architecture & Security Teams

## Context

Previous records ([ADR-0001](0001-zero-compromise-memory-first-security-architecture.md), [ADR-0002](0002-industrial-grade-zero-friction-desktop-lifecycle-and-envelope-vault.md), and [ADR-0003](0003-clean-break-secret-derivation-and-memory-zeroization.md)) established a memory-first security model, envelope multi-slot persistence, and standardized HKDF-SHA256 derivation for `atrium.portal.Secret/v1`.

However, an exhaustive architectural review across the entire system boundary—including the live interaction between `sigil` and `xdg-desktop-portal-atrium` (ADR-0020 / ADR-0022)—revealed foundational dilemmas and historical baggage that require a final, uncompromising clean break:

1. **The False Dichotomy: "Sandbox Portal vs. Central Keyring"**:
   - Modern sandboxed desktops (Flatpak / Wayland) operate under a zero-trust model where each application is a sovereign island. For the portal secret interface (`org.freedesktop.portal.Secret`), applications only need a stable, mathematically isolated 32-byte master secret to encrypt their own local databases (e.g., Firefox's `key4.db`, Chrome's `Login Data`). In this mode, a centralized credential database is redundant and harmful ($O(N)$ storage growth, file lock contention, orphan records upon uninstall).
   - Conversely, terminal and host workflows (e.g., `git-credential-libsecret`, GitHub CLI `gh`, AWS SSO, `NetworkManager` Wi-Fi passwords, system VPNs, and native developer IDEs) fundamentally depend on a trusted central credential broker (`org.freedesktop.secrets`). These tools do not embed local encrypted database engines and require cross-process credential sharing by attribute queries (`service="github", user="alice"`).
   - Prior iterations oscillated between attempting to eliminate the centralized keyring entirely (which breaks real-world developer and system workflows) or forcing sandboxed portal secrets into the centralized database (which introduces stateful database bloat and orphan keys).
2. **The Legacy Keyring Flaws (Historical Baggage)**:
   - Traditional desktop keyrings (GNOME Keyring / KWallet) implemented stateful vaults by decrypting the entire database into process heap memory upon login and keeping all plaintext secrets resident indefinitely.
   - User password changes required whole-database re-encryption, frequently causing database corruption, lock contention, and desynchronization upon unexpected power failure.
   - Historical protocol shims forced the inclusion of deprecated 1024-bit Diffie-Hellman (RFC 2631) and AES-CBC modes into the core cryptography dependencies.
3. **IPC Wire Residuals (Dynamic Heap Fragmentation)**:
   - The native IPC boundary between `sigil` and `atrium-portal-secret` relied on length-prefixed JSON (`serde_json`).
   - Dynamic JSON parsing allocates temporary heap strings and intermediate AST nodes. While final secret buffers were wrapped in `Zeroizing`, general-purpose memory allocators (glibc/jemalloc) do not scrub deallocated heap space, leaving microscopic transient secret fragments vulnerable to process memory forensic scans.

---

## Decision

We execute a complete, uncompromising clean break by establishing the **Dual-Sovereign Architecture**—anchoring both sandboxed isolation and host collaboration to a single immutable cryptographic root while physically and logically separating their operational tracks.

```text
       【Perimeter: Sandbox Isolation】                      【Broker: Host Collaboration】
  Flatpak / Wayland Apps (Firefox, Chromium)             Git CLI, VS Code, NetworkManager, Host Tools
                  │                                                        │
                  ▼ [UNIX_FD Passing]                                      ▼ [D-Bus Method Calls]
         xdg-desktop-portal (Frontend)                            org.freedesktop.secrets
                  │                                                        │
                  ▼ [org.freedesktop.impl.portal.Secret]                   │
       xdg-desktop-portal-atrium                                           │
  (Zero-State Gateway, SO_PEERCRED Verified)                               │
                  │                                                        │
                  ▼ [sigil-wire-v2: Zero-Alloc Binary Protocol]            │
         $XDG_RUNTIME_DIR/sigil/native.sock                                │
                  │                                                        │
┌─────────────────┴────────────────────────────────────────────────────────┴─────────────────┐
│                                     sigil Core Daemon                                      │
│                                                                                            │
│   ┌────────────────────────────────────────────────────────────────────────────────────┐   │
│   │            LockedMemoryBox (Single 4KB Page: mmap + mlock + MADV_DONTDUMP)         │   │
│   │  - 256-bit Immutable VolumeKey (Root Cryptographic Anchor)                         │   │
│   │  - Away-from-Desk logind Monitor: Instant zeroization on Active=false / Lock       │   │
│   └─────────────────────────────────────────┬──────────────────────────────────────────┘   │
│                                             │                                              │
│                      ┌──────────────────────┴──────────────────────┐                       │
│                      ▼                                             ▼                       │
│     【Track A: Stateless HKDF-SHA256】             【Track B: Modern Per-Item Store】       │
│     - 100% In-Memory Mathematical Expansion         - Decrypt-on-Demand (ItemKey HKDF)     │
│     - Zero Disk I/O, Zero Database Rows             - Zero Plaintext Resident in Memory    │
│     - Microsecond Lifetime (< 5μs), Instant Wipe    - Cross-Process Attribute Queries      │
└──────────────────────┬─────────────────────────────────────────────┬───────────────────────┘
                       │                                             │
                       ▼ Physical Persistence (Lifetime < 1KB)        ▼ Incremental Atomic WAL
            [vault.meta] [vault.slots/]                           [vault.store]
              (Slot 0: Argon2id KEK)                         (ChaCha20-Poly1305 Items)
```

### 1. The Single Cryptographic Anchor & Invariant Root
- **256-bit Immutable `VolumeKey`**:
  Provisioned once during initial vault initialization via system CSPRNG (`getrandom`). This root seed serves as the sole cryptographic origin for both tracks and **never changes over the lifetime of the installation**.
- **Multi-Slot Envelope Decoupling**:
  The `VolumeKey` is sealed into independent key slots (`vault.slots/slot-*.enc`) using Argon2id-derived Key Encryption Keys (KEK).
  User password rotations (`passwd` via `pam_sigil`) perform an $O(1)$ atomic rewrite of `slot-0.enc` alone. Neither sandboxed local databases nor centralized host credentials undergo re-encryption.

### 2. Track A: Stateless Mathematical Derivation (Portal Track)
Dedicated exclusively to sandboxed applications routed through `xdg-desktop-portal-atrium`:
- **Radical Statelessness**:
  Neither `sigil` nor `atrium-portal-secret` writes any database record, file, or log during application secret derivation.
- **Canonical Derivation (RFC 5869 HKDF-SHA256)**:
  $$\text{PRK} = \text{VolumeKey} \quad (32\text{ bytes})$$
  $$\text{Info} = \text{"atrium.portal.Secret/v1"} \,\|\, 0x00 \,\|\, \text{app\_id} \,\|\, 0x00 \,\|\, \text{"master-secret"}$$
  $$\text{AppSecret} = \operatorname{HKDF-Expand}(\text{PRK}, \text{Info}, 32)$$
- **Guaranteed Isolation & Zero Residue**:
  Subkeys across distinct `app_id` values are mutually orthogonal. When an application is uninstalled, zero cryptographic residue or orphan entries remain on the host system.

### 3. Track B: Modernized Per-Item Keyring Vault (Host Track)
Dedicated to native tools, developer CLI utilities, and system infrastructure:
- **Per-Item AEAD Envelope**:
  The obsolete monolith encrypted blob (`vault.data`) is replaced with an append-only atomic record store (`vault.store`).
  Each credential item is encrypted with an ephemeral subkey derived directly from the root anchor:
  $$\text{ItemKey} = \operatorname{HKDF-Expand}(\text{VolumeKey}, \text{"sigil.item/v1"} \,\|\, \text{item\_uuid}, 32)$$
  $$\text{Ciphertext} = \operatorname{ChaCha20-Poly1305}(\text{ItemKey}, \text{SecretBytes}, \text{AAD}=\text{SerializedAttributes})$$
- **Decrypt-on-Demand (Zero Plaintext Memory Residence)**:
  Unlocking the vault loads only metadata and searchable attributes into memory; **plaintext secrets remain encrypted on disk**.
  When an authorized caller queries a secret (e.g. `git` requesting a token), `sigil` reads that specific item, decrypts it on the stack, writes it to the client D-Bus pipe, and **immediately zeroizes the stack buffer**.
  The count of plaintext secrets resident in daemon memory is strictly $O(1)$ (transient) rather than $O(N)$ (permanent).

### 4. Zero-Allocation Binary Protocol (`sigil-wire-v2`)
JSON serialization across the native Unix socket is purged. It is replaced by a rigid, fixed-alignment binary wire format:

```rust
#[repr(C, packed)]
pub struct SigilWireHeader {
    pub magic: [u8; 4],     // b"SIGL"
    pub version: u8,         // 0x02
    pub opcode: u8,          // 0x01: GetAppSecret, 0x02: Lock, 0x03: IsLocked
    pub status: u8,          // 0x00: Success, 0x01: Locked, 0x02: Denied, 0x03: Error
    pub reserved: u8,        // 0x00
    pub body_len: u16,       // Body length, strictly bounded <= 512 bytes
}
```

- **Stack-Allocated Buffers**:
  Clients and servers encode and decode requests within fixed `[u8; 512]` stack arrays.
- **Zero Heap Footprint**:
  No dynamic heap reallocation, no AST construction, and no unscrubbed allocator debris. All buffers are deterministically cleared upon frame completion.

### 5. Memory Hardening & Zero-Trace Lifecycle
- **`LockedMemoryBox`**:
  `sigil` encapsulates the 32-byte `VolumeKey` within a private, memory-locked page via `libc::mmap`, `libc::mlock` (preventing disk swap), and `libc::madvise(..., MADV_DONTDUMP)` (preventing core dump inclusion).
- **Away-from-Desk Zeroization**:
  Active monitoring of `systemd-logind` (`PrepareForSleep`, `Session.Lock`, and `Active=false`) wipes `LockedMemoryBox` to zero within the first microsecond of seat deactivation, returning the vault to Sealed state.
- **Zero-Touch PAM Reconstruction**:
  Re-authentication through `pam_sigil.so` unseals Slot 0 and repopulates `LockedMemoryBox` instantaneously without GUI dialogs or user interruption.

---

## Alternatives Considered

1. **Purging the Keyring Entirely (Sandboxed Portal Only)**:
   *Rejected*. Sandboxed apps do not share credentials. Forcing Git CLI, `gh`, `aws-cli`, and `NetworkManager` into individual silos or unsupported environments causes users to store plaintext secrets in `~/.git-credentials` or unencrypted environment files.
2. **Retaining the Monolithic Keyring Blob for Track B**:
   *Rejected*. Storing all items in one encrypted file forces full-database re-encryption on password changes and eagerly loads all plaintext secrets into memory, violating defense-in-depth principles.
3. **Maintaining JSON IPC with In-Memory Scrubbing**:
   *Rejected*. General-purpose allocators provide no guarantees against compiler optimizations or heap fragmentation. Only fixed-size stack buffers guarantee provable zero-residual memory hygiene.

---

## Consequences

### Positive
- **Architectural Harmony**: Sandboxed apps receive 100% stateless, zero-overhead keys; native developer tooling retains rich attribute-based secret sharing.
- **Invulnerable Password Rotation**: Modifying user passwords is an isolated $O(1)$ slot update that never touches or endangers stored application secrets.
- **Zero Heap Footprint**: `sigil-wire-v2` eliminates dynamic heap allocations and residual plaintext fragments across the native IPC boundary.
- **Zero Plaintext In-Memory Exposure**: Secrets are decrypted strictly on demand and scrubbed instantly; no bulk plaintexts reside in memory while unlocked.
- **Full Alignment with Ecosystem**: Implements the exact stateless contract required by `xdg-desktop-portal-atrium` (ADR-0020 / ADR-0022) while delivering a production-grade secret broker.

### Negative / Trade-offs
- **Binary Wire Upgrade**:
  `atrium-portal-secret/src/native.rs` and `sigil-ipc` must adopt the `sigil-wire-v2` framing codec simultaneously.
- **Data Migration**:
  Legacy v1/v2 monolithic `vault.data` entries are lazily migrated into the per-item AEAD record format upon first unlock.
