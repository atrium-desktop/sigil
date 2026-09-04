# Threat Model

## 1. Scope & Objective

`sigil` is a desktop session credential service responsible for cryptographic protection, lifecycle management, sandboxed application isolation, and credential policies.

This threat model defines the assets, trust boundaries, attacker capabilities, protected threats, and out-of-scope conditions for the system under the envelope multi-slot architecture (ADR-0002).

---

## 2. Assets to Protect

1. **VolumeKey (Master Symmetric Key)**: The 256-bit symmetric root key in volatile memory and its sealed slot wrappers (`vault.slots/`).
2. **Bulk Stored Secrets**: Passwords, API tokens, certificates, and symmetric keys contained in `vault.data`.
3. **Derived Application Secrets**: Namespace/subject-isolated keys derived for sandboxed Flatpak/Snap applications via HKDF-SHA256.
4. **Metadata & Schema Confidentiality**: Account names, labels, collection definitions, and secret attributes.

---

## 3. Trust Boundaries

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│ Unconfined Desktop Session (UID: 1000)                                      │
│                                                                             │
│  ┌────────────────────────┐                   ┌──────────────────────────┐  │
│  │ Flatpak Sandbox (App A)│                   │ Flatpak Sandbox (App B)  │  │
│  └───────────┬────────────┘                   └────────────┬─────────────┘  │
│              │ (bwrap / portal)                            │                │
│              ▼                                             ▼                │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │ xdg-desktop-portal (verifies caller app-id)                           │  │
│  └───────────────────────────────────┬───────────────────────────────────┘  │
│                                      │                                      │
│                                      ▼                                      │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │ xdg-desktop-portal-atrium (Trusted Portal Broker)                     │  │
│  └───────────────────────────────────┬───────────────────────────────────┘  │
│                                      │                                      │
│                                      ▼ Unix Domain Socket                   │
│                                      │ SO_PEERCRED verified (UID equality)  │
│  ┌───────────────────────────────────┴───────────────────────────────────┐  │
│  │ sigil Daemon (Isolated TCB & Vault Guardian)                          │  │
│  │  - PR_SET_DUMPABLE = 0                                                │  │
│  │  - RLIMIT_CORE = 0                                                    │  │
│  │  - ZeroizeOnDrop memory buffers                                       │  │
│  └───────────────────────────────────▲───────────────────────────────────┘  │
│                                      │                                      │
│  ┌───────────────────────────────────┴───────────────────────────────────┐  │
│  │ pam_sigil.so (Ephemeral memory pass-through, zero disk footprint)     │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Protected Threats (Security Claims)

### At-Rest Filesystem Extraction (Stolen Device / Offline Drive)
- **Defense**: `vault.data` is encrypted with XChaCha20-Poly1305 using a 256-bit `VolumeKey`. The `VolumeKey` is sealed in `slot-0.enc` via Argon2id (64 MiB RAM, 3 iterations, 4 lanes). Without the user's password or emergency recovery key, brute-force attacks against the ciphertext are computationally intractable.
- **Envelope Benefit**: The volume key never appears on disk in plaintext (no `vault.key`).

### Away-from-Desk / Cold-Boot Memory Sniffing (Locked Screen)
- **Defense**: When the screen is locked, `systemd-logind` broadcasts `org.freedesktop.login1.Session.Lock`. `sigil` instantly zeroizes the `VolumeKey` and wipes all decrypted memory caches.
- **Result**: While the user is away, the system state in memory is cryptographically equivalent to a freshly booted, locked machine.

### Fast User Switching & Multi-Tenant Snooping
- **Defense**:
  1. `sigil` monitors the `Active` session attribute. When switching desktop sessions (`Active=false`), keys are immediately purged from RAM.
  2. IPC sockets reside in `/run/user/<uid>/` (mode `0700`).
  3. The daemon verifies `SO_PEERCRED` on every IPC connection, blocking any cross-user attempts with immediate termination.
  4. System accounts (`uid < 1000`) are bypassed by `pam_sigil.so`.

### Cross-Application Data Exfiltration
- **Defense**: Sandboxed applications communicate with `xdg-desktop-portal-atrium` instead of having direct access to raw Secret Service collections. `sigil` derives mathematical orthogonal subkeys via HKDF-SHA256 (`derive_app_secret`) keyed to `(namespace, subject, purpose)`. App A cannot access App B's secrets even if both run within the same user session.

### Process Inspection & Core Dump Leakage
- **Defense**: `sigil` explicitly invokes `libc::prctl(PR_SET_DUMPABLE, 0)` and sets `RLIMIT_CORE = 0`. Non-root processes under the same UID cannot inspect `/proc/<pid>/mem` or trigger core dumps to recover keys.

### Out-of-Band Password Desynchronization
- **Defense**: If an administrator executes `sudo passwd <user>`, the vault marks `desync_detected: true`. Rather than becoming irreversibly corrupted or locked out, `sigil` provides a self-healing challenge channel through `sigil-prompter` allowing the user to provide the previous password or recovery key to re-synchronize Slot 0.

---

## 5. Non-Claims & Explicit Out-of-Scope Conditions

- **Compromised Kernel / Root**: A malicious root user or compromised kernel has arbitrary access to physical pages and hardware registers and can inspect memory during the brief moments when the vault is actively unlocked.
- **Compromised Wayland Compositor / Input Snooper**: An adversary running within the trusted compositor process can keylog input passwords before they reach PAM or `sigil-prompter`.
- **Active Physical Memory Interposer (Liquid Nitrogen / Specialized Bus Tap During Active Operation)**: If the physical machine is captured while actively unlocked and the screen is not locked, hardware-level memory extraction attacks are outside user-space daemon guarantees.
