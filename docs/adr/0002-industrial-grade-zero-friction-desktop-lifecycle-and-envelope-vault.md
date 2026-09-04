# ADR-0002: Industrial-Grade Zero-Friction Desktop Lifecycle and Envelope Vault Architecture

- **Status**: Accepted
- **Date**: 2026-09-08
- **Authors**: Sigil Architecture & Desktop Platform Team
- **Deciders**: Desktop Architecture Group, Security WG
- **Informed**: System Packaging, Atrium Desktop Team, Release Engineering

## Context and Problem Statement

ADR-0001 established a memory-first, zero-disk-in-transit security baseline for `sigil`, deprecating insecure plaintext filesystem tokens and enforcing kernel-level `SO_PEERCRED` checks. However, production desktop deployments and Linux distributions (such as Atrium / Theseus) exposed critical lifecycle gaps and historical compromises:

1. **Cold Boot & First-Login Chicken-and-Egg Race**:
   During initial display manager authentication (Greetd/TTY), PAM executes in the system user context before the user's systemd session bus and `$XDG_RUNTIME_DIR/sigil/native.sock` exist. Under ADR-0001, PAM socket connections failed silently, leaving vaults locked or uninitialized until manual intervention or deferred prompter popups appeared.
2. **Coupled Key Derivation & Password Desynchronization**:
   Vault ciphertext was encrypted directly by a key derived from the user's login password. When a user changed their password via `passwd` or system settings—or when an administrator reset it via `sudo passwd <user>`—the credentials became desynchronized and permanently unrecoverable without manual forensic recovery.
3. **The "Keyfile" Security Compromise**:
   To avoid desktop unlock friction, legacy advice compromised by storing unencrypted 256-bit keys (`vault.key`) under the assumption that Full Disk Encryption (LUKS) was sufficient. Once booted, any process with the user's UID or physical DMA access while away from desk could extract all credentials immediately.
4. **Fast User Switching & Incomplete Zeroization**:
   Relying solely on `org.freedesktop.login1.Session.Lock` left sensitive keys resident in physical RAM when users switched graphical sessions (`Active=false`), leaving secrets exposed to other logged-in users or physical memory dumpers.
5. **Lack of Automated First-Login Provisioning**:
   New users had to interact with CLI commands or unexpected dialog boxes on their first desktop boot instead of experiencing zero-configuration, instant readiness.

We need a definitive, uncompromising, industrial-grade architecture that delivers zero-friction desktop integration (at parity with macOS Keychain) while strengthening the defense-in-depth posture across multi-user, suspend, biometric, and disaster-recovery scenarios.

## Decision Drivers

- **Zero Touch / Zero Friction**: Out-of-the-box operation on first login, seamless wake-up on screen unlock, zero CLI or dialog prompts during normal operation.
- **Envelope Encryption**: Decouple data payload encryption from authentication mechanisms (passwords, recovery codes, hardware tokens) via independent key slots.
- **Race-Free IPC**: Guarantee daemon socket availability at PAM login time using systemd socket activation.
- **Session-Bound Lifetime (Strict Zeroization)**: Tie in-memory master keys directly to seat and session activity, instantly zeroizing keys on screen lock, user switch, and suspend.
- **Self-Healing Synchronization**: Gracefully handle password changes, administrator resets, and offline credential drift without data loss.

## Considered Options

- **Option 1: Retain Direct Password Derivation + PAM Polling Loops**:
  Keep the single-file Argon2id encrypted vault; have PAM poll `$XDG_RUNTIME_DIR` until the daemon starts.
- **Option 2: Daemon Autostart via Legacy SUID Helper**:
  Have PAM invoke a setuid/setgid binary to bootstrap `sigil` before login finishes.
- **Option 3: Envelope Multi-Slot Architecture with Systemd User Socket Activation & Active Session Zeroization** (Selected).

## Decision Outcome

Chosen option: **Option 3: Envelope Multi-Slot Architecture with Systemd User Socket Activation & Active Session Zeroization**.

We break completely with legacy keyfiles and coupled derivation, adopting a four-pillar industrial architecture:

### 1. Envelope Encryption Storage Model (Key Slots)

The persistent storage layout is restructured into an envelope architecture inspired by LUKS2 and `systemd-homed`:

```text
~/.local/share/sigil/
├── vault.meta          # Metadata: format version, UUID, active slot manifests
├── vault.slots/        # Authentication Key Slots (wrap the same 256-bit VolumeKey)
│   ├── slot-0.kdf      # Slot 0 (OS Password): Argon2id parameters & 32-byte salt
│   ├── slot-0.enc      # Slot 0: VolumeKey ciphertext encrypted with password key
│   ├── slot-1.kdf      # Slot 1 (Emergency Recovery Key / Paper Key)
│   ├── slot-1.enc      # Slot 1: VolumeKey ciphertext encrypted with recovery key
│   └── ...
└── vault.data          # Vault Data: Encrypted with VolumeKey using XChaCha20-Poly1305
```

- **Symmetric Volume Key**: Generated once from hardware-backed CSPRNG (`/dev/urandom` / `getrandom`) with 256 bits of cryptographic entropy.
- **Password Rotation**: Changing the user password only re-encrypts `slot-0.enc` (~64 bytes). The bulk `vault.data` payload is never re-encrypted, eliminating I/O latency and corruption risks.
- **Keyfile Mode Deprecated**: Raw unencrypted `vault.key` files on disk are permanently eliminated from standard desktop operation.

### 2. Race-Free Bootstrapping via Systemd Socket Activation

To solve the chicken-and-egg startup timing:
- Package a user socket unit: `/usr/lib/systemd/user/sigil.socket` listening on `%t/sigil/native.sock` (`0600`).
- During login, PAM session setup (`pam_systemd.so`) sets up `/run/user/<uid>` and activates user sockets before `pam_sigil.so` executes.
- `pam_sigil.so` connects to `%t/sigil/native.sock`. The Linux kernel buffers the connection and systemd immediately socket-activates the `sigil.service` daemon if not already running.
- **First-Login Provisioning**: When `sigil` receives `UnlockWithPassword` on an uninitialized vault, it automatically creates the random `VolumeKey`, seals it into `slot-0`, initializes an empty `vault.data`, and transitions immediately to `Unlocked`. No CLI commands or popup prompts are needed.

### 3. Comprehensive Session Activity Eviction (Logind Dual-Trigger)

`sigil` subscribes to system bus signals from `org.freedesktop.login1`:
1. **`Session.Lock`**: When the user locks the screen, all in-memory `VolumeKey` bytes and decrypted credential items undergo in-place cryptographic zeroization (`zeroize::Zeroize`). The state transitions to `Locked`.
2. **`Session.Active` Property Change**: When a fast user switch occurs or the seat switches VT, `Active` becomes `false`. `sigil` immediately zeroizes keys.
3. **Screen Unlock**: `tessera-lock` or display manager triggers `pam_sigil.so` upon successful authentication, passing the password over the native socket in volatile memory to restore the `VolumeKey` transparently.

### 4. Cascade Password Rotation & Desynchronization Self-Healing

- **Standard Passphrase Change (`pam_sm_chauthtok`)**:
  `pam_sigil.so` implements the PAM password stack. During `passwd` or graphical settings changes, it captures `old_authtok` and `new_authtok` and issues `IpcRequest::RotateSlotPassword`. `sigil` verifies and updates `slot-0` atomically.
- **Forced/Offline Password Reset Self-Healing**:
  If an administrator forces a password reset (`sudo passwd <user>`) without old credentials, `pam_sigil` flags `desync_detected: true`. On subsequent login, the vault transitions to `LockState::Desynced`. When a client requests a credential, `sigil-prompter` displays an integrated self-healing prompt:
  > *"System password was reset. Enter your previous password or Recovery Key to restore and synchronize your credential vault."*
  Entering the previous secret verifies `slot-0` or `slot-1`, updates `slot-0` with the current active password, and clears the desync condition.

### 5. Multi-User & System Account Shielding

`pam_sigil.so` strictly enforces `UID_MIN` boundaries:
- System users (UID < 1000 or UID == 65534) are bypassed immediately without I/O.
- IPC connections require kernel `SO_PEERCRED` matches.
- Multi-user desktops maintain completely isolated data directories and runtime sockets under `/run/user/<uid>/sigil/native.sock`.

## Pros and Cons of the Options

### Option 1: Direct Password Derivation + Polling
- Good: Simple single-file structure.
- Bad: Chicken-and-egg login race requires fragile sleep/poll loops. Changing passwords forces re-encrypting entire vault. Admin reset causes irreversible lockouts.

### Option 2: SUID Helper Bootstrapping
- Good: Can launch daemon prior to systemd session availability.
- Bad: SUID binaries introduce critical privilege escalation attack surface; rejected under modern distribution security baselines.

### Option 3: Envelope Multi-Slot Architecture with Systemd User Socket Activation (Selected)
- Good: Eliminates all race conditions via kernel socket activation.
- Good: Password rotations are atomic sub-millisecond operations.
- Good: Self-healing capability recovers from administrator resets and offline desyncs.
- Good: True zero-touch first login provisioning without compromising security.
- Good: Defense-in-depth memory zeroization covers fast user switching and lock screens.
- Bad: Requires migration logic for legacy single-file vaults (handled via transparent on-load envelope wrapping).

## Consequences

### Positive Consequences
- **Mac-Grade Frictionless UX**: Zero configuration, zero startup commands, zero credential popups during normal desktop lifecycle.
- **Robust Disaster Recovery**: Support for emergency paper recovery keys and painless password updates.
- **Strict Separation of Concerns**: PAM only transports ephemeral authentication tokens; systemd manages process lifecycle; `sigil` manages cryptography and policy.
- **Physical Memory Protection**: Leaving the desk or switching users guarantees key eradication in RAM.

### Negative Consequences & Mitigation
- **Migration of Legacy Vaults**: Existing single-file `vault.enc` + `vault.kdf` files must be read.
  *Mitigation*: The storage engine detects legacy format upon unlock, generates a random `VolumeKey`, migrates items into `vault.data`, creates `slot-0`, and deletes deprecated files atomically.
- **Biometric / Passwordless Logins**: Logins without passwords (e.g. fingerprint without TPM2) cannot unlock the password slot.
  *Mitigation*: Vault remains securely locked until first credential access triggers `sigil-prompter` for a single password entry, or unlocks via TPM2 hardware slot when hardware enclaves are available.

## Links

- Supersedes the cold-start and keyfile trade-offs described in [ADR-0001](0001-zero-compromise-memory-first-security-architecture.md)
- Storage Specification: `docs/reference/storage-format.md`
- Native IPC Specification: `docs/reference/native-ipc.md`
- Architecture Guide: `docs/explanation/architecture.md`
