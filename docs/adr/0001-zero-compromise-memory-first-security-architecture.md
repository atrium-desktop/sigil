# ADR-0001: Zero-Compromise Memory-First Security Architecture

- **Status**: Accepted
- **Date**: 2026-09-04
- **Authors**: Sigil Security Team

## Context

Desktop credential management services (implementing `org.freedesktop.secrets`) have historically made compromises between security and convenience:
1. **Plaintext Credential Transit**: The previous implementation used a PAM module (`pam_sigil.so`) that intercepted user passwords during login or screensaver dismissal and wrote them in plaintext to a filesystem location (`/run/user/<uid>/sigil-pam-token`). Even with `0600` permissions on tmpfs, any process running under the same UID could poll and read user passwords, creating a severe race-window vulnerability. Furthermore, daemon refactoring left this file unconsumed while the PAM module continued writing it.
2. **Insecure Auto-Creation of Keyfile**: On an uninitialized system, the daemon automatically created an unencrypted `vault.key` (`0600`) on disk, leaving credentials vulnerable to offline theft if LUKS is absent, or to any unauthorized process running under the same UID.
3. **Process Snooping & Core Dumps**: The daemon process did not enforce anti-debugging restrictions (`PR_SET_DUMPABLE=0`) or disable core dumps (`RLIMIT_CORE=0`), leaving memory buffers vulnerable to inspection via `/proc/<pid>/mem` or crash dumps.
4. **Coarse-Grained D-Bus Access**: Standard D-Bus Secret Service exposes the entire collection to all processes sharing the session bus without per-application isolation.

To achieve an uncompromising, defense-in-depth posture, the architecture must ensure that credentials never hit the disk in transit, process memory is hardened, and authentication occurs strictly in volatile, locked memory.

## Decision

We adopt the **Zero-Compromise Memory-First Security Architecture**:

1. **Eliminate All File-Based Transit (Zero-Disk in Transit)**:
   - Completely remove the `/run/user/<uid>/sigil-pam-token` file creation and consumption pattern.
   - `pam_sigil.so` communicates directly with the running `sigil` daemon via the native Unix domain socket (`$XDG_RUNTIME_DIR/sigil/native.sock`).
   - The PAM module transmits the unlock password over the socket using a framed IPC protocol (`UnlockWithPassword`).
   - Password buffers in both the PAM module and the daemon are wrapped in zeroizing structures (`zeroize::Zeroize` / `explicit_bzero`) and erased immediately after use.
   - Socket connections require kernel-level `SO_PEERCRED` verification to enforce strict UID equality.

2. **Harden Default Vault Initialization**:
   - The daemon will **no longer** silently auto-generate an unencrypted `vault.key` on an empty directory.
   - Initial vault setup requires explicit user-driven initialization with a passphrase derived via Argon2id.
   - Keyfile mode is retained strictly as an explicit, opt-in feature for specialized headless setups that already run on encrypted disks.

3. **Process Runtime Hardening**:
   - The daemon immediately invokes `libc::prctl(libc::PR_SET_DUMPABLE, 0)` on startup to disallow unprivileged `ptrace` attachment and reading `/proc/<pid>/mem`.
   - The daemon sets `RLIMIT_CORE` to 0 to prevent writing core dumps containing sensitive cryptographic keys or decrypted secrets upon crash.
   - Sensitive memory buffers are zeroized upon deallocation, and lock events (such as logind `Session.Lock`) immediately drop and overwrite the master key and any cached secrets.

4. **Portal-First Isolation**:
   - Encourage the usage of `org.freedesktop.impl.portal.Secret` for sandboxed applications (Flatpak/Snap), where HKDF-SHA256 derives application-scoped subkeys rather than granting blanket access to the entire vault.

## Alternatives Considered

1. **Retain tmpfs Token File with Stricter Permissions / O_TMPFILE**:
   - *Rejected*: Any file-based mechanism in `/run/user/<uid>` is accessible to every process running under the same user UID, violating sandboxing and least privilege.
2. **Keyfile-Only Mode as Primary**:
   - *Rejected*: While convenient on LUKS full-disk encrypted disks, an unencrypted `vault.key` provides no defense against local malware, shared workstations, or pre-login inspection by root.

## Consequences

### Positive
- **Zero Disk Footprint**: User passwords never touch disk or tmpfs at any stage of login, unlock, or operation.
- **Race Condition Elimination**: Communication over native Unix domain sockets is point-to-point and synchronous, avoiding filesystem polling or stale token files.
- **Process Memory Protection**: Disabling dumpability and core dumps prevents forensic extraction of in-flight secrets from the daemon.
- **Clear Security Model**: Password-derived Argon2id vaults become the standard, provably secure default.

### Negative / Trade-offs
- If the `sigil` daemon is not running when PAM sets credentials during cold TTY login, the PAM socket connection will safely fail, and the vault will remain locked until the user service starts and prompts for unlock via UI or CLI.
