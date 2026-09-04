# Acceptance

This document defines the real, end-to-end acceptance validation procedures for `sigil`.

It answers: **Can an authentic user install, launch, configure, and operate `sigil` through standard desktop and CLI interfaces according to specification?**

---

## Scope & Prerequisites

- **Scope**: Vault initialization, PAM automatic login unlock, screensaver lock/re-unlock, CLI secret operations, and D-Bus Secret Service client integration (e.g. `secret-tool` / browsers).
- **Prerequisites**:
  - Linux desktop environment (Wayland or X11) with systemd user session.
  - Rust toolchain and compiled binaries (`sigil`, `sigil-cli`, `pam_sigil.so`, `sigil-prompter`).
  - Access to `sudo` for PAM module installation in testing environments.

---

## Launch & User Entry Point

1. Start the daemon under the current user session:
   ```bash
   systemctl --user start sigil.service
   # Or run directly for inspection:
   sigil
   ```
2. Verify D-Bus service ownership:
   ```bash
   busctl --user status org.freedesktop.secrets
   ```

---

## Core User Journeys

### Journey 1: First-Time Setup (Password Mode)

1. Run initialization via CLI:
   ```bash
   sigil-cli init
   ```
2. Enter and confirm a strong passphrase when prompted.
3. **Expected Result**:
   - `~/.local/share/sigil/vault.enc` and `~/.local/share/sigil/vault.salt` are created with `0600` permissions.
   - `~/.local/share/sigil/vault.key` does NOT exist.
   - `sigil-cli status` reports state as `Unlocked`.

### Journey 2: PAM Memory-Only Login Unlock

1. Install `pam_sigil.so` to `/lib/security/pam_sigil.so`.
2. Add `auth optional pam_sigil.so` to `/etc/pam.d/system-login` (or `/etc/pam.d/common-auth`).
3. Log out and log back in with your user password.
4. **Expected Result**:
   - `/run/user/<uid>/sigil-pam-token` is **never created** (verify with `ls -la /run/user/$(id -u)/sigil*`).
   - `sigil` daemon is running and vault is in `Unlocked` state immediately after login without any extra password prompt.

### Journey 3: Screensaver Lock & Re-Unlock Integration

1. Add `auth optional pam_sigil.so` to `/etc/pam.d/swaylock` (or your screensaver PAM configuration).
2. Trigger a lock signal via `loginctl lock-session`.
3. Check daemon status:
   ```bash
   sigil-cli status
   # Expected: Locked
   ```
4. Unlock the screen by entering your password in the screensaver.
5. Check daemon status:
   ```bash
   sigil-cli status
   # Expected: Unlocked
   ```

### Journey 4: D-Bus Secret Service Storage & Retrieval

1. Store a secret using standard `secret-tool`:
   ```bash
   secret-tool store --label="Test Credential" service test-service username alice
   # Enter secret: "super-secret-token"
   ```
2. Retrieve the stored secret:
   ```bash
   secret-tool lookup service test-service username alice
   ```
3. **Expected Result**:
   - Outputs `super-secret-token`.
   - Data is stored encrypted in `~/.local/share/sigil/vault.enc`.

---

## Acceptance Scenario Matrix

| Scenario ID | Precondition | User Action | Expected Observable Outcome | Pass / Fail |
|---|---|---|---|:---:|
| **SC-01** | Empty vault directory | Launch `sigil` | Daemon logs `No vault found... Awaiting initialization`; does NOT write unencrypted `vault.key` | [ ] |
| **SC-02** | Initialized vault (password mode) | Launch `sigil` | Daemon stays in `Locked` state awaiting PAM / CLI unlock | [ ] |
| **SC-03** | Vault is locked | Run `sigil-cli unlock` | Prompts for password, unblocks, status becomes `Unlocked` | [ ] |
| **SC-04** | Running daemon with secrets | Run `sigil-cli change-password` | Atomically updates `vault.enc` and `vault.salt`; secrets remain intact | [ ] |
| **SC-05** | Screen locks | `loginctl lock-session` | Master key dropped, collections cleared, status becomes `Locked` | [ ] |
| **SC-06** | Third-party UID process | Connect to `native.sock` | Rejected with `AccessDenied: Peer UID does not match` | [ ] |
| **SC-07** | Daemon crash or kill | Inspect core dump setting | `ulimit -c` is 0, `/proc/<pid>/mem` unreadable by non-root | [ ] |

---

## Final Acceptance Checklist

- [ ] All automated unit and integration tests pass (`cargo test --workspace`).
- [ ] Static analysis and formatting pass cleanly (`cargo clippy`, `cargo fmt`).
- [ ] PAM module transmits passwords over Unix socket with zero files on disk.
- [ ] Native IPC rejects connections from unauthorized UIDs.
- [ ] No unencrypted `vault.key` is silently created on cold boot.
- [ ] D-Bus `org.freedesktop.secrets` interface works seamlessly with `secret-tool` and Chrome.
