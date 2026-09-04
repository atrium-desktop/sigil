# Testing

This document details how to execute, interpret, and extend the automated test suite for `sigil`.

---

## Scope & Test Model

`sigil` uses a tiered testing strategy across its workspace crates:

- **Unit Tests**: Cryptographic primitives (`sigil-crypto`), storage encryption and serialization (`sigil-store`), domain type invariants (`sigil-core`).
- **Integration Tests**:
  - `sigil-ipc`: Daemon-client framing, asynchronous request/response loops, synchronous socket unlock, peer authentication via `SO_PEERCRED`.
  - `sigil-client`: End-to-end service state management, lock transitions, and `org.freedesktop.portal.Secret` derivation.
  - `sigil-secret-service`: D-Bus protocol compliance and collection/item lifecycle.
- **Static Analysis**: `clippy` checks with `-D warnings` and formatting enforcement via `rustfmt`.

---

## Run Commands

```bash
# Run full workspace test suite
cargo test --workspace

# Run tests for a specific crate
cargo test -p sigil-crypto
cargo test -p sigil-ipc
cargo test -p sigil-store
cargo test -p sigil-client

# Run integration tests specifically
cargo test --test portal_integration -p sigil-client

# Run tests with unbuffered logging output
cargo test -p sigil-ipc -- --nocapture

# Run static analysis and linting
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

---

## Key Test Scenarios Covered

1. **Cryptographic Roundtrips** (`crates/sigil-crypto`):
   - XChaCha20-Poly1305 encryption/decryption with AAD integrity verification.
   - Argon2id key derivation consistency across salt/params.
   - Diffie-Hellman 1024-bit key exchange and AES-128 session encryption.
   - HKDF application secret isolation (different app IDs yield orthogonal secrets).
2. **Storage and Atomicity** (`crates/sigil-store`):
   - Atomic replacement with file syncing and directory permission clamping (`0700` / `0600`).
   - Re-keying and staged password migrations.
3. **IPC & Zero-Disk Unlock** (`crates/sigil-ipc`):
   - Native Unix domain socket connection, framing, and command dispatch.
   - Password unlock over synchronous socket mimicking PAM `pam_sigil.so`.
   - In-memory credential erasure via `zeroize::Zeroize`.
4. **Portal Isolation** (`crates/sigil-client`):
   - Verification that app secrets are strictly derived per app ID without revealing master key.

---

## Failure Triage Matrix

| Failure Symptom | Likely Cause | Investigation Step |
|---|---|---|
| `AccessDenied: Peer UID mismatch` | Test socket connected across different user or invalid UID | Verify socket file is in `/tmp` or `$XDG_RUNTIME_DIR` with correct owner |
| `CryptoFailure: Argon2 derivation failed` | Out of memory or invalid Argon2 parameters | Check KdfParams in test (use lower memory for unit tests: `m_cost: 1024`) |
| `ConnectionRefused` on IPC socket | Daemon thread panicked before socket bind | Check stdout/stderr of spawned server task |
| `D-Bus NameAlreadyOwner` | Real `org.freedesktop.secrets` provider running locally | Ensure GNOME Keyring or background `sigil` is stopped or use mock bus |
| Test hangs during sync socket read | Single-threaded Tokio test blocked on synchronous read | Ensure `#[tokio::test(flavor = "multi_thread")]` is used when combining sync and async IO |

---

## Adding a Test

1. **Unit tests**: Place inside `tests` module in the same crate file or `tests/` directory.
2. **Deterministic paths**: Use unique temporary directories (`std::env::temp_dir().join(...)`) and ensure cleanup in a drop guard or at the end of the test.
3. **No plaintext leaks**: Do not log raw secret values or master keys in test output.
