# Developer Documentation

Welcome to the `sigil` developer documentation. This section serves as the contributor firewall, covering local environment setup, architecture guidelines, automated testing, and end-to-end acceptance validation.

---

## Developer Guides

- **[Testing Guide](testing.md)**: Automated unit, integration, and security tests; cargo commands, linting, and diagnostic triage matrix.
- **[Acceptance Testing](acceptance.md)**: End-to-end human and system verification procedures for releases, user journeys, and edge cases.

---

## Local Development Workflow

### Prerequisites

- Rust toolchain (stable, 2021 edition or newer)
- `libpam0g-dev` (Debian/Ubuntu) or `pam-devel` (Fedora/Arch)
- `pkg-config`
- `dbus-daemon` / `dbus-broker` (session bus)

### Build Commands

```bash
# Debug build of all workspace binaries and crates
cargo build --workspace

# Release build with optimizations and symbols
cargo build --release

# Run linting and static checks
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

### Running Locally

```bash
# Run daemon locally with debug logging
RUST_LOG=debug cargo run -p sigil

# In another terminal: query lock status or ping
cargo run -p sigil-cli -- status
```
