# Development Guide

This guide establishes the standard local workflow for compiling, running, and debugging `sigil`.

---

## 1. Prerequisites

### System Libraries

`sigil` requires D-Bus development headers, PAM development headers, and standard C build tools:

| Distribution | Installation Command |
| :--- | :--- |
| **Debian / Ubuntu** | `sudo apt install libdbus-1-dev libpam0g-dev libclang-dev pkg-config` |
| **Arch Linux** | `sudo pacman -S dbus pam clang pkgconf` |
| **Fedora** | `sudo dnf install dbus-devel pam-devel clang pkgconf` |

### Optional Debugging Tools

| Distribution | Installation Command |
| :--- | :--- |
| **Debian / Ubuntu** | `sudo apt install systemd libsecret-tools d-feet dbus-monitor` |
| **Arch Linux** | `sudo pacman -S systemd libsecret d-feet` |
| **Fedora** | `sudo dnf install systemd libsecret d-feet dbus-tools` |

`busctl` is included with systemd; `secret-tool` is included with libsecret.

### Rust Toolchain

Install stable Rust (2021 edition or newer):
```bash
rustup update stable
```

---

## 2. Workspace Build Commands

```bash
# Debug build across all workspace crates
cargo build --workspace

# Fast daemon iteration build
cargo build -p sigil

# Release build with optimizations
cargo build --workspace --release

# Format check and clippy lints
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

---

## 3. Running the Daemon Locally

The daemon registers the well-known D-Bus name `org.freedesktop.secrets`. Only one service per session can hold this name.

### Running with Existing Session Service Stopped

```bash
# Stop any running secret service
systemctl --user stop sigil.service gnome-keyring-daemon.service 2>/dev/null || true

# Run daemon with debug logging
RUST_LOG=debug cargo run -p sigil
```

### Running Inside an Isolated D-Bus Session

To avoid disturbing your desktop session, launch inside a private `dbus-run-session`:

```bash
dbus-run-session -- bash
# Inside the subshell:
RUST_LOG=debug cargo run -p sigil
```

### Key Environment Variables

| Variable | Description |
| :--- | :--- |
| `RUST_LOG` | Log verbosity (`error`, `warn`, `info`, `debug`, `trace`) |
| `SIGIL_SOCKET_PATH` | Override the Unix domain socket path |
| `SIGIL_DATA_DIR` | Override the vault storage directory |
| `SIGIL_PROMPTER_PATH` | Path to the `sigil-prompter` binary |

---

## 4. Manual Testing with `secret-tool`

In one terminal, start the daemon:
```bash
RUST_LOG=debug cargo run -p sigil
```

In a second terminal, store and retrieve a test password:

```bash
# Store a secret under label "my-secret"
secret-tool store --label="my-secret" service test account user

# Retrieve the stored secret
secret-tool lookup service test account user

# Search for matching items
secret-tool search service test
```

---

## 5. Linked Worktree Workflow with Optics

When developing features that touch `sigil-prompter` and its companion C rendering engine **Optics**, use the dual Git worktree workflow documented in [`optics-dev-worktree.md`](optics-dev-worktree.md).
