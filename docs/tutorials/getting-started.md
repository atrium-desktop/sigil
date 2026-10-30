# Getting Started with Sigil

In this tutorial, you will build Sigil from source, launch the daemon in your local session, initialize an encrypted credential vault, and store and retrieve a secret using standard freedesktop tooling.

---

## 1. Build the Workspace

From your clean clone, build all workspace components:

```bash
cargo build --release
```

This compiles:
- `target/release/sigil`: The main desktop credential infrastructure daemon.
- `target/release/sigil-prompter`: The native graphical unlock prompt agent.
- `target/release/libpam_sigil.so`: The transparent PAM login/unlock module.

---

## 2. Launch the Daemon

Before starting the daemon, ensure any conflicting Secret Service provider (such as gnome-keyring or kwallet) is stopped, or run inside an isolated session:

```bash
# Option A: Run inside an isolated D-Bus subshell (recommended for first test)
dbus-run-session -- bash

# Option B: Run directly in your current user session
systemctl --user stop gnome-keyring-daemon.service 2>/dev/null || true
```

Start `sigil` with informative logging:

```bash
RUST_LOG=info ./target/release/sigil
```

In the log output, verify that the daemon acquires the `org.freedesktop.secrets` D-Bus name and binds its native Unix domain socket at `/run/user/<uid>/sigil/native.sock`.

---

## 3. Store Your First Secret

Open a second terminal window (or ensure you are in the same D-Bus session if using `dbus-run-session`).

Use the standard freedesktop `secret-tool` utility to store a password:

```bash
secret-tool store --label="Test Credential" service tutorial user alice
```

When prompted:
1. If the vault is uninitialized, enter your initial master passphrase.
2. Enter the secret value (e.g. `s3cr3t-p@ssw0rd`).

Sigil automatically creates the envelope multi-slot vault (`~/.local/share/sigil/vault.meta` and `vault.slots/slot_0.slot`), encrypts your secret with XChaCha20-Poly1305, and commits it safely to disk.

---

## 4. Retrieve the Stored Secret

Query the stored secret using matching attribute keys:

```bash
secret-tool lookup service tutorial user alice
```

The output prints `s3cr3t-p@ssw0rd` directly to stdout.

---

## 5. Next Steps

Now that you have confirmed the daemon is operational:
- Configure transparent PAM login unlock with the [Configure Unlock Guide](../how-to/configure-unlock.md).
- Integrate desktop autostart with Hyprland, Sway, or Wayland via the [Desktop Setup Guide](../how-to/desktop-setup.md).
- Connect web browsers and Git credentials via the [Application Integration Guide](../how-to/application-integration.md).
- Understand the cryptographic architecture and envelope storage model in [Architecture Explanation](../explanation/architecture.md).
