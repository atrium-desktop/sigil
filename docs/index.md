# Sigil Documentation

Welcome to the `sigil` documentation. `sigil` is a secure, memory-first desktop credential infrastructure daemon implemented in Rust. It provides a standard freedesktop.org Secret Service API implementation, a hardened native IPC interface, and an XDG Desktop Portal Secret backend.

---

## Documentation Navigation

```text
docs/
├── tutorials/         # Guided hands-on lessons (learning-oriented)
├── how-to/            # Task-oriented step-by-step guides & topic recipes
├── reference/         # Native IPC protocol, storage formats, CLI specifications
├── explanation/       # Architecture, threat model, cryptographic concepts
├── adr/               # Architecture Decision Records (canonical decision registry)
└── dev/               # Engineering surface: standards, blueprints, testing runbooks
```

---

### Tutorials (Learning)

- **[Getting Started](tutorials/getting-started.md)**: Guided walkthrough from clean clone to building, launching the daemon, initializing a vault, and storing/retrieving credentials.
- **[Tutorials Index](tutorials/index.md)**: Learning paths and prerequisites.

---

### How-To Guides (Tasks)

#### Packaging & Desktop Operations
- **[Packaging Guide](how-to/packaging-guide.md)**: Distro packaging recipes for Arch Linux (`PKGBUILD`), Fedora (`.spec`), Debian/Ubuntu (`debian/`), and NixOS.
- **[Desktop Environment & Compositor Setup](how-to/desktop-setup.md)**: Autostart, session management, and screensaver integration (Hyprland, Sway, Wayland).
- **[Configure Unlock Strategies](how-to/configure-unlock.md)**: Setting up transparent PAM unlock, systemd socket activation, and screen locker integration.
- **[Troubleshoot D-Bus Conflicts](how-to/troubleshoot-dbus-conflicts.md)**: Handling coexistence and cleanly replacing GNOME Keyring or KWallet.

#### Integration & Applications
- **[Application & Client Integration](how-to/application-integration.md)**: Connecting browsers (Chrome/Brave), Git credentials (`git-credential-libsecret`), and programming language SDKs.
- **[Sandboxed Applications & Portal Guide](how-to/sandboxed-apps-portal.md)**: Flatpak / Snap sandboxing and isolated per-application secret derivation via `org.freedesktop.portal.Secret`.
- **[Vault Lifecycle & Key Management](how-to/vault-lifecycle.md)**: Initializing vaults, two-phase password changes, backups, and emergency recovery.

---

### References (Lookup)

- **[Native IPC Specification](reference/native-ipc.md)**: Unix socket framing, protocol payloads, and peer authentication.
- **[Storage Format](reference/storage-format.md)**: Encrypted vault format, Argon2id KDF sidecar, and permission invariants.
- **[CLI Tooling](reference/cli.md)**: Standard CLI integration via `secret-tool` and `busctl`.

---

### Explanations (Understanding)

- **[Architecture Overview](explanation/architecture.md)**: System decomposition, crate boundaries, and design principles.
- **[Threat Model](explanation/threat-model.md)**: Trust boundaries, security claims, and non-claims.
- **[Freedesktop Specifications](explanation/freedesktop-spec.md)**: Secret Service API and Portal Secret integration.
- **[Unlock Strategies](explanation/unlock-strategies.md)**: Envelope key slots, transparent PAM pass-through, and session zeroization.

---

### Architecture Decisions & Engineering Standards

- **[Architecture Decision Records](adr/index.md)**: Canonical architectural decision registry ([ADR-0001](adr/0001-zero-compromise-memory-first-security-architecture.md) through [ADR-0005](adr/0005-docgov-decoupling-flat-standards-suite-and-documentation-topology-modernization.md)).
- **[Developer Portal](dev/index.md)**: Contributor workflows, testing runbooks, living subsystem blueprints, and authoritative standards suite in `docs/dev/standards/`.
