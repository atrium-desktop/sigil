# sigil Documentation

Welcome to the `sigil` documentation. `sigil` is a secure, memory-first desktop credential infrastructure daemon implemented in Rust. It provides a standard freedesktop.org Secret Service API implementation, a native IPC interface, and an XDG Desktop Portal Secret backend.

---

## Documentation Navigation

```text
docs/
├── adr/               # Architecture Decision Records (immutable)
├── explanation/       # Architecture, threat model, cryptographic concepts
├── how-to/            # Task-oriented step-by-step guides & topics
├── reference/         # Native IPC protocol, storage formats, CLI specifications
├── dev/               # Contributor firewall: setup, testing, acceptance
└── governance/        # Documentation governance (protocol v3.1.0)
```

---

### Explanations (Understanding)

- **[Architecture Overview](explanation/architecture.md)**: System decomposition, crate boundaries, and design principles.
- **[Threat Model](explanation/threat-model.md)**: Trust boundaries, security claims, and non-claims.
- **[Freedesktop Specifications](explanation/freedesktop-spec.md)**: Secret Service API and Portal Secret integration.
- **[Unlock Strategies](explanation/unlock-strategies.md)**: Envelope key slots, transparent PAM pass-through, and session zeroization.

---

### How-To Guides & Topics (Tasks)

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

### Developer & Contributor Firewall

- **[Developer Guide](dev/index.md)**: Local build environment, workflow, and architecture constraints.
- **[Testing Guide](dev/testing.md)**: Automated test execution, unit/integration tiers, and diagnostic triage matrix.
- **[Acceptance Testing](dev/acceptance.md)**: Human and stakeholder end-to-end verification and acceptance scenarios.

---

### Governance & Architecture

- **[Architecture Decision Records](adr/index.md)**: Architectural decisions ([ADR-0001: Zero-Compromise Security Architecture](adr/0001-zero-compromise-memory-first-security-architecture.md), [ADR-0002: Industrial-Grade Zero-Friction Desktop Lifecycle](adr/0002-industrial-grade-zero-friction-desktop-lifecycle-and-envelope-vault.md)).
- **[Governance Standards](governance/index.md)**: Modular documentation governance framework (protocol v3.1.0).
