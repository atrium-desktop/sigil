# How-To Guides

Task-oriented, step-by-step guides and topic walkthroughs for configuring, packaging, and operating `sigil`.

---

## Desktop Setup & Packaging

- **[Packaging Guide](packaging-guide.md)**: Distro packaging recipes for Arch Linux (`PKGBUILD`), Fedora (`.spec`), Debian/Ubuntu (`debian/`), and NixOS.
- **[Desktop Environment & Compositor Setup](desktop-setup.md)**: Autostart and session management on Hyprland, Sway, River, and Wayland desktop environments.
- **[Configure Unlock Strategies](configure-unlock.md)**: Detailed setup for PAM automatic unlock, keyfile mode, and GUI prompts.
- **[Troubleshoot D-Bus Conflicts](troubleshoot-dbus-conflicts.md)**: Resolving bus name ownership conflicts with GNOME Keyring or KWallet.

---

## Application & Ecosystem Integration

- **[Application & Client Integration](application-integration.md)**: Connecting browsers (Chrome/Brave), Git credentials (`git-credential-libsecret`), and programming language SDKs (Python, Node.js, Rust).
- **[Sandboxed Applications & Portal Guide](sandboxed-apps-portal.md)**: Flatpak / Snap sandboxing and isolated per-application secret derivation via `org.freedesktop.portal.Secret`.

---

## Vault Operations

- **[Vault Lifecycle & Key Management](vault-lifecycle.md)**: Initializing vaults, two-phase password changes, switching security modes, backups, and emergency recovery.
