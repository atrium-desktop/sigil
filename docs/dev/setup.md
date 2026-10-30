# Developer Setup

This guide provides a rapid setup checklist for developers preparing to work on `sigil`.

---

## Quick Setup Steps

1. **Install System Dependencies**:
   - Debian/Ubuntu: `sudo apt install libdbus-1-dev libpam0g-dev libclang-dev pkg-config`
   - Arch Linux: `sudo pacman -S dbus pam clang pkgconf`
   - Fedora: `sudo dnf install dbus-devel pam-devel clang pkgconf`

2. **Ensure Stable Rust**:
   ```bash
   rustup update stable
   ```

3. **Verify Build**:
   ```bash
   cargo build --workspace
   cargo test --workspace
   ```

4. **Next Steps**:
   - For complete build options, debugging tools, and isolated D-Bus execution, see [Development Guide](development.md).
   - For automated testing commands and test tiers, see [Testing Guide](testing.md).
   - For companion UI engine development, see [Optics Development Worktree](optics-dev-worktree.md).
   - For architectural and engineering standards, see [Standards Suite](standards/README.md).
