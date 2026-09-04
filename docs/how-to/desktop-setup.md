# Desktop Environment & Compositor Setup

This topic guide explains how to configure `sigil` across modern Wayland compositors (Hyprland, Sway, River) and desktop environments, replacing GNOME Keyring or KWallet.

---

## 1. Session Autostart

`sigil` is designed to run as a systemd user service.

### Recommended: systemd User Service

1. Enable and start the service for your user session:
   ```bash
   systemctl --user enable --now sigil.service
   ```
2. Verify that `sigil` acquired the D-Bus Secret Service name:
   ```bash
   busctl --user status org.freedesktop.secrets
   ```

### Non-systemd / Standalone Wayland Compositor Autostart

If your compositor does not manage a full systemd user session:

#### Hyprland (`~/.config/hypr/hyprland.conf`)
```ini
exec-once = sigil
```

#### Sway (`~/.config/sway/config`)
```ini
exec sigil
```

---

## 2. PAM Login & Screensaver Integration

The `pam_sigil.so` PAM module allows `sigil` to unlock automatically upon login and whenever you unlock your screensaver.

### Login PAM Stack

Add the following line to your system's auth stack:

- **Arch Linux**: `/etc/pam.d/system-login`
- **Debian / Ubuntu**: `/etc/pam.d/common-auth`
- **Fedora**: `/etc/pam.d/login`

```pam
auth optional pam_sigil.so
```

### Screensaver Re-Unlock Stack

When your screen locks, `sigil` receives the `org.freedesktop.login1.Session.Lock` signal and immediately clears master keys from memory.

To unlock automatically when you type your password to dismiss the screen locker, configure the locker's PAM file:

#### Swaylock (`/etc/pam.d/swaylock`)
```pam
# Include default auth
auth include system-auth
# Automatically pass unlock password to sigil via memory-only socket
auth optional pam_sigil.so
```

#### Hyprlock (`/etc/pam.d/hyprlock`)
```pam
auth include system-auth
auth optional pam_sigil.so
```

---

## 3. Replacing GNOME Keyring & KWallet

To prevent D-Bus name conflicts on `org.freedesktop.secrets`, mask or disable legacy keyrings:

```bash
# Mask GNOME Keyring services in systemd user session
systemctl --user mask gnome-keyring-daemon.service gnome-keyring-daemon.socket

# Disable PAM hooks for gnome-keyring if present
# Edit /etc/pam.d/common-auth or /etc/pam.d/login and comment out pam_gnome_keyring.so
```

For full troubleshooting steps, see [Troubleshooting D-Bus Conflicts](troubleshoot-dbus-conflicts.md).
