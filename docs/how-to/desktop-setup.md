# Desktop Environment & Compositor Setup

This guide explains how to integrate `sigil` into modern desktop environments and Wayland compositors (Atrium, Tessera, Hyprland, Sway, River) as the primary, zero-friction credential provider replacing GNOME Keyring and KWallet.

---

## 1. Systemd User Session Integration (Best Practice)

In modern Linux distributions, `sigil` is managed via systemd user units with on-demand socket activation.

### Enable the Units

```bash
# Enable the socket unit for seamless on-demand start during PAM login
systemctl --user enable sigil.socket

# Start or reload user units
systemctl --user daemon-reload
systemctl --user start sigil.socket
```

### Verify Registration

Once your session starts and a client or PAM accesses the socket, verify that `sigil` has acquired the D-Bus Secret Service name:

```bash
busctl --user status org.freedesktop.secrets
```

You should see `sigil` actively serving the object paths:
- `/org/freedesktop/secrets`
- `/org/freedesktop/secrets/collection/login`
- `/org/freedesktop/secrets/aliases/default`
- `/org/freedesktop/secrets/prompt/default`

---

## 2. PAM Login & Lock Screen Integration

### Automatic First-Login & Wakeup
With `pam_sigil.so` configured:
1. **Initial Login**: Users entering their password at the display manager (Greetd / TTY) automatically provision and unlock their vault.
2. **Lock Screen Dismissal**: When unlocking with `tessera-lock`, `swaylock`, or `hyprlock`, PAM re-transmits the password directly over the native socket in volatile memory.

### Dual-Trigger Session Zeroization (Away-from-Desk)
When your display locks or you switch desktop sessions:
- `systemd-logind` broadcasts `org.freedesktop.login1.Session.Lock`.
- The session `Active` attribute drops to `false`.
- `sigil` intercepts these signals and wipes the `VolumeKey` and decrypted caches using `zeroize::Zeroize`.

---

## 3. Sandboxed Application Integration (Flatpak / Snap)

Sandboxed applications do not access raw D-Bus collections directly. Instead, they interact with the Portal Secret API:

```text
Flatpak App ──► xdg-desktop-portal ──► xdg-desktop-portal-atrium ──► sigil (native IPC)
```

`sigil` derives mathematical orthogonal keys per application using HKDF-SHA256 (`derive_app_secret`). Sandboxed apps are mathematically partitioned and cannot observe or decrypt secrets belonging to other applications.

---

## 4. Replacing GNOME Keyring & KWallet

To avoid D-Bus conflicts over `org.freedesktop.secrets`:

```bash
# Mask legacy keyrings in the systemd user session
systemctl --user mask gnome-keyring-daemon.service gnome-keyring-daemon.socket
systemctl --user mask kwalletd5.service kwallet-pam.service

# Verify no duplicate Secret Service providers
grep -rn "org.freedesktop.secrets" /usr/share/dbus-1/services/ ~/.local/share/dbus-1/services/
```

Ensure only `org.freedesktop.secrets.service` pointing to `sigil` is active.
