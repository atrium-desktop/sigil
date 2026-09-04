# Sandboxed Applications & XDG Desktop Portal Guide

This guide explains how sandboxed applications (Flatpak, Snap) securely obtain isolated cryptographic credentials through the XDG Desktop Portal Secret interface (`org.freedesktop.portal.Secret`).

---

## 1. Why Portal Secret Over Raw D-Bus?

Traditional D-Bus Secret Service (`org.freedesktop.secrets`) has no application isolation: any application running under your UID can enumerate and read all secrets in your keyring.

In modern sandboxed environments (like Flatpak):
1. The sandbox blocks direct access to the `org.freedesktop.secrets` D-Bus bus name.
2. The application requests a secret via the unprivileged Portal interface: `org.freedesktop.portal.Secret.RetrieveSecret`.
3. `sigil` uses **HMAC-based Key Derivation (HKDF-SHA256)** to derive a deterministic, 256-bit secret scoped specifically to that application's `app_id`.

```text
               ┌───────────────────────────────┐
               │    Master Key (in memory)     │
               └──────────────┬────────────────┘
                              │
               HKDF-SHA256(salt="org.freedesktop.portal.Secret",
                           info=app_id)
                              │
               ┌──────────────┴────────────────┐
               ▼                               ▼
       ┌───────────────┐               ┌───────────────┐
       │ App 1 Secret  │               │ App 2 Secret  │
       │ (e.g. Chrome) │               │ (e.g. Signal) │
       └───────────────┘               └───────────────┘
```

**Security Guarantee**: Even if App 1 is compromised, it cannot compute the master key, nor can it compute App 2's secret.

---

## 2. Flatpak Manifest Configuration

Applications packaging for Flatpak do not require special permissions to use the Portal Secret backend:

```json
{
  "app-id": "org.example.MyApp",
  "finish-args": [
    "--talk-name=org.freedesktop.portal.Desktop"
  ]
}
```

The portal backend identifies the caller via `SO_PEERCRED` / `GetConnectionCredentials` and passes the authentic `app_id` to `sigil`.

---

## 3. Retrieving a Portal Secret Programmatically

Applications can use libportal or direct D-Bus calls to retrieve their token:

### Example: Rust with `ashpd`
```rust
use ashpd::desktop::secret::Secret;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let secret = Secret::new().await?;
    let token = secret.retrieve_token().await?;
    println!("Retrieved 32-byte application secret token: {:?}", token);
    Ok(())
}
```

### Example: Python (`gio` / D-Bus)
```python
from gi.repository import Gio

bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
proxy = Gio.DBusProxy.new_sync(
    bus,
    Gio.DBusProxyFlags.NONE,
    None,
    "org.freedesktop.portal.Desktop",
    "/org/freedesktop/portal/desktop",
    "org.freedesktop.portal.Secret",
    None,
)

# Calls RetrieveSecret(fd, options)
# Returns an isolated master token written to the provided file descriptor.
```
