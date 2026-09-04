# Standard CLI Tooling Reference (`secret-tool` & `busctl`)

Under the modern zero-friction architecture (ADR-0002), `sigil` is a pure session infrastructure daemon. It intentionally provides **no custom proprietary CLI utility**, as proprietary CLIs that mutate vault files on disk create state corruption, race conditions with running daemons, and security bypasses.

Instead, `sigil` strictly adheres to the Freedesktop Secret Service standard and exposes its interface through standard Linux desktop tools: `secret-tool` (from `libsecret`) and `busctl` (from `systemd`).

---

## 1. Using `secret-tool` (Standard Desktop CLI)

`secret-tool` is the standard tool available on all Linux distributions for storing, retrieving, and searching session credentials.

### Storing a Secret

```bash
# Prompts for secret on stdin (or echo password | secret-tool store ...)
secret-tool store --label="GitHub Access Token" \
    service github.com \
    account alice@example.com
```

### Retrieving a Secret

```bash
secret-tool lookup service github.com account alice@example.com
```

### Searching for Credentials

```bash
secret-tool search service github.com
```

### Deleting a Secret

```bash
secret-tool clear service github.com account alice@example.com
```

---

## 2. Inspecting the Daemon with `busctl`

You can directly query daemon health and D-Bus properties:

### Check Owning Process
```bash
busctl --user status org.freedesktop.secrets
```

### List Collections
```bash
busctl --user call org.freedesktop.secrets \
    /org/freedesktop/secrets \
    org.freedesktop.DBus.Properties Get ss \
    org.freedesktop.Secret.Service Collections
```

### Lock the Vault Immediately
```bash
busctl --user call org.freedesktop.secrets \
    /org/freedesktop/secrets \
    org.freedesktop.Secret.Service Lock ao 1 /org/freedesktop/secrets/collection/login
```

---

## 3. Supported Environment Variables

| Variable | Description | Default |
|---|---|---|
| `SIGIL_DATA_DIR` | Custom directory path for vault storage | `~/.local/share/sigil` (`$XDG_DATA_HOME/sigil`) |
| `SIGIL_SOCKET_PATH` | Path for the private native IPC socket | `/run/user/<uid>/sigil/native.sock` (`$XDG_RUNTIME_DIR/sigil/native.sock`) |
| `SIGIL_PASSWORD` | Automated unlock password for headless/CI/IoT environments | *(Unset)* |
