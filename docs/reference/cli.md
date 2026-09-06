# CLI & Standard Tooling Reference

`sigil` is a modern desktop session credential infrastructure daemon implementing the [`org.freedesktop.secrets`](https://specifications.freedesktop.org/secret-service/latest/) specification.

In accordance with ADR-0002 (Zero-Friction Desktop Lifecycle) and modern Unix ergonomics:
- **Daemon Interface**: `sigil` and `sigil-prompter` provide complete, standard POSIX/GNU CLI interfaces (`--version`, `--help`, configuration overrides, and diagnostic verbosity flags) with strict validation.
- **Credential Storage & Retrieval**: Standard desktop tools (`secret-tool` from `libsecret` and `busctl` from `systemd`) manage credential items over the standard D-Bus session bus. Administrative commands do not directly mutate on-disk vault files, preventing race conditions with the running daemon.

---

## 1. `sigil` Daemon CLI Reference

### Synopsis

```bash
sigil [OPTIONS]
```

### Options

| Option | Short | Environment Variable | Default Value | Description |
|---|:---:|---|---|---|
| `--version` | `-V` | *(None)* | *(Current version)* | Print version information and exit immediately with status 0. |
| `--help` | `-h` | *(None)* | *(Help text)* | Print help information and exit immediately with status 0. |
| `--data-dir <DIR>` | `-d` | `SIGIL_DATA_DIR` | `~/.local/share/sigil` | Custom path to the vault persistent storage directory. |
| `--socket-path <PATH>` | `-s` | `SIGIL_SOCKET_PATH` | `$XDG_RUNTIME_DIR/sigil/native.sock` | Custom path to the native IPC Unix domain socket. |
| `--password <PASSWORD>` | | `SIGIL_PASSWORD` | *(None)* | Headless vault unlock password for automated testing/CI environments. |
| `--password-file <FILE>`| | *(None)* | *(None)* | Read headless vault unlock password from a file. |
| `--verbose` | `-v` | *(None)* | `info` level | Increase logging verbosity (`-v` for `debug`, `-vv` for `trace`). |
| `--quiet` | `-q` | *(None)* | `info` level | Suppress non-error log messages (restricts output to `error`). Conflicts with `--verbose`. |

### Configuration Precedence

When configuring runtime directories or passwords, `sigil` evaluates configuration in the following order:

```text
Command-line Flag  >  Environment Variable  >  Standard XDG / System Default
  (--data-dir)           (SIGIL_DATA_DIR)        (~/.local/share/sigil)
```

### Security Considerations for Headless Passwords

> [!WARNING]
> Command-line arguments may be visible to other processes under the same user ID via `/proc/$PID/cmdline`.
> For automated, headless, or production deployments, prefer `--password-file` (e.g. integrated with `systemd` credentials via `LoadCredential=`) or the `SIGIL_PASSWORD` environment variable. In all cases, memory holding the password buffer is zeroized (`zeroize::Zeroize`) immediately after vault initialization or unlocking.

### Strict Argument Validation

Unlike legacy daemons, `sigil` parses and validates all command-line arguments **before** applying process hardening, initializing log subsystems, or binding D-Bus and socket endpoints:
- Executing `sigil --version` or `sigil --help` will **never** register a D-Bus name or conflict with an active instance.
- Providing an unknown argument (e.g., `sigil --invalid`) will fail immediately with exit code `2` and display the help hint, preventing accidental daemon execution.

---

## 2. `sigil-prompter` CLI Reference

`sigil-prompter` is the native Wayland/X11 graphical unlock and self-healing recovery prompter.

### Synopsis

```bash
sigil-prompter [OPTIONS]
```

### Options

| Option | Short | Description |
|---|:---:|---|
| `--version` | `-V` | Print version information and exit immediately. |
| `--help` | `-h` | Print help information and exit immediately. |

---

## 3. Credential Management with `secret-tool`

`secret-tool` (part of `libsecret`) is the standard freedesktop tool for querying, storing, and clearing secrets.

### Storing a Secret

```bash
# Prompts for secret on stdin (or echo "secret" | secret-tool store ...)
secret-tool store --label="GitHub Personal Access Token" \
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

## 4. Daemon Inspection with `busctl`

You can inspect the running daemon and its D-Bus properties directly using `systemd`'s `busctl`:

### Check Owning Process

```bash
busctl --user status org.freedesktop.secrets
```

### List Available Collections

```bash
busctl --user call org.freedesktop.secrets \
    /org/freedesktop/secrets \
    org.freedesktop.DBus.Properties Get ss \
    org.freedesktop.Secret.Service Collections
```

### Manually Lock the Default Login Collection

```bash
busctl --user call org.freedesktop.secrets \
    /org/freedesktop/secrets \
    org.freedesktop.Secret.Service Lock ao 1 /org/freedesktop/secrets/collection/login
```
