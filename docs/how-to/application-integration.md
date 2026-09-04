# Application & Client Integration Guide

`sigil` implements the standard [`org.freedesktop.secrets`](https://specifications.freedesktop.org/secret-service/latest/) specification. Any application or library targeting GNOME Keyring or KWallet over D-Bus works seamlessly with `sigil`.

---

## 1. Web Browsers (Chrome, Chromium, Brave, Edge)

Chromium-based browsers query the Secret Service on startup to encrypt saved passwords, cookies, and tokens.

### Configuration

Ensure your browser is configured to use the `gnome-libsecret` password store:

```bash
# Launch Chrome with explicit backend:
google-chrome --password-store=gnome-libsecret

# Or persistently via ~/.config/chrome-flags.conf (or chromium-flags.conf):
--password-store=gnome-libsecret
```

When Chrome saves or reads a password, it calls `OpenSession` and stores the credential in the default `login` collection managed by `sigil`.

---

## 2. Git Credential Storage

Use `git-credential-libsecret` to store Git tokens securely:

```bash
# Verify git-credential-libsecret is installed
which git-credential-libsecret

# Configure Git globally
git config --global credential.helper /usr/lib/git-core/git-credential-libsecret
```

Upon your next `git push` or `git pull`, credentials will be persisted encrypted inside `sigil`.

---

## 3. CLI Secret Operations (`secret-tool`)

`secret-tool` from `libsecret` allows scripting credential storage directly:

### Store a Secret
```bash
secret-tool store --label="GitHub Token" service github username octocat
# Enter password / secret token interactively:
```

### Lookup a Secret
```bash
secret-tool lookup service github username octocat
```

### Clear / Delete a Secret
```bash
secret-tool clear service github username octocat
```

---

## 4. Programming Language SDKs

### Python (`secretstorage` / `keyring`)
```python
import keyring

# Store password
keyring.set_password("myapp", "alice", "super-secret-123")

# Retrieve password
password = keyring.get_password("myapp", "alice")
print(f"Retrieved: {password}")
```

### Node.js (`keytar`)
```javascript
const keytar = require('keytar');

async function main() {
  await keytar.setPassword('myapp', 'alice', 'super-secret-123');
  const secret = await keytar.getPassword('myapp', 'alice');
  console.log('Secret:', secret);
}
main();
```

### Rust (`oo7` / `keyring-rs`)
```rust
use oo7::Keyring;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let keyring = Keyring::new().await?;
    let default_col = keyring.default_collection().await?;
    
    default_col.create_item("My App", [("service", "myapp")], b"secret-token", true).await?;
    Ok(())
}
```
