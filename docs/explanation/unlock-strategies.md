# Vault Lifecycle and Unlock Strategies

In legacy systems, credential managers forced users to make an unwelcome choice:
- **High Friction**: Endure separate passwords, constant unlock dialogs, and manual initializations; OR
- **Security Compromise**: Store an unencrypted keyfile (`vault.key`) on disk, rendering security dependent entirely on full-disk encryption and leaving credentials completely unprotected while logged in.

`sigil` **rejects this compromise entirely**. Under ADR-0002, `sigil` implements an uncompromising, zero-friction lifecycle based on **Envelope Key Slots**, **Systemd Socket Activation**, and **Session-Bound Memory Eviction**.

---

## The Zero-Friction Standard Lifecycle

Users interact with exactly one credential: their **system login passphrase**. The credential vault adapts automatically across the entire lifecycle:

```text
                     User interacts with a single system password
                                          │
       ┌──────────────────────────────────┼──────────────────────────────────┐
       ▼                                  ▼                                  ▼
[1. First Login Provisioning]    [2. Daily Unlock & Wakeup]      [3. Away-from-Desk Protection]
New machine or user created      Display manager / lock screen   Screen locked / user switched
pam_sigil detects empty vault    pam_sigil passes token via IPC  logind sends Lock / Active=false
sigil auto-initializes Slot 0    sigil restores VolumeKey in RAM sigil immediately zeroes memory
【Zero Config / Zero Popups】    【Transparent / Sub-second】    【Zero-Trace / Defense in Depth】
                                          ▲
                                          │ [4. Password Synchronization]
                                          │ User runs `passwd` or changes OS password
                                          │ pam_sigil captures chauthtok event
                                          │ Transparently rewrenches Slot 0
```

---

## Lifecycle Stages in Detail

### 1. First-Login Zero-Touch Provisioning
When a user logs into a freshly installed desktop (or a newly created user account):
1. The user authenticates at the display manager (Greetd / TTY) where `pam_sigil.so` hooks `auth` to stash credentials with zeroization protection.
2. `pam_systemd` establishes the user runtime environment (`/run/user/<uid>`) and binds `sigil.socket`.
3. `pam_sigil.so` executes in `open_session`, connects to `/run/user/<uid>/sigil/native.sock` via exponential backoff, and immediately wipes stashed memory.
4. `systemd.socket` activates `sigil.service` on-demand with socket fd 3 adoption.
5. The daemon detects that no vault exists (`LockState::Uninitialized`):
   - Generates a 256-bit CSPRNG `VolumeKey`.
   - Initializes an empty encrypted `vault.data`.
   - Derives a key from the user's login password via Argon2id and seals the `VolumeKey` into `vault.slots/slot-0.enc`.
   - Transitions directly to `LockState::Unlocked`.
6. **Result**: The user enters the desktop immediately with an active, secure vault. No CLI initialization, no popups.

### 2. Daily Unlock & Transparent Screen Wakeup
1. **Boot / Cold Login**: The password entered at the display manager is passed directly over the native socket in volatile memory. The daemon restores the `VolumeKey` and loads collections. Web browsers, Git, and portals access secrets without prompting.
2. **Lock Screen Dismissal**: When the user unlocks the screen (via `tessera-lock` or equivalent), the PAM stack triggers `pam_sigil.so` during `setcred`/`authenticate`. The `VolumeKey` is re-instantiated in memory before the desktop compositor renders.

### 3. Away-from-Desk Protection (Logind-Bound Zeroization)
When the user steps away from their workstation:
- Locking the screen broadcasts `org.freedesktop.login1.Session.Lock`.
- Switching users or virtual terminals changes the session `Active` property to `false`.
- `sigil` intercepts these events and immediately triggers cryptographic zeroization (`zeroize::Zeroize`) on the `VolumeKey` and all decrypted in-memory items.
- **Result**: Physical memory holds zero key material while the machine is locked, neutralizing cold-boot attacks and unauthorized local scripts.

### 4. Password Rotation & Self-Healing

#### A. Standard User Password Change
When the user updates their password via `passwd` or the desktop settings:
1. `pam_sigil.so` intercepts `pam_sm_chauthtok`.
2. It captures `old_authtok` and `new_authtok` and sends `IpcRequest::RotateSlotPassword`.
3. `sigil` decrypts `slot-0.enc` using the old password, derives a new slot key from the new password, and atomically writes the updated `slot-0.enc` and `slot-0.kdf`.
4. Bulk data (`vault.data`) remains untouched.

#### B. Administrator Reset & Out-of-Band Self-Healing
If an administrator changes the user's password (`sudo passwd <user>`), the old password is unknown to PAM:
1. `pam_sigil.so` flags `desync_detected: true` in `vault.meta`.
2. On next login, the vault enters `LockState::Desynced`.
3. When an application requests a secret, `sigil-prompter` displays an integrated recovery dialog:
   > *"Your system password was changed by an administrator. Please enter your previous password or Emergency Recovery Key to re-synchronize your credentials."*
4. Providing the previous secret verifies the slot, updates Slot 0 with the current session password, and restores full transparency.

---

## Biometric and Passwordless Logins

When authentication occurs without an alphanumeric password (e.g. fingerprint via `fprintd` or face unlock via `Howdy`), PAM receives no plaintext authentication token.

`sigil` resolves this through a graded fallback:

| Scenario | Vault Behavior |
| :--- | :--- |
| **No TPM2 / Pure Software** | The vault remains `Locked` upon login. The first time an application requests a credential, `sigil-prompter` requests the user's system password once to unlock Slot 0 for the session. |
| **With TPM2 Enclave (Hardware Bound)** | The `VolumeKey` is sealed to Slot 2 (`slot-2.tpm2`) with a TPM2 policy asserting PCR state and user biometric presence. Fingerprint verification satisfies the hardware policy and unseals the `VolumeKey` directly. |
