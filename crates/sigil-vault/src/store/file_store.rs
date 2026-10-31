use crate::domain::{Result, SigilError};
use crate::model::{StoredVaultData, VaultMeta};
use sigil_crypto::{
    decode_kdf, decrypt_xchacha20poly1305, derive_key_argon2id, encode_kdf,
    encrypt_xchacha20poly1305, generate_salt, KdfParams, MasterKey, DEFAULT_SALT_LEN,
};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use tracing::{info, warn};
use zeroize::Zeroize;

pub const VAULT_META_FILENAME: &str = "vault.meta";
pub const VAULT_DATA_FILENAME: &str = "vault.data";
pub const VAULT_SLOTS_DIRNAME: &str = "vault.slots";
pub const VAULT_LOCK_FILENAME: &str = ".vault.lock";

/// An RAII guard representing an exclusive POSIX `flock(LOCK_EX)` on the vault.
pub struct VaultLockGuard {
    _file: File,
}

impl Drop for VaultLockGuard {
    fn drop(&mut self) {
        let fd = self._file.as_raw_fd();
        unsafe {
            let _ = libc::flock(fd, libc::LOCK_UN);
        }
    }
}

/// Verifies directory permissions and ensures path is not an unauthorized symlink.
pub fn ensure_secure_dir(dir: &Path) -> Result<()> {
    if !dir.exists() {
        fs::create_dir_all(dir)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    } else {
        let meta = fs::symlink_metadata(dir)?;
        if meta.file_type().is_symlink() {
            return Err(SigilError::AccessDenied(format!(
                "Vault directory cannot be a symlink: {}",
                dir.display()
            )));
        }
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            warn!(
                "Vault directory {} permissions {:#o} too open, tightening to 0700",
                dir.display(),
                mode
            );
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        }
    }
    Ok(())
}

/// Atomically replaces a file by writing to a secure tempfile and renaming it.
pub fn atomic_replace(path: &Path, content: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| SigilError::StorageFailure("Cannot get parent directory of path".into()))?;
    ensure_secure_dir(parent)?;

    let temp_name = format!(".tmp_{}_{}", std::process::id(), rand::random::<u64>());
    let temp_path = parent.join(temp_name);

    {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp_path)?;

        file.write_all(content)?;
        file.sync_all()?;
    }

    fs::rename(&temp_path, path)?;

    // Sync parent directory to persist directory entry on Linux
    if let Ok(dir_file) = File::open(parent) {
        let _ = dir_file.sync_all();
    }

    Ok(())
}

#[derive(Clone, Debug)]
pub struct FileVaultStore {
    dir: PathBuf,
}

impl FileVaultStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn meta_path(&self) -> PathBuf {
        self.dir.join(VAULT_META_FILENAME)
    }

    pub fn data_path(&self) -> PathBuf {
        self.dir.join(VAULT_DATA_FILENAME)
    }

    pub fn slots_dir(&self) -> PathBuf {
        self.dir.join(VAULT_SLOTS_DIRNAME)
    }

    pub fn slot_kdf_path(&self, slot: u32) -> PathBuf {
        self.slots_dir().join(format!("slot-{slot}.kdf"))
    }

    pub fn slot_enc_path(&self, slot: u32) -> PathBuf {
        self.slots_dir().join(format!("slot-{slot}.enc"))
    }

    pub fn lock_path(&self) -> PathBuf {
        self.dir.join(VAULT_LOCK_FILENAME)
    }

    /// Acquires an exclusive advisory POSIX `flock(LOCK_EX)` on `.vault.lock`.
    pub fn acquire_exclusive_lock(&self) -> Result<VaultLockGuard> {
        ensure_secure_dir(&self.dir)?;
        let path = self.lock_path();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&path)?;

        let fd = file.as_raw_fd();
        let ret = unsafe { libc::flock(fd, libc::LOCK_EX) };
        if ret != 0 {
            return Err(SigilError::StorageFailure(format!(
                "Failed to acquire flock on {}: {}",
                path.display(),
                std::io::Error::last_os_error()
            )));
        }

        Ok(VaultLockGuard { _file: file })
    }

    /// Checks if a vault exists (envelope metadata or data present).
    pub fn exists(&self) -> bool {
        self.meta_path().exists() || self.data_path().exists()
    }

    /// Checks if the vault is flagged as desynchronized.
    pub fn is_desynced(&self) -> bool {
        if let Ok(meta) = self.read_meta() {
            meta.desync_detected
        } else {
            false
        }
    }

    /// Flags the vault as desynchronized (e.g. after out-of-band admin reset).
    pub fn mark_desynced(&self, desynced: bool) -> Result<()> {
        let _lock = self.acquire_exclusive_lock()?;
        self.mark_desynced_internal(desynced)
    }

    fn mark_desynced_internal(&self, desynced: bool) -> Result<()> {
        if self.meta_path().exists() {
            let mut meta = self.read_meta()?;
            meta.desync_detected = desynced;
            self.write_meta_internal(&meta)?;
        }
        Ok(())
    }

    pub fn read_meta(&self) -> Result<VaultMeta> {
        let path = self.meta_path();
        if !path.exists() {
            return Err(SigilError::NotFound("vault.meta not found".into()));
        }
        let bytes = fs::read(&path)?;
        serde_json::from_slice(&bytes)
            .map_err(|e| SigilError::CorruptData(format!("Corrupt vault.meta: {e}")))
    }

    pub fn write_meta(&self, meta: &VaultMeta) -> Result<()> {
        let _lock = self.acquire_exclusive_lock()?;
        self.write_meta_internal(meta)
    }

    fn write_meta_internal(&self, meta: &VaultMeta) -> Result<()> {
        let bytes = serde_json::to_vec(meta).map_err(|e| {
            SigilError::StorageFailure(format!("Failed to serialize vault.meta: {e}"))
        })?;
        atomic_replace(&self.meta_path(), &bytes)
    }

    /// Wraps `volume_key` into `slot` using `password` (Argon2id + XChaCha20-Poly1305).
    pub fn seal_slot_with_password(
        &self,
        slot: u32,
        volume_key: &MasterKey,
        password: &str,
    ) -> Result<()> {
        let _lock = self.acquire_exclusive_lock()?;
        self.seal_slot_internal(slot, volume_key, password)
    }

    fn seal_slot_internal(&self, slot: u32, volume_key: &MasterKey, password: &str) -> Result<()> {
        ensure_secure_dir(&self.slots_dir())?;

        let salt = generate_salt(DEFAULT_SALT_LEN);
        let salt_hex = sigil_types::encode_hex(&salt);
        let params = KdfParams::default();

        let kdf_bytes = encode_kdf(&params, &salt_hex)?;
        atomic_replace(&self.slot_kdf_path(slot), &kdf_bytes)?;

        let slot_key = derive_key_argon2id(password.as_bytes(), &salt, &params)?;
        let wrapped_volume_key = encrypt_xchacha20poly1305(&slot_key, volume_key.as_bytes(), b"")?;
        atomic_replace(&self.slot_enc_path(slot), &wrapped_volume_key)?;

        // Ensure slot is recorded in active_slots
        let mut meta = if self.meta_path().exists() {
            self.read_meta()?
        } else {
            VaultMeta::default()
        };
        if !meta.active_slots.contains(&slot) {
            meta.active_slots.push(slot);
            meta.active_slots.sort_unstable();
        }
        self.write_meta_internal(&meta)?;

        Ok(())
    }

    /// Unwraps `volume_key` from `slot` using `password`.
    pub fn unseal_slot_with_password(&self, slot: u32, password: &str) -> Result<MasterKey> {
        let kdf_path = self.slot_kdf_path(slot);
        let enc_path = self.slot_enc_path(slot);

        if !kdf_path.exists() || !enc_path.exists() {
            return Err(SigilError::NotFound(format!("Slot {slot} does not exist")));
        }

        let kdf_bytes = fs::read(&kdf_path)?;
        let (params, salt_hex) = decode_kdf(&kdf_bytes)?;

        let salt = sigil_types::decode_hex(&salt_hex)
            .map_err(|e| SigilError::CorruptData(format!("Invalid salt hex: {e}")))?;

        let slot_key = derive_key_argon2id(password.as_bytes(), &salt, &params)?;

        let enc_bytes = fs::read(&enc_path)?;
        let mut decrypted = decrypt_xchacha20poly1305(&slot_key, &enc_bytes, b"")?;
        let volume_key = MasterKey::from_slice(decrypted.as_slice())?;
        decrypted.zeroize();

        Ok(volume_key)
    }

    /// Initializes a fresh vault: generates a random VolumeKey, wraps it into Slot 0,
    /// writes default metadata and initial empty vault data atomically under exclusive lock.
    pub fn initialize_with_password(&self, password: &str) -> Result<MasterKey> {
        let _lock = self.acquire_exclusive_lock()?;
        let volume_key = MasterKey::generate();
        self.seal_slot_internal(0, &volume_key, password)?;
        let meta = VaultMeta::default();
        self.write_meta_internal(&meta)?;
        let data = StoredVaultData::default();
        self.save_internal(&volume_key, &data)?;
        Ok(volume_key)
    }

    /// Unlocks the vault using `password` (checking Slot 0).
    pub fn unlock_with_password(&self, password: &str) -> Result<MasterKey> {
        match self.unseal_slot_with_password(0, password) {
            Ok(volume_key) => Ok(volume_key),
            Err(e) => {
                if self.is_desynced() {
                    Err(SigilError::AuthenticationRequired(
                        "Vault credentials are desynchronized. Recovery is required.".into(),
                    ))
                } else {
                    Err(e)
                }
            }
        }
    }

    /// Rotates the password for Slot 0 using `old_password` and `new_password` atomically.
    pub fn rotate_password(&self, old_password: &str, new_password: &str) -> Result<()> {
        let _lock = self.acquire_exclusive_lock()?;
        let volume_key = self.unseal_slot_with_password(0, old_password)?;
        self.seal_slot_internal(0, &volume_key, new_password)?;
        self.mark_desynced_internal(false)?;
        info!("Successfully rotated Slot 0 password.");
        Ok(())
    }

    /// Recovers and re-synchronizes the vault using a known recovery secret or previous password atomically.
    pub fn recover_and_sync(&self, recovery_secret: &str, new_password: &str) -> Result<MasterKey> {
        let _lock = self.acquire_exclusive_lock()?;
        // Try unwrapping with recovery_secret as Slot 0 (previous password) or Slot 1 (recovery key)
        let volume_key = if let Ok(k) = self.unseal_slot_with_password(0, recovery_secret) {
            k
        } else if let Ok(normalized) = sigil_crypto::normalize_recovery_key(recovery_secret) {
            if let Ok(k) = self.unseal_slot_with_password(1, &normalized) {
                k
            } else {
                return Err(SigilError::AuthenticationRequired(
                    "Invalid recovery secret or previous password".into(),
                ));
            }
        } else if let Ok(k) = self.unseal_slot_with_password(1, recovery_secret) {
            k
        } else {
            return Err(SigilError::AuthenticationRequired(
                "Invalid recovery secret or previous password".into(),
            ));
        };

        // Re-seal Slot 0 with the new password
        self.seal_slot_internal(0, &volume_key, new_password)?;
        self.mark_desynced_internal(false)?;
        info!("Vault successfully recovered and re-synchronized with new session password.");
        Ok(volume_key)
    }

    /// Enrolls an emergency recovery key into Slot 1 using the provided VolumeKey.
    pub fn enroll_recovery_key(&self, volume_key: &MasterKey, recovery_key: &str) -> Result<()> {
        let normalized = sigil_crypto::normalize_recovery_key(recovery_key)
            .map_err(|e| SigilError::InvalidRequest(e.to_string()))?;
        self.seal_slot_with_password(1, volume_key, &normalized)?;
        info!("Emergency recovery key successfully enrolled in Slot 1.");
        Ok(())
    }

    /// Unseals the VolumeKey from Slot 1 using the emergency recovery key.
    pub fn unseal_slot_with_recovery_key(&self, recovery_key: &str) -> Result<MasterKey> {
        let normalized = sigil_crypto::normalize_recovery_key(recovery_key)
            .map_err(|e| SigilError::AuthenticationRequired(e.to_string()))?;
        self.unseal_slot_with_password(1, &normalized)
    }

    /// Loads and decrypts the vault data using `volume_key`.
    pub fn load(&self, volume_key: &MasterKey) -> Result<StoredVaultData> {
        let path = self.data_path();
        if !path.exists() {
            return Err(SigilError::NotFound("Vault data file not found".into()));
        }

        let meta = fs::symlink_metadata(&path)?;
        if meta.file_type().is_symlink() {
            return Err(SigilError::AccessDenied(
                "Vault data cannot be a symlink".into(),
            ));
        }

        let mut file = File::open(&path)?;
        let mut encrypted_bytes = Vec::new();
        file.read_to_end(&mut encrypted_bytes)?;

        let mut decrypted_secret = decrypt_xchacha20poly1305(volume_key, &encrypted_bytes, b"")?;
        let data: StoredVaultData = serde_json::from_slice(decrypted_secret.as_slice())
            .map_err(|e| SigilError::CorruptData(format!("JSON deserialization failed: {e}")))?;

        decrypted_secret.zeroize();
        Ok(data)
    }

    /// Encrypts and atomically saves the vault data using `volume_key`.
    pub fn save(&self, volume_key: &MasterKey, data: &StoredVaultData) -> Result<()> {
        let _lock = self.acquire_exclusive_lock()?;
        self.save_internal(volume_key, data)
    }

    fn save_internal(&self, volume_key: &MasterKey, data: &StoredVaultData) -> Result<()> {
        ensure_secure_dir(&self.dir)?;

        let mut json_bytes = serde_json::to_vec(data)
            .map_err(|e| SigilError::StorageFailure(format!("JSON serialization failed: {e}")))?;

        let encrypted = encrypt_xchacha20poly1305(volume_key, &json_bytes, b"")?;
        json_bytes.zeroize();

        atomic_replace(&self.data_path(), &encrypted)
    }
}
