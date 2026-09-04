use crate::model::{StoredVaultData, VaultMeta};
use sigil_domain::{Result, SigilError};
use sigil_crypto::{
    decode_kdf, decrypt_xchacha20poly1305, derive_key_argon2id, encode_kdf,
    encrypt_xchacha20poly1305, generate_salt, KdfParams, MasterKey, DEFAULT_SALT_LEN,
};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use tracing::{info, warn};
use zeroize::Zeroize;

pub const VAULT_META_FILENAME: &str = "vault.meta";
pub const VAULT_DATA_FILENAME: &str = "vault.data";
pub const VAULT_SLOTS_DIRNAME: &str = "vault.slots";

// Legacy v1 format filenames retained purely for transparent on-load migration
pub const LEGACY_VAULT_ENC_FILENAME: &str = "vault.enc";
pub const LEGACY_VAULT_KDF_FILENAME: &str = "vault.kdf";
pub const LEGACY_VAULT_SALT_FILENAME: &str = "vault.salt";

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
    let parent = path.parent().ok_or_else(|| {
        SigilError::StorageFailure("Cannot get parent directory of path".into())
    })?;
    ensure_secure_dir(parent)?;

    let mut temp_path = path.to_path_buf();
    temp_path.set_extension(format!("tmp.{}", std::process::id()));

    {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temp_path)?;
        file.write_all(content)?;
        file.sync_all()?;
    }

    fs::rename(&temp_path, path)?;
    Ok(())
}

/// A filesystem-backed envelope multi-slot vault store.
#[derive(Clone, Debug)]
pub struct FileVaultStore {
    pub dir: PathBuf,
}

impl FileVaultStore {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
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

    pub fn legacy_enc_path(&self) -> PathBuf {
        self.dir.join(LEGACY_VAULT_ENC_FILENAME)
    }

    pub fn legacy_kdf_path(&self) -> PathBuf {
        self.dir.join(LEGACY_VAULT_KDF_FILENAME)
    }

    pub fn legacy_salt_path(&self) -> PathBuf {
        self.dir.join(LEGACY_VAULT_SALT_FILENAME)
    }

    /// Checks if a vault exists (either v2 envelope data or legacy v1).
    pub fn exists(&self) -> bool {
        self.data_path().exists() || self.legacy_enc_path().exists()
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
        if self.meta_path().exists() {
            let mut meta = self.read_meta()?;
            meta.desync_detected = desynced;
            self.write_meta(&meta)?;
        }
        Ok(())
    }

    pub fn read_meta(&self) -> Result<VaultMeta> {
        let bytes = fs::read(self.meta_path())?;
        serde_json::from_slice(&bytes)
            .map_err(|e| SigilError::CorruptData(format!("Corrupt vault.meta: {e}")))
    }

    pub fn write_meta(&self, meta: &VaultMeta) -> Result<()> {
        let json = serde_json::to_vec(meta)
            .map_err(|e| SigilError::StorageFailure(format!("Failed to serialize vault.meta: {e}")))?;
        atomic_replace(&self.meta_path(), &json)
    }

    /// Encrypts `volume_key` into a given slot with `password`.
    pub fn seal_slot_with_password(
        &self,
        slot: u32,
        volume_key: &MasterKey,
        password: &str,
    ) -> Result<()> {
        ensure_secure_dir(&self.slots_dir())?;

        let salt = generate_salt(DEFAULT_SALT_LEN);
        let salt_hex: String = salt.iter().map(|b| format!("{:02x}", b)).collect();
        let params = KdfParams::default();

        let mut slot_key = derive_key_argon2id(password.as_bytes(), &salt, &params)?;
        let kdf_bytes = encode_kdf(&params, &salt_hex)?;

        let encrypted_volume_key =
            encrypt_xchacha20poly1305(&slot_key, volume_key.as_bytes(), b"")?;
        slot_key.zeroize();

        atomic_replace(&self.slot_kdf_path(slot), &kdf_bytes)?;
        atomic_replace(&self.slot_enc_path(slot), &encrypted_volume_key)?;

        Ok(())
    }

    /// Unwraps the `VolumeKey` from a password slot.
    pub fn unseal_slot_with_password(&self, slot: u32, password: &str) -> Result<MasterKey> {
        let kdf_path = self.slot_kdf_path(slot);
        let enc_path = self.slot_enc_path(slot);

        if !kdf_path.exists() || !enc_path.exists() {
            return Err(SigilError::NotFound(format!("Slot {slot} does not exist")));
        }

        let kdf_bytes = fs::read(&kdf_path)?;
        let (params, salt_hex) = decode_kdf(&kdf_bytes)?;

        let mut salt = Vec::new();
        for i in (0..salt_hex.len()).step_by(2) {
            if i + 2 <= salt_hex.len() {
                let byte = u8::from_str_radix(&salt_hex[i..i + 2], 16)
                    .map_err(|e| SigilError::CryptoFailure(format!("Invalid salt hex: {e}")))?;
                salt.push(byte);
            }
        }

        let mut slot_key = derive_key_argon2id(password.as_bytes(), &salt, &params)?;

        let encrypted_bytes = fs::read(&enc_path)?;
        let mut decrypted = decrypt_xchacha20poly1305(&slot_key, &encrypted_bytes, b"")?;
        slot_key.zeroize();

        if decrypted.len() != 32 {
            decrypted.zeroize();
            return Err(SigilError::CorruptData(
                "Unsealed VolumeKey is not 32 bytes".into(),
            ));
        }

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(decrypted.as_slice());
        decrypted.zeroize();

        Ok(MasterKey::new(key_array))
    }

    /// Initializes a brand new envelope vault with `password` sealing Slot 0.
    pub fn initialize_with_password(&self, password: &str) -> Result<MasterKey> {
        ensure_secure_dir(&self.dir)?;
        ensure_secure_dir(&self.slots_dir())?;

        let volume_key = MasterKey::generate();

        // Seal Slot 0
        self.seal_slot_with_password(0, &volume_key, password)?;

        // Write meta
        let meta = VaultMeta::default();
        self.write_meta(&meta)?;

        // Write empty payload
        let initial_data = StoredVaultData::default();
        self.save(&volume_key, &initial_data)?;

        info!("Successfully initialized envelope vault with Slot 0.");
        Ok(volume_key)
    }

    /// Unlocks the vault using `password` (checking Slot 0, and performing migration if legacy v1).
    pub fn unlock_with_password(&self, password: &str) -> Result<MasterKey> {
        // Check for legacy v1 format first
        if !self.data_path().exists() && self.legacy_enc_path().exists() {
            info!("Legacy v1 vault detected. Performing transparent migration to v2 envelope slots.");
            return self.migrate_legacy_v1_vault(password);
        }

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

    /// Rotates the password for Slot 0 using `old_password` and `new_password`.
    pub fn rotate_password(&self, old_password: &str, new_password: &str) -> Result<()> {
        let volume_key = self.unseal_slot_with_password(0, old_password)?;
        self.seal_slot_with_password(0, &volume_key, new_password)?;
        self.mark_desynced(false)?;
        info!("Successfully rotated Slot 0 password.");
        Ok(())
    }

    /// Recovers and re-synchronizes the vault using a known recovery secret or previous password.
    pub fn recover_and_sync(&self, recovery_secret: &str, new_password: &str) -> Result<MasterKey> {
        // Try unwrapping with recovery_secret as Slot 0 (previous password) or Slot 1 (paper key)
        let volume_key = if let Ok(k) = self.unseal_slot_with_password(0, recovery_secret) {
            k
        } else if let Ok(k) = self.unseal_slot_with_password(1, recovery_secret) {
            k
        } else {
            return Err(SigilError::AuthenticationRequired(
                "Invalid recovery secret or previous password".into(),
            ));
        };

        // Re-seal Slot 0 with the new password
        self.seal_slot_with_password(0, &volume_key, new_password)?;
        self.mark_desynced(false)?;
        info!("Vault successfully recovered and re-synchronized with new session password.");
        Ok(volume_key)
    }

    /// Migrates a legacy single-file v1 vault into the v2 envelope architecture.
    fn migrate_legacy_v1_vault(&self, password: &str) -> Result<MasterKey> {
        let (params, salt_hex) = if self.legacy_kdf_path().exists() {
            let kdf_bytes = fs::read(self.legacy_kdf_path())?;
            decode_kdf(&kdf_bytes)?
        } else if self.legacy_salt_path().exists() {
            let salt_str = fs::read_to_string(self.legacy_salt_path())?;
            (KdfParams::default(), salt_str.trim().to_string())
        } else {
            return Err(SigilError::StorageFailure(
                "No legacy salt or KDF configuration found".into(),
            ));
        };

        let mut salt = Vec::new();
        for i in (0..salt_hex.len()).step_by(2) {
            if i + 2 <= salt_hex.len() {
                let byte = u8::from_str_radix(&salt_hex[i..i + 2], 16)
                    .map_err(|e| SigilError::CryptoFailure(format!("Invalid salt hex: {e}")))?;
                salt.push(byte);
            }
        }

        let legacy_key = derive_key_argon2id(password.as_bytes(), &salt, &params)?;

        // Read legacy vault.enc
        let enc_bytes = fs::read(self.legacy_enc_path())?;
        let mut decrypted = decrypt_xchacha20poly1305(&legacy_key, &enc_bytes, b"")?;
        let data: StoredVaultData = serde_json::from_slice(decrypted.as_slice())
            .map_err(|e| SigilError::CorruptData(format!("Failed to parse legacy vault data: {e}")))?;
        decrypted.zeroize();

        // Generate fresh VolumeKey and initialize v2 envelope layout
        let volume_key = MasterKey::generate();
        self.seal_slot_with_password(0, &volume_key, password)?;

        let meta = VaultMeta::default();
        self.write_meta(&meta)?;
        self.save(&volume_key, &data)?;

        // Atomically unlink legacy files
        let _ = fs::remove_file(self.legacy_enc_path());
        let _ = fs::remove_file(self.legacy_kdf_path());
        let _ = fs::remove_file(self.legacy_salt_path());

        info!("Legacy vault successfully migrated to format v2 envelope slots.");
        Ok(volume_key)
    }

    /// Loads and decrypts the vault data using `volume_key`.
    pub fn load(&self, volume_key: &MasterKey) -> Result<StoredVaultData> {
        let path = if self.data_path().exists() {
            self.data_path()
        } else if self.legacy_enc_path().exists() {
            self.legacy_enc_path()
        } else {
            return Err(SigilError::NotFound("Vault data file not found".into()));
        };

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
        ensure_secure_dir(&self.dir)?;

        let mut json_bytes = serde_json::to_vec(data)
            .map_err(|e| SigilError::StorageFailure(format!("JSON serialization failed: {e}")))?;

        let encrypted = encrypt_xchacha20poly1305(volume_key, &json_bytes, b"")?;
        json_bytes.zeroize();

        atomic_replace(&self.data_path(), &encrypted)
    }
}
