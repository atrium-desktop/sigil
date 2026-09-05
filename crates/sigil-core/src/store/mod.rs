pub mod file_store;
pub mod model;

pub use file_store::{
    atomic_replace, ensure_secure_dir, FileVaultStore, VAULT_DATA_FILENAME, VAULT_META_FILENAME,
    VAULT_SLOTS_DIRNAME,
};
pub use model::{StoredCollection, StoredItem, StoredVaultData, VaultMeta, CURRENT_VAULT_VERSION};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::MasterKey;
    use std::collections::HashMap;

    #[test]
    fn test_file_store_roundtrip() {
        let temp_dir = std::env::temp_dir().join(format!("sigil_test_store_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);

        let store = FileVaultStore::new(temp_dir.clone());
        assert!(!store.exists());

        let key = MasterKey::generate();
        let mut data = StoredVaultData::default();
        data.collections.push(StoredCollection {
            id: "login".into(),
            label: "Login".into(),
            items: vec![StoredItem {
                id: "item1".into(),
                label: "My Password".into(),
                attributes: HashMap::from([("xdg:schema".into(), "login".into())]),
                secret: b"super-secret-pw".to_vec(),
                content_type: "text/plain".into(),
                created_at: 100,
                modified_at: 100,
            }],
        });

        store.save(&key, &data).unwrap();
        assert!(store.exists());

        let loaded = store.load(&key).unwrap();
        assert_eq!(loaded.collections.len(), 1);
        assert_eq!(loaded.collections[0].items.len(), 1);
        assert_eq!(loaded.collections[0].items[0].label, "My Password");
        assert_eq!(loaded.collections[0].items[0].secret, b"super-secret-pw");

        // Clean up
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_envelope_slot_lifecycle_and_rotation() {
        let temp_dir = std::env::temp_dir().join(format!("sigil_test_slot_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);

        let store = FileVaultStore::new(temp_dir.clone());
        assert!(!store.exists());

        // 1. Initial provision with password
        let vol_key = store.initialize_with_password("initial-pass").unwrap();
        assert!(store.exists());
        assert!(!store.is_desynced());

        // Save some confidential item
        let mut data = StoredVaultData::default();
        data.collections.push(StoredCollection {
            id: "login".into(),
            label: "Login".into(),
            items: vec![StoredItem {
                id: "secret1".into(),
                label: "Bank Account".into(),
                attributes: HashMap::new(),
                secret: b"12345678".to_vec(),
                content_type: "text/plain".into(),
                created_at: 200,
                modified_at: 200,
            }],
        });
        store.save(&vol_key, &data).unwrap();

        // 2. Unlock with password
        let unlocked_key = store.unlock_with_password("initial-pass").unwrap();
        assert_eq!(vol_key.as_bytes(), unlocked_key.as_bytes());

        // Unlock with bad password fails
        assert!(store.unlock_with_password("wrong-pass").is_err());

        // 3. Rotate password (e.g. pam_sm_chauthtok)
        store.rotate_password("initial-pass", "new-system-pass").unwrap();

        // Old password fails, new password succeeds
        assert!(store.unlock_with_password("initial-pass").is_err());
        let rotated_key = store.unlock_with_password("new-system-pass").unwrap();
        assert_eq!(vol_key.as_bytes(), rotated_key.as_bytes());

        // Data is still completely intact
        let loaded = store.load(&rotated_key).unwrap();
        assert_eq!(loaded.collections[0].items[0].label, "Bank Account");

        // 4. Test out-of-band desync and self-healing recovery
        store.mark_desynced(true).unwrap();
        assert!(store.is_desynced());

        let recovered_key = store.recover_and_sync("new-system-pass", "final-pass").unwrap();
        assert_eq!(vol_key.as_bytes(), recovered_key.as_bytes());
        assert!(!store.is_desynced());

        // Now final-pass unlocks smoothly
        let final_key = store.unlock_with_password("final-pass").unwrap();
        assert_eq!(vol_key.as_bytes(), final_key.as_bytes());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
