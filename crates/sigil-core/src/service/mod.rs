pub mod state;

pub use state::{CollectionRecord, ItemRecord, SigilService};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::MasterKey;
    use crate::domain::{LockState, Namespace, Purpose, Subject};
    use crate::store::FileVaultStore;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_service_lifecycle_and_crud() {
        let temp_dir = std::env::temp_dir().join(format!("sigil_svc_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);

        let store = FileVaultStore::new(temp_dir.clone());
        let service = SigilService::new(store);

        assert!(service.is_locked().await);

        // Derive secret while locked fails
        let res = service
            .derive_app_secret(
                &Namespace::new("xdg-portal"),
                &Subject::new("org.mozilla.Firefox"),
                &Purpose::new("master-secret"),
            )
            .await;
        assert!(res.is_err());

        // Unlock
        let key = MasterKey::generate();
        service.unlock_with_master_key(key).await.unwrap();
        assert!(!service.is_locked().await);

        // Derive secret succeeds
        let sec = service
            .derive_app_secret(
                &Namespace::new("xdg-portal"),
                &Subject::new("org.mozilla.Firefox"),
                &Purpose::new("master-secret"),
            )
            .await
            .unwrap();
        assert_eq!(sec.len(), 32);

        // Item CRUD
        service
            .set_item(
                "login",
                "item-1",
                "Test Label",
                HashMap::from([("service".into(), "github.com".into())]),
                b"my-password",
                "text/plain",
                false,
            )
            .await
            .unwrap();

        let item = service.get_item("login", "item-1").await.unwrap();
        assert_eq!(item.label, "Test Label");
        let secret = service.get_item_secret("login", "item-1").await.unwrap();
        assert_eq!(secret.as_slice(), b"my-password");

        // Search
        let matches = service
            .search_items(
                None,
                &HashMap::from([("service".into(), "github.com".into())]),
            )
            .await
            .unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0], ("login".into(), "item-1".into()));

        // Lock
        service.lock().await.unwrap();
        assert!(service.is_locked().await);
        assert!(service.get_item("login", "item-1").await.is_err());

        // Cleanup
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_auto_provision_rotate_and_recover() {
        let temp_dir = std::env::temp_dir().join(format!("sigil_svc_auto_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);

        let store = FileVaultStore::new(temp_dir.clone());
        let service = SigilService::new(store.clone());

        assert_eq!(service.lock_state().await, LockState::Uninitialized);

        // Auto-provision via unlock_with_password
        service
            .unlock_with_password("my-initial-pwd")
            .await
            .unwrap();
        assert_eq!(service.lock_state().await, LockState::Unlocked);

        // Store an item and save
        service
            .set_item(
                "login",
                "vault-secret",
                "My Secret",
                HashMap::new(),
                b"confidential-data",
                "text/plain",
                false,
            )
            .await
            .unwrap();

        // Lock
        service.lock().await.unwrap();
        assert_eq!(service.lock_state().await, LockState::Locked);

        // Rotate password
        service
            .rotate_password("my-initial-pwd", "my-new-pwd")
            .await
            .unwrap();

        // Old password fails
        assert!(service
            .unlock_with_password("my-initial-pwd")
            .await
            .is_err());

        // New password unlocks
        service.unlock_with_password("my-new-pwd").await.unwrap();
        assert_eq!(service.lock_state().await, LockState::Unlocked);
        let item = service.get_item("login", "vault-secret").await.unwrap();
        assert_eq!(item.label, "My Secret");
        let secret = service
            .get_item_secret("login", "vault-secret")
            .await
            .unwrap();
        assert_eq!(secret.as_slice(), b"confidential-data");

        // Simulate desync
        service.lock().await.unwrap();
        store.mark_desynced(true).unwrap();
        assert_eq!(service.lock_state().await, LockState::Desynced);

        // Recover and sync with new session password
        service
            .recover_and_sync("my-new-pwd", "recovered-pwd")
            .await
            .unwrap();
        assert_eq!(service.lock_state().await, LockState::Unlocked);
        assert!(!store.is_desynced());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
