use sigil_crypto::MasterKey;
use sigil_vault::{FileVaultStore, SigilService};
use std::collections::HashMap;

#[tokio::test]
async fn test_vault_backup_export_and_import() {
    let temp_dir_a =
        std::env::temp_dir().join(format!("sigil_backup_test_a_{}", std::process::id()));
    let temp_dir_b =
        std::env::temp_dir().join(format!("sigil_backup_test_b_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp_dir_a);
    let _ = std::fs::remove_dir_all(&temp_dir_b);

    // 1. Setup Vault A and populate credentials
    let store_a = FileVaultStore::new(temp_dir_a.clone());
    let service_a = SigilService::new(store_a);
    let master_key_a = MasterKey::generate();
    service_a
        .unlock_with_master_key(master_key_a)
        .await
        .unwrap();

    service_a
        .create_collection("personal", "Personal Credentials")
        .await
        .unwrap();

    service_a
        .set_item(
            "personal",
            "email",
            "Work Email",
            HashMap::from([("user".into(), "alice@example.com".into())]),
            b"secret-email-password",
            "text/plain",
            false,
        )
        .await
        .unwrap();

    service_a
        .set_item(
            "login",
            "ssh-key",
            "Server SSH Key",
            HashMap::from([("host".into(), "prod.server".into())]),
            b"ssh-rsa AAAA... confidential-key",
            "text/plain",
            false,
        )
        .await
        .unwrap();

    // 2. Export Vault A with a dedicated backup password
    let backup_pwd = "my-hardened-backup-passphrase-2026";
    let backup_bytes = service_a.export_vault_archive(backup_pwd).await.unwrap();
    assert!(!backup_bytes.is_empty());

    // 3. Setup fresh Vault B
    let store_b = FileVaultStore::new(temp_dir_b.clone());
    let service_b = SigilService::new(store_b);
    let master_key_b = MasterKey::generate();
    service_b
        .unlock_with_master_key(master_key_b)
        .await
        .unwrap();

    // Attempting import with wrong password must fail
    assert!(service_b
        .import_vault_archive(&backup_bytes, "wrong-password")
        .await
        .is_err());

    // Import with correct password succeeds
    let imported_count = service_b
        .import_vault_archive(&backup_bytes, backup_pwd)
        .await
        .unwrap();
    assert_eq!(imported_count, 2);

    // 4. Verify all items restored with accurate contents in Vault B
    let email_item = service_b.get_item("personal", "email").await.unwrap();
    assert_eq!(email_item.label, "Work Email");
    assert_eq!(
        email_item.attributes.get("user").map(String::as_str),
        Some("alice@example.com")
    );
    let email_sec = service_b
        .get_item_secret("personal", "email")
        .await
        .unwrap();
    assert_eq!(email_sec.as_slice(), b"secret-email-password");

    let ssh_item = service_b.get_item("login", "ssh-key").await.unwrap();
    assert_eq!(ssh_item.label, "Server SSH Key");
    let ssh_sec = service_b.get_item_secret("login", "ssh-key").await.unwrap();
    assert_eq!(ssh_sec.as_slice(), b"ssh-rsa AAAA... confidential-key");

    // Clean up
    let _ = std::fs::remove_dir_all(&temp_dir_a);
    let _ = std::fs::remove_dir_all(&temp_dir_b);
}
