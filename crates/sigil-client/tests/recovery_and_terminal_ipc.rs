use sigil_client::SigilClient;
use sigil_crypto::generate_recovery_key;
use sigil_ipc_server::NativeIpcServer;
use sigil_vault::{FileVaultStore, SigilService};
use std::os::unix::fs::PermissionsExt;

#[tokio::test]
async fn test_recovery_key_ipc_lifecycle() {
    let temp_dir =
        std::env::temp_dir().join(format!("sigil_recovery_ipc_test_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(&temp_dir).unwrap();
    std::fs::set_permissions(&temp_dir, std::fs::Permissions::from_mode(0o700)).unwrap();

    let sock_path = temp_dir.join("native.sock");
    let store = FileVaultStore::new(temp_dir.clone());
    let service = SigilService::new(store);

    let server = NativeIpcServer::new(sock_path.clone(), service.clone());
    tokio::spawn(async move {
        let _ = server.run().await;
    });

    for _ in 0..50 {
        if sock_path.exists() {
            break;
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }

    let client = SigilClient::new(sock_path);

    // Initial state: locked / uninitialized
    assert!(client.is_locked().await.unwrap());

    // 1. Provision / unlock with initial password
    client
        .unlock_with_password("my-initial-password")
        .await
        .unwrap();
    assert!(!client.is_locked().await.unwrap());

    // 2. Generate and enroll recovery key into Slot 1
    let rkey = generate_recovery_key();
    assert!(rkey.starts_with("SIGIL-RKEY-"));
    client.enroll_recovery_key(&rkey).await.unwrap();

    // 3. Lock the vault
    client.lock().await.unwrap();
    assert!(client.is_locked().await.unwrap());

    // 4. Unlock with recovery key
    client.unlock_with_recovery_key(&rkey).await.unwrap();
    assert!(!client.is_locked().await.unwrap());

    // 5. Lock and unlock with typo-tolerant recovery key (lowercase, spaces instead of dashes)
    client.lock().await.unwrap();
    assert!(client.is_locked().await.unwrap());

    let typo_key = rkey.to_lowercase().replace('-', " ");
    client.unlock_with_recovery_key(&typo_key).await.unwrap();
    assert!(!client.is_locked().await.unwrap());

    let _ = std::fs::remove_dir_all(&temp_dir);
}
