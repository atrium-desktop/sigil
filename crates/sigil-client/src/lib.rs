pub mod client;
pub mod error;

pub use client::{SigilClient, DEFAULT_SOCKET_SUBPATH};
pub use error::{ClientError, Result};

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_core::{FileVaultStore, MasterKey, NativeIpcServer, SigilService};

    #[tokio::test]
    async fn test_client_integration() {
        let temp_dir = std::env::temp_dir().join(format!("sigil_client_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);

        let sock_path = temp_dir.join("native.sock");
        let store = FileVaultStore::new(temp_dir.clone());
        let service = SigilService::new(store.clone());

        let server = NativeIpcServer::new(sock_path.clone(), service.clone());
        tokio::spawn(async move {
            let _ = server.run().await;
        });

        // Wait for socket to be ready
        for _ in 0..50 {
            if sock_path.exists() {
                break;
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }

        let client = SigilClient::new(sock_path);

        // Ping works
        client.ping().await.unwrap();

        // While locked, get_application_secret returns ClientError::Locked
        assert!(client.is_locked().await.unwrap());
        let err = client
            .get_application_secret("xdg-portal", "org.test.App", "master-secret")
            .await;
        assert!(matches!(err, Err(ClientError::Locked)));

        // Unlock
        let key = MasterKey::generate();
        service.unlock_with_master_key(key).await.unwrap();
        assert!(!client.is_locked().await.unwrap());

        // Now secret retrieval succeeds
        let sec = client
            .get_application_secret("xdg-portal", "org.test.App", "master-secret")
            .await
            .unwrap();
        assert_eq!(sec.len(), 32);

        // Lock via client
        client.lock().await.unwrap();
        assert!(client.is_locked().await.unwrap());

        // Setup password vault and unlock with password via client
        let pwd = "super-secret-passphrase";
        store.initialize_with_password(pwd).unwrap();

        client.unlock_with_password(pwd).await.unwrap();
        assert!(!client.is_locked().await.unwrap());

        // Test rotate password via client
        client.rotate_password(pwd, "rotated-passphrase").await.unwrap();
        client.lock().await.unwrap();
        assert!(client.unlock_with_password(pwd).await.is_err());
        client.unlock_with_password("rotated-passphrase").await.unwrap();
        assert!(!client.is_locked().await.unwrap());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
