pub mod frame;
pub mod peer;
pub mod protocol;
pub mod server;

pub use frame::{
    read_request, read_response, read_response_sync, write_request, write_request_sync,
    write_response,
};
pub use peer::check_peer_credentials;
pub use protocol::{IpcRequest, IpcResponse, PromptResponse};
pub use server::NativeIpcServer;

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_crypto::MasterKey;
    use sigil_service::SigilService;
    use sigil_store::FileVaultStore;
    use tokio::net::UnixStream;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_ipc_server_client_flow() {
        let temp_dir = std::env::temp_dir().join(format!("sigil_ipc_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);

        let sock_path = temp_dir.join("native.sock");
        let store = FileVaultStore::new(temp_dir.clone());
        let service = SigilService::new(store.clone());

        let key = MasterKey::generate();
        service.unlock_with_master_key(key).await.unwrap();

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

        let mut stream = UnixStream::connect(&sock_path).await.unwrap();

        // Ping
        write_request(&mut stream, &IpcRequest::Ping).await.unwrap();
        let resp = read_response(&mut stream).await.unwrap();
        assert!(matches!(resp, IpcResponse::Success));

        // GetApplicationSecret
        write_request(
            &mut stream,
            &IpcRequest::GetApplicationSecret {
                namespace: "xdg-portal".into(),
                subject: "org.mozilla.Firefox".into(),
                purpose: "master-secret".into(),
            },
        )
        .await
        .unwrap();

        let resp = read_response(&mut stream).await.unwrap();
        match resp {
            IpcResponse::Secret(bytes) => assert_eq!(bytes.len(), 32),
            other => panic!("Expected Secret, got {:?}", other),
        }

        // Setup password vault on disk first via envelope initialization
        let password = "TestPassword123!";
        store.initialize_with_password(password).unwrap();

        // Lock the service
        write_request(&mut stream, &IpcRequest::Lock).await.unwrap();
        let resp = read_response(&mut stream).await.unwrap();
        assert!(matches!(resp, IpcResponse::Success));
        assert_eq!(service.lock_state().await, sigil_domain::LockState::Locked);

        // Unlock using synchronous socket (mimicking PAM module)
        let mut sync_stream = std::os::unix::net::UnixStream::connect(&sock_path).unwrap();
        write_request_sync(
            &mut sync_stream,
            &IpcRequest::UnlockWithPassword {
                password: password.to_string(),
            },
        )
        .unwrap();
        let sync_resp = read_response_sync(&mut sync_stream).unwrap();
        assert!(matches!(sync_resp, IpcResponse::Success));
        assert_eq!(service.lock_state().await, sigil_domain::LockState::Unlocked);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
