pub mod crypto;
pub mod domain;
pub mod server;
pub mod service;
pub mod store;

pub use crypto::*;
pub use domain::*;
pub use server::NativeIpcServer;
pub use service::*;
pub use store::*;

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_ipc::{read_response, write_request, IpcRequest, IpcResponse};
    use tokio::net::UnixStream;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_ipc_server_client_flow() {
        let temp_dir = std::env::temp_dir().join(format!("sigil_ipc_core_test_{}", std::process::id()));
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

        // GetLockStatus
        write_request(&mut stream, &IpcRequest::GetLockStatus).await.unwrap();
        let resp = read_response(&mut stream).await.unwrap();
        assert!(matches!(resp, IpcResponse::LockStatus(LockState::Unlocked)));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
