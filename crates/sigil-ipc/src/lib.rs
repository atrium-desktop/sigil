pub mod error;
pub mod frame;
pub mod peer;
pub mod protocol;

pub use error::{IpcError, IpcResult};
pub use frame::{
    read_request, read_request_sync, read_response, read_response_sync, write_request,
    write_request_sync, write_response, write_response_sync, MAX_FRAME_SIZE,
};
pub use peer::check_peer_credentials;
pub use protocol::{IpcRequest, IpcResponse, LockState, PromptResponse, SecretBytes};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_frame_roundtrip() {
        let req = IpcRequest::Ping;
        let mut buf = Vec::new();
        write_request_sync(&mut buf, &req).unwrap();

        let mut cursor = std::io::Cursor::new(buf);
        let decoded = read_request_sync(&mut cursor).unwrap();
        assert!(matches!(decoded, IpcRequest::Ping));
    }

    #[tokio::test]
    async fn test_async_frame_roundtrip() {
        let resp = IpcResponse::Success;
        let mut buf = Vec::new();
        write_response(&mut buf, &resp).await.unwrap();

        let mut cursor = std::io::Cursor::new(buf);
        let decoded = read_response(&mut cursor).await.unwrap();
        assert!(matches!(decoded, IpcResponse::Success));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_peer_credentials_self() {
        let (s1, _s2) = std::os::unix::net::UnixStream::pair().unwrap();
        assert!(check_peer_credentials(&s1).is_ok());
    }
}
