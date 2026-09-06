use thiserror::Error;

#[derive(Error, Debug)]
pub enum IpcError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid protocol magic: {0:?}")]
    InvalidMagic([u8; 4]),

    #[error("Unsupported protocol version: {0}")]
    UnsupportedVersion(u8),

    #[error("Invalid opcode: {0}")]
    InvalidOpcode(u8),

    #[error("Invalid status: {0}")]
    InvalidStatus(u8),

    #[error("Malformed frame payload: {0}")]
    MalformedPayload(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Deserialization error: {0}")]
    Deserialization(String),

    #[error("Frame size {0} exceeds limit {1}")]
    FrameTooLarge(usize, usize),

    #[error("Access denied: {0}")]
    AccessDenied(String),

    #[error("Daemon error: {0}")]
    DaemonError(String),
}

pub type IpcResult<T> = std::result::Result<T, IpcError>;
