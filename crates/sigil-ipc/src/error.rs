use thiserror::Error;

#[derive(Error, Debug)]
pub enum IpcError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

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
