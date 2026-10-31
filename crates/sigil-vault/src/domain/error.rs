use thiserror::Error;

#[derive(Error, Debug)]
pub enum SigilError {
    #[error("Vault is locked")]
    Locked,

    #[error("Item or collection not found: {0}")]
    NotFound(String),

    #[error("Item or collection already exists: {0}")]
    AlreadyExists(String),

    #[error("Access denied: {0}")]
    AccessDenied(String),

    #[error("Invalid request or arguments: {0}")]
    InvalidRequest(String),

    #[error("Authentication required: {0}")]
    AuthenticationRequired(String),

    #[error("Authentication was cancelled")]
    Cancelled,

    #[error("Storage failure: {0}")]
    StorageFailure(String),

    #[error("Cryptographic operation failure: {0}")]
    CryptoFailure(String),

    #[error("Corrupt data or format violation: {0}")]
    CorruptData(String),

    #[error("IO failure: {0}")]
    Io(#[from] std::io::Error),

    #[error("Internal failure: {0}")]
    Internal(String),
}

impl From<sigil_crypto::CryptoError> for SigilError {
    fn from(err: sigil_crypto::CryptoError) -> Self {
        match err {
            sigil_crypto::CryptoError::CryptoFailure(msg) => SigilError::CryptoFailure(msg),
            sigil_crypto::CryptoError::CorruptData(msg) => SigilError::CorruptData(msg),
        }
    }
}

pub type Result<T> = std::result::Result<T, SigilError>;
