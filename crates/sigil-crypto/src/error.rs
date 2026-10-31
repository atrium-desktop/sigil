use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Crypto failure: {0}")]
    CryptoFailure(String),

    #[error("Corrupt data: {0}")]
    CorruptData(String),
}

pub type Result<T> = std::result::Result<T, CryptoError>;
