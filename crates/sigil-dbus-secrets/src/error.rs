use zbus::DBusError;

/// Standard D-Bus errors mandated by the FreeDesktop Secret Service specification.
#[derive(Debug, DBusError)]
#[zbus(prefix = "org.freedesktop.Secret.Error")]
pub enum SecretServiceError {
    #[zbus(error)]
    ZBus(zbus::Error),

    IsLocked(String),
    NoSuchObject(String),
    AlreadyExists(String),
    InvalidArgs(String),
    Failed(String),
}

impl From<sigil_vault::SigilError> for SecretServiceError {
    fn from(err: sigil_vault::SigilError) -> Self {
        match err {
            sigil_vault::SigilError::Locked => {
                SecretServiceError::IsLocked("The requested item or collection is locked".into())
            }
            sigil_vault::SigilError::NotFound(msg) => SecretServiceError::NoSuchObject(msg),
            sigil_vault::SigilError::AlreadyExists(msg) => SecretServiceError::AlreadyExists(msg),
            sigil_vault::SigilError::InvalidRequest(msg) => SecretServiceError::InvalidArgs(msg),
            other => SecretServiceError::Failed(other.to_string()),
        }
    }
}
