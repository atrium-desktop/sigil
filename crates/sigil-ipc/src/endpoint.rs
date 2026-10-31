use std::path::{Path, PathBuf};

pub const DEFAULT_SOCKET_SUBPATH: &str = "sigil/native.sock";

/// Returns the default native socket path for the current user session:
/// Checks `SIGIL_SOCKET_PATH` env var first, then `$XDG_RUNTIME_DIR/sigil/native.sock`,
/// falling back to `/tmp/sigil/native.sock`.
pub fn default_socket_path() -> PathBuf {
    if let Ok(path) = std::env::var("SIGIL_SOCKET_PATH") {
        if !path.is_empty() {
            return PathBuf::from(path);
        }
    }
    let runtime_dir = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(runtime_dir).join(DEFAULT_SOCKET_SUBPATH)
}

/// Returns the native socket path for a specific UID (typically used by PAM modules).
pub fn socket_path_for_uid(uid: u32) -> PathBuf {
    PathBuf::from(format!("/run/user/{uid}/sigil/native.sock"))
}

/// Resolves custom path if provided, otherwise falls back to `default_socket_path()`.
pub fn resolve_socket_path(custom: Option<&Path>) -> PathBuf {
    match custom {
        Some(p) => p.to_path_buf(),
        None => default_socket_path(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socket_path_for_uid() {
        assert_eq!(
            socket_path_for_uid(1000),
            PathBuf::from("/run/user/1000/sigil/native.sock")
        );
    }
}
