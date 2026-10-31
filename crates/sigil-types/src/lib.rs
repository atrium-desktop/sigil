use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::ops::Deref;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Protected secret-bearing memory container.
///
/// Implements `Zeroize` and `ZeroizeOnDrop` so secret bytes are zeroed out when dropped.
/// Explicitly avoids leaking contents in `Debug` and `Display` formatters.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn from_slice(slice: &[u8]) -> Self {
        Self(slice.to_vec())
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn expose_secret(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for SecretBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes([redacted; {} bytes])", self.0.len())
    }
}

impl fmt::Display for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[redacted; {} bytes]", self.0.len())
    }
}

/// Service lock state on wire protocol and in-memory engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LockState {
    Uninitialized,
    Locked,
    Unlocked,
    Desynced,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PromptResponse {
    pub password: Option<String>,
}

/// Strongly typed namespace (e.g., "xdg-portal", "secret-service", "atrium.portal.Secret/v1").
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Namespace(String);

impl Namespace {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Namespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&str> for Namespace {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for Namespace {
    fn from(s: String) -> Self {
        Self(s)
    }
}

/// Strongly typed subject/application identifier (e.g., "org.mozilla.Firefox", "default").
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Subject(String);

impl Subject {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Subject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&str> for Subject {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for Subject {
    fn from(s: String) -> Self {
        Self(s)
    }
}

/// Strongly typed credential purpose (e.g., "master-secret", "login-password").
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Purpose(String);

impl Purpose {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Purpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&str> for Purpose {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for Purpose {
    fn from(s: String) -> Self {
        Self(s)
    }
}

/// Unique ID identifying a stored credential.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CredentialId(String);

impl CredentialId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CredentialId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// An encrypted blob with metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedBlob {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// Credential kind category.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CredentialKind {
    ApplicationSecret,
    Password,
    Token,
    GenericSecret,
}

/// Credential metadata (label, attributes, timestamps).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialMetadata {
    pub label: String,
    pub attributes: HashMap<String, String>,
    pub created_at: u64,
    pub modified_at: u64,
}

/// Encodes binary bytes to a lowercase hex string.
pub fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut s, "{:02x}", b);
    }
    s
}

/// Decodes a lowercase or uppercase hex string to binary bytes.
pub fn decode_hex(s: &str) -> std::result::Result<Vec<u8>, String> {
    let trimmed = s.trim();
    if !trimmed.len().is_multiple_of(2) {
        return Err("Hex string has odd length".into());
    }
    let mut bytes = Vec::with_capacity(trimmed.len() / 2);
    for i in (0..trimmed.len()).step_by(2) {
        let byte = u8::from_str_radix(&trimmed[i..i + 2], 16)
            .map_err(|e| format!("Invalid hex digit at index {i}: {e}"))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_bytes_redaction() {
        let sec = SecretBytes::new(b"confidential".to_vec());
        let dbg = format!("{:?}", sec);
        assert!(!dbg.contains("confidential"));
        assert!(dbg.contains("redacted"));

        let disp = format!("{}", sec);
        assert!(!disp.contains("confidential"));
        assert!(disp.contains("redacted"));
        assert_eq!(sec.as_slice(), b"confidential");
    }

    #[test]
    fn test_domain_types_display_and_conversion() {
        let ns = Namespace::from("xdg-portal");
        assert_eq!(ns.as_str(), "xdg-portal");
        assert_eq!(format!("{}", ns), "xdg-portal");

        let subj = Subject::new("org.mozilla.Firefox");
        assert_eq!(subj.as_str(), "org.mozilla.Firefox");

        let purpose = Purpose::new("master-secret");
        assert_eq!(purpose.as_str(), "master-secret");
    }
}
