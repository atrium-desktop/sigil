use crate::domain::SecretBytes;
use crate::key::MasterKey;
use hkdf::Hkdf;
use sha2::Sha256;

/// Derives a stable 32-byte application secret for a specific namespace, subject, and purpose.
///
/// HKDF-SHA256:
/// PRK = MasterKey
/// Info = Namespace \0 Subject \0 Purpose
pub fn derive_app_secret(
    master_key: &MasterKey,
    namespace: &str,
    subject: &str,
    purpose: &str,
) -> SecretBytes {
    let mut info = Vec::with_capacity(namespace.len() + subject.len() + purpose.len() + 2);
    info.extend_from_slice(namespace.as_bytes());
    info.push(0);
    info.extend_from_slice(subject.as_bytes());
    info.push(0);
    info.extend_from_slice(purpose.as_bytes());

    let hk = Hkdf::<Sha256>::from_prk(master_key.as_bytes())
        .expect("MasterKey length is 32 bytes, which is valid for HKDF-SHA256 PRK");

    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm)
        .expect("32 bytes is well within 255 * 32 bytes expansion limit");

    SecretBytes::new(okm.to_vec())
}

/// Derives a dedicated 32-byte AEAD key for a specific item id.
pub fn derive_item_key(master_key: &MasterKey, item_id: &str) -> MasterKey {
    let mut info = Vec::with_capacity(14 + item_id.len());
    info.extend_from_slice(b"sigil.item/v1\0");
    info.extend_from_slice(item_id.as_bytes());

    let hk = Hkdf::<Sha256>::from_prk(master_key.as_bytes())
        .expect("MasterKey length is 32 bytes, which is valid for HKDF-SHA256 PRK");

    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm)
        .expect("32 bytes is well within expansion limit");

    MasterKey::new(okm)
}
