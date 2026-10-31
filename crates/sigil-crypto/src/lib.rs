pub mod cipher;
pub mod error;
pub mod hkdf;
pub mod kdf;
pub mod key;
pub mod recovery;

pub use cipher::{decrypt_xchacha20poly1305, encrypt_xchacha20poly1305, NONCE_LEN};
pub use error::{CryptoError, Result as CryptoResult};
pub use hkdf::{derive_app_secret, derive_item_key};
pub use kdf::{
    decode_kdf, derive_key_argon2id, encode_kdf, generate_salt, KdfConfig, KdfParams,
    DEFAULT_SALT_LEN, KDF_FILE_VERSION, KDF_NAME,
};
pub use key::{LockedKeyBox, MasterKey, MASTER_KEY_LEN};
pub use recovery::{generate_recovery_key, normalize_recovery_key, RECOVERY_KEY_PREFIX};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xchacha20_roundtrip() {
        let key = MasterKey::generate();
        let plaintext = b"Hello, sigil cryptographic world!";
        let aad = b"context-metadata";

        let ciphertext = encrypt_xchacha20poly1305(&key, plaintext, aad).unwrap();
        assert_ne!(ciphertext, plaintext);

        let decrypted = decrypt_xchacha20poly1305(&key, &ciphertext, aad).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);

        // Tampered ciphertext fails
        let mut tampered = ciphertext.clone();
        let len = tampered.len();
        tampered[len - 1] ^= 0x01;
        assert!(decrypt_xchacha20poly1305(&key, &tampered, aad).is_err());

        // Wrong AAD fails
        assert!(decrypt_xchacha20poly1305(&key, &ciphertext, b"wrong-aad").is_err());
    }

    #[test]
    fn test_argon2id_derivation() {
        let password = b"correct horse battery staple";
        let salt = generate_salt(DEFAULT_SALT_LEN);
        let params = KdfParams {
            m_cost: 1024, // low memory for fast test
            t_cost: 1,
            p_cost: 1,
            version: 0x13,
        };

        let key1 = derive_key_argon2id(password, &salt, &params).unwrap();
        let key2 = derive_key_argon2id(password, &salt, &params).unwrap();
        assert_eq!(key1, key2);

        let wrong_key = derive_key_argon2id(b"wrong password", &salt, &params).unwrap();
        assert_ne!(key1, wrong_key);
    }

    #[test]
    fn test_hkdf_domain_isolation() {
        let key = MasterKey::generate();
        let s1 = derive_app_secret(&key, "xdg-portal", "org.mozilla.Firefox", "master-secret");
        let s2 = derive_app_secret(&key, "xdg-portal", "org.chromium.Chromium", "master-secret");
        let s3 = derive_app_secret(&key, "other-ns", "org.mozilla.Firefox", "master-secret");
        let s4 = derive_app_secret(&key, "xdg-portal", "org.mozilla.Firefox", "token");

        assert_eq!(s1.len(), 32);
        assert_ne!(s1.as_slice(), s2.as_slice());
        assert_ne!(s1.as_slice(), s3.as_slice());
        assert_ne!(s1.as_slice(), s4.as_slice());
    }

    #[test]
    fn test_locked_key_box() {
        let key = MasterKey::generate();
        let key_box = LockedKeyBox::new(&key);

        key_box.expose_key(|slice| {
            assert_eq!(slice, key.as_bytes());
        });

        let recovered = key_box.to_master_key();
        assert_eq!(recovered.as_bytes(), key.as_bytes());
        drop(key_box);
    }

    #[test]
    fn test_master_key_hex_and_slice() {
        let key = MasterKey::generate();
        let hex = key.to_hex();
        assert_eq!(hex.len(), 64);

        let parsed = MasterKey::from_hex(&hex).unwrap();
        assert_eq!(parsed.as_bytes(), key.as_bytes());

        let from_slice = MasterKey::from_slice(key.as_bytes()).unwrap();
        assert_eq!(from_slice.as_bytes(), key.as_bytes());

        // Invalid lengths fail
        assert!(MasterKey::from_slice(&[0u8; 16]).is_err());
        assert!(MasterKey::from_hex("001122").is_err());
    }

    #[test]
    fn test_kdf_encoding_roundtrip() {
        let params = KdfParams {
            m_cost: 16384,
            t_cost: 2,
            p_cost: 2,
            version: 0x13,
        };
        let salt = "abcdef0123456789";
        let encoded = encode_kdf(&params, salt).unwrap();
        let (decoded_params, decoded_salt) = decode_kdf(&encoded).unwrap();
        assert_eq!(decoded_params, params);
        assert_eq!(decoded_salt, salt);
    }
}
