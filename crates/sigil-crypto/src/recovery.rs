use crate::error::{CryptoError, Result};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroize;

const CROCKFORD_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
pub const RECOVERY_KEY_PREFIX: &str = "SIGIL-RKEY";
pub const RECOVERY_KEY_ENTROPY_BYTES: usize = 20; // 160 bits of CSPRNG entropy
pub const RECOVERY_KEY_RAW_CHARS: usize = 32;

/// Generates a new 160-bit cryptographically secure emergency recovery key.
/// Returns the formatted key string: `SIGIL-RKEY-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`.
pub fn generate_recovery_key() -> String {
    let mut entropy = [0u8; RECOVERY_KEY_ENTROPY_BYTES];
    OsRng.fill_bytes(&mut entropy);
    let key = encode_crockford_160(&entropy);
    entropy.zeroize();
    key
}

/// Encodes 20 bytes into 32 Crockford Base32 characters grouped into 8 chunks of 4.
fn encode_crockford_160(bytes: &[u8; 20]) -> String {
    let mut chars = Vec::with_capacity(32);

    let (chunks, _) = bytes.as_chunks::<5>();
    for chunk in chunks {
        let b0 = chunk[0] as u64;
        let b1 = chunk[1] as u64;
        let b2 = chunk[2] as u64;
        let b3 = chunk[3] as u64;
        let b4 = chunk[4] as u64;

        let num: u64 = (b0 << 32) | (b1 << 24) | (b2 << 16) | (b3 << 8) | b4;

        for i in (0..8).rev() {
            let idx = ((num >> (i * 5)) & 0x1F) as usize;
            chars.push(CROCKFORD_ALPHABET[idx] as char);
        }
    }

    // Format with prefix and hyphens: SIGIL-RKEY-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX
    let mut formatted = String::with_capacity(53);
    formatted.push_str(RECOVERY_KEY_PREFIX);

    for (i, c) in chars.iter().enumerate() {
        if i % 4 == 0 {
            formatted.push('-');
        }
        formatted.push(*c);
    }

    formatted
}

/// Normalizes and validates a user-entered recovery key:
/// - Strips optional `SIGIL-RKEY-` prefix
/// - Strips hyphens, underscores, and whitespace
/// - Converts to uppercase
/// - Auto-corrects typo-prone characters (I/L -> 1, O -> 0)
/// - Validates Crockford Base32 alphabet and exact length
///
/// Returns the canonical formatted string: `SIGIL-RKEY-XXXX-XXXX-...`.
pub fn normalize_recovery_key(input: &str) -> Result<String> {
    let trimmed = input.trim();
    let body_start = if let Some(rest) = trimmed
        .strip_prefix("SIGIL-RKEY-")
        .or_else(|| trimmed.strip_prefix("sigil-rkey-"))
        .or_else(|| trimmed.strip_prefix("SIGIL-RKEY:"))
        .or_else(|| trimmed.strip_prefix("sigil-rkey:"))
        .or_else(|| trimmed.strip_prefix("SIGIL-RKEY "))
        .or_else(|| trimmed.strip_prefix("sigil-rkey "))
        .or_else(|| trimmed.strip_prefix("SIGIL-RKEY"))
        .or_else(|| trimmed.strip_prefix("sigil-rkey"))
        .or_else(|| trimmed.strip_prefix("SIGIL RKEY "))
        .or_else(|| trimmed.strip_prefix("sigil rkey "))
    {
        rest
    } else {
        trimmed
    };

    let mut clean_chars = Vec::with_capacity(32);
    for c in body_start.chars() {
        if c == '-' || c == '_' || c.is_whitespace() || c == ':' {
            continue;
        }
        let mapped = match c.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            other => other,
        };

        if !CROCKFORD_ALPHABET.contains(&(mapped as u8)) {
            return Err(CryptoError::CryptoFailure(format!(
                "Invalid character '{c}' in recovery key"
            )));
        }
        clean_chars.push(mapped);
    }

    if clean_chars.len() != RECOVERY_KEY_RAW_CHARS {
        return Err(CryptoError::CryptoFailure(format!(
            "Recovery key must contain exactly {RECOVERY_KEY_RAW_CHARS} characters (got {})",
            clean_chars.len()
        )));
    }

    let mut canonical = String::with_capacity(50);
    canonical.push_str(RECOVERY_KEY_PREFIX);
    for (i, c) in clean_chars.iter().enumerate() {
        if i % 4 == 0 {
            canonical.push('-');
        }
        canonical.push(*c);
    }

    Ok(canonical)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_normalize_recovery_key() {
        let key = generate_recovery_key();
        assert!(key.starts_with("SIGIL-RKEY-"));
        assert_eq!(key.len(), 50); // "SIGIL-RKEY" (10) + 8 * ("-" + 4 chars) (40) = 50 chars.

        let normalized = normalize_recovery_key(&key).unwrap();
        assert_eq!(normalized, key);
    }

    #[test]
    fn test_recovery_key_typo_correction() {
        // Test lower-case, missing prefix, O -> 0, l/I -> 1
        let raw = "0123-4567-89ab-cdef-ghjk-mnpq-rstv-wxy1";
        let norm = normalize_recovery_key(raw).unwrap();
        assert!(norm.starts_with("SIGIL-RKEY-"));

        // O and L typo correction: o -> 0, L -> 1
        let typo = "o123-4567-89ab-cdef-ghjk-mnpq-rstv-wxyL";
        let norm2 = normalize_recovery_key(typo).unwrap();
        assert_eq!(norm, norm2);
    }

    #[test]
    fn test_invalid_length_or_char() {
        assert!(normalize_recovery_key("SIGIL-RKEY-TOO-SHORT").is_err());
        assert!(
            normalize_recovery_key("SIGIL-RKEY-0123-4567-89AB-CDEF-GHJK-MNPQ-RSTV-WXYZ-EXTRA")
                .is_err()
        );
        // 'U' is excluded from Crockford Base32
        assert!(
            normalize_recovery_key("SIGIL-RKEY-0123-4567-89AB-CDEF-GHJK-MNPQ-RSTV-WXYU").is_err()
        );
    }
}
