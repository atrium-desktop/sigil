use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const CURRENT_VAULT_VERSION: u32 = 2;

/// Format v2 metadata manifest for the envelope vault.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultMeta {
    #[serde(default = "default_vault_version")]
    pub version: u32,
    pub vault_uuid: String,
    pub created_at: u64,
    pub modified_at: u64,
    pub active_slots: Vec<u32>,
    #[serde(default)]
    pub desync_detected: bool,
}

impl Default for VaultMeta {
    fn default() -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            version: CURRENT_VAULT_VERSION,
            vault_uuid: format!("vault_{now}"),
            created_at: now,
            modified_at: now,
            active_slots: vec![0],
            desync_detected: false,
        }
    }
}

/// Format v2/v3 item representation with per-item AEAD encrypted secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredItem {
    pub id: String,
    pub label: String,
    pub attributes: HashMap<String, String>,
    #[serde(default)]
    pub encrypted_secret: Vec<u8>,
    #[serde(default, rename = "secret", skip_serializing)]
    pub legacy_secret: Option<Vec<u8>>,
    pub content_type: String,
    pub created_at: u64,
    pub modified_at: u64,
}

impl StoredItem {
    pub fn is_encrypted(&self) -> bool {
        !self.encrypted_secret.is_empty()
    }
}

/// In-memory representation of a collection in the vault.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredCollection {
    pub id: String,
    pub label: String,
    pub items: Vec<StoredItem>,
}

/// The root data structure serialized into encrypted vault payloads.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredVaultData {
    #[serde(default = "default_vault_version")]
    pub version: u32,
    pub collections: Vec<StoredCollection>,
}

fn default_vault_version() -> u32 {
    CURRENT_VAULT_VERSION
}

impl Default for StoredVaultData {
    fn default() -> Self {
        Self {
            version: CURRENT_VAULT_VERSION,
            collections: Vec::new(),
        }
    }
}
