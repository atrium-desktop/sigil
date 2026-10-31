use crate::crypto::{
    decrypt_xchacha20poly1305, derive_app_secret, derive_item_key, encrypt_xchacha20poly1305,
    LockedKeyBox, MasterKey,
};
use crate::domain::{LockState, Namespace, Purpose, Result, SecretBytes, SigilError, Subject};
use crate::store::{FileVaultStore, StoredCollection, StoredItem, StoredVaultData};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::info;
use zeroize::Zeroize;

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Clone, Debug)]
pub struct ItemRecord {
    pub id: String,
    pub label: String,
    pub attributes: HashMap<String, String>,
    pub encrypted_secret: Vec<u8>,
    pub content_type: String,
    pub created_at: u64,
    pub modified_at: u64,
}

#[derive(Clone, Debug)]
pub struct CollectionRecord {
    pub id: String,
    pub label: String,
    pub items: HashMap<String, ItemRecord>,
    pub created_at: u64,
    pub modified_at: u64,
}

pub struct ServiceInner {
    pub store: FileVaultStore,
    pub locked_key: Option<LockedKeyBox>,
    pub collections: HashMap<String, CollectionRecord>,
}

#[derive(Clone)]
pub struct SigilService {
    inner: Arc<RwLock<ServiceInner>>,
    tokio_handle: Option<tokio::runtime::Handle>,
}

impl SigilService {
    pub fn new(store: FileVaultStore) -> Self {
        let tokio_handle = tokio::runtime::Handle::try_current().ok();
        let mut collections = HashMap::new();
        let now = current_timestamp();
        // Ensure default "login" collection exists in state
        collections.insert(
            "login".to_string(),
            CollectionRecord {
                id: "login".to_string(),
                label: "Login".to_string(),
                items: HashMap::new(),
                created_at: now,
                modified_at: now,
            },
        );

        Self {
            inner: Arc::new(RwLock::new(ServiceInner {
                store,
                locked_key: None,
                collections,
            })),
            tokio_handle,
        }
    }

    pub fn tokio_handle(&self) -> Option<tokio::runtime::Handle> {
        self.tokio_handle
            .clone()
            .or_else(|| tokio::runtime::Handle::try_current().ok())
    }

    pub async fn lock_state(&self) -> LockState {
        let inner = self.inner.read().await;
        if inner.locked_key.is_some() {
            LockState::Unlocked
        } else if !inner.store.exists() {
            LockState::Uninitialized
        } else if inner.store.is_desynced() {
            LockState::Desynced
        } else {
            LockState::Locked
        }
    }

    pub async fn is_locked(&self) -> bool {
        let inner = self.inner.read().await;
        inner.locked_key.is_none()
    }

    pub async fn lock(&self) -> Result<()> {
        let mut inner = self.inner.write().await;
        if inner.locked_key.take().is_some() {
            info!("Master key cleared from LockedMemoryBox. Credential service locked.");
        }
        for col in inner.collections.values_mut() {
            for item in col.items.values_mut() {
                item.encrypted_secret.zeroize();
            }
            col.items.clear();
        }
        Ok(())
    }

    pub async fn unlock_with_master_key(&self, key: MasterKey) -> Result<()> {
        let mut inner = self.inner.write().await;
        let now = current_timestamp();
        if inner.store.exists() {
            let data = inner.store.load(&key)?;
            inner.collections.clear();
            for col in data.collections {
                let mut items = HashMap::new();
                for item in col.items {
                    items.insert(
                        item.id.clone(),
                        ItemRecord {
                            id: item.id.clone(),
                            label: item.label.clone(),
                            attributes: item.attributes.clone(),
                            encrypted_secret: item.encrypted_secret.clone(),
                            content_type: item.content_type.clone(),
                            created_at: item.created_at,
                            modified_at: item.modified_at,
                        },
                    );
                }
                let col_created = if col.created_at == 0 {
                    now
                } else {
                    col.created_at
                };
                let col_modified = if col.modified_at == 0 {
                    now
                } else {
                    col.modified_at
                };
                inner.collections.insert(
                    col.id.clone(),
                    CollectionRecord {
                        id: col.id,
                        label: col.label,
                        items,
                        created_at: col_created,
                        modified_at: col_modified,
                    },
                );
            }
            // Ensure default login collection always present
            inner
                .collections
                .entry("login".to_string())
                .or_insert_with(|| CollectionRecord {
                    id: "login".to_string(),
                    label: "Login".to_string(),
                    items: HashMap::new(),
                    created_at: now,
                    modified_at: now,
                });
        }
        inner.locked_key = Some(LockedKeyBox::new(&key));
        info!("Credential service successfully unlocked (key memory-locked).");
        Ok(())
    }

    pub async fn unlock_with_password(&self, password: &str) -> Result<()> {
        let store = {
            let inner = self.inner.read().await;
            inner.store.clone()
        };
        // Zero-touch automatic provisioning if vault does not exist yet
        let key = if !store.exists() {
            info!(
                "No existing vault found. Auto-provisioning initial envelope vault with password."
            );
            store.initialize_with_password(password)?
        } else {
            store.unlock_with_password(password)?
        };
        self.unlock_with_master_key(key).await
    }

    pub async fn rotate_password(&self, old_password: &str, new_password: &str) -> Result<()> {
        let store = {
            let inner = self.inner.read().await;
            inner.store.clone()
        };
        store.rotate_password(old_password, new_password)
    }

    pub async fn recover_and_sync(&self, recovery_secret: &str, new_password: &str) -> Result<()> {
        let store = {
            let inner = self.inner.read().await;
            inner.store.clone()
        };
        let key = store.recover_and_sync(recovery_secret, new_password)?;
        self.unlock_with_master_key(key).await
    }

    /// Enrolls an emergency recovery key into Slot 1 while the vault is unlocked.
    pub async fn enroll_recovery_key(&self, recovery_key: &str) -> Result<()> {
        let inner = self.inner.read().await;
        let locked_key = inner.locked_key.as_ref().ok_or(SigilError::Locked)?;
        locked_key.expose_key(|key_bytes| {
            let volume_key = MasterKey::new(*key_bytes);
            inner.store.enroll_recovery_key(&volume_key, recovery_key)
        })
    }

    /// Unlocks the vault using the emergency recovery key from Slot 1.
    pub async fn unlock_with_recovery_key(&self, recovery_key: &str) -> Result<()> {
        let store = {
            let inner = self.inner.read().await;
            inner.store.clone()
        };
        let key = store.unseal_slot_with_recovery_key(recovery_key)?;
        self.unlock_with_master_key(key).await
    }

    pub async fn derive_app_secret(
        &self,
        namespace: &Namespace,
        subject: &Subject,
        purpose: &Purpose,
    ) -> Result<SecretBytes> {
        let inner = self.inner.read().await;
        let locked_key = inner.locked_key.as_ref().ok_or(SigilError::Locked)?;

        locked_key.expose_key(|key_bytes| {
            let key = MasterKey::new(*key_bytes);
            Ok(derive_app_secret(
                &key,
                namespace.as_str(),
                subject.as_str(),
                purpose.as_str(),
            ))
        })
    }

    pub async fn get_collection_ids(&self) -> Vec<String> {
        let inner = self.inner.read().await;
        inner.collections.keys().cloned().collect()
    }

    pub async fn get_collection(&self, id: &str) -> Result<CollectionRecord> {
        let inner = self.inner.read().await;
        inner
            .collections
            .get(id)
            .cloned()
            .ok_or_else(|| SigilError::NotFound(format!("Collection {id} not found")))
    }

    pub async fn create_collection(&self, id: &str, label: &str) -> Result<()> {
        let mut inner = self.inner.write().await;
        if inner.collections.contains_key(id) {
            return Err(SigilError::AlreadyExists(format!(
                "Collection {id} already exists"
            )));
        }
        let now = current_timestamp();
        inner.collections.insert(
            id.to_string(),
            CollectionRecord {
                id: id.to_string(),
                label: label.to_string(),
                items: HashMap::new(),
                created_at: now,
                modified_at: now,
            },
        );
        self.save_locked(&mut inner)?;
        Ok(())
    }

    pub async fn update_collection_label(&self, id: &str, new_label: &str) -> Result<()> {
        let mut inner = self.inner.write().await;
        let col = inner
            .collections
            .get_mut(id)
            .ok_or_else(|| SigilError::NotFound(format!("Collection {id} not found")))?;
        col.label = new_label.to_string();
        col.modified_at = current_timestamp();
        self.save_locked(&mut inner)?;
        Ok(())
    }

    pub async fn delete_collection(&self, id: &str) -> Result<()> {
        let mut inner = self.inner.write().await;
        if inner.collections.remove(id).is_none() {
            return Err(SigilError::NotFound(format!("Collection {id} not found")));
        }
        self.save_locked(&mut inner)?;
        Ok(())
    }

    pub async fn get_item(&self, collection_id: &str, item_id: &str) -> Result<ItemRecord> {
        let inner = self.inner.read().await;
        if inner.locked_key.is_none() {
            return Err(SigilError::Locked);
        }
        let col = inner
            .collections
            .get(collection_id)
            .ok_or_else(|| SigilError::NotFound(format!("Collection {collection_id} not found")))?;
        col.items
            .get(item_id)
            .cloned()
            .ok_or_else(|| SigilError::NotFound(format!("Item {item_id} not found")))
    }

    /// Decrypts an individual secret on-demand strictly when requested.
    /// Plaintext is never resident in daemon memory and is wiped on drop.
    pub async fn get_item_secret(&self, collection_id: &str, item_id: &str) -> Result<SecretBytes> {
        let inner = self.inner.read().await;
        let locked_key = inner.locked_key.as_ref().ok_or(SigilError::Locked)?;
        let col = inner
            .collections
            .get(collection_id)
            .ok_or_else(|| SigilError::NotFound(format!("Collection {collection_id} not found")))?;
        let item = col
            .items
            .get(item_id)
            .ok_or_else(|| SigilError::NotFound(format!("Item {item_id} not found")))?;

        locked_key.expose_key(|key_bytes| {
            let volume_key = MasterKey::new(*key_bytes);
            let item_key = derive_item_key(&volume_key, &item.id);
            let decrypted = decrypt_xchacha20poly1305(&item_key, &item.encrypted_secret, b"")?;
            Ok(decrypted)
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn set_item(
        &self,
        collection_id: &str,
        item_id: &str,
        label: &str,
        attributes: HashMap<String, String>,
        secret: &[u8],
        content_type: &str,
        replace: bool,
    ) -> Result<()> {
        let mut inner = self.inner.write().await;
        let locked_key = inner.locked_key.as_ref().ok_or(SigilError::Locked)?;

        let encrypted_secret = locked_key.expose_key(|key_bytes| {
            let volume_key = MasterKey::new(*key_bytes);
            let item_key = derive_item_key(&volume_key, item_id);
            encrypt_xchacha20poly1305(&item_key, secret, b"")
        })?;

        let col = inner
            .collections
            .get_mut(collection_id)
            .ok_or_else(|| SigilError::NotFound(format!("Collection {collection_id} not found")))?;

        let now = current_timestamp();
        if let Some(existing) = col.items.get_mut(item_id) {
            if !replace {
                return Err(SigilError::AlreadyExists(format!(
                    "Item {item_id} already exists"
                )));
            }
            existing.label = label.to_string();
            existing.attributes = attributes;
            existing.encrypted_secret = encrypted_secret;
            existing.content_type = content_type.to_string();
            existing.modified_at = now;
        } else {
            col.items.insert(
                item_id.to_string(),
                ItemRecord {
                    id: item_id.to_string(),
                    label: label.to_string(),
                    attributes,
                    encrypted_secret,
                    content_type: content_type.to_string(),
                    created_at: now,
                    modified_at: now,
                },
            );
        }

        self.save_locked(&mut inner)?;
        Ok(())
    }

    pub async fn delete_item(&self, collection_id: &str, item_id: &str) -> Result<()> {
        let mut inner = self.inner.write().await;
        if inner.locked_key.is_none() {
            return Err(SigilError::Locked);
        }
        let col = inner
            .collections
            .get_mut(collection_id)
            .ok_or_else(|| SigilError::NotFound(format!("Collection {collection_id} not found")))?;

        if col.items.remove(item_id).is_none() {
            return Err(SigilError::NotFound(format!("Item {item_id} not found")));
        }

        self.save_locked(&mut inner)?;
        Ok(())
    }

    pub async fn search_items(
        &self,
        collection_id: Option<&str>,
        attributes: &HashMap<String, String>,
    ) -> Result<Vec<(String, String)>> {
        let inner = self.inner.read().await;
        if inner.locked_key.is_none() {
            return Err(SigilError::Locked);
        }

        let mut matches = Vec::new();
        let target_collections: Vec<&CollectionRecord> = match collection_id {
            Some(id) => inner.collections.get(id).into_iter().collect(),
            None => inner.collections.values().collect(),
        };

        for col in target_collections {
            for item in col.items.values() {
                let all_match = attributes
                    .iter()
                    .all(|(k, v)| item.attributes.get(k).map(|iv| iv == v).unwrap_or(false));
                if all_match {
                    matches.push((col.id.clone(), item.id.clone()));
                }
            }
        }

        Ok(matches)
    }

    fn save_locked(&self, inner: &mut ServiceInner) -> Result<()> {
        let master_key = match inner.locked_key.as_ref() {
            Some(k) => k.to_master_key(),
            None => return Ok(()), // Not yet unlocked, don't write empty
        };

        let mut collections_data = Vec::new();
        for col in inner.collections.values() {
            let mut items_data = Vec::new();
            for item in col.items.values() {
                items_data.push(StoredItem {
                    id: item.id.clone(),
                    label: item.label.clone(),
                    attributes: item.attributes.clone(),
                    encrypted_secret: item.encrypted_secret.clone(),
                    content_type: item.content_type.clone(),
                    created_at: item.created_at,
                    modified_at: item.modified_at,
                });
            }
            collections_data.push(StoredCollection {
                id: col.id.clone(),
                label: col.label.clone(),
                items: items_data,
                created_at: col.created_at,
                modified_at: col.modified_at,
            });
        }

        let vault_data = StoredVaultData {
            version: 1,
            collections: collections_data,
        };

        inner.store.save(&master_key, &vault_data)
    }

    /// Exports the entire unlocked vault into an encrypted, portable backup archive.
    pub async fn export_vault_archive(&self, export_password: &str) -> Result<Vec<u8>> {
        let (collections, master_key) = {
            let inner = self.inner.read().await;
            let locked_key = inner.locked_key.as_ref().ok_or(SigilError::Locked)?;
            (inner.collections.clone(), locked_key.to_master_key())
        };

        let mut export_cols = Vec::new();
        for col in collections.values() {
            let mut export_items = Vec::new();
            for item in col.items.values() {
                let item_key = derive_item_key(&master_key, &item.id);
                let secret = decrypt_xchacha20poly1305(&item_key, &item.encrypted_secret, b"")?;
                export_items.push(DecryptedExportItem {
                    id: item.id.clone(),
                    label: item.label.clone(),
                    attributes: item.attributes.clone(),
                    secret: secret.as_slice().to_vec(),
                    content_type: item.content_type.clone(),
                    created_at: item.created_at,
                    modified_at: item.modified_at,
                });
            }
            export_cols.push(DecryptedExportCollection {
                id: col.id.clone(),
                label: col.label.clone(),
                items: export_items,
                created_at: col.created_at,
                modified_at: col.modified_at,
            });
        }

        let payload = VaultArchivePayload {
            exported_at: current_timestamp(),
            collections: export_cols,
        };

        let mut payload_bytes = serde_json::to_vec(&payload)
            .map_err(|e| SigilError::StorageFailure(format!("Export serialization failed: {e}")))?;

        let salt = crate::crypto::generate_salt(crate::crypto::DEFAULT_SALT_LEN);
        let kdf_params = crate::crypto::KdfParams::default();
        let derived_key =
            crate::crypto::derive_key_argon2id(export_password.as_bytes(), &salt, &kdf_params)?;

        let encrypted_payload =
            encrypt_xchacha20poly1305(&derived_key, &payload_bytes, b"sigil-backup-v1")?;
        payload_bytes.zeroize();

        let envelope = VaultBackupEnvelope {
            format: "sigil-backup".into(),
            version: 1,
            salt_hex: sigil_types::encode_hex(&salt),
            kdf_params,
            encrypted_payload,
        };

        serde_json::to_vec_pretty(&envelope)
            .map_err(|e| SigilError::StorageFailure(format!("Envelope serialization failed: {e}")))
    }

    /// Imports credentials from an encrypted backup archive into the active vault.
    pub async fn import_vault_archive(
        &self,
        archive_bytes: &[u8],
        export_password: &str,
    ) -> Result<usize> {
        let envelope: VaultBackupEnvelope = serde_json::from_slice(archive_bytes)
            .map_err(|e| SigilError::CorruptData(format!("Invalid backup archive format: {e}")))?;

        if envelope.format != "sigil-backup" || envelope.version != 1 {
            return Err(SigilError::CorruptData(
                "Unsupported backup archive format or version".into(),
            ));
        }

        let salt = sigil_types::decode_hex(&envelope.salt_hex)
            .map_err(|e| SigilError::CorruptData(format!("Invalid salt in backup: {e}")))?;

        let derived_key = crate::crypto::derive_key_argon2id(
            export_password.as_bytes(),
            &salt,
            &envelope.kdf_params,
        )?;
        let mut decrypted_payload = decrypt_xchacha20poly1305(
            &derived_key,
            &envelope.encrypted_payload,
            b"sigil-backup-v1",
        )?;

        let payload: VaultArchivePayload = serde_json::from_slice(decrypted_payload.as_slice())
            .map_err(|e| SigilError::CorruptData(format!("Corrupt archive payload: {e}")))?;
        decrypted_payload.zeroize();

        let mut imported_count = 0;
        for col in payload.collections {
            let _ = self.create_collection(&col.id, &col.label).await;
            for item in col.items {
                self.set_item(
                    &col.id,
                    &item.id,
                    &item.label,
                    item.attributes,
                    &item.secret,
                    &item.content_type,
                    true,
                )
                .await?;
                imported_count += 1;
            }
        }

        Ok(imported_count)
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct DecryptedExportItem {
    id: String,
    label: String,
    attributes: HashMap<String, String>,
    secret: Vec<u8>,
    content_type: String,
    created_at: u64,
    modified_at: u64,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct DecryptedExportCollection {
    id: String,
    label: String,
    items: Vec<DecryptedExportItem>,
    created_at: u64,
    modified_at: u64,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct VaultArchivePayload {
    exported_at: u64,
    collections: Vec<DecryptedExportCollection>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct VaultBackupEnvelope {
    format: String,
    version: u32,
    salt_hex: String,
    kdf_params: crate::crypto::KdfParams,
    encrypted_payload: Vec<u8>,
}
