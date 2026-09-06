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
}

pub struct ServiceInner {
    pub store: FileVaultStore,
    pub locked_key: Option<LockedKeyBox>,
    pub collections: HashMap<String, CollectionRecord>,
}

#[derive(Clone)]
pub struct SigilService {
    inner: Arc<RwLock<ServiceInner>>,
}

impl SigilService {
    pub fn new(store: FileVaultStore) -> Self {
        let mut collections = HashMap::new();
        // Ensure default "login" collection exists in state
        collections.insert(
            "login".to_string(),
            CollectionRecord {
                id: "login".to_string(),
                label: "Login".to_string(),
                items: HashMap::new(),
            },
        );

        Self {
            inner: Arc::new(RwLock::new(ServiceInner {
                store,
                locked_key: None,
                collections,
            })),
        }
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
                inner.collections.insert(
                    col.id.clone(),
                    CollectionRecord {
                        id: col.id,
                        label: col.label,
                        items,
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
        inner.collections.insert(
            id.to_string(),
            CollectionRecord {
                id: id.to_string(),
                label: label.to_string(),
                items: HashMap::new(),
            },
        );
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
                    legacy_secret: None,
                    content_type: item.content_type.clone(),
                    created_at: item.created_at,
                    modified_at: item.modified_at,
                });
            }
            collections_data.push(StoredCollection {
                id: col.id.clone(),
                label: col.label.clone(),
                items: items_data,
            });
        }

        let vault_data = StoredVaultData {
            version: 1,
            collections: collections_data,
        };

        inner.store.save(&master_key, &vault_data)
    }
}
