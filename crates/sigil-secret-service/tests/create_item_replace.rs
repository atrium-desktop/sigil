//! Regression test for `Collection.CreateItem` replace semantics.
//!
//! The Secret Service spec says: "If replace is set, then it replaces an item
//! already present with the same values for the attributes." Previously the
//! handler always generated a fresh random item id, so every store created a
//! duplicate item. Clients such as gh's go-keyring then accumulated stale
//! copies of the same credential.

use std::collections::HashMap;
use std::sync::Arc;

use sigil_core::{FileVaultStore, SigilService};
use sigil_secret_service::{Collection, SecretStruct, Session};
use tokio::sync::RwLock;
use zbus::zvariant::{OwnedObjectPath, Value};

#[tokio::test]
async fn create_item_with_replace_keeps_a_single_item() {
    let dir = std::env::temp_dir().join(format!(
        "sigil_create_item_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let service = SigilService::new(FileVaultStore::new(dir.clone()));
    service.unlock_with_password("test-password").await.unwrap();

    let sessions = Arc::new(RwLock::new(HashMap::new()));
    let session_path =
        OwnedObjectPath::try_from("/org/freedesktop/secrets/session/s_test").unwrap();
    sessions.write().await.insert(
        session_path.clone(),
        Arc::new(Session::new_plain(session_path.clone())),
    );

    let collection = Collection {
        id: "login".to_string(),
        service: service.clone(),
        sessions: sessions.clone(),
    };

    let name = format!("com.example.SigilCreateItemTest{}", std::process::id());
    let path = "/org/freedesktop/secrets/collection/login";
    let conn = zbus::connection::Builder::session()
        .unwrap()
        .name(name.clone())
        .unwrap()
        .serve_at(path, collection)
        .unwrap()
        .build()
        .await
        .unwrap();

    let mut attributes = HashMap::new();
    attributes.insert("service".to_string(), "gh:github.com".to_string());
    attributes.insert("username".to_string(), "ming2k".to_string());

    let mut properties: HashMap<String, Value<'_>> = HashMap::new();
    properties.insert(
        "org.freedesktop.Secret.Item.Label".to_string(),
        Value::from("test"),
    );
    properties.insert(
        "org.freedesktop.Secret.Item.Attributes".to_string(),
        Value::from(attributes),
    );

    for value in [b"token-one".as_slice(), b"token-two".as_slice()] {
        let secret = SecretStruct {
            session: session_path.clone(),
            parameters: vec![],
            value: value.to_vec(),
            content_type: "text/plain".to_string(),
        };
        conn.call_method(
            Some(name.as_str()),
            path,
            Some("org.freedesktop.Secret.Collection"),
            "CreateItem",
            &(properties.clone(), secret, true),
        )
        .await
        .unwrap();
    }

    let collection = service.get_collection("login").await.unwrap();
    assert_eq!(
        collection.items.len(),
        1,
        "CreateItem with replace=true must not create duplicate items"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
