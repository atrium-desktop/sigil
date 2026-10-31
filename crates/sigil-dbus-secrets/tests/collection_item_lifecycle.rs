use std::collections::HashMap;
use std::ops::Deref;
use std::sync::Arc;
use tokio::sync::RwLock;
use zbus::zvariant::{OwnedObjectPath, Value};

use sigil_dbus_secrets::{Collection, Item, Session};
use sigil_vault::{FileVaultStore, SigilService};

#[tokio::test]
async fn test_collection_set_label_and_object_deregistration() {
    let dir = std::env::temp_dir().join(format!(
        "sigil_col_lifecycle_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let service = SigilService::new(FileVaultStore::new(dir.clone()));
    service.unlock_with_password("test-pass").await.unwrap();

    let sessions = Arc::new(RwLock::new(HashMap::new()));
    let session_path =
        OwnedObjectPath::try_from("/org/freedesktop/secrets/session/s_test").unwrap();
    sessions.write().await.insert(
        session_path.clone(),
        Arc::new(Session::new_plain(session_path.clone())),
    );

    let col_id = "test_col";
    service
        .create_collection(col_id, "Original Label")
        .await
        .unwrap();

    let collection = Collection {
        id: col_id.to_string(),
        service: service.clone(),
        sessions: sessions.clone(),
    };

    let bus_name = format!("com.example.SigilColTest{}", std::process::id());
    let col_path = format!("/org/freedesktop/secrets/collection/{}", col_id);

    let conn = zbus::connection::Builder::session()
        .unwrap()
        .name(bus_name.clone())
        .unwrap()
        .serve_at(col_path.as_str(), collection)
        .unwrap()
        .build()
        .await
        .unwrap();

    // 1. Verify initial label and non-zero timestamps
    let reply = conn
        .call_method(
            Some(bus_name.as_str()),
            col_path.as_str(),
            Some("org.freedesktop.DBus.Properties"),
            "Get",
            &("org.freedesktop.Secret.Collection", "Label"),
        )
        .await
        .unwrap();

    let val: zbus::zvariant::OwnedValue = reply.body().deserialize().unwrap();
    if let Value::Str(s) = val.deref() {
        assert_eq!(s.as_str(), "Original Label");
    } else {
        panic!("Expected string property for Label");
    }

    // 2. Set new label via D-Bus properties
    conn.call_method(
        Some(bus_name.as_str()),
        col_path.as_str(),
        Some("org.freedesktop.DBus.Properties"),
        "Set",
        &(
            "org.freedesktop.Secret.Collection",
            "Label",
            Value::from("Updated Label"),
        ),
    )
    .await
    .expect("Set Label should succeed");

    // 3. Verify updated label in service
    let col_record = service.get_collection(col_id).await.unwrap();
    assert_eq!(col_record.label, "Updated Label");
    assert!(col_record.created_at > 0);
    assert!(col_record.modified_at >= col_record.created_at);

    // 4. Create an item and export on D-Bus
    service
        .set_item(
            col_id,
            "item_1",
            "Item One",
            HashMap::new(),
            b"secret-123",
            "text/plain",
            false,
        )
        .await
        .unwrap();

    let item_path = format!("/org/freedesktop/secrets/collection/{}/item_1", col_id);
    let item_obj = Item {
        collection_id: col_id.to_string(),
        item_id: "item_1".to_string(),
        service: service.clone(),
        sessions: sessions.clone(),
    };
    conn.object_server()
        .at(item_path.as_str(), item_obj)
        .await
        .unwrap();

    // 5. Delete item via D-Bus -> must be removed from storage and deregistered from D-Bus
    conn.call_method(
        Some(bus_name.as_str()),
        item_path.as_str(),
        Some("org.freedesktop.Secret.Item"),
        "Delete",
        &(),
    )
    .await
    .expect("Item Delete should succeed");

    // Storage is deleted
    assert!(service.get_item(col_id, "item_1").await.is_err());

    // Subsequent call to item path fails because it was deregistered
    let after_delete = conn
        .call_method(
            Some(bus_name.as_str()),
            item_path.as_str(),
            Some("org.freedesktop.Secret.Item"),
            "Delete",
            &(),
        )
        .await;
    assert!(
        after_delete.is_err(),
        "Deregistered item path must return D-Bus error"
    );

    // 6. Delete collection via D-Bus -> must be removed from storage and deregistered
    conn.call_method(
        Some(bus_name.as_str()),
        col_path.as_str(),
        Some("org.freedesktop.Secret.Collection"),
        "Delete",
        &(),
    )
    .await
    .expect("Collection Delete should succeed");

    assert!(service.get_collection(col_id).await.is_err());
    let col_after_delete = conn
        .call_method(
            Some(bus_name.as_str()),
            col_path.as_str(),
            Some("org.freedesktop.Secret.Collection"),
            "Delete",
            &(),
        )
        .await;
    assert!(
        col_after_delete.is_err(),
        "Deregistered collection path must return D-Bus error"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
