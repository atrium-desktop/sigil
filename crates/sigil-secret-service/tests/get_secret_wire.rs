//! Regression test for the D-Bus wire signature of `Item.GetSecret`.
//!
//! The Secret Service spec defines `GetSecret` as returning a single `Secret`
//! STRUCT (`(oayays)`). zbus serialises the return type of an interface method
//! as the tuple of output arguments, so returning a bare struct flattens it
//! into four separate out-args (`oayays`). Strict clients such as libsecret and
//! gh's go-keyring/godbus then fail to decode the reply. This test pins the
//! on-the-wire signature so the bug cannot silently regress.

use std::collections::HashMap;
use std::sync::Arc;

use sigil_core::{FileVaultStore, SigilService};
use sigil_secret_service::{Item, Session};
use tokio::sync::RwLock;
use zbus::zvariant::OwnedObjectPath;

#[tokio::test]
async fn get_secret_reply_is_a_single_struct() {
    let dir = std::env::temp_dir().join(format!(
        "sigil_get_secret_wire_{}_{}",
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

    let mut attributes = HashMap::new();
    attributes.insert("service".to_string(), "gh:github.com".to_string());
    service
        .set_item(
            "login",
            "item_1",
            "test item",
            attributes,
            b"github_pat_test",
            "text/plain",
            true,
        )
        .await
        .unwrap();

    let sessions = Arc::new(RwLock::new(HashMap::new()));
    let session_path =
        OwnedObjectPath::try_from("/org/freedesktop/secrets/session/s_test").unwrap();
    sessions.write().await.insert(
        session_path.clone(),
        Arc::new(Session::new_plain(session_path.clone())),
    );

    let item = Item {
        collection_id: "login".to_string(),
        item_id: "item_1".to_string(),
        service,
        sessions,
    };

    let name = format!("com.example.SigilGetSecretTest{}", std::process::id());
    let item_path = "/org/freedesktop/secrets/collection/login/item_1";
    let conn = zbus::connection::Builder::session()
        .unwrap()
        .name(name.clone())
        .unwrap()
        .serve_at(item_path, item)
        .unwrap()
        .build()
        .await
        .unwrap();

    let reply = conn
        .call_method(
            Some(name.as_str()),
            item_path,
            Some("org.freedesktop.Secret.Item"),
            "GetSecret",
            &(session_path,),
        )
        .await
        .unwrap();

    assert_eq!(
        reply.header().signature().to_string(),
        "(oayays)",
        "GetSecret must return a single Secret STRUCT, not flattened out-args"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
