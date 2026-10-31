use futures_util::StreamExt;
use sigil_dbus_secrets::SecretServiceDbus;
use sigil_vault::{FileVaultStore, SigilService};
use std::ops::Deref;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

#[tokio::test]
async fn test_dbus_prompt_lifecycle_dismiss_and_complete() {
    let dir = std::env::temp_dir().join(format!(
        "sigil_prompt_test_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let store = FileVaultStore::new(dir.clone());
    // Provision vault so it has data
    store.initialize_with_password("vault-pass-123").unwrap();

    let service = SigilService::new(store);
    assert!(service.is_locked().await);

    let secret_service = SecretServiceDbus::new(service.clone());
    let bus_name = format!("com.example.SigilPromptTest{}", std::process::id());
    let service_path = "/org/freedesktop/secrets";

    // Service side connection hosting org.freedesktop.secrets
    let _server_conn = zbus::connection::Builder::session()
        .unwrap()
        .name(bus_name.clone())
        .unwrap()
        .serve_at(service_path, secret_service)
        .unwrap()
        .build()
        .await
        .unwrap();

    // Client side connection (distinct peer on session bus)
    let client_conn = zbus::connection::Builder::session()
        .unwrap()
        .build()
        .await
        .unwrap();

    let item_path =
        OwnedObjectPath::try_from("/org/freedesktop/secrets/collection/login/test_item").unwrap();

    // 1. When locked, Unlock() must return a dynamic prompt path (not "/")
    let reply = client_conn
        .call_method(
            Some(bus_name.as_str()),
            service_path,
            Some("org.freedesktop.Secret.Service"),
            "Unlock",
            &(vec![item_path.clone()],),
        )
        .await
        .unwrap();

    let (_unlocked, prompt_path): (Vec<OwnedObjectPath>, OwnedObjectPath) =
        reply.body().deserialize().unwrap();

    // 2. Set up signal stream for Prompt.Completed on prompt_path from client_conn
    let prompt_proxy = zbus::Proxy::new(
        &client_conn,
        bus_name.as_str(),
        prompt_path.as_str(),
        "org.freedesktop.Secret.Prompt",
    )
    .await
    .unwrap();

    let mut signal_stream = prompt_proxy.receive_signal("Completed").await.unwrap();

    // 3. Call Dismiss() -> must emit Completed(dismissed=true, result=[])
    client_conn
        .call_method(
            Some(bus_name.as_str()),
            prompt_path.as_str(),
            Some("org.freedesktop.Secret.Prompt"),
            "Dismiss",
            &(),
        )
        .await
        .unwrap();

    let signal_msg = tokio::time::timeout(std::time::Duration::from_secs(5), signal_stream.next())
        .await
        .expect("Timed out waiting for Completed signal on Dismiss")
        .expect("Should receive Completed signal");

    let (dismissed, result): (bool, OwnedValue) = signal_msg.body().deserialize().unwrap();
    assert!(dismissed, "Completed signal must indicate dismissed=true");
    if let Value::Array(arr) = result.deref() {
        assert!(arr.is_empty(), "Result must be empty when dismissed");
    } else {
        panic!("Result must be an array");
    }

    // 4. Prompt object should now be deregistered from ObjectServer
    tokio::time::sleep(std::time::Duration::from_millis(80)).await;
    let after_dismiss = client_conn
        .call_method(
            Some(bus_name.as_str()),
            prompt_path.as_str(),
            Some("org.freedesktop.Secret.Prompt"),
            "Dismiss",
            &(),
        )
        .await;
    assert!(
        after_dismiss.is_err(),
        "Deregistered prompt must return D-Bus error"
    );

    // 5. Unlock the service and test Prompt completion flow
    let reply2 = client_conn
        .call_method(
            Some(bus_name.as_str()),
            service_path,
            Some("org.freedesktop.Secret.Service"),
            "Unlock",
            &(vec![item_path.clone()],),
        )
        .await
        .unwrap();

    let (_, prompt_path2): (Vec<OwnedObjectPath>, OwnedObjectPath) =
        reply2.body().deserialize().unwrap();

    let prompt_proxy2 = zbus::Proxy::new(
        &client_conn,
        bus_name.as_str(),
        prompt_path2.as_str(),
        "org.freedesktop.Secret.Prompt",
    )
    .await
    .unwrap();
    let mut signal_stream2 = prompt_proxy2.receive_signal("Completed").await.unwrap();

    // Unlock the service before triggering prompt()
    service
        .unlock_with_password("vault-pass-123")
        .await
        .unwrap();

    // Call Prompt.Prompt("")
    client_conn
        .call_method(
            Some(bus_name.as_str()),
            prompt_path2.as_str(),
            Some("org.freedesktop.Secret.Prompt"),
            "Prompt",
            &("",),
        )
        .await
        .unwrap();

    let signal_msg2 =
        tokio::time::timeout(std::time::Duration::from_secs(5), signal_stream2.next())
            .await
            .expect("Timed out waiting for Completed signal on Prompt")
            .expect("Should receive Completed signal on prompt");

    let (dismissed2, result2): (bool, OwnedValue) = signal_msg2.body().deserialize().unwrap();
    assert!(
        !dismissed2,
        "Completed signal must indicate dismissed=false when unlocked"
    );
    if let Value::Array(arr) = result2.deref() {
        assert_eq!(arr.len(), 1, "Should contain the unlocked item path");
    } else {
        panic!("Result must be an array");
    }

    let _ = std::fs::remove_dir_all(&dir);
}
