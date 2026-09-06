use std::collections::HashMap;
use std::io::Read;
use std::os::fd::{AsFd, FromRawFd};
use std::path::PathBuf;
use zbus::blocking::Connection;
use zbus::zvariant::{Fd, ObjectPath, OwnedObjectPath, OwnedValue, Value};
use sigil_client::SigilClient;

fn get_pipe() -> (std::fs::File, std::fs::File) {
    let mut fds = [0; 2];
    let ret = unsafe { libc::pipe(fds.as_mut_ptr()) };
    assert_eq!(ret, 0, "libc::pipe failed");
    let read_file = unsafe { std::fs::File::from_raw_fd(fds[0]) };
    let write_file = unsafe { std::fs::File::from_raw_fd(fds[1]) };
    (read_file, write_file)
}

#[tokio::test]
#[ignore = "requires running live sigil and portal session"]
async fn test_live_sigil_native_socket() {
    let runtime_dir = std::env::var("XDG_RUNTIME_DIR").expect("XDG_RUNTIME_DIR must be set");
    let sock_path = PathBuf::from(runtime_dir).join("sigil/native.sock");
    println!("Testing live sigil socket at: {:?}", sock_path);
    assert!(sock_path.exists(), "sigil native.sock does not exist");

    let client = SigilClient::new(sock_path);

    // 1. Check lock state
    let is_locked = client.is_locked().await.expect("is_locked query failed");
    println!("sigil is_locked: {}", is_locked);
    assert!(!is_locked, "sigil should be unlocked in user session");

    // 2. Retrieve app secrets
    let app1_secret = client
        .get_application_secret(
            "atrium.portal.Secret/v1",
            "org.test.client_a",
            "master-secret",
        )
        .await
        .expect("get_application_secret for app1 failed");
    assert_eq!(app1_secret.len(), 32);

    let app1_secret_repeat = client
        .get_application_secret(
            "atrium.portal.Secret/v1",
            "org.test.client_a",
            "master-secret",
        )
        .await
        .expect("get_application_secret repeated failed");
    assert_eq!(app1_secret.as_slice(), app1_secret_repeat.as_slice(), "Secrets must be deterministic");

    let app2_secret = client
        .get_application_secret(
            "atrium.portal.Secret/v1",
            "org.test.client_b",
            "master-secret",
        )
        .await
        .expect("get_application_secret for app2 failed");
    assert_eq!(app2_secret.len(), 32);
    assert_ne!(app1_secret.as_slice(), app2_secret.as_slice(), "Different apps must receive isolated secrets");

    println!("Live sigil native socket tests passed successfully!");
}

#[test]
#[ignore = "requires running live sigil and portal session"]
fn test_live_xdg_desktop_portal_atrium_backend() {
    let conn = Connection::session().expect("Failed to connect to D-Bus session");

    // 1. Verify backend presence
    let portal = zbus::blocking::Proxy::new(
        &conn,
        "org.freedesktop.impl.portal.desktop.atrium",
        "/org/freedesktop/portal/desktop",
        "org.freedesktop.impl.portal.Secret",
    )
    .expect("Failed to create proxy for atrium portal Secret");

    let version: u32 = portal.get_property("version").expect("Failed to get version property");
    println!("atrium portal Secret version: {}", version);
    assert_eq!(version, 1);

    // 2. Test RetrieveSecret directly on the backend
    let (mut read_pipe, write_pipe) = get_pipe();
    let fd = Fd::from(write_pipe.as_fd());
    let handle = ObjectPath::try_from("/org/freedesktop/portal/desktop/request/test/1").unwrap();
    let options: HashMap<String, Value> = HashMap::new();

    let reply: (u32, HashMap<String, OwnedValue>) = portal
        .call("RetrieveSecret", &(handle, "org.test.portal_app", fd, options))
        .expect("RetrieveSecret D-Bus call failed");

    println!("RetrieveSecret return code: {}, results: {:?}", reply.0, reply.1);
    assert_eq!(reply.0, 0, "RetrieveSecret returned non-zero error code");

    // Close the write pipe in our process so read_pipe can see EOF
    drop(write_pipe);

    let mut secret_bytes = Vec::new();
    read_pipe.read_to_end(&mut secret_bytes).expect("Failed to read from pipe");
    println!("Read {} secret bytes from portal pipe", secret_bytes.len());
    assert_eq!(secret_bytes.len(), 32, "Portal secret should be 32 bytes");

    // 3. Verify it matches what sigil native IPC derives for the same parameters
    let runtime_dir = std::env::var("XDG_RUNTIME_DIR").expect("XDG_RUNTIME_DIR must be set");
    let sock_path = PathBuf::from(runtime_dir).join("sigil/native.sock");
    let rt = tokio::runtime::Runtime::new().unwrap();
    let native_secret = rt.block_on(async {
        let client = SigilClient::new(sock_path);
        client
            .get_application_secret(
                "atrium.portal.Secret/v1",
                "org.test.portal_app",
                "master-secret",
            )
            .await
            .unwrap()
    });

    assert_eq!(secret_bytes, native_secret.as_slice(), "Portal delivered secret must match sigil derived secret");
    println!("Live xdg-desktop-portal-atrium backend verification passed!");
}

#[test]
#[ignore = "requires running live sigil and portal session"]
fn test_live_xdg_desktop_portal_frontend() {
    let conn = Connection::session().expect("Failed to connect to D-Bus session");

    let portal = zbus::blocking::Proxy::new(
        &conn,
        "org.freedesktop.portal.Desktop",
        "/org/freedesktop/portal/desktop",
        "org.freedesktop.portal.Secret",
    )
    .expect("Failed to create proxy for frontend portal Secret");

    let (mut read_pipe, write_pipe) = get_pipe();
    let fd = Fd::from(write_pipe.as_fd());
    let options: HashMap<String, Value> = HashMap::new();

    let request_handle: OwnedObjectPath = portal
        .call("RetrieveSecret", &(fd, options))
        .expect("RetrieveSecret frontend D-Bus call failed");

    println!("Frontend returned request handle: {}", request_handle.as_str());

    // Close the write pipe in our process
    drop(write_pipe);

    // Read secret written by backend via frontend routing
    let mut secret_bytes = Vec::new();
    read_pipe.read_to_end(&mut secret_bytes).expect("Failed to read from pipe");
    println!("Frontend flow: Read {} secret bytes from pipe", secret_bytes.len());
    assert_eq!(secret_bytes.len(), 32, "Portal frontend should write 32 bytes to fd");

    println!("Live xdg-desktop-portal frontend end-to-end verification passed!");
}

