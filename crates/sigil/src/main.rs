use directories::ProjectDirs;
use sigil_ipc::NativeIpcServer;
use sigil_secret_service::{Collection, Prompt, SecretServiceDbus};
use sigil_service::SigilService;
use sigil_store::{ensure_secure_dir, FileVaultStore, StoredVaultData};
use std::error::Error;
use std::path::PathBuf;
use tracing::{error, info, warn};
use zbus::connection;
use zeroize::Zeroize;

mod logind;

fn apply_process_hardening() {
    #[cfg(target_os = "linux")]
    unsafe {
        // Disallow ptrace attachment from unprivileged processes and reading /proc/$pid/mem
        if libc::prctl(libc::PR_SET_DUMPABLE, 0) != 0 {
            warn!("Failed to set PR_SET_DUMPABLE to 0");
        }
        // Disable core dumps to prevent dumping sensitive keys / items on crash
        let rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::setrlimit(libc::RLIMIT_CORE, &rlim) != 0 {
            warn!("Failed to set RLIMIT_CORE to 0");
        }
    }
}

fn get_data_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("SIGIL_DATA_DIR") {
        return PathBuf::from(dir);
    }
    if let Some(proj_dirs) = ProjectDirs::from("org", "freedesktop", "sigil") {
        proj_dirs.data_dir().to_path_buf()
    } else {
        PathBuf::from(".local/share/sigil")
    }
}

fn get_runtime_socket_path() -> PathBuf {
    if let Ok(path) = std::env::var("SIGIL_SOCKET_PATH") {
        return PathBuf::from(path);
    }
    let runtime_dir = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(runtime_dir).join("sigil/native.sock")
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    apply_process_hardening();
    tracing_subscriber::fmt::init();
    info!("Starting sigil daemon...");

    let data_dir = get_data_dir();
    ensure_secure_dir(&data_dir)?;
    let store = FileVaultStore::new(data_dir.clone());
    let service = SigilService::new(store.clone());

    // Check for explicit headless password configuration
    if let Ok(mut pwd) = std::env::var("SIGIL_PASSWORD") {
        if !pwd.is_empty() {
            if !store.exists() {
                info!("Initializing password vault from SIGIL_PASSWORD.");
                let salt = sigil_crypto::generate_salt(sigil_crypto::DEFAULT_SALT_LEN);
                let params = sigil_crypto::KdfParams::default();
                match sigil_crypto::derive_key_argon2id(pwd.as_bytes(), &salt, &params) {
                    Ok(key) => {
                        let salt_hex: String = salt.iter().map(|b| format!("{:02x}", b)).collect();
                        let _ = sigil_store::atomic_replace(&store.salt_path(), salt_hex.as_bytes());
                        let _ = store.save(&key, &StoredVaultData::default());
                        let _ = service.unlock_with_master_key(key).await;
                        info!("Vault initialized and unlocked from SIGIL_PASSWORD.");
                    }
                    Err(e) => error!("Failed to derive key from SIGIL_PASSWORD: {}", e),
                }
            } else {
                match service.unlock_with_password(&pwd).await {
                    Ok(_) => info!("Vault unlocked from SIGIL_PASSWORD."),
                    Err(e) => error!("Failed to unlock vault with SIGIL_PASSWORD: {}", e),
                }
            }
            pwd.zeroize();
        }
    }

    // Auto-unlock with keyfile if in keyfile mode and still locked
    if service.is_locked().await {
        if store.exists() {
            if store.is_keyfile_mode() {
                match store.read_keyfile() {
                    Ok(key) => match service.unlock_with_master_key(key).await {
                        Ok(_) => info!("Vault unlocked using keyfile."),
                        Err(e) => error!("Failed to unlock vault with keyfile: {}", e),
                    },
                    Err(e) => error!("Failed to read keyfile: {}", e),
                }
            } else {
                info!("Password-mode vault detected. Awaiting unlock via PAM or IPC.");
            }
        } else {
            info!(
                "No vault found at {}. Awaiting initialization with password.",
                data_dir.display()
            );
        }
    }

    // Spawn Native IPC server
    let socket_path = get_runtime_socket_path();
    let ipc_service = service.clone();
    tokio::spawn(async move {
        let server = NativeIpcServer::new(socket_path, ipc_service);
        if let Err(e) = server.run().await {
            error!("Native IPC server terminated with error: {}", e);
        }
    });

    // Spawn logind lock listener
    logind::spawn_lock_listener(service.clone());

    // Setup Secret Service D-Bus interface
    let secret_service = SecretServiceDbus::new(service.clone());
    let prompt = Prompt {
        path: zbus::zvariant::ObjectPath::from_static_str("/org/freedesktop/secrets/prompt/default").unwrap(),
    };

    let default_login_col = Collection {
        id: "login".into(),
        service: service.clone(),
        sessions: secret_service.sessions.clone(),
    };

    let _conn = connection::Builder::session()?
        .name("org.freedesktop.secrets")?
        .serve_at("/org/freedesktop/secrets", secret_service)?
        .serve_at("/org/freedesktop/secrets/prompt/default", prompt)?
        .serve_at("/org/freedesktop/secrets/collection/login", default_login_col)?
        .build()
        .await?;

    info!("sigil successfully registered on D-Bus as org.freedesktop.secrets.");

    // Keep daemon running
    std::future::pending::<()>().await;

    Ok(())
}
