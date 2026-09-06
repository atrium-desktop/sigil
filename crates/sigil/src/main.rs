use clap::Parser;
use sigil_core::{ensure_secure_dir, FileVaultStore, NativeIpcServer, SigilService};
use sigil_secret_service::{Collection, Prompt, SecretServiceDbus};
use std::error::Error;
use tracing::{error, info, warn};
use zbus::connection;
use zeroize::Zeroize;

mod cli;
mod logind;

use cli::Cli;

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
        // Opportunistically lock process memory pages to prevent swapping secrets to disk
        if libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) != 0 {
            tracing::debug!("mlockall failed (likely unprivileged memory limit); continuing with standard protection");
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Parse CLI arguments before any daemon initialization or hardening
    let mut cli = Cli::parse();

    apply_process_hardening();
    cli.init_logging();
    info!("Starting sigil daemon v{}...", env!("CARGO_PKG_VERSION"));

    let data_dir = cli.resolve_data_dir();
    ensure_secure_dir(&data_dir)?;
    let store = FileVaultStore::new(data_dir.clone());
    let service = SigilService::new(store.clone());

    // Resolve headless unlock password if provided via CLI flag, file, or environment variable
    let mut initial_password = if let Some(ref path) = cli.password_file {
        match std::fs::read_to_string(path) {
            Ok(content) => Some(content.trim_end_matches(&['\r', '\n'][..]).to_string()),
            Err(e) => {
                error!("Failed to read password file at {}: {}", path.display(), e);
                None
            }
        }
    } else {
        cli.password.take()
    };

    if let Some(ref mut pwd) = initial_password {
        if !pwd.is_empty() {
            match service.unlock_with_password(pwd).await {
                Ok(_) => info!("Vault initialized/unlocked from CLI password configuration."),
                Err(e) => error!(
                    "Failed to initialize/unlock vault with provided password: {}",
                    e
                ),
            }
            pwd.zeroize();
        }
    }

    if service.is_locked().await {
        if store.exists() {
            if store.is_desynced() {
                warn!("Vault credentials are desynchronized. Awaiting self-healing recovery via prompter.");
            } else {
                info!("Vault sealed. Awaiting transparent unlock via PAM or native IPC.");
            }
        } else {
            info!(
                "No vault found at {}. Awaiting zero-touch auto-provisioning via PAM on first login.",
                data_dir.display()
            );
        }
    }

    // Spawn Native IPC server
    let socket_path = cli.resolve_socket_path();
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
        path: zbus::zvariant::ObjectPath::from_static_str(
            "/org/freedesktop/secrets/prompt/default",
        )
        .unwrap(),
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
        .serve_at(
            "/org/freedesktop/secrets/collection/login",
            default_login_col.clone(),
        )?
        .serve_at(
            "/org/freedesktop/secrets/aliases/default",
            default_login_col,
        )?
        .build()
        .await?;

    info!("sigil successfully registered on D-Bus as org.freedesktop.secrets.");

    // Keep daemon running
    std::future::pending::<()>().await;

    Ok(())
}
