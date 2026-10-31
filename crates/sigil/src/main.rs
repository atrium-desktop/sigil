use clap::Parser;
use sigil_dbus_secrets::{Collection, Prompt, SecretServiceDbus};
use sigil_ipc_server::NativeIpcServer;
use sigil_vault::{ensure_secure_dir, FileVaultStore, SigilService};
use std::error::Error;
use tracing::{error, info, warn};
use zbus::connection;
use zeroize::Zeroize;

mod cli;
mod doctor;
mod import;
mod logind;
mod terminal;

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
    if cli.command.is_none() {
        info!("Starting sigil daemon v{}...", env!("CARGO_PKG_VERSION"));
    }

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

    let mut vault_pwd_for_backup = initial_password.clone();

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

    // Handle subcommands if specified
    if let Some(cmd) = cli.command.clone() {
        match cmd {
            cli::Commands::Status => {
                let socket_path = cli.resolve_socket_path();
                let client = sigil_client::SigilClient::new(&socket_path);
                match client.ping().await {
                    Ok(_) => {
                        let lock_state = client
                            .get_lock_status()
                            .await
                            .unwrap_or(sigil_types::LockState::Locked);
                        println!("Sigil Credential Daemon: RUNNING");
                        println!("Lock State:              {:?}", lock_state);
                        println!("Socket:                  {}", socket_path.display());
                        println!("Storage:                 {}", data_dir.display());
                    }
                    Err(_) => {
                        println!("Sigil Credential Daemon: STOPPED (Socket unresponsive)");
                        println!("Socket:                  {}", socket_path.display());
                        println!("Storage:                 {}", data_dir.display());
                        println!(
                            "\nTo start daemon via systemd: systemctl --user start sigil.socket"
                        );
                    }
                }
                return Ok(());
            }
            cli::Commands::Lock => {
                let socket_path = cli.resolve_socket_path();
                let client = sigil_client::SigilClient::new(&socket_path);
                match client.lock().await {
                    Ok(_) => {
                        println!("Vault successfully locked. In-memory keys zeroized.");
                        return Ok(());
                    }
                    Err(e) => {
                        eprintln!("Failed to lock running daemon: {e}");
                        std::process::exit(1);
                    }
                }
            }
            cli::Commands::Unlock {
                password,
                password_file,
                recovery_key,
            } => {
                let socket_path = cli.resolve_socket_path();
                let client = sigil_client::SigilClient::new(&socket_path);
                let daemon_running = client.ping().await.is_ok();

                if let Some(mut rkey) = recovery_key {
                    if daemon_running {
                        match client.unlock_with_recovery_key(&rkey).await {
                            Ok(_) => {
                                rkey.zeroize();
                                println!("Vault unlocked successfully via recovery key.");
                                return Ok(());
                            }
                            Err(e) => {
                                rkey.zeroize();
                                eprintln!("Failed to unlock vault via recovery key: {e}");
                                std::process::exit(1);
                            }
                        }
                    } else {
                        match service.unlock_with_recovery_key(&rkey).await {
                            Ok(_) => {
                                rkey.zeroize();
                                println!("Local vault verified and unlocked via recovery key.");
                                return Ok(());
                            }
                            Err(e) => {
                                rkey.zeroize();
                                eprintln!("Failed to unlock local vault via recovery key: {e}");
                                std::process::exit(1);
                            }
                        }
                    }
                }

                let mut pwd = if let Some(p) = password {
                    p
                } else if let Some(ref pf) = password_file {
                    std::fs::read_to_string(pf)
                        .map(|c| c.trim_end_matches(&['\r', '\n'][..]).to_string())
                        .unwrap_or_default()
                } else {
                    terminal::read_password_prompt("Enter master vault password: ")
                        .map(|g| g.into_inner())
                        .unwrap_or_default()
                };

                if pwd.is_empty() {
                    eprintln!("Error: Password cannot be empty.");
                    std::process::exit(1);
                }

                if daemon_running {
                    match client.unlock_with_password(&pwd).await {
                        Ok(_) => {
                            pwd.zeroize();
                            println!("Vault unlocked successfully.");
                            return Ok(());
                        }
                        Err(e) => {
                            pwd.zeroize();
                            eprintln!("Failed to unlock running daemon: {e}");
                            std::process::exit(1);
                        }
                    }
                } else {
                    match service.unlock_with_password(&pwd).await {
                        Ok(_) => {
                            pwd.zeroize();
                            println!("Local vault master password verified successfully.");
                            println!("\n[NOTE] The background daemon is not currently running.");
                            println!("To start the daemon and enable D-Bus Secret Service, run:");
                            println!("    systemctl --user start sigil.service");
                            println!("or start it in the background: sigil &");
                            return Ok(());
                        }
                        Err(e) => {
                            pwd.zeroize();
                            eprintln!("Failed to unlock local vault: {e}");
                            std::process::exit(1);
                        }
                    }
                }
            }
            cli::Commands::Recover {
                recovery_secret,
                new_password,
            } => {
                let socket_path = cli.resolve_socket_path();
                let client = sigil_client::SigilClient::new(&socket_path);
                let daemon_running = client.ping().await.is_ok();

                let mut secret = if let Some(s) = recovery_secret {
                    s
                } else {
                    terminal::read_password_prompt(
                        "Enter previous password or emergency recovery key: ",
                    )
                    .map(|g| g.into_inner())
                    .unwrap_or_default()
                };

                if secret.is_empty() {
                    eprintln!("Error: Recovery secret cannot be empty.");
                    std::process::exit(1);
                }

                let mut new_pwd = if let Some(p) = new_password {
                    p
                } else {
                    terminal::read_password_prompt(
                        "Enter new session password to re-encrypt Slot 0: ",
                    )
                    .map(|g| g.into_inner())
                    .unwrap_or_default()
                };

                if new_pwd.is_empty() {
                    secret.zeroize();
                    eprintln!("Error: New password cannot be empty.");
                    std::process::exit(1);
                }

                if daemon_running {
                    match client.recover_and_sync(&secret, &new_pwd).await {
                        Ok(_) => {
                            secret.zeroize();
                            new_pwd.zeroize();
                            println!("Vault successfully recovered and synchronized with new session password.");
                            return Ok(());
                        }
                        Err(e) => {
                            secret.zeroize();
                            new_pwd.zeroize();
                            eprintln!("Recovery failed on running daemon: {e}");
                            std::process::exit(1);
                        }
                    }
                } else {
                    match service.recover_and_sync(&secret, &new_pwd).await {
                        Ok(_) => {
                            secret.zeroize();
                            new_pwd.zeroize();
                            println!(
                                "Local vault successfully recovered and Slot 0 re-synchronized."
                            );
                            println!("\n[NOTE] Start the daemon to resume service: systemctl --user start sigil.service");
                            return Ok(());
                        }
                        Err(e) => {
                            secret.zeroize();
                            new_pwd.zeroize();
                            eprintln!("Local vault recovery failed: {e}");
                            std::process::exit(1);
                        }
                    }
                }
            }
            cli::Commands::RecoveryKey { action } => match action {
                cli::RecoveryKeyAction::Generate => {
                    let socket_path = cli.resolve_socket_path();
                    let client = sigil_client::SigilClient::new(&socket_path);
                    let daemon_running = client.ping().await.is_ok();

                    let rkey = sigil_crypto::generate_recovery_key();

                    if daemon_running {
                        if client.is_locked().await.unwrap_or(true) {
                            eprintln!("Error: Vault is locked. Please run 'sigil unlock' first.");
                            std::process::exit(1);
                        }
                        if let Err(e) = client.enroll_recovery_key(&rkey).await {
                            eprintln!("Error enrolling recovery key in running daemon: {e}");
                            std::process::exit(1);
                        }
                    } else {
                        if service.is_locked().await {
                            let mut pwd = terminal::read_password_prompt(
                                "Enter master vault password to enroll recovery key: ",
                            )
                            .map(|g| g.into_inner())
                            .unwrap_or_default();
                            if let Err(e) = service.unlock_with_password(&pwd).await {
                                pwd.zeroize();
                                eprintln!("Failed to unlock local vault: {e}");
                                std::process::exit(1);
                            }
                            pwd.zeroize();
                        }
                        if let Err(e) = service.enroll_recovery_key(&rkey).await {
                            eprintln!("Error enrolling recovery key in local vault: {e}");
                            std::process::exit(1);
                        }
                    }

                    println!("\n==============================================================");
                    println!("YOUR EMERGENCY RECOVERY KEY:");
                    println!();
                    println!("    {}", rkey);
                    println!();
                    println!("Write this key down and store it in a secure location.");
                    println!("It can be used to recover access to your credentials if your");
                    println!("system login password is lost or desynchronized.");
                    println!("==============================================================\n");
                    return Ok(());
                }
                cli::RecoveryKeyAction::Verify { key } => {
                    let rkey = if let Some(k) = key {
                        k
                    } else {
                        terminal::read_password_prompt("Enter recovery key to verify: ")
                            .map(|g| g.into_inner())
                            .unwrap_or_default()
                    };
                    match store.unseal_slot_with_recovery_key(&rkey) {
                        Ok(_) => {
                            println!("Recovery key is VALID for Slot 1.");
                            return Ok(());
                        }
                        Err(e) => {
                            eprintln!("Recovery key verification FAILED: {e}");
                            std::process::exit(1);
                        }
                    }
                }
            },
            cli::Commands::Doctor => {
                let socket_path = cli.resolve_socket_path();
                let checks = doctor::run_diagnostics(&data_dir, &socket_path).await;
                println!("\n=== Sigil Desktop Infrastructure Diagnostic Doctor ===\n");
                let mut passed = 0;
                let mut warned = 0;
                let mut failed = 0;

                for c in checks {
                    match c.status {
                        doctor::CheckStatus::Pass => {
                            passed += 1;
                            println!("[\x1b[32mPASS\x1b[0m] {}: {}", c.name, c.message);
                        }
                        doctor::CheckStatus::Warn => {
                            warned += 1;
                            println!("[\x1b[33mWARN\x1b[0m] {}: {}", c.name, c.message);
                            if let Some(r) = c.remediation {
                                println!("       \x1b[36mRemediation:\x1b[0m {}", r);
                            }
                        }
                        doctor::CheckStatus::Fail => {
                            failed += 1;
                            println!("[\x1b[31mFAIL\x1b[0m] {}: {}", c.name, c.message);
                            if let Some(r) = c.remediation {
                                println!("       \x1b[36mRemediation:\x1b[0m {}", r);
                            }
                        }
                    }
                }
                println!(
                    "\nDiagnostics complete: {} passed, {} warnings, {} failures.\n",
                    passed, warned, failed
                );
                return Ok(());
            }
            cli::Commands::ImportCredentials {
                input,
                collection,
                format,
            } => {
                if service.is_locked().await {
                    let mut pwd = terminal::read_password_prompt(
                        "Enter master vault password to import credentials: ",
                    )
                    .map(|g| g.into_inner())
                    .unwrap_or_default();
                    if let Err(e) = service.unlock_with_password(&pwd).await {
                        pwd.zeroize();
                        eprintln!("Failed to unlock vault for import: {e}");
                        std::process::exit(1);
                    }
                    pwd.zeroize();
                }

                match import::import_credentials_file(
                    &service,
                    &input,
                    &collection,
                    format.as_deref(),
                )
                .await
                {
                    Ok(count) => {
                        println!(
                            "Successfully imported {} credentials into collection '{}'.",
                            count, collection
                        );
                        return Ok(());
                    }
                    Err(e) => {
                        eprintln!("Import failed: {e}");
                        std::process::exit(1);
                    }
                }
            }
            cli::Commands::ExportVault {
                output,
                archive_password,
            } => {
                if service.is_locked().await {
                    eprintln!(
                        "Error: Vault must be unlocked with --password or --password-file to perform export."
                    );
                    std::process::exit(1);
                }
                let mut pwd = archive_password
                    .or_else(|| vault_pwd_for_backup.take())
                    .unwrap_or_default();
                if pwd.is_empty() {
                    eprintln!("Error: Archive encryption password required (--archive-password or --password)");
                    std::process::exit(1);
                }
                let bytes = service.export_vault_archive(&pwd).await?;
                pwd.zeroize();
                std::fs::write(&output, bytes)?;
                println!("Vault backup successfully exported to {}", output.display());
                return Ok(());
            }
            cli::Commands::ImportVault {
                input,
                archive_password,
            } => {
                if service.is_locked().await {
                    eprintln!(
                        "Error: Vault must be unlocked with --password or --password-file to perform import."
                    );
                    std::process::exit(1);
                }
                let bytes = std::fs::read(&input)?;
                let mut pwd = archive_password
                    .or_else(|| vault_pwd_for_backup.take())
                    .unwrap_or_default();
                if pwd.is_empty() {
                    eprintln!("Error: Archive decryption password required (--archive-password or --password)");
                    std::process::exit(1);
                }
                let count = service.import_vault_archive(&bytes, &pwd).await?;
                pwd.zeroize();
                println!(
                    "Successfully imported {} credentials from {}",
                    count,
                    input.display()
                );
                return Ok(());
            }
        }
    }
    if let Some(ref mut p) = vault_pwd_for_backup {
        p.zeroize();
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
        path: zbus::zvariant::OwnedObjectPath::try_from("/org/freedesktop/secrets/prompt/default")
            .unwrap(),
        target_objects: Vec::new(),
        service: service.clone(),
        dismissed: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
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
