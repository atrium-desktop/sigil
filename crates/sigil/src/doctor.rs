use sigil_client::SigilSyncClient;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

#[derive(Debug, PartialEq, Eq)]
pub enum CheckStatus {
    Pass,
    Warn,
    Fail,
}

pub struct CheckResult {
    pub name: &'static str,
    pub status: CheckStatus,
    pub message: String,
    pub remediation: Option<String>,
}

pub async fn run_diagnostics(data_dir: &Path, socket_path: &Path) -> Vec<CheckResult> {
    let mut results = Vec::new();

    // 1. Native IPC Socket & Daemon Liveness
    results.push(check_native_ipc(socket_path));

    // 2. Storage Directory & Envelope Manifest
    results.push(check_vault_storage(data_dir));

    // 3. D-Bus org.freedesktop.secrets Service Ownership
    results.push(check_dbus_secrets().await);

    // 4. Graphical Display Environment
    results.push(check_display_environment());

    // 5. GUI Prompter Executable
    results.push(check_prompter_executable());

    // 6. PAM Security Module Placement
    results.push(check_pam_module());

    // 7. Process Hardening Baseline
    results.push(check_process_hardening());

    results
}

fn check_native_ipc(socket_path: &Path) -> CheckResult {
    if !socket_path.exists() {
        return CheckResult {
            name: "Native IPC Socket",
            status: CheckStatus::Warn,
            message: format!(
                "Socket file {} does not exist. (Daemon not running or managed via socket activation)",
                socket_path.display()
            ),
            remediation: Some(
                "Start socket activation: systemctl --user enable --now sigil.socket".into(),
            ),
        };
    }

    // Check permissions
    if let Ok(meta) = fs::metadata(socket_path) {
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o600 {
            return CheckResult {
                name: "Native IPC Socket",
                status: CheckStatus::Warn,
                message: format!("Socket permissions are {:04o} (expected 0600)", mode),
                remediation: Some(format!("chmod 0600 {}", socket_path.display())),
            };
        }
    }

    let client = SigilSyncClient::new(socket_path);
    match client.ping() {
        Ok(_) => {
            let lock_state = client
                .get_lock_status()
                .map(|s| format!("{s:?}"))
                .unwrap_or_else(|_| "Unknown".into());
            CheckResult {
                name: "Native IPC Socket",
                status: CheckStatus::Pass,
                message: format!(
                    "Connected to daemon at {} (State: {})",
                    socket_path.display(),
                    lock_state
                ),
                remediation: None,
            }
        }
        Err(e) => CheckResult {
            name: "Native IPC Socket",
            status: CheckStatus::Fail,
            message: format!("Failed to ping socket {}: {}", socket_path.display(), e),
            remediation: Some(
                "Check daemon logs via: journalctl --user -u sigil.service -e".into(),
            ),
        },
    }
}

fn check_vault_storage(data_dir: &Path) -> CheckResult {
    if !data_dir.exists() {
        return CheckResult {
            name: "Vault Storage",
            status: CheckStatus::Warn,
            message: format!(
                "Storage directory {} does not exist yet (will auto-provision on first login)",
                data_dir.display()
            ),
            remediation: None,
        };
    }

    if let Ok(meta) = fs::metadata(data_dir) {
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return CheckResult {
                name: "Vault Storage",
                status: CheckStatus::Warn,
                message: format!(
                    "Directory {} permissions {:04o} are too open (expected 0700)",
                    data_dir.display(),
                    mode
                ),
                remediation: Some(format!("chmod 0700 {}", data_dir.display())),
            };
        }
    }

    let meta_path = data_dir.join("vault.meta");
    let slots_dir = data_dir.join("vault.slots");

    if meta_path.exists() && slots_dir.exists() {
        let mut active_slots = Vec::new();
        let mut desync_detected = false;
        if let Ok(content) = fs::read(&meta_path) {
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&content) {
                if let Some(arr) = v.get("active_slots").and_then(|a| a.as_array()) {
                    for slot in arr {
                        if let Some(n) = slot.as_u64() {
                            active_slots.push(n);
                        }
                    }
                }
                desync_detected = v
                    .get("desync_detected")
                    .and_then(|d| d.as_bool())
                    .unwrap_or(false);
            }
        }

        if desync_detected {
            return CheckResult {
                name: "Vault Storage",
                status: CheckStatus::Fail,
                message: format!(
                    "Vault credentials desynchronized at {} (Slot 0 invalid after out-of-band admin reset)",
                    data_dir.display()
                ),
                remediation: Some(
                    "Re-synchronize Slot 0 using: sigil recover --recovery-secret <OLD_PASS_OR_KEY> --new-password <NEW_PASS>".into(),
                ),
            };
        }

        CheckResult {
            name: "Vault Storage",
            status: CheckStatus::Pass,
            message: format!(
                "Envelope storage active at {} (Enrolled slots: {:?})",
                data_dir.display(),
                active_slots
            ),
            remediation: None,
        }
    } else {
        CheckResult {
            name: "Vault Storage",
            status: CheckStatus::Pass,
            message: format!(
                "Directory exists at {} (ready for initial provisioning)",
                data_dir.display()
            ),
            remediation: None,
        }
    }
}

async fn check_dbus_secrets() -> CheckResult {
    let conn = match zbus::Connection::session().await {
        Ok(c) => c,
        Err(e) => {
            return CheckResult {
                name: "D-Bus Secret Service",
                status: CheckStatus::Warn,
                message: format!("Unable to connect to D-Bus session bus: {e}"),
                remediation: None,
            };
        }
    };

    let dbus_proxy = match zbus::fdo::DBusProxy::new(&conn).await {
        Ok(p) => p,
        Err(e) => {
            return CheckResult {
                name: "D-Bus Secret Service",
                status: CheckStatus::Warn,
                message: format!("Failed to create DBus proxy: {e}"),
                remediation: None,
            };
        }
    };

    match dbus_proxy
        .get_name_owner("org.freedesktop.secrets".try_into().unwrap())
        .await
    {
        Ok(owner) => {
            // Find pid
            let bus_name = zbus::names::BusName::Unique(owner.into());
            let pid = dbus_proxy
                .get_connection_unix_process_id(bus_name)
                .await
                .ok();

            let comm = pid.and_then(|p| {
                fs::read_to_string(format!("/proc/{p}/comm"))
                    .ok()
                    .map(|s| s.trim().to_string())
            });

            if let Some(ref name) = comm {
                if name.contains("gnome-keyring") || name.contains("kwallet") {
                    return CheckResult {
                        name: "D-Bus Secret Service",
                        status: CheckStatus::Fail,
                        message: format!(
                            "org.freedesktop.secrets is currently owned by conflicting daemon '{}' (PID: {:?})",
                            name, pid
                        ),
                        remediation: Some(
                            "Mask conflicting daemon: systemctl --user mask --now gnome-keyring-daemon.service gnome-keyring-daemon.socket".into()
                        ),
                    };
                }
            }

            CheckResult {
                name: "D-Bus Secret Service",
                status: CheckStatus::Pass,
                message: format!(
                    "Name org.freedesktop.secrets is owned by '{}' (PID: {:?})",
                    comm.as_deref().unwrap_or("unknown"),
                    pid
                ),
                remediation: None,
            }
        }
        Err(_) => CheckResult {
            name: "D-Bus Secret Service",
            status: CheckStatus::Pass,
            message: "org.freedesktop.secrets is currently unclaimed (available for sigil)".into(),
            remediation: None,
        },
    }
}

fn check_display_environment() -> CheckResult {
    let wayland = std::env::var("WAYLAND_DISPLAY").ok();
    let x11 = std::env::var("DISPLAY").ok();

    if let Some(w) = wayland {
        CheckResult {
            name: "Display Environment",
            status: CheckStatus::Pass,
            message: format!("Wayland active ({w})"),
            remediation: None,
        }
    } else if let Some(x) = x11 {
        CheckResult {
            name: "Display Environment",
            status: CheckStatus::Pass,
            message: format!("X11 active ({x})"),
            remediation: None,
        }
    } else {
        CheckResult {
            name: "Display Environment",
            status: CheckStatus::Warn,
            message:
                "No graphical display detected (WAYLAND_DISPLAY and DISPLAY unset). TTY/SSH mode."
                    .into(),
            remediation: Some(
                "In headless/SSH environments, unlock credentials using: sigil unlock".into(),
            ),
        }
    }
}

fn check_prompter_executable() -> CheckResult {
    match sigil_dbus_secrets::resolve_prompter_bin() {
        Some(bin) => CheckResult {
            name: "GUI Prompter Binary",
            status: CheckStatus::Pass,
            message: format!("Found prompter executable at {}", bin.display()),
            remediation: None,
        },
        None => CheckResult {
            name: "GUI Prompter Binary",
            status: CheckStatus::Warn,
            message: "sigil-prompter binary not found in standard paths or $SIGIL_PROMPTER".into(),
            remediation: Some("Install sigil-prompter to /usr/bin/sigil-prompter".into()),
        },
    }
}

fn check_pam_module() -> CheckResult {
    let candidate_paths = [
        "/usr/lib/security/pam_sigil.so",
        "/lib/security/pam_sigil.so",
        "/usr/lib/x86_64-linux-gnu/security/pam_sigil.so",
        "/usr/lib64/security/pam_sigil.so",
    ];

    let mut found_path: Option<PathBuf> = None;
    for p in &candidate_paths {
        let pb = PathBuf::from(p);
        if pb.exists() {
            found_path = Some(pb);
            break;
        }
    }

    if let Some(path) = found_path {
        CheckResult {
            name: "PAM Security Module",
            status: CheckStatus::Pass,
            message: format!("pam_sigil.so found at {}", path.display()),
            remediation: None,
        }
    } else {
        CheckResult {
            name: "PAM Security Module",
            status: CheckStatus::Warn,
            message: "pam_sigil.so not found in standard security directories".into(),
            remediation: Some(
                "Install pam_sigil.so to /usr/lib/security/pam_sigil.so for zero-touch unlock"
                    .into(),
            ),
        }
    }
}

fn check_process_hardening() -> CheckResult {
    let dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE) };
    let mut rlim: libc::rlimit = unsafe { std::mem::zeroed() };
    let _ = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut rlim) };

    if dumpable == 0 && rlim.rlim_cur == 0 {
        CheckResult {
            name: "Process Hardening",
            status: CheckStatus::Pass,
            message: "Anti-dumping and zero-core-dump protections active".into(),
            remediation: None,
        }
    } else {
        CheckResult {
            name: "Process Hardening",
            status: CheckStatus::Pass,
            message: "Process hardening applies automatically when sigil daemon starts".into(),
            remediation: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_display_environment() {
        std::env::set_var("WAYLAND_DISPLAY", "wayland-test-0");
        let res = check_display_environment();
        assert_eq!(res.status, CheckStatus::Pass);
        assert!(res.message.contains("Wayland active"));
    }

    #[test]
    fn test_check_vault_storage_desync_detection() {
        let temp_dir = std::env::temp_dir().join(format!("sigil_doc_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();
        fs::create_dir_all(temp_dir.join("vault.slots")).unwrap();

        // Write meta with desync_detected = true
        let meta_json = r#"{
            "version": 2,
            "vault_uuid": "test-vault",
            "created_at": 1000,
            "modified_at": 1000,
            "active_slots": [0, 1],
            "desync_detected": true
        }"#;
        fs::write(temp_dir.join("vault.meta"), meta_json).unwrap();

        let res = check_vault_storage(&temp_dir);
        assert_eq!(res.status, CheckStatus::Fail);
        assert!(res.message.contains("desynchronized"));
        assert!(res.remediation.is_some());

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
