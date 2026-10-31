use rand::rngs::OsRng;
use rand::RngCore;
use sigil_vault::SigilService;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::{info, warn};
use zbus::interface;
use zbus::zvariant::{Array, OwnedObjectPath, OwnedValue, Value};

/// Resolves the absolute path to the `sigil-prompter` executable.
pub fn resolve_prompter_bin() -> Option<PathBuf> {
    if let Ok(env_path) = std::env::var("SIGIL_PROMPTER") {
        let p = PathBuf::from(env_path);
        if p.exists() {
            return Some(p);
        }
    }

    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let candidate = parent.join("sigil-prompter");
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }

    for standard_path in &["/usr/bin/sigil-prompter", "/usr/local/bin/sigil-prompter"] {
        let p = PathBuf::from(standard_path);
        if p.exists() {
            return Some(p);
        }
    }

    None
}

/// Dynamic Secret Service Prompt implementing `org.freedesktop.Secret.Prompt`.
pub struct Prompt {
    pub path: OwnedObjectPath,
    pub target_objects: Vec<OwnedObjectPath>,
    pub service: SigilService,
    pub dismissed: Arc<AtomicBool>,
}

#[interface(name = "org.freedesktop.Secret.Prompt")]
impl Prompt {
    async fn prompt(
        &self,
        #[zbus(connection)] conn: &zbus::Connection,
        window_id: &str,
    ) -> zbus::fdo::Result<()> {
        let path = self.path.clone();
        let target_objects = self.target_objects.clone();
        let service = self.service.clone();
        let dismissed = self.dismissed.clone();
        let conn = conn.clone();
        let win_id = window_id.to_string();

        let task = async move {
            let was_unlocked = !service.is_locked().await;
            if was_unlocked {
                let unlocked_values: Vec<Value> = target_objects
                    .iter()
                    .map(|p| Value::ObjectPath(p.as_ref()))
                    .collect();
                let array_val = Value::Array(Array::from(unlocked_values));
                if let Ok(ov) = array_val.try_into_owned() {
                    if let Ok(emitter) =
                        zbus::object_server::SignalEmitter::new(&conn, path.as_ref())
                    {
                        let _ = Prompt::completed(&emitter, false, ov).await;
                    }
                }
                tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                let _ = conn.object_server().remove::<Prompt, _>(&path).await;
                return;
            }

            // Pre-flight check: ensure graphical display server is present
            let has_display =
                std::env::var("WAYLAND_DISPLAY").is_ok() || std::env::var("DISPLAY").is_ok();

            if !has_display {
                warn!(
                    "org.freedesktop.Secret.Prompt: No graphical display server detected \
                    (WAYLAND_DISPLAY and DISPLAY unset). Fast-failing prompt request. \
                    Run 'sigil unlock' in terminal or authenticate via PAM."
                );
                // Immediately emit dismissed completed signal and deregister
                if let Ok(emitter) = zbus::object_server::SignalEmitter::new(&conn, path.as_ref()) {
                    let empty_array = Value::Array(Array::from(Vec::<Value>::new()));
                    if let Ok(ov) = empty_array.try_into_owned() {
                        let _ = Prompt::completed(&emitter, true, ov).await;
                    }
                }
                tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                let _ = conn.object_server().remove::<Prompt, _>(&path).await;
                return;
            }

            // Attempt to spawn prompter GUI
            let prompter_bin = resolve_prompter_bin();
            let mut prompter_child = match prompter_bin {
                Some(ref bin) => {
                    info!("Spawning credential prompter at {:?}", bin);
                    let mut cmd = tokio::process::Command::new(bin);
                    if !win_id.is_empty() {
                        cmd.env("WINDOW_ID", &win_id);
                    }
                    cmd.spawn().ok()
                }
                None => {
                    warn!("sigil-prompter binary not found in standard paths or SIGIL_PROMPTER");
                    None
                }
            };

            // Wait for vault to unlock or prompter child to exit
            let timeout = std::time::Duration::from_secs(60);
            let start = std::time::Instant::now();
            let mut unlocked = false;

            while start.elapsed() < timeout {
                if dismissed.load(Ordering::SeqCst) {
                    break;
                }
                if !service.is_locked().await {
                    unlocked = true;
                    break;
                }
                if let Some(ref mut child) = prompter_child {
                    if let Ok(Some(_status)) = child.try_wait() {
                        // Prompter exited, check final lock status
                        unlocked = !service.is_locked().await;
                        break;
                    }
                } else {
                    // No prompter binary available, fail-fast without hanging
                    break;
                }
                tokio::time::sleep(tokio::time::Duration::from_millis(150)).await;
            }

            if let Some(mut child) = prompter_child {
                let _ = child.kill().await;
            }

            let is_dismissed = dismissed.load(Ordering::SeqCst) || !unlocked;
            let result_values: Vec<Value> = if unlocked {
                target_objects
                    .iter()
                    .map(|p| Value::ObjectPath(p.as_ref()))
                    .collect()
            } else {
                Vec::new()
            };

            let array_val = Value::Array(Array::from(result_values));
            if let Ok(ov) = array_val.try_into_owned() {
                if let Ok(emitter) = zbus::object_server::SignalEmitter::new(&conn, path.as_ref()) {
                    let _ = Prompt::completed(&emitter, is_dismissed, ov).await;
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            let _ = conn.object_server().remove::<Prompt, _>(&path).await;
        };

        if let Some(handle) = self.service.tokio_handle() {
            handle.spawn(task);
        } else {
            std::thread::spawn(move || {
                if let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    rt.block_on(task);
                }
            });
        }

        Ok(())
    }

    async fn dismiss(&self, #[zbus(connection)] conn: &zbus::Connection) -> zbus::fdo::Result<()> {
        self.dismissed.store(true, Ordering::SeqCst);
        let empty = Value::Array(Array::from(Vec::<Value>::new()));
        if let Ok(ov) = empty.try_into_owned() {
            if let Ok(emitter) = zbus::object_server::SignalEmitter::new(conn, self.path.as_ref()) {
                let _ = Prompt::completed(&emitter, true, ov).await;
            }
        }
        let conn_clone = conn.clone();
        let path_clone = self.path.clone();
        let cleanup = async move {
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            let _ = conn_clone
                .object_server()
                .remove::<Prompt, _>(&path_clone)
                .await;
        };

        if let Some(handle) = self.service.tokio_handle() {
            handle.spawn(cleanup);
        } else {
            std::thread::spawn(move || {
                if let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    rt.block_on(cleanup);
                }
            });
        }

        Ok(())
    }

    #[zbus(signal)]
    pub async fn completed(
        emitter: &zbus::object_server::SignalEmitter<'_>,
        dismissed: bool,
        result: OwnedValue,
    ) -> zbus::Result<()>;
}

/// Creates and exports a dynamic Prompt on the session bus for unlocking `objects`.
pub async fn create_dynamic_prompt(
    conn: &zbus::Connection,
    service: SigilService,
    target_objects: Vec<OwnedObjectPath>,
) -> zbus::fdo::Result<OwnedObjectPath> {
    let mut rng = OsRng;
    let prompt_id = format!("p_{}", rng.next_u64());
    let prompt_path =
        OwnedObjectPath::try_from(format!("/org/freedesktop/secrets/prompt/{prompt_id}"))
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

    let prompt_obj = Prompt {
        path: prompt_path.clone(),
        target_objects,
        service,
        dismissed: Arc::new(AtomicBool::new(false)),
    };

    conn.object_server()
        .at(&prompt_path, prompt_obj)
        .await
        .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

    info!(
        "Exported dynamic Secret Service Prompt at {:?}",
        prompt_path
    );
    Ok(prompt_path)
}
