use futures_util::StreamExt;
use sigil_service::SigilService;
use tracing::{error, info, warn};

/// Subscribe to logind Session.Lock signal and Active=false property ->
/// immediately destroy in-memory master keys upon screen lock, user switch, or seat deactivation.
pub fn spawn_lock_listener(service: SigilService) {
    tokio::spawn(async move {
        if let Err(e) = run_lock_listener(service).await {
            warn!("logind session listener stopped: {}", e);
        }
    });
}

async fn run_lock_listener(service: SigilService) -> Result<(), Box<dyn std::error::Error>> {
    let system_bus = match zbus::Connection::system().await {
        Ok(c) => c,
        Err(e) => {
            warn!("Could not connect to system bus for logind: {}", e);
            return Ok(());
        }
    };

    let session_id = std::env::var("XDG_SESSION_ID").unwrap_or_default();
    let session_path: zbus::zvariant::OwnedObjectPath = if session_id.is_empty() {
        let manager = zbus::Proxy::new(
            &system_bus,
            "org.freedesktop.login1",
            "/org/freedesktop/login1",
            "org.freedesktop.login1.Manager",
        )
        .await?;
        manager
            .call("GetSessionByPID", &(std::process::id()))
            .await?
    } else {
        let manager = zbus::Proxy::new(
            &system_bus,
            "org.freedesktop.login1",
            "/org/freedesktop/login1",
            "org.freedesktop.login1.Manager",
        )
        .await?;
        manager.call("GetSession", &session_id.as_str()).await?
    };

    let session = zbus::Proxy::new(
        &system_bus,
        "org.freedesktop.login1",
        session_path.as_str(),
        "org.freedesktop.login1.Session",
    )
    .await?;

    info!(
        "Subscribed to logind Lock signal and session activity on {}",
        session_path
    );

    let mut lock_stream = session.receive_signal("Lock").await?;
    let mut active_stream = session.receive_property_changed::<bool>("Active").await;

    loop {
        tokio::select! {
            Some(_) = lock_stream.next() => {
                info!("Screen locked — zeroizing in-memory keys and locking vault.");
                if let Err(e) = service.lock().await {
                    error!("Error locking vault on screen lock: {}", e);
                }
            }
            Some(prop_change) = active_stream.next() => {
                if let Ok(active) = prop_change.get().await {
                    if !active {
                        info!("Session became inactive (user switched or display suspended) — locking vault.");
                        if let Err(e) = service.lock().await {
                            error!("Error locking vault on session deactivation: {}", e);
                        }
                    }
                }
            }
            else => break,
        }
    }

    Ok(())
}
