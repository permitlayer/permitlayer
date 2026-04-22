use std::future::Future;
use tokio::sync::broadcast;

/// Create a shutdown signaling pair:
/// - A future that resolves when SIGTERM or SIGINT is received (pass to
///   `axum::serve(...).with_graceful_shutdown()`).
/// - A broadcast sender that notifies cleanup tasks (PID removal, audit flush).
pub fn shutdown_channel() -> (impl Future<Output = ()>, broadcast::Sender<()>) {
    let (tx, _) = broadcast::channel::<()>(1);
    let tx_clone = tx.clone();
    let fut = async move {
        wait_for_shutdown_signal().await;
        tracing::info!("shutdown signal received");
        let _ = tx_clone.send(());
    };
    (fut, tx)
}

/// Await SIGTERM or SIGINT (CTRL+C). Returns when either fires.
#[allow(clippy::expect_used)] // Signal handler registration is infallible in practice.
async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigterm = signal(SignalKind::terminate())
            .expect("static invariant: SIGTERM handler registration");
        let ctrl_c = tokio::signal::ctrl_c();
        tokio::select! {
            _ = ctrl_c => {},
            _ = sigterm.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.expect("static invariant: ctrl-c handler");
    }
}
