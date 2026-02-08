use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

pub(crate) async fn start_auto_cleanup(
    rate_limit_tracker: Arc<crate::proxy::rate_limit::RateLimitTracker>,
    auto_cleanup_handle: &Arc<tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>>,
    cancel_token: &CancellationToken,
) {
    let tracker = rate_limit_tracker;
    let cancel = cancel_token.child_token();

    let handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(15));
        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    tracing::info!("Auto-cleanup task received cancel signal");
                    break;
                }
                _ = interval.tick() => {
                    let cleaned = tracker.cleanup_expired();
                    if cleaned > 0 {
                        tracing::info!(
                            "Auto-cleanup: Removed {} expired rate limit record(s)",
                            cleaned
                        );
                    }
                }
            }
        }
    });

    let mut guard = auto_cleanup_handle.lock().await;
    if let Some(old) = guard.take() {
        old.abort();
        tracing::warn!("Aborted previous auto-cleanup task");
    }
    *guard = Some(handle);

    tracing::info!("Rate limit auto-cleanup task started (interval: 15s)");
}

pub(crate) async fn graceful_shutdown(
    cancel_token: &CancellationToken,
    auto_cleanup_handle: &Arc<tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>>,
    timeout: Duration,
) {
    tracing::info!("Initiating graceful shutdown of background tasks...");

    cancel_token.cancel();

    match tokio::time::timeout(timeout, abort_background_tasks(auto_cleanup_handle)).await {
        Ok(_) => tracing::info!("All background tasks cleaned up gracefully"),
        Err(_) => tracing::warn!(
            "Graceful cleanup timed out after {:?}, tasks were force-aborted",
            timeout
        ),
    }
}

pub(crate) async fn abort_background_tasks(
    auto_cleanup_handle: &Arc<tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>>,
) {
    abort_task(auto_cleanup_handle, "Auto-cleanup task").await;
}

async fn abort_task(
    handle: &Arc<tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>>,
    task_name: &str,
) {
    let Some(handle) = handle.lock().await.take() else {
        return;
    };

    handle.abort();
    match handle.await {
        Ok(()) => tracing::debug!("{} completed", task_name),
        Err(e) if e.is_cancelled() => tracing::info!("{} aborted", task_name),
        Err(e) => tracing::warn!("{} error: {}", task_name, e),
    }
}
