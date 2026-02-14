use crate::modules::auth::account::get_data_dir;
use std::fs;
use std::path::PathBuf;
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
struct LocalTimer;

impl tracing_subscriber::fmt::time::FormatTime for LocalTimer {
    fn format_time(&self, w: &mut tracing_subscriber::fmt::format::Writer<'_>) -> std::fmt::Result {
        let now = chrono::Local::now();
        write!(w, "{}", now.to_rfc3339())
    }
}

pub fn get_log_dir() -> Result<PathBuf, String> {
    let data_dir = get_data_dir()?;
    let log_dir = data_dir.join("logs");

    if !log_dir.exists() {
        fs::create_dir_all(&log_dir)
            .map_err(|e| format!("Failed to create log directory: {}", e))?;
    }

    Ok(log_dir)
}
pub fn init_logger() {
    let _ = tracing_log::LogTracer::init();

    let log_dir = match get_log_dir() {
        Ok(dir) => dir,
        Err(e) => {
            eprintln!("Failed to initialize log directory: {}", e);
            return;
        }
    };
    let file_appender = tracing_appender::rolling::daily(log_dir, "app.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
    let console_layer = fmt::Layer::new()
        .with_target(false)
        .with_thread_ids(false)
        .with_level(true)
        .with_timer(LocalTimer);
    let file_layer = fmt::Layer::new()
        .with_writer(non_blocking)
        .with_ansi(false)
        .with_target(true)
        .with_level(true)
        .with_timer(LocalTimer);
    let filter_layer = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let bridge_layer = crate::modules::system::log_bridge::LogBridgeLayer::new();
    let _ = tracing_subscriber::registry()
        .with(filter_layer)
        .with(console_layer)
        .with(file_layer)
        .with(bridge_layer)
        .try_init();
    std::mem::forget(_guard);

    info!("Log system initialized (Console + File persistence)");
    if let Err(e) = cleanup_old_logs(7) {
        warn!("Failed to cleanup old logs: {}", e);
    }
}
pub fn cleanup_old_logs(days_to_keep: u64) -> Result<(), String> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let log_dir = get_log_dir()?;
    if !log_dir.exists() {
        return Ok(());
    }
    const MAX_TOTAL_SIZE_BYTES: u64 = 1024 * 1024 * 1024;
    const TARGET_SIZE_BYTES: u64 = 512 * 1024 * 1024;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("Failed to get system time: {}", e))?
        .as_secs();

    let cutoff_time = now.saturating_sub(days_to_keep * 24 * 60 * 60);

    let mut entries_info = Vec::new();
    let entries =
        fs::read_dir(&log_dir).map_err(|e| format!("Failed to read log directory: {}", e))?;

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        if let Ok(metadata) = fs::metadata(&path) {
            let modified = metadata.modified().unwrap_or(SystemTime::now());
            let modified_secs = modified
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            let size = metadata.len();
            entries_info.push((path, size, modified_secs));
        }
    }

    let mut deleted_count = 0;
    let mut total_size_freed = 0u64;
    let mut remaining_entries = Vec::new();
    for (path, size, modified_secs) in entries_info {
        if modified_secs < cutoff_time {
            if let Err(e) = fs::remove_file(&path) {
                warn!("Failed to delete old log file {:?}: {}", path, e);
                remaining_entries.push((path, size, modified_secs));
            } else {
                deleted_count += 1;
                total_size_freed += size;
                info!("Deleted old log file (expired): {:?}", path.file_name());
            }
        } else {
            remaining_entries.push((path, size, modified_secs));
        }
    }
    let mut current_total_size: u64 = remaining_entries.iter().map(|(_, size, _)| *size).sum();

    if current_total_size > MAX_TOTAL_SIZE_BYTES {
        info!(
            "Log directory size ({} MB) exceeds limit (1024 MB), starting size-based cleanup...",
            current_total_size / 1024 / 1024
        );
        remaining_entries.sort_by_key(|(_, _, modified)| *modified);

        for (path, size, _) in remaining_entries {
            if current_total_size <= TARGET_SIZE_BYTES {
                break;
            }
            if let Err(e) = fs::remove_file(&path) {
                warn!(
                    "Failed to delete log file during size cleanup {:?}: {}",
                    path, e
                );
            } else {
                deleted_count += 1;
                total_size_freed += size;
                current_total_size -= size;
                info!("Deleted log file (size limit): {:?}", path.file_name());
            }
        }
    }

    if deleted_count > 0 {
        let size_mb = total_size_freed as f64 / 1024.0 / 1024.0;
        info!(
            "Log cleanup completed: deleted {} files, freed {:.2} MB space",
            deleted_count, size_mb
        );
    }

    Ok(())
}
pub fn clear_logs() -> Result<(), String> {
    let log_dir = get_log_dir()?;
    if log_dir.exists() {
        let entries =
            fs::read_dir(&log_dir).map_err(|e| format!("Failed to read log directory: {}", e))?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                let _ = fs::OpenOptions::new().write(true).truncate(true).open(path);
            }
        }
    }
    Ok(())
}
pub fn log_info(message: &str) {
    if let Some(ctx) = crate::modules::system::request_context::try_get() {
        match (ctx.request_id.as_deref(), ctx.correlation_id.as_deref()) {
            (Some(request_id), Some(correlation_id)) => {
                info!(request_id = %request_id, correlation_id = %correlation_id, "{}", message);
            }
            (Some(request_id), None) => {
                info!(request_id = %request_id, "{}", message);
            }
            (None, Some(correlation_id)) => {
                info!(correlation_id = %correlation_id, "{}", message);
            }
            (None, None) => info!("{}", message),
        }
    } else {
        info!("{}", message);
    }
}
pub fn log_warn(message: &str) {
    if let Some(ctx) = crate::modules::system::request_context::try_get() {
        match (ctx.request_id.as_deref(), ctx.correlation_id.as_deref()) {
            (Some(request_id), Some(correlation_id)) => {
                warn!(request_id = %request_id, correlation_id = %correlation_id, "{}", message);
            }
            (Some(request_id), None) => {
                warn!(request_id = %request_id, "{}", message);
            }
            (None, Some(correlation_id)) => {
                warn!(correlation_id = %correlation_id, "{}", message);
            }
            (None, None) => warn!("{}", message),
        }
    } else {
        warn!("{}", message);
    }
}
pub fn log_error(message: &str) {
    if let Some(ctx) = crate::modules::system::request_context::try_get() {
        match (ctx.request_id.as_deref(), ctx.correlation_id.as_deref()) {
            (Some(request_id), Some(correlation_id)) => {
                error!(
                    request_id = %request_id,
                    correlation_id = %correlation_id,
                    "{}",
                    message
                );
            }
            (Some(request_id), None) => {
                error!(request_id = %request_id, "{}", message);
            }
            (None, Some(correlation_id)) => {
                error!(correlation_id = %correlation_id, "{}", message);
            }
            (None, None) => error!("{}", message),
        }
    } else {
        error!("{}", message);
    }
}