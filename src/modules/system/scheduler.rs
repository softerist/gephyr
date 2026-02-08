use crate::modules::system::{config, logger};
use tokio::time::{self, Duration};

pub fn start_scheduler(proxy_state: crate::commands::proxy::ProxyServiceState) {
    tokio::spawn(async move {
        logger::log_info("Quota refresh scheduler started (warmup disabled in headless mode).");
        let mut interval = time::interval(Duration::from_secs(600));

        loop {
            interval.tick().await;

            let Ok(app_config) = config::load_app_config() else {
                continue;
            };

            if !app_config.auto_refresh {
                continue;
            }

            match crate::commands::refresh_all_quotas_internal(&proxy_state).await {
                Ok(stats) => logger::log_info(&format!(
                    "[Scheduler] Quota refresh completed: total={}, success={}, failed={}",
                    stats.total, stats.success, stats.failed
                )),
                Err(e) => logger::log_warn(&format!("[Scheduler] Quota refresh failed: {}", e)),
            }
        }
    });
}
