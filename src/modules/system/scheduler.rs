use crate::modules::system::{config, logger};
use rand::Rng;
use tokio::time::{self, Duration};

fn scheduler_refresh_jitter_bounds() -> (u64, u64) {
    let min = std::env::var("ABV_SCHEDULER_REFRESH_JITTER_MIN_SECONDS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(30);
    let max = std::env::var("ABV_SCHEDULER_REFRESH_JITTER_MAX_SECONDS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(120);
    if min <= max {
        (min, max)
    } else {
        (max, min)
    }
}

pub fn start_scheduler(proxy_state: crate::commands::proxy::ProxyServiceState) {
    tokio::spawn(async move {
        logger::log_info("Quota refresh scheduler started (warmup disabled in headless mode).");
        let mut interval = time::interval(Duration::from_secs(600));
        let (jitter_min, jitter_max) = scheduler_refresh_jitter_bounds();

        loop {
            interval.tick().await;

            let Ok(app_config) = config::load_app_config() else {
                continue;
            };

            if !app_config.auto_refresh {
                continue;
            }

            let jitter_secs = if jitter_max == 0 {
                0
            } else {
                rand::thread_rng().gen_range(jitter_min..=jitter_max)
            };
            if jitter_secs > 0 {
                logger::log_info(&format!(
                    "[Scheduler] Applying refresh jitter before run: {}s",
                    jitter_secs
                ));
                time::sleep(Duration::from_secs(jitter_secs)).await;
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
