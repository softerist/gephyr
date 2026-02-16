use crate::modules::system::{config, logger};
use rand::Rng;
use serde::Serialize;
use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;
use tokio::time::{self, Duration};

fn scheduler_refresh_jitter_bounds() -> (u64, u64) {
    let min = std::env::var("SCHEDULER_REFRESH_JITTER_MIN_SECONDS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(30);
    let max = std::env::var("SCHEDULER_REFRESH_JITTER_MAX_SECONDS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(120);
    if min <= max {
        (min, max)
    } else {
        (max, min)
    }
}

fn scheduler_models_for_log(models: &[String]) -> String {
    if models.is_empty() {
        "none".to_string()
    } else {
        models.join(",")
    }
}

async fn run_scheduled_warmup_if_enabled(
    proxy_state: &crate::commands::proxy::ProxyServiceState,
    app_config: &crate::models::AppConfig,
) {
    if !app_config.scheduled_warmup.enabled {
        return;
    }

    let token_manager = {
        let instance_lock = proxy_state.instance.read().await;
        instance_lock
            .as_ref()
            .map(|instance| instance.token_manager.clone())
    };

    let Some(token_manager) = token_manager else {
        logger::log_warn("[Scheduler] Warmup skipped: proxy service instance is unavailable");
        return;
    };

    let active_accounts = token_manager.len();
    if active_accounts == 0 {
        logger::log_warn("[Scheduler] Warmup skipped: no active accounts");
        return;
    }

    logger::log_info(&format!(
        "[Scheduler] Scheduled warmup started (accounts={}, monitored_models={})",
        active_accounts,
        scheduler_models_for_log(&app_config.scheduled_warmup.monitored_models)
    ));

    let summary = token_manager.run_startup_health_check().await;
    if summary.disabled > 0 || summary.network_errors > 0 {
        logger::log_warn(&format!(
            "[Scheduler] Warmup completed with warnings: total={}, skipped={}, refreshed={}, disabled={}, network_errors={}",
            summary.total,
            summary.skipped,
            summary.refreshed,
            summary.disabled,
            summary.network_errors
        ));
    } else {
        logger::log_info(&format!(
            "[Scheduler] Warmup completed: total={}, skipped={}, refreshed={}",
            summary.total, summary.skipped, summary.refreshed
        ));
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SchedulerRefreshObservabilitySnapshot {
    pub scheduler_refresh_runs_last_minute: usize,
    pub scheduler_refresh_failures_last_minute: usize,
    pub scheduler_refresh_accounts_attempted_last_minute: usize,
}

#[derive(Default)]
struct SchedulerRefreshObservabilityState {
    runs: VecDeque<(Instant, usize, bool)>,
}

fn scheduler_refresh_observability_state() -> &'static Mutex<SchedulerRefreshObservabilityState> {
    static STATE: OnceLock<Mutex<SchedulerRefreshObservabilityState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(SchedulerRefreshObservabilityState::default()))
}

fn cleanup_scheduler_refresh_observability_locked(
    state: &mut SchedulerRefreshObservabilityState,
    now: Instant,
) {
    let window_start = now.checked_sub(Duration::from_secs(60)).unwrap_or(now);
    while let Some((ts, _, _)) = state.runs.front() {
        if *ts < window_start {
            state.runs.pop_front();
        } else {
            break;
        }
    }
}

fn record_scheduler_refresh_run(accounts_attempted: usize, failed: bool) {
    if let Ok(mut state) = scheduler_refresh_observability_state().lock() {
        let now = Instant::now();
        cleanup_scheduler_refresh_observability_locked(&mut state, now);
        state.runs.push_back((now, accounts_attempted, failed));
    }
}

pub fn scheduler_refresh_observability_snapshot() -> SchedulerRefreshObservabilitySnapshot {
    if let Ok(mut state) = scheduler_refresh_observability_state().lock() {
        cleanup_scheduler_refresh_observability_locked(&mut state, Instant::now());

        let mut runs_last_minute = 0usize;
        let mut failures_last_minute = 0usize;
        let mut accounts_attempted_last_minute = 0usize;

        for (_, accounts_attempted, failed) in &state.runs {
            runs_last_minute += 1;
            accounts_attempted_last_minute += *accounts_attempted;
            if *failed {
                failures_last_minute += 1;
            }
        }

        return SchedulerRefreshObservabilitySnapshot {
            scheduler_refresh_runs_last_minute: runs_last_minute,
            scheduler_refresh_failures_last_minute: failures_last_minute,
            scheduler_refresh_accounts_attempted_last_minute: accounts_attempted_last_minute,
        };
    }

    SchedulerRefreshObservabilitySnapshot {
        scheduler_refresh_runs_last_minute: 0,
        scheduler_refresh_failures_last_minute: 0,
        scheduler_refresh_accounts_attempted_last_minute: 0,
    }
}

#[cfg(test)]
fn clear_scheduler_refresh_observability_for_tests() {
    if let Ok(mut state) = scheduler_refresh_observability_state().lock() {
        *state = SchedulerRefreshObservabilityState::default();
    }
}

pub fn start_scheduler(proxy_state: crate::commands::proxy::ProxyServiceState) {
    tokio::spawn(async move {
        logger::log_info("Quota refresh scheduler started.");
        let mut interval = time::interval(Duration::from_secs(600));
        let (jitter_min, jitter_max) = scheduler_refresh_jitter_bounds();

        loop {
            interval.tick().await;

            let Ok(app_config) = config::load_app_config() else {
                continue;
            };

            run_scheduled_warmup_if_enabled(&proxy_state, &app_config).await;

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
                Ok(stats) => {
                    record_scheduler_refresh_run(stats.total, false);
                    logger::log_info(&format!(
                        "[Scheduler] Quota refresh completed: total={}, success={}, failed={}",
                        stats.total, stats.success, stats.failed
                    ));
                }
                Err(e) => {
                    record_scheduler_refresh_run(0, true);
                    logger::log_warn(&format!("[Scheduler] Quota refresh failed: {}", e));
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheduler_refresh_observability_snapshot_tracks_runs() {
        clear_scheduler_refresh_observability_for_tests();

        record_scheduler_refresh_run(3, false);
        record_scheduler_refresh_run(2, true);

        let snapshot = scheduler_refresh_observability_snapshot();
        assert_eq!(snapshot.scheduler_refresh_runs_last_minute, 2);
        assert_eq!(snapshot.scheduler_refresh_failures_last_minute, 1);
        assert_eq!(snapshot.scheduler_refresh_accounts_attempted_last_minute, 5);

        clear_scheduler_refresh_observability_for_tests();
    }

    #[test]
    fn scheduler_models_for_log_renders_empty_and_values() {
        assert_eq!(scheduler_models_for_log(&[]), "none");
        assert_eq!(
            scheduler_models_for_log(&["gemini-2.5-pro".to_string(), "gemini-3-flash".to_string()]),
            "gemini-2.5-pro,gemini-3-flash"
        );
    }
}
