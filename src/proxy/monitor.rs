use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyRequestLog {
    pub id: String,
    pub timestamp: i64,
    pub method: String,
    pub url: String,
    pub status: u16,
    pub duration: u64,
    pub model: Option<String>,
    pub mapped_model: Option<String>,
    pub account_email: Option<String>,
    pub client_ip: Option<String>,
    pub error: Option<String>,
    pub request_body: Option<String>,
    pub response_body: Option<String>,
    pub input_tokens: Option<u32>,
    pub output_tokens: Option<u32>,
    pub protocol: Option<String>,
    pub username: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProxyStats {
    pub total_requests: u64,
    pub success_count: u64,
    pub error_count: u64,
}

pub struct ProxyMonitor {
    pub logs: RwLock<VecDeque<ProxyRequestLog>>,
    pub stats: RwLock<ProxyStats>,
    pub max_logs: usize,
    pub enabled: AtomicBool,
}

impl ProxyMonitor {
    pub fn new(max_logs: usize) -> Self {
        Self {
            logs: RwLock::new(VecDeque::with_capacity(max_logs)),
            stats: RwLock::new(ProxyStats::default()),
            max_logs,
            enabled: AtomicBool::new(false),
        }
    }

    pub async fn run_startup_maintenance(&self) {
        let result = tokio::task::spawn_blocking(|| {
            crate::modules::persistence::proxy_db::init_db()?;
            crate::modules::persistence::proxy_db::cleanup_old_logs(30)
        })
        .await;

        match result {
            Ok(Ok(deleted)) => {
                if deleted > 0 {
                    tracing::info!("Auto cleanup: removed {} old logs (>30 days)", deleted);
                }
            }
            Ok(Err(e)) => {
                tracing::error!("Monitor startup maintenance failed: {}", e);
            }
            Err(e) => {
                tracing::error!("Monitor startup maintenance join failed: {}", e);
            }
        }
    }

    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    pub async fn log_request(&self, log: ProxyRequestLog) {
        if !self.is_enabled() {
            return;
        }
        tracing::info!("[Monitor] Logging request: {} {}", log.method, log.url);
        {
            let mut stats = self.stats.write().await;
            stats.total_requests += 1;
            if log.status >= 200 && log.status < 400 {
                stats.success_count += 1;
            } else {
                stats.error_count += 1;
            }
        }
        {
            let mut logs = self.logs.write().await;
            if logs.len() >= self.max_logs {
                logs.pop_back();
            }
            logs.push_front(log.clone());
        }
        let log_to_save = log.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::modules::persistence::proxy_db::save_log(&log_to_save) {
                tracing::error!("Failed to save proxy log to DB: {}", e);
            }
            if let Some(ip) = &log_to_save.client_ip {
                let security_log = crate::modules::persistence::security_db::IpAccessLog {
                    id: uuid::Uuid::new_v4().to_string(),
                    client_ip: ip.clone(),
                    timestamp: log_to_save.timestamp / 1000,
                    method: Some(log_to_save.method.clone()),
                    path: Some(log_to_save.url.clone()),
                    user_agent: None,
                    status: Some(log_to_save.status as i32),
                    duration: Some(log_to_save.duration as i64),
                    api_key_hash: None,
                    blocked: false,
                    block_reason: None,
                    username: log_to_save.username.clone(),
                };

                if let Err(e) =
                    crate::modules::persistence::security_db::save_ip_access_log(&security_log)
                {
                    tracing::error!("Failed to save security log: {}", e);
                }
            }
            if let (Some(account), Some(input), Some(output)) = (
                &log_to_save.account_email,
                log_to_save.input_tokens,
                log_to_save.output_tokens,
            ) {
                let model = log_to_save
                    .model
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string());
                if let Err(e) =
                    crate::modules::stats::token_stats::record_usage(account, &model, input, output)
                {
                    tracing::debug!("Failed to record token stats: {}", e);
                }
            }
        });
    }

    pub async fn get_logs(&self, limit: usize) -> Vec<ProxyRequestLog> {
        let db_result = tokio::task::spawn_blocking(move || {
            crate::modules::persistence::proxy_db::get_logs(limit)
        })
        .await;

        match db_result {
            Ok(Ok(logs)) => logs,
            Ok(Err(e)) => {
                tracing::error!("Failed to get logs from DB: {}", e);
                let logs = self.logs.read().await;
                logs.iter().take(limit).cloned().collect()
            }
            Err(e) => {
                tracing::error!("Spawn blocking failed for get_logs: {}", e);
                let logs = self.logs.read().await;
                logs.iter().take(limit).cloned().collect()
            }
        }
    }

    pub async fn get_stats(&self) -> ProxyStats {
        let db_result =
            tokio::task::spawn_blocking(crate::modules::persistence::proxy_db::get_stats).await;

        match db_result {
            Ok(Ok(stats)) => stats,
            Ok(Err(e)) => {
                tracing::error!("Failed to get stats from DB: {}", e);
                self.stats.read().await.clone()
            }
            Err(e) => {
                tracing::error!("Spawn blocking failed for get_stats: {}", e);
                self.stats.read().await.clone()
            }
        }
    }

    pub async fn get_logs_filtered(
        &self,
        page: usize,
        page_size: usize,
        search_text: Option<String>,
        level: Option<String>,
    ) -> Result<Vec<ProxyRequestLog>, String> {
        let offset = (page.max(1) - 1) * page_size;
        let errors_only = level.as_deref() == Some("error");
        let search = search_text.unwrap_or_default();

        let res = tokio::task::spawn_blocking(move || {
            crate::modules::persistence::proxy_db::get_logs_filtered(
                &search,
                errors_only,
                page_size,
                offset,
            )
        })
        .await;

        match res {
            Ok(r) => r,
            Err(e) => Err(format!("Spawn blocking failed: {}", e)),
        }
    }

    pub async fn clear(&self) {
        let mut logs = self.logs.write().await;
        logs.clear();
        let mut stats = self.stats.write().await;
        *stats = ProxyStats::default();

        let _ = tokio::task::spawn_blocking(|| {
            if let Err(e) = crate::modules::persistence::proxy_db::clear_logs() {
                tracing::error!("Failed to clear logs in DB: {}", e);
            }
        })
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::ProxyMonitor;

    #[test]
    fn constructor_is_runtime_safe() {
        let result = std::panic::catch_unwind(|| ProxyMonitor::new(16));
        assert!(
            result.is_ok(),
            "constructor should not require Tokio runtime"
        );
    }
}
