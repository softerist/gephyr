use crate::proxy::config::{ProxyEntry, ProxyPoolConfig, ProxySelectionStrategy};
use dashmap::DashMap;
use futures::{stream, StreamExt};
use reqwest::Client;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock};

use std::sync::OnceLock;
pub static GLOBAL_PROXY_POOL: OnceLock<Arc<ProxyPoolManager>> = OnceLock::new();
pub fn get_global_proxy_pool() -> Option<Arc<ProxyPoolManager>> {
    GLOBAL_PROXY_POOL.get().cloned()
}
pub fn init_global_proxy_pool(config: Arc<RwLock<ProxyPoolConfig>>) -> Arc<ProxyPoolManager> {
    let manager = Arc::new(ProxyPoolManager::new(config));
    let _ = GLOBAL_PROXY_POOL.set(manager.clone());
    manager
}
#[derive(Debug, Clone)]
pub struct PoolProxyConfig {
    pub proxy: reqwest::Proxy,
    pub entry_id: String,
}

#[derive(Debug, Clone, Copy, Default, serde::Serialize)]
pub struct ProxyPoolObservabilitySnapshot {
    pub shared_fallback_selections_total: u64,
    pub strict_rejections_total: u64,
}

pub struct ProxyPoolManager {
    config: Arc<RwLock<ProxyPoolConfig>>,
    total_usage_counter: Arc<DashMap<String, usize>>,
    account_bindings: Arc<DashMap<String, String>>,
    round_robin_index: Arc<AtomicUsize>,
    shared_fallback_selections_total: Arc<AtomicU64>,
    strict_rejections_total: Arc<AtomicU64>,
    bind_lock: Mutex<()>,
}

impl ProxyPoolManager {
    pub fn new(config: Arc<RwLock<ProxyPoolConfig>>) -> Self {
        let account_bindings = Arc::new(DashMap::new());
        if let Ok(cfg) = config.try_read() {
            for (account_id, proxy_id) in &cfg.account_bindings {
                account_bindings.insert(account_id.clone(), proxy_id.clone());
            }
            if !cfg.account_bindings.is_empty() {
                tracing::info!(
                    "[ProxyPool] Loaded {} account bindings from config",
                    cfg.account_bindings.len()
                );
            }
        }

        Self {
            config,
            total_usage_counter: Arc::new(DashMap::new()),
            account_bindings,
            round_robin_index: Arc::new(AtomicUsize::new(0)),
            shared_fallback_selections_total: Arc::new(AtomicU64::new(0)),
            strict_rejections_total: Arc::new(AtomicU64::new(0)),
            bind_lock: Mutex::new(()),
        }
    }
    pub async fn get_effective_client(
        &self,
        account_id: Option<&str>,
        timeout_secs: u64,
    ) -> Result<Client, String> {
        let mut builder = crate::utils::http::apply_tls_backend(Client::builder())
            .timeout(Duration::from_secs(timeout_secs))
            .user_agent(crate::constants::USER_AGENT.as_str());
        let proxy_opt = if let Some(acc_id) = account_id {
            self.get_proxy_for_account(acc_id).await?
        } else {
            let config = self.config.read().await;
            if config.enabled {
                let res = self.select_proxy_from_pool(&config).await.ok().flatten();
                if let Some(ref p) = res {
                    tracing::info!(
                        "[Proxy] Route: Generic Request -> Proxy {} (Pool)",
                        p.entry_id
                    );
                } else {
                    tracing::warn!("[Proxy] Route: Generic Request -> No available proxy in pool, falling back to upstream or direct");
                }
                res
            } else {
                tracing::debug!("[Proxy] Route: Generic Request -> Proxy pool disabled");
                None
            }
        };

        if let Some(proxy_cfg) = proxy_opt {
            builder = builder.proxy(proxy_cfg.proxy);
        } else if let Ok(app_cfg) = crate::modules::system::config::load_app_config() {
            let up = app_cfg.proxy.upstream_proxy;
            if up.enabled && !up.url.is_empty() {
                if let Ok(p) = reqwest::Proxy::all(&up.url) {
                    tracing::info!(
                        "[Proxy] Route: {:?} -> Upstream: {} (AppConfig)",
                        account_id.unwrap_or("Generic"),
                        up.url
                    );
                    builder = builder.proxy(p);
                }
            } else {
                tracing::info!(
                    "[Proxy] Route: {:?} -> Direct",
                    account_id.unwrap_or("Generic")
                );
            }
        }

        builder
            .build()
            .map_err(|e| format!("Failed to build effective HTTP client: {}", e))
    }
    pub async fn get_proxy_for_account(
        &self,
        account_id: &str,
    ) -> Result<Option<PoolProxyConfig>, String> {
        let config = self.config.read().await;

        if !config.enabled || config.proxies.is_empty() {
            if config.require_proxy_for_account_requests {
                self.note_strict_rejection(
                    account_id,
                    "pool disabled or no proxies configured",
                );
                return Err(
                    "Proxy routing rejected: proxy pool is disabled or has no proxies configured"
                        .to_string(),
                );
            }
            return Ok(None);
        }
        if let Some(proxy) = self.get_bound_proxy(account_id, &config).await? {
            tracing::info!(
                "[Proxy] Route: Account {} -> Proxy {} (Bound)",
                account_id,
                proxy.entry_id
            );
            return Ok(Some(proxy));
        }
        let res = self.select_proxy_from_pool(&config).await?;
        if let Some(ref p) = res {
            tracing::info!(
                "[Proxy] Route: Account {} -> Proxy {} (Pool)",
                account_id,
                p.entry_id
            );
        }
        if res.is_none() && config.require_proxy_for_account_requests {
            self.note_strict_rejection(account_id, "no eligible proxy available");
            return Err(format!(
                "Proxy routing rejected for account {}: no eligible proxy available",
                account_id
            ));
        }
        Ok(res)
    }
    async fn get_bound_proxy(
        &self,
        account_id: &str,
        config: &ProxyPoolConfig,
    ) -> Result<Option<PoolProxyConfig>, String> {
        if let Some(proxy_id) = self.account_bindings.get(account_id) {
            if let Some(entry) = config.proxies.iter().find(|p| p.id == *proxy_id.value()) {
                if entry.enabled {
                    if config.auto_failover && !entry.is_healthy {
                        return Ok(None);
                    }
                    return Ok(Some(self.build_proxy_config(entry)?));
                }
            }
        }
        Ok(None)
    }
    async fn select_proxy_from_pool(
        &self,
        config: &ProxyPoolConfig,
    ) -> Result<Option<PoolProxyConfig>, String> {
        let bound_ids: std::collections::HashSet<String> = self
            .account_bindings
            .iter()
            .map(|kv| kv.value().clone())
            .collect();

        let healthy_proxies: Vec<_> = config
            .proxies
            .iter()
            .filter(|p| {
                if !p.enabled {
                    return false;
                }
                if config.auto_failover && !p.is_healthy {
                    return false;
                }
                if bound_ids.contains(&p.id) {
                    return false;
                }
                true
            })
            .collect();

        if healthy_proxies.is_empty() {
            if !config.allow_shared_proxy_fallback {
                tracing::warn!(
                    "[ProxyPool] All healthy proxies are currently bound; shared fallback is disabled."
                );
                return Ok(None);
            }
            let shared_healthy: Vec<_> = config
                .proxies
                .iter()
                .filter(|p| {
                    if !p.enabled {
                        return false;
                    }
                    if config.auto_failover && !p.is_healthy {
                        return false;
                    }
                    true
                })
                .collect();
            if shared_healthy.is_empty() {
                return Ok(None);
            }
            tracing::warn!(
                "[ProxyPool] All healthy proxies are currently bound; allowing shared proxy selection for unbound account."
            );
            let selected = self.select_and_build_proxy(config, &shared_healthy)?;
            if selected.is_some() {
                self.note_shared_fallback_selection(config, shared_healthy.len());
            }
            return Ok(selected);
        }

        self.select_and_build_proxy(config, &healthy_proxies)
    }

    pub fn get_observability_snapshot(&self) -> ProxyPoolObservabilitySnapshot {
        ProxyPoolObservabilitySnapshot {
            shared_fallback_selections_total: self
                .shared_fallback_selections_total
                .load(Ordering::Relaxed),
            strict_rejections_total: self.strict_rejections_total.load(Ordering::Relaxed),
        }
    }

    fn note_shared_fallback_selection(&self, config: &ProxyPoolConfig, candidate_count: usize) {
        let total = self
            .shared_fallback_selections_total
            .fetch_add(1, Ordering::Relaxed)
            + 1;
        tracing::warn!(
            "[ProxyPool] Shared fallback selection used (total={}, strategy={:?}, candidates={})",
            total,
            config.strategy,
            candidate_count
        );
    }

    fn note_strict_rejection(&self, account_id: &str, reason: &str) {
        let total = self.strict_rejections_total.fetch_add(1, Ordering::Relaxed) + 1;
        tracing::warn!(
            "[ProxyPool] Strict account routing rejection for {}: {} (total={})",
            account_id,
            reason,
            total
        );
    }

    fn select_and_build_proxy(
        &self,
        config: &ProxyPoolConfig,
        candidates: &[&ProxyEntry],
    ) -> Result<Option<PoolProxyConfig>, String> {
        let selected = match config.strategy {
            ProxySelectionStrategy::RoundRobin => self.select_round_robin(candidates),
            ProxySelectionStrategy::Random => self.select_random(candidates),
            ProxySelectionStrategy::Priority => self.select_by_priority(candidates),
            ProxySelectionStrategy::LeastConnections => self.select_least_connections(candidates),
            ProxySelectionStrategy::WeightedRoundRobin => self.select_weighted(candidates),
        };

        if let Some(entry) = selected {
            *self
                .total_usage_counter
                .entry(entry.id.clone())
                .or_insert(0) += 1;
            Ok(Some(self.build_proxy_config(entry)?))
        } else {
            Ok(None)
        }
    }

    fn select_round_robin<'a>(&self, proxies: &[&'a ProxyEntry]) -> Option<&'a ProxyEntry> {
        if proxies.is_empty() {
            return None;
        }
        let index = self.round_robin_index.fetch_add(1, Ordering::Relaxed);
        Some(proxies[index % proxies.len()])
    }

    fn select_random<'a>(&self, proxies: &[&'a ProxyEntry]) -> Option<&'a ProxyEntry> {
        if proxies.is_empty() {
            return None;
        }
        use rand::seq::SliceRandom;
        let mut rng = rand::thread_rng();
        proxies.choose(&mut rng).copied()
    }

    fn select_by_priority<'a>(&self, proxies: &[&'a ProxyEntry]) -> Option<&'a ProxyEntry> {
        proxies.iter().min_by_key(|p| p.priority).copied()
    }

    fn select_least_connections<'a>(&self, proxies: &[&'a ProxyEntry]) -> Option<&'a ProxyEntry> {
        proxies
            .iter()
            .min_by_key(|p| self.total_usage_counter.get(&p.id).map(|v| *v).unwrap_or(0))
            .copied()
    }

    fn select_weighted<'a>(&self, proxies: &[&'a ProxyEntry]) -> Option<&'a ProxyEntry> {
        if proxies.is_empty() {
            return None;
        }

        use rand::distributions::WeightedIndex;
        use rand::prelude::Distribution;

        let max_priority = proxies.iter().map(|p| p.priority as i64).max().unwrap_or(0);
        let weights: Vec<u64> = proxies
            .iter()
            .map(|p| (max_priority - (p.priority as i64) + 1).max(1) as u64)
            .collect();

        let mut rng = rand::thread_rng();
        let dist = WeightedIndex::new(&weights).ok()?;
        Some(proxies[dist.sample(&mut rng)])
    }
    fn build_proxy_config(&self, entry: &ProxyEntry) -> Result<PoolProxyConfig, String> {
        let url = if !entry.url.contains("://") && !entry.url.is_empty() {
            format!("http://{}", entry.url)
        } else {
            entry.url.clone()
        };

        let mut proxy =
            reqwest::Proxy::all(&url).map_err(|e| format!("Invalid proxy URL: {}", e))?;
        if let Some(auth) = &entry.auth {
            proxy = proxy.basic_auth(&auth.username, &auth.password);
        }

        Ok(PoolProxyConfig {
            proxy,
            entry_id: entry.id.clone(),
        })
    }
    pub async fn bind_account_to_proxy(
        &self,
        account_id: String,
        proxy_id: String,
    ) -> Result<(), String> {
        let _guard = self.bind_lock.lock().await;
        {
            let config = self.config.read().await;
            if !config.proxies.iter().any(|p| p.id == proxy_id) {
                return Err(format!("Proxy {} not found", proxy_id));
            }
            if let Some(entry) = config.proxies.iter().find(|p| p.id == proxy_id) {
                if let Some(max) = entry.max_accounts {
                    if max > 0 {
                        let current_count = self
                            .account_bindings
                            .iter()
                            .filter(|kv| *kv.value() == proxy_id)
                            .count();
                        if current_count >= max {
                            return Err(format!(
                                "Proxy {} has reached max accounts limit",
                                proxy_id
                            ));
                        }
                    }
                }
            }
        }
        self.account_bindings
            .insert(account_id.clone(), proxy_id.clone());
        self.persist_bindings().await;

        tracing::info!(
            "[ProxyPool] Bound account {} to proxy {}",
            account_id,
            proxy_id
        );
        Ok(())
    }
    pub async fn unbind_account_proxy(&self, account_id: String) {
        self.account_bindings.remove(&account_id);
        self.persist_bindings().await;

        tracing::info!("[ProxyPool] Unbound account {}", account_id);
    }
    pub fn get_account_binding(&self, account_id: &str) -> Option<String> {
        self.account_bindings
            .get(account_id)
            .map(|v| v.value().clone())
    }
    pub fn get_all_bindings_snapshot(&self) -> std::collections::HashMap<String, String> {
        self.account_bindings
            .iter()
            .map(|kv| (kv.key().clone(), kv.value().clone()))
            .collect()
    }
    async fn persist_bindings(&self) {
        let bindings = self.get_all_bindings_snapshot();
        {
            let mut config = self.config.write().await;
            config.account_bindings = bindings;
        }
        if let Ok(mut app_config) = crate::modules::system::config::load_app_config() {
            let config = self.config.read().await;
            app_config.proxy.proxy_pool = config.clone();
            if let Err(e) = crate::modules::system::config::save_app_config(&app_config) {
                tracing::error!("[ProxyPool] Failed to persist bindings: {}", e);
            }
        }
    }
    pub async fn health_check(&self) -> Result<(), String> {
        let proxies_to_check: Vec<_> = {
            let config = self.config.read().await;
            config
                .proxies
                .iter()
                .filter(|p| p.enabled)
                .cloned()
                .collect()
        };

        let concurrency_limit = 20usize;
        let results = stream::iter(proxies_to_check)
            .map(|proxy| async move {
                let (is_healthy, latency) = self.check_proxy_health(&proxy).await;

                let latency_msg = if let Some(ms) = latency {
                    format!("{}ms", ms)
                } else {
                    "-".to_string()
                };

                tracing::info!(
                    "Proxy {} ({}) health check: {} (Latency: {})",
                    proxy.name,
                    proxy.url,
                    if is_healthy { "✓ OK" } else { "✗ FAILED" },
                    latency_msg
                );

                (proxy.id, is_healthy, latency)
            })
            .buffer_unordered(concurrency_limit)
            .collect::<Vec<_>>()
            .await;
        let mut config = self.config.write().await;
        for (id, is_healthy, latency) in results {
            if let Some(proxy) = config.proxies.iter_mut().find(|p| p.id == id) {
                proxy.is_healthy = is_healthy;
                proxy.latency = latency;
                proxy.last_check_time = Some(chrono::Utc::now().timestamp());
            }
        }

        Ok(())
    }

    fn health_check_status_is_healthy(status: reqwest::StatusCode, expects_204: bool) -> bool {
        if expects_204 {
            status == reqwest::StatusCode::NO_CONTENT
        } else {
            status.is_success()
        }
    }

    async fn check_proxy_health(&self, entry: &ProxyEntry) -> (bool, Option<u64>) {
        let (check_url, expects_204) = if let Some(url) = &entry.health_check_url {
            if url.trim().is_empty() {
                ("http://cp.cloudflare.com/generate_204", true)
            } else {
                (url.as_str(), false)
            }
        } else {
            ("http://cp.cloudflare.com/generate_204", true)
        };
        let proxy_res = self.build_proxy_config(entry);
        if let Err(e) = proxy_res {
            tracing::error!("Proxy {} build config failed: {}", entry.url, e);
            return (false, None);
        }
        let proxy_cfg = proxy_res.unwrap();

        let client_result = crate::utils::http::apply_tls_backend(Client::builder())
            .proxy(proxy_cfg.proxy)
            .timeout(Duration::from_secs(10))
            .user_agent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
            .build();

        let client = match client_result {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Proxy {} build client failed: {}", entry.url, e);
                return (false, None);
            }
        };

        let start = std::time::Instant::now();
        match client.get(check_url).send().await {
            Ok(resp) => {
                let latency = start.elapsed().as_millis() as u64;
                if Self::health_check_status_is_healthy(resp.status(), expects_204) {
                    (true, Some(latency))
                } else {
                    tracing::warn!(
                        "Proxy {} health check status error: {} (expects_204={})",
                        entry.url,
                        resp.status(),
                        expects_204
                    );
                    (false, None)
                }
            }
            Err(e) => {
                tracing::warn!("Proxy {} health check request failed: {}", entry.url, e);
                (false, None)
            }
        }
    }
    pub fn start_health_check_loop(self: Arc<Self>) {
        tokio::spawn(async move {
            tracing::info!("Starting proxy pool health check loop...");
            loop {
                let enabled = self.config.read().await.enabled;
                if enabled {
                    if let Err(e) = self.health_check().await {
                        tracing::error!("Proxy pool health check failed: {}", e);
                    }
                }
                let interval_secs = {
                    let cfg = self.config.read().await;
                    if !cfg.enabled {
                        60
                    } else {
                        cfg.health_check_interval.max(30)
                    }
                };

                tokio::time::sleep(Duration::from_secs(interval_secs)).await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn build_proxy_entry(id: &str, priority: i32) -> ProxyEntry {
        ProxyEntry {
            id: id.to_string(),
            name: id.to_string(),
            url: "http://127.0.0.1:8080".to_string(),
            auth: None,
            enabled: true,
            priority,
            tags: vec![],
            max_accounts: None,
            health_check_url: None,
            last_check_time: None,
            is_healthy: true,
            latency: None,
        }
    }

    #[tokio::test]
    async fn select_proxy_from_pool_allows_shared_selection_when_all_proxies_are_bound() {
        let mut bindings = HashMap::new();
        bindings.insert("acct-1".to_string(), "proxy-a".to_string());
        bindings.insert("acct-2".to_string(), "proxy-b".to_string());
        let cfg = ProxyPoolConfig {
            enabled: true,
            proxies: vec![
                build_proxy_entry("proxy-a", 1),
                build_proxy_entry("proxy-b", 2),
            ],
            health_check_interval: 300,
            auto_failover: true,
            allow_shared_proxy_fallback: true,
            require_proxy_for_account_requests: false,
            strategy: ProxySelectionStrategy::Priority,
            account_bindings: bindings,
        };
        let manager = ProxyPoolManager::new(Arc::new(RwLock::new(cfg.clone())));

        let selected = manager
            .select_proxy_from_pool(&cfg)
            .await
            .expect("selection should succeed");

        assert!(
            selected.is_some(),
            "unbound account selection should not fail when all healthy proxies are bound"
        );
        assert_eq!(
            selected.expect("selected proxy").entry_id,
            "proxy-a",
            "priority strategy should still be applied in shared-selection mode"
        );
        let snapshot = manager.get_observability_snapshot();
        assert_eq!(snapshot.shared_fallback_selections_total, 1);
        assert_eq!(snapshot.strict_rejections_total, 0);
    }

    #[tokio::test]
    async fn least_connections_uses_total_historical_usage_counter() {
        let cfg = ProxyPoolConfig {
            enabled: true,
            proxies: vec![
                build_proxy_entry("proxy-a", 1),
                build_proxy_entry("proxy-b", 2),
            ],
            health_check_interval: 300,
            auto_failover: true,
            allow_shared_proxy_fallback: true,
            require_proxy_for_account_requests: false,
            strategy: ProxySelectionStrategy::LeastConnections,
            account_bindings: HashMap::new(),
        };
        let manager = ProxyPoolManager::new(Arc::new(RwLock::new(cfg.clone())));
        manager.total_usage_counter.insert("proxy-a".to_string(), 8);
        manager.total_usage_counter.insert("proxy-b".to_string(), 1);

        let selected = manager
            .select_proxy_from_pool(&cfg)
            .await
            .expect("selection should succeed")
            .expect("proxy should be selected");

        assert_eq!(selected.entry_id, "proxy-b");
    }

    #[test]
    fn default_health_check_requires_204() {
        assert!(ProxyPoolManager::health_check_status_is_healthy(
            reqwest::StatusCode::NO_CONTENT,
            true
        ));
        assert!(!ProxyPoolManager::health_check_status_is_healthy(
            reqwest::StatusCode::OK,
            true
        ));
    }

    #[test]
    fn custom_health_check_accepts_any_2xx() {
        assert!(ProxyPoolManager::health_check_status_is_healthy(
            reqwest::StatusCode::OK,
            false
        ));
        assert!(ProxyPoolManager::health_check_status_is_healthy(
            reqwest::StatusCode::NO_CONTENT,
            false
        ));
        assert!(!ProxyPoolManager::health_check_status_is_healthy(
            reqwest::StatusCode::BAD_GATEWAY,
            false
        ));
    }

    #[tokio::test]
    async fn select_proxy_from_pool_returns_none_when_shared_fallback_disabled() {
        let mut bindings = HashMap::new();
        bindings.insert("acct-1".to_string(), "proxy-a".to_string());
        bindings.insert("acct-2".to_string(), "proxy-b".to_string());
        let cfg = ProxyPoolConfig {
            enabled: true,
            proxies: vec![
                build_proxy_entry("proxy-a", 1),
                build_proxy_entry("proxy-b", 2),
            ],
            health_check_interval: 300,
            auto_failover: true,
            allow_shared_proxy_fallback: false,
            require_proxy_for_account_requests: false,
            strategy: ProxySelectionStrategy::Priority,
            account_bindings: bindings,
        };
        let manager = ProxyPoolManager::new(Arc::new(RwLock::new(cfg.clone())));

        let selected = manager
            .select_proxy_from_pool(&cfg)
            .await
            .expect("selection should succeed");
        assert!(
            selected.is_none(),
            "selection should return none when all proxies are bound and shared fallback is disabled"
        );
    }

    #[tokio::test]
    async fn get_proxy_for_account_errors_when_required_and_no_proxy_available() {
        let mut bindings = HashMap::new();
        bindings.insert("acct-1".to_string(), "proxy-a".to_string());
        bindings.insert("acct-2".to_string(), "proxy-b".to_string());
        let cfg = ProxyPoolConfig {
            enabled: true,
            proxies: vec![
                build_proxy_entry("proxy-a", 1),
                build_proxy_entry("proxy-b", 2),
            ],
            health_check_interval: 300,
            auto_failover: true,
            allow_shared_proxy_fallback: false,
            require_proxy_for_account_requests: true,
            strategy: ProxySelectionStrategy::Priority,
            account_bindings: bindings,
        };
        let manager = ProxyPoolManager::new(Arc::new(RwLock::new(cfg.clone())));

        let err = manager
            .get_proxy_for_account("acct-unbound")
            .await
            .expect_err("expected strict proxy requirement error");
        assert!(err.contains("no eligible proxy available"));
        let snapshot = manager.get_observability_snapshot();
        assert_eq!(snapshot.strict_rejections_total, 1);
        assert_eq!(snapshot.shared_fallback_selections_total, 0);
    }
}
