use crate::proxy::config::{ProxyEntry, ProxyPoolConfig, ProxySelectionStrategy};
use dashmap::DashMap;
use futures::{stream, StreamExt};
use reqwest::Client;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

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
pub struct ProxyPoolManager {
    config: Arc<RwLock<ProxyPoolConfig>>,
    usage_counter: Arc<DashMap<String, usize>>,
    account_bindings: Arc<DashMap<String, String>>,
    round_robin_index: Arc<AtomicUsize>,
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
            usage_counter: Arc::new(DashMap::new()),
            account_bindings,
            round_robin_index: Arc::new(AtomicUsize::new(0)),
        }
    }
    pub async fn get_effective_client(
        &self,
        account_id: Option<&str>,
        timeout_secs: u64,
    ) -> Client {
        let mut builder = Client::builder().timeout(Duration::from_secs(timeout_secs));
        let proxy_opt = if let Some(acc_id) = account_id {
            self.get_proxy_for_account(acc_id).await.ok().flatten()
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

        builder.build().unwrap_or_else(|_| Client::new())
    }
    pub async fn get_proxy_for_account(
        &self,
        account_id: &str,
    ) -> Result<Option<PoolProxyConfig>, String> {
        let config = self.config.read().await;

        if !config.enabled || config.proxies.is_empty() {
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
            return Ok(None);
        }

        let selected = match config.strategy {
            ProxySelectionStrategy::RoundRobin => self.select_round_robin(&healthy_proxies),
            ProxySelectionStrategy::Random => self.select_random(&healthy_proxies),
            ProxySelectionStrategy::Priority => self.select_by_priority(&healthy_proxies),
            ProxySelectionStrategy::LeastConnections => {
                self.select_least_connections(&healthy_proxies)
            }
            ProxySelectionStrategy::WeightedRoundRobin => self.select_weighted(&healthy_proxies),
        };

        if let Some(entry) = selected {
            *self.usage_counter.entry(entry.id.clone()).or_insert(0) += 1;
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
            .min_by_key(|p| self.usage_counter.get(&p.id).map(|v| *v).unwrap_or(0))
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
    async fn check_proxy_health(&self, entry: &ProxyEntry) -> (bool, Option<u64>) {
        let check_url = if let Some(url) = &entry.health_check_url {
            if url.trim().is_empty() {
                "http://cp.cloudflare.com/generate_204"
            } else {
                url.as_str()
            }
        } else {
            "http://cp.cloudflare.com/generate_204"
        };
        let proxy_res = self.build_proxy_config(entry);
        if let Err(e) = proxy_res {
            tracing::error!("Proxy {} build config failed: {}", entry.url, e);
            return (false, None);
        }
        let proxy_cfg = proxy_res.unwrap();

        let client_result = Client::builder()
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
                if resp.status().is_success() {
                    (true, Some(latency))
                } else {
                    tracing::warn!(
                        "Proxy {} health check status error: {}",
                        entry.url,
                        resp.status()
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
