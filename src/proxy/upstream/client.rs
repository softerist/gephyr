use dashmap::DashMap;
use reqwest::{header, Client, Response, StatusCode};
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::Duration;
const V1_INTERNAL_BASE_URL_PROD: &str = "https://cloudcode-pa.googleapis.com/v1internal";
const V1_INTERNAL_BASE_URL_DAILY: &str = "https://daily-cloudcode-pa.googleapis.com/v1internal";
const V1_INTERNAL_BASE_URL_SANDBOX: &str =
    "https://daily-cloudcode-pa.sandbox.googleapis.com/v1internal";

const V1_INTERNAL_BASE_URL_FALLBACKS: [&str; 3] = [
    V1_INTERNAL_BASE_URL_SANDBOX,
    V1_INTERNAL_BASE_URL_DAILY,
    V1_INTERNAL_BASE_URL_PROD,
];

pub struct UpstreamClient {
    default_client: Client,
    proxy_pool: Option<Arc<crate::proxy::proxy_pool::ProxyPoolManager>>,
    client_cache: DashMap<String, Client>,
    user_agent_override: RwLock<Option<String>>,
}

impl UpstreamClient {
    pub fn new(
        proxy_config: Option<crate::proxy::config::UpstreamProxyConfig>,
        proxy_pool: Option<Arc<crate::proxy::proxy_pool::ProxyPoolManager>>,
    ) -> Self {
        let default_client = Self::build_client_internal(proxy_config)
            .expect("Failed to create default HTTP client");

        Self {
            default_client,
            proxy_pool,
            client_cache: DashMap::new(),
            user_agent_override: RwLock::new(None),
        }
    }
    fn build_client_internal(
        proxy_config: Option<crate::proxy::config::UpstreamProxyConfig>,
    ) -> Result<Client, reqwest::Error> {
        let mut builder = Client::builder()
            .connect_timeout(Duration::from_secs(20))
            .pool_max_idle_per_host(16)
            .pool_idle_timeout(Duration::from_secs(90))
            .tcp_keepalive(Duration::from_secs(60))
            .timeout(Duration::from_secs(600))
            .user_agent(crate::constants::USER_AGENT.as_str());

        if let Some(config) = proxy_config {
            if config.enabled && !config.url.is_empty() {
                if let Ok(proxy) = reqwest::Proxy::all(&config.url) {
                    builder = builder.proxy(proxy);
                    tracing::info!("UpstreamClient enabled proxy: {}", config.url);
                }
            }
        }

        builder.build()
    }
    fn build_client_with_proxy(
        &self,
        proxy_config: crate::proxy::proxy_pool::PoolProxyConfig,
    ) -> Result<Client, reqwest::Error> {
        Client::builder()
            .connect_timeout(Duration::from_secs(20))
            .pool_max_idle_per_host(16)
            .pool_idle_timeout(Duration::from_secs(90))
            .tcp_keepalive(Duration::from_secs(60))
            .timeout(Duration::from_secs(600))
            .user_agent(crate::constants::USER_AGENT.as_str())
            .proxy(proxy_config.proxy)
            .build()
    }
    pub async fn set_user_agent_override(&self, ua: Option<String>) {
        let mut lock = self.user_agent_override.write().await;
        *lock = ua;
        tracing::debug!("UpstreamClient User-Agent override updated: {:?}", lock);
    }
    pub async fn get_user_agent(&self) -> String {
        let ua_override = self.user_agent_override.read().await;
        ua_override
            .as_ref()
            .cloned()
            .unwrap_or_else(|| crate::constants::USER_AGENT.clone())
    }
    pub async fn get_client(&self, account_id: Option<&str>) -> Client {
        if let Some(pool) = &self.proxy_pool {
            if let Some(acc_id) = account_id {
                match pool.get_proxy_for_account(acc_id).await {
                    Ok(Some(proxy_cfg)) => {
                        if let Some(client) = self.client_cache.get(&proxy_cfg.entry_id) {
                            return client.clone();
                        }
                        match self.build_client_with_proxy(proxy_cfg.clone()) {
                            Ok(client) => {
                                self.client_cache
                                    .insert(proxy_cfg.entry_id.clone(), client.clone());
                                tracing::info!(
                                    "Using ProxyPool proxy ID: {} for account: {}",
                                    proxy_cfg.entry_id,
                                    acc_id
                                );
                                return client;
                            }
                            Err(e) => {
                                tracing::error!("Failed to build client for proxy {}: {}, falling back to default", proxy_cfg.entry_id, e);
                            }
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        tracing::error!(
                            "Error getting proxy for account {}: {}, falling back to default",
                            acc_id,
                            e
                        );
                    }
                }
            }
        }
        self.default_client.clone()
    }
    fn build_url(base_url: &str, method: &str, query_string: Option<&str>) -> String {
        if let Some(qs) = query_string {
            format!("{}:{}?{}", base_url, method, qs)
        } else {
            format!("{}:{}", base_url, method)
        }
    }
    fn should_try_next_endpoint(status: StatusCode) -> bool {
        status == StatusCode::TOO_MANY_REQUESTS
            || status == StatusCode::REQUEST_TIMEOUT
            || status == StatusCode::NOT_FOUND
            || status.is_server_error()
    }
    pub async fn call_v1_internal(
        &self,
        method: &str,
        access_token: &str,
        body: Value,
        query_string: Option<&str>,
        account_id: Option<&str>,
    ) -> Result<Response, String> {
        self.call_v1_internal_with_headers(
            method,
            access_token,
            body,
            query_string,
            std::collections::HashMap::new(),
            account_id,
        )
        .await
    }
    pub async fn call_v1_internal_with_headers(
        &self,
        method: &str,
        access_token: &str,
        body: Value,
        query_string: Option<&str>,
        extra_headers: std::collections::HashMap<String, String>,
        account_id: Option<&str>,
    ) -> Result<Response, String> {
        let client = self.get_client(account_id).await;
        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("application/json"),
        );
        headers.insert(
            header::AUTHORIZATION,
            header::HeaderValue::from_str(&format!("Bearer {}", access_token))
                .map_err(|e| e.to_string())?,
        );
        headers.insert(
            header::USER_AGENT,
            header::HeaderValue::from_str(&self.get_user_agent().await).unwrap_or_else(|e| {
                tracing::warn!("Invalid User-Agent header value, using fallback: {}", e);
                header::HeaderValue::from_static("antigravity")
            }),
        );
        for (k, v) in extra_headers {
            if let Ok(hk) = header::HeaderName::from_bytes(k.as_bytes()) {
                if let Ok(hv) = header::HeaderValue::from_str(&v) {
                    headers.insert(hk, hv);
                }
            }
        }

        let mut last_err: Option<String> = None;
        for (idx, base_url) in V1_INTERNAL_BASE_URL_FALLBACKS.iter().enumerate() {
            let url = Self::build_url(base_url, method, query_string);
            let has_next = idx + 1 < V1_INTERNAL_BASE_URL_FALLBACKS.len();

            let response = client
                .post(&url)
                .headers(headers.clone())
                .json(&body)
                .send()
                .await;

            match response {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        if idx > 0 {
                            tracing::info!(
                                "✓ Upstream fallback succeeded | Endpoint: {} | Status: {} | Next endpoints available: {}",
                                base_url,
                                status,
                                V1_INTERNAL_BASE_URL_FALLBACKS.len() - idx - 1
                            );
                        } else {
                            tracing::debug!(
                                "✓ Upstream request succeeded | Endpoint: {} | Status: {}",
                                base_url,
                                status
                            );
                        }
                        return Ok(resp);
                    }
                    if has_next && Self::should_try_next_endpoint(status) {
                        tracing::warn!(
                            "Upstream endpoint returned {} at {} (method={}), trying next endpoint",
                            status,
                            base_url,
                            method
                        );
                        last_err = Some(format!("Upstream {} returned {}", base_url, status));
                        continue;
                    }
                    return Ok(resp);
                }
                Err(e) => {
                    let msg = format!("HTTP request failed at {}: {}", base_url, e);
                    tracing::debug!("{}", msg);
                    last_err = Some(msg);
                    if !has_next {
                        break;
                    }
                    continue;
                }
            }
        }

        Err(last_err.unwrap_or_else(|| "All endpoints failed".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_url() {
        let base_url = "https://cloudcode-pa.googleapis.com/v1internal";

        let url1 = UpstreamClient::build_url(base_url, "generateContent", None);
        assert_eq!(
            url1,
            "https://cloudcode-pa.googleapis.com/v1internal:generateContent"
        );

        let url2 = UpstreamClient::build_url(base_url, "streamGenerateContent", Some("alt=sse"));
        assert_eq!(
            url2,
            "https://cloudcode-pa.googleapis.com/v1internal:streamGenerateContent?alt=sse"
        );
    }

    #[test]
    fn test_client_creation_initializes_user_agent_path() {
        let _client = UpstreamClient::new(None, None);
        assert!(crate::constants::USER_AGENT.starts_with("antigravity/"));
    }
}
