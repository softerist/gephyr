// Upstream client implementation
// Encapsulated based on high-performance communication interface

use std::sync::Arc;
use dashmap::DashMap;
use reqwest::{header, Client, Response, StatusCode};
use serde_json::Value;
use tokio::time::Duration;
use tokio::sync::RwLock;

// Cloud Code v1internal endpoints (fallback order: Sandbox → Daily → Prod)
// Prioritize Sandbox/Daily environment to avoid 429 errors from the Prod environment
const V1_INTERNAL_BASE_URL_PROD: &str = "https://cloudcode-pa.googleapis.com/v1internal";
const V1_INTERNAL_BASE_URL_DAILY: &str = "https://daily-cloudcode-pa.googleapis.com/v1internal";
const V1_INTERNAL_BASE_URL_SANDBOX: &str = "https://daily-cloudcode-pa.sandbox.googleapis.com/v1internal";

const V1_INTERNAL_BASE_URL_FALLBACKS: [&str; 3] = [
    V1_INTERNAL_BASE_URL_SANDBOX, // Priority 1: Sandbox (Known to be effective and stable)
    V1_INTERNAL_BASE_URL_DAILY,   // Priority 2: Daily (Backup)
    V1_INTERNAL_BASE_URL_PROD,    // Priority 3: Prod (Only as fallback)
];

pub struct UpstreamClient {
    default_client: Client,
    proxy_pool: Option<Arc<crate::proxy::proxy_pool::ProxyPoolManager>>,
    client_cache: DashMap<String, Client>, // proxy_id -> Client
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

    // Internal helper to build a client with optional upstream proxy config
    fn build_client_internal(proxy_config: Option<crate::proxy::config::UpstreamProxyConfig>) -> Result<Client, reqwest::Error> {
        let mut builder = Client::builder()
            // Connection settings (Optimize connection reuse, reduce handshake overhead)
            .connect_timeout(Duration::from_secs(20))
            .pool_max_idle_per_host(16)                  // Up to 16 idle connections per host
            .pool_idle_timeout(Duration::from_secs(90))  // Idle connections kept for 90 seconds
            .tcp_keepalive(Duration::from_secs(60))      // TCP keepalive probe 60 seconds
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
    
    // Build a client with a specific PoolProxyConfig (from ProxyPool)
    fn build_client_with_proxy(&self, proxy_config: crate::proxy::proxy_pool::PoolProxyConfig) -> Result<Client, reqwest::Error> {
        // Reuse base settings similar to default client but with specific proxy
        Client::builder()
            .connect_timeout(Duration::from_secs(20))
            .pool_max_idle_per_host(16)
            .pool_idle_timeout(Duration::from_secs(90))
            .tcp_keepalive(Duration::from_secs(60))
            .timeout(Duration::from_secs(600))
            .user_agent(crate::constants::USER_AGENT.as_str())
            .proxy(proxy_config.proxy) // Apply the specific proxy
            .build()
    }

    // Set dynamic User-Agent override
    pub async fn set_user_agent_override(&self, ua: Option<String>) {
        let mut lock = self.user_agent_override.write().await;
        *lock = ua;
        tracing::debug!("UpstreamClient User-Agent override updated: {:?}", lock);
    }

    // Get current User-Agent
    pub async fn get_user_agent(&self) -> String {
        let ua_override = self.user_agent_override.read().await;
        ua_override.as_ref().cloned().unwrap_or_else(|| crate::constants::USER_AGENT.clone())
    }

    // Get client for a specific account (or default if no proxy bound)
    pub async fn get_client(&self, account_id: Option<&str>) -> Client {
        if let Some(pool) = &self.proxy_pool {
            if let Some(acc_id) = account_id {
                // Try to get per-account proxy
                match pool.get_proxy_for_account(acc_id).await {
                    Ok(Some(proxy_cfg)) => {
                         // Check cache
                         if let Some(client) = self.client_cache.get(&proxy_cfg.entry_id) {
                             return client.clone();
                         }
                         // Build new client and cache it
                         match self.build_client_with_proxy(proxy_cfg.clone()) {
                             Ok(client) => {
                                 self.client_cache.insert(proxy_cfg.entry_id.clone(), client.clone());
                                 tracing::info!("Using ProxyPool proxy ID: {} for account: {}", proxy_cfg.entry_id, acc_id);
                                 return client;
                             }
                             Err(e) => {
                                 tracing::error!("Failed to build client for proxy {}: {}, falling back to default", proxy_cfg.entry_id, e);
                             }
                         }
                    }
                    Ok(None) => {
                        // No proxy found or required for this account, use default
                    }
                    Err(e) => {
                        tracing::error!("Error getting proxy for account {}: {}, falling back to default", acc_id, e);
                    }
                }
            }
        }
        // Fallback to default client
        self.default_client.clone()
    }


    // Build v1internal URL
    fn build_url(base_url: &str, method: &str, query_string: Option<&str>) -> String {
        if let Some(qs) = query_string {
            format!("{}:{}?{}", base_url, method, qs)
        } else {
            format!("{}:{}", base_url, method)
        }
    }

    // Determine if we should try next endpoint (fallback logic)
    fn should_try_next_endpoint(status: StatusCode) -> bool {
        status == StatusCode::TOO_MANY_REQUESTS
            || status == StatusCode::REQUEST_TIMEOUT
            || status == StatusCode::NOT_FOUND
            || status.is_server_error()
    }

    // Call v1internal API (Basic Method)
    // 
    // Initiates a basic network request, supporting multi-endpoint auto-fallback.
    // [UPDATED] Takes optional account_id for per-account proxy selection.
    pub async fn call_v1_internal(
        &self,
        method: &str,
        access_token: &str,
        body: Value,
        query_string: Option<&str>,
        account_id: Option<&str>, //  Account ID for proxy selection
    ) -> Result<Response, String> {
        self.call_v1_internal_with_headers(method, access_token, body, query_string, std::collections::HashMap::new(), account_id).await
    }

    // Call v1internal API, supports transparently passing additional Headers
    pub async fn call_v1_internal_with_headers(
        &self,
        method: &str,
        access_token: &str,
        body: Value,
        query_string: Option<&str>,
        extra_headers: std::collections::HashMap<String, String>,
        account_id: Option<&str>, //  Account ID
    ) -> Result<Response, String> {
        //  Get client based on account (cached in proxy pool manager)
        let client = self.get_client(account_id).await;

        // Build Headers (Reused across all endpoints)
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

        // Support custom User-Agent override
        headers.insert(
            header::USER_AGENT,
            header::HeaderValue::from_str(&self.get_user_agent().await)
                .unwrap_or_else(|e| {
                    tracing::warn!("Invalid User-Agent header value, using fallback: {}", e);
                    header::HeaderValue::from_static("antigravity")
                }),
        );

        // Inject additional Headers (e.g., anthropic-beta)
        for (k, v) in extra_headers {
            if let Ok(hk) = header::HeaderName::from_bytes(k.as_bytes()) {
                if let Ok(hv) = header::HeaderValue::from_str(&v) {
                    headers.insert(hk, hv);
                }
            }
        }

        let mut last_err: Option<String> = None;

        // Traverse all endpoints, automatically switch on failure
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
                            tracing::debug!("✓ Upstream request succeeded | Endpoint: {} | Status: {}", base_url, status);
                        }
                        return Ok(resp);
                    }

                    // Switch if there is a next endpoint and the current error is retryable
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

                    // Non-retryable error or already the last endpoint, return directly
                    return Ok(resp);
                }
                Err(e) => {
                    let msg = format!("HTTP request failed at {}: {}", base_url, e);
                    tracing::debug!("{}", msg);
                    last_err = Some(msg);

                    // If it is the last endpoint, exit the loop
                    if !has_next {
                        break;
                    }
                    continue;
                }
            }
        }

        Err(last_err.unwrap_or_else(|| "All endpoints failed".to_string()))
    }

    // Call v1internal API (with 429 retry, supports closure)
    // 
    // Core request logic with fault tolerance and retry
    // 
    // # Arguments
    // * `method` - API method (e.g., "generateContent")
    // * `query_string` - Optional query string (e.g., "?alt=sse")
    // * `get_credentials` - Closure, fetch credentials (supports account rotation)
    // * `build_body` - Closure, receives project_id and builds request body
    // * `max_attempts` - Max attempts
    // 
    // # Returns
    // HTTP Response
    // Deprecated retry method removed (call_v1_internal_with_retry)

    // Deprecated helper method removed (parse_retry_delay)

    // Deprecated helper method removed (parse_duration_ms)

    // Fetch available models list
    // 
    // Fetch remote model list, support multi-endpoint auto-fallback
    #[allow(dead_code)] // API ready for future model discovery feature
    pub async fn fetch_available_models(&self, access_token: &str, account_id: Option<&str>) -> Result<Value, String> {
        //  Get client based on account
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

        // Support custom User-Agent override
        headers.insert(
            header::USER_AGENT,
            header::HeaderValue::from_str(&self.get_user_agent().await)
                .unwrap_or_else(|e| {
                    tracing::warn!("Invalid User-Agent header value, using fallback: {}", e);
                    header::HeaderValue::from_static("antigravity")
                }),
        );

        let mut last_err: Option<String> = None;

        // Iterate through all endpoints, automatically switch on failure
        for (idx, base_url) in V1_INTERNAL_BASE_URL_FALLBACKS.iter().enumerate() {
            let url = Self::build_url(base_url, "fetchAvailableModels", None);

            let response = client
                .post(&url)
                .headers(headers.clone())
                .json(&serde_json::json!({}))
                .send()
                .await;

            match response {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        if idx > 0 {
                            tracing::info!(
                                "✓ Upstream fallback succeeded for fetchAvailableModels | Endpoint: {} | Status: {}",
                                base_url,
                                status
                            );
                        } else {
                            tracing::debug!("✓ fetchAvailableModels succeeded | Endpoint: {}", base_url);
                        }
                        let json: Value = resp
                            .json()
                            .await
                            .map_err(|e| format!("Parse json failed: {}", e))?;
                        return Ok(json);
                    }

                    // Switch if there is a next endpoint and the current error is retryable
                    let has_next = idx + 1 < V1_INTERNAL_BASE_URL_FALLBACKS.len();
                    if has_next && Self::should_try_next_endpoint(status) {
                        tracing::warn!(
                            "fetchAvailableModels returned {} at {}, trying next endpoint",
                            status,
                            base_url
                        );
                        last_err = Some(format!("Upstream error: {}", status));
                        continue;
                    }

                    // Non-retryable error or already the last endpoint
                    return Err(format!("Upstream error: {}", status));
                }
                Err(e) => {
                    let msg = format!("Request failed at {}: {}", base_url, e);
                    tracing::debug!("{}", msg);
                    last_err = Some(msg);

                    // If it is the last endpoint, exit the loop
                    if idx + 1 >= V1_INTERNAL_BASE_URL_FALLBACKS.len() {
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

}
