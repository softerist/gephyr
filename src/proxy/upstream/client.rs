use dashmap::DashMap;
use reqwest::{Client, Response, StatusCode};
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::Duration;
use crate::proxy::upstream::header_policy::{
    build_google_headers, host_from_url, GoogleHeaderPolicyContext, GoogleHeaderScope,
    GoogleOutboundHeaderPolicy,
};
const V1_INTERNAL_BASE_URL_PROD: &str = "https://cloudcode-pa.googleapis.com/v1internal";

const V1_INTERNAL_BASE_URL_FALLBACKS: [&str; 1] = [V1_INTERNAL_BASE_URL_PROD];

fn load_account_device_profile(account_id: Option<&str>) -> Option<crate::models::DeviceProfile> {
    let id = account_id?;
    crate::modules::auth::account::load_account(id)
        .ok()
        .and_then(|account| account.device_profile)
}

pub struct UpstreamClient {
    default_client: Client,
    proxy_pool: Option<Arc<crate::proxy::proxy_pool::ProxyPoolManager>>,
    client_cache: DashMap<String, Client>,
    user_agent_override: RwLock<Option<String>>,
    google_policy: RwLock<GoogleOutboundHeaderPolicy>,
    v1_internal_base_urls: RwLock<Vec<String>>,
}

impl UpstreamClient {
    pub fn new(
        proxy_config: Option<crate::proxy::config::UpstreamProxyConfig>,
        proxy_pool: Option<Arc<crate::proxy::proxy_pool::ProxyPoolManager>>,
    ) -> Self {
        Self::new_with_policy(
            proxy_config,
            proxy_pool,
            GoogleOutboundHeaderPolicy::default(),
        )
    }

    pub fn new_with_google_config(
        proxy_config: Option<crate::proxy::config::UpstreamProxyConfig>,
        proxy_pool: Option<Arc<crate::proxy::proxy_pool::ProxyPoolManager>>,
        google: crate::proxy::config::GoogleConfig,
        debug: crate::proxy::config::DebugLoggingConfig,
    ) -> Self {
        let base_urls = Self::build_v1_internal_base_urls(&google);
        Self::new_with_policy_and_base_urls(
            proxy_config,
            proxy_pool,
            GoogleOutboundHeaderPolicy::from_proxy_config(google, debug),
            base_urls,
        )
    }

    fn new_with_policy(
        proxy_config: Option<crate::proxy::config::UpstreamProxyConfig>,
        proxy_pool: Option<Arc<crate::proxy::proxy_pool::ProxyPoolManager>>,
        google_policy: GoogleOutboundHeaderPolicy,
    ) -> Self {
        Self::new_with_policy_and_base_urls(
            proxy_config,
            proxy_pool,
            google_policy,
            V1_INTERNAL_BASE_URL_FALLBACKS
                .iter()
                .map(|url| (*url).to_string())
                .collect(),
        )
    }

    fn new_with_policy_and_base_urls(
        proxy_config: Option<crate::proxy::config::UpstreamProxyConfig>,
        proxy_pool: Option<Arc<crate::proxy::proxy_pool::ProxyPoolManager>>,
        google_policy: GoogleOutboundHeaderPolicy,
        v1_internal_base_urls: Vec<String>,
    ) -> Self {
        let default_client = Self::build_client_internal(proxy_config)
            .expect("Failed to create default HTTP client");

        Self {
            default_client,
            proxy_pool,
            client_cache: DashMap::new(),
            user_agent_override: RwLock::new(None),
            google_policy: RwLock::new(google_policy),
            v1_internal_base_urls: RwLock::new(v1_internal_base_urls),
        }
    }

    fn build_v1_internal_base_urls(google: &crate::proxy::config::GoogleConfig) -> Vec<String> {
        let hosts =
            crate::proxy::google::endpoints::cloudcode_hosts_for_profile(google.mimic.profile.clone());
        let mut urls: Vec<String> = hosts
            .into_iter()
            .map(|host| format!("https://{}/v1internal", host))
            .collect();
        if urls.is_empty() {
            urls.push(V1_INTERNAL_BASE_URL_PROD.to_string());
        }
        urls
    }

    #[cfg(test)]
    fn new_for_test(base_url: &str, google_policy: GoogleOutboundHeaderPolicy) -> Self {
        Self::new_with_policy_and_base_urls(
            None,
            None,
            google_policy,
            vec![base_url.to_string()],
        )
    }
    fn build_client_internal(
        proxy_config: Option<crate::proxy::config::UpstreamProxyConfig>,
    ) -> Result<Client, reqwest::Error> {
        let mut builder = crate::utils::http::apply_tls_backend(Client::builder())
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
        crate::utils::http::apply_tls_backend(Client::builder())
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
    pub async fn set_google_policy(&self, policy: GoogleOutboundHeaderPolicy) {
        let mut lock = self.google_policy.write().await;
        *lock = policy;
    }
    pub async fn set_google_runtime_config(
        &self,
        google: crate::proxy::config::GoogleConfig,
        debug: crate::proxy::config::DebugLoggingConfig,
    ) {
        {
            let mut lock = self.google_policy.write().await;
            *lock = GoogleOutboundHeaderPolicy::from_proxy_config(google.clone(), debug);
        }
        let mut urls = self.v1_internal_base_urls.write().await;
        *urls = Self::build_v1_internal_base_urls(&google);
    }
    pub async fn get_google_policy(&self) -> GoogleOutboundHeaderPolicy {
        self.google_policy.read().await.clone()
    }
    pub async fn get_client(&self, account_id: Option<&str>) -> Result<Client, String> {
        if let Some(pool) = &self.proxy_pool {
            if let Some(acc_id) = account_id {
                match pool.get_proxy_for_account(acc_id).await {
                    Ok(Some(proxy_cfg)) => {
                        if let Some(client) = self.client_cache.get(&proxy_cfg.entry_id) {
                            return Ok(client.clone());
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
                                return Ok(client);
                            }
                            Err(e) => {
                                tracing::error!("Failed to build client for proxy {}: {}, falling back to default", proxy_cfg.entry_id, e);
                            }
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        return Err(format!("Error getting proxy for account {}: {}", acc_id, e));
                    }
                }
            }
        }
        Ok(self.default_client.clone())
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
        let client = self.get_client(account_id).await?;
        let user_agent = self.get_user_agent().await;
        let device_profile = load_account_device_profile(account_id);
        let google_policy = self.get_google_policy().await;

        let mut last_err: Option<String> = None;
        let base_urls = self.v1_internal_base_urls.read().await.clone();
        for (idx, base_url) in base_urls.iter().enumerate() {
            let url = Self::build_url(base_url, method, query_string);
            let has_next = idx + 1 < base_urls.len();
            let endpoint_host = host_from_url(&url);
            let headers = build_google_headers(
                GoogleHeaderPolicyContext {
                    endpoint: &url,
                    endpoint_host: endpoint_host.as_deref(),
                    scope: GoogleHeaderScope::Cloudcode,
                    user_agent: &user_agent,
                    access_token: Some(access_token),
                    content_type_json: true,
                    device_profile: device_profile.as_ref(),
                    extra_headers: Some(&extra_headers),
                    force_connection_close: false,
                },
                &google_policy,
            );

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
                                base_urls.len() - idx - 1
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
    use axum::{extract::State, http::HeaderMap, routing::post, Json, Router};
    use serde_json::json;
    use std::sync::Arc;
    use tokio::net::TcpListener;
    use tokio::sync::Mutex as AsyncMutex;

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

    #[derive(Clone, Default)]
    struct UpstreamCaptureState {
        headers: Arc<AsyncMutex<Vec<(String, String)>>>,
    }

    async fn capture_handler(
        State(state): State<UpstreamCaptureState>,
        headers: HeaderMap,
    ) -> Json<serde_json::Value> {
        let mut out = Vec::new();
        for (name, value) in &headers {
            out.push((
                name.as_str().to_string(),
                value.to_str().unwrap_or("<non-utf8>").to_string(),
            ));
        }
        *state.headers.lock().await = out;
        Json(json!({
            "ok": true
        }))
    }

    async fn start_mock_upstream_server() -> (String, UpstreamCaptureState, tokio::task::JoinHandle<()>) {
        let state = UpstreamCaptureState::default();
        let app = Router::new()
            .route("/v1internal:generateContent", post(capture_handler))
            .with_state(state.clone());

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock upstream");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve mock upstream");
        });
        (format!("http://{}/v1internal", addr), state, server)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn call_v1_internal_applies_google_header_policy() {
        let (base_url, state, server) = start_mock_upstream_server().await;
        let client = UpstreamClient::new_for_test(&base_url, GoogleOutboundHeaderPolicy::default());
        let mut extra_headers = std::collections::HashMap::new();
        extra_headers.insert("x-forwarded-for".to_string(), "1.2.3.4".to_string());
        extra_headers.insert("anthropic-beta".to_string(), "context-1m-2025-08-07".to_string());

        let response = client
            .call_v1_internal_with_headers(
                "generateContent",
                "test-access-token",
                json!({"contents":[]}),
                None,
                extra_headers,
                None,
            )
            .await
            .expect("upstream call should succeed");

        assert!(response.status().is_success());
        let captured = state.headers.lock().await.clone();
        server.abort();

        let find = |name: &str| -> Option<String> {
            captured
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.clone())
        };

        assert_eq!(find("authorization"), Some("Bearer test-access-token".to_string()));
        assert_eq!(find("content-type"), Some("application/json".to_string()));
        assert_eq!(
            find("accept-encoding"),
            Some("gzip, deflate, br".to_string())
        );
        assert_eq!(
            find("user-agent"),
            Some(format!(
                "{} google-api-nodejs-client/10.3.0",
                crate::constants::USER_AGENT.as_str()
            ))
        );
        assert_eq!(
            find("anthropic-beta"),
            Some("context-1m-2025-08-07".to_string())
        );
        assert!(find("x-forwarded-for").is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn google_policy_can_be_hot_updated_at_runtime() {
        let client = UpstreamClient::new_for_test(
            "http://127.0.0.1:1/v1internal",
            GoogleOutboundHeaderPolicy::default(),
        );
        let initial = client.get_google_policy().await;
        assert!(matches!(
            initial.mode,
            crate::proxy::config::GoogleMode::CodeassistCompat
        ));

        let mut updated = initial.clone();
        updated.mode = crate::proxy::config::GoogleMode::CodeassistCompat;
        updated.send_host_header = true;
        updated.log_google_outbound_headers = true;
        updated.identity_metadata.ide_type = "UPDATED_IDE".to_string();
        client.set_google_policy(updated.clone()).await;

        let effective = client.get_google_policy().await;
        assert!(matches!(
            effective.mode,
            crate::proxy::config::GoogleMode::CodeassistCompat
        ));
        assert!(effective.send_host_header);
        assert!(effective.log_google_outbound_headers);
        assert_eq!(effective.identity_metadata.ide_type, "UPDATED_IDE");
    }
}
