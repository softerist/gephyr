use crate::modules::system::config::load_app_config;
use once_cell::sync::Lazy;
use reqwest::{Client, Proxy};
use serde::Serialize;
use std::sync::{Mutex, OnceLock};

#[cfg(not(any(feature = "tls-native", feature = "tls-rustls")))]
compile_error!("one TLS backend feature must be enabled: `tls-native` or `tls-rustls`");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TlsBackendSelection {
    NativeTls,
    Rustls,
}

#[derive(Debug, Clone, Serialize)]
pub struct TlsCanarySnapshot {
    pub configured: bool,
    pub required: bool,
    pub url: Option<String>,
    pub timeout_seconds: u64,
    pub last_checked_unix: Option<i64>,
    pub last_success_unix: Option<i64>,
    pub last_http_status: Option<u16>,
    pub last_error: Option<String>,
}

impl Default for TlsCanarySnapshot {
    fn default() -> Self {
        Self {
            configured: false,
            required: false,
            url: None,
            timeout_seconds: 5,
            last_checked_unix: None,
            last_success_unix: None,
            last_http_status: None,
            last_error: None,
        }
    }
}

pub static SHARED_CLIENT: Lazy<Client> = Lazy::new(|| create_base_client(15));
pub static SHARED_CLIENT_LONG: Lazy<Client> = Lazy::new(|| create_base_client(60));

fn tls_canary_state() -> &'static Mutex<TlsCanarySnapshot> {
    static STATE: OnceLock<Mutex<TlsCanarySnapshot>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(TlsCanarySnapshot::default()))
}

fn parse_tls_backend_override() -> Option<TlsBackendSelection> {
    let raw = std::env::var("TLS_BACKEND").ok()?;
    match raw.trim().to_ascii_lowercase().as_str() {
        "native" | "native-tls" | "default-tls" => Some(TlsBackendSelection::NativeTls),
        "rustls" => Some(TlsBackendSelection::Rustls),
        _ => None,
    }
}

pub fn tls_requested_backend_name() -> Option<String> {
    parse_tls_backend_override().map(|selection| match selection {
        TlsBackendSelection::NativeTls => "native-tls".to_string(),
        TlsBackendSelection::Rustls => "rustls".to_string(),
    })
}

fn supports_tls_backend(selection: TlsBackendSelection) -> bool {
    match selection {
        TlsBackendSelection::NativeTls => cfg!(feature = "tls-native"),
        TlsBackendSelection::Rustls => cfg!(feature = "tls-rustls"),
    }
}

pub fn tls_compiled_backends() -> Vec<&'static str> {
    let mut backends = Vec::new();
    #[cfg(feature = "tls-native")]
    {
        backends.push("native-tls");
    }
    #[cfg(feature = "tls-rustls")]
    {
        backends.push("rustls");
    }
    backends
}

fn compiled_default_tls_backend() -> TlsBackendSelection {
    #[cfg(all(feature = "tls-native", not(feature = "tls-rustls")))]
    {
        return TlsBackendSelection::NativeTls;
    }
    #[cfg(all(feature = "tls-rustls", not(feature = "tls-native")))]
    {
        return TlsBackendSelection::Rustls;
    }
    #[cfg(all(feature = "tls-native", feature = "tls-rustls"))]
    {
        TlsBackendSelection::NativeTls
    }
}

fn selected_tls_backend() -> TlsBackendSelection {
    if let Some(requested) = parse_tls_backend_override() {
        if supports_tls_backend(requested) {
            return requested;
        }
        tracing::warn!(
            "TLS_BACKEND requested an unavailable backend for this build; falling back to compiled default"
        );
    }
    compiled_default_tls_backend()
}

pub fn apply_tls_backend(builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
    match selected_tls_backend() {
        TlsBackendSelection::NativeTls => {
            #[cfg(feature = "tls-native")]
            {
                return builder;
            }
            #[cfg(not(feature = "tls-native"))]
            {
                builder
            }
        }
        TlsBackendSelection::Rustls => {
            #[cfg(feature = "tls-rustls")]
            {
                return builder.use_rustls_tls();
            }
            #[cfg(not(feature = "tls-rustls"))]
            {
                builder
            }
        }
    }
}

fn create_base_client(timeout_secs: u64) -> Client {
    let mut builder = apply_tls_backend(Client::builder())
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .user_agent(crate::constants::USER_AGENT.as_str());

    if let Ok(config) = load_app_config() {
        let proxy_config = config.proxy.upstream_proxy;
        if proxy_config.enabled && !proxy_config.url.is_empty() {
            match Proxy::all(&proxy_config.url) {
                Ok(proxy) => {
                    builder = builder.proxy(proxy);
                    tracing::info!(
                        "HTTP shared client enabled upstream proxy: {}",
                        proxy_config.url
                    );
                }
                Err(e) => {
                    tracing::error!("invalid_proxy_url: {}, error: {}", proxy_config.url, e);
                }
            }
        }
    }

    builder.build().unwrap_or_else(|_| Client::new())
}
pub fn get_client() -> Client {
    SHARED_CLIENT.clone()
}
pub fn get_long_client() -> Client {
    SHARED_CLIENT_LONG.clone()
}

pub fn tls_backend_name() -> &'static str {
    match selected_tls_backend() {
        TlsBackendSelection::NativeTls => "native-tls",
        TlsBackendSelection::Rustls => "rustls",
    }
}

pub fn log_tls_startup_diagnostics() {
    let requested_raw = std::env::var("TLS_BACKEND").ok();
    let requested_normalized = tls_requested_backend_name();
    let compiled = tls_compiled_backends().join(",");
    let effective = tls_backend_name();

    tracing::info!(
        "TLS startup diagnostics: requested_raw={:?}, requested_normalized={:?}, compiled=[{}], effective={}",
        requested_raw,
        requested_normalized,
        compiled,
        effective
    );
}

fn tls_canary_url() -> Option<String> {
    let raw = std::env::var("TLS_CANARY_URL").ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn tls_canary_timeout_seconds() -> u64 {
    std::env::var("TLS_CANARY_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(|v| v.clamp(1, 60))
        .unwrap_or(5)
}

pub fn tls_canary_required() -> bool {
    std::env::var("TLS_CANARY_REQUIRED")
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn update_tls_canary_snapshot(
    configured: bool,
    required: bool,
    url: Option<String>,
    timeout_seconds: u64,
    status: Option<u16>,
    error: Option<String>,
    success: bool,
) {
    if let Ok(mut snapshot) = tls_canary_state().lock() {
        let now = chrono::Utc::now().timestamp();
        snapshot.configured = configured;
        snapshot.required = required;
        snapshot.url = url;
        snapshot.timeout_seconds = timeout_seconds;
        snapshot.last_checked_unix = Some(now);
        snapshot.last_http_status = status;
        snapshot.last_error = error;
        if success {
            snapshot.last_success_unix = Some(now);
        }
    }
}

pub fn tls_canary_snapshot() -> TlsCanarySnapshot {
    if let Ok(snapshot) = tls_canary_state().lock() {
        return snapshot.clone();
    }
    TlsCanarySnapshot::default()
}

pub async fn run_tls_startup_canary_probe() -> Result<(), String> {
    let canary_url = tls_canary_url();
    let required = tls_canary_required();
    let timeout_secs = tls_canary_timeout_seconds();

    if canary_url.is_none() {
        update_tls_canary_snapshot(false, required, None, timeout_secs, None, None, false);
        return Ok(());
    }
    let url = canary_url.unwrap_or_default();

    let client = create_base_client(timeout_secs);
    match client.get(&url).send().await {
        Ok(response) => {
            let status = response.status().as_u16();
            if response.status().is_success() {
                update_tls_canary_snapshot(
                    true,
                    required,
                    Some(url.clone()),
                    timeout_secs,
                    Some(status),
                    None,
                    true,
                );
                tracing::info!(
                    "TLS startup canary succeeded: url={}, status={}, timeout={}s",
                    url,
                    status,
                    timeout_secs
                );
                Ok(())
            } else {
                let message = format!(
                    "TLS startup canary returned non-success status: url={}, status={}",
                    url, status
                );
                update_tls_canary_snapshot(
                    true,
                    required,
                    Some(url),
                    timeout_secs,
                    Some(status),
                    Some(message.clone()),
                    false,
                );
                Err(message)
            }
        }
        Err(e) => {
            let message = format!(
                "TLS startup canary request failed: url={}, timeout={}s, error={}",
                url, timeout_secs, e
            );
            update_tls_canary_snapshot(
                true,
                required,
                Some(url),
                timeout_secs,
                None,
                Some(message.clone()),
                false,
            );
            Err(message)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        get_client, parse_tls_backend_override, run_tls_startup_canary_probe, tls_backend_name,
        tls_canary_required, tls_canary_snapshot, tls_compiled_backends, TlsBackendSelection,
    };
    use axum::{extract::State, http::HeaderMap, routing::get, Json, Router};
    use serde_json::json;
    use std::sync::{Arc, Mutex, OnceLock};
    use tokio::net::TcpListener;
    use tokio::sync::Mutex as AsyncMutex;

    fn tls_env_test_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[derive(Clone, Default)]
    struct UaState {
        captured: Arc<AsyncMutex<Vec<String>>>,
    }

    async fn capture_ua(
        State(state): State<UaState>,
        headers: HeaderMap,
    ) -> Json<serde_json::Value> {
        if let Some(ua) = headers.get(reqwest::header::USER_AGENT) {
            if let Ok(value) = ua.to_str() {
                state.captured.lock().await.push(value.to_string());
            }
        }
        Json(json!({"ok": true}))
    }

    #[test]
    fn tls_backend_name_is_supported_value() {
        let v = tls_backend_name();
        assert!(v == "native-tls" || v == "rustls");
    }

    #[test]
    fn parse_tls_backend_override_handles_supported_labels() {
        let _guard = tls_env_test_lock().lock().expect("tls env test lock");
        std::env::set_var("TLS_BACKEND", "native-tls");
        assert_eq!(
            parse_tls_backend_override(),
            Some(TlsBackendSelection::NativeTls)
        );

        std::env::set_var("TLS_BACKEND", "rustls");
        assert_eq!(
            parse_tls_backend_override(),
            Some(TlsBackendSelection::Rustls)
        );

        std::env::remove_var("TLS_BACKEND");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn shared_client_sends_default_user_agent() {
        let state = UaState::default();
        let app = Router::new()
            .route("/ua", get(capture_ua))
            .with_state(state.clone());
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("listener local addr");

        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve ua test app");
        });

        let client = get_client();
        let url = format!("http://{}/ua", addr);
        client
            .get(url)
            .send()
            .await
            .expect("shared client request should succeed");

        server.abort();

        let captured = state.captured.lock().await.clone();
        assert!(
            captured
                .iter()
                .any(|ua| ua == crate::constants::USER_AGENT.as_str()),
            "shared client should send default user-agent"
        );
    }

    #[test]
    fn tls_compiled_backends_contains_at_least_one_backend() {
        assert!(!tls_compiled_backends().is_empty());
    }

    #[test]
    fn tls_canary_required_parses_truthy_flag() {
        let _guard = tls_env_test_lock().lock().expect("tls env test lock");
        std::env::set_var("TLS_CANARY_REQUIRED", "true");
        assert!(tls_canary_required());
        std::env::remove_var("TLS_CANARY_REQUIRED");
        assert!(!tls_canary_required());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tls_startup_canary_success_updates_snapshot() {
        let _guard = tls_env_test_lock().lock().expect("tls env test lock");
        let app = Router::new().route("/canary", get(|| async { Json(json!({"ok": true})) }));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind canary test listener");
        let addr = listener.local_addr().expect("canary test local addr");
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve canary test app");
        });

        std::env::set_var("TLS_CANARY_URL", format!("http://{}/canary", addr));
        std::env::set_var("TLS_CANARY_TIMEOUT_SECS", "2");
        std::env::set_var("TLS_CANARY_REQUIRED", "true");

        let probe = run_tls_startup_canary_probe().await;
        server.abort();

        assert!(probe.is_ok());
        let snapshot = tls_canary_snapshot();
        assert!(snapshot.configured);
        assert!(snapshot.required);
        assert_eq!(snapshot.last_http_status, Some(200));
        assert!(snapshot.last_error.is_none());

        std::env::remove_var("TLS_CANARY_URL");
        std::env::remove_var("TLS_CANARY_TIMEOUT_SECS");
        std::env::remove_var("TLS_CANARY_REQUIRED");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tls_startup_canary_failure_updates_snapshot() {
        let _guard = tls_env_test_lock().lock().expect("tls env test lock");

        std::env::set_var("TLS_CANARY_URL", "http://127.0.0.1:9/invalid");
        std::env::set_var("TLS_CANARY_TIMEOUT_SECS", "1");
        std::env::remove_var("TLS_CANARY_REQUIRED");

        let probe = run_tls_startup_canary_probe().await;
        assert!(probe.is_err());

        let snapshot = tls_canary_snapshot();
        assert!(snapshot.configured);
        assert_eq!(snapshot.required, false);
        assert!(snapshot.last_error.is_some());

        std::env::remove_var("TLS_CANARY_URL");
        std::env::remove_var("TLS_CANARY_TIMEOUT_SECS");
    }
}