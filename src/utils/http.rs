use crate::modules::system::config::load_app_config;
use once_cell::sync::Lazy;
use reqwest::{Client, Proxy};

#[cfg(not(any(feature = "tls-native", feature = "tls-rustls")))]
compile_error!("one TLS backend feature must be enabled: `tls-native` or `tls-rustls`");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TlsBackendSelection {
    NativeTls,
    Rustls,
}

pub static SHARED_CLIENT: Lazy<Client> = Lazy::new(|| create_base_client(15));
pub static SHARED_CLIENT_LONG: Lazy<Client> = Lazy::new(|| create_base_client(60));

fn parse_tls_backend_override() -> Option<TlsBackendSelection> {
    let raw = std::env::var("ABV_TLS_BACKEND").ok()?;
    match raw.trim().to_ascii_lowercase().as_str() {
        "native" | "native-tls" | "default-tls" => Some(TlsBackendSelection::NativeTls),
        "rustls" => Some(TlsBackendSelection::Rustls),
        _ => None,
    }
}

fn supports_tls_backend(selection: TlsBackendSelection) -> bool {
    match selection {
        TlsBackendSelection::NativeTls => cfg!(feature = "tls-native"),
        TlsBackendSelection::Rustls => cfg!(feature = "tls-rustls"),
    }
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
            "ABV_TLS_BACKEND requested an unavailable backend for this build; falling back to compiled default"
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

#[cfg(test)]
mod tests {
    use super::{get_client, parse_tls_backend_override, tls_backend_name, TlsBackendSelection};
    use axum::{extract::State, http::HeaderMap, routing::get, Json, Router};
    use serde_json::json;
    use std::sync::Arc;
    use tokio::net::TcpListener;
    use tokio::sync::Mutex as AsyncMutex;

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
        std::env::set_var("ABV_TLS_BACKEND", "native-tls");
        assert_eq!(
            parse_tls_backend_override(),
            Some(TlsBackendSelection::NativeTls)
        );

        std::env::set_var("ABV_TLS_BACKEND", "rustls");
        assert_eq!(
            parse_tls_backend_override(),
            Some(TlsBackendSelection::Rustls)
        );

        std::env::remove_var("ABV_TLS_BACKEND");
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
}
