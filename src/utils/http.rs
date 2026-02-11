use crate::modules::system::config::load_app_config;
use once_cell::sync::Lazy;
use reqwest::{Client, Proxy};

#[cfg(all(feature = "tls-native", feature = "tls-rustls"))]
compile_error!("features `tls-native` and `tls-rustls` are mutually exclusive");
#[cfg(not(any(feature = "tls-native", feature = "tls-rustls")))]
compile_error!("one TLS backend feature must be enabled: `tls-native` or `tls-rustls`");

pub static SHARED_CLIENT: Lazy<Client> = Lazy::new(|| create_base_client(15));
pub static SHARED_CLIENT_LONG: Lazy<Client> = Lazy::new(|| create_base_client(60));
fn create_base_client(timeout_secs: u64) -> Client {
    let mut builder = Client::builder()
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
    #[cfg(feature = "tls-rustls")]
    {
        "rustls"
    }
    #[cfg(all(feature = "tls-native", not(feature = "tls-rustls")))]
    {
        "native-tls"
    }
}

#[cfg(test)]
mod tests {
    use super::tls_backend_name;

    #[test]
    fn tls_backend_name_is_supported_value() {
        let v = tls_backend_name();
        assert!(v == "native-tls" || v == "rustls");
    }
}
