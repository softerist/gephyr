use crate::models::AppConfig;
use crate::proxy::config::{
    ComplianceConfig, CorsConfig, CorsMode, ExperimentalConfig, ProxyConfig, ProxyPoolConfig,
    UpstreamProxyConfig, ZaiConfig,
};
use std::fmt;
#[derive(Debug, Clone)]
pub struct ConfigError {
    pub field: String,
    pub message: String,
    pub actual_value: Option<String>,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.actual_value {
            Some(val) => write!(f, "  • {}: {} (got: {})", self.field, self.message, val),
            None => write!(f, "  • {}: {}", self.field, self.message),
        }
    }
}

impl ConfigError {
    fn new(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            message: message.into(),
            actual_value: None,
        }
    }

    fn with_value(
        field: impl Into<String>,
        message: impl Into<String>,
        value: impl ToString,
    ) -> Self {
        Self {
            field: field.into(),
            message: message.into(),
            actual_value: Some(value.to_string()),
        }
    }
}
pub fn validate_app_config(config: &AppConfig) -> Result<(), Vec<ConfigError>> {
    let mut errors = Vec::new();
    validate_proxy_config(&config.proxy, &mut errors);
    if config.quota_protection.enabled {
        let threshold = config.quota_protection.threshold_percentage;
        if threshold == 0 || threshold >= 100 {
            errors.push(ConfigError::with_value(
                "quota_protection.threshold_percentage",
                "must be between 1 and 99",
                threshold,
            ));
        }
    }
    if config.circuit_breaker.enabled {
        if config.circuit_breaker.backoff_steps.is_empty() {
            errors.push(ConfigError::new(
                "circuit_breaker.backoff_steps",
                "must not be empty when circuit breaker is enabled",
            ));
        }
        for (i, step) in config.circuit_breaker.backoff_steps.iter().enumerate() {
            if *step == 0 {
                errors.push(ConfigError::with_value(
                    format!("circuit_breaker.backoff_steps[{}]", i),
                    "backoff step must be greater than 0",
                    step,
                ));
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}
fn validate_proxy_config(config: &ProxyConfig, errors: &mut Vec<ConfigError>) {
    if config.port == 0 {
        errors.push(ConfigError::with_value(
            "proxy.port",
            "must be between 1 and 65535",
            config.port,
        ));
    }
    if config.api_key.trim().is_empty() {
        errors.push(ConfigError::new("proxy.api_key", "must not be empty"));
    }
    if config.request_timeout == 0 {
        errors.push(ConfigError::with_value(
            "proxy.request_timeout",
            "must be greater than 0",
            config.request_timeout,
        ));
    } else if config.request_timeout > 600 {
        errors.push(ConfigError::with_value(
            "proxy.request_timeout",
            "should not exceed 600 seconds (10 minutes)",
            config.request_timeout,
        ));
    }
    validate_trusted_proxies(config, errors);
    validate_upstream_proxy(&config.upstream_proxy, errors);
    validate_zai_config(&config.zai, errors);
    validate_experimental_config(&config.experimental, errors);
    validate_cors_config(&config.cors, errors);
    validate_proxy_pool(&config.proxy_pool, errors);
    validate_compliance_config(&config.compliance, errors);
}

fn validate_trusted_proxies(config: &ProxyConfig, errors: &mut Vec<ConfigError>) {
    for (index, raw_pattern) in config.trusted_proxies.iter().enumerate() {
        let pattern = raw_pattern.trim();
        if pattern.is_empty() {
            errors.push(ConfigError::new(
                format!("proxy.trusted_proxies[{}]", index),
                "must not be empty",
            ));
            continue;
        }

        if let Ok(_ip) = pattern.parse::<std::net::IpAddr>() {
            continue;
        }

        let Some((network, prefix_str)) = pattern.split_once('/') else {
            errors.push(ConfigError::with_value(
                format!("proxy.trusted_proxies[{}]", index),
                "must be a valid IP or CIDR (e.g. 127.0.0.1 or 10.0.0.0/8)",
                pattern,
            ));
            continue;
        };

        let Ok(network_ip) = network.trim().parse::<std::net::IpAddr>() else {
            errors.push(ConfigError::with_value(
                format!("proxy.trusted_proxies[{}]", index),
                "CIDR network must be a valid IP address",
                pattern,
            ));
            continue;
        };

        let Ok(prefix_len) = prefix_str.trim().parse::<u8>() else {
            errors.push(ConfigError::with_value(
                format!("proxy.trusted_proxies[{}]", index),
                "CIDR prefix must be numeric",
                pattern,
            ));
            continue;
        };

        let max_prefix = if network_ip.is_ipv4() { 32 } else { 128 };
        if prefix_len > max_prefix {
            errors.push(ConfigError::with_value(
                format!("proxy.trusted_proxies[{}]", index),
                format!(
                    "CIDR prefix out of range for address family (max {})",
                    max_prefix
                ),
                pattern,
            ));
        }
    }
}

fn validate_cors_config(config: &CorsConfig, errors: &mut Vec<ConfigError>) {
    if matches!(config.mode, CorsMode::Permissive) {
        return;
    }

    for (index, raw_origin) in config.allowed_origins.iter().enumerate() {
        let origin = raw_origin.trim();
        if origin.is_empty() {
            errors.push(ConfigError::new(
                format!("proxy.cors.allowed_origins[{}]", index),
                "must not be empty",
            ));
            continue;
        }

        let parsed = match url::Url::parse(origin) {
            Ok(url) => url,
            Err(_) => {
                errors.push(ConfigError::with_value(
                    format!("proxy.cors.allowed_origins[{}]", index),
                    "must be a valid absolute HTTP(S) origin",
                    origin,
                ));
                continue;
            }
        };

        let scheme = parsed.scheme();
        if scheme != "http" && scheme != "https" {
            errors.push(ConfigError::with_value(
                format!("proxy.cors.allowed_origins[{}]", index),
                "must use http:// or https://",
                origin,
            ));
        }

        if parsed.host_str().is_none() {
            errors.push(ConfigError::with_value(
                format!("proxy.cors.allowed_origins[{}]", index),
                "must include a host",
                origin,
            ));
        }

        if parsed.path() != "/"
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
        {
            errors.push(ConfigError::with_value(
                format!("proxy.cors.allowed_origins[{}]", index),
                "must be origin-only (no path/query/fragment/userinfo)",
                origin,
            ));
        }
    }
}
fn validate_upstream_proxy(config: &UpstreamProxyConfig, errors: &mut Vec<ConfigError>) {
    if config.enabled && !config.url.is_empty() && !is_valid_proxy_url(&config.url) {
        errors.push(ConfigError::with_value(
            "proxy.upstream_proxy.url",
            "must be a valid proxy URL (http://, https://, or socks5://)",
            &config.url,
        ));
    }
}
fn validate_zai_config(config: &ZaiConfig, errors: &mut Vec<ConfigError>) {
    if config.enabled {
        if config.api_key.trim().is_empty() {
            errors.push(ConfigError::new(
                "proxy.zai.api_key",
                "must not be empty when z.ai is enabled",
            ));
        }

        if !config.base_url.starts_with("https://") && !config.base_url.starts_with("http://") {
            errors.push(ConfigError::with_value(
                "proxy.zai.base_url",
                "must be a valid HTTP(S) URL",
                &config.base_url,
            ));
        }
    }
}
fn validate_experimental_config(config: &ExperimentalConfig, errors: &mut Vec<ConfigError>) {
    let l1 = config.context_compression_threshold_l1;
    let l2 = config.context_compression_threshold_l2;
    let l3 = config.context_compression_threshold_l3;
    if !(0.0..=1.0).contains(&l1) {
        errors.push(ConfigError::with_value(
            "experimental.context_compression_threshold_l1",
            "must be between 0.0 and 1.0",
            l1,
        ));
    }
    if !(0.0..=1.0).contains(&l2) {
        errors.push(ConfigError::with_value(
            "experimental.context_compression_threshold_l2",
            "must be between 0.0 and 1.0",
            l2,
        ));
    }
    if !(0.0..=1.0).contains(&l3) {
        errors.push(ConfigError::with_value(
            "experimental.context_compression_threshold_l3",
            "must be between 0.0 and 1.0",
            l3,
        ));
    }
    if l1 >= l2 {
        errors.push(ConfigError::with_value(
            "experimental.context_compression_threshold_l1",
            "L1 threshold must be less than L2",
            format!("L1={} >= L2={}", l1, l2),
        ));
    }
    if l2 >= l3 {
        errors.push(ConfigError::with_value(
            "experimental.context_compression_threshold_l2",
            "L2 threshold must be less than L3",
            format!("L2={} >= L3={}", l2, l3),
        ));
    }
}
fn validate_proxy_pool(config: &ProxyPoolConfig, errors: &mut Vec<ConfigError>) {
    if config.enabled {
        for (i, proxy) in config.proxies.iter().enumerate() {
            if proxy.enabled && !is_valid_proxy_url(&proxy.url) {
                errors.push(ConfigError::with_value(
                    format!("proxy.proxy_pool.proxies[{}].url", i),
                    "must be a valid proxy URL (http://, https://, or socks5://)",
                    &proxy.url,
                ));
            }
        }
    }
}
fn validate_compliance_config(config: &ComplianceConfig, errors: &mut Vec<ConfigError>) {
    if !config.enabled {
        return;
    }

    if config.max_global_requests_per_minute == 0 {
        errors.push(ConfigError::new(
            "proxy.compliance.max_global_requests_per_minute",
            "must be greater than 0 when compliance is enabled",
        ));
    }
    if config.max_account_requests_per_minute == 0 {
        errors.push(ConfigError::new(
            "proxy.compliance.max_account_requests_per_minute",
            "must be greater than 0 when compliance is enabled",
        ));
    }
    if config.max_account_concurrency == 0 {
        errors.push(ConfigError::new(
            "proxy.compliance.max_account_concurrency",
            "must be greater than 0 when compliance is enabled",
        ));
    }
    if config.max_retry_attempts == 0 {
        errors.push(ConfigError::new(
            "proxy.compliance.max_retry_attempts",
            "must be greater than 0 when compliance is enabled",
        ));
    }
}
fn is_valid_proxy_url(url: &str) -> bool {
    let url_lower = url.to_lowercase();
    (url_lower.starts_with("http://")
        || url_lower.starts_with("https://")
        || url_lower.starts_with("socks5://"))
        && url::Url::parse(url).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::AppConfig;

    #[test]
    fn test_valid_default_config() {
        let config = AppConfig::new();
        let result = validate_app_config(&config);
        assert!(
            result.is_ok(),
            "Default config should be valid: {:?}",
            result
        );
    }

    #[test]
    fn test_invalid_port_zero() {
        let mut config = AppConfig::new();
        config.proxy.port = 0;
        let result = validate_app_config(&config);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.field.contains("port")));
    }

    #[test]
    fn test_empty_api_key() {
        let mut config = AppConfig::new();
        config.proxy.api_key = "".to_string();
        let result = validate_app_config(&config);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.field.contains("api_key")));
    }

    #[test]
    fn test_invalid_timeout() {
        let mut config = AppConfig::new();
        config.proxy.request_timeout = 0;
        let result = validate_app_config(&config);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.field.contains("request_timeout")));
    }

    #[test]
    fn test_timeout_too_high() {
        let mut config = AppConfig::new();
        config.proxy.request_timeout = 1000;
        let result = validate_app_config(&config);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.field.contains("request_timeout")));
    }

    #[test]
    fn test_compression_thresholds_ordering() {
        let mut config = AppConfig::new();
        config.proxy.experimental.context_compression_threshold_l1 = 0.6;
        config.proxy.experimental.context_compression_threshold_l2 = 0.5;
        let result = validate_app_config(&config);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.field.contains("threshold_l1")));
    }

    #[test]
    fn test_zai_enabled_missing_key() {
        let mut config = AppConfig::new();
        config.proxy.zai.enabled = true;
        config.proxy.zai.api_key = "".to_string();
        let result = validate_app_config(&config);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.field.contains("zai.api_key")));
    }

    #[test]
    fn test_upstream_proxy_invalid_url() {
        let mut config = AppConfig::new();
        config.proxy.upstream_proxy.enabled = true;
        config.proxy.upstream_proxy.url = "not-a-valid-url".to_string();
        let result = validate_app_config(&config);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors
            .iter()
            .any(|e| e.field.contains("upstream_proxy.url")));
    }

    #[test]
    fn test_invalid_cors_origin_with_path() {
        let mut config = AppConfig::new();
        config.proxy.cors.mode = crate::proxy::config::CorsMode::Strict;
        config.proxy.cors.allowed_origins = vec!["http://localhost:3000/path".to_string()];

        let result = validate_app_config(&config);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors
            .iter()
            .any(|e| e.field.contains("cors.allowed_origins")));
    }

    #[test]
    fn test_permissive_cors_skips_origin_validation() {
        let mut config = AppConfig::new();
        config.proxy.cors.mode = crate::proxy::config::CorsMode::Permissive;
        config.proxy.cors.allowed_origins = vec!["not-a-url".to_string()];

        let result = validate_app_config(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_trusted_proxy_entry() {
        let mut config = AppConfig::new();
        config.proxy.trusted_proxies = vec!["bad-value".to_string()];

        let result = validate_app_config(&config);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.field.contains("trusted_proxies")));
    }

    #[test]
    fn test_valid_trusted_proxy_entries() {
        let mut config = AppConfig::new();
        config.proxy.trusted_proxies = vec![
            "127.0.0.1".to_string(),
            "10.0.0.0/8".to_string(),
            "2001:db8::/32".to_string(),
        ];

        let result = validate_app_config(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_quota_protection_threshold_bounds() {
        let mut config = AppConfig::new();
        config.quota_protection.enabled = true;
        config.quota_protection.threshold_percentage = 0;
        let result = validate_app_config(&config);
        assert!(result.is_err());
        config.quota_protection.threshold_percentage = 100;
        let result = validate_app_config(&config);
        assert!(result.is_err());
        config.quota_protection.threshold_percentage = 50;
        let result = validate_app_config(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_circuit_breaker_empty_steps() {
        let mut config = AppConfig::new();
        config.circuit_breaker.enabled = true;
        config.circuit_breaker.backoff_steps = vec![];
        let result = validate_app_config(&config);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.field.contains("backoff_steps")));
    }
}
