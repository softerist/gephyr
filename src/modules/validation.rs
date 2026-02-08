//! Configuration validation module
//!
//! Provides fail-fast startup validation for application configuration.
//! All validation errors are collected and reported together for better UX.

use crate::models::AppConfig;
use crate::proxy::config::{ProxyConfig, ZaiConfig, ProxyPoolConfig, ExperimentalConfig, UpstreamProxyConfig};
use std::fmt;

/// A configuration validation error with context
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

    fn with_value(field: impl Into<String>, message: impl Into<String>, value: impl ToString) -> Self {
        Self {
            field: field.into(),
            message: message.into(),
            actual_value: Some(value.to_string()),
        }
    }
}

/// Validate the entire application configuration.
/// Returns Ok(()) if valid, or Err with all collected errors.
pub fn validate_app_config(config: &AppConfig) -> Result<(), Vec<ConfigError>> {
    let mut errors = Vec::new();

    // Validate proxy config
    validate_proxy_config(&config.proxy, &mut errors);

    // Validate quota protection
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

    // Validate circuit breaker
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

/// Validate proxy service configuration
fn validate_proxy_config(config: &ProxyConfig, errors: &mut Vec<ConfigError>) {
    // Port validation
    if config.port == 0 {
        errors.push(ConfigError::with_value(
            "proxy.port",
            "must be between 1 and 65535",
            config.port,
        ));
    }

    // API key validation
    if config.api_key.trim().is_empty() {
        errors.push(ConfigError::new(
            "proxy.api_key",
            "must not be empty",
        ));
    }

    // Request timeout validation
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

    // Upstream proxy validation
    validate_upstream_proxy(&config.upstream_proxy, errors);

    // z.ai validation
    validate_zai_config(&config.zai, errors);

    // Experimental thresholds validation
    validate_experimental_config(&config.experimental, errors);

    // Proxy pool validation
    validate_proxy_pool(&config.proxy_pool, errors);
}

/// Validate upstream proxy configuration
fn validate_upstream_proxy(config: &UpstreamProxyConfig, errors: &mut Vec<ConfigError>) {
    if config.enabled && !config.url.is_empty() {
        if !is_valid_proxy_url(&config.url) {
            errors.push(ConfigError::with_value(
                "proxy.upstream_proxy.url",
                "must be a valid proxy URL (http://, https://, or socks5://)",
                &config.url,
            ));
        }
    }
}

/// Validate z.ai provider configuration
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

/// Validate experimental feature configuration
fn validate_experimental_config(config: &ExperimentalConfig, errors: &mut Vec<ConfigError>) {
    let l1 = config.context_compression_threshold_l1;
    let l2 = config.context_compression_threshold_l2;
    let l3 = config.context_compression_threshold_l3;

    // Validate individual thresholds are in range 0.0-1.0
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

    // Validate ordering: L1 < L2 < L3
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

/// Validate proxy pool configuration
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

/// Check if a URL is a valid proxy URL
fn is_valid_proxy_url(url: &str) -> bool {
    let url_lower = url.to_lowercase();
    (url_lower.starts_with("http://") || 
     url_lower.starts_with("https://") || 
     url_lower.starts_with("socks5://")) &&
    url::Url::parse(url).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::AppConfig;

    #[test]
    fn test_valid_default_config() {
        let config = AppConfig::new();
        let result = validate_app_config(&config);
        assert!(result.is_ok(), "Default config should be valid: {:?}", result);
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
        // L1 >= L2 should fail
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
        assert!(errors.iter().any(|e| e.field.contains("upstream_proxy.url")));
    }

    #[test]
    fn test_quota_protection_threshold_bounds() {
        let mut config = AppConfig::new();
        config.quota_protection.enabled = true;
        
        // Test 0
        config.quota_protection.threshold_percentage = 0;
        let result = validate_app_config(&config);
        assert!(result.is_err());
        
        // Test 100
        config.quota_protection.threshold_percentage = 100;
        let result = validate_app_config(&config);
        assert!(result.is_err());
        
        // Test valid
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
