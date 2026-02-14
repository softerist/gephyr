use reqwest::header::{self, HeaderMap, HeaderName, HeaderValue};
use serde_json::json;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct GoogleOutboundHeaderPolicy {
    pub mode: crate::proxy::config::GoogleMode,
    pub send_host_header: bool,
    pub log_google_outbound_headers: bool,
    pub identity_metadata: crate::proxy::config::GoogleIdentityMetadata,
}

impl Default for GoogleOutboundHeaderPolicy {
    fn default() -> Self {
        Self {
            mode: crate::proxy::config::GoogleMode::PublicGoogle,
            send_host_header: false,
            log_google_outbound_headers: false,
            identity_metadata: crate::proxy::config::GoogleIdentityMetadata::default(),
        }
    }
}

impl GoogleOutboundHeaderPolicy {
    pub fn from_proxy_config(
        google: crate::proxy::config::GoogleConfig,
        debug: crate::proxy::config::DebugLoggingConfig,
    ) -> Self {
        Self {
            mode: google.mode,
            send_host_header: google.headers.send_host_header,
            log_google_outbound_headers: debug.log_google_outbound_headers,
            identity_metadata: google.identity_metadata,
        }
    }

    pub fn should_send_host_header(&self) -> bool {
        matches!(self.mode, crate::proxy::config::GoogleMode::CodeassistCompat)
            && self.send_host_header
    }
}

pub fn load_policy_from_runtime_config() -> GoogleOutboundHeaderPolicy {
    if let Ok(cfg) = crate::modules::system::config::load_app_config() {
        return GoogleOutboundHeaderPolicy::from_proxy_config(
            cfg.proxy.google,
            cfg.proxy.debug_logging,
        );
    }
    GoogleOutboundHeaderPolicy::default()
}

pub struct GoogleHeaderPolicyContext<'a> {
    pub endpoint: &'a str,
    pub endpoint_host: Option<&'a str>,
    pub user_agent: &'a str,
    pub access_token: Option<&'a str>,
    pub content_type_json: bool,
    pub device_profile: Option<&'a crate::models::DeviceProfile>,
    pub extra_headers: Option<&'a HashMap<String, String>>,
}

pub fn build_google_headers(
    context: GoogleHeaderPolicyContext<'_>,
    policy: &GoogleOutboundHeaderPolicy,
) -> HeaderMap {
    let mut headers = HeaderMap::new();

    if context.content_type_json {
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
    }

    if let Some(token) = context.access_token {
        if let Ok(value) = HeaderValue::from_str(&format!("Bearer {}", token)) {
            headers.insert(header::AUTHORIZATION, value);
        }
    }

    if let Ok(value) = HeaderValue::from_str(context.user_agent) {
        headers.insert(header::USER_AGENT, value);
    } else {
        headers.insert(header::USER_AGENT, HeaderValue::from_static("antigravity"));
    }

    headers.insert(
        header::ACCEPT_ENCODING,
        HeaderValue::from_static("gzip"),
    );

    if policy.should_send_host_header() {
        if let Some(host) = context.endpoint_host {
            if let Ok(value) = HeaderValue::from_str(host) {
                headers.insert(header::HOST, value);
            }
        }
    }

    if let Some(profile) = context.device_profile {
        apply_device_profile_headers(&mut headers, profile);
    }

    if let Some(extra) = context.extra_headers {
        for (k, v) in extra {
            if let Ok(name) = HeaderName::from_bytes(k.as_bytes()) {
                if !is_forwardable_header_name(&name) {
                    continue;
                }
                if let Ok(value) = HeaderValue::from_str(v) {
                    headers.insert(name, value);
                }
            }
        }
    }

    log_google_outbound_headers(context.endpoint, policy, &headers);
    headers
}

pub fn build_load_code_assist_metadata(policy: &GoogleOutboundHeaderPolicy) -> serde_json::Value {
    json!({
        "metadata": {
            "ideType": policy.identity_metadata.ide_type,
            "platform": policy.identity_metadata.platform,
            "pluginType": policy.identity_metadata.plugin_type
        }
    })
}

pub fn host_from_url(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    let host = parsed.host_str()?.to_string();
    if let Some(port) = parsed.port() {
        return Some(format!("{}:{}", host, port));
    }
    Some(host)
}

pub fn apply_device_profile_headers(headers: &mut HeaderMap, profile: &crate::models::DeviceProfile) {
    if let Some(v) = profile.machine_id.as_deref() {
        insert_custom_header(headers, "x-machine-id", v);
    }
    if let Some(v) = profile.mac_machine_id.as_deref() {
        insert_custom_header(headers, "x-mac-machine-id", v);
    }
    if let Some(v) = profile.dev_device_id.as_deref() {
        insert_custom_header(headers, "x-dev-device-id", v);
    }
    if let Some(v) = profile.sqm_id.as_deref() {
        insert_custom_header(headers, "x-sqm-id", v);
    }
}

fn insert_custom_header(headers: &mut HeaderMap, name: &'static str, value: &str) {
    match HeaderValue::from_str(value) {
        Ok(v) => {
            headers.insert(HeaderName::from_static(name), v);
        }
        Err(e) => {
            tracing::warn!("Invalid {} header value skipped: {}", name, e);
        }
    }
}

fn is_forwardable_header_name(name: &HeaderName) -> bool {
    let lower = name.as_str().to_ascii_lowercase();

    if lower.starts_with("sec-") || lower.starts_with("x-forwarded-") {
        return false;
    }

    if matches!(
        lower.as_str(),
        "origin"
            | "referer"
            | "cookie"
            | "x-real-ip"
            | "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "host"
    ) {
        return false;
    }

    matches!(lower.as_str(), "anthropic-beta")
}

fn log_google_outbound_headers(
    endpoint: &str,
    policy: &GoogleOutboundHeaderPolicy,
    headers: &HeaderMap,
) {
    if !policy.log_google_outbound_headers {
        return;
    }

    let mut redacted = serde_json::Map::new();
    for (name, value) in headers {
        let key = name.as_str().to_string();
        let raw = value.to_str().unwrap_or("<non-utf8>");
        redacted.insert(key.clone(), serde_json::Value::String(redact_header_value(&key, raw)));
    }

    let mode = match policy.mode {
        crate::proxy::config::GoogleMode::PublicGoogle => "public_google",
        crate::proxy::config::GoogleMode::CodeassistCompat => "codeassist_compat",
    };

    tracing::debug!(
        endpoint = endpoint,
        mode = mode,
        headers = %serde_json::Value::Object(redacted),
        "google_outbound_headers"
    );
}

fn redact_header_value(name: &str, value: &str) -> String {
    let lower = name.to_ascii_lowercase();
    if lower.contains("authorization")
        || lower.contains("api-key")
        || lower.contains("token")
        || lower.contains("cookie")
    {
        return "<redacted>".to_string();
    }
    value.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_device_profile() -> crate::models::DeviceProfile {
        crate::models::DeviceProfile {
            machine_id: Some("machine-1".to_string()),
            mac_machine_id: Some("mac-1".to_string()),
            dev_device_id: Some("dev-1".to_string()),
            sqm_id: Some("{SQM-1}".to_string()),
        }
    }

    #[test]
    fn builds_baseline_google_headers() {
        let policy = GoogleOutboundHeaderPolicy::default();
        let headers = build_google_headers(
            GoogleHeaderPolicyContext {
                endpoint: "https://cloudcode-pa.googleapis.com/v1internal:generateContent",
                endpoint_host: Some("cloudcode-pa.googleapis.com"),
                user_agent: "antigravity/test",
                access_token: Some("access-token"),
                content_type_json: true,
                device_profile: None,
                extra_headers: None,
            },
            &policy,
        );

        assert!(headers.contains_key(header::AUTHORIZATION));
        assert_eq!(
            headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok()),
            Some("antigravity/test")
        );
        assert_eq!(
            headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
        assert_eq!(
            headers
                .get(header::ACCEPT_ENCODING)
                .and_then(|v| v.to_str().ok()),
            Some("gzip")
        );
    }

    #[test]
    fn applies_device_profile_headers_when_present() {
        let policy = GoogleOutboundHeaderPolicy::default();
        let profile = test_device_profile();
        let headers = build_google_headers(
            GoogleHeaderPolicyContext {
                endpoint: "https://cloudcode-pa.googleapis.com/v1internal:generateContent",
                endpoint_host: Some("cloudcode-pa.googleapis.com"),
                user_agent: "antigravity/test",
                access_token: Some("access-token"),
                content_type_json: true,
                device_profile: Some(&profile),
                extra_headers: None,
            },
            &policy,
        );

        assert_eq!(
            headers.get("x-machine-id").and_then(|v| v.to_str().ok()),
            Some("machine-1")
        );
        assert_eq!(
            headers
                .get("x-mac-machine-id")
                .and_then(|v| v.to_str().ok()),
            Some("mac-1")
        );
        assert_eq!(
            headers.get("x-dev-device-id").and_then(|v| v.to_str().ok()),
            Some("dev-1")
        );
        assert_eq!(
            headers.get("x-sqm-id").and_then(|v| v.to_str().ok()),
            Some("{SQM-1}")
        );
    }

    #[test]
    fn host_header_is_compat_mode_only() {
        let mut policy = GoogleOutboundHeaderPolicy::default();
        policy.send_host_header = true;
        let headers = build_google_headers(
            GoogleHeaderPolicyContext {
                endpoint: "https://cloudcode-pa.googleapis.com/v1internal:generateContent",
                endpoint_host: Some("cloudcode-pa.googleapis.com"),
                user_agent: "antigravity/test",
                access_token: Some("access-token"),
                content_type_json: true,
                device_profile: None,
                extra_headers: None,
            },
            &policy,
        );
        assert!(headers.get(header::HOST).is_none());

        policy.mode = crate::proxy::config::GoogleMode::CodeassistCompat;
        let headers = build_google_headers(
            GoogleHeaderPolicyContext {
                endpoint: "https://cloudcode-pa.googleapis.com/v1internal:generateContent",
                endpoint_host: Some("cloudcode-pa.googleapis.com"),
                user_agent: "antigravity/test",
                access_token: Some("access-token"),
                content_type_json: true,
                device_profile: None,
                extra_headers: None,
            },
            &policy,
        );
        assert_eq!(
            headers.get(header::HOST).and_then(|v| v.to_str().ok()),
            Some("cloudcode-pa.googleapis.com")
        );
    }

    #[test]
    fn blocks_non_forwardable_extra_headers() {
        let policy = GoogleOutboundHeaderPolicy::default();
        let mut extra = HashMap::new();
        extra.insert("origin".to_string(), "https://example.com".to_string());
        extra.insert("referer".to_string(), "https://example.com/a".to_string());
        extra.insert("x-forwarded-for".to_string(), "1.2.3.4".to_string());
        extra.insert("anthropic-beta".to_string(), "context-1m-2025-08-07".to_string());

        let headers = build_google_headers(
            GoogleHeaderPolicyContext {
                endpoint: "https://cloudcode-pa.googleapis.com/v1internal:generateContent",
                endpoint_host: Some("cloudcode-pa.googleapis.com"),
                user_agent: "antigravity/test",
                access_token: Some("access-token"),
                content_type_json: true,
                device_profile: None,
                extra_headers: Some(&extra),
            },
            &policy,
        );

        assert!(headers.get("origin").is_none());
        assert!(headers.get("referer").is_none());
        assert!(headers.get("x-forwarded-for").is_none());
        assert_eq!(
            headers
                .get("anthropic-beta")
                .and_then(|v| v.to_str().ok()),
            Some("context-1m-2025-08-07")
        );
    }

    #[test]
    fn denies_unknown_extra_headers_by_default() {
        let policy = GoogleOutboundHeaderPolicy::default();
        let mut extra = HashMap::new();
        extra.insert("x-custom-extra".to_string(), "value".to_string());

        let headers = build_google_headers(
            GoogleHeaderPolicyContext {
                endpoint: "https://cloudcode-pa.googleapis.com/v1internal:generateContent",
                endpoint_host: Some("cloudcode-pa.googleapis.com"),
                user_agent: "antigravity/test",
                access_token: Some("access-token"),
                content_type_json: true,
                device_profile: None,
                extra_headers: Some(&extra),
            },
            &policy,
        );

        assert!(headers.get("x-custom-extra").is_none());
    }

    #[test]
    fn metadata_payload_includes_full_identity_shape() {
        let policy = GoogleOutboundHeaderPolicy::default();
        let value = build_load_code_assist_metadata(&policy);
        assert_eq!(
            value
                .pointer("/metadata/ideType")
                .and_then(|v| v.as_str()),
            Some("ANTIGRAVITY")
        );
        assert_eq!(
            value
                .pointer("/metadata/platform")
                .and_then(|v| v.as_str()),
            Some("PLATFORM_UNSPECIFIED")
        );
        assert_eq!(
            value
                .pointer("/metadata/pluginType")
                .and_then(|v| v.as_str()),
            Some("GEMINI")
        );
    }

    #[test]
    fn redacts_sensitive_headers() {
        assert_eq!(
            redact_header_value("authorization", "Bearer abc"),
            "<redacted>"
        );
        assert_eq!(redact_header_value("x-goog-api-key", "secret"), "<redacted>");
        assert_eq!(redact_header_value("user-agent", "ua"), "ua");
    }
}
