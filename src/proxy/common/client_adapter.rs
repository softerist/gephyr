use super::client_adapters::OpencodeAdapter;
use axum::http::HeaderMap;
use once_cell::sync::Lazy;
use std::sync::Arc;
pub trait ClientAdapter: Send + Sync {
    fn matches(&self, headers: &HeaderMap) -> bool;
    fn let_it_crash(&self) -> bool {
        false
    }
    fn signature_buffer_strategy(&self) -> SignatureBufferStrategy {
        SignatureBufferStrategy::Default
    }
    fn inject_beta_headers(&self, _headers: &mut HeaderMap) {}
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureBufferStrategy {
    Default,
    Fifo,
    #[allow(dead_code)]
    Lifo,
}
pub static CLIENT_ADAPTERS: Lazy<Vec<Arc<dyn ClientAdapter>>> =
    Lazy::new(|| vec![Arc::new(OpencodeAdapter)]);
pub fn get_user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    struct TestAdapter;

    impl ClientAdapter for TestAdapter {
        fn matches(&self, headers: &HeaderMap) -> bool {
            get_user_agent(headers)
                .map(|ua| ua.contains("test-client"))
                .unwrap_or(false)
        }
    }

    #[test]
    fn test_adapter_matches() {
        let adapter = TestAdapter;

        let mut headers = HeaderMap::new();
        headers.insert("user-agent", HeaderValue::from_static("test-client/1.0"));

        assert!(adapter.matches(&headers));
    }

    #[test]
    fn test_adapter_no_match() {
        let adapter = TestAdapter;

        let mut headers = HeaderMap::new();
        headers.insert("user-agent", HeaderValue::from_static("other-client/1.0"));

        assert!(!adapter.matches(&headers));
    }

    #[test]
    fn test_get_user_agent() {
        let mut headers = HeaderMap::new();
        headers.insert("user-agent", HeaderValue::from_static("opencode/1.0"));

        assert_eq!(get_user_agent(&headers), Some("opencode/1.0".to_string()));
    }
}
