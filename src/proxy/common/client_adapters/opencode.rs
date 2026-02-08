use super::super::client_adapter::{get_user_agent, ClientAdapter, SignatureBufferStrategy};
use axum::http::{HeaderMap, HeaderValue};
pub struct OpencodeAdapter;

impl ClientAdapter for OpencodeAdapter {
    fn matches(&self, headers: &HeaderMap) -> bool {
        get_user_agent(headers)
            .map(|ua| ua.to_lowercase().contains("opencode"))
            .unwrap_or(false)
    }
    fn let_it_crash(&self) -> bool {
        true
    }

    fn signature_buffer_strategy(&self) -> SignatureBufferStrategy {
        SignatureBufferStrategy::Fifo
    }

    fn inject_beta_headers(&self, headers: &mut HeaderMap) {
        let value = HeaderValue::from_static("context-1m-2025-08-07");
        headers.insert("anthropic-beta", value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opencode_adapter_matches() {
        let adapter = OpencodeAdapter;

        let mut headers = HeaderMap::new();
        headers.insert("user-agent", HeaderValue::from_static("opencode/1.0.0"));

        assert!(adapter.matches(&headers));
    }

    #[test]
    fn test_opencode_adapter_case_insensitive() {
        let adapter = OpencodeAdapter;

        let mut headers = HeaderMap::new();
        headers.insert("user-agent", HeaderValue::from_static("OpenCode/1.0.0"));

        assert!(adapter.matches(&headers));
    }

    #[test]
    fn test_opencode_adapter_no_match() {
        let adapter = OpencodeAdapter;

        let mut headers = HeaderMap::new();
        headers.insert("user-agent", HeaderValue::from_static("curl/7.68.0"));

        assert!(!adapter.matches(&headers));
    }

    #[test]
    fn test_opencode_adapter_strategies() {
        let adapter = OpencodeAdapter;

        assert!(adapter.let_it_crash());
        assert_eq!(
            adapter.signature_buffer_strategy(),
            SignatureBufferStrategy::Fifo
        );
    }

    #[test]
    fn test_opencode_adapter_beta_headers() {
        let adapter = OpencodeAdapter;

        let mut headers = HeaderMap::new();
        adapter.inject_beta_headers(&mut headers);

        assert!(headers.contains_key("anthropic-beta"));
        assert_eq!(
            headers.get("anthropic-beta").unwrap().to_str().unwrap(),
            "context-1m-2025-08-07"
        );
    }
}
