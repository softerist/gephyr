use axum::http::HeaderMap;
use once_cell::sync::Lazy;
use std::sync::Arc; //  Import Arc
use super::client_adapters::OpencodeAdapter;

// Client Adapter trait
// 
// Provides customized protocol processing strategies for different clients (e.g., opencode, Cherry Studio).
// Each client can implement its own adapter to handle specific requirements.
// 
// # Design Principles
// 1. **Complete Isolation**: Adapters serve as an optional enhancement layer, not modifying existing protocol core logic
// 2. **Backward Compatibility**: Requests that don't match any adapter are processed exactly as before
// 3. **Single-file Modification**: Client-specific logic is encapsulated in its respective adapter file
pub trait ClientAdapter: Send + Sync {
    // Determines if this adapter matches the given request
    // 
    // # Arguments
    // * `headers` - Request headers, typically identifying the client via fields like User-Agent
    // 
    // # Returns
    // Returns true if matched, false otherwise
    fn matches(&self, headers: &HeaderMap) -> bool;
    
    // Whether to adopt a "let it crash" philosophy
    // 
    // Reduce unnecessary retry and recovery logic, allowing errors to fail fast
    fn let_it_crash(&self) -> bool {
        false
    }
    
    // Signature buffer strategy
    // 
    // Different clients may require different signature management (FIFO/LIFO)
    fn signature_buffer_strategy(&self) -> SignatureBufferStrategy {
        SignatureBufferStrategy::Default
    }
    
    // Inject missing Beta headers for the client
    // 
    // Certain clients may require specific Beta headers to function correctly
    fn inject_beta_headers(&self, _headers: &mut HeaderMap) {
        // Do not inject by default
    }
    
}

// Signature buffer strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureBufferStrategy {
    // Default strategy (current implementation)
    Default,
    // FIFO (First In First Out) - Suitable for multi-concurrent tool calls
    Fifo,
    // LIFO (Last In First Out) - Suitable for nested calls
    #[allow(dead_code)]
    Lifo,
}

// Global client adapter registry
// 
// All registered adapters are checked during request processing
pub static CLIENT_ADAPTERS: Lazy<Vec<Arc<dyn ClientAdapter>>> = Lazy::new(|| {
    vec![
        Arc::new(OpencodeAdapter),
        // More adapters can be easily added in the future:
        // Arc::new(CherryStudioAdapter),
    ]
});

// Helper function: Extract User-Agent from HeaderMap
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
