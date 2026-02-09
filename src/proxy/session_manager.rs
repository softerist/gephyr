use crate::proxy::mappers::claude::models::{ClaudeRequest, MessageContent};
use crate::proxy::mappers::openai::models::{OpenAIContent, OpenAIRequest};
use axum::http::HeaderMap;
use serde_json::Value;
use sha2::{Digest, Sha256};
pub struct SessionManager;

impl SessionManager {
    fn normalize_explicit_session_id(raw: &str) -> Option<String> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return None;
        }
        if trimmed.len() <= 256 {
            return Some(trimmed.to_string());
        }

        // Prevent unbounded growth in in-memory and persisted binding keys while keeping stability.
        let mut hasher = Sha256::new();
        hasher.update(trimmed.as_bytes());
        let hash = format!("{:x}", hasher.finalize());
        let sid = format!("sid-explicit-{}", &hash[..16]);
        tracing::warn!(
            "[SessionManager] Explicit session id too long ({}), hashed to {}",
            trimmed.len(),
            sid
        );
        Some(sid)
    }

    fn extract_explicit_session_id_from_headers(headers: Option<&HeaderMap>) -> Option<String> {
        let headers = headers?;

        for key in [
            "x-session-id",
            "x-client-session-id",
            "x-gephyr-session-id",
            "x-conversation-id",
            "x-thread-id",
        ] {
            if let Some(value) = headers.get(key).and_then(|v| v.to_str().ok()) {
                if let Some(sid) = Self::normalize_explicit_session_id(value) {
                    tracing::debug!(
                        "[SessionManager] Using explicit session id from header {}",
                        key
                    );
                    return Some(sid);
                }
            }
        }

        None
    }

    fn extract_explicit_session_id_from_json(raw: Option<&Value>) -> Option<String> {
        let raw = raw?;

        for key in [
            "session_id",
            "sessionId",
            "conversation_id",
            "conversationId",
            "thread_id",
            "threadId",
        ] {
            if let Some(value) = raw.get(key).and_then(|v| v.as_str()) {
                if let Some(sid) = Self::normalize_explicit_session_id(value) {
                    tracing::debug!(
                        "[SessionManager] Using explicit session id from payload field {}",
                        key
                    );
                    return Some(sid);
                }
            }
        }

        if let Some(metadata) = raw.get("metadata") {
            for key in ["session_id", "sessionId", "user_id", "userId"] {
                if let Some(value) = metadata.get(key).and_then(|v| v.as_str()) {
                    if let Some(sid) = Self::normalize_explicit_session_id(value) {
                        tracing::debug!(
                            "[SessionManager] Using explicit session id from metadata.{}",
                            key
                        );
                        return Some(sid);
                    }
                }
            }
        }

        None
    }

    fn hash_from_text_or_fallback(texts: impl Iterator<Item = String>, fallback: String) -> String {
        let mut hasher = Sha256::new();

        let mut content_found = false;
        for text in texts {
            let clean_text = text.trim().to_string();
            if clean_text.len() > 10 && !clean_text.contains("<system-reminder>") {
                hasher.update(clean_text.as_bytes());
                content_found = true;
                break;
            }
        }

        if !content_found {
            hasher.update(fallback.as_bytes());
        }

        let hash = format!("{:x}", hasher.finalize());
        format!("sid-{}", &hash[..16])
    }

    pub fn extract_session_id(request: &ClaudeRequest) -> String {
        if let Some(metadata) = &request.metadata {
            if let Some(user_id) = &metadata.user_id {
                if !user_id.is_empty() && !user_id.contains("session-") {
                    tracing::debug!("[SessionManager] Using explicit user_id: {}", user_id);
                    return user_id.clone();
                }
            }
        }
        let mut hasher = Sha256::new();

        let mut content_found = false;
        for msg in &request.messages {
            if msg.role != "user" {
                continue;
            }

            let text = match &msg.content {
                MessageContent::String(s) => s.clone(),
                MessageContent::Array(blocks) => blocks
                    .iter()
                    .filter_map(|block| match block {
                        crate::proxy::mappers::claude::models::ContentBlock::Text { text } => {
                            Some(text.as_str())
                        }
                        _ => None,
                    })
                    .collect::<Vec<_>>()
                    .join(" "),
            };

            let clean_text = text.trim();
            if clean_text.len() > 10 && !clean_text.contains("<system-reminder>") {
                hasher.update(clean_text.as_bytes());
                content_found = true;
                break;
            }
        }

        if !content_found {
            if let Some(last_msg) = request.messages.last() {
                hasher.update(format!("{:?}", last_msg.content).as_bytes());
            }
        }

        let hash = format!("{:x}", hasher.finalize());
        let sid = format!("sid-{}", &hash[..16]);

        tracing::debug!(
            "[SessionManager] Generated session_id: {} (content_found: {}, model: {})",
            sid,
            content_found,
            request.model
        );
        sid
    }

    pub fn extract_openai_session_id_with_overrides(
        request: &OpenAIRequest,
        headers: Option<&HeaderMap>,
        raw_body: Option<&Value>,
    ) -> String {
        if let Some(sid) = Self::extract_explicit_session_id_from_headers(headers)
            .or_else(|| Self::extract_explicit_session_id_from_json(raw_body))
        {
            return sid;
        }

        Self::extract_openai_session_id(request)
    }

    pub fn extract_openai_session_id(request: &OpenAIRequest) -> String {
        let texts = request.messages.iter().filter_map(|msg| {
            if msg.role != "user" {
                return None;
            }
            let content = msg.content.as_ref()?;
            let text = match content {
                OpenAIContent::String(s) => s.clone(),
                OpenAIContent::Array(blocks) => blocks
                    .iter()
                    .filter_map(|block| match block {
                        crate::proxy::mappers::openai::models::OpenAIContentBlock::Text {
                            text,
                        } => Some(text.as_str()),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
                    .join(" "),
            };
            Some(text)
        });

        let fallback = request
            .messages
            .last()
            .map(|last_msg| format!("{:?}", last_msg.content))
            .unwrap_or_default();

        let sid = Self::hash_from_text_or_fallback(texts, fallback);
        tracing::debug!("[SessionManager-OpenAI] Generated fingerprint: {}", sid);
        sid
    }

    pub fn extract_gemini_session_id_with_overrides(
        request: &Value,
        model_name: &str,
        headers: Option<&HeaderMap>,
    ) -> String {
        if let Some(sid) = Self::extract_explicit_session_id_from_headers(headers)
            .or_else(|| Self::extract_explicit_session_id_from_json(Some(request)))
        {
            return sid;
        }

        Self::extract_gemini_session_id(request, model_name)
    }

    pub fn extract_gemini_session_id(request: &Value, _model_name: &str) -> String {
        let texts = request
            .get("contents")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
            .filter(|content| content.get("role").and_then(|v| v.as_str()) == Some("user"))
            .filter_map(|content| {
                let parts = content.get("parts").and_then(|v| v.as_array())?;
                let combined = parts
                    .iter()
                    .filter_map(|part| part.get("text").and_then(|v| v.as_str()))
                    .collect::<Vec<_>>()
                    .join(" ");
                Some(combined)
            });

        let sid = Self::hash_from_text_or_fallback(texts, request.to_string());
        tracing::debug!("[SessionManager-Gemini] Generated fingerprint: {}", sid);
        sid
    }
}

#[cfg(test)]
mod tests {
    use super::SessionManager;
    use crate::proxy::mappers::openai::models::OpenAIRequest;
    use axum::http::HeaderMap;
    use serde_json::json;

    fn build_openai_request(user_text: &str) -> OpenAIRequest {
        serde_json::from_value(json!({
            "model": "gemini-3-flash",
            "messages": [
                { "role": "user", "content": user_text }
            ]
        }))
        .expect("valid OpenAIRequest")
    }

    #[test]
    fn test_openai_explicit_session_id_from_header_wins() {
        let req = build_openai_request("hello session hashing fallback");
        let mut headers = HeaderMap::new();
        headers.insert("x-session-id", "stable-session-123".parse().unwrap());

        let sid = SessionManager::extract_openai_session_id_with_overrides(
            &req,
            Some(&headers),
            Some(&json!({"session_id":"ignored-by-header"})),
        );
        assert_eq!(sid, "stable-session-123");
    }

    #[test]
    fn test_openai_explicit_session_id_from_payload_used_when_no_header() {
        let req = build_openai_request("hello session hashing fallback");
        let sid = SessionManager::extract_openai_session_id_with_overrides(
            &req,
            None,
            Some(&json!({"session_id":"payload-session-42"})),
        );
        assert_eq!(sid, "payload-session-42");
    }

    #[test]
    fn test_gemini_explicit_session_id_from_payload_used() {
        let body = json!({
            "sessionId": "gemini-session-7",
            "contents": [
                { "role": "user", "parts": [{ "text": "ignored due to explicit id" }] }
            ]
        });

        let sid =
            SessionManager::extract_gemini_session_id_with_overrides(&body, "gemini-3-flash", None);
        assert_eq!(sid, "gemini-session-7");
    }
}
