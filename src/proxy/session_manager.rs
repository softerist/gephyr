use sha2::{Sha256, Digest};
use crate::proxy::mappers::claude::models::{ClaudeRequest, MessageContent};
use crate::proxy::mappers::openai::models::{OpenAIRequest, OpenAIContent};
use serde_json::Value;

// Session manager utility
pub struct SessionManager;

impl SessionManager {
    // Generate a stable session fingerprint (Session Fingerprint) based on a Claude request.
    // 
    // Design Philosophy:
    // - Only hash the first user message content; do not mix in model names or timestamps.
    // - Ensure all turns of the same conversation use the same session_id.
    // - Maximize the hit rate of prompt caching.
    // 
    // Priority:
    // 1. metadata.user_id (explicitly provided by the client)
    // 2. SHA256 hash of the first user message
    pub fn extract_session_id(request: &ClaudeRequest) -> String {
        // 1. Prioritize user_id in metadata
        if let Some(metadata) = &request.metadata {
            if let Some(user_id) = &metadata.user_id {
                if !user_id.is_empty() && !user_id.contains("session-") {
                    tracing::debug!("[SessionManager] Using explicit user_id: {}", user_id);
                    return user_id.clone();
                }
            }
        }

        // 2. Alternative: SHA256 hash based on the first user message
        let mut hasher = Sha256::new();

        let mut content_found = false;
        for msg in &request.messages {
            if msg.role != "user" { continue; }
            
            let text = match &msg.content {
                MessageContent::String(s) => s.clone(),
                MessageContent::Array(blocks) => {
                    blocks.iter()
                        .filter_map(|block| match block {
                            crate::proxy::mappers::claude::models::ContentBlock::Text { text } => Some(text.as_str()),
                            _ => None,
                        })
                        .collect::<Vec<_>>()
                        .join(" ")
                }
            };

            let clean_text = text.trim();
            // Skip very short messages (likely CLI probe messages) or messages containing system labels
            if clean_text.len() > 10 && !clean_text.contains("<system-reminder>") {
                hasher.update(clean_text.as_bytes());
                content_found = true;
                break; // Only take the first key message as an anchor
            }
        }

        if !content_found {
            // If no meaningful content is found, fallback to hashing the last message
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

    // Generate a stable session fingerprint based on an OpenAI request
    pub fn extract_openai_session_id(request: &OpenAIRequest) -> String {
        let mut hasher = Sha256::new();

        let mut content_found = false;
        for msg in &request.messages {
            if msg.role != "user" { continue; }
            if let Some(content) = &msg.content {
                let text = match content {
                    OpenAIContent::String(s) => s.clone(),
                    OpenAIContent::Array(blocks) => {
                        blocks.iter()
                            .filter_map(|block| match block {
                                crate::proxy::mappers::openai::models::OpenAIContentBlock::Text { text } => Some(text.as_str()),
                                _ => None,
                            })
                            .collect::<Vec<_>>()
                            .join(" ")
                    }
                };

                let clean_text = text.trim();
                if clean_text.len() > 10 && !clean_text.contains("<system-reminder>") {
                    hasher.update(clean_text.as_bytes());
                    content_found = true;
                    break;
                }
            }
        }

        if !content_found {
            if let Some(last_msg) = request.messages.last() {
                hasher.update(format!("{:?}", last_msg.content).as_bytes());
            }
        }

        let hash = format!("{:x}", hasher.finalize());
        let sid = format!("sid-{}", &hash[..16]);
        tracing::debug!("[SessionManager-OpenAI] Generated fingerprint: {}", sid);
        sid
    }

    // Generate a stable session fingerprint based on a Gemini native request (JSON)
    pub fn extract_gemini_session_id(request: &Value, _model_name: &str) -> String {
        let mut hasher = Sha256::new();

        let mut content_found = false;
        if let Some(contents) = request.get("contents").and_then(|v| v.as_array()) {
            for content in contents {
                if content.get("role").and_then(|v| v.as_str()) != Some("user") { continue; }
                
                if let Some(parts) = content.get("parts").and_then(|v| v.as_array()) {
                    let mut text_parts = Vec::new();
                    for part in parts {
                        if let Some(text) = part.get("text").and_then(|v| v.as_str()) {
                            text_parts.push(text);
                        }
                    }
                    
                    let combined_text = text_parts.join(" ");
                    let clean_text = combined_text.trim();
                    if clean_text.len() > 10 && !clean_text.contains("<system-reminder>") {
                        hasher.update(clean_text.as_bytes());
                        content_found = true;
                        break;
                    }
                }
            }
        }

        if !content_found {
             // Fallback: summarize the first user part of the entire body
             hasher.update(request.to_string().as_bytes());
        }

        let hash = format!("{:x}", hasher.finalize());
        let sid = format!("sid-{}", &hash[..16]);
        tracing::debug!("[SessionManager-Gemini] Generated fingerprint: {}", sid);
        sid
    }
}
