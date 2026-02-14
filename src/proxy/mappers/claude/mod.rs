pub mod collector;
pub mod models;
pub mod request;
pub mod streaming;
pub mod thinking_utils;
pub mod utils;

use crate::proxy::common::client_adapter::ClientAdapter;
pub use collector::collect_stream_to_json;
pub use models::*;
pub use request::{
    clean_cache_control_from_messages, merge_consecutive_messages, transform_claude_request_in,
};
pub use streaming::{PartProcessor, StreamingState};
pub use thinking_utils::{
    close_tool_loop_for_thinking, filter_invalid_thinking_blocks_with_family,
};

use bytes::Bytes;
use futures::Stream;
use std::pin::Pin;
pub struct ClaudeSseStreamInput {
    pub gemini_stream: Pin<Box<dyn Stream<Item = Result<Bytes, reqwest::Error>> + Send>>,
    pub trace_id: String,
    pub email: String,
    pub session_id: Option<String>,
    pub scaling_enabled: bool,
    pub context_limit: u32,
    pub estimated_prompt_tokens: Option<u32>,
    pub message_count: usize,
    pub client_adapter: Option<std::sync::Arc<dyn ClientAdapter>>,
}

pub fn create_claude_sse_stream(
    input: ClaudeSseStreamInput,
) -> Pin<Box<dyn Stream<Item = Result<Bytes, String>> + Send>> {
    use async_stream::stream;
    use bytes::BytesMut;
    use futures::StreamExt;
    let ClaudeSseStreamInput {
        mut gemini_stream,
        trace_id,
        email,
        session_id,
        scaling_enabled,
        context_limit,
        estimated_prompt_tokens,
        message_count,
        client_adapter,
    } = input;

    Box::pin(stream! {
        let mut state = StreamingState::new();
        state.session_id = session_id;
        state.message_count = message_count;
        state.scaling_enabled = scaling_enabled;
        state.context_limit = context_limit;
        state.estimated_prompt_tokens = estimated_prompt_tokens;
        state.set_client_adapter(client_adapter);
        let mut buffer = BytesMut::new();

        loop {
            let next_chunk = tokio::time::timeout(
                std::time::Duration::from_secs(30),
                gemini_stream.next()
            ).await;

            match next_chunk {
                Ok(Some(chunk_result)) => {
                    match chunk_result {
                        Ok(chunk) => {
                            buffer.extend_from_slice(&chunk);
                            while let Some(pos) = buffer.iter().position(|&b| b == b'\n') {
                                let line_raw = buffer.split_to(pos + 1);
                                if let Ok(line_str) = std::str::from_utf8(&line_raw) {
                                    let line = line_str.trim();
                                    if line.is_empty() { continue; }

                                    if let Some(sse_chunks) = process_sse_line(line, &mut state, &trace_id, &email) {
                                        for sse_chunk in sse_chunks {
                                            yield Ok(sse_chunk);
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            yield Err(format!("Stream error: {}", e));
                            break;
                        }
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    yield Ok(Bytes::from(": ping\n\n"));
                }
            }
        }
        if state.has_thinking && !state.has_content {
            tracing::warn!("[{}] Stream interrupted after thinking (No Content). Triggering recovery...", trace_id);
            if state.current_block_type() == crate::proxy::mappers::claude::streaming::BlockType::Thinking {
               let close_chunks = state.end_block();
               for chunk in close_chunks {
                   yield Ok(chunk);
               }
            }
            let recovery_msg = "\n\n[System] Upstream model interrupted after thinking. (Recovered by Antigravity)";
            let start_chunks = state.start_block(
                crate::proxy::mappers::claude::streaming::BlockType::Text,
                serde_json::json!({ "type": "text", "text": recovery_msg })
            );
            for chunk in start_chunks { yield Ok(chunk); }

            let stop_chunks = state.end_block();
            for chunk in stop_chunks { yield Ok(chunk); }
            state.has_content = true;
            let recovery_usage = crate::proxy::mappers::claude::models::Usage {
                input_tokens: 0,
                output_tokens: 100,
                cache_read_input_tokens: None,
                cache_creation_input_tokens: None,
                server_tool_use: None,
            };

            let delta = serde_json::json!({
                "type": "message_delta",
                "delta": { "stop_reason": "end_turn", "stop_sequence": null },
                "usage": recovery_usage
            });

            yield Ok(state.emit("message_delta", delta));
        }
        for chunk in emit_force_stop(&mut state) {
            yield Ok(chunk);
        }
    })
}
fn process_sse_line(
    line: &str,
    state: &mut StreamingState,
    trace_id: &str,
    email: &str,
) -> Option<Vec<Bytes>> {
    if !line.starts_with("data: ") {
        return None;
    }

    let data_str = line[6..].trim();
    if data_str.is_empty() {
        return None;
    }

    if data_str == "[DONE]" {
        let chunks = emit_force_stop(state);
        if chunks.is_empty() {
            return None;
        }
        return Some(chunks);
    }
    let json_value: serde_json::Value = match serde_json::from_str(data_str) {
        Ok(v) => v,
        Err(_) => return None,
    };

    let mut chunks = Vec::new();
    let raw_json = json_value.get("response").unwrap_or(&json_value);
    if !state.message_start_sent {
        chunks.push(state.emit_message_start(raw_json));
    }
    if let Some(candidate) = raw_json.get("candidates").and_then(|c| c.get(0)) {
        if let Some(grounding) = candidate.get("groundingMetadata") {
            if let Some(query) = grounding
                .get("webSearchQueries")
                .and_then(|v| v.as_array())
                .and_then(|arr| arr.first())
                .and_then(|v| v.as_str())
            {
                state.web_search_query = Some(query.to_string());
            }
            if let Some(chunks_arr) = grounding.get("groundingChunks").and_then(|v| v.as_array()) {
                state.grounding_chunks = Some(chunks_arr.clone());
            } else if let Some(chunks_arr) = grounding
                .get("grounding_metadata")
                .and_then(|m| m.get("groundingChunks"))
                .and_then(|v| v.as_array())
            {
                state.grounding_chunks = Some(chunks_arr.clone());
            }
        }
    }
    if let Some(parts) = raw_json
        .get("candidates")
        .and_then(|c| c.get(0))
        .and_then(|cand| cand.get("content"))
        .and_then(|content| content.get("parts"))
        .and_then(|p| p.as_array())
    {
        for part_value in parts {
            if let Ok(part) = serde_json::from_value::<GeminiPart>(part_value.clone()) {
                let mut processor = PartProcessor::new(state);
                chunks.extend(processor.process(&part));
            }
        }
    }
    if let Some(finish_reason) = raw_json
        .get("candidates")
        .and_then(|c| c.get(0))
        .and_then(|cand| cand.get("finishReason"))
        .and_then(|f| f.as_str())
    {
        let usage = raw_json
            .get("usageMetadata")
            .and_then(|u| serde_json::from_value::<UsageMetadata>(u.clone()).ok());

        if let Some(ref u) = usage {
            let cached_tokens = u.cached_content_token_count.unwrap_or(0);
            let cache_info = if cached_tokens > 0 {
                format!(", Cached: {}", cached_tokens)
            } else {
                String::new()
            };

            tracing::info!(
                "[{}] ✓ Stream completed | Account: {} | In: {} tokens | Out: {} tokens{}",
                trace_id,
                email,
                u.prompt_token_count
                    .unwrap_or(0)
                    .saturating_sub(cached_tokens),
                u.candidates_token_count.unwrap_or(0),
                cache_info
            );
        }

        chunks.extend(state.emit_finish(Some(finish_reason), usage.as_ref()));
    }

    if chunks.is_empty() {
        None
    } else {
        Some(chunks)
    }
}
pub fn emit_force_stop(state: &mut StreamingState) -> Vec<Bytes> {
    if !state.message_stop_sent {
        let mut chunks = state.emit_finish(None, None);
        if chunks.is_empty() {
            chunks.push(Bytes::from(
                "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
            ));
            state.message_stop_sent = true;
        }
        return chunks;
    }
    vec![]
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_sse_line_done() {
        let mut state = StreamingState::new();
        let result = process_sse_line("data: [DONE]", &mut state, "test_id", "test@example.com");
        assert!(result.is_some());
        let chunks = result.unwrap();
        assert!(!chunks.is_empty());

        let all_text: String = chunks
            .iter()
            .map(|b| String::from_utf8(b.to_vec()).unwrap_or_default())
            .collect();
        assert!(all_text.contains("message_stop"));
    }

    #[test]
    fn test_process_sse_line_with_text() {
        let mut state = StreamingState::new();

        let test_data = r#"data: {"candidates":[{"content":{"parts":[{"text":"Hello"}]}}],"usageMetadata":{},"modelVersion":"test","responseId":"123"}"#;

        let result = process_sse_line(test_data, &mut state, "test_id", "test@example.com");
        assert!(result.is_some());

        let chunks = result.unwrap();
        assert!(!chunks.is_empty());
        let all_text: String = chunks
            .iter()
            .map(|b| String::from_utf8(b.to_vec()).unwrap_or_default())
            .collect();

        assert!(all_text.contains("message_start"));
        assert!(all_text.contains("content_block_start"));
        assert!(all_text.contains("Hello"));
    }

    #[tokio::test]
    async fn test_thinking_only_interruption_recovery() {
        use futures::StreamExt;
        let mock_stream = async_stream::stream! {
            let thinking_json = serde_json::json!({
                "candidates": [{
                    "content": {
                        "parts": [{ "text": "Thinking...", "thought": true }]
                    }
                }],
                "modelVersion": "gemini-3-flash-thinking",
                "responseId": "msg_interrupted"
            });
            yield Ok(bytes::Bytes::from(format!("data: {}\n\n", thinking_json)));
        };
        let mut claude_stream = create_claude_sse_stream(ClaudeSseStreamInput {
            gemini_stream: Box::pin(mock_stream),
            trace_id: "trace_test".to_string(),
            email: "test@example.com".to_string(),
            session_id: None,
            scaling_enabled: false,
            context_limit: 1_000,
            estimated_prompt_tokens: None,
            message_count: 1,
            client_adapter: None,
        });
        let mut all_chunks = Vec::new();
        while let Some(result) = claude_stream.next().await {
            if let Ok(bytes) = result {
                all_chunks.push(String::from_utf8(bytes.to_vec()).unwrap());
            }
        }
        let output = all_chunks.join("");
        assert!(output.contains("Thinking..."));
        assert!(output.contains("Recovered by Antigravity"));
        assert!(output.contains("\"usage\":"));
        assert!(output.contains("\"output_tokens\":100"));
    }
}