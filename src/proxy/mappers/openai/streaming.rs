use bytes::{Bytes, BytesMut};
use chrono::Utc;
use futures::{Stream, StreamExt};
use rand::Rng;
use serde_json::{json, Value};
use std::pin::Pin;
use tracing::debug;
use uuid::Uuid;

use crate::proxy::signature_cache::SignatureCache;
pub fn store_thought_signature(sig: &str, session_id: &str, message_count: usize) {
    if sig.is_empty() {
        return;
    }
    crate::proxy::mappers::signature_store::store_thought_signature(sig);
    SignatureCache::global().cache_session_signature(session_id, sig.to_string(), message_count);

    tracing::debug!(
        "[ThoughtSig] Storing Session signature (sid: {}, len: {}, msg_count: {})",
        session_id,
        sig.len(),
        message_count
    );
}
fn extract_usage_metadata(u: &Value) -> Option<super::models::OpenAIUsage> {
    use super::models::{OpenAIUsage, PromptTokensDetails};

    let prompt_tokens = u
        .get("promptTokenCount")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;
    let completion_tokens = u
        .get("candidatesTokenCount")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;
    let total_tokens = u
        .get("totalTokenCount")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;
    let cached_tokens = u
        .get("cachedContentTokenCount")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32);

    Some(OpenAIUsage {
        prompt_tokens,
        completion_tokens,
        total_tokens,
        prompt_tokens_details: cached_tokens.map(|ct| PromptTokensDetails {
            cached_tokens: Some(ct),
        }),
        completion_tokens_details: None,
    })
}

fn build_grounding_fallback_text(candidate: &Value) -> String {
    let mut grounding_text = String::new();
    if let Some(grounding) = candidate.get("groundingMetadata") {
        if let Some(queries) = grounding.get("webSearchQueries").and_then(|q| q.as_array()) {
            let query_list: Vec<&str> = queries.iter().filter_map(|v| v.as_str()).collect();
            if !query_list.is_empty() {
                grounding_text.push_str("\n\n---\nSearched for: ");
                grounding_text.push_str(&query_list.join(", "));
            }
        }
        if let Some(chunks) = grounding.get("groundingChunks").and_then(|c| c.as_array()) {
            let mut links = Vec::new();
            for (i, chunk) in chunks.iter().enumerate() {
                if let Some(web) = chunk.get("web") {
                    let title = web
                        .get("title")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Web source");
                    let uri = web.get("uri").and_then(|v| v.as_str()).unwrap_or("#");
                    links.push(format!("[{}] [{}]({})", i + 1, title, uri));
                }
            }
            if !links.is_empty() {
                grounding_text.push_str("\n\nSource citations:\n");
                grounding_text.push_str(&links.join("\n"));
            }
        }
    }
    grounding_text
}

fn stable_tool_call_id(func_call: &Value) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    use std::hash::{Hash, Hasher};
    serde_json::to_string(func_call)
        .unwrap_or_default()
        .hash(&mut hasher);
    format!("call_{:x}", hasher.finish())
}

pub fn create_openai_sse_stream(
    mut gemini_stream: Pin<Box<dyn Stream<Item = Result<Bytes, reqwest::Error>> + Send>>,
    model: String,
    session_id: String,
    message_count: usize,
) -> Pin<Box<dyn Stream<Item = Result<Bytes, String>> + Send>> {
    let mut buffer = BytesMut::new();
    let stream_id = format!("chatcmpl-{}", Uuid::new_v4());
    let created_ts = Utc::now().timestamp();

    let stream = async_stream::stream! {
        let mut emitted_tool_calls = std::collections::HashSet::new();
        let mut tool_call_indices: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
        let mut final_usage: Option<super::models::OpenAIUsage> = None;
        let mut error_occurred = false;

        let mut heartbeat_interval = tokio::time::interval(std::time::Duration::from_secs(15));
        heartbeat_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                item = gemini_stream.next() => {
                    match item {
                        Some(Ok(bytes)) => {
                            buffer.extend_from_slice(&bytes);
                            while let Some(pos) = buffer.iter().position(|&b| b == b'\n') {
                                let line_raw = buffer.split_to(pos + 1);
                                if let Ok(line_str) = std::str::from_utf8(&line_raw) {
                                    let line = line_str.trim();
                                    if line.is_empty() { continue; }
                                    if line.starts_with("data: ") {
                                        let json_part = line.trim_start_matches("data: ").trim();
                                        if json_part == "[DONE]" { continue; }
                                        if let Ok(mut json) = serde_json::from_str::<Value>(json_part) {
                                            let actual_data = if let Some(inner) = json.get_mut("response").map(|v| v.take()) { inner } else { json };
                                            if let Some(u) = actual_data.get("usageMetadata") {
                                                final_usage = extract_usage_metadata(u);
                                            }

                                            if let Some(candidates) = actual_data.get("candidates").and_then(|c| c.as_array()) {
                                                for (idx, candidate) in candidates.iter().enumerate() {
                                                    let parts = candidate.get("content").and_then(|c| c.get("parts")).and_then(|p| p.as_array());
                                                    let mut content_out = String::new();
                                                    let mut thought_out = String::new();

                                                    if let Some(parts_list) = parts {
                                                        for part in parts_list {
                                                            let is_thought_part = part.get("thought").and_then(|v| v.as_bool()).unwrap_or(false);
                                                            if let Some(text) = part.get("text").and_then(|t| t.as_str()) {
                                                                if is_thought_part { thought_out.push_str(text); }
                                                                else { content_out.push_str(text); }
                                                            }
                                                            if let Some(sig) = part.get("thoughtSignature").or(part.get("thought_signature")).and_then(|s| s.as_str()) {
                                                                store_thought_signature(sig, &session_id, message_count);
                                                            }
                                                            if let Some(img) = part.get("inlineData") {
                                                                let mime_type = img.get("mimeType").and_then(|v| v.as_str()).unwrap_or("image/png");
                                                                let data = img.get("data").and_then(|v| v.as_str()).unwrap_or("");
                                                                if !data.is_empty() {
                                                                    content_out.push_str(&format!("![image](data:{};base64,{})", mime_type, data));
                                                                }
                                                            }
                                                            if let Some(func_call) = part.get("functionCall") {
                                                                let call_key = serde_json::to_string(func_call).unwrap_or_default();
                                                                if !emitted_tool_calls.contains(&call_key) {
                                                                    emitted_tool_calls.insert(call_key.clone());
                                                                    let tool_call_index = if let Some(existing) =
                                                                        tool_call_indices.get(&call_key)
                                                                    {
                                                                        *existing
                                                                    } else {
                                                                        let new_index =
                                                                            tool_call_indices.len() as u32;
                                                                        tool_call_indices
                                                                            .insert(call_key.clone(), new_index);
                                                                        new_index
                                                                    };
                                                                    let name = func_call.get("name").and_then(|v| v.as_str()).unwrap_or("unknown");
                                                                    let mut args = func_call.get("args").unwrap_or(&json!({})).clone();
                                                                    if name == "shell" || name == "bash" || name == "local_shell" {
                                                                        if let Some(obj) = args.as_object_mut() {
                                                                            if !obj.contains_key("command") {
                                                                                for alt_key in &["cmd", "code", "script", "shell_command"] {
                                                                                    if let Some(val) = obj.remove(*alt_key) {
                                                                                        obj.insert("command".to_string(), val);
                                                                                        debug!("[OpenAI-Stream] Normalized shell arg '{}' -> 'command'", alt_key);
                                                                                        break;
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }

                                                                    let args_str = serde_json::to_string(&args).unwrap_or_default();
                                                                    let call_id = stable_tool_call_id(func_call);

                                                                    let tool_call_chunk = json!({
                                                                        "id": &stream_id,
                                                                        "object": "chat.completion.chunk",
                                                                        "created": created_ts,
                                                                        "model": &model,
                                                                        "choices": [{
                                                                            "index": idx as u32,
                                                                            "delta": {
                                                                                "role": "assistant",
                                                                                "tool_calls": [{
                                                                                    "index": tool_call_index,
                                                                                    "id": call_id,
                                                                                    "type": "function",
                                                                                    "function": { "name": name, "arguments": args_str }
                                                                                }]
                                                                            },
                                                                            "finish_reason": serde_json::Value::Null
                                                                        }]
                                                                    });
                                                                    let sse_out = format!("data: {}\n\n", serde_json::to_string(&tool_call_chunk).unwrap_or_default());
                                                                    yield Ok::<Bytes, String>(Bytes::from(sse_out));
                                                                }
                                                            }
                                                        }
                                                    }

                                                    if let Some(grounding) = candidate.get("groundingMetadata") {
                                                        let mut grounding_text = String::new();
                                                        if let Some(queries) = grounding.get("webSearchQueries").and_then(|q| q.as_array()) {
                                                            let query_list: Vec<&str> = queries.iter().filter_map(|v| v.as_str()).collect();
                                                            if !query_list.is_empty() {
                                                                grounding_text.push_str("\n\n---\n**🔍 Searched for you:** ");
                                                                grounding_text.push_str(&query_list.join(", "));
                                                            }
                                                        }
                                                        if let Some(chunks) = grounding.get("groundingChunks").and_then(|c| c.as_array()) {
                                                            let mut links = Vec::new();
                                                            for (i, chunk) in chunks.iter().enumerate() {
                                                                if let Some(web) = chunk.get("web") {
                                                                    let title = web.get("title").and_then(|v| v.as_str()).unwrap_or("Web source");
                                                                    let uri = web.get("uri").and_then(|v| v.as_str()).unwrap_or("#");
                                                                    links.push(format!("[{}] [{}]({})", i + 1, title, uri));
                                                                }
                                                            }
                                                            if !links.is_empty() {
                                                                grounding_text.push_str("\n\n**🌐 Source Citations:**\n");
                                                                grounding_text.push_str(&links.join("\n"));
                                                            }
                                                        }
                                                        if !grounding_text.is_empty() { content_out.push_str(&grounding_text); }
                                                    }

                                                    let gemini_finish_reason = candidate.get("finishReason").and_then(|f| f.as_str()).map(|f| match f {
                                                        "STOP" => "stop",
                                                        "MAX_TOKENS" => "length",
                                                        "SAFETY" => "content_filter",
                                                        "RECITATION" => "content_filter",
                                                        _ => f,
                                                    });
                                                    let finish_reason = if !emitted_tool_calls.is_empty() && gemini_finish_reason.is_some() {
                                                        Some("tool_calls")
                                                    } else {
                                                        gemini_finish_reason
                                                    };

                                                    if !thought_out.is_empty() {
                                                        let reasoning_chunk = json!({
                                                            "id": &stream_id,
                                                            "object": "chat.completion.chunk",
                                                            "created": created_ts,
                                                            "model": &model,
                                                            "choices": [{
                                                                "index": idx as u32,
                                                                "delta": { "role": "assistant", "content": serde_json::Value::Null, "reasoning_content": thought_out },
                                                                "finish_reason": serde_json::Value::Null
                                                            }]
                                                        });
                                                        let sse_out = format!("data: {}\n\n", serde_json::to_string(&reasoning_chunk).unwrap_or_default());
                                                        yield Ok::<Bytes, String>(Bytes::from(sse_out));
                                                    }

                                                    if !content_out.is_empty() || finish_reason.is_some() {
                                                        let mut openai_chunk = json!({
                                                            "id": &stream_id,
                                                            "object": "chat.completion.chunk",
                                                            "created": created_ts,
                                                            "model": &model,
                                                            "choices": [{
                                                                "index": idx as u32,
                                                                "delta": { "content": content_out },
                                                                "finish_reason": finish_reason
                                                            }]
                                                        });
                                                        if let Some(ref usage) = final_usage {
                                                            openai_chunk["usage"] = serde_json::to_value(usage).unwrap();
                                                        }
                                                        if finish_reason.is_some() { final_usage = None; }
                                                        let sse_out = format!("data: {}\n\n", serde_json::to_string(&openai_chunk).unwrap_or_default());
                                                        yield Ok::<Bytes, String>(Bytes::from(sse_out));
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Some(Err(e)) => {
                            use crate::proxy::mappers::error_classifier::classify_stream_error;
                            let (error_type, user_msg, i18n_key) = classify_stream_error(&e);
                            tracing::error!("OpenAI Stream Error: {}", e);
                            let error_chunk = json!({
                                "id": &stream_id, "object": "chat.completion.chunk", "created": created_ts, "model": &model, "choices": [],
                                "error": { "type": error_type, "message": user_msg, "code": "stream_error", "i18n_key": i18n_key }
                            });
                            yield Ok(Bytes::from(format!("data: {}\n\n", serde_json::to_string(&error_chunk).unwrap_or_default())));
                            yield Ok(Bytes::from("data: [DONE]\n\n"));
                            error_occurred = true;
                            break;
                        }
                        None => break,
                    }
                }
                _ = heartbeat_interval.tick() => {
                    yield Ok::<Bytes, String>(Bytes::from(": ping\n\n"));
                }
            }
        }
        if !error_occurred {
            yield Ok::<Bytes, String>(Bytes::from("data: [DONE]\n\n"));
        }
    };
    Box::pin(stream)
}

pub fn create_legacy_sse_stream(
    mut gemini_stream: Pin<Box<dyn Stream<Item = Result<Bytes, reqwest::Error>> + Send>>,
    model: String,
    session_id: String,
    message_count: usize,
) -> Pin<Box<dyn Stream<Item = Result<Bytes, String>> + Send>> {
    let mut buffer = BytesMut::new();
    let charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();
    let random_str: String = (0..28)
        .map(|_| {
            let idx = rng.gen_range(0..charset.len());
            charset.chars().nth(idx).unwrap()
        })
        .collect();
    let stream_id = format!("cmpl-{}", random_str);
    let created_ts = Utc::now().timestamp();

    let stream = async_stream::stream! {
        let mut final_usage: Option<super::models::OpenAIUsage> = None;
        let mut error_occurred = false;
        let mut heartbeat_interval = tokio::time::interval(std::time::Duration::from_secs(15));
        heartbeat_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                item = gemini_stream.next() => {
                    match item {
                        Some(Ok(bytes)) => {
                            buffer.extend_from_slice(&bytes);
                            while let Some(pos) = buffer.iter().position(|&b| b == b'\n') {
                                let line_raw = buffer.split_to(pos + 1);
                                if let Ok(line_str) = std::str::from_utf8(&line_raw) {
                                    let line = line_str.trim();
                                    if line.is_empty() { continue; }
                                    if line.starts_with("data: ") {
                                        let json_part = line.trim_start_matches("data: ").trim();
                                        if json_part == "[DONE]" { continue; }
                                        if let Ok(mut json) = serde_json::from_str::<Value>(json_part) {
                                            let actual_data = if let Some(inner) = json.get_mut("response").map(|v| v.take()) { inner } else { json };
                                            if let Some(u) = actual_data.get("usageMetadata") { final_usage = extract_usage_metadata(u); }

                                            let mut content_out = String::new();
                                            if let Some(candidates) = actual_data.get("candidates").and_then(|c| c.as_array()) {
                                                if let Some(candidate) = candidates.first() {
                                                    if let Some(parts) = candidate.get("content").and_then(|c| c.get("parts")).and_then(|p| p.as_array()) {
                                                        for part in parts {
                                                            if let Some(text) = part.get("text").and_then(|t| t.as_str()) {
                                                                content_out.push_str(text);
                                                            }
                                                            if let Some(sig) = part.get("thoughtSignature").or(part.get("thought_signature")).and_then(|s| s.as_str()) {
                                                                store_thought_signature(sig, &session_id, message_count);
                                                            }
                                                        }
                                                    }
                                                }
                                            }

                                            let finish_reason = actual_data.get("candidates").and_then(|c| c.as_array()).and_then(|c| c.first()).and_then(|c| c.get("finishReason")).and_then(|f| f.as_str()).map(|f| match f {
                                                "STOP" => "stop", "MAX_TOKENS" => "length", "SAFETY" => "content_filter", _ => f,
                                            });

                                            let mut legacy_chunk = json!({
                                                "id": &stream_id, "object": "text_completion", "created": created_ts, "model": &model,
                                                "choices": [{ "text": content_out, "index": 0, "logprobs": null, "finish_reason": finish_reason }]
                                            });
                                            if let Some(ref usage) = final_usage { legacy_chunk["usage"] = serde_json::to_value(usage).unwrap(); }
                                            if finish_reason.is_some() { final_usage = None; }
                                            yield Ok::<Bytes, String>(Bytes::from(format!("data: {}\n\n", serde_json::to_string(&legacy_chunk).unwrap_or_default())));
                                        }
                                    }
                                }
                            }
                        }
                        Some(Err(e)) => {
                            use crate::proxy::mappers::error_classifier::classify_stream_error;
                            let (error_type, user_msg, i18n_key) = classify_stream_error(&e);
                            tracing::error!("Legacy Stream Error: {}", e);
                            let error_chunk = json!({
                                "id": &stream_id, "object": "text_completion", "created": created_ts, "model": &model, "choices": [],
                                "error": { "type": error_type, "message": user_msg, "code": "stream_error", "i18n_key": i18n_key }
                            });
                            yield Ok::<Bytes, String>(Bytes::from(format!("data: {}\n\n", serde_json::to_string(&error_chunk).unwrap_or_default())));
                            yield Ok::<Bytes, String>(Bytes::from("data: [DONE]\n\n"));
                            error_occurred = true;
                            break;
                        }
                        None => break,
                    }
                }
                _ = heartbeat_interval.tick() => { yield Ok::<Bytes, String>(Bytes::from(": ping\n\n")); }
            }
        }
        if !error_occurred {
            yield Ok::<Bytes, String>(Bytes::from("data: [DONE]\n\n"));
        }
    };
    Box::pin(stream)
}

pub fn create_codex_sse_stream(
    mut gemini_stream: Pin<Box<dyn Stream<Item = Result<Bytes, reqwest::Error>> + Send>>,
    model: String,
    session_id: String,
    message_count: usize,
) -> Pin<Box<dyn Stream<Item = Result<Bytes, String>> + Send>> {
    let mut buffer = BytesMut::new();
    let charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();
    let random_str: String = (0..24)
        .map(|_| {
            let idx = rng.gen_range(0..charset.len());
            charset.chars().nth(idx).unwrap()
        })
        .collect();
    let response_id = format!("resp-{}", random_str);

    let stream = async_stream::stream! {
        let output_item_id = format!("msg_{}", Uuid::new_v4().simple());
        let created_ev = json!({
            "type": "response.created",
            "response": {
                "id": &response_id,
                "object": "response",
                "status": "in_progress",
                "model": &model,
                "output": []
            }
        });
        yield Ok::<Bytes, String>(Bytes::from(format!("data: {}\n\n", serde_json::to_string(&created_ev).unwrap())));
        let output_item_added_ev = json!({
            "type": "response.output_item.added",
            "output_index": 0,
            "item": {
                "id": &output_item_id,
                "type": "message",
                "status": "in_progress",
                "role": "assistant",
                "content": []
            }
        });
        yield Ok::<Bytes, String>(Bytes::from(format!("data: {}\n\n", serde_json::to_string(&output_item_added_ev).unwrap())));
        let content_part_added_ev = json!({
            "type": "response.content_part.added",
            "output_index": 0,
            "item_id": &output_item_id,
            "content_index": 0,
            "part": { "type": "output_text", "text": "" }
        });
        yield Ok::<Bytes, String>(Bytes::from(format!("data: {}\n\n", serde_json::to_string(&content_part_added_ev).unwrap())));

        let mut emitted_tool_calls = std::collections::HashSet::new();
        let mut tool_call_indices: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
        let mut full_text = String::new();
        let mut error_occurred = false;
        let mut heartbeat_interval = tokio::time::interval(std::time::Duration::from_secs(15));
        heartbeat_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                item = gemini_stream.next() => {
                    match item {
                        Some(Ok(bytes)) => {
                            buffer.extend_from_slice(&bytes);
                            while let Some(pos) = buffer.iter().position(|&b| b == b'\n') {
                                let line_raw = buffer.split_to(pos + 1);
                                if let Ok(line_str) = std::str::from_utf8(&line_raw) {
                                    let line = line_str.trim();
                                    if line.is_empty() || !line.starts_with("data: ") { continue; }
                                    let json_part = line.trim_start_matches("data: ").trim();
                                    if json_part == "[DONE]" { continue; }

                                    if let Ok(mut json) = serde_json::from_str::<Value>(json_part) {
                                        let actual_data = if let Some(inner) = json.get_mut("response").map(|v| v.take()) { inner } else { json };
                                        if let Some(candidates) = actual_data.get("candidates").and_then(|c| c.as_array()) {
                                            if let Some(candidate) = candidates.first() {
                                                let mut text_chunk = String::new();
                                                if let Some(parts) = candidate.get("content").and_then(|c| c.get("parts")).and_then(|p| p.as_array()) {
                                                    for part in parts {
                                                        if let Some(text) = part.get("text").and_then(|t| t.as_str()) {
                                                            text_chunk.push_str(text);
                                                        }
                                                        if let Some(sig) = part.get("thoughtSignature").or(part.get("thought_signature")).and_then(|s| s.as_str()) {
                                                            store_thought_signature(sig, &session_id, message_count);
                                                        }
                                                        if let Some(func_call) = part.get("functionCall") {
                                                            let call_key = serde_json::to_string(func_call).unwrap_or_default();
                                                            if !emitted_tool_calls.contains(&call_key) {
                                                                emitted_tool_calls.insert(call_key.clone());
                                                                let tool_call_index = if let Some(existing) = tool_call_indices.get(&call_key) {
                                                                    *existing
                                                                } else {
                                                                    let new_index = tool_call_indices.len() as u32;
                                                                    tool_call_indices.insert(call_key.clone(), new_index);
                                                                    new_index
                                                                };
                                                                let name = func_call.get("name").and_then(|v| v.as_str()).unwrap_or("unknown");
                                                                let args = func_call.get("args").cloned().unwrap_or_else(|| json!({}));
                                                                let args_str = serde_json::to_string(&args).unwrap_or_default();
                                                                let call_id = stable_tool_call_id(func_call);
                                                                let tool_added_ev = json!({
                                                                    "type": "response.output_item.added",
                                                                    "output_index": tool_call_index + 1,
                                                                    "item": {
                                                                        "id": call_id,
                                                                        "type": "function_call",
                                                                        "status": "completed",
                                                                        "name": name,
                                                                        "arguments": args_str
                                                                    }
                                                                });
                                                                yield Ok::<Bytes, String>(Bytes::from(format!("data: {}\n\n", serde_json::to_string(&tool_added_ev).unwrap())));
                                                                let tool_done_ev = json!({
                                                                    "type": "response.output_item.done",
                                                                    "output_index": tool_call_index + 1,
                                                                    "item": {
                                                                        "id": call_id,
                                                                        "type": "function_call",
                                                                        "status": "completed",
                                                                        "name": name,
                                                                        "arguments": args_str
                                                                    }
                                                                });
                                                                yield Ok::<Bytes, String>(Bytes::from(format!("data: {}\n\n", serde_json::to_string(&tool_done_ev).unwrap())));
                                                            }
                                                        }
                                                    }
                                                }
                                                if text_chunk.is_empty() {
                                                    let grounding_fallback = build_grounding_fallback_text(candidate);
                                                    if !grounding_fallback.is_empty() {
                                                        text_chunk = grounding_fallback;
                                                    }
                                                }
                                                if !text_chunk.is_empty() {
                                                    full_text.push_str(&text_chunk);
                                                    let delta_ev = json!({
                                                        "type": "response.output_text.delta",
                                                        "output_index": 0,
                                                        "item_id": &output_item_id,
                                                        "content_index": 0,
                                                        "delta": text_chunk
                                                    });
                                                    yield Ok::<Bytes, String>(Bytes::from(format!("data: {}\n\n", serde_json::to_string(&delta_ev).unwrap())));
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Some(Err(e)) => {
                            error_occurred = true;
                            let err_ev = json!({
                                "type": "response.failed",
                                "response": {
                                    "id": &response_id,
                                    "object": "response",
                                    "status": "failed"
                                },
                                "error": {
                                    "message": e.to_string()
                                }
                            });
                            yield Ok::<Bytes, String>(Bytes::from(format!("data: {}\n\n", serde_json::to_string(&err_ev).unwrap())));
                            break;
                        }
                        None => break,
                    }
                }
                _ = heartbeat_interval.tick() => { yield Ok::<Bytes, String>(Bytes::from(": ping\n\n")); }
            }
        }
        if !error_occurred {
            let output_text_done_ev = json!({
                "type": "response.output_text.done",
                "output_index": 0,
                "item_id": &output_item_id,
                "content_index": 0,
                "text": &full_text
            });
            yield Ok::<Bytes, String>(Bytes::from(format!("data: {}\n\n", serde_json::to_string(&output_text_done_ev).unwrap())));
            let content_part_done_ev = json!({
                "type": "response.content_part.done",
                "output_index": 0,
                "item_id": &output_item_id,
                "content_index": 0,
                "part": { "type": "output_text", "text": &full_text }
            });
            yield Ok::<Bytes, String>(Bytes::from(format!("data: {}\n\n", serde_json::to_string(&content_part_done_ev).unwrap())));
            let output_item_done_ev = json!({
                "type": "response.output_item.done",
                "output_index": 0,
                "item": {
                    "id": &output_item_id,
                    "type": "message",
                    "status": "completed",
                    "role": "assistant",
                    "content": [{
                        "type": "output_text",
                        "text": &full_text
                    }]
                }
            });
            yield Ok::<Bytes, String>(Bytes::from(format!("data: {}\n\n", serde_json::to_string(&output_item_done_ev).unwrap())));
            let completed_ev = json!({
                "type": "response.completed",
                "response": {
                    "id": &response_id,
                    "object": "response",
                    "status": "completed",
                    "model": &model,
                    "output": [{
                        "id": &output_item_id,
                        "type": "message",
                        "status": "completed",
                        "role": "assistant",
                        "content": [{
                            "type": "output_text",
                            "text": &full_text
                        }]
                    }]
                }
            });
            yield Ok::<Bytes, String>(Bytes::from(format!("data: {}\n\n", serde_json::to_string(&completed_ev).unwrap())));
        }
        yield Ok::<Bytes, String>(Bytes::from("data: [DONE]\n\n"));
    };
    Box::pin(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;

    fn data_line(json: serde_json::Value) -> Bytes {
        Bytes::from(format!("data: {}\n", serde_json::to_string(&json).unwrap()))
    }

    async fn collect_event_payloads(
        mut stream: Pin<Box<dyn Stream<Item = Result<Bytes, String>> + Send>>,
    ) -> Vec<serde_json::Value> {
        let mut payloads = Vec::new();
        while let Some(item) = stream.next().await {
            let bytes = item.expect("stream item should be ok");
            let line = String::from_utf8(bytes.to_vec()).expect("valid utf8");
            for part in line.lines() {
                if !part.starts_with("data: ") {
                    continue;
                }
                let raw = part.trim_start_matches("data: ").trim();
                if raw == "[DONE]" {
                    continue;
                }
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) {
                    payloads.push(v);
                }
            }
        }
        payloads
    }

    #[tokio::test]
    async fn codex_stream_emits_lifecycle_events_in_order() {
        let gemini_events = vec![Ok::<Bytes, reqwest::Error>(data_line(json!({
            "candidates": [{
                "content": { "parts": [{ "text": "Hello from Codex stream." }] },
                "finishReason": "STOP"
            }]
        })))];
        let stream = create_codex_sse_stream(
            Box::pin(futures::stream::iter(gemini_events)),
            "gpt-5.3-codex".to_string(),
            "session-lifecycle".to_string(),
            1,
        );
        let payloads = collect_event_payloads(stream).await;
        let event_types: Vec<&str> = payloads
            .iter()
            .filter_map(|p| p.get("type").and_then(|v| v.as_str()))
            .collect();
        let expected = vec![
            "response.created",
            "response.output_item.added",
            "response.content_part.added",
            "response.output_text.delta",
            "response.output_text.done",
            "response.content_part.done",
            "response.output_item.done",
            "response.completed",
        ];
        assert_eq!(event_types, expected);
    }

    #[tokio::test]
    async fn codex_stream_uses_grounding_as_non_empty_fallback_text() {
        let gemini_events = vec![Ok::<Bytes, reqwest::Error>(data_line(json!({
            "candidates": [{
                "content": { "parts": [] },
                "groundingMetadata": {
                    "webSearchQueries": ["gephyr proxy"],
                    "groundingChunks": [{
                        "web": {
                            "title": "Gephyr",
                            "uri": "https://example.com/gephyr"
                        }
                    }]
                },
                "finishReason": "STOP"
            }]
        })))];
        let stream = create_codex_sse_stream(
            Box::pin(futures::stream::iter(gemini_events)),
            "gpt-5.3-codex".to_string(),
            "session-grounding".to_string(),
            1,
        );
        let payloads = collect_event_payloads(stream).await;
        let delta_event = payloads
            .iter()
            .find(|p| p.get("type").and_then(|v| v.as_str()) == Some("response.output_text.delta"))
            .expect("expected output_text delta event");
        let delta = delta_event
            .get("delta")
            .and_then(|v| v.as_str())
            .expect("delta text");
        assert!(
            delta.contains("Searched for"),
            "grounding fallback should produce readable text"
        );
    }

    #[tokio::test]
    async fn openai_stream_assigns_stable_tool_call_indices() {
        let gemini_events = vec![
            Ok::<Bytes, reqwest::Error>(data_line(json!({
                "candidates": [{
                    "content": { "parts": [{
                        "functionCall": { "name": "first_tool", "args": { "a": 1 } }
                    }] }
                }]
            }))),
            Ok::<Bytes, reqwest::Error>(data_line(json!({
                "candidates": [{
                    "content": { "parts": [{
                        "functionCall": { "name": "second_tool", "args": { "b": 2 } }
                    }] },
                    "finishReason": "STOP"
                }]
            }))),
        ];
        let stream = create_openai_sse_stream(
            Box::pin(futures::stream::iter(gemini_events)),
            "gpt-5.3-codex".to_string(),
            "session-tools".to_string(),
            1,
        );
        let payloads = collect_event_payloads(stream).await;
        let mut tool_indices = Vec::new();
        for payload in payloads {
            let idx = payload
                .get("choices")
                .and_then(|c| c.as_array())
                .and_then(|arr| arr.first())
                .and_then(|choice| choice.get("delta"))
                .and_then(|delta| delta.get("tool_calls"))
                .and_then(|calls| calls.as_array())
                .and_then(|calls| calls.first())
                .and_then(|call| call.get("index"))
                .and_then(|idx| idx.as_u64());
            if let Some(index) = idx {
                tool_indices.push(index);
            }
        }
        assert_eq!(tool_indices, vec![0, 1]);
    }
}
