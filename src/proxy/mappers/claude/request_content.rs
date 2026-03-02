use crate::proxy::mappers::claude::models::*;
use crate::proxy::mappers::signature_store::get_thought_signature;
use crate::proxy::mappers::tool_result_compressor;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};

const MAX_TOOL_RESULT_CHARS: usize = 200_000;

pub(super) struct GoogleContentsOptions<'a> {
    pub is_thinking_enabled: bool,
    pub allow_dummy_thought: bool,
    pub mapped_model: &'a str,
    pub session_id: &'a str,
    pub is_retry: bool,
}

struct BuildContentsContext<'a> {
    is_thinking_enabled: bool,
    session_id: &'a str,
    allow_dummy_thought: bool,
    is_retry: bool,
    tool_name_to_schema: &'a HashMap<String, Value>,
    mapped_model: &'a str,
    existing_tool_result_ids: &'a HashSet<String>,
}

struct BuildContentsState<'a> {
    tool_id_to_name: &'a mut HashMap<String, String>,
    last_thought_signature: &'a mut Option<String>,
    pending_tool_use_ids: &'a mut Vec<String>,
    last_user_task_text_normalized: &'a mut Option<String>,
    previous_was_tool_result: &'a mut bool,
}

fn build_contents(
    content: &MessageContent,
    is_assistant: bool,
    ctx: &BuildContentsContext<'_>,
    state: &mut BuildContentsState<'_>,
) -> Result<Vec<Value>, String> {
    let mut parts = Vec::new();
    let mut current_turn_tool_result_ids = HashSet::new();
    let mut saw_non_thinking = false;

    match content {
        MessageContent::String(text) => {
            if text != "(no content)" && !text.trim().is_empty() {
                parts.push(json!({"text": text.trim()}));
            }
        }
        MessageContent::Array(blocks) => {
            for item in blocks {
                match item {
                    ContentBlock::Text { text } => {
                        if text != "(no content)" {
                            if !is_assistant && *state.previous_was_tool_result {
                                if let Some(last_task) = state.last_user_task_text_normalized {
                                    let current_normalized =
                                        text.replace(|c: char| c.is_whitespace(), "");
                                    if !current_normalized.is_empty()
                                        && current_normalized == *last_task
                                    {
                                        tracing::info!("[Claude-Request] Dropping duplicated task text echo (len: {})", text.len());
                                        continue;
                                    }
                                }
                            }

                            parts.push(json!({"text": text}));
                            saw_non_thinking = true;
                            if !is_assistant {
                                *state.last_user_task_text_normalized =
                                    Some(text.replace(|c: char| c.is_whitespace(), ""));
                            }
                            *state.previous_was_tool_result = false;
                        }
                    }
                    ContentBlock::Thinking {
                        thinking,
                        signature,
                        ..
                    } => {
                        tracing::debug!(
                            "[DEBUG-TRANSFORM] Processing thinking block. Sig: {:?}",
                            signature
                        );
                        if saw_non_thinking || !parts.is_empty() {
                            tracing::warn!("[Claude-Request] Thinking block found at non-zero index (prev parts: {}). Downgrading to Text.", parts.len());
                            if !thinking.is_empty() {
                                parts.push(json!({
                                    "text": thinking
                                }));
                                saw_non_thinking = true;
                            }
                            continue;
                        }
                        if !ctx.is_thinking_enabled {
                            tracing::warn!("[Claude-Request] Thinking disabled. Downgrading thinking block to text.");
                            if !thinking.is_empty() {
                                parts.push(json!({
                                    "text": thinking
                                }));
                            }
                            continue;
                        }
                        if thinking.is_empty() {
                            tracing::warn!("[Claude-Request] Empty thinking block detected. Downgrading to Text.");
                            parts.push(json!({
                                "text": "..."
                            }));
                            continue;
                        }
                        if let Some(sig) = signature {
                            if sig.len() < super::thinking::MIN_SIGNATURE_LENGTH {
                                tracing::warn!(
                                    "[Thinking-Signature] Signature too short (len: {} < {}), downgrading to text.",
                                    sig.len(),
                                    super::thinking::MIN_SIGNATURE_LENGTH
                                );
                                parts.push(json!({"text": thinking}));
                                saw_non_thinking = true;
                                continue;
                            }

                            let cached_family =
                                crate::proxy::SignatureCache::global().get_signature_family(sig);

                            match cached_family {
                                Some(family) => {
                                    let compatible = !ctx.is_retry
                                        && is_model_compatible(&family, ctx.mapped_model);

                                    if !compatible {
                                        tracing::warn!(
                                            "[Thinking-Signature] {} signature (Family: {}, Target: {}). Downgrading to text.",
                                            if ctx.is_retry {
                                                "Stripping historical"
                                            } else {
                                                "Incompatible"
                                            },
                                            family,
                                            ctx.mapped_model
                                        );
                                        parts.push(json!({"text": thinking}));
                                        saw_non_thinking = true;
                                        continue;
                                    }
                                    *state.last_thought_signature = Some(sig.clone());
                                    let mut part = json!({
                                        "text": thinking,
                                        "thought": true,
                                        "thoughtSignature": sig
                                    });
                                    crate::proxy::common::json_schema::clean_json_schema(&mut part);
                                    parts.push(part);
                                }
                                None => {
                                    if sig.len() >= super::thinking::MIN_SIGNATURE_LENGTH {
                                        tracing::debug!(
                                            "[Thinking-Signature] Unknown signature origin but valid length (len: {}), using as-is for JSON tool calling.",
                                            sig.len()
                                        );
                                        *state.last_thought_signature = Some(sig.clone());
                                        let mut part = json!({
                                            "text": thinking,
                                            "thought": true,
                                            "thoughtSignature": sig
                                        });
                                        crate::proxy::common::json_schema::clean_json_schema(
                                            &mut part,
                                        );
                                        parts.push(part);
                                    } else {
                                        tracing::warn!(
                                            "[Thinking-Signature] Unknown signature origin and too short (len: {}). Downgrading to text for safety.",
                                            sig.len()
                                        );
                                        parts.push(json!({"text": thinking}));
                                        saw_non_thinking = true;
                                        continue;
                                    }
                                }
                            }
                        } else {
                            tracing::warn!(
                                "[Thinking-Signature] No signature provided. Downgrading to text."
                            );
                            parts.push(json!({"text": thinking}));
                            saw_non_thinking = true;
                        }
                    }
                    ContentBlock::RedactedThinking { data } => {
                        tracing::debug!("[Claude-Request] Degrade RedactedThinking to text");
                        parts.push(json!({
                            "text": format!("[Redacted Thinking: {}]", data)
                        }));
                        saw_non_thinking = true;
                        continue;
                    }
                    ContentBlock::Image { source, .. } => {
                        if source.source_type == "base64" {
                            parts.push(json!({
                                "inlineData": {
                                    "mimeType": source.media_type,
                                    "data": source.data
                                }
                            }));
                            saw_non_thinking = true;
                        }
                    }
                    ContentBlock::Document { source, .. } => {
                        if source.source_type == "base64" {
                            parts.push(json!({
                                "inlineData": {
                                    "mimeType": source.media_type,
                                    "data": source.data
                                }
                            }));
                            saw_non_thinking = true;
                        }
                    }
                    ContentBlock::ToolUse {
                        id,
                        name,
                        input,
                        signature,
                        ..
                    } => {
                        let mut final_input = input.clone();
                        if let Some(original_schema) = ctx.tool_name_to_schema.get(name) {
                            crate::proxy::common::json_schema::fix_tool_call_args(
                                &mut final_input,
                                original_schema,
                            );
                        }

                        let mut part = json!({
                            "functionCall": {
                                "name": name,
                                "args": final_input,
                                "id": id
                            }
                        });
                        saw_non_thinking = true;
                        if is_assistant {
                            state.pending_tool_use_ids.push(id.clone());
                        }
                        state.tool_id_to_name.insert(id.clone(), name.clone());
                        apply_tool_use_signature(&mut part, id, signature, ctx, state);
                        parts.push(part);
                    }
                    ContentBlock::ToolResult {
                        tool_use_id,
                        content,
                        is_error,
                        ..
                    } => {
                        current_turn_tool_result_ids.insert(tool_use_id.clone());
                        let func_name = state
                            .tool_id_to_name
                            .get(tool_use_id)
                            .cloned()
                            .unwrap_or_else(|| tool_use_id.clone());
                        let merged_content =
                            build_tool_result_content(content, is_error.unwrap_or(false));

                        parts.push(json!({
                            "functionResponse": {
                                "name": func_name,
                                "response": {"result": merged_content},
                                "id": tool_use_id
                            }
                        }));
                        if let Some(sig) = state.last_thought_signature.as_ref() {
                            if let Some(last_part) = parts.last_mut() {
                                last_part["thoughtSignature"] = json!(sig);
                            }
                        }
                        *state.previous_was_tool_result = true;
                    }
                    ContentBlock::ServerToolUse { .. }
                    | ContentBlock::WebSearchToolResult { .. } => {
                        continue;
                    }
                }
            }
        }
    }
    if !is_assistant && !state.pending_tool_use_ids.is_empty() {
        let missing_ids: Vec<_> = state
            .pending_tool_use_ids
            .iter()
            .filter(|id| !current_turn_tool_result_ids.contains(*id))
            .cloned()
            .collect();

        if !missing_ids.is_empty() {
            tracing::warn!("[Elastic-Recovery] Injecting {} missing tool results into User message (IDs: {:?})", missing_ids.len(), missing_ids);
            for id in missing_ids.iter().rev() {
                let name = state.tool_id_to_name.get(id).cloned().unwrap_or(id.clone());
                let synthetic_part = json!({
                    "functionResponse": {
                        "name": name,
                        "response": {
                            "result": "Tool execution interrupted. No result provided."
                        },
                        "id": id
                    }
                });
                parts.insert(0, synthetic_part);
            }
        }
        state.pending_tool_use_ids.clear();
    }
    if ctx.allow_dummy_thought && is_assistant && ctx.is_thinking_enabled {
        let has_thought_part = parts.iter().any(|p| {
            p.get("thought").and_then(|v| v.as_bool()).unwrap_or(false)
                || p.get("thoughtSignature").is_some()
                || p.get("thought").and_then(|v| v.as_str()).is_some()
        });

        if !has_thought_part {
            parts.insert(
                0,
                json!({
                    "text": "Thinking...",
                    "thought": true
                }),
            );
            tracing::debug!(
                "Injected dummy thought block for historical assistant message at index {}",
                parts.len()
            );
        } else {
            let first_is_thought = parts.first().is_some_and(|p| {
                (p.get("thought").is_some() || p.get("thoughtSignature").is_some())
                    && p.get("text").is_some()
            });

            if !first_is_thought {
                parts.insert(
                    0,
                    json!({
                        "text": "...",
                        "thought": true
                    }),
                );
                tracing::debug!("First part of model message at {} is not a valid thought block. Prepending dummy.", parts.len());
            } else if let Some(p0) = parts.get_mut(0) {
                if p0.get("thought").is_none() {
                    p0.as_object_mut()
                        .map(|obj| obj.insert("thought".to_string(), json!(true)));
                }
            }
        }
    }

    Ok(parts)
}

fn apply_tool_use_signature(
    part: &mut Value,
    id: &str,
    signature: &Option<String>,
    ctx: &BuildContentsContext<'_>,
    state: &BuildContentsState<'_>,
) {
    let final_sig = resolve_tool_use_signature(id, signature, ctx, state);
    if let Some(sig) = final_sig {
        if ctx.is_retry && signature.is_none() {
            tracing::warn!(
                "[Tool-Signature] Skipping signature backfill for tool_use: {} during retry.",
                id
            );
            return;
        }
        if sig.len() < super::thinking::MIN_SIGNATURE_LENGTH {
            tracing::warn!(
                "[Tool-Signature] Signature too short for tool_use: {} (len: {} < {}), skipping.",
                id,
                sig.len(),
                super::thinking::MIN_SIGNATURE_LENGTH
            );
            return;
        }
        if should_use_tool_signature(&sig, id, ctx) {
            part["thoughtSignature"] = json!(sig);
        }
    } else {
        let is_google_cloud = ctx.mapped_model.starts_with("projects/");
        if ctx.is_thinking_enabled && !is_google_cloud {
            tracing::debug!(
                "[Tool-Signature] Adding GEMINI_SKIP_SIGNATURE for tool_use: {}",
                id
            );
            part["thoughtSignature"] = json!("skip_thought_signature_validator");
        }
    }
}

fn resolve_tool_use_signature(
    id: &str,
    signature: &Option<String>,
    ctx: &BuildContentsContext<'_>,
    state: &BuildContentsState<'_>,
) -> Option<String> {
    signature
        .as_ref()
        .or(state.last_thought_signature.as_ref())
        .cloned()
        .or_else(|| {
            crate::proxy::SignatureCache::global()
                .get_session_signature(ctx.session_id)
                .inspect(|s| {
                    tracing::info!(
                        "[Claude-Request] Recovered signature from SESSION cache (session: {}, len: {})",
                        ctx.session_id,
                        s.len()
                    );
                })
        })
        .or_else(|| {
            crate::proxy::SignatureCache::global()
                .get_tool_signature(id)
                .inspect(|_s| {
                    tracing::info!(
                        "[Claude-Request] Recovered signature from TOOL cache for tool_id: {}",
                        id
                    );
                })
        })
        .or_else(|| {
            let global_sig = get_thought_signature();
            if let Some(sig) = &global_sig {
                tracing::warn!(
                    "[Claude-Request] Using deprecated GLOBAL thought_signature fallback (length: {}). This indicates session cache miss.",
                    sig.len()
                );
            }
            global_sig
        })
}

fn should_use_tool_signature(sig: &str, id: &str, ctx: &BuildContentsContext<'_>) -> bool {
    let cached_family = crate::proxy::SignatureCache::global().get_signature_family(sig);

    match cached_family {
        Some(family) => {
            if is_model_compatible(&family, ctx.mapped_model) {
                true
            } else {
                tracing::warn!(
                    "[Tool-Signature] Incompatible signature for tool_use: {} (Family: {}, Target: {})",
                    id,
                    family,
                    ctx.mapped_model
                );
                false
            }
        }
        None => {
            if sig.len() >= super::thinking::MIN_SIGNATURE_LENGTH {
                tracing::debug!(
                    "[Tool-Signature] Unknown signature origin but valid length (len: {}) for tool_use: {}, using as-is for JSON tool calling.",
                    sig.len(),
                    id
                );
                true
            } else if ctx.is_thinking_enabled {
                tracing::warn!(
                    "[Tool-Signature] Unknown signature origin and too short for tool_use: {} (len: {}). Dropping in thinking mode.",
                    id,
                    sig.len()
                );
                false
            } else {
                true
            }
        }
    }
}

fn build_tool_result_content(content: &Value, is_error: bool) -> String {
    let mut compacted_content = content.clone();
    if let Some(blocks) = compacted_content.as_array_mut() {
        tool_result_compressor::sanitize_tool_result_blocks(blocks);
    }
    let mut merged_content = match &compacted_content {
        Value::String(s) => s.clone(),
        Value::Array(arr) => arr
            .iter()
            .filter_map(|block| {
                if let Some(text) = block.get("text").and_then(|v| v.as_str()) {
                    Some(text.to_string())
                } else if block.get("source").is_some() {
                    if block.get("type").and_then(|v| v.as_str()) == Some("image") {
                        Some("[image omitted to save context]".to_string())
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .join("\n"),
        _ => content.to_string(),
    };

    if merged_content.len() > MAX_TOOL_RESULT_CHARS {
        tracing::warn!(
            "Truncating tool result from {} chars to {}",
            merged_content.len(),
            MAX_TOOL_RESULT_CHARS
        );
        let mut truncated = merged_content
            .chars()
            .take(MAX_TOOL_RESULT_CHARS)
            .collect::<String>();
        truncated.push_str("\n...[truncated output]");
        merged_content = truncated;
    }
    if merged_content.trim().is_empty() {
        if is_error {
            merged_content = "Tool execution failed with no output.".to_string();
        } else {
            merged_content = "Command executed successfully.".to_string();
        }
    }
    merged_content
}

fn build_google_content(
    msg: &Message,
    ctx: &BuildContentsContext<'_>,
    state: &mut BuildContentsState<'_>,
) -> Result<Value, String> {
    let role = if msg.role == "assistant" {
        "model"
    } else {
        &msg.role
    };
    if role == "model" && !state.pending_tool_use_ids.is_empty() {
        tracing::warn!("[Elastic-Recovery] Detected interrupted tool chain (Assistant -> Assistant). Injecting synthetic User message for IDs: {:?}", state.pending_tool_use_ids);

        let synthetic_parts: Vec<serde_json::Value> = state
            .pending_tool_use_ids
            .iter()
            .filter(|id| !ctx.existing_tool_result_ids.contains(*id))
            .map(|id| {
                let name = state.tool_id_to_name.get(id).cloned().unwrap_or(id.clone());
                json!({
                    "functionResponse": {
                        "name": name,
                        "response": {
                            "result": "Tool execution interrupted. No result provided."
                        },
                        "id": id
                    }
                })
            })
            .collect();

        if !synthetic_parts.is_empty() {
            return Ok(json!({
                "role": "user",
                "parts": synthetic_parts
            }));
        }
        state.pending_tool_use_ids.clear();
    }

    let parts = build_contents(&msg.content, msg.role == "assistant", ctx, state)?;

    if parts.is_empty() {
        return Ok(json!(null));
    }

    Ok(json!({
        "role": role,
        "parts": parts
    }))
}

pub(super) fn build_google_contents(
    messages: &[Message],
    tool_id_to_name: &mut HashMap<String, String>,
    tool_name_to_schema: &HashMap<String, Value>,
    options: GoogleContentsOptions<'_>,
) -> Result<Value, String> {
    let mut contents = Vec::new();
    let mut last_thought_signature: Option<String> = None;
    let mut _accumulated_usage: Option<Value> = None;
    let mut pending_tool_use_ids: Vec<String> = Vec::new();
    let mut last_user_task_text_normalized: Option<String> = None;
    let mut previous_was_tool_result = false;

    let _msg_count = messages.len();
    let mut existing_tool_result_ids = HashSet::new();
    for msg in messages {
        if let MessageContent::Array(blocks) = &msg.content {
            for block in blocks {
                if let ContentBlock::ToolResult { tool_use_id, .. } = block {
                    existing_tool_result_ids.insert(tool_use_id.clone());
                }
            }
        }
    }

    let build_ctx = BuildContentsContext {
        is_thinking_enabled: options.is_thinking_enabled,
        session_id: options.session_id,
        allow_dummy_thought: options.allow_dummy_thought,
        is_retry: options.is_retry,
        tool_name_to_schema,
        mapped_model: options.mapped_model,
        existing_tool_result_ids: &existing_tool_result_ids,
    };
    let mut build_state = BuildContentsState {
        tool_id_to_name,
        last_thought_signature: &mut last_thought_signature,
        pending_tool_use_ids: &mut pending_tool_use_ids,
        last_user_task_text_normalized: &mut last_user_task_text_normalized,
        previous_was_tool_result: &mut previous_was_tool_result,
    };

    for msg in messages {
        let google_content = build_google_content(msg, &build_ctx, &mut build_state)?;

        if !google_content.is_null() {
            contents.push(google_content);
        }
    }
    let mut merged_contents = merge_adjacent_roles(contents);
    if !options.is_thinking_enabled {
        for msg in &mut merged_contents {
            super::generation::clean_thinking_fields_recursive(msg);
        }
    }

    Ok(json!(merged_contents))
}

fn merge_adjacent_roles(mut contents: Vec<Value>) -> Vec<Value> {
    if contents.is_empty() {
        return contents;
    }

    let mut merged = Vec::new();
    let mut current_msg = contents.remove(0);

    for msg in contents {
        let current_role = current_msg["role"].as_str().unwrap_or_default();
        let next_role = msg["role"].as_str().unwrap_or_default();

        if current_role == next_role {
            if let Some(current_parts) = current_msg.get_mut("parts").and_then(|p| p.as_array_mut())
            {
                if let Some(next_parts) = msg.get("parts").and_then(|p| p.as_array()) {
                    current_parts.extend(next_parts.clone());
                    super::preprocess::reorder_gemini_parts(current_parts);
                }
            }
        } else {
            merged.push(current_msg);
            current_msg = msg;
        }
    }
    merged.push(current_msg);
    merged
}

fn is_model_compatible(cached: &str, target: &str) -> bool {
    crate::proxy::common::model_mapping::is_signature_family_compatible(cached, target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn build_tool_result_content_handles_empty_non_error() {
        let content = json!([]);
        let result = build_tool_result_content(&content, false);
        assert_eq!(result, "Command executed successfully.");
    }

    #[test]
    fn build_tool_result_content_handles_empty_error() {
        let content = json!([]);
        let result = build_tool_result_content(&content, true);
        assert_eq!(result, "Tool execution failed with no output.");
    }

    #[test]
    fn build_tool_result_content_collapses_array_blocks_and_omits_images() {
        let content = json!([
            {"type":"text","text":"line 1"},
            {"type":"image","source":{"type":"base64","media_type":"image/png","data":"AAAA"}},
            {"type":"text","text":"line 2"}
        ]);
        let result = build_tool_result_content(&content, false);
        assert!(result.contains("line 1"));
        assert!(result.contains("line 2"));
        assert!(!result.trim().is_empty());
    }

    #[test]
    fn build_tool_result_content_truncates_large_payload() {
        let long = "x".repeat(MAX_TOOL_RESULT_CHARS + 5000);
        let content = Value::String(long);
        let result = build_tool_result_content(&content, false);
        assert!(result.len() > MAX_TOOL_RESULT_CHARS);
        assert!(result.contains("...[truncated output]"));
    }
}
