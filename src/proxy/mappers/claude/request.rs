use super::models::*;
use crate::proxy::mappers::signature_store::get_thought_signature;
use crate::proxy::mappers::tool_result_compressor;
use crate::proxy::session_manager::SessionManager;
use serde_json::{json, Value};
use std::collections::HashMap;
#[path = "request_generation.rs"]
mod generation;
#[path = "request_preprocess.rs"]
mod preprocess;
#[path = "request_thinking.rs"]
mod thinking;

fn build_safety_settings() -> Value {
    generation::build_safety_settings()
}
pub fn clean_cache_control_from_messages(messages: &mut [Message]) {
    preprocess::clean_cache_control_from_messages(messages);
}

fn sort_thinking_blocks_first(messages: &mut [Message]) {
    preprocess::sort_thinking_blocks_first(messages);
}

pub fn merge_consecutive_messages(messages: &mut Vec<Message>) {
    preprocess::merge_consecutive_messages(messages);
}

fn reorder_gemini_parts(parts: &mut Vec<Value>) {
    preprocess::reorder_gemini_parts(parts);
}

pub fn transform_claude_request_in(
    claude_req: &ClaudeRequest,
    project_id: &str,
    is_retry: bool,
) -> Result<Value, String> {
    let mut cleaned_req = claude_req.clone();
    merge_consecutive_messages(&mut cleaned_req.messages);

    clean_cache_control_from_messages(&mut cleaned_req.messages);
    sort_thinking_blocks_first(&mut cleaned_req.messages);

    let claude_req = &cleaned_req;
    let session_id = SessionManager::extract_session_id(claude_req);
    tracing::debug!("[Claude-Request] Session ID: {}", session_id);
    let has_web_search_tool = claude_req
        .tools
        .as_ref()
        .map(|tools| {
            tools.iter().any(|t| {
                t.is_web_search()
                    || t.name.as_deref() == Some("google_search")
                    || t.type_.as_deref() == Some("web_search_20250305")
            })
        })
        .unwrap_or(false);
    let mut tool_id_to_name: HashMap<String, String> = HashMap::new();
    let has_mcp_tools = claude_req
        .tools
        .as_ref()
        .map(|tools| {
            tools.iter().any(|t| {
                t.name
                    .as_deref()
                    .map(|n| n.starts_with("mcp__"))
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false);
    let mut tool_name_to_schema = HashMap::new();
    if let Some(tools) = &claude_req.tools {
        for tool in tools {
            if let (Some(name), Some(schema)) = (&tool.name, &tool.input_schema) {
                tool_name_to_schema.insert(name.clone(), schema.clone());
            }
        }
    }
    let system_instruction =
        build_system_instruction(&claude_req.system, &claude_req.model, has_mcp_tools);
    let web_search_fallback_model =
        crate::proxy::common::model_mapping::web_search_fallback_model();

    let mapped_model = if has_web_search_tool {
        tracing::debug!(
            "[Claude-Request] Web search tool detected, using fallback model: {}",
            web_search_fallback_model
        );
        web_search_fallback_model.to_string()
    } else {
        crate::proxy::common::model_mapping::map_claude_model_to_gemini(&claude_req.model)
    };
    let tools_val: Option<Vec<Value>> = claude_req.tools.as_ref().map(|list| {
        list.iter()
            .map(|t| serde_json::to_value(t).unwrap_or(json!({})))
            .collect()
    });
    let config = crate::proxy::mappers::common_utils::resolve_request_config(
        &claude_req.model,
        &mapped_model,
        &tools_val,
        claude_req.size.as_deref(),
        claude_req.quality.as_deref(),
        None,
    );
    let allow_dummy_thought = false;
    let mut is_thinking_enabled = claude_req
        .thinking
        .as_ref()
        .map(|t| t.type_ == "enabled")
        .unwrap_or_else(|| should_enable_thinking_by_default(&claude_req.model));
    let target_model_supports_thinking =
        crate::proxy::common::model_mapping::model_supports_thinking(&mapped_model);

    if is_thinking_enabled && !target_model_supports_thinking {
        tracing::warn!(
            "[Thinking-Mode] Target model '{}' does not support thinking. Force disabling thinking mode.",
            mapped_model
        );
        is_thinking_enabled = false;
    }
    if is_thinking_enabled {
        let should_disable = should_disable_thinking_due_to_history(&claude_req.messages);
        if should_disable {
            tracing::warn!("[Thinking-Mode] Automatically disabling thinking checks due to incompatible tool-use history (mixed application)");
            is_thinking_enabled = false;
        }
    }
    if is_thinking_enabled {
        let global_sig = get_thought_signature();
        let has_thinking_history = claude_req.messages.iter().any(|m| {
            if m.role == "assistant" {
                if let MessageContent::Array(blocks) = &m.content {
                    return blocks
                        .iter()
                        .any(|b| matches!(b, ContentBlock::Thinking { .. }));
                }
            }
            false
        });
        let has_function_calls = claude_req.messages.iter().any(|m| {
            if let MessageContent::Array(blocks) = &m.content {
                blocks
                    .iter()
                    .any(|b| matches!(b, ContentBlock::ToolUse { .. }))
            } else {
                false
            }
        });
        let needs_signature_check = has_function_calls;

        if !has_thinking_history && is_thinking_enabled {
            tracing::info!(
                "[Thinking-Mode] First thinking request detected. Using permissive mode - \
                 signature validation will be handled by upstream API."
            );
        }

        if needs_signature_check
            && !has_valid_signature_for_function_calls(
                &claude_req.messages,
                &global_sig,
                &session_id,
            )
        {
            tracing::warn!(
                "[Thinking-Mode] No valid signature found for function calls. \
                 Disabling thinking to prevent Gemini 3 Pro rejection."
            );
            is_thinking_enabled = false;
        }
    }
    let generation_config = build_generation_config(
        claude_req,
        &mapped_model,
        has_web_search_tool,
        is_thinking_enabled,
    );
    let contents = build_google_contents(
        &claude_req.messages,
        &mut tool_id_to_name,
        &tool_name_to_schema,
        GoogleContentsOptions {
            is_thinking_enabled,
            allow_dummy_thought,
            mapped_model: &mapped_model,
            session_id: &session_id,
            is_retry,
        },
    )?;
    let tools = build_tools(&claude_req.tools, has_web_search_tool)?;
    let safety_settings = build_safety_settings();
    let mut inner_request = json!({
        "contents": contents,
        "safetySettings": safety_settings,
    });
    crate::proxy::mappers::common_utils::deep_clean_undefined(&mut inner_request);

    if let Some(sys_inst) = system_instruction {
        inner_request["systemInstruction"] = sys_inst;
    }

    if !generation_config.is_null() {
        inner_request["generationConfig"] = generation_config;
    }

    if let Some(tools_val) = tools {
        inner_request["tools"] = tools_val;
        inner_request["toolConfig"] = json!({
            "functionCallingConfig": {
                "mode": "VALIDATED"
            }
        });
    }
    if config.inject_google_search && !has_web_search_tool {
        crate::proxy::mappers::common_utils::inject_google_search_tool(&mut inner_request);
    }
    if let Some(image_config) = config.image_config {
        if let Some(obj) = inner_request.as_object_mut() {
            obj.remove("tools");
            obj.remove("systemInstruction");
            let gen_config = obj.entry("generationConfig").or_insert_with(|| json!({}));
            if let Some(gen_obj) = gen_config.as_object_mut() {
                gen_obj.remove("responseMimeType");
                gen_obj.remove("responseModalities");
                gen_obj.insert("imageConfig".to_string(), image_config);
            }
        }
    }
    let request_id = format!("agent-{}", uuid::Uuid::new_v4());
    let mut body = json!({
        "project": project_id,
        "requestId": request_id,
        "request": inner_request,
        "model": config.final_model,
        "userAgent": "antigravity",
        "requestType": config.request_type,
    });
    if let Some(metadata) = &claude_req.metadata {
        if let Some(user_id) = &metadata.user_id {
            body["request"]["sessionId"] = json!(user_id);
        }
    }
    preprocess::deep_clean_cache_control(&mut body);
    tracing::debug!("[DEBUG-593] Final deep clean complete, request ready to send");

    Ok(body)
}
fn should_disable_thinking_due_to_history(messages: &[Message]) -> bool {
    thinking::should_disable_thinking_due_to_history(messages)
}
fn should_enable_thinking_by_default(model: &str) -> bool {
    thinking::should_enable_thinking_by_default(model)
}
const MIN_SIGNATURE_LENGTH: usize = thinking::MIN_SIGNATURE_LENGTH;
fn has_valid_signature_for_function_calls(
    messages: &[Message],
    global_sig: &Option<String>,
    session_id: &str,
) -> bool {
    thinking::has_valid_signature_for_function_calls(messages, global_sig, session_id)
}
fn build_system_instruction(
    system: &Option<SystemPrompt>,
    _model_name: &str,
    has_mcp_tools: bool,
) -> Option<Value> {
    thinking::build_system_instruction(system, has_mcp_tools)
}
struct BuildContentsContext<'a> {
    is_thinking_enabled: bool,
    session_id: &'a str,
    allow_dummy_thought: bool,
    is_retry: bool,
    tool_name_to_schema: &'a HashMap<String, Value>,
    mapped_model: &'a str,
    existing_tool_result_ids: &'a std::collections::HashSet<String>,
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
    let mut current_turn_tool_result_ids = std::collections::HashSet::new();
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
                            if sig.len() < MIN_SIGNATURE_LENGTH {
                                tracing::warn!(
                                    "[Thinking-Signature] Signature too short (len: {} < {}), downgrading to text.",
                                    sig.len(), MIN_SIGNATURE_LENGTH
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
                                            if ctx.is_retry { "Stripping historical" } else { "Incompatible" },
                                            family, ctx.mapped_model
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
                                    if sig.len() >= MIN_SIGNATURE_LENGTH {
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
                        let final_sig = signature.as_ref()
                            .or(state.last_thought_signature.as_ref())
                            .cloned()
                            .or_else(|| {
                                crate::proxy::SignatureCache::global().get_session_signature(ctx.session_id)
                                    .inspect(|s| {
                                        tracing::info!(
                                            "[Claude-Request] Recovered signature from SESSION cache (session: {}, len: {})",
                                            ctx.session_id, s.len()
                                        );
                                    })
                            })
                            .or_else(|| {
                                crate::proxy::SignatureCache::global().get_tool_signature(id)
                                    .inspect(|_s| {
                                        tracing::info!("[Claude-Request] Recovered signature from TOOL cache for tool_id: {}", id);
                                    })
                            })
                            .or_else(|| {
                                let global_sig = get_thought_signature();
                                if let Some(sig) = &global_sig {
                                    tracing::warn!(
                                        "[Claude-Request] Using deprecated GLOBAL thought_signature fallback (length: {}). \
                                         This indicates session cache miss.",
                                        sig.len()
                                    );
                                }
                                global_sig
                            });
                        if let Some(sig) = final_sig {
                            if ctx.is_retry && signature.is_none() {
                                tracing::warn!("[Tool-Signature] Skipping signature backfill for tool_use: {} during retry.", id);
                            } else if sig.len() < MIN_SIGNATURE_LENGTH {
                                tracing::warn!(
                                    "[Tool-Signature] Signature too short for tool_use: {} (len: {} < {}), skipping.",
                                    id, sig.len(), MIN_SIGNATURE_LENGTH
                                );
                            } else {
                                let cached_family = crate::proxy::SignatureCache::global()
                                    .get_signature_family(&sig);

                                let should_use_sig = match cached_family {
                                    Some(family) => {
                                        if is_model_compatible(&family, ctx.mapped_model) {
                                            true
                                        } else {
                                            tracing::warn!(
                                                "[Tool-Signature] Incompatible signature for tool_use: {} (Family: {}, Target: {})",
                                                id, family, ctx.mapped_model
                                            );
                                            false
                                        }
                                    }
                                    None => {
                                        if sig.len() >= MIN_SIGNATURE_LENGTH {
                                            tracing::debug!(
                                                "[Tool-Signature] Unknown signature origin but valid length (len: {}) for tool_use: {}, using as-is for JSON tool calling.",
                                                sig.len(), id
                                            );
                                            true
                                        } else if ctx.is_thinking_enabled {
                                            tracing::warn!(
                                                "[Tool-Signature] Unknown signature origin and too short for tool_use: {} (len: {}). Dropping in thinking mode.",
                                                id, sig.len()
                                            );
                                            false
                                        } else {
                                            true
                                        }
                                    }
                                };
                                if should_use_sig {
                                    part["thoughtSignature"] = json!(sig);
                                }
                            }
                        } else {
                            let is_google_cloud = ctx.mapped_model.starts_with("projects/");
                            if ctx.is_thinking_enabled && !is_google_cloud {
                                tracing::debug!("[Tool-Signature] Adding GEMINI_SKIP_SIGNATURE for tool_use: {}", id);
                                part["thoughtSignature"] =
                                    json!("skip_thought_signature_validator");
                            }
                        }
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
                        let mut compacted_content = content.clone();
                        if let Some(blocks) = compacted_content.as_array_mut() {
                            tool_result_compressor::sanitize_tool_result_blocks(blocks);
                        }
                        let mut merged_content = match &compacted_content {
                            serde_json::Value::String(s) => s.clone(),
                            serde_json::Value::Array(arr) => arr
                                .iter()
                                .filter_map(|block| {
                                    if let Some(text) = block.get("text").and_then(|v| v.as_str()) {
                                        Some(text.to_string())
                                    } else if block.get("source").is_some() {
                                        if block.get("type").and_then(|v| v.as_str())
                                            == Some("image")
                                        {
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
                        const MAX_TOOL_RESULT_CHARS: usize = 200_000;
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
                            if is_error.unwrap_or(false) {
                                merged_content =
                                    "Tool execution failed with no output.".to_string();
                            } else {
                                merged_content = "Command executed successfully.".to_string();
                            }
                        }

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
struct GoogleContentsOptions<'a> {
    is_thinking_enabled: bool,
    allow_dummy_thought: bool,
    mapped_model: &'a str,
    session_id: &'a str,
    is_retry: bool,
}

fn build_google_contents(
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
    let mut existing_tool_result_ids = std::collections::HashSet::new();
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

    for msg in messages.iter() {
        let google_content = build_google_content(msg, &build_ctx, &mut build_state)?;

        if !google_content.is_null() {
            contents.push(google_content);
        }
    }
    let mut merged_contents = merge_adjacent_roles(contents);
    if !options.is_thinking_enabled {
        for msg in &mut merged_contents {
            clean_thinking_fields_recursive(msg);
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
                    reorder_gemini_parts(current_parts);
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
fn build_tools(tools: &Option<Vec<Tool>>, has_web_search: bool) -> Result<Option<Value>, String> {
    generation::build_tools(tools, has_web_search)
}
fn build_generation_config(
    claude_req: &ClaudeRequest,
    mapped_model: &str,
    has_web_search: bool,
    is_thinking_enabled: bool,
) -> Value {
    generation::build_generation_config(
        claude_req,
        mapped_model,
        has_web_search,
        is_thinking_enabled,
    )
}
pub fn clean_thinking_fields_recursive(val: &mut Value) {
    generation::clean_thinking_fields_recursive(val);
}
fn is_model_compatible(cached: &str, target: &str) -> bool {
    crate::proxy::common::model_mapping::is_signature_family_compatible(cached, target)
}

#[cfg(test)]
#[path = "request_tests.rs"]
mod tests;
