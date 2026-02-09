use super::models::*;
use crate::proxy::mappers::signature_store::get_thought_signature;
use crate::proxy::mappers::tool_result_compressor;
use crate::proxy::session_manager::SessionManager;
use serde_json::{json, Value};
use std::collections::HashMap;
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SafetyThreshold {
    Off,
    BlockLowAndAbove,
    BlockMediumAndAbove,
    BlockOnlyHigh,
    BlockNone,
}

impl SafetyThreshold {
    pub fn from_env() -> Self {
        match std::env::var("GEMINI_SAFETY_THRESHOLD").as_deref() {
            Ok("OFF") | Ok("off") => SafetyThreshold::Off,
            Ok("LOW") | Ok("low") => SafetyThreshold::BlockLowAndAbove,
            Ok("MEDIUM") | Ok("medium") => SafetyThreshold::BlockMediumAndAbove,
            Ok("HIGH") | Ok("high") => SafetyThreshold::BlockOnlyHigh,
            Ok("NONE") | Ok("none") => SafetyThreshold::BlockNone,
            _ => SafetyThreshold::Off,
        }
    }
    pub fn to_gemini_threshold(self) -> &'static str {
        match self {
            SafetyThreshold::Off => "OFF",
            SafetyThreshold::BlockLowAndAbove => "BLOCK_LOW_AND_ABOVE",
            SafetyThreshold::BlockMediumAndAbove => "BLOCK_MEDIUM_AND_ABOVE",
            SafetyThreshold::BlockOnlyHigh => "BLOCK_ONLY_HIGH",
            SafetyThreshold::BlockNone => "BLOCK_NONE",
        }
    }
}
fn build_safety_settings() -> Value {
    let threshold = SafetyThreshold::from_env();
    let threshold_str = threshold.to_gemini_threshold();

    json!([
        { "category": "HARM_CATEGORY_HARASSMENT", "threshold": threshold_str },
        { "category": "HARM_CATEGORY_HATE_SPEECH", "threshold": threshold_str },
        { "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": threshold_str },
        { "category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": threshold_str },
        { "category": "HARM_CATEGORY_CIVIC_INTEGRITY", "threshold": threshold_str },
    ])
}
pub fn clean_cache_control_from_messages(messages: &mut [Message]) {
    tracing::info!(
        "[DEBUG-593] Starting cache_control cleanup for {} messages",
        messages.len()
    );

    let mut total_cleaned = 0;

    for (idx, msg) in messages.iter_mut().enumerate() {
        if let MessageContent::Array(blocks) = &mut msg.content {
            for (block_idx, block) in blocks.iter_mut().enumerate() {
                match block {
                    ContentBlock::Thinking { cache_control, .. } => {
                        if cache_control.is_some() {
                            tracing::info!(
                                " Found cache_control in Thinking block at message[{}].content[{}]: {:?}",
                                idx,
                                block_idx,
                                cache_control
                            );
                            *cache_control = None;
                            total_cleaned += 1;
                        }
                    }
                    ContentBlock::Image { cache_control, .. } => {
                        if cache_control.is_some() {
                            tracing::debug!(
                                "[Cache-Control-Cleaner] Removed cache_control from Image block at message[{}].content[{}]",
                                idx,
                                block_idx
                            );
                            *cache_control = None;
                            total_cleaned += 1;
                        }
                    }
                    ContentBlock::Document { cache_control, .. } => {
                        if cache_control.is_some() {
                            tracing::debug!(
                                "[Cache-Control-Cleaner] Removed cache_control from Document block at message[{}].content[{}]",
                                idx,
                                block_idx
                            );
                            *cache_control = None;
                            total_cleaned += 1;
                        }
                    }
                    ContentBlock::ToolUse { cache_control, .. } => {
                        if cache_control.is_some() {
                            tracing::debug!(
                                "[Cache-Control-Cleaner] Removed cache_control from ToolUse block at message[{}].content[{}]",
                                idx,
                                block_idx
                            );
                            *cache_control = None;
                            total_cleaned += 1;
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    if total_cleaned > 0 {
        tracing::info!(
            "[DEBUG-593] Cache control cleanup complete: removed {} cache_control fields",
            total_cleaned
        );
    } else {
        tracing::debug!("[DEBUG-593] No cache_control fields found");
    }
}
fn deep_clean_cache_control(value: &mut Value) {
    match value {
        Value::Object(map) => {
            if map.remove("cache_control").is_some() {
                tracing::debug!("[DEBUG-593] Removed cache_control from nested JSON object");
            }
            for (_, v) in map.iter_mut() {
                deep_clean_cache_control(v);
            }
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                deep_clean_cache_control(item);
            }
        }
        _ => {}
    }
}
fn sort_thinking_blocks_first(messages: &mut [Message]) {
    for msg in messages.iter_mut() {
        if msg.role == "assistant" {
            if let MessageContent::Array(blocks) = &mut msg.content {
                let mut thinking_blocks: Vec<ContentBlock> = Vec::new();
                let mut text_blocks: Vec<ContentBlock> = Vec::new();
                let mut tool_blocks: Vec<ContentBlock> = Vec::new();
                let mut other_blocks: Vec<ContentBlock> = Vec::new();

                let original_len = blocks.len();
                let mut needs_reorder = false;
                let mut saw_non_thinking = false;

                for block in blocks.iter() {
                    match block {
                        ContentBlock::Thinking { .. } | ContentBlock::RedactedThinking { .. } => {
                            if saw_non_thinking {
                                needs_reorder = true;
                            }
                        }
                        ContentBlock::Text { .. } => {
                            saw_non_thinking = true;
                        }
                        ContentBlock::ToolUse { .. } => {
                            saw_non_thinking = true;
                        }
                        _ => saw_non_thinking = true,
                    }
                }

                if needs_reorder || original_len > 1 {
                    for block in blocks.drain(..) {
                        match &block {
                            ContentBlock::Thinking { .. }
                            | ContentBlock::RedactedThinking { .. } => {
                                thinking_blocks.push(block);
                            }
                            ContentBlock::Text { text } => {
                                if !text.trim().is_empty() && text != "(no content)" {
                                    text_blocks.push(block);
                                }
                            }
                            ContentBlock::ToolUse { .. } => {
                                tool_blocks.push(block);
                            }
                            _ => {
                                other_blocks.push(block);
                            }
                        }
                    }
                    blocks.extend(thinking_blocks);
                    blocks.extend(text_blocks);
                    blocks.extend(other_blocks);
                    blocks.extend(tool_blocks);

                    if needs_reorder {
                        tracing::warn!(
                            "Reordered assistant messages to [Thinking, Text, Tool] structure."
                        );
                    }
                }
            }
        }
    }
}
pub fn merge_consecutive_messages(messages: &mut Vec<Message>) {
    if messages.len() <= 1 {
        return;
    }

    let mut merged: Vec<Message> = Vec::with_capacity(messages.len());
    let old_messages = std::mem::take(messages);
    let mut messages_iter = old_messages.into_iter();

    if let Some(mut current) = messages_iter.next() {
        for next in messages_iter {
            if current.role == next.role {
                match (&mut current.content, next.content) {
                    (MessageContent::Array(current_blocks), MessageContent::Array(next_blocks)) => {
                        current_blocks.extend(next_blocks);
                    }
                    (MessageContent::Array(current_blocks), MessageContent::String(next_text)) => {
                        current_blocks.push(ContentBlock::Text { text: next_text });
                    }
                    (MessageContent::String(current_text), MessageContent::String(next_text)) => {
                        *current_text = format!("{}\n\n{}", current_text, next_text);
                    }
                    (MessageContent::String(current_text), MessageContent::Array(next_blocks)) => {
                        let mut new_blocks = vec![ContentBlock::Text {
                            text: current_text.clone(),
                        }];
                        new_blocks.extend(next_blocks);
                        current.content = MessageContent::Array(new_blocks);
                    }
                }
            } else {
                merged.push(current);
                current = next;
            }
        }
        merged.push(current);
    }

    *messages = merged;
}
fn reorder_gemini_parts(parts: &mut Vec<Value>) {
    if parts.len() <= 1 {
        return;
    }

    let mut thinking_parts = Vec::new();
    let mut text_parts = Vec::new();
    let mut tool_parts = Vec::new();
    let mut other_parts = Vec::new();

    for part in parts.drain(..) {
        if part.get("thought").and_then(|t| t.as_bool()) == Some(true) {
            thinking_parts.push(part);
        } else if part.get("functionCall").is_some() {
            tool_parts.push(part);
        } else if let Some(text) = part.get("text").and_then(|t| t.as_str()) {
            if !text.trim().is_empty() && text != "(no content)" {
                text_parts.push(part);
            }
        } else {
            other_parts.push(part);
        }
    }

    parts.extend(thinking_parts);
    parts.extend(text_parts);
    parts.extend(other_parts);
    parts.extend(tool_parts);
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
    deep_clean_cache_control(&mut body);
    tracing::debug!("[DEBUG-593] Final deep clean complete, request ready to send");

    Ok(body)
}
fn should_disable_thinking_due_to_history(messages: &[Message]) -> bool {
    for msg in messages.iter().rev() {
        if msg.role == "assistant" {
            if let MessageContent::Array(blocks) = &msg.content {
                let has_tool_use = blocks
                    .iter()
                    .any(|b| matches!(b, ContentBlock::ToolUse { .. }));
                let has_thinking = blocks
                    .iter()
                    .any(|b| matches!(b, ContentBlock::Thinking { .. }));
                if has_tool_use && !has_thinking {
                    tracing::info!("[Thinking-Mode] Detected ToolUse without Thinking in history. Requesting disable.");
                    return true;
                }
            }
            return false;
        }
    }
    false
}
fn should_enable_thinking_by_default(model: &str) -> bool {
    let should_enable = crate::proxy::common::model_mapping::should_auto_enable_thinking(model);
    if should_enable {
        tracing::debug!(
            "[Thinking-Mode] Auto-enabling thinking for model: {}",
            model
        );
    }
    should_enable
}
const MIN_SIGNATURE_LENGTH: usize = 50;
fn has_valid_signature_for_function_calls(
    messages: &[Message],
    global_sig: &Option<String>,
    session_id: &str,
) -> bool {
    if let Some(sig) = global_sig {
        if sig.len() >= MIN_SIGNATURE_LENGTH {
            tracing::debug!(
                "[Signature-Check] Found valid signature in global store (len: {})",
                sig.len()
            );
            return true;
        }
    }
    if let Some(sig) = crate::proxy::SignatureCache::global().get_session_signature(session_id) {
        if sig.len() >= MIN_SIGNATURE_LENGTH {
            tracing::info!(
                "[Signature-Check] Found valid signature in SESSION cache (session: {}, len: {})",
                session_id,
                sig.len()
            );
            return true;
        }
    }
    for msg in messages.iter().rev() {
        if msg.role == "assistant" {
            if let MessageContent::Array(blocks) = &msg.content {
                for block in blocks {
                    if let ContentBlock::Thinking {
                        signature: Some(sig),
                        ..
                    } = block
                    {
                        if sig.len() >= MIN_SIGNATURE_LENGTH {
                            tracing::debug!(
                                "[Signature-Check] Found valid signature in message history (len: {})",
                                sig.len()
                            );
                            return true;
                        }
                    }
                }
            }
        }
    }

    tracing::warn!(
        "[Signature-Check] No valid signature found (session: {}, checked: global store, session cache, message history)",
        session_id
    );
    false
}
fn build_system_instruction(
    system: &Option<SystemPrompt>,
    _model_name: &str,
    has_mcp_tools: bool,
) -> Option<Value> {
    let mut parts = Vec::new();
    let antigravity_identity = "You are Antigravity, a powerful agentic AI coding assistant designed by the Google Deepmind team working on Advanced Agentic Coding.\n\
    You are pair programming with a USER to solve their coding task. The task may require creating a new codebase, modifying or debugging an existing codebase, or simply answering a question.\n\
    **Absolute paths only**\n\
    **Proactiveness**";
    let mut user_has_antigravity = false;
    if let Some(sys) = system {
        match sys {
            SystemPrompt::String(text) => {
                if text.contains("You are Antigravity") {
                    user_has_antigravity = true;
                }
            }
            SystemPrompt::Array(blocks) => {
                for block in blocks {
                    if block.block_type == "text" && block.text.contains("You are Antigravity") {
                        user_has_antigravity = true;
                        break;
                    }
                }
            }
        }
    }
    if !user_has_antigravity {
        parts.push(json!({"text": antigravity_identity}));
    }
    if let Some(sys) = system {
        match sys {
            SystemPrompt::String(text) => {
                parts.push(json!({"text": text}));
            }
            SystemPrompt::Array(blocks) => {
                for block in blocks {
                    if block.block_type == "text" {
                        parts.push(json!({"text": block.text}));
                    }
                }
            }
        }
    }
    if has_mcp_tools {
        let mcp_xml_prompt = "\n\
        ==== MCP XML Tool Calling Protocol (Workaround) ====\n\
        When you need to call an MCP tool with a name starting with `mcp__`:\n\
        1) Try XML format calling first: output `<mcp__tool_name>{\"arg\":\"value\"}</mcp__tool_name>`.\n\
        2) You must directly output the XML block without markdown wrapping, and the content should be JSON formatted input parameters.\n\
        3) This method has higher connectivity and fault tolerance, suitable for large result return scenarios.\n\
        ===========================================";
        parts.push(json!({"text": mcp_xml_prompt}));
    }
    if !user_has_antigravity {
        parts.push(json!({"text": "\n--- [SYSTEM_PROMPT_END] ---"}));
    }

    Some(json!({
        "role": "user",
        "parts": parts
    }))
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
                                    let compatible =
                                        !ctx.is_retry
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
                let name = state
                    .tool_id_to_name
                    .get(id)
                    .cloned()
                    .unwrap_or(id.clone());
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

    let parts = build_contents(
        &msg.content,
        msg.role == "assistant",
        ctx,
        state,
    )?;

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
    if let Some(tools_list) = tools {
        let mut function_declarations: Vec<Value> = Vec::new();
        let mut has_google_search = has_web_search;

        for tool in tools_list {
            if tool.is_web_search() {
                has_google_search = true;
                continue;
            }

            if let Some(t_type) = &tool.type_ {
                if t_type == "web_search_20250305" {
                    has_google_search = true;
                    continue;
                }
            }
            if let Some(name) = &tool.name {
                if name == "web_search" || name == "google_search" {
                    has_google_search = true;
                    continue;
                }
                let mut input_schema = tool.input_schema.clone().unwrap_or(json!({
                    "type": "object",
                    "properties": {}
                }));
                crate::proxy::common::json_schema::clean_json_schema(&mut input_schema);

                function_declarations.push(json!({
                    "name": name,
                    "description": tool.description,
                    "parameters": input_schema
                }));
            }
        }

        let mut tool_obj = serde_json::Map::new();
        if !function_declarations.is_empty() {
            tool_obj.insert(
                "functionDeclarations".to_string(),
                json!(function_declarations),
            );
            if has_google_search {
                tracing::info!(
                    "[Claude-Request] Skipping googleSearch injection due to {} existing function declarations. \
                     Gemini v1internal does not support mixed tool types.",
                    function_declarations.len()
                );
            }
        } else if has_google_search {
            tool_obj.insert("googleSearch".to_string(), json!({}));
        }

        if !tool_obj.is_empty() {
            return Ok(Some(json!([tool_obj])));
        }
    }

    Ok(None)
}
fn build_generation_config(
    claude_req: &ClaudeRequest,
    mapped_model: &str,
    has_web_search: bool,
    is_thinking_enabled: bool,
) -> Value {
    let mut config = json!({});
    if is_thinking_enabled {
        let mut thinking_config = json!({"includeThoughts": true});
        let budget_tokens = claude_req
            .thinking
            .as_ref()
            .and_then(|t| t.budget_tokens)
            .unwrap_or(16000);

        let tb_config = crate::proxy::config::get_thinking_budget_config();
        let budget = match tb_config.mode {
            crate::proxy::config::ThinkingBudgetMode::Passthrough => budget_tokens,
            crate::proxy::config::ThinkingBudgetMode::Custom => {
                let mut custom_value = tb_config.custom_value;
                let model_lower = mapped_model.to_lowercase();
                let is_gemini_limited = has_web_search
                    || model_lower.contains("gemini")
                    || model_lower.contains("flash")
                    || model_lower.ends_with("-thinking");

                if is_gemini_limited && custom_value > 24576 {
                    tracing::warn!(
                        "[Claude-Request] Custom mode: capping thinking_budget from {} to 24576 for Gemini model {}",
                        custom_value, mapped_model
                    );
                    custom_value = 24576;
                }
                custom_value
            }
            crate::proxy::config::ThinkingBudgetMode::Auto => {
                let model_lower = mapped_model.to_lowercase();
                let is_gemini_limited = has_web_search
                    || model_lower.contains("gemini")
                    || model_lower.contains("flash")
                    || model_lower.ends_with("-thinking");
                if is_gemini_limited && budget_tokens > 24576 {
                    tracing::info!(
                        "[Claude-Request] Auto mode: capping thinking_budget from {} to 24576 for Gemini model {}",
                        budget_tokens, mapped_model
                    );
                    24576
                } else {
                    budget_tokens
                }
            }
        };
        thinking_config["thinkingBudget"] = json!(budget);
        config["thinkingConfig"] = thinking_config;
    }
    if let Some(temp) = claude_req.temperature {
        config["temperature"] = json!(temp);
    }
    if let Some(top_p) = claude_req.top_p {
        config["topP"] = json!(top_p);
    }
    if let Some(top_k) = claude_req.top_k {
        config["topK"] = json!(top_k);
    }
    if let Some(output_config) = &claude_req.output_config {
        if let Some(effort) = &output_config.effort {
            config["effortLevel"] = json!(match effort.to_lowercase().as_str() {
                "high" => "HIGH",
                "medium" => "MEDIUM",
                "low" => "LOW",
                _ => "HIGH",
            });
            tracing::debug!(
                "[Generation-Config] Effort level set: {} -> {}",
                effort,
                config["effortLevel"]
            );
        }
    }
    let mut final_max_tokens: Option<i64> = claude_req.max_tokens.map(|t| t as i64);
    if let Some(thinking_config) = config.get("thinkingConfig") {
        if let Some(budget) = thinking_config
            .get("thinkingBudget")
            .and_then(|t| t.as_u64())
        {
            let current = final_max_tokens.unwrap_or(0);
            if current <= budget as i64 {
                final_max_tokens = Some((budget + 8192) as i64);
                tracing::info!(
                    "[Generation-Config] Bumping maxOutputTokens to {} due to thinking budget of {}",
                    final_max_tokens.unwrap(), budget
                );
            }
        }
    }

    if let Some(val) = final_max_tokens {
        config["maxOutputTokens"] = json!(val);
    }
    config["stopSequences"] = json!(["<|user|>", "<|end_of_turn|>", "\n\nHuman:"]);

    config
}
pub fn clean_thinking_fields_recursive(val: &mut Value) {
    match val {
        Value::Object(map) => {
            map.remove("thought");
            map.remove("thoughtSignature");
            for (_, v) in map.iter_mut() {
                clean_thinking_fields_recursive(v);
            }
        }
        Value::Array(arr) => {
            for v in arr.iter_mut() {
                clean_thinking_fields_recursive(v);
            }
        }
        _ => {}
    }
}
fn is_model_compatible(cached: &str, target: &str) -> bool {
    crate::proxy::common::model_mapping::is_signature_family_compatible(cached, target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::common::json_schema::clean_json_schema;
    use crate::proxy::common::model_mapping::{
        MODEL_CLAUDE_SONNET_45, MODEL_GEMINI_3_FLASH_THINKING, MODEL_GEMINI_3_PRO,
        MODEL_GEMINI_3_PRO_PREVIEW,
    };

    #[test]
    fn test_ephemeral_injection_debug() {
        let json_with_null = json!({
            "model": MODEL_CLAUDE_SONNET_45,
            "messages": [
                {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "thinking",
                            "thinking": "test",
                            "signature": "sig_1234567890",
                            "cache_control": null
                        }
                    ]
                }
            ]
        });

        let req: ClaudeRequest = serde_json::from_value(json_with_null).unwrap();
        if let MessageContent::Array(blocks) = &req.messages[0].content {
            if let ContentBlock::Thinking { cache_control, .. } = &blocks[0] {
                assert!(
                    cache_control.is_none(),
                    "Deserialization should result in None for null cache_control"
                );
            }
        }
        let serialized = serde_json::to_value(&req).unwrap();
        println!("Serialized: {}", serialized);
        assert!(serialized["messages"][0]["content"][0]
            .get("cache_control")
            .is_none());
    }

    #[test]
    fn test_simple_request() {
        let req = ClaudeRequest {
            model: MODEL_CLAUDE_SONNET_45.to_string(),
            messages: vec![Message {
                role: "user".to_string(),
                content: MessageContent::String("Hello".to_string()),
            }],
            system: None,
            tools: None,
            stream: false,
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            thinking: None,
            metadata: None,
            output_config: None,
            size: None,
            quality: None,
        };

        let result = transform_claude_request_in(&req, "test-project", false);
        assert!(result.is_ok());

        let body = result.unwrap();
        assert_eq!(body["project"], "test-project");
        assert!(body["requestId"].as_str().unwrap().starts_with("agent-"));
    }

    #[test]
    fn test_clean_json_schema() {
        let mut schema = json!({
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "location": {
                    "type": "string",
                    "description": "The city and state, e.g. San Francisco, CA",
                    "minLength": 1,
                    "exclusiveMinimum": 0
                },
                "unit": {
                    "type": ["string", "null"],
                    "enum": ["celsius", "fahrenheit"],
                    "default": "celsius"
                },
                "date": {
                    "type": "string",
                    "format": "date"
                }
            },
            "required": ["location"]
        });

        clean_json_schema(&mut schema);
        assert!(schema.get("$schema").is_none());
        assert!(schema.get("additionalProperties").is_none());
        assert!(schema["properties"]["location"].get("minLength").is_none());
        assert!(schema["properties"]["unit"].get("default").is_none());
        assert!(schema["properties"]["date"].get("format").is_none());
        assert_eq!(schema["properties"]["unit"]["type"], "string");
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["properties"]["location"]["type"], "string");
        assert_eq!(schema["properties"]["date"]["type"], "string");
    }

    #[test]
    fn test_complex_tool_result() {
        let req = ClaudeRequest {
            model: MODEL_CLAUDE_SONNET_45.to_string(),
            messages: vec![
                Message {
                    role: "user".to_string(),
                    content: MessageContent::String("Run command".to_string()),
                },
                Message {
                    role: "assistant".to_string(),
                    content: MessageContent::Array(vec![ContentBlock::ToolUse {
                        id: "call_1".to_string(),
                        name: "run_command".to_string(),
                        input: json!({"command": "ls"}),
                        signature: None,
                        cache_control: None,
                    }]),
                },
                Message {
                    role: "user".to_string(),
                    content: MessageContent::Array(vec![ContentBlock::ToolResult {
                        tool_use_id: "call_1".to_string(),
                        content: json!([
                            {"type": "text", "text": "file1.txt\n"},
                            {"type": "text", "text": "file2.txt"}
                        ]),
                        is_error: Some(false),
                    }]),
                },
            ],
            system: None,
            tools: None,
            stream: false,
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            thinking: None,
            metadata: None,
            output_config: None,
            size: None,
            quality: None,
        };

        let result = transform_claude_request_in(&req, "test-project", false);
        assert!(result.is_ok());

        let body = result.unwrap();
        let contents = body["request"]["contents"].as_array().unwrap();
        let tool_resp_msg = &contents[2];
        let parts = tool_resp_msg["parts"].as_array().unwrap();
        let func_resp = &parts[0]["functionResponse"];

        assert_eq!(func_resp["name"], "run_command");
        assert_eq!(func_resp["id"], "call_1");
        let resp_text = func_resp["response"]["result"].as_str().unwrap();
        assert!(resp_text.contains("file1.txt"));
        assert!(resp_text.contains("file2.txt"));
        assert!(resp_text.contains("\n"));
    }

    #[test]
    fn test_cache_control_cleanup() {
        let req = ClaudeRequest {
            model: MODEL_CLAUDE_SONNET_45.to_string(),
            messages: vec![
                Message {
                    role: "user".to_string(),
                    content: MessageContent::String("Hello".to_string()),
                },
                Message {
                    role: "assistant".to_string(),
                    content: MessageContent::Array(vec![
                        ContentBlock::Thinking {
                            thinking: "Let me think...".to_string(),
                            signature: Some("sig123".to_string()),
                            cache_control: Some(json!({"type": "ephemeral"})),
                        },
                        ContentBlock::Text {
                            text: "Here is my response".to_string(),
                        },
                    ]),
                },
                Message {
                    role: "user".to_string(),
                    content: MessageContent::Array(vec![ContentBlock::Image {
                        source: ImageSource {
                            source_type: "base64".to_string(),
                            media_type: "image/png".to_string(),
                            data: "iVBORw0KGgo=".to_string(),
                        },
                        cache_control: Some(json!({"type": "ephemeral"})),
                    }]),
                },
            ],
            system: None,
            tools: None,
            stream: false,
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            thinking: None,
            metadata: None,
            output_config: None,
            size: None,
            quality: None,
        };

        let result = transform_claude_request_in(&req, "test-project", false);
        assert!(result.is_ok());
        let body = result.unwrap();
        assert_eq!(body["project"], "test-project");
    }

    #[test]
    fn test_thinking_mode_auto_disable_on_tool_use_history() {
        let req = ClaudeRequest {
            model: MODEL_CLAUDE_SONNET_45.to_string(),
            messages: vec![
                Message {
                    role: "user".to_string(),
                    content: MessageContent::String("Check files".to_string()),
                },
                Message {
                    role: "assistant".to_string(),
                    content: MessageContent::Array(vec![
                        ContentBlock::Text {
                            text: "Checking...".to_string(),
                        },
                        ContentBlock::ToolUse {
                            id: "tool_1".to_string(),
                            name: "list_files".to_string(),
                            input: json!({}),
                            cache_control: None,
                            signature: None,
                        },
                    ]),
                },
                Message {
                    role: "user".to_string(),
                    content: MessageContent::Array(vec![ContentBlock::ToolResult {
                        tool_use_id: "tool_1".to_string(),
                        content: serde_json::Value::String("file1.txt\nfile2.txt".to_string()),
                        is_error: Some(false),
                    }]),
                },
            ],
            system: None,
            tools: Some(vec![Tool {
                name: Some("list_files".to_string()),
                description: Some("List files".to_string()),
                input_schema: Some(json!({"type": "object"})),
                type_: None,
            }]),
            stream: false,
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            thinking: Some(ThinkingConfig {
                type_: "enabled".to_string(),
                budget_tokens: Some(1024),
            }),
            metadata: None,
            output_config: None,
            size: None,
            quality: None,
        };

        let result = transform_claude_request_in(&req, "test-project", false);
        assert!(result.is_ok());

        let body = result.unwrap();
        let request = &body["request"];
        if let Some(gen_config) = request.get("generationConfig") {
            assert!(
                gen_config.get("thinkingConfig").is_none(),
                "thinkingConfig should be removed due to downgrade"
            );
        }
        assert!(request.get("contents").is_some());
    }

    #[test]
    fn test_thinking_block_not_prepend_when_disabled() {
        let req = ClaudeRequest {
            model: MODEL_CLAUDE_SONNET_45.to_string(),
            messages: vec![
                Message {
                    role: "user".to_string(),
                    content: MessageContent::String("Hello".to_string()),
                },
                Message {
                    role: "assistant".to_string(),
                    content: MessageContent::Array(vec![ContentBlock::Text {
                        text: "Response".to_string(),
                    }]),
                },
            ],
            system: None,
            tools: None,
            stream: false,
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            thinking: None,
            metadata: None,
            output_config: None,
            size: None,
            quality: None,
        };

        let result = transform_claude_request_in(&req, "test-project", false);
        assert!(result.is_ok());

        let body = result.unwrap();
        let contents = body["request"]["contents"].as_array().unwrap();

        let last_model_msg = contents
            .iter()
            .rev()
            .find(|c| c["role"] == "model")
            .unwrap();

        let parts = last_model_msg["parts"].as_array().unwrap();
        assert_eq!(parts.len(), 1, "Should only have the original text block");
        assert_eq!(parts[0]["text"], "Response");
    }

    #[test]
    fn test_thinking_block_empty_content_fix() {
        let req = ClaudeRequest {
            model: MODEL_CLAUDE_SONNET_45.to_string(),
            messages: vec![Message {
                role: "assistant".to_string(),
                content: MessageContent::Array(vec![
                    ContentBlock::Thinking {
                        thinking: "".to_string(),
                        signature: Some("sig".to_string()),
                        cache_control: None,
                    },
                    ContentBlock::Text {
                        text: "Hi".to_string(),
                    },
                ]),
            }],
            system: None,
            tools: None,
            stream: false,
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            thinking: Some(ThinkingConfig {
                type_: "enabled".to_string(),
                budget_tokens: Some(1024),
            }),
            metadata: None,
            output_config: None,
            size: None,
            quality: None,
        };

        let result = transform_claude_request_in(&req, "test-project", false);
        assert!(result.is_ok(), "Transformation failed");
        let body = result.unwrap();
        let contents = body["request"]["contents"].as_array().unwrap();
        let parts = contents[0]["parts"].as_array().unwrap();
        assert_eq!(
            parts[0]["text"], "...",
            "Empty thinking should be filled with ..."
        );
        assert!(
            parts[0].get("thought").is_none(),
            "Empty thinking should be downgraded to text"
        );
    }

    #[test]
    fn test_redacted_thinking_degradation() {
        let req = ClaudeRequest {
            model: MODEL_CLAUDE_SONNET_45.to_string(),
            messages: vec![Message {
                role: "assistant".to_string(),
                content: MessageContent::Array(vec![
                    ContentBlock::RedactedThinking {
                        data: "some data".to_string(),
                    },
                    ContentBlock::Text {
                        text: "Hi".to_string(),
                    },
                ]),
            }],
            system: None,
            tools: None,
            stream: false,
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            thinking: None,
            metadata: None,
            output_config: None,
            size: None,
            quality: None,
        };

        let result = transform_claude_request_in(&req, "test-project", false);
        assert!(result.is_ok());
        let body = result.unwrap();
        let parts = body["request"]["contents"][0]["parts"].as_array().unwrap();
        let text = parts[0]["text"].as_str().unwrap();
        assert!(text.contains("[Redacted Thinking: some data]"));
        assert!(
            parts[0].get("thought").is_none(),
            "Redacted thinking should NOT have thought: true"
        );
    }
    #[test]
    fn test_thinking_blocks_sorted_first_after_compression() {
        let mut messages = vec![Message {
            role: "assistant".to_string(),
            content: MessageContent::Array(vec![
                ContentBlock::Text {
                    text: "Some regular text".to_string(),
                },
                ContentBlock::Thinking {
                    thinking: "My thinking process".to_string(),
                    signature: Some(
                        "valid_signature_1234567890_abcdefghij_klmnopqrstuvwxyz_test".to_string(),
                    ),
                    cache_control: None,
                },
                ContentBlock::Text {
                    text: "More text".to_string(),
                },
            ]),
        }];
        sort_thinking_blocks_first(&mut messages);
        if let MessageContent::Array(blocks) = &messages[0].content {
            assert_eq!(blocks.len(), 3, "Should still have 3 blocks");
            assert!(
                matches!(blocks[0], ContentBlock::Thinking { .. }),
                "Thinking should be first"
            );
            assert!(
                matches!(blocks[1], ContentBlock::Text { .. }),
                "Text should be second"
            );
            assert!(
                matches!(blocks[2], ContentBlock::Text { .. }),
                "Text should be third"
            );
            if let ContentBlock::Thinking { thinking, .. } = &blocks[0] {
                assert_eq!(thinking, "My thinking process");
            }
        } else {
            panic!("Expected Array content");
        }
    }

    #[test]
    fn test_thinking_blocks_no_reorder_when_already_first() {
        let mut messages = vec![Message {
            role: "assistant".to_string(),
            content: MessageContent::Array(vec![
                ContentBlock::Thinking {
                    thinking: "My thinking".to_string(),
                    signature: Some("sig123".to_string()),
                    cache_control: None,
                },
                ContentBlock::Text {
                    text: "Some text".to_string(),
                },
            ]),
        }];
        sort_thinking_blocks_first(&mut messages);
        if let MessageContent::Array(blocks) = &messages[0].content {
            assert!(
                matches!(blocks[0], ContentBlock::Thinking { .. }),
                "Thinking should still be first"
            );
            assert!(
                matches!(blocks[1], ContentBlock::Text { .. }),
                "Text should still be second"
            );
        }
    }

    #[test]
    fn test_merge_consecutive_messages() {
        let mut messages = vec![
            Message {
                role: "user".to_string(),
                content: MessageContent::String("Hello".to_string()),
            },
            Message {
                role: "user".to_string(),
                content: MessageContent::Array(vec![ContentBlock::Text {
                    text: "World".to_string(),
                }]),
            },
            Message {
                role: "assistant".to_string(),
                content: MessageContent::String("Hi".to_string()),
            },
            Message {
                role: "user".to_string(),
                content: MessageContent::Array(vec![ContentBlock::ToolResult {
                    tool_use_id: "test_id".to_string(),
                    content: serde_json::json!("result"),
                    is_error: None,
                }]),
            },
            Message {
                role: "user".to_string(),
                content: MessageContent::Array(vec![ContentBlock::Text {
                    text: "System Reminder".to_string(),
                }]),
            },
        ];

        merge_consecutive_messages(&mut messages);

        assert_eq!(messages.len(), 3);
        assert_eq!(messages[0].role, "user");
        if let MessageContent::Array(blocks) = &messages[0].content {
            assert_eq!(blocks.len(), 2);
            match &blocks[0] {
                ContentBlock::Text { text } => assert_eq!(text, "Hello"),
                _ => panic!("Expected text block"),
            }
            match &blocks[1] {
                ContentBlock::Text { text } => assert_eq!(text, "World"),
                _ => panic!("Expected text block"),
            }
        } else {
            panic!("Expected array content at index 0");
        }

        assert_eq!(messages[1].role, "assistant");

        assert_eq!(messages[2].role, "user");
        if let MessageContent::Array(blocks) = &messages[2].content {
            assert_eq!(blocks.len(), 2);
            match &blocks[0] {
                ContentBlock::ToolResult { tool_use_id, .. } => assert_eq!(tool_use_id, "test_id"),
                _ => panic!("Expected tool_result block"),
            }
            match &blocks[1] {
                ContentBlock::Text { text } => assert_eq!(text, "System Reminder"),
                _ => panic!("Expected text block"),
            }
        } else {
            panic!("Expected array content at index 2");
        }
    }
    #[test]
    fn test_default_max_tokens() {
        let req = ClaudeRequest {
            model: MODEL_CLAUDE_SONNET_45.to_string(),
            messages: vec![Message {
                role: "user".to_string(),
                content: MessageContent::String("Hello".to_string()),
            }],
            system: None,
            tools: None,
            stream: false,
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            thinking: None,
            metadata: None,
            output_config: None,
            size: None,
            quality: None,
        };

        let result = transform_claude_request_in(&req, "test-v", false).unwrap();
        let gen_config = &result["request"]["generationConfig"];
        assert!(
            gen_config.get("maxOutputTokens").is_none(),
            "maxOutputTokens should not be set when max_tokens is None"
        );
    }
    #[test]
    fn test_claude_flash_thinking_budget_capping() {
        let req = ClaudeRequest {
            model: MODEL_GEMINI_3_FLASH_THINKING.to_string(),
            messages: vec![],
            thinking: Some(ThinkingConfig {
                type_: "enabled".to_string(),
                budget_tokens: Some(32000),
            }),
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stream: false,
            system: None,
            tools: None,
            metadata: None,
            output_config: None,
            size: None,
            quality: None,
        };
        let result = transform_claude_request_in(&req, "proj", false).unwrap();

        let gen_config = &result["request"]["generationConfig"];
        let budget = gen_config["thinkingConfig"]["thinkingBudget"]
            .as_u64()
            .unwrap();
        assert_eq!(budget, 24576);
        let req_pro = ClaudeRequest {
            model: MODEL_GEMINI_3_PRO.to_string(),
            messages: vec![],
            thinking: Some(ThinkingConfig {
                type_: "enabled".to_string(),
                budget_tokens: Some(32000),
            }),
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stream: false,
            system: None,
            tools: None,
            metadata: None,
            output_config: None,
            size: None,
            quality: None,
        };
        let result_pro = transform_claude_request_in(&req_pro, "proj", false).unwrap();
        let budget_pro = result_pro["request"]["generationConfig"]["thinkingConfig"]
            ["thinkingBudget"]
            .as_u64()
            .unwrap();
        assert_eq!(budget_pro, 24576);
    }

    #[test]
    fn test_gemini_pro_thinking_support() {
        let req = ClaudeRequest {
            model: MODEL_GEMINI_3_PRO_PREVIEW.to_string(),
            messages: vec![Message {
                role: "user".to_string(),
                content: MessageContent::String("Hello".to_string()),
            }],
            thinking: Some(ThinkingConfig {
                type_: "enabled".to_string(),
                budget_tokens: Some(16000),
            }),
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stream: false,
            system: None,
            tools: None,
            metadata: None,
            output_config: None,
            size: None,
            quality: None,
        };
        let result = transform_claude_request_in(&req, "proj", false).unwrap();
        let gen_config = &result["request"]["generationConfig"];
        assert!(
            gen_config.get("thinkingConfig").is_some(),
            "thinkingConfig should be preserved for gemini-3-pro"
        );

        let budget = gen_config["thinkingConfig"]["thinkingBudget"]
            .as_u64()
            .unwrap();
        assert_eq!(budget, 16000);
    }

    #[test]
    fn test_gemini_pro_default_thinking() {
        let req = ClaudeRequest {
            model: MODEL_GEMINI_3_PRO_PREVIEW.to_string(),
            messages: vec![Message {
                role: "user".to_string(),
                content: MessageContent::String("Hello".to_string()),
            }],
            thinking: None,
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stream: false,
            system: None,
            tools: None,
            metadata: None,
            output_config: None,
            size: None,
            quality: None,
        };
        let result = transform_claude_request_in(&req, "proj", false).unwrap();
        let gen_config = &result["request"]["generationConfig"];
        assert!(
            gen_config.get("thinkingConfig").is_some(),
            "thinkingConfig should be auto-enabled for gemini-3-pro"
        );
    }
}
