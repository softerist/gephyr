use crate::proxy::mappers::claude::models::*;
use crate::proxy::mappers::signature_store::get_thought_signature;
use crate::proxy::session_manager::SessionManager;
use serde_json::Value;
use std::collections::HashMap;

pub(super) struct RequestContext {
    pub cleaned_req: ClaudeRequest,
    pub session_id: String,
    pub has_web_search_tool: bool,
    pub has_mcp_tools: bool,
    pub mapped_model: String,
    pub tool_name_to_schema: HashMap<String, Value>,
    pub is_thinking_enabled: bool,
    pub allow_dummy_thought: bool,
}

pub(super) fn prepare_request_context(claude_req: &ClaudeRequest) -> RequestContext {
    let mut cleaned_req = claude_req.clone();
    super::merge_consecutive_messages(&mut cleaned_req.messages);
    super::clean_cache_control_from_messages(&mut cleaned_req.messages);
    super::sort_thinking_blocks_first(&mut cleaned_req.messages);

    let session_id = SessionManager::extract_session_id(&cleaned_req);
    tracing::debug!("[Claude-Request] Session ID: {}", session_id);

    let has_web_search_tool = cleaned_req
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

    let has_mcp_tools = cleaned_req
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
    if let Some(tools) = &cleaned_req.tools {
        for tool in tools {
            if let (Some(name), Some(schema)) = (&tool.name, &tool.input_schema) {
                tool_name_to_schema.insert(name.clone(), schema.clone());
            }
        }
    }

    let web_search_fallback_model =
        crate::proxy::common::model_mapping::web_search_fallback_model();

    let mapped_model = if has_web_search_tool {
        tracing::debug!(
            "[Claude-Request] Web search tool detected, using fallback model: {}",
            web_search_fallback_model
        );
        web_search_fallback_model.to_string()
    } else {
        crate::proxy::common::model_mapping::map_claude_model_to_gemini(&cleaned_req.model)
    };

    let mut is_thinking_enabled = cleaned_req
        .thinking
        .as_ref()
        .map(|t| t.type_ == "enabled")
        .unwrap_or_else(|| super::thinking::should_enable_thinking_by_default(&cleaned_req.model));
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
        let should_disable =
            super::thinking::should_disable_thinking_due_to_history(&cleaned_req.messages);
        if should_disable {
            tracing::warn!("[Thinking-Mode] Automatically disabling thinking checks due to incompatible tool-use history (mixed application)");
            is_thinking_enabled = false;
        }
    }

    if is_thinking_enabled {
        let global_sig = get_thought_signature();
        let has_thinking_history = cleaned_req.messages.iter().any(|m| {
            if m.role == "assistant" {
                if let MessageContent::Array(blocks) = &m.content {
                    return blocks
                        .iter()
                        .any(|b| matches!(b, ContentBlock::Thinking { .. }));
                }
            }
            false
        });
        let has_function_calls = cleaned_req.messages.iter().any(|m| {
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
            && !super::thinking::has_valid_signature_for_function_calls(
                &cleaned_req.messages,
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

    RequestContext {
        cleaned_req,
        session_id,
        has_web_search_tool,
        has_mcp_tools,
        mapped_model,
        tool_name_to_schema,
        is_thinking_enabled,
        allow_dummy_thought: false,
    }
}
