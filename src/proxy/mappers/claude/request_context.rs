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

    let has_web_search_tool = detect_web_search_tool(&cleaned_req);
    let has_mcp_tools = detect_mcp_tools(&cleaned_req);
    let tool_name_to_schema = collect_tool_name_to_schema(&cleaned_req);
    let mapped_model = resolve_mapped_model(&cleaned_req.model, has_web_search_tool);
    let is_thinking_enabled = resolve_thinking_enabled(&cleaned_req, &mapped_model, &session_id);

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

fn detect_web_search_tool(claude_req: &ClaudeRequest) -> bool {
    claude_req
        .tools
        .as_ref()
        .map(|tools| {
            tools.iter().any(|t| {
                t.is_web_search()
                    || t.name.as_deref() == Some("google_search")
                    || t.type_.as_deref() == Some("web_search_20250305")
            })
        })
        .unwrap_or(false)
}

fn detect_mcp_tools(claude_req: &ClaudeRequest) -> bool {
    claude_req
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
        .unwrap_or(false)
}

fn collect_tool_name_to_schema(claude_req: &ClaudeRequest) -> HashMap<String, Value> {
    let mut tool_name_to_schema = HashMap::new();
    if let Some(tools) = &claude_req.tools {
        for tool in tools {
            if let (Some(name), Some(schema)) = (&tool.name, &tool.input_schema) {
                tool_name_to_schema.insert(name.clone(), schema.clone());
            }
        }
    }
    tool_name_to_schema
}

fn resolve_mapped_model(original_model: &str, has_web_search_tool: bool) -> String {
    let web_search_fallback_model =
        crate::proxy::common::model_mapping::web_search_fallback_model();

    if has_web_search_tool {
        tracing::debug!(
            "[Claude-Request] Web search tool detected, using fallback model: {}",
            web_search_fallback_model
        );
        web_search_fallback_model.to_string()
    } else {
        crate::proxy::common::model_mapping::map_claude_model_to_gemini(original_model)
    }
}

fn resolve_thinking_enabled(
    claude_req: &ClaudeRequest,
    mapped_model: &str,
    session_id: &str,
) -> bool {
    let mut is_thinking_enabled = claude_req
        .thinking
        .as_ref()
        .map(|t| t.type_ == "enabled")
        .unwrap_or_else(|| super::thinking::should_enable_thinking_by_default(&claude_req.model));
    let target_model_supports_thinking =
        crate::proxy::common::model_mapping::model_supports_thinking(mapped_model);

    if is_thinking_enabled && !target_model_supports_thinking {
        tracing::warn!(
            "[Thinking-Mode] Target model '{}' does not support thinking. Force disabling thinking mode.",
            mapped_model
        );
        is_thinking_enabled = false;
    }

    if is_thinking_enabled
        && super::thinking::should_disable_thinking_due_to_history(&claude_req.messages)
    {
        tracing::warn!("[Thinking-Mode] Automatically disabling thinking checks due to incompatible tool-use history (mixed application)");
        is_thinking_enabled = false;
    }

    if !is_thinking_enabled {
        return false;
    }

    let global_sig = get_thought_signature();
    let (has_thinking_history, has_function_calls) = inspect_message_history(&claude_req.messages);

    if !has_thinking_history {
        tracing::info!(
            "[Thinking-Mode] First thinking request detected. Using permissive mode - \
             signature validation will be handled by upstream API."
        );
    }

    if has_function_calls
        && !super::thinking::has_valid_signature_for_function_calls(
            &claude_req.messages,
            &global_sig,
            session_id,
        )
    {
        tracing::warn!(
            "[Thinking-Mode] No valid signature found for function calls. \
             Disabling thinking to prevent Gemini 3 Pro rejection."
        );
        return false;
    }

    true
}

fn inspect_message_history(messages: &[Message]) -> (bool, bool) {
    let has_thinking_history = messages.iter().any(|m| {
        if m.role == "assistant" {
            if let MessageContent::Array(blocks) = &m.content {
                return blocks
                    .iter()
                    .any(|b| matches!(b, ContentBlock::Thinking { .. }));
            }
        }
        false
    });

    let has_function_calls = messages.iter().any(|m| {
        if let MessageContent::Array(blocks) = &m.content {
            blocks
                .iter()
                .any(|b| matches!(b, ContentBlock::ToolUse { .. }))
        } else {
            false
        }
    });

    (has_thinking_history, has_function_calls)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn mk_req(model: &str) -> ClaudeRequest {
        ClaudeRequest {
            model: model.to_string(),
            messages: vec![Message {
                role: "user".to_string(),
                content: MessageContent::String("hello".to_string()),
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
        }
    }

    #[test]
    fn detect_web_search_tool_works_for_type_and_name() {
        let mut req = mk_req("gpt-5");
        req.tools = Some(vec![Tool {
            type_: Some("web_search_20250305".to_string()),
            name: None,
            description: None,
            input_schema: None,
        }]);
        assert!(detect_web_search_tool(&req));

        req.tools = Some(vec![Tool {
            type_: None,
            name: Some("google_search".to_string()),
            description: None,
            input_schema: None,
        }]);
        assert!(detect_web_search_tool(&req));

        req.tools = None;
        assert!(!detect_web_search_tool(&req));
    }

    #[test]
    fn resolve_mapped_model_uses_web_search_fallback_when_tool_detected() {
        let fallback = crate::proxy::common::model_mapping::web_search_fallback_model();
        let mapped = resolve_mapped_model("claude-sonnet-4-5", true);
        assert_eq!(mapped, fallback);
    }

    #[test]
    fn resolve_mapped_model_uses_normal_mapping_without_web_search_tool() {
        let fallback = crate::proxy::common::model_mapping::web_search_fallback_model();
        let mapped = resolve_mapped_model("claude-sonnet-4-5", false);
        assert_eq!(
            mapped,
            crate::proxy::common::model_mapping::map_claude_model_to_gemini("claude-sonnet-4-5")
        );
        assert_ne!(mapped, fallback);
    }

    #[test]
    fn resolve_thinking_enabled_disables_when_target_model_lacks_thinking() {
        let mut req = mk_req("claude-sonnet-4-5");
        req.thinking = Some(ThinkingConfig {
            type_: "enabled".to_string(),
            budget_tokens: Some(4096),
        });

        let fallback = crate::proxy::common::model_mapping::web_search_fallback_model();
        let enabled = resolve_thinking_enabled(&req, fallback, "session-1");
        assert!(!enabled);
    }

    #[test]
    fn prepare_request_context_sets_expected_flags_and_schema_map() {
        let mut req = mk_req("claude-sonnet-4-5");
        req.thinking = Some(ThinkingConfig {
            type_: "enabled".to_string(),
            budget_tokens: Some(2048),
        });
        req.tools = Some(vec![
            Tool {
                type_: Some("web_search_20250305".to_string()),
                name: None,
                description: None,
                input_schema: None,
            },
            Tool {
                type_: None,
                name: Some("mcp__fs_read".to_string()),
                description: Some("read files".to_string()),
                input_schema: Some(
                    json!({"type":"object","properties":{"path":{"type":"string"}}}),
                ),
            },
        ]);

        let ctx = prepare_request_context(&req);
        assert!(ctx.has_web_search_tool);
        assert!(ctx.has_mcp_tools);
        assert_eq!(
            ctx.mapped_model,
            crate::proxy::common::model_mapping::web_search_fallback_model()
        );
        assert!(ctx.tool_name_to_schema.contains_key("mcp__fs_read"));
        assert!(!ctx.allow_dummy_thought);
    }
}
