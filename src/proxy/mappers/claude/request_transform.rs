use crate::proxy::mappers::claude::models::*;
use serde_json::Value;

pub(super) fn transform_claude_request_in(
    claude_req: &ClaudeRequest,
    project_id: &str,
    is_retry: bool,
) -> Result<Value, String> {
    let ctx = super::context::prepare_request_context(claude_req);
    super::builder::build_request_body(&ctx, project_id, is_retry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::mappers::claude::models::{
        ClaudeRequest, Message, MessageContent, ThinkingConfig, Tool,
    };
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
            max_tokens: Some(128),
            temperature: Some(0.1),
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
        }
    }

    #[test]
    fn transform_chain_returns_valid_outer_envelope() {
        let req = mk_req("claude-sonnet-4-5");
        let out = transform_claude_request_in(&req, "proj-1", false).unwrap();

        assert_eq!(out["project"], json!("proj-1"));
        assert!(out["requestId"].as_str().unwrap_or_default().starts_with("agent-"));
        assert!(out["request"].get("contents").is_some());
        assert!(out["request"].get("safetySettings").is_some());
    }

    #[test]
    fn transform_chain_web_search_tool_uses_fallback_model() {
        let mut req = mk_req("claude-sonnet-4-5");
        req.tools = Some(vec![Tool {
            type_: Some("web_search_20250305".to_string()),
            name: None,
            description: None,
            input_schema: None,
        }]);

        let out = transform_claude_request_in(&req, "proj-2", false).unwrap();
        assert_eq!(
            out["model"],
            json!(crate::proxy::common::model_mapping::web_search_fallback_model())
        );
        assert_eq!(out["requestType"], json!("web_search"));
    }
}
