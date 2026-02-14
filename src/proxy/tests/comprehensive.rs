#[cfg(test)]
mod tests {
    use crate::proxy::mappers::claude::models::{
        ClaudeRequest, ContentBlock, Message, MessageContent, ThinkingConfig,
    };
    use crate::proxy::mappers::claude::request::transform_claude_request_in;
    use crate::proxy::mappers::claude::thinking_utils::{
        analyze_conversation_state, close_tool_loop_for_thinking,
    };
    use serde_json::json;
    #[test]
    fn test_first_thinking_request_permissive_mode() {
        let req = ClaudeRequest {
            model: "claude-sonnet-4-5".to_string(),
            messages: vec![Message {
                role: "user".to_string(),
                content: MessageContent::String("Hello, please think.".to_string()),
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
        assert!(result.is_ok(), "First thinking request should be allowed");

        let body = result.unwrap();
        let request = &body["request"];
        let has_thinking_config = request
            .get("generationConfig")
            .and_then(|g| g.get("thinkingConfig"))
            .is_some();

        assert!(
            has_thinking_config,
            "Thinking config should be preserved for first request without tool calls"
        );
    }
    #[test]
    fn test_tool_loop_recovery() {
        let mut messages = vec![
            Message {
                role: "user".to_string(),
                content: MessageContent::String("Check weather".to_string()),
            },
            Message {
                role: "assistant".to_string(),
                content: MessageContent::Array(vec![ContentBlock::ToolUse {
                    id: "call_1".to_string(),
                    name: "get_weather".to_string(),
                    input: json!({"location": "Beijing"}),
                    signature: None,
                    cache_control: None,
                }]),
            },
            Message {
                role: "user".to_string(),
                content: MessageContent::Array(vec![ContentBlock::ToolResult {
                    tool_use_id: "call_1".to_string(),
                    content: json!("Sunny"),
                    is_error: None,
                }]),
            },
        ];
        let state = analyze_conversation_state(&messages);
        assert!(state.in_tool_loop, "Should detect tool loop");
        close_tool_loop_for_thinking(&mut messages);
        assert_eq!(
            messages.len(),
            5,
            "Should have injected 2 synthetic messages"
        );
        let injected_assistant = &messages[3];
        assert_eq!(injected_assistant.role, "assistant");
        let injected_user = &messages[4];
        assert_eq!(injected_user.role, "user");
        let new_state = analyze_conversation_state(&messages);
        assert!(!new_state.in_tool_loop, "Tool loop should be broken/closed");
    }
}