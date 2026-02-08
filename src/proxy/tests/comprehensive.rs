#[cfg(test)]
mod tests {
    use crate::proxy::mappers::claude::models::{
        ClaudeRequest, Message, MessageContent, ContentBlock, ThinkingConfig
    };
    use crate::proxy::mappers::claude::request::transform_claude_request_in;
    use crate::proxy::mappers::claude::thinking_utils::{analyze_conversation_state, close_tool_loop_for_thinking};
    use serde_json::json;

    
    // ==================================================================================
    // Scenario 1: First Thinking Request
    // Verify if the first Thinking request is allowed in the absence of historical signatures (Permissive Mode)
    // ==================================================================================
    #[test]
    fn test_first_thinking_request_permissive_mode() {
        // 1. Construct a standard new request (no historical messages)
        let req = ClaudeRequest {
            model: "claude-sonnet-4-5".to_string(),
            messages: vec![
                Message {
                    role: "user".to_string(),
                    content: MessageContent::String("Hello, please think.".to_string()),
                }
            ],
            system: None,
            tools: None, // No tool calls
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

        // 2. Execute transformation
        // If the fix is effective, this should return successfully, and thinkingConfig should be preserved
        let result = transform_claude_request_in(&req, "test-project", false);
        assert!(result.is_ok(), "First thinking request should be allowed");

        let body = result.unwrap();
        let request = &body["request"];
        
        // Verify if thinkingConfig exists (i.e., thinking mode is not disabled)
        let has_thinking_config = request.get("generationConfig")
            .and_then(|g| g.get("thinkingConfig"))
            .is_some();
            
        assert!(has_thinking_config, "Thinking config should be preserved for first request without tool calls");
    }

    // ==================================================================================
    // Scenario 2: Tool Loop Recovery
    // Verify if synthetic messages are automatically injected to close the loop when a missing Thinking block in historical messages causes an infinite loop
    // ==================================================================================
    #[test]
    fn test_tool_loop_recovery() {
        // 1. Construct a "Broken Tool Loop" scenario
        // Assistant (ToolUse) -> User (ToolResult)
        // But the Assistant message lacks a Thinking block (simulating being stripped)
        let mut messages = vec![
            Message {
                role: "user".to_string(),
                content: MessageContent::String("Check weather".to_string()),
            },
            Message {
                role: "assistant".to_string(),
                content: MessageContent::Array(vec![
                    // Only ToolUse, no Thinking (Broken State)
                    ContentBlock::ToolUse {
                        id: "call_1".to_string(),
                        name: "get_weather".to_string(),
                        input: json!({"location": "Beijing"}),
                        signature: None,
                        cache_control: None,
                    }
                ]),
            },
            Message {
                role: "user".to_string(),
                content: MessageContent::Array(vec![
                    ContentBlock::ToolResult {
                        tool_use_id: "call_1".to_string(),
                        content: json!("Sunny"),
                        is_error: None,
                    }
                ]),
            }
        ];

        // 2. Analyze current state
        let state = analyze_conversation_state(&messages);
        assert!(state.in_tool_loop, "Should detect tool loop");

        // 3. Execute recovery logic
        close_tool_loop_for_thinking(&mut messages);

        // 4. Verify if synthetic messages were injected
        assert_eq!(messages.len(), 5, "Should have injected 2 synthetic messages");
        
        // Verify that the second-to-last message is an Assistant "Completed" message
        let injected_assistant = &messages[3];
        assert_eq!(injected_assistant.role, "assistant");
        
        // Verify that the last message is a User "Proceed" message
        let injected_user = &messages[4];
        assert_eq!(injected_user.role, "user");
        
        // This way, the current state is no longer "in_tool_loop" (last message is User Text), and the model can start a new Thinking session
        let new_state = analyze_conversation_state(&messages);
        assert!(!new_state.in_tool_loop, "Tool loop should be broken/closed");
    }

    // ==================================================================================
    // Scenario 3: Cross-model Compatibility - Simulated
    // Since is_model_compatible in request.rs is private, we verify the effect through integration tests
    // ==================================================================================
    /* 
       Note: Since is_model_compatible and caching logic are deeply integrated in transform_claude_request_in, 
       and rely on the global singleton SignatureCache, it's difficult for unit tests to simulate a state where "an old signature is cached but the model has switched".
       Testing is mainly done by verifying the side effect that "incompatible signatures are discarded" (i.e., thoughtSignature field messages).
       However, because SignatureCache is global, we cannot easily preset the state in tests.
       Therefore, this scenario primarily relies on manual testing in the Verification Guide.
       Alternatively, we could test some public helpers in request.rs if they existed, but currently none do.
    */

}
