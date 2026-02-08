// Gemini v1internal wrapping/unwrapping
use serde_json::{json, Value};

// Wrap request body into v1internal format
pub fn wrap_request(
    body: &Value,
    project_id: &str,
    mapped_model: &str,
    session_id: Option<&str>,
) -> Value {
    // Prioritize passed mapped_model, otherwise try to get from body
    let original_model = body
        .get("model")
        .and_then(|v| v.as_str())
        .unwrap_or(mapped_model);

    // If mapped_model is empty, use original_model
    let final_model_name = if !mapped_model.is_empty() {
        mapped_model
    } else {
        original_model
    };

    // Copy body for modification
    let mut inner_request = body.clone();

    // Deep clean [undefined] strings (common injection in clients like Cherry Studio)
    crate::proxy::mappers::common_utils::deep_clean_undefined(&mut inner_request);

    // Inject dummy IDs for Claude models in Gemini protocol
    // Google v1internal requires 'id' for tool calls when the model is Claude, 
    // even though the standard Gemini protocol doesn't have it.
    let is_target_claude = crate::proxy::common::model_mapping::is_claude_model(final_model_name);
    
    if let Some(contents) = inner_request.get_mut("contents").and_then(|c| c.as_array_mut()) {
        for content in contents {
            // Maintain independent counters for each message to ensure Call and corresponding Response generate the same ID (fallback rule)
            let mut name_counters: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

            if let Some(parts) = content.get_mut("parts").and_then(|p| p.as_array_mut()) {
                for part in parts {
                    if let Some(obj) = part.as_object_mut() {
                        // 1. Handle functionCall (Assistant requests tool call)
                        if let Some(fc) = obj.get_mut("functionCall") {
                            if fc.get("id").is_none() && is_target_claude {
                                let name = fc.get("name").and_then(|n| n.as_str()).unwrap_or("unknown");
                                let count = name_counters.entry(name.to_string()).or_insert(0);
                                let call_id = format!("call_{}_{}", name, count);
                                *count += 1;
                                
                                fc.as_object_mut().unwrap().insert("id".to_string(), json!(call_id));
                                tracing::debug!("[Gemini-Wrap] Request stage: Injected missing call_id '{}' for Claude model", call_id);
                            }
                        }
                        
                        // 2. Handle functionResponse (User replies with tool result)
                        if let Some(fr) = obj.get_mut("functionResponse") {
                            if fr.get("id").is_none() && is_target_claude {
                                // Heuristic: If client (like OpenCode) does not include ID in response, it means it didn't have ID when receiving the call.
                                // The ID generated here MUST match the one we inject in inject_ids_to_response.
                                let name = fr.get("name").and_then(|n| n.as_str()).unwrap_or("unknown");
                                let count = name_counters.entry(name.to_string()).or_insert(0);
                                let call_id = format!("call_{}_{}", name, count);
                                *count += 1;
                                
                                fr.as_object_mut().unwrap().insert("id".to_string(), json!(call_id));
                                tracing::debug!("[Gemini-Wrap] Request stage: Injected synced response_id '{}' for Claude model", call_id);
                            }
                        }

                        // 3. Handle thoughtSignature (maintain existing logic)
                        if obj.contains_key("functionCall") && obj.get("thoughtSignature").is_none() {
                            if let Some(s_id) = session_id {
                                if let Some(sig) = crate::proxy::SignatureCache::global().get_session_signature(s_id) {
                                    obj.insert("thoughtSignature".to_string(), json!(sig));
                                    tracing::debug!("[Gemini-Wrap] Injected signature (len: {}) for session: {}", sig.len(), s_id);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Gemini Flash thinking budget capping
    // [CONFIGURABLE] Now following global Thinking Budget configuration
    // Also apply to Pro/Thinking models to ensure budget processing
    // Auto-inject thinkingConfig if missing for these models
    let lower_model = final_model_name.to_lowercase();
    if lower_model.contains("flash")
        || lower_model.contains("pro")
        || lower_model.contains("thinking")
    {
        // Ensure generationConfig exists
        let gen_config = inner_request
            .as_object_mut()
            .unwrap()
            .entry("generationConfig")
            .or_insert(json!({}))
            .as_object_mut()
            .unwrap();

        // Check if thinkingConfig exists, if not, inject default if it's a known thinking model without config
        // Only inject if it's NOT a model that explicitly forbids thinking (no such cases yet for this filter)
    // Note: "gemini-3-pro" requires thinkingConfig. Keep auto-injecting for 3-pro/3-flash thinking.
        if gen_config.get("thinkingConfig").is_none() {
             // For safety, only auto-inject for models we usually want thinking on.
             let should_inject =
                 crate::proxy::common::model_mapping::model_supports_thinking(&lower_model);
                                 
             if should_inject {
                 tracing::debug!("[Gemini-Wrap] Auto-injecting default thinkingConfig for {}", final_model_name);
                 
                 // Use a safe default budget or let auto-capping handle it (if we set something high)
                 // But wait, if we set it here, the capping logic below will see it and clamp it if needed.
                 // Let's rely on global default logic if possible, or hardcode a safe default.
                 // The capping logic reads from it.
                 // Let's inject a reasonable default that triggers thinking.
                 gen_config.insert("thinkingConfig".to_string(), json!({
                     "includeThoughts": true,
                     "thinkingBudget": 24576 // Default safe budget for auto-injected (aligned with other mappers)
                 }));
             }
        }

        if let Some(thinking_config) = gen_config.get_mut("thinkingConfig") {
            if let Some(budget_val) = thinking_config.get("thinkingBudget") {
                if let Some(budget) = budget_val.as_u64() {
                    let tb_config = crate::proxy::config::get_thinking_budget_config();
                    let final_budget = match tb_config.mode {
                        crate::proxy::config::ThinkingBudgetMode::Passthrough => {
                            // Passthrough mode: no changes, use upstream value completely
                            tracing::debug!(
                                "[Gemini-Wrap] Passthrough mode: keeping budget {} for model {}",
                                budget, final_model_name
                            );
                            budget
                        }
                        crate::proxy::config::ThinkingBudgetMode::Custom => {
                            // Custom mode: use fixed value from global config
                            // Even in Custom mode, cap to 24576 for known Gemini thinking limit
                            let val = tb_config.custom_value as u64;
                            if val > 24576 {
                                tracing::warn!(
                                    "[Gemini-Wrap] Custom mode: capping thinking_budget from {} to 24576 for model {}",
                                    val, final_model_name
                                );
                                24576
                            } else {
                                if val != budget {
                                    tracing::debug!(
                                        "[Gemini-Wrap] Custom mode: overriding {} with {} for model {}",
                                        budget, val, final_model_name
                                    );
                                }
                                val
                            }
                        }
                        crate::proxy::config::ThinkingBudgetMode::Auto => {
                            // Auto mode: apply 24576 capping (backward compatibility)
                            if budget > 24576 {
                                tracing::info!(
                                    "[Gemini-Wrap] Auto mode: capping thinking_budget from {} to 24576 for model {}", 
                                    budget, final_model_name
                                );
                                24576
                            } else {
                                budget
                            }
                        }
                    };

                    if final_budget != budget {
                        thinking_config["thinkingBudget"] = json!(final_budget);
                    }
                }
            }
        }
    }

    //  Removed forced maxOutputTokens (64000) as it exceeds limits for older Gemini standard models (8192).
    // This caused upstream to return empty/invalid responses, leading to 'NoneType' object has no attribute 'strip' in Python clients.
    // relying on upstream defaults or user provided values is safer.

    // Extract tools list for web search detection (Gemini style might be nested)
    let tools_val: Option<Vec<Value>> = inner_request
        .get("tools")
        .and_then(|t| t.as_array())
        .map(|arr| arr.clone());

    //  Extract OpenAI-compatible image parameters from root (for gemini-3-pro-image)
    let size = body.get("size").and_then(|v| v.as_str());
    let quality = body.get("quality").and_then(|v| v.as_str());

    // Use shared grounding/config logic
    let config = crate::proxy::mappers::common_utils::resolve_request_config(
        original_model,
        final_model_name,
        &tools_val,
        size,    //  Pass size parameter
        quality, //  Pass quality parameter
        Some(body),  //  Pass request body for imageConfig parsing
    );

    // Clean tool declarations (remove forbidden Schema fields like multipleOf, and remove redundant search decls)
    if let Some(tools) = inner_request.get_mut("tools") {
        if let Some(tools_arr) = tools.as_array_mut() {
            for tool in tools_arr {
                if let Some(decls) = tool.get_mut("functionDeclarations") {
                    if let Some(decls_arr) = decls.as_array_mut() {
                        // 1. Filter out web search keyword functions
                        decls_arr.retain(|decl| {
                            if let Some(name) = decl.get("name").and_then(|v| v.as_str()) {
                                if name == "web_search" || name == "google_search" {
                                    return false;
                                }
                            }
                            true
                        });

                        // 2. Clean remaining Schema
                        //  Gemini CLI uses parametersJsonSchema, while standard Gemini API uses parameters.
                        // Need to rename parametersJsonSchema to parameters.
                        for decl in decls_arr {
                            // Detect and convert field names
                            if let Some(decl_obj) = decl.as_object_mut() {
                                // If parametersJsonSchema exists, rename it to parameters
                                if let Some(params_json_schema) =
                                    decl_obj.remove("parametersJsonSchema")
                                {
                                    let mut params = params_json_schema;
                                    crate::proxy::common::json_schema::clean_json_schema(
                                        &mut params,
                                    );
                                    decl_obj.insert("parameters".to_string(), params);
                                } else if let Some(params) = decl_obj.get_mut("parameters") {
                                    // Standard parameters field
                                    crate::proxy::common::json_schema::clean_json_schema(params);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    tracing::debug!(
        " Gemini Wrap: original='{}', mapped='{}', final='{}', type='{}'",
        original_model,
        final_model_name,
        config.final_model,
        config.request_type
    );

    // Inject googleSearch tool if needed
    if config.inject_google_search {
        crate::proxy::mappers::common_utils::inject_google_search_tool(&mut inner_request);
    }

    // Inject imageConfig if present (for image generation models)
    if let Some(image_config) = config.image_config {
        if let Some(obj) = inner_request.as_object_mut() {
            // 1. Filter tools: remove tools for image generation
            obj.remove("tools");

            // 2. Remove systemInstruction (image generation does not support system prompts)
            obj.remove("systemInstruction");

            //  Ensure 'role' field exists for all contents (Native clients might omit it)
            if let Some(contents) = obj.get_mut("contents").and_then(|c| c.as_array_mut()) {
                for content in contents {
                    if let Some(c_obj) = content.as_object_mut() {
                        if !c_obj.contains_key("role") {
                            c_obj.insert("role".to_string(), json!("user"));
                        }
                    }
                }
            }

            // 3. Clean generationConfig (remove responseMimeType, responseModalities etc.)
            let gen_config = obj.entry("generationConfig").or_insert_with(|| json!({}));
            if let Some(gen_obj) = gen_config.as_object_mut() {
                // [REMOVED] thinkingConfig interception removed to allow CoT output during image generation
                // gen_obj.remove("thinkingConfig");
                gen_obj.remove("responseMimeType");
                gen_obj.remove("responseModalities"); // Cherry Studio sends this, might conflict
                gen_obj.insert("imageConfig".to_string(), image_config);
            }
        }
    } else {
        //  Only inject Antigravity identity in non-image generation mode (original simplified version)
        let antigravity_identity = "You are Antigravity, a powerful agentic AI coding assistant designed by the Google Deepmind team working on Advanced Agentic Coding.\n\
        You are pair programming with a USER to solve their coding task. The task may require creating a new codebase, modifying or debugging an existing codebase, or simply answering a question.\n\
        **Absolute paths only**\n\
        **Proactiveness**";

        // [HYBRID] Check if systemInstruction already exists
        if let Some(system_instruction) = inner_request.get_mut("systemInstruction") {
            //  Add missing role: user
            if let Some(obj) = system_instruction.as_object_mut() {
                if !obj.contains_key("role") {
                    obj.insert("role".to_string(), json!("user"));
                }
            }

            if let Some(parts) = system_instruction.get_mut("parts") {
                if let Some(parts_array) = parts.as_array_mut() {
                    // Check if the first part already contains Antigravity identity
                    let has_antigravity = parts_array
                        .get(0)
                        .and_then(|p| p.get("text"))
                        .and_then(|t| t.as_str())
                        .map(|s| s.contains("You are Antigravity"))
                        .unwrap_or(false);

                    if !has_antigravity {
                        // Insert Antigravity identity at the beginning
                        parts_array.insert(0, json!({"text": antigravity_identity}));
                    }
                }
            }
        } else {
            // systemInstruction does not exist, create a new one
            inner_request["systemInstruction"] = json!({
                "role": "user",
                "parts": [{"text": antigravity_identity}]
            });
        }
    }

    let final_request = json!({
        "project": project_id,
        "requestId": format!("agent-{}", uuid::Uuid::new_v4()), // Corrected to agent- prefix
        "request": inner_request,
        "model": config.final_model,
        "userAgent": "antigravity",
        "requestType": config.request_type
    });

    final_request
}

#[cfg(test)]
mod test_fixes {
    use super::*;
    use serde_json::json;
    use crate::proxy::common::model_mapping::MODEL_GEMINI_PRO_ALIAS;

    #[test]
    fn test_wrap_request_with_signature() {
        let session_id = "test-session-sig";
        let signature = "test-signature-must-be-longer-than-fifty-characters-to-be-cached-by-signature-cache-12345"; // > 50 chars
        crate::proxy::SignatureCache::global().cache_session_signature(
            session_id,
            signature.to_string(),
            1,
        );

        let body = json!({
            "model": MODEL_GEMINI_PRO_ALIAS,
            "contents": [{
                "role": "user",
                "parts": [{
                    "functionCall": {
                        "name": "get_weather",
                        "args": {"location": "London"}
                    }
                }]
            }]
        });

        let result = wrap_request(&body, "proj", MODEL_GEMINI_PRO_ALIAS, Some(session_id));
        let injected_sig = result["request"]["contents"][0]["parts"][0]["thoughtSignature"]
            .as_str()
            .unwrap();
        assert_eq!(injected_sig, signature);
    }
}

// Unwrap response (extract response field)
pub fn unwrap_response(response: &Value) -> Value {
    response.get("response").unwrap_or(response).clone()
}

// [NEW v3.3.18] Auto-inject Tool ID into Gemini response for Claude models
// 
// The purpose is to allow clients (like OpenCode/Vercel AI SDK) to perceive the ID
// and return it as is in the next turn of conversation, satisfying Google v1internal's validation for Claude models.
pub fn inject_ids_to_response(response: &mut Value, model_name: &str) {
    if !crate::proxy::common::model_mapping::is_claude_model(model_name) {
        return;
    }

    if let Some(candidates) = response.get_mut("candidates").and_then(|c| c.as_array_mut()) {
        for candidate in candidates {
            if let Some(parts) = candidate.get_mut("content").and_then(|c| c.get_mut("parts")).and_then(|p| p.as_array_mut()) {
                let mut name_counters: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
                for part in parts {
                    if let Some(fc) = part.get_mut("functionCall").and_then(|f| f.as_object_mut()) {
                        if fc.get("id").is_none() {
                            let name = fc.get("name").and_then(|n| n.as_str()).unwrap_or("unknown");
                            let count = name_counters.entry(name.to_string()).or_insert(0);
                            let call_id = format!("call_{}_{}", name, count);
                            *count += 1;
                            
                            fc.insert("id".to_string(), json!(call_id));
                            tracing::debug!("[Gemini-Wrap] Response stage: Injected synthetic call_id '{}' for client", call_id);
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use crate::proxy::common::model_mapping::{
        MODEL_GEMINI_3_FLASH,
        MODEL_GEMINI_3_FLASH_THINKING,
        MODEL_GEMINI_3_PRO,
        MODEL_GEMINI_3_PRO_IMAGE,
        MODEL_GEMINI_3_PRO_PREVIEW,
        MODEL_GEMINI_PRO_ALIAS,
    };

    #[test]
    fn test_wrap_request() {
        let body = json!({
            "model": MODEL_GEMINI_3_FLASH,
            "contents": [{"role": "user", "parts": [{"text": "Hi"}]}]
        });

        let result = wrap_request(&body, "test-project", MODEL_GEMINI_3_FLASH, None);
        assert_eq!(result["project"], "test-project");
        assert_eq!(result["model"], MODEL_GEMINI_3_FLASH);
        assert!(result["requestId"].as_str().unwrap().starts_with("agent-"));
    }

    #[test]
    fn test_unwrap_response() {
        let wrapped = json!({
            "response": {
                "candidates": [{"content": {"parts": [{"text": "Hello"}]}}]
            }
        });

        let result = unwrap_response(&wrapped);
        assert!(result.get("candidates").is_some());
        assert!(result.get("response").is_none());
    }

    #[test]
    fn test_antigravity_identity_injection_with_role() {
        let body = json!({
            "model": MODEL_GEMINI_PRO_ALIAS,
            "messages": []
        });

        let result = wrap_request(&body, "test-proj", MODEL_GEMINI_PRO_ALIAS, None);

        // Verify systemInstruction
        let _sys = result
            .get("request")
            .unwrap()
            .get("systemInstruction")
            .unwrap();
    }

    #[test]
    fn test_gemini_flash_thinking_budget_capping() {
        let _budget_guard = crate::proxy::config::lock_thinking_budget_for_test();
        let body = json!({
            "model": MODEL_GEMINI_3_FLASH_THINKING,
            "generationConfig": {
                "thinkingConfig": {
                    "includeThoughts": true,
                    "thinkingBudget": 32000
                }
            }
        });

        // Test with Flash model
        let result = wrap_request(&body, "test-proj", MODEL_GEMINI_3_FLASH_THINKING, None);
        let req = result.get("request").unwrap();
        let gen_config = req.get("generationConfig").unwrap();
        let budget = gen_config["thinkingConfig"]["thinkingBudget"]
            .as_u64()
            .unwrap();

        // Should be capped at 24576
        assert_eq!(budget, 24576);

        // Test with Pro model (should NOT cap)
        let body_pro = json!({
            "model": MODEL_GEMINI_3_PRO,
            "generationConfig": {
                "thinkingConfig": {
                    "includeThoughts": true,
                    "thinkingBudget": 32000
                }
            }
        });
        let result_pro = wrap_request(&body_pro, "test-proj", MODEL_GEMINI_3_PRO, None);
        let budget_pro = result_pro["request"]["generationConfig"]["thinkingConfig"]
            ["thinkingBudget"]
            .as_u64()
            .unwrap();
        // Pro models now also capped to 24576 in wrap_request logic
        assert_eq!(budget_pro, 24576);
    }

    #[test]
    fn test_user_instruction_preservation() {
        let body = json!({
            "model": MODEL_GEMINI_PRO_ALIAS,
            "systemInstruction": {
                "role": "user",
                "parts": [{"text": "User custom prompt"}]
            }
        });

        let result = wrap_request(&body, "test-proj", MODEL_GEMINI_PRO_ALIAS, None);
        let sys = result
            .get("request")
            .unwrap()
            .get("systemInstruction")
            .unwrap();
        let parts = sys.get("parts").unwrap().as_array().unwrap();

        // Should have 2 parts: Antigravity + User
        assert_eq!(parts.len(), 2);
        assert!(parts[0]
            .get("text")
            .unwrap()
            .as_str()
            .unwrap()
            .contains("You are Antigravity"));
        assert_eq!(
            parts[1].get("text").unwrap().as_str().unwrap(),
            "User custom prompt"
        );
    }

    #[test]
    fn test_duplicate_prevention() {
        let body = json!({
            "model": MODEL_GEMINI_PRO_ALIAS,
            "systemInstruction": {
                "parts": [{"text": "You are Antigravity..."}]
            }
        });

        let result = wrap_request(&body, "test-proj", MODEL_GEMINI_PRO_ALIAS, None);
        let sys = result
            .get("request")
            .unwrap()
            .get("systemInstruction")
            .unwrap();
        let parts = sys.get("parts").unwrap().as_array().unwrap();

        // Should NOT inject duplicate, so only 1 part remains
        assert_eq!(parts.len(), 1);
    }

    #[test]
    fn test_image_generation_with_reference_images() {
        // Create 14 reference images + 1 text prompt
        let mut parts = Vec::new();
        parts.push(json!({"text": "Generate a variation"}));

        for _ in 0..14 {
            parts.push(json!({
                "inlineData": {
                    "mimeType": "image/jpeg",
                    "data": "base64data..."
                }
            }));
        }

        let body = json!({
            "model": MODEL_GEMINI_3_PRO_IMAGE,
            "contents": [{"parts": parts}]
        });

        let result = wrap_request(&body, "test-proj", MODEL_GEMINI_3_PRO_IMAGE, None);

        let request = result.get("request").unwrap();
        let contents = request.get("contents").unwrap().as_array().unwrap();
        let result_parts = contents[0].get("parts").unwrap().as_array().unwrap();

        // Verify all 15 parts (1 text + 14 images) are preserved
        assert_eq!(result_parts.len(), 15);
    }

    #[test]
    fn test_gemini_pro_thinking_budget_processing() {
        let _budget_guard = crate::proxy::config::lock_thinking_budget_for_test();
        // Update global config to Custom mode to verify logic execution
        use crate::proxy::config::{ThinkingBudgetConfig, ThinkingBudgetMode, update_thinking_budget_config};
        
        // Save old config (optional, but good practice if tests ran in parallel, but here it's fine)
        update_thinking_budget_config(ThinkingBudgetConfig {
            mode: ThinkingBudgetMode::Custom,
            custom_value: 1024, // Distinct value
        });

        let body = json!({
            "model": MODEL_GEMINI_3_PRO_PREVIEW,
            "generationConfig": {
                "thinkingConfig": {
                    "includeThoughts": true,
                    "thinkingBudget": 32000
                }
            }
        });

        // Test with Pro model
        let result = wrap_request(&body, "test-proj", MODEL_GEMINI_3_PRO_PREVIEW, None);
        let req = result.get("request").unwrap();
        let gen_config = req.get("generationConfig").unwrap();
        
        let budget = gen_config["thinkingConfig"]["thinkingBudget"]
            .as_u64()
            .unwrap();

        // If logic executes, it sees Custom mode and sets 1024
        // If logic skipped, it keeps 32000
        assert_eq!(budget, 1024, "Budget should be overridden to 1024 by custom config, proving logic execution");

    }

    #[test]
    fn test_gemini_pro_auto_inject_thinking() {
        let _budget_guard = crate::proxy::config::lock_thinking_budget_for_test();
        // Reset thinking budget to auto mode at the start to avoid interference from parallel tests
        crate::proxy::config::update_thinking_budget_config(
            crate::proxy::config::ThinkingBudgetConfig {
                mode: crate::proxy::config::ThinkingBudgetMode::Auto,
                custom_value: 24576,
            }
        );

        // Request WITHOUT thinkingConfig
        let body = json!({
            "model": MODEL_GEMINI_3_PRO_PREVIEW,
            // No generationConfig or empty one
            "generationConfig": {}
        });

        // Test with Pro model
        let result = wrap_request(&body, "test-proj", MODEL_GEMINI_3_PRO_PREVIEW, None);
        let req = result.get("request").unwrap();
        let gen_config = req.get("generationConfig").unwrap();
        
        // Should have auto-injected thinkingConfig
        assert!(gen_config.get("thinkingConfig").is_some(), "Should auto-inject thinkingConfig for gemini-3-pro");
        
        let budget = gen_config["thinkingConfig"]["thinkingBudget"]
            .as_u64()
            .unwrap();
            
        // Default injected value is 1024 (based on Custom mode in previous test) or 24576 (default)
        // Since we restored default config (Auto 24576) in previous test, it should be 24576
        assert_eq!(budget, 24576);
    }

    #[test]
    fn test_openai_image_params_support() {
        // Test Case 1: Standard Size + Quality (HD/4K)
        let body_1 = json!({
            "model": MODEL_GEMINI_3_PRO_IMAGE,
            "size": "1920x1080",
            "quality": "hd",
            "prompt": "Test"
        });
        
        let result_1 = wrap_request(&body_1, "test-proj", MODEL_GEMINI_3_PRO_IMAGE, None);
        let req_1 = result_1.get("request").unwrap();
        let gen_config_1 = req_1.get("generationConfig").unwrap();
        let image_config_1 = gen_config_1.get("imageConfig").unwrap();
        
        assert_eq!(image_config_1["aspectRatio"], "16:9");
        assert_eq!(image_config_1["imageSize"], "4K");

        // Test Case 2: Aspect Ratio String + Standard Quality
        let body_2 = json!({
            "model": MODEL_GEMINI_3_PRO_IMAGE,
            "size": "1:1",
            "quality": "standard",
             "prompt": "Test"
        });
        
        let result_2 = wrap_request(&body_2, "test-proj", MODEL_GEMINI_3_PRO_IMAGE, None);
        let req_2 = result_2.get("request").unwrap();
        let image_config_2 = req_2["generationConfig"]["imageConfig"].as_object().unwrap();
        
        assert_eq!(image_config_2["aspectRatio"], "1:1");
        assert_eq!(image_config_2["imageSize"], "1K");
    }
}
