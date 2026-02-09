use serde_json::{json, Value};
use super::models::V1InternalRequest;
pub fn wrap_request(
    body: &Value,
    project_id: &str,
    mapped_model: &str,
    session_id: Option<&str>,
) -> Value {
    let original_model = body
        .get("model")
        .and_then(|v| v.as_str())
        .unwrap_or(mapped_model);
    let final_model_name = if !mapped_model.is_empty() {
        mapped_model
    } else {
        original_model
    };
    let mut inner_request = body.clone();
    crate::proxy::mappers::common_utils::deep_clean_undefined(&mut inner_request);
    let is_target_claude = crate::proxy::common::model_mapping::is_claude_model(final_model_name);

    if let Some(contents) = inner_request
        .get_mut("contents")
        .and_then(|c| c.as_array_mut())
    {
        for content in contents {
            let mut name_counters: std::collections::HashMap<String, usize> =
                std::collections::HashMap::new();

            if let Some(parts) = content.get_mut("parts").and_then(|p| p.as_array_mut()) {
                for part in parts {
                    if let Some(obj) = part.as_object_mut() {
                        if let Some(fc) = obj.get_mut("functionCall") {
                            if fc.get("id").is_none() && is_target_claude {
                                let name =
                                    fc.get("name").and_then(|n| n.as_str()).unwrap_or("unknown");
                                let count = name_counters.entry(name.to_string()).or_insert(0);
                                let call_id = format!("call_{}_{}", name, count);
                                *count += 1;

                                fc.as_object_mut()
                                    .unwrap()
                                    .insert("id".to_string(), json!(call_id));
                                tracing::debug!("[Gemini-Wrap] Request stage: Injected missing call_id '{}' for Claude model", call_id);
                            }
                        }
                        if let Some(fr) = obj.get_mut("functionResponse") {
                            if fr.get("id").is_none() && is_target_claude {
                                let name =
                                    fr.get("name").and_then(|n| n.as_str()).unwrap_or("unknown");
                                let count = name_counters.entry(name.to_string()).or_insert(0);
                                let call_id = format!("call_{}_{}", name, count);
                                *count += 1;

                                fr.as_object_mut()
                                    .unwrap()
                                    .insert("id".to_string(), json!(call_id));
                                tracing::debug!("[Gemini-Wrap] Request stage: Injected synced response_id '{}' for Claude model", call_id);
                            }
                        }
                        if obj.contains_key("functionCall") && obj.get("thoughtSignature").is_none()
                        {
                            if let Some(s_id) = session_id {
                                if let Some(sig) = crate::proxy::SignatureCache::global()
                                    .get_session_signature(s_id)
                                {
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
    let lower_model = final_model_name.to_lowercase();
    if lower_model.contains("flash")
        || lower_model.contains("pro")
        || lower_model.contains("thinking")
    {
        let gen_config = inner_request
            .as_object_mut()
            .unwrap()
            .entry("generationConfig")
            .or_insert(json!({}))
            .as_object_mut()
            .unwrap();
        if gen_config.get("thinkingConfig").is_none() {
            let should_inject =
                crate::proxy::common::model_mapping::model_supports_thinking(&lower_model);

            if should_inject {
                tracing::debug!(
                    "[Gemini-Wrap] Auto-injecting default thinkingConfig for {}",
                    final_model_name
                );
                gen_config.insert(
                    "thinkingConfig".to_string(),
                    json!({
                        "includeThoughts": true,
                        "thinkingBudget": 24576
                    }),
                );
            }
        }

        if let Some(thinking_config) = gen_config.get_mut("thinkingConfig") {
            if let Some(budget_val) = thinking_config.get("thinkingBudget") {
                if let Some(budget) = budget_val.as_u64() {
                    let tb_config = crate::proxy::config::get_thinking_budget_config();
                    let final_budget = match tb_config.mode {
                        crate::proxy::config::ThinkingBudgetMode::Passthrough => {
                            tracing::debug!(
                                "[Gemini-Wrap] Passthrough mode: keeping budget {} for model {}",
                                budget,
                                final_model_name
                            );
                            budget
                        }
                        crate::proxy::config::ThinkingBudgetMode::Custom => {
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
    let tools_val: Option<Vec<Value>> = inner_request
        .get("tools")
        .and_then(|t| t.as_array())
        .cloned();
    let size = body.get("size").and_then(|v| v.as_str());
    let quality = body.get("quality").and_then(|v| v.as_str());
    let config = crate::proxy::mappers::common_utils::resolve_request_config(
        original_model,
        final_model_name,
        &tools_val,
        size,
        quality,
        Some(body),
    );
    if let Some(tools) = inner_request.get_mut("tools") {
        if let Some(tools_arr) = tools.as_array_mut() {
            for tool in tools_arr {
                if let Some(decls) = tool.get_mut("functionDeclarations") {
                    if let Some(decls_arr) = decls.as_array_mut() {
                        decls_arr.retain(|decl| {
                            if let Some(name) = decl.get("name").and_then(|v| v.as_str()) {
                                if name == "web_search" || name == "google_search" {
                                    return false;
                                }
                            }
                            true
                        });
                        for decl in decls_arr {
                            if let Some(decl_obj) = decl.as_object_mut() {
                                if let Some(params_json_schema) =
                                    decl_obj.remove("parametersJsonSchema")
                                {
                                    let mut params = params_json_schema;
                                    crate::proxy::common::json_schema::clean_json_schema(
                                        &mut params,
                                    );
                                    decl_obj.insert("parameters".to_string(), params);
                                } else if let Some(params) = decl_obj.get_mut("parameters") {
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
    if config.inject_google_search {
        crate::proxy::mappers::common_utils::inject_google_search_tool(&mut inner_request);
    }
    if let Some(image_config) = config.image_config {
        if let Some(obj) = inner_request.as_object_mut() {
            obj.remove("tools");
            obj.remove("systemInstruction");
            if let Some(contents) = obj.get_mut("contents").and_then(|c| c.as_array_mut()) {
                for content in contents {
                    if let Some(c_obj) = content.as_object_mut() {
                        if !c_obj.contains_key("role") {
                            c_obj.insert("role".to_string(), json!("user"));
                        }
                    }
                }
            }
            let gen_config = obj.entry("generationConfig").or_insert_with(|| json!({}));
            if let Some(gen_obj) = gen_config.as_object_mut() {
                gen_obj.remove("responseMimeType");
                gen_obj.remove("responseModalities");
                gen_obj.insert("imageConfig".to_string(), image_config);
            }
        }
    } else {
        let antigravity_identity = "You are Antigravity, a powerful agentic AI coding assistant designed by the Google Deepmind team working on Advanced Agentic Coding.\n\
        You are pair programming with a USER to solve their coding task. The task may require creating a new codebase, modifying or debugging an existing codebase, or simply answering a question.\n\
        **Absolute paths only**\n\
        **Proactiveness**";
        if let Some(system_instruction) = inner_request.get_mut("systemInstruction") {
            if let Some(obj) = system_instruction.as_object_mut() {
                if !obj.contains_key("role") {
                    obj.insert("role".to_string(), json!("user"));
                }
            }

            if let Some(parts) = system_instruction.get_mut("parts") {
                if let Some(parts_array) = parts.as_array_mut() {
                    let has_antigravity = parts_array
                        .first()
                        .and_then(|p| p.get("text"))
                        .and_then(|t| t.as_str())
                        .map(|s| s.contains("You are Antigravity"))
                        .unwrap_or(false);

                    if !has_antigravity {
                        parts_array.insert(0, json!({"text": antigravity_identity}));
                    }
                }
            }
        } else {
            inner_request["systemInstruction"] = json!({
                "role": "user",
                "parts": [{"text": antigravity_identity}]
            });
        }
    }

    let final_request = V1InternalRequest {
        project: project_id.to_string(),
        request_id: format!("agent-{}", uuid::Uuid::new_v4()),
        request: inner_request,
        model: config.final_model,
        user_agent: "antigravity".to_string(),
        request_type: config.request_type,
    };

    serde_json::to_value(final_request).unwrap_or_else(|_| json!({}))
}

#[cfg(test)]
mod test_fixes {
    use super::*;
    use crate::proxy::common::model_mapping::MODEL_GEMINI_PRO_ALIAS;
    use serde_json::json;

    #[test]
    fn test_wrap_request_with_signature() {
        let session_id = "test-session-sig";
        let signature = "test-signature-must-be-longer-than-fifty-characters-to-be-cached-by-signature-cache-12345";
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
pub fn unwrap_response(response: &Value) -> Value {
    response.get("response").unwrap_or(response).clone()
}
pub fn inject_ids_to_response(response: &mut Value, model_name: &str) {
    if !crate::proxy::common::model_mapping::is_claude_model(model_name) {
        return;
    }

    if let Some(candidates) = response
        .get_mut("candidates")
        .and_then(|c| c.as_array_mut())
    {
        for candidate in candidates {
            if let Some(parts) = candidate
                .get_mut("content")
                .and_then(|c| c.get_mut("parts"))
                .and_then(|p| p.as_array_mut())
            {
                let mut name_counters: std::collections::HashMap<String, usize> =
                    std::collections::HashMap::new();
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
    use crate::proxy::common::model_mapping::{
        MODEL_GEMINI_3_FLASH, MODEL_GEMINI_3_FLASH_THINKING, MODEL_GEMINI_3_PRO,
        MODEL_GEMINI_3_PRO_IMAGE, MODEL_GEMINI_3_PRO_PREVIEW, MODEL_GEMINI_PRO_ALIAS,
    };
    use serde_json::json;

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
        let result = wrap_request(&body, "test-proj", MODEL_GEMINI_3_FLASH_THINKING, None);
        let req = result.get("request").unwrap();
        let gen_config = req.get("generationConfig").unwrap();
        let budget = gen_config["thinkingConfig"]["thinkingBudget"]
            .as_u64()
            .unwrap();
        assert_eq!(budget, 24576);
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
        assert_eq!(parts.len(), 1);
    }

    #[test]
    fn test_image_generation_with_reference_images() {
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
        assert_eq!(result_parts.len(), 15);
    }

    #[test]
    fn test_gemini_pro_thinking_budget_processing() {
        let _budget_guard = crate::proxy::config::lock_thinking_budget_for_test();
        use crate::proxy::config::{
            update_thinking_budget_config, ThinkingBudgetConfig, ThinkingBudgetMode,
        };
        update_thinking_budget_config(ThinkingBudgetConfig {
            mode: ThinkingBudgetMode::Custom,
            custom_value: 1024,
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
        let result = wrap_request(&body, "test-proj", MODEL_GEMINI_3_PRO_PREVIEW, None);
        let req = result.get("request").unwrap();
        let gen_config = req.get("generationConfig").unwrap();

        let budget = gen_config["thinkingConfig"]["thinkingBudget"]
            .as_u64()
            .unwrap();
        assert_eq!(
            budget, 1024,
            "Budget should be overridden to 1024 by custom config, proving logic execution"
        );
    }

    #[test]
    fn test_gemini_pro_auto_inject_thinking() {
        let _budget_guard = crate::proxy::config::lock_thinking_budget_for_test();
        crate::proxy::config::update_thinking_budget_config(
            crate::proxy::config::ThinkingBudgetConfig {
                mode: crate::proxy::config::ThinkingBudgetMode::Auto,
                custom_value: 24576,
            },
        );
        let body = json!({
            "model": MODEL_GEMINI_3_PRO_PREVIEW,
            "generationConfig": {}
        });
        let result = wrap_request(&body, "test-proj", MODEL_GEMINI_3_PRO_PREVIEW, None);
        let req = result.get("request").unwrap();
        let gen_config = req.get("generationConfig").unwrap();
        assert!(
            gen_config.get("thinkingConfig").is_some(),
            "Should auto-inject thinkingConfig for gemini-3-pro"
        );

        let budget = gen_config["thinkingConfig"]["thinkingBudget"]
            .as_u64()
            .unwrap();
        assert_eq!(budget, 24576);
    }

    #[test]
    fn test_openai_image_params_support() {
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
        let body_2 = json!({
            "model": MODEL_GEMINI_3_PRO_IMAGE,
            "size": "1:1",
            "quality": "standard",
             "prompt": "Test"
        });

        let result_2 = wrap_request(&body_2, "test-proj", MODEL_GEMINI_3_PRO_IMAGE, None);
        let req_2 = result_2.get("request").unwrap();
        let image_config_2 = req_2["generationConfig"]["imageConfig"]
            .as_object()
            .unwrap();

        assert_eq!(image_config_2["aspectRatio"], "1:1");
        assert_eq!(image_config_2["imageSize"], "1K");
    }
}
