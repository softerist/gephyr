use super::models::*;

use serde_json::{json, Value};

pub fn transform_openai_request(
    request: &OpenAIRequest,
    project_id: &str,
    mapped_model: &str,
) -> (Value, String, usize) {
    let session_id =
        crate::proxy::session_manager::SessionManager::extract_openai_session_id(request);
    let message_count = request.messages.len();
    let tools_val = request.tools.as_ref().map(|list| list.to_vec());

    let mapped_model_lower = mapped_model.to_lowercase();
    let config = crate::proxy::mappers::common_utils::resolve_request_config(
        &request.model,
        &mapped_model_lower,
        &tools_val,
        request.size.as_deref(),
        request.quality.as_deref(),
        None,
    );
    let is_gemini_thinking =
        !crate::proxy::common::model_mapping::is_claude_model(&mapped_model_lower)
            && crate::proxy::common::model_mapping::model_supports_thinking(&mapped_model_lower);
    let is_claude_thinking =
        crate::proxy::common::model_mapping::is_claude_model(&mapped_model_lower)
            && mapped_model_lower.ends_with("-thinking");
    let is_thinking_model = is_gemini_thinking || is_claude_thinking;
    let user_enabled_thinking = request
        .thinking
        .as_ref()
        .map(|t| t.thinking_type.as_deref() == Some("enabled"))
        .unwrap_or(false);
    let user_thinking_budget = request.thinking.as_ref().and_then(|t| t.budget_tokens);
    let has_incompatible_assistant_history = request.messages.iter().any(|msg| {
        msg.role == "assistant"
            && msg
                .reasoning_content
                .as_ref()
                .map(|s| s.is_empty())
                .unwrap_or(true)
    });
    let has_tool_history = request
        .messages
        .iter()
        .any(|msg| msg.role == "tool" || msg.role == "function" || msg.tool_calls.is_some());
    let mut actual_include_thinking = is_thinking_model || user_enabled_thinking;
    let session_thought_sig =
        crate::proxy::SignatureCache::global().get_session_signature(&session_id);

    if is_claude_thinking && has_incompatible_assistant_history && session_thought_sig.is_none() {
        tracing::warn!("[OpenAI-Thinking] Incompatible assistant history detected for Claude thinking model without session signature. Disabling thinking for this request to avoid 400 error. (sid: {})", session_id);
        actual_include_thinking = false;
    }
    if user_enabled_thinking {
        crate::modules::system::logger::log_info(&format!(
            "[OpenAI-Thinking] User explicitly enabled thinking with budget: {:?}",
            user_thinking_budget
        ));
    }

    tracing::debug!(
        " OpenAI Request: original='{}', mapped='{}', type='{}', has_image_config={}",
        request.model,
        mapped_model,
        config.request_type,
        config.image_config.is_some()
    );
    let mut system_instructions: Vec<String> = request
        .messages
        .iter()
        .filter(|msg| msg.role == "system" || msg.role == "developer")
        .filter_map(|msg| {
            msg.content.as_ref().map(|c| match c {
                OpenAIContent::String(s) => s.clone(),
                OpenAIContent::Array(blocks) => blocks
                    .iter()
                    .filter_map(|b| {
                        if let OpenAIContentBlock::Text { text } = b {
                            Some(text.clone())
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("\n"),
            })
        })
        .collect();
    if let Some(inst) = &request.instructions {
        if !inst.is_empty() {
            system_instructions.insert(0, inst.clone());
        }
    }
    let mut tool_id_to_name = std::collections::HashMap::new();
    for msg in &request.messages {
        if let Some(tool_calls) = &msg.tool_calls {
            for call in tool_calls {
                let name = &call.function.name;
                let final_name = if name == "local_shell_call" {
                    "shell"
                } else {
                    name
                };
                tool_id_to_name.insert(call.id.clone(), final_name.to_string());
            }
        }
    }
    let thought_sig = session_thought_sig;
    if let Some(sig) = &thought_sig {
        tracing::debug!(
            "[OpenAI-Request] Using session signature (sid: {}, len: {})",
            session_id,
            sig.len()
        );
    }
    let mut tool_name_to_schema = std::collections::HashMap::new();
    if let Some(tools) = &request.tools {
        for tool in tools {
            if let (Some(name), Some(params)) = (
                tool.get("function")
                    .and_then(|f| f.get("name"))
                    .and_then(|v| v.as_str()),
                tool.get("function").and_then(|f| f.get("parameters")),
            ) {
                tool_name_to_schema.insert(name.to_string(), params.clone());
            } else if let (Some(name), Some(params)) = (
                tool.get("name").and_then(|v| v.as_str()),
                tool.get("parameters"),
            ) {
                tool_name_to_schema.insert(name.to_string(), params.clone());
            }
        }
    }
    let contents: Vec<Value> = request
        .messages
        .iter()
        .filter(|msg| msg.role != "system" && msg.role != "developer")
        .map(|msg| {
            let role = match msg.role.as_str() {
                "assistant" => "model",
                "tool" | "function" => "user",
                _ => &msg.role,
            };

            let mut parts = Vec::new();
            if let Some(reasoning) = &msg.reasoning_content {
                let is_invalid_placeholder = reasoning == "[undefined]" || reasoning.is_empty();

                if !is_invalid_placeholder {
                    let thought_part = json!({
                        "text": reasoning,
                        "thought": true,
                    });
                    parts.push(thought_part);
                }
            } else if actual_include_thinking && role == "model" {
                tracing::debug!("[OpenAI-Thinking] Injecting placeholder thinking block for assistant message");
                let mut thought_part = json!({
                    "text": "Applying tool decisions and generating response...",
                    "thought": true,
                });
                if is_gemini_thinking {
                    thought_part["thoughtSignature"] = json!("skip_thought_signature_validator");
                }

                parts.push(thought_part);
            }
            let is_tool_role = msg.role == "tool" || msg.role == "function";
            if let (Some(content), false) = (&msg.content, is_tool_role) {
                match content {
                    OpenAIContent::String(s) => {
                        if !s.is_empty() {
                            parts.push(json!({"text": s}));
                        }
                    }
                    OpenAIContent::Array(blocks) => {
                        for block in blocks {
                            match block {
                                OpenAIContentBlock::Text { text } => {
                                    parts.push(json!({"text": text}));
                                }
                                OpenAIContentBlock::ImageUrl { image_url } => {
                                    if image_url.url.starts_with("data:") {
                                        if let Some(pos) = image_url.url.find(",") {
                                            let mime_part = &image_url.url[5..pos];
                                            let mime_type = mime_part.split(';').next().unwrap_or("image/jpeg");
                                            let data = &image_url.url[pos + 1..];

                                            parts.push(json!({
                                                "inlineData": { "mimeType": mime_type, "data": data }
                                            }));
                                        }
                                    } else if image_url.url.starts_with("http") {
                                        parts.push(json!({
                                            "fileData": { "fileUri": &image_url.url, "mimeType": "image/jpeg" }
                                        }));
                                    } else {
                                        let file_path = if image_url.url.starts_with("file://") {
                                            #[cfg(target_os = "windows")]
                                            { image_url.url.trim_start_matches("file://").replace('/', "\\") }
                                            #[cfg(not(target_os = "windows"))]
                                            { image_url.url.trim_start_matches("file://").to_string() }
                                        } else {
                                            image_url.url.clone()
                                        };

                                        tracing::debug!("[OpenAI-Request] Reading local image: {}", file_path);
                                        if let Ok(file_bytes) = std::fs::read(&file_path) {
                                            use base64::Engine as _;
                                            let b64 = base64::engine::general_purpose::STANDARD.encode(&file_bytes);
                                            let mime_type = if file_path.to_lowercase().ends_with(".png") {
                                                "image/png"
                                            } else if file_path.to_lowercase().ends_with(".gif") {
                                                "image/gif"
                                            } else if file_path.to_lowercase().ends_with(".webp") {
                                                "image/webp"
                                            } else {
                                                "image/jpeg"
                                            };

                                            parts.push(json!({
                                                "inlineData": { "mimeType": mime_type, "data": b64 }
                                            }));
                                            tracing::debug!("[OpenAI-Request] Successfully loaded image: {} ({} bytes)", file_path, file_bytes.len());
                                        } else {
                                            tracing::debug!("[OpenAI-Request] Failed to read local image: {}", file_path);
                                        }
                                    }
                                }
                                OpenAIContentBlock::AudioUrl { audio_url: _ } => {
                                    tracing::debug!("[OpenAI-Request] Skipping audio_url (not yet implemented in v3.3.16)");
                                }
                            }
                        }
                    }
                }
            }
            if let Some(tool_calls) = &msg.tool_calls {
                for tc in tool_calls.iter() {



                    let mut args = serde_json::from_str::<Value>(&tc.function.arguments).unwrap_or(json!({}));
                    if let Some(original_schema) = tool_name_to_schema.get(&tc.function.name) {
                        crate::proxy::common::json_schema::fix_tool_call_args(&mut args, original_schema);
                    }

                    let mut func_call_part = json!({
                        "functionCall": {
                            "name": if tc.function.name == "local_shell_call" { "shell" } else { &tc.function.name },
                            "args": args,
                            "id": &tc.id,
                        }
                    });
                    crate::proxy::common::json_schema::clean_json_schema(&mut func_call_part);

                    if let Some(ref sig) = thought_sig {
                        func_call_part["thoughtSignature"] = json!(sig);
                    } else if is_thinking_model {
                        tracing::debug!("[OpenAI-Signature] Adding GEMINI_SKIP_SIGNATURE for tool_use: {}", tc.id);
                        func_call_part["thoughtSignature"] = json!("skip_thought_signature_validator");
                    }

                    parts.push(func_call_part);
                }
            }
            if msg.role == "tool" || msg.role == "function" {
                let name = msg.name.as_deref().unwrap_or("unknown");
                let final_name = if name == "local_shell_call" { "shell" }
                                else if let Some(id) = &msg.tool_call_id { tool_id_to_name.get(id).map(|s| s.as_str()).unwrap_or(name) }
                                else { name };

                let content_val = match &msg.content {
                    Some(OpenAIContent::String(s)) => s.clone(),
                    Some(OpenAIContent::Array(blocks)) => blocks.iter().filter_map(|b| if let OpenAIContentBlock::Text { text } = b { Some(text.clone()) } else { None }).collect::<Vec<_>>().join("\n"),
                    None => "".to_string()
                };

                parts.push(json!({
                    "functionResponse": {
                       "name": final_name,
                       "response": { "result": content_val },
                       "id": msg.tool_call_id.clone().unwrap_or_default()
                    }
                }));
            }

            json!({ "role": role, "parts": parts })
        })
        .filter(|msg| !msg["parts"].as_array().map(|a| a.is_empty()).unwrap_or(true))
        .collect();
    let mut contents = contents;
    if actual_include_thinking && has_tool_history {
        tracing::debug!("[OpenAI-Thinking] Applied thinking recovery (stripping old thought blocks) for tool history");
        contents = super::thinking_recovery::strip_all_thinking_blocks(contents);
    }
    let mut merged_contents: Vec<Value> = Vec::new();
    for msg in contents {
        if let Some(last) = merged_contents.last_mut() {
            if last["role"] == msg["role"] {
                if let (Some(last_parts), Some(msg_parts)) =
                    (last["parts"].as_array_mut(), msg["parts"].as_array())
                {
                    last_parts.extend(msg_parts.iter().cloned());
                    continue;
                }
            }
        }
        merged_contents.push(msg);
    }
    let contents = merged_contents;

    let mut gen_config = json!({
        "temperature": request.temperature.unwrap_or(1.0),
        "topP": request.top_p.unwrap_or(0.95),
    });
    if let Some(max_tokens) = request.max_tokens {
        gen_config["maxOutputTokens"] = json!(max_tokens);
    }
    if let Some(n) = request.n {
        gen_config["candidateCount"] = json!(n);
    }
    if actual_include_thinking {
        let tb_config = crate::proxy::config::get_thinking_budget_config();
        let user_budget: i64 = user_thinking_budget.map(|b| b as i64).unwrap_or(24576);

        let budget = match tb_config.mode {
            crate::proxy::config::ThinkingBudgetMode::Passthrough => {
                tracing::debug!(
                    "[OpenAI-Request] Passthrough mode: using caller's budget {}",
                    user_budget
                );
                user_budget
            }
            crate::proxy::config::ThinkingBudgetMode::Custom => {
                let mut custom_value = tb_config.custom_value as i64;
                let is_gemini_limited = mapped_model_lower.contains("gemini") || is_claude_thinking;

                if is_gemini_limited && custom_value > 24576 {
                    tracing::warn!(
                        "[OpenAI-Request] Custom mode: capping thinking_budget from {} to 24576 for Gemini model {}",
                        custom_value, mapped_model
                    );
                    custom_value = 24576;
                }

                tracing::debug!(
                    "[OpenAI-Request] Custom mode: overriding {} with fixed value {}",
                    user_budget,
                    custom_value
                );
                custom_value
            }
            crate::proxy::config::ThinkingBudgetMode::Auto => {
                let is_gemini_limited = mapped_model_lower.contains("gemini") || is_claude_thinking;

                if is_gemini_limited && user_budget > 24576 {
                    tracing::info!(
                        "[OpenAI-Request] Auto mode: capping thinking budget from {} to 24576 for model: {}",
                        user_budget, mapped_model
                    );
                    24576
                } else {
                    user_budget
                }
            }
        };

        gen_config["thinkingConfig"] = json!({
            "includeThoughts": true,
            "thinkingBudget": budget
        });
        let current_max = gen_config["maxOutputTokens"].as_i64().unwrap_or(0);
        if current_max <= budget {
            let new_max = budget + 8192;
            gen_config["maxOutputTokens"] = json!(new_max);
            tracing::debug!(
                "[OpenAI-Request] Adjusted maxOutputTokens to {} for thinking model (budget={})",
                new_max,
                budget
            );
        }

        tracing::debug!(
            "[OpenAI-Request] Injected thinkingConfig for model {}: thinkingBudget={} (mode={:?})",
            mapped_model,
            budget,
            tb_config.mode
        );
    }

    if let Some(stop) = &request.stop {
        if stop.is_string() {
            gen_config["stopSequences"] = json!([stop]);
        } else if stop.is_array() {
            gen_config["stopSequences"] = stop.clone();
        }
    }

    if let Some(fmt) = &request.response_format {
        if fmt.r#type == "json_object" {
            gen_config["responseMimeType"] = json!("application/json");
        }
    }

    let mut inner_request = json!({
        "contents": contents,
        "generationConfig": gen_config,
        "safetySettings": [
            { "category": "HARM_CATEGORY_HARASSMENT", "threshold": "OFF" },
            { "category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "OFF" },
            { "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "OFF" },
            { "category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "OFF" },
            { "category": "HARM_CATEGORY_CIVIC_INTEGRITY", "threshold": "OFF" },
        ]
    });
    crate::proxy::mappers::common_utils::deep_clean_undefined(&mut inner_request);
    if let Some(tools) = &request.tools {
        let mut function_declarations: Vec<Value> = Vec::new();
        for tool in tools.iter() {
            let mut gemini_func = if let Some(func) = tool.get("function") {
                func.clone()
            } else {
                let mut func = tool.clone();
                if let Some(obj) = func.as_object_mut() {
                    obj.remove("type");
                    obj.remove("strict");
                    obj.remove("additionalProperties");
                }
                func
            };

            let name_opt = gemini_func
                .get("name")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            if let Some(name) = &name_opt {
                if name == "web_search" || name == "google_search" || name == "web_search_20250305"
                {
                    continue;
                }

                if name == "local_shell_call" {
                    if let Some(obj) = gemini_func.as_object_mut() {
                        obj.insert("name".to_string(), json!("shell"));
                    }
                }
            } else {
                tracing::warn!(
                    "[OpenAI-Request] Skipping tool without name: {:?}",
                    gemini_func
                );
                continue;
            }
            if let Some(obj) = gemini_func.as_object_mut() {
                obj.remove("format");
                obj.remove("strict");
                obj.remove("additionalProperties");
                obj.remove("type");
                obj.remove("external_web_access");
            }

            if let Some(params) = gemini_func.get_mut("parameters") {
                crate::proxy::common::json_schema::clean_json_schema(params);
                if let Some(params_obj) = params.as_object_mut() {
                    if !params_obj.contains_key("type") {
                        params_obj.insert("type".to_string(), json!("OBJECT"));
                    }
                }
                enforce_uppercase_types(params);
            } else {
                tracing::debug!(
                    "[OpenAI-Request] Injecting default schema for custom tool: {}",
                    gemini_func
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown")
                );

                gemini_func.as_object_mut().unwrap().insert(
                    "parameters".to_string(),
                    json!({
                        "type": "OBJECT",
                        "properties": {
                            "content": {
                                "type": "STRING",
                                "description": "The raw content or patch to be applied"
                            }
                        },
                        "required": ["content"]
                    }),
                );
            }
            function_declarations.push(gemini_func);
        }

        if !function_declarations.is_empty() {
            inner_request["tools"] = json!([{ "functionDeclarations": function_declarations }]);
        }
    }
    let antigravity_identity = "You are Antigravity, a powerful agentic AI coding assistant designed by the Google Deepmind team working on Advanced Agentic Coding.\n\
    You are pair programming with a USER to solve their coding task. The task may require creating a new codebase, modifying or debugging an existing codebase, or simply answering a question.\n\
    **Absolute paths only**\n\
    **Proactiveness**";
    let user_has_antigravity = system_instructions
        .iter()
        .any(|s| s.contains("You are Antigravity"));

    let mut parts = Vec::new();
    if !user_has_antigravity {
        parts.push(json!({"text": antigravity_identity}));
    }
    for inst in system_instructions {
        parts.push(json!({"text": inst}));
    }

    inner_request["systemInstruction"] = json!({
        "role": "user",
        "parts": parts
    });

    if config.inject_google_search {
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

    let final_body = json!({
        "project": project_id,
        "requestId": format!("openai-{}", uuid::Uuid::new_v4()),
        "request": inner_request,
        "model": config.final_model,
        "userAgent": "antigravity",
        "requestType": config.request_type
    });

    (final_body, session_id, message_count)
}

fn enforce_uppercase_types(value: &mut Value) {
    if let Value::Object(map) = value {
        if let Some(Value::String(s)) = map.get_mut("type") {
            *s = s.to_uppercase();
        }
        if let Some(Value::Object(props)) = map.get_mut("properties") {
            for v in props.values_mut() {
                enforce_uppercase_types(v);
            }
        }
        if let Some(items) = map.get_mut("items") {
            enforce_uppercase_types(items);
        }
    } else if let Value::Array(arr) = value {
        for item in arr {
            enforce_uppercase_types(item);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::common::model_mapping::{
        MODEL_CLAUDE_SONNET_45, MODEL_CLAUDE_SONNET_45_THINKING, MODEL_GEMINI_3_FLASH,
        MODEL_GEMINI_3_FLASH_THINKING, MODEL_GEMINI_3_PRO, MODEL_GEMINI_3_PRO_HIGH_THINKING,
        MODEL_GEMINI_3_PRO_PREVIEW, MODEL_GPT_5,
    };

    #[test]
    fn gemini_3_pro_budget_capping() {
        let _budget_guard = crate::proxy::config::lock_thinking_budget_for_test();
        let req = OpenAIRequest {
            model: MODEL_GEMINI_3_PRO.to_string(),
            messages: vec![OpenAIMessage {
                role: "user".to_string(),
                content: Some(OpenAIContent::String("test".into())),
                reasoning_content: None,
                tool_calls: None,
                tool_call_id: None,
                name: None,
            }],
            stream: false,
            n: None,
            max_tokens: None,
            temperature: None,
            top_p: None,
            stop: None,
            response_format: None,
            tools: None,
            tool_choice: None,
            parallel_tool_calls: None,
            instructions: None,
            input: None,
            prompt: None,
            size: None,
            quality: None,
            person_generation: None,
            thinking: None,
        };
        let (result, _sid, _msg_count) =
            transform_openai_request(&req, "test-v", MODEL_GEMINI_3_PRO);
        let budget = result["request"]["generationConfig"]["thinkingConfig"]["thinkingBudget"]
            .as_i64()
            .unwrap();
        assert_eq!(
            budget, 24576,
            "Gemini-3-pro budget must be capped to 24576 in Auto mode"
        );
    }

    #[test]
    fn custom_mode_gemini_capping() {
        let _budget_guard = crate::proxy::config::lock_thinking_budget_for_test();
        use crate::proxy::config::{
            update_thinking_budget_config, ThinkingBudgetConfig, ThinkingBudgetMode,
        };
        update_thinking_budget_config(ThinkingBudgetConfig {
            mode: ThinkingBudgetMode::Custom,
            custom_value: 32000,
        });

        let req = OpenAIRequest {
            model: MODEL_GEMINI_3_FLASH_THINKING.to_string(),
            messages: vec![OpenAIMessage {
                role: "user".to_string(),
                content: Some(OpenAIContent::String("test".into())),
                reasoning_content: None,
                tool_calls: None,
                tool_call_id: None,
                name: None,
            }],
            stream: false,
            n: None,
            max_tokens: None,
            temperature: None,
            top_p: None,
            stop: None,
            response_format: None,
            tools: None,
            tool_choice: None,
            parallel_tool_calls: None,
            instructions: None,
            input: None,
            prompt: None,
            size: None,
            quality: None,
            person_generation: None,
            thinking: None,
        };
        let (result, _sid, _msg_count) =
            transform_openai_request(&req, "test-v", MODEL_GEMINI_3_FLASH_THINKING);
        let budget = result["request"]["generationConfig"]["thinkingConfig"]["thinkingBudget"]
            .as_i64()
            .unwrap();
        assert_eq!(
            budget, 24576,
            "Gemini custom budget must be capped to 24576"
        );
        let (result_claude, _, _) =
            transform_openai_request(&req, "test-v", MODEL_CLAUDE_SONNET_45);
        let _budget_claude = result_claude["request"]["generationConfig"]["thinkingConfig"]
            ["thinkingBudget"]
            .as_i64();
    }

    #[test]
    fn test_transform_openai_request_multimodal() {
        let req = OpenAIRequest {
            model: MODEL_GPT_5.to_string(),
            messages: vec![OpenAIMessage {
                role: "user".to_string(),
                content: Some(OpenAIContent::Array(vec![
                    OpenAIContentBlock::Text { text: "What is in this image?".to_string() },
                    OpenAIContentBlock::ImageUrl { image_url: OpenAIImageUrl {
                        url: "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==".to_string(),
                        detail: None
                    } }
                ])),
                reasoning_content: None,
                tool_calls: None,
                tool_call_id: None,
                name: None,
            }],
            stream: false,
            n: None,
            max_tokens: None,
            temperature: None,
            top_p: None,
            stop: None,
            response_format: None,
            tools: None,
            tool_choice: None,
            parallel_tool_calls: None,
            instructions: None,
            input: None,
            prompt: None,
            size: None,
            quality: None,
            person_generation: None,
            thinking: None,
        };

        let (result, _sid, _msg_count) =
            transform_openai_request(&req, "test-v", MODEL_GEMINI_3_FLASH);
        let parts = &result["request"]["contents"][0]["parts"];
        assert_eq!(parts.as_array().unwrap().len(), 2);
        assert_eq!(parts[0]["text"].as_str().unwrap(), "What is in this image?");
        assert_eq!(
            parts[1]["inlineData"]["mimeType"].as_str().unwrap(),
            "image/png"
        );
    }

    #[test]
    fn test_gemini_pro_thinking_injection() {
        let _budget_guard = crate::proxy::config::lock_thinking_budget_for_test();
        let req = OpenAIRequest {
            model: MODEL_GEMINI_3_PRO_PREVIEW.to_string(),
            messages: vec![OpenAIMessage {
                role: "user".to_string(),
                content: Some(OpenAIContent::String("Thinking test".to_string())),
                reasoning_content: None,
                tool_calls: None,
                tool_call_id: None,
                name: None,
            }],
            stream: false,
            n: None,
            thinking: Some(ThinkingConfig {
                thinking_type: Some("enabled".to_string()),
                budget_tokens: Some(16000),
            }),
            max_tokens: None,
            temperature: None,
            top_p: None,
            stop: None,
            response_format: None,
            tools: None,
            tool_choice: None,
            parallel_tool_calls: None,
            instructions: None,
            input: None,
            prompt: None,
            size: None,
            quality: None,
            person_generation: None,
        };
        let (result, _sid, _msg_count) =
            transform_openai_request(&req, "test-p", MODEL_GEMINI_3_PRO_PREVIEW);
        let gen_config = &result["request"]["generationConfig"];
        assert!(
            gen_config.get("thinkingConfig").is_some(),
            "thinkingConfig should be injected for gemini-3-pro"
        );

        let budget = gen_config["thinkingConfig"]["thinkingBudget"]
            .as_u64()
            .unwrap();
        assert_eq!(budget, 16000);
    }
    #[test]
    fn test_default_max_tokens_openai() {
        let _budget_guard = crate::proxy::config::lock_thinking_budget_for_test();
        let req = OpenAIRequest {
            model: MODEL_GPT_5.to_string(),
            messages: vec![OpenAIMessage {
                role: "user".to_string(),
                content: Some(OpenAIContent::String("Hello".to_string())),
                reasoning_content: None,
                tool_calls: None,
                tool_call_id: None,
                name: None,
            }],
            stream: false,
            n: None,
            max_tokens: None,
            temperature: None,
            top_p: None,
            stop: None,
            response_format: None,
            tools: None,
            tool_choice: None,
            parallel_tool_calls: None,
            instructions: None,
            input: None,
            prompt: None,
            size: None,
            quality: None,
            person_generation: None,
            thinking: None,
        };

        let (result, _sid, _msg_count) =
            transform_openai_request(&req, "test-p", MODEL_GEMINI_3_PRO_HIGH_THINKING);
        let gen_config = &result["request"]["generationConfig"];
        let max_output_tokens = gen_config["maxOutputTokens"].as_i64().unwrap();
        assert_eq!(max_output_tokens, 32768);
        let budget = gen_config["thinkingConfig"]["thinkingBudget"]
            .as_i64()
            .unwrap();
        assert_eq!(budget, 24576);
    }

    #[test]
    fn test_flash_thinking_budget_capping() {
        let _budget_guard = crate::proxy::config::lock_thinking_budget_for_test();
        let req = OpenAIRequest {
            model: MODEL_GPT_5.to_string(),
            messages: vec![OpenAIMessage {
                role: "user".to_string(),
                content: Some(OpenAIContent::String("Hello".to_string())),
                reasoning_content: None,
                tool_calls: None,
                tool_call_id: None,
                name: None,
            }],
            stream: false,
            n: None,
            thinking: Some(ThinkingConfig {
                thinking_type: Some("enabled".to_string()),
                budget_tokens: Some(32768),
            }),
            max_tokens: None,
            temperature: None,
            top_p: None,
            stop: None,
            response_format: None,
            tools: None,
            tool_choice: None,
            parallel_tool_calls: None,
            instructions: None,
            input: None,
            prompt: None,
            size: None,
            quality: None,
            person_generation: None,
        };
        let (result, _sid, _msg_count) =
            transform_openai_request(&req, "test-p", MODEL_GEMINI_3_FLASH_THINKING);
        let gen_config = &result["request"]["generationConfig"];
        let budget = gen_config["thinkingConfig"]["thinkingBudget"]
            .as_i64()
            .unwrap();
        assert_eq!(budget, 24576);
        let max_output = gen_config["maxOutputTokens"].as_i64().unwrap();
        assert_eq!(max_output, 32768);
    }
    #[test]
    fn test_vertex_ai_sentinel_injection() {
        let req = OpenAIRequest {
            model: MODEL_CLAUDE_SONNET_45_THINKING.to_string(),
            messages: vec![OpenAIMessage {
                role: "assistant".to_string(),
                content: None,
                reasoning_content: Some("Thinking...".to_string()),
                tool_calls: Some(vec![ToolCall {
                    id: "call_123".to_string(),
                    r#type: "function".to_string(),
                    function: ToolFunction {
                        name: "test_tool".to_string(),
                        arguments: "{}".to_string(),
                    },
                }]),
                tool_call_id: None,
                name: None,
            }],
            stream: false,
            n: None,
            max_tokens: None,
            temperature: None,
            top_p: None,
            stop: None,
            response_format: None,
            tools: Some(vec![json!({
                "type": "function",
                "function": {
                    "name": "test_tool",
                    "description": "Test tool",
                    "parameters": {
                        "type": "object",
                        "properties": {}
                    }
                }
            })]),
            tool_choice: None,
            parallel_tool_calls: None,
            instructions: None,
            input: None,
            prompt: None,
            size: None,
            quality: None,
            person_generation: None,
            thinking: None,
        };
        let mapped_model = format!(
            "projects/my-project/locations/us-central1/publishers/google/models/{}",
            MODEL_GEMINI_3_FLASH_THINKING
        );

        let (result, _sid, _msg_count) = transform_openai_request(&req, "test-v", &mapped_model);
        let contents = result["request"]["contents"].as_array().unwrap();
        let parts = contents[0]["parts"].as_array().unwrap();
        let tool_part = parts
            .iter()
            .find(|p| p.get("functionCall").is_some())
            .expect("Should find functionCall part");

        assert_eq!(tool_part["functionCall"]["name"], "test_tool");
        assert_eq!(
            tool_part["thoughtSignature"], "skip_thought_signature_validator",
            "Vertex AI model must have sentinel signature injected"
        );
    }
}
