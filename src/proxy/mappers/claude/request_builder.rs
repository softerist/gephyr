use crate::proxy::mappers::claude::models::Tool;
use serde_json::{json, Value};
use std::collections::HashMap;

pub(super) fn build_request_body(
    ctx: &super::context::RequestContext,
    project_id: &str,
    is_retry: bool,
) -> Result<Value, String> {
    let claude_req = &ctx.cleaned_req;
    let mut tool_id_to_name: HashMap<String, String> = HashMap::new();

    let system_instruction =
        super::thinking::build_system_instruction(&claude_req.system, ctx.has_mcp_tools);
    let tools_val = serialize_tools(&claude_req.tools);
    let config = crate::proxy::mappers::common_utils::resolve_request_config(
        &claude_req.model,
        &ctx.mapped_model,
        &tools_val,
        claude_req.size.as_deref(),
        claude_req.quality.as_deref(),
        None,
    );

    let generation_config = super::generation::build_generation_config(
        claude_req,
        &ctx.mapped_model,
        ctx.has_web_search_tool,
        ctx.is_thinking_enabled,
    );
    let contents = super::content::build_google_contents(
        &claude_req.messages,
        &mut tool_id_to_name,
        &ctx.tool_name_to_schema,
        super::content::GoogleContentsOptions {
            is_thinking_enabled: ctx.is_thinking_enabled,
            allow_dummy_thought: ctx.allow_dummy_thought,
            mapped_model: &ctx.mapped_model,
            session_id: &ctx.session_id,
            is_retry,
        },
    )?;
    let tools = super::generation::build_tools(&claude_req.tools, ctx.has_web_search_tool)?;
    let safety_settings = super::generation::build_safety_settings();
    let mut inner_request = build_inner_request(contents, safety_settings);
    apply_system_instruction(&mut inner_request, system_instruction);
    apply_generation_config(&mut inner_request, generation_config);
    apply_tools(&mut inner_request, tools);

    if config.inject_google_search && !ctx.has_web_search_tool {
        crate::proxy::mappers::common_utils::inject_google_search_tool(&mut inner_request);
    }
    if let Some(image_config) = config.image_config.clone() {
        apply_image_config(&mut inner_request, image_config);
    }

    let mut body = build_outer_body(project_id, inner_request, &config);
    if let Some(metadata) = &claude_req.metadata {
        if let Some(user_id) = &metadata.user_id {
            body["request"]["sessionId"] = json!(user_id);
        }
    }
    super::preprocess::deep_clean_cache_control(&mut body);
    tracing::debug!("[DEBUG-593] Final deep clean complete, request ready to send");

    Ok(body)
}

fn serialize_tools(tools: &Option<Vec<Tool>>) -> Option<Vec<Value>> {
    tools.as_ref().map(|list| {
        list.iter()
            .map(|t| serde_json::to_value(t).unwrap_or(json!({})))
            .collect()
    })
}

fn build_inner_request(contents: Value, safety_settings: Value) -> Value {
    let mut inner_request = json!({
        "contents": contents,
        "safetySettings": safety_settings,
    });
    crate::proxy::mappers::common_utils::deep_clean_undefined(&mut inner_request);
    inner_request
}

fn apply_system_instruction(inner_request: &mut Value, system_instruction: Option<Value>) {
    if let Some(sys_inst) = system_instruction {
        inner_request["systemInstruction"] = sys_inst;
    }
}

fn apply_generation_config(inner_request: &mut Value, generation_config: Value) {
    if !generation_config.is_null() {
        inner_request["generationConfig"] = generation_config;
    }
}

fn apply_tools(inner_request: &mut Value, tools: Option<Value>) {
    if let Some(tools_val) = tools {
        inner_request["tools"] = tools_val;
        inner_request["toolConfig"] = json!({
            "functionCallingConfig": {
                "mode": "VALIDATED"
            }
        });
    }
}

fn apply_image_config(inner_request: &mut Value, image_config: Value) {
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

fn build_outer_body(
    project_id: &str,
    inner_request: Value,
    config: &crate::proxy::mappers::common_utils::RequestConfig,
) -> Value {
    let request_id = format!("agent-{}", uuid::Uuid::new_v4());
    json!({
        "project": project_id,
        "requestId": request_id,
        "request": inner_request,
        "model": config.final_model,
        "userAgent": "antigravity",
        "requestType": config.request_type,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_tools_sets_tools_and_validated_mode() {
        let mut inner = json!({});
        apply_tools(&mut inner, Some(json!([{"functionDeclarations": []}])));

        assert!(inner.get("tools").is_some());
        assert_eq!(
            inner["toolConfig"]["functionCallingConfig"]["mode"],
            json!("VALIDATED")
        );
    }

    #[test]
    fn apply_image_config_removes_text_tooling_fields_and_sets_image_config() {
        let mut inner = json!({
            "tools": [{"functionDeclarations": []}],
            "systemInstruction": {"parts":[{"text":"x"}]},
            "generationConfig": {
                "responseMimeType": "application/json",
                "responseModalities": ["TEXT"],
                "temperature": 0.2
            }
        });
        let image_cfg = json!({"aspectRatio":"16:9","imageSize":"2K"});

        apply_image_config(&mut inner, image_cfg.clone());

        assert!(inner.get("tools").is_none());
        assert!(inner.get("systemInstruction").is_none());
        assert_eq!(inner["generationConfig"]["imageConfig"], image_cfg);
        assert!(inner["generationConfig"].get("responseMimeType").is_none());
        assert!(inner["generationConfig"]
            .get("responseModalities")
            .is_none());
        assert_eq!(inner["generationConfig"]["temperature"], json!(0.2));
    }

    #[test]
    fn build_outer_body_contains_required_envelope_fields() {
        let cfg = crate::proxy::mappers::common_utils::RequestConfig {
            request_type: "agent".to_string(),
            inject_google_search: false,
            final_model: "gemini-3.0-flash".to_string(),
            image_config: None,
        };
        let inner = json!({"contents":[]});

        let body = build_outer_body("project-1", inner.clone(), &cfg);

        assert_eq!(body["project"], json!("project-1"));
        assert_eq!(body["request"], inner);
        assert_eq!(body["model"], json!("gemini-3.0-flash"));
        assert_eq!(body["requestType"], json!("agent"));
        let request_id = body["requestId"].as_str().unwrap_or_default();
        assert!(request_id.starts_with("agent-"));
    }

    #[test]
    fn build_inner_request_cleans_undefined_markers() {
        let contents = json!([{
            "role":"user",
            "parts":[{"text":"ok","junk":"[undefined]"}]
        }]);
        let safety = json!([{"category":"HARM_CATEGORY_HARASSMENT","threshold":"OFF"}]);

        let built = build_inner_request(contents, safety);

        assert!(built["contents"][0]["parts"][0].get("junk").is_none());
        assert!(built.get("safetySettings").is_some());
    }
}
