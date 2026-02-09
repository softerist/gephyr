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

    let tools_val: Option<Vec<Value>> = claude_req.tools.as_ref().map(|list| {
        list.iter()
            .map(|t| serde_json::to_value(t).unwrap_or(json!({})))
            .collect()
    });
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
    if config.inject_google_search && !ctx.has_web_search_tool {
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
    super::preprocess::deep_clean_cache_control(&mut body);
    tracing::debug!("[DEBUG-593] Final deep clean complete, request ready to send");

    Ok(body)
}
