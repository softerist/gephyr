use crate::proxy::mappers::claude::models::*;
use serde_json::{json, Value};

#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) enum SafetyThreshold {
    Off,
    BlockLowAndAbove,
    BlockMediumAndAbove,
    BlockOnlyHigh,
    BlockNone,
}

impl SafetyThreshold {
    pub(super) fn from_env() -> Self {
        match std::env::var("GEMINI_SAFETY_THRESHOLD").as_deref() {
            Ok("OFF") | Ok("off") => SafetyThreshold::Off,
            Ok("LOW") | Ok("low") => SafetyThreshold::BlockLowAndAbove,
            Ok("MEDIUM") | Ok("medium") => SafetyThreshold::BlockMediumAndAbove,
            Ok("HIGH") | Ok("high") => SafetyThreshold::BlockOnlyHigh,
            Ok("NONE") | Ok("none") => SafetyThreshold::BlockNone,
            _ => SafetyThreshold::Off,
        }
    }
    pub(super) fn to_gemini_threshold(self) -> &'static str {
        match self {
            SafetyThreshold::Off => "OFF",
            SafetyThreshold::BlockLowAndAbove => "BLOCK_LOW_AND_ABOVE",
            SafetyThreshold::BlockMediumAndAbove => "BLOCK_MEDIUM_AND_ABOVE",
            SafetyThreshold::BlockOnlyHigh => "BLOCK_ONLY_HIGH",
            SafetyThreshold::BlockNone => "BLOCK_NONE",
        }
    }
}

pub(super) fn build_safety_settings() -> Value {
    let threshold = SafetyThreshold::from_env();
    let threshold_str = threshold.to_gemini_threshold();

    json!([
        { "category": "HARM_CATEGORY_HARASSMENT", "threshold": threshold_str },
        { "category": "HARM_CATEGORY_HATE_SPEECH", "threshold": threshold_str },
        { "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": threshold_str },
        { "category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": threshold_str },
        { "category": "HARM_CATEGORY_CIVIC_INTEGRITY", "threshold": threshold_str },
    ])
}

pub(super) fn build_tools(
    tools: &Option<Vec<Tool>>,
    has_web_search: bool,
) -> Result<Option<Value>, String> {
    if let Some(tools_list) = tools {
        let mut function_declarations: Vec<Value> = Vec::new();
        let mut has_google_search = has_web_search;

        for tool in tools_list {
            if tool.is_web_search() {
                has_google_search = true;
                continue;
            }

            if let Some(t_type) = &tool.type_ {
                if t_type == "web_search_20250305" {
                    has_google_search = true;
                    continue;
                }
            }
            if let Some(name) = &tool.name {
                if name == "web_search" || name == "google_search" {
                    has_google_search = true;
                    continue;
                }
                let mut input_schema = tool.input_schema.clone().unwrap_or(json!({
                    "type": "object",
                    "properties": {}
                }));
                crate::proxy::common::json_schema::clean_json_schema(&mut input_schema);

                function_declarations.push(json!({
                    "name": name,
                    "description": tool.description,
                    "parameters": input_schema
                }));
            }
        }

        let mut tool_obj = serde_json::Map::new();
        if !function_declarations.is_empty() {
            tool_obj.insert(
                "functionDeclarations".to_string(),
                json!(function_declarations),
            );
            if has_google_search {
                tracing::info!(
                    "[Claude-Request] Skipping googleSearch injection due to {} existing function declarations. \
                     Gemini v1internal does not support mixed tool types.",
                    function_declarations.len()
                );
            }
        } else if has_google_search {
            tool_obj.insert("googleSearch".to_string(), json!({}));
        }

        if !tool_obj.is_empty() {
            return Ok(Some(json!([tool_obj])));
        }
    }

    Ok(None)
}

pub(super) fn build_generation_config(
    claude_req: &ClaudeRequest,
    mapped_model: &str,
    has_web_search: bool,
    is_thinking_enabled: bool,
) -> Value {
    let mut config = json!({});
    if is_thinking_enabled {
        let mut thinking_config = json!({"includeThoughts": true});
        let budget_tokens = claude_req
            .thinking
            .as_ref()
            .and_then(|t| t.budget_tokens)
            .unwrap_or(16000);

        let tb_config = crate::proxy::config::get_thinking_budget_config();
        let budget = match tb_config.mode {
            crate::proxy::config::ThinkingBudgetMode::Passthrough => budget_tokens,
            crate::proxy::config::ThinkingBudgetMode::Custom => {
                let mut custom_value = tb_config.custom_value;
                let model_lower = mapped_model.to_lowercase();
                let is_gemini_limited = has_web_search
                    || model_lower.contains("gemini")
                    || model_lower.contains("flash")
                    || model_lower.ends_with("-thinking");

                if is_gemini_limited && custom_value > 24576 {
                    tracing::warn!(
                        "[Claude-Request] Custom mode: capping thinking_budget from {} to 24576 for Gemini model {}",
                        custom_value, mapped_model
                    );
                    custom_value = 24576;
                }
                custom_value
            }
            crate::proxy::config::ThinkingBudgetMode::Auto => {
                let model_lower = mapped_model.to_lowercase();
                let is_gemini_limited = has_web_search
                    || model_lower.contains("gemini")
                    || model_lower.contains("flash")
                    || model_lower.ends_with("-thinking");
                if is_gemini_limited && budget_tokens > 24576 {
                    tracing::info!(
                        "[Claude-Request] Auto mode: capping thinking_budget from {} to 24576 for Gemini model {}",
                        budget_tokens, mapped_model
                    );
                    24576
                } else {
                    budget_tokens
                }
            }
        };
        thinking_config["thinkingBudget"] = json!(budget);
        config["thinkingConfig"] = thinking_config;
    }
    if let Some(temp) = claude_req.temperature {
        config["temperature"] = json!(temp);
    }
    if let Some(top_p) = claude_req.top_p {
        config["topP"] = json!(top_p);
    }
    if let Some(top_k) = claude_req.top_k {
        config["topK"] = json!(top_k);
    }
    if let Some(output_config) = &claude_req.output_config {
        if let Some(effort) = &output_config.effort {
            config["effortLevel"] = json!(match effort.to_lowercase().as_str() {
                "high" => "HIGH",
                "medium" => "MEDIUM",
                "low" => "LOW",
                _ => "HIGH",
            });
            tracing::debug!(
                "[Generation-Config] Effort level set: {} -> {}",
                effort,
                config["effortLevel"]
            );
        }
    }
    let mut final_max_tokens: Option<i64> = claude_req.max_tokens.map(|t| t as i64);
    if let Some(thinking_config) = config.get("thinkingConfig") {
        if let Some(budget) = thinking_config
            .get("thinkingBudget")
            .and_then(|t| t.as_u64())
        {
            let current = final_max_tokens.unwrap_or(0);
            if current <= budget as i64 {
                final_max_tokens = Some((budget + 8192) as i64);
                tracing::info!(
                    "[Generation-Config] Bumping maxOutputTokens to {} due to thinking budget of {}",
                    final_max_tokens.unwrap(),
                    budget
                );
            }
        }
    }

    if let Some(val) = final_max_tokens {
        config["maxOutputTokens"] = json!(val);
    }
    config["stopSequences"] = json!(["<|user|>", "<|end_of_turn|>", "\n\nHuman:"]);

    config
}

pub(super) fn clean_thinking_fields_recursive(val: &mut Value) {
    match val {
        Value::Object(map) => {
            map.remove("thought");
            map.remove("thoughtSignature");
            for (_, v) in map.iter_mut() {
                clean_thinking_fields_recursive(v);
            }
        }
        Value::Array(arr) => {
            for v in arr.iter_mut() {
                clean_thinking_fields_recursive(v);
            }
        }
        _ => {}
    }
}
