use crate::proxy::common::model_mapping::{
    is_high_quality_grounding_candidate, is_image_generation_model, normalize_preview_alias,
    web_search_fallback_model, MODEL_GEMINI_3_PRO_IMAGE,
};
use serde_json::{json, Value};
#[derive(Debug, Clone)]
pub struct RequestConfig {
    pub request_type: String,
    pub inject_google_search: bool,
    pub final_model: String,
    pub image_config: Option<Value>,
}

pub fn resolve_request_config(
    original_model: &str,
    mapped_model: &str,
    tools: &Option<Vec<Value>>,
    size: Option<&str>,
    quality: Option<&str>,
    body: Option<&Value>,
) -> RequestConfig {
    if is_image_generation_model(mapped_model) {
        if let Some(body_val) = body {
            if let Some(gen_config) = body_val.get("generationConfig") {
                if let Some(image_config) = gen_config.get("imageConfig") {
                    tracing::info!(
                        "[Common-Utils] Parsed imageConfig from Gemini request body: {:?}",
                        image_config
                    );
                    let parsed_base_model = MODEL_GEMINI_3_PRO_IMAGE.to_string();

                    return RequestConfig {
                        request_type: "image_gen".to_string(),
                        inject_google_search: false,
                        final_model: parsed_base_model,
                        image_config: Some(image_config.clone()),
                    };
                }
            }
        }
        let (image_config, parsed_base_model) =
            parse_image_config_with_params(original_model, size, quality);

        return RequestConfig {
            request_type: "image_gen".to_string(),
            inject_google_search: false,
            final_model: parsed_base_model,
            image_config: Some(image_config),
        };
    }
    let has_networking_tool = detects_networking_tool(tools);
    let _has_non_networking = contains_non_networking_tool(tools);
    let is_online_suffix = original_model.ends_with("-online");
    let _is_high_quality_model = is_high_quality_grounding_candidate(mapped_model);
    let enable_networking = is_online_suffix || has_networking_tool;
    let mut final_model = mapped_model.trim_end_matches("-online").to_string();
    final_model = normalize_preview_alias(&final_model);

    if enable_networking && final_model != web_search_fallback_model() {
        tracing::info!(
            "[Common-Utils] Downgrading {} to {} for web search",
            final_model,
            web_search_fallback_model()
        );
        final_model = web_search_fallback_model().to_string();
    }

    RequestConfig {
        request_type: if enable_networking {
            "web_search".to_string()
        } else {
            "agent".to_string()
        },
        inject_google_search: enable_networking,
        final_model,
        image_config: None,
    }
}
#[allow(dead_code)]
pub fn parse_image_config(model_name: &str) -> (Value, String) {
    parse_image_config_with_params(model_name, None, None)
}
pub fn parse_image_config_with_params(
    model_name: &str,
    size: Option<&str>,
    quality: Option<&str>,
) -> (Value, String) {
    let mut aspect_ratio = "1:1";
    if let Some(s) = size {
        aspect_ratio = calculate_aspect_ratio_from_size(s);
    } else if model_name.contains("-21x9") || model_name.contains("-21-9") {
        aspect_ratio = "21:9";
    } else if model_name.contains("-16x9") || model_name.contains("-16-9") {
        aspect_ratio = "16:9";
    } else if model_name.contains("-9x16") || model_name.contains("-9-16") {
        aspect_ratio = "9:16";
    } else if model_name.contains("-4x3") || model_name.contains("-4-3") {
        aspect_ratio = "4:3";
    } else if model_name.contains("-3x4") || model_name.contains("-3-4") {
        aspect_ratio = "3:4";
    } else if model_name.contains("-3x2") || model_name.contains("-3-2") {
        aspect_ratio = "3:2";
    } else if model_name.contains("-2x3") || model_name.contains("-2-3") {
        aspect_ratio = "2:3";
    } else if model_name.contains("-5x4") || model_name.contains("-5-4") {
        aspect_ratio = "5:4";
    } else if model_name.contains("-4x5") || model_name.contains("-4-5") {
        aspect_ratio = "4:5";
    } else if model_name.contains("-1x1") || model_name.contains("-1-1") {
        aspect_ratio = "1:1";
    }

    let mut config = serde_json::Map::new();
    config.insert("aspectRatio".to_string(), json!(aspect_ratio));
    if let Some(q) = quality {
        match q.to_lowercase().as_str() {
            "hd" | "4k" => {
                config.insert("imageSize".to_string(), json!("4K"));
            }
            "medium" | "2k" => {
                config.insert("imageSize".to_string(), json!("2K"));
            }
            "standard" | "1k" => {
                config.insert("imageSize".to_string(), json!("1K"));
            }
            _ => {}
        }
    } else {
        let is_hd = model_name.contains("-4k") || model_name.contains("-hd");
        let is_2k = model_name.contains("-2k");

        if is_hd {
            config.insert("imageSize".to_string(), json!("4K"));
        } else if is_2k {
            config.insert("imageSize".to_string(), json!("2K"));
        }
    }
    (
        serde_json::Value::Object(config),
        MODEL_GEMINI_3_PRO_IMAGE.to_string(),
    )
}
fn calculate_aspect_ratio_from_size(size: &str) -> &'static str {
    match size {
        "21:9" => return "21:9",
        "16:9" => return "16:9",
        "9:16" => return "9:16",
        "4:3" => return "4:3",
        "3:4" => return "3:4",
        "3:2" => return "3:2",
        "2:3" => return "2:3",
        "5:4" => return "5:4",
        "4:5" => return "4:5",
        "1:1" => return "1:1",
        _ => {}
    }

    if let Some((w_str, h_str)) = size.split_once('x') {
        if let (Ok(width), Ok(height)) = (w_str.parse::<f64>(), h_str.parse::<f64>()) {
            if width > 0.0 && height > 0.0 {
                let ratio = width / height;
                if (ratio - 21.0 / 9.0).abs() < 0.05 {
                    return "21:9";
                }
                if (ratio - 16.0 / 9.0).abs() < 0.05 {
                    return "16:9";
                }
                if (ratio - 4.0 / 3.0).abs() < 0.05 {
                    return "4:3";
                }
                if (ratio - 3.0 / 4.0).abs() < 0.05 {
                    return "3:4";
                }
                if (ratio - 9.0 / 16.0).abs() < 0.05 {
                    return "9:16";
                }
                if (ratio - 3.0 / 2.0).abs() < 0.05 {
                    return "3:2";
                }
                if (ratio - 2.0 / 3.0).abs() < 0.05 {
                    return "2:3";
                }
                if (ratio - 5.0 / 4.0).abs() < 0.05 {
                    return "5:4";
                }
                if (ratio - 4.0 / 5.0).abs() < 0.05 {
                    return "4:5";
                }
                if (ratio - 1.0).abs() < 0.05 {
                    return "1:1";
                }
            }
        }
    }

    "1:1"
}
pub fn inject_google_search_tool(body: &mut Value) {
    if let Some(obj) = body.as_object_mut() {
        let tools_entry = obj.entry("tools").or_insert_with(|| json!([]));
        if let Some(tools_arr) = tools_entry.as_array_mut() {
            let has_functions = tools_arr.iter().any(|t| {
                t.as_object()
                    .is_some_and(|o| o.contains_key("functionDeclarations"))
            });

            if has_functions {
                tracing::debug!(
                    "Skipping googleSearch injection due to existing functionDeclarations"
                );
                return;
            }
            tools_arr.retain(|t| {
                if let Some(o) = t.as_object() {
                    !(o.contains_key("googleSearch") || o.contains_key("googleSearchRetrieval"))
                } else {
                    true
                }
            });
            tools_arr.push(json!({
                "googleSearch": {}
            }));
        }
    }
}
pub fn deep_clean_undefined(value: &mut Value) {
    match value {
        Value::Object(map) => {
            map.retain(|_, v| {
                if let Some(s) = v.as_str() {
                    s != "[undefined]"
                } else {
                    true
                }
            });
            for v in map.values_mut() {
                deep_clean_undefined(v);
            }
        }
        Value::Array(arr) => {
            for v in arr.iter_mut() {
                deep_clean_undefined(v);
            }
        }
        _ => {}
    }
}
pub fn detects_networking_tool(tools: &Option<Vec<Value>>) -> bool {
    if let Some(list) = tools {
        for tool in list {
            if let Some(n) = tool.get("name").and_then(|v| v.as_str()) {
                if n == "web_search"
                    || n == "google_search"
                    || n == "web_search_20250305"
                    || n == "google_search_retrieval"
                {
                    return true;
                }
            }

            if let Some(t) = tool.get("type").and_then(|v| v.as_str()) {
                if t == "web_search_20250305"
                    || t == "google_search"
                    || t == "web_search"
                    || t == "google_search_retrieval"
                {
                    return true;
                }
            }
            if let Some(func) = tool.get("function") {
                if let Some(n) = func.get("name").and_then(|v| v.as_str()) {
                    let keywords = [
                        "web_search",
                        "google_search",
                        "web_search_20250305",
                        "google_search_retrieval",
                    ];
                    if keywords.contains(&n) {
                        return true;
                    }
                }
            }
            if let Some(decls) = tool.get("functionDeclarations").and_then(|v| v.as_array()) {
                for decl in decls {
                    if let Some(n) = decl.get("name").and_then(|v| v.as_str()) {
                        if n == "web_search"
                            || n == "google_search"
                            || n == "google_search_retrieval"
                        {
                            return true;
                        }
                    }
                }
            }
            if tool.get("googleSearch").is_some() || tool.get("googleSearchRetrieval").is_some() {
                return true;
            }
        }
    }
    false
}
pub fn contains_non_networking_tool(tools: &Option<Vec<Value>>) -> bool {
    if let Some(list) = tools {
        for tool in list {
            let mut is_networking = false;
            if let Some(n) = tool.get("name").and_then(|v| v.as_str()) {
                let keywords = [
                    "web_search",
                    "google_search",
                    "web_search_20250305",
                    "google_search_retrieval",
                ];
                if keywords.contains(&n) {
                    is_networking = true;
                }
            } else if let Some(func) = tool.get("function") {
                if let Some(n) = func.get("name").and_then(|v| v.as_str()) {
                    let keywords = [
                        "web_search",
                        "google_search",
                        "web_search_20250305",
                        "google_search_retrieval",
                    ];
                    if keywords.contains(&n) {
                        is_networking = true;
                    }
                }
            } else if tool.get("googleSearch").is_some()
                || tool.get("googleSearchRetrieval").is_some()
            {
                is_networking = true;
            } else if tool.get("functionDeclarations").is_some() {
                if let Some(decls) = tool.get("functionDeclarations").and_then(|v| v.as_array()) {
                    for decl in decls {
                        if let Some(n) = decl.get("name").and_then(|v| v.as_str()) {
                            let keywords =
                                ["web_search", "google_search", "google_search_retrieval"];
                            if !keywords.contains(&n) {
                                return true;
                            }
                        }
                    }
                }
                is_networking = true;
            }

            if !is_networking {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::common::model_mapping::{
        web_search_fallback_model, MODEL_CLAUDE_SONNET_ALIAS, MODEL_GEMINI_3_FLASH,
        MODEL_GEMINI_3_PRO_IMAGE, MODEL_GPT_53_CODEX,
    };

    #[test]
    fn test_high_quality_model_auto_grounding() {
        let config = resolve_request_config(
            MODEL_GPT_53_CODEX,
            MODEL_GEMINI_3_FLASH,
            &None,
            None,
            None,
            None,
        );
        assert_eq!(config.request_type, "agent");
        assert!(!config.inject_google_search);
    }

    #[test]
    fn test_gemini_native_tool_detection() {
        let tools = Some(vec![json!({
            "functionDeclarations": [
                { "name": "web_search", "parameters": {} }
            ]
        })]);
        assert!(detects_networking_tool(&tools));
    }

    #[test]
    fn test_online_suffix_force_grounding() {
        let config = resolve_request_config(
            &format!("{}-online", MODEL_GEMINI_3_FLASH),
            MODEL_GEMINI_3_FLASH,
            &None,
            None,
            None,
            None,
        );
        assert_eq!(config.request_type, "web_search");
        assert!(config.inject_google_search);
        assert_eq!(config.final_model, web_search_fallback_model());
    }

    #[test]
    fn test_default_no_grounding() {
        let config = resolve_request_config(
            MODEL_CLAUDE_SONNET_ALIAS,
            MODEL_GEMINI_3_FLASH,
            &None,
            None,
            None,
            None,
        );
        assert_eq!(config.request_type, "agent");
        assert!(!config.inject_google_search);
    }

    #[test]
    fn test_image_model_excluded() {
        let config = resolve_request_config(
            MODEL_GEMINI_3_PRO_IMAGE,
            MODEL_GEMINI_3_PRO_IMAGE,
            &None,
            None,
            None,
            None,
        );
        assert_eq!(config.request_type, "image_gen");
        assert!(!config.inject_google_search);
    }

    #[test]
    fn test_image_2k_and_ultrawide_config() {
        let (config_2k, _) = parse_image_config(&format!("{}-2k", MODEL_GEMINI_3_PRO_IMAGE));
        assert_eq!(config_2k["imageSize"], "2K");
        let (config_21x9, _) = parse_image_config(&format!("{}-21x9", MODEL_GEMINI_3_PRO_IMAGE));
        assert_eq!(config_21x9["aspectRatio"], "21:9");
        let (config_combined, _) =
            parse_image_config(&format!("{}-2k-21x9", MODEL_GEMINI_3_PRO_IMAGE));
        assert_eq!(config_combined["imageSize"], "2K");
        assert_eq!(config_combined["aspectRatio"], "21:9");
        let (config_4k_wide, _) =
            parse_image_config(&format!("{}-4k-21x9", MODEL_GEMINI_3_PRO_IMAGE));
        assert_eq!(config_4k_wide["imageSize"], "4K");
        assert_eq!(config_4k_wide["aspectRatio"], "21:9");
    }

    #[test]
    fn test_parse_image_config_with_openai_params() {
        let (config_hd, _) =
            parse_image_config_with_params(MODEL_GEMINI_3_PRO_IMAGE, None, Some("hd"));
        assert_eq!(config_hd["imageSize"], "4K");
        assert_eq!(config_hd["aspectRatio"], "1:1");

        let (config_medium, _) =
            parse_image_config_with_params(MODEL_GEMINI_3_PRO_IMAGE, None, Some("medium"));
        assert_eq!(config_medium["imageSize"], "2K");

        let (config_standard, _) =
            parse_image_config_with_params(MODEL_GEMINI_3_PRO_IMAGE, None, Some("standard"));
        assert_eq!(config_standard["imageSize"], "1K");
        let (config_16_9, _) =
            parse_image_config_with_params(MODEL_GEMINI_3_PRO_IMAGE, Some("1280x720"), None);
        assert_eq!(config_16_9["aspectRatio"], "16:9");

        let (config_9_16, _) =
            parse_image_config_with_params(MODEL_GEMINI_3_PRO_IMAGE, Some("720x1280"), None);
        assert_eq!(config_9_16["aspectRatio"], "9:16");

        let (config_4_3, _) =
            parse_image_config_with_params(MODEL_GEMINI_3_PRO_IMAGE, Some("800x600"), None);
        assert_eq!(config_4_3["aspectRatio"], "4:3");
        let (config_combined, _) =
            parse_image_config_with_params(MODEL_GEMINI_3_PRO_IMAGE, Some("1920x1080"), Some("hd"));
        assert_eq!(config_combined["aspectRatio"], "16:9");
        assert_eq!(config_combined["imageSize"], "4K");
        let (config_compat, _) = parse_image_config_with_params(
            &format!("{}-16x9-4k", MODEL_GEMINI_3_PRO_IMAGE),
            None,
            None,
        );
        assert_eq!(config_compat["aspectRatio"], "16:9");
        assert_eq!(config_compat["imageSize"], "4K");
        let (config_override, _) = parse_image_config_with_params(
            &format!("{}-1x1-2k", MODEL_GEMINI_3_PRO_IMAGE),
            Some("1280x720"),
            Some("hd"),
        );
        assert_eq!(config_override["aspectRatio"], "16:9");
        assert_eq!(config_override["imageSize"], "4K");
    }

    #[test]
    fn test_calculate_aspect_ratio_from_size() {
        assert_eq!(calculate_aspect_ratio_from_size("1280x720"), "16:9");
        assert_eq!(calculate_aspect_ratio_from_size("1920x1080"), "16:9");
        assert_eq!(calculate_aspect_ratio_from_size("720x1280"), "9:16");
        assert_eq!(calculate_aspect_ratio_from_size("1080x1920"), "9:16");
        assert_eq!(calculate_aspect_ratio_from_size("1024x1024"), "1:1");
        assert_eq!(calculate_aspect_ratio_from_size("800x600"), "4:3");
        assert_eq!(calculate_aspect_ratio_from_size("600x800"), "3:4");
        assert_eq!(calculate_aspect_ratio_from_size("2560x1080"), "21:9");
        assert_eq!(calculate_aspect_ratio_from_size("1500x1000"), "3:2");
        assert_eq!(calculate_aspect_ratio_from_size("1000x1500"), "2:3");
        assert_eq!(calculate_aspect_ratio_from_size("1250x1000"), "5:4");
        assert_eq!(calculate_aspect_ratio_from_size("1000x1250"), "4:5");
        assert_eq!(calculate_aspect_ratio_from_size("21:9"), "21:9");
        assert_eq!(calculate_aspect_ratio_from_size("16:9"), "16:9");
        assert_eq!(calculate_aspect_ratio_from_size("1:1"), "1:1");
        assert_eq!(calculate_aspect_ratio_from_size("invalid"), "1:1");
        assert_eq!(calculate_aspect_ratio_from_size("1920x0"), "1:1");
        assert_eq!(calculate_aspect_ratio_from_size("0x1080"), "1:1");
        assert_eq!(calculate_aspect_ratio_from_size("abc x def"), "1:1");
    }
}
