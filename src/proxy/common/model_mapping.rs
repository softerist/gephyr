// Model name mapping
use std::collections::HashMap;
use once_cell::sync::Lazy;

static CLAUDE_TO_GEMINI: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
    let mut m = HashMap::new();

    // Directly supported models
    m.insert("claude-opus-4-5-thinking", "claude-opus-4-5-thinking");
    m.insert("claude-sonnet-4-5", "claude-sonnet-4-5");
    m.insert("claude-sonnet-4-5-thinking", "claude-sonnet-4-5-thinking");

    // Alias mapping
    m.insert("claude-sonnet-4-5-20250929", "claude-sonnet-4-5-thinking");
    m.insert("claude-3-5-sonnet-20241022", "claude-sonnet-4-5");
    m.insert("claude-3-5-sonnet-20240620", "claude-sonnet-4-5");
    m.insert("claude-opus-4", "claude-opus-4-5-thinking");
    m.insert("claude-opus-4-5-20251101", "claude-opus-4-5-thinking");

    // Claude Opus 4.6 (nuevo modelo thinking)
    m.insert("claude-opus-4-6-thinking", "claude-opus-4-6-thinking");
    m.insert("claude-opus-4-6", "claude-opus-4-6-thinking");
    m.insert("claude-opus-4-6-20260201", "claude-opus-4-6-thinking");

    m.insert("claude-haiku-4", "claude-sonnet-4-5");
    m.insert("claude-3-haiku-20240307", "claude-sonnet-4-5");
    m.insert("claude-haiku-4-5-20251001", "claude-sonnet-4-5");
    // OpenAI protocol mapping table
    m.insert("gpt-4", "gemini-2.5-flash");
    m.insert("gpt-4-turbo", "gemini-2.5-flash");
    m.insert("gpt-4-turbo-preview", "gemini-2.5-flash");
    m.insert("gpt-4-0125-preview", "gemini-2.5-flash");
    m.insert("gpt-4-1106-preview", "gemini-2.5-flash");
    m.insert("gpt-4-0613", "gemini-2.5-flash");

    m.insert("gpt-4o", "gemini-2.5-flash");
    m.insert("gpt-4o-2024-05-13", "gemini-2.5-flash");
    m.insert("gpt-4o-2024-08-06", "gemini-2.5-flash");

    m.insert("gpt-4o-mini", "gemini-2.5-flash");
    m.insert("gpt-4o-mini-2024-07-18", "gemini-2.5-flash");

    m.insert("gpt-3.5-turbo", "gemini-2.5-flash");
    m.insert("gpt-3.5-turbo-16k", "gemini-2.5-flash");
    m.insert("gpt-3.5-turbo-0125", "gemini-2.5-flash");
    m.insert("gpt-3.5-turbo-1106", "gemini-2.5-flash");
    m.insert("gpt-3.5-turbo-0613", "gemini-2.5-flash");

    // Gemini protocol mapping table
    m.insert("gemini-2.5-flash-lite", "gemini-2.5-flash");
    m.insert("gemini-2.5-flash-thinking", "gemini-2.5-flash-thinking");
    m.insert("gemini-3-pro-low", "gemini-3-pro-preview");
    m.insert("gemini-3-pro-high", "gemini-3-pro-preview");
    m.insert("gemini-3-pro-preview", "gemini-3-pro-preview");
    m.insert("gemini-3-pro", "gemini-3-pro-preview");  // Unified mapping to preview
    m.insert("gemini-2.5-flash", "gemini-2.5-flash");
    m.insert("gemini-3-flash", "gemini-3-flash");
    m.insert("gemini-3-pro-image", "gemini-3-pro-image");

    //  Unified Virtual ID for Background Tasks (Title, Summary, etc.)
    // Allows users to override all background tasks via custom_mapping
    m.insert("internal-background-task", "gemini-2.5-flash");


    m
});


// Map Claude model names to Gemini model names
// 
// # Mapping Strategy
// 1. **Exact Match**: Check the CLAUDE_TO_GEMINI mapping table
// 2. **Known Prefix Pass-through**: gemini-* and *-thinking models are passed through directly
// 3. ** Direct Pass-through**: Unknown model IDs are passed directly to the Google API (supporting trial of unreleased models)
// 
// # Parameters
// - `input`: Original model name
// 
// # Returns
// Mapped target model name
// 
// # Examples
// ```
// // Exact match
// assert_eq!(map_claude_model_to_gemini("claude-opus-4"), "claude-opus-4-5-thinking");
// 
// // Gemini model pass-through
// assert_eq!(map_claude_model_to_gemini("gemini-2.5-flash"), "gemini-2.5-flash");
// 
// // Direct pass-through for unknown models (NEW!)
// assert_eq!(map_claude_model_to_gemini("claude-opus-4-6"), "claude-opus-4-6");
// assert_eq!(map_claude_model_to_gemini("claude-sonnet-5"), "claude-sonnet-5");
// ```
pub fn map_claude_model_to_gemini(input: &str) -> String {
    // 1. Check exact match in map
    if let Some(mapped) = CLAUDE_TO_GEMINI.get(input) {
        return mapped.to_string();
    }

    // 2. Pass-through known prefixes (gemini-, -thinking) to support dynamic suffixes
    if input.starts_with("gemini-") || input.contains("thinking") {
        return input.to_string();
    }


    // 3. [ENHANCED] Pass through unknown model IDs directly instead of forcing fallback
    // This allows users to experience unreleased models (e.g., claude-opus-4-6) via custom mapping
    // The Google API will automatically handle invalid models and return errors; users can adjust mapping based on the errors
    input.to_string()
}

// Get all built-in supported model list keywords
pub fn get_supported_models() -> Vec<String> {
    CLAUDE_TO_GEMINI.keys().map(|s| s.to_string()).collect()
}

// Dynamically get listing of all available models (including built-in and user-custom)
pub async fn get_all_dynamic_models(
    custom_mapping: &tokio::sync::RwLock<std::collections::HashMap<String, String>>,
) -> Vec<String> {
    use std::collections::HashSet;
    let mut model_ids = HashSet::new();

    // 1. Get all built-in mapped models
    for m in get_supported_models() {
        model_ids.insert(m);
    }

    // 2. Get all custom mapped models (Custom)
    {
        let mapping = custom_mapping.read().await;
        for key in mapping.keys() {
            model_ids.insert(key.clone());
        }
    }

    // 5. Ensure common Gemini/drawing model IDs are included
    model_ids.insert("gemini-3-pro-low".to_string());
    
    // Dynamically generate all Image Gen Combinations
    let base = "gemini-3-pro-image";
    let resolutions = vec!["", "-2k", "-4k"];
    let ratios = vec!["", "-1x1", "-4x3", "-3x4", "-16x9", "-9x16", "-21x9"];
    
    for res in resolutions {
        for ratio in ratios.iter() {
            let mut id = base.to_string();
            id.push_str(res);
            id.push_str(ratio);
            model_ids.insert(id);
        }
    }

    model_ids.insert("gemini-2.0-flash-exp".to_string());
    model_ids.insert("gemini-2.5-flash".to_string());
    // gemini-2.5-pro removed 
    model_ids.insert("gemini-3-flash".to_string());
    model_ids.insert("gemini-3-pro-high".to_string());
    model_ids.insert("gemini-3-pro-low".to_string());


    let mut sorted_ids: Vec<_> = model_ids.into_iter().collect();
    sorted_ids.sort();
    sorted_ids
}

// Wildcard matching - supports multiple wildcards
//
// **Note**: Matching is **case-sensitive**. Pattern `GPT-4*` will NOT match `gpt-4-turbo`.
//
// Examples:
// - `gpt-4*` matches `gpt-4`, `gpt-4-turbo` ✓
// - `claude-*-sonnet-*` matches `claude-3-5-sonnet-20241022` ✓
// - `*-thinking` matches `claude-opus-4-5-thinking` ✓
// - `a*b*c` matches `a123b456c` ✓
fn wildcard_match(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();

    // No wildcard - exact match
    if parts.len() == 1 {
        return pattern == text;
    }

    let mut text_pos = 0;

    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue; // Skip empty segments from consecutive wildcards
        }

        if i == 0 {
            // First segment must match start
            if !text[text_pos..].starts_with(part) {
                return false;
            }
            text_pos += part.len();
        } else if i == parts.len() - 1 {
            // Last segment must match end
            return text[text_pos..].ends_with(part);
        } else {
            // Middle segments - find next occurrence
            if let Some(pos) = text[text_pos..].find(part) {
                text_pos += pos + part.len();
            } else {
                return false;
            }
        }
    }

    true
}

// Core model routing resolution engine
// Priority: Exact match > Wildcard match > System default mapping
// 
// # Parameters
// - `original_model`: Original model name
// - `custom_mapping`: User-defined mapping table
// 
// # Returns
// Mapped target model name
pub fn resolve_model_route(
    original_model: &str,
    custom_mapping: &std::collections::HashMap<String, String>,
) -> String {
    // 1. Exact match (highest priority)
    if let Some(target) = custom_mapping.get(original_model) {
        crate::modules::logger::log_info(&format!("[Router] Exact mapping: {} -> {}", original_model, target));
        return target.clone();
    }
    
    // 2. Wildcard match - most specific (highest non-wildcard chars) wins
    // Note: When multiple patterns have the SAME specificity, HashMap iteration order
    // determines the result (non-deterministic). Users can avoid this by making patterns
    // more specific. Future improvement: use IndexMap + frontend sorting for full control.
    let mut best_match: Option<(&str, &str, usize)> = None;

    for (pattern, target) in custom_mapping.iter() {
        if pattern.contains('*') && wildcard_match(pattern, original_model) {
            let specificity = pattern.chars().count() - pattern.matches('*').count();
            if best_match.is_none() || specificity > best_match.unwrap().2 {
                best_match = Some((pattern.as_str(), target.as_str(), specificity));
            }
        }
    }

    if let Some((pattern, target, _)) = best_match {
        crate::modules::logger::log_info(&format!(
            "[Router] Wildcard match: {} -> {} (rule: {})",
            original_model, target, pattern
        ));
        return target.to_string();
    }
    
    // 3. System default mapping
    let result = map_claude_model_to_gemini(original_model);
    if result != original_model {
        crate::modules::logger::log_info(&format!("[Router] System default mapping: {} -> {}", original_model, result));
    }
    result
}

// Normalize any physical model name to one of the 3 standard protection IDs.
// This ensures quota protection works consistently regardless of API versioning or request variations.
// 
// Standard IDs:
// - `gemini-3-flash`: All Flash variants (1.5-flash, 2.5-flash, 3-flash, etc.)
// - `gemini-3-pro-high`: All Pro variants (1.5-pro, 2.5-pro, etc.)
// - `claude-sonnet-4-5`: All Claude Sonnet variants (3-5-sonnet, sonnet-4-5, etc.)
// 
// Returns `None` if the model doesn't match any of the 3 protected categories.
pub fn normalize_to_standard_id(model_name: &str) -> Option<String> {
    //  Strict matching based on user-defined groups (Case Insensitive)
    let lower = model_name.to_lowercase();
    match lower.as_str() {
        // Gemini 3 Flash Group
        "gemini-3-flash" => Some("gemini-3-flash".to_string()),

        // Gemini 3 Pro High Group
        "gemini-3-pro-high" | "gemini-3-pro-low" => Some("gemini-3-pro-high".to_string()),

        // Claude 4.5 Sonnet Group (includes Opus 4.5 and 4.6)
        "claude-sonnet-4-5" | "claude-sonnet-4-5-thinking" | "claude-opus-4-5-thinking" | "claude-opus-4-6-thinking" => Some("claude-sonnet-4-5".to_string()),

        _ => None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_model_mapping() {
        assert_eq!(
            map_claude_model_to_gemini("claude-3-5-sonnet-20241022"),
            "claude-sonnet-4-5"
        );
        assert_eq!(
            map_claude_model_to_gemini("claude-opus-4"),
            "claude-opus-4-5-thinking"
        );
        // Test gemini pass-through (should not be caught by "mini" rule)
        assert_eq!(
            map_claude_model_to_gemini("gemini-2.5-flash-mini-test"),
            "gemini-2.5-flash-mini-test"
        );
        assert_eq!(
            map_claude_model_to_gemini("unknown-model"),
            "unknown-model"
        );
    }

    #[test]
    fn test_wildcard_priority() {
        let mut custom = HashMap::new();
        custom.insert("gpt*".to_string(), "fallback".to_string());
        custom.insert("gpt-4*".to_string(), "specific".to_string());
        custom.insert("claude-opus-*".to_string(), "opus-default".to_string());
        custom.insert("claude-opus*thinking".to_string(), "opus-thinking".to_string());

        // More specific pattern wins
        assert_eq!(resolve_model_route("gpt-4-turbo", &custom), "specific");
        assert_eq!(resolve_model_route("gpt-3.5", &custom), "fallback");
        // Suffix constraint is more specific than prefix-only
        assert_eq!(resolve_model_route("claude-opus-4-5-thinking", &custom), "opus-thinking");
        assert_eq!(resolve_model_route("claude-opus-4", &custom), "opus-default");
    }

    #[test]
    fn test_multi_wildcard_support() {
        let mut custom = HashMap::new();
        custom.insert("claude-*-sonnet-*".to_string(), "sonnet-versioned".to_string());
        custom.insert("gpt-*-*".to_string(), "gpt-multi".to_string());
        custom.insert("*thinking*".to_string(), "has-thinking".to_string());

        // Multi-wildcard patterns should work
        assert_eq!(
            resolve_model_route("claude-3-5-sonnet-20241022", &custom),
            "sonnet-versioned"
        );
        assert_eq!(
            resolve_model_route("gpt-4-turbo-preview", &custom),
            "gpt-multi"
        );
        assert_eq!(
            resolve_model_route("claude-thinking-extended", &custom),
            "has-thinking"
        );

        // Negative case: *thinking* should NOT match models without "thinking"
        assert_eq!(
            resolve_model_route("random-model-name", &custom),
            "random-model-name"  // Falls back to system default (pass-through)
        );
    }

    #[test]
    fn test_wildcard_edge_cases() {
        let mut custom = HashMap::new();
        custom.insert("prefix*".to_string(), "prefix-match".to_string());
        custom.insert("*".to_string(), "catch-all".to_string());
        custom.insert("a*b*c".to_string(), "multi-wild".to_string());

        // Specificity: "prefix*" (6) > "*" (0)
        assert_eq!(resolve_model_route("prefix-anything", &custom), "prefix-match");
        // Catch-all has lowest specificity
        assert_eq!(resolve_model_route("random-model", &custom), "catch-all");
        // Multi-wildcard: "a*b*c" (3)
        assert_eq!(resolve_model_route("a-test-b-foo-c", &custom), "multi-wild");
    }
}
