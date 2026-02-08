// Model name mapping
use std::collections::HashMap;
use once_cell::sync::Lazy;

pub const MODEL_GEMINI_3_FLASH: &str = "gemini-3-flash";
pub const MODEL_GEMINI_3_FLASH_PREVIEW: &str = "gemini-3-flash-preview";
pub const MODEL_GEMINI_3_FLASH_THINKING: &str = "gemini-3-flash-thinking";
pub const MODEL_GEMINI_30_FLASH: &str = "gemini-3.0-flash";
pub const MODEL_GEMINI_30_FLASH_THINKING: &str = "gemini-3.0-flash-thinking";
pub const MODEL_GEMINI_30_PRO: &str = "gemini-3.0-pro";
pub const MODEL_GEMINI_30_PRO_THINKING: &str = "gemini-3.0-pro-thinking";
pub const MODEL_GEMINI_30_ULTRA: &str = "gemini-3.0-ultra";
pub const MODEL_GEMINI_3_PRO: &str = "gemini-3-pro";
pub const MODEL_GEMINI_3_PRO_LOW: &str = "gemini-3-pro-low";
pub const MODEL_GEMINI_3_PRO_HIGH: &str = "gemini-3-pro-high";
pub const MODEL_GEMINI_3_PRO_PREVIEW: &str = "gemini-3-pro-preview";
pub const MODEL_GEMINI_3_PRO_IMAGE: &str = "gemini-3-pro-image";
pub const MODEL_GEMINI_3_PRO_IMAGE_PREVIEW: &str = "gemini-3-pro-image-preview";
pub const MODEL_GEMINI_PRO_ALIAS: &str = "gemini-pro";
pub const MODEL_GEMINI_3_PRO_HIGH_THINKING: &str = "gemini-3-pro-high-thinking";

pub const MODEL_CLAUDE_SONNET_45: &str = "claude-sonnet-4-5";
pub const MODEL_CLAUDE_SONNET_45_THINKING: &str = "claude-sonnet-4-5-thinking";
pub const MODEL_CLAUDE_SONNET_46: &str = "claude-sonnet-4-6";
pub const MODEL_CLAUDE_SONNET_46_THINKING: &str = "claude-sonnet-4-6-thinking";
pub const MODEL_CLAUDE_OPUS_45: &str = "claude-opus-4-5";
pub const MODEL_CLAUDE_OPUS_45_THINKING: &str = "claude-opus-4-5-thinking";
pub const MODEL_CLAUDE_OPUS_46: &str = "claude-opus-4-6";
pub const MODEL_CLAUDE_OPUS_46_THINKING: &str = "claude-opus-4-6-thinking";
pub const MODEL_CLAUDE_HAIKU_45: &str = "claude-haiku-4-5";
pub const MODEL_GPT_5: &str = "gpt-5";
pub const MODEL_GPT_53_CODEX: &str = "gpt-5.3-codex";
pub const MODEL_CLAUDE_SONNET_ALIAS: &str = "claude-sonnet";

pub const MODEL_INTERNAL_BACKGROUND_TASK: &str = "internal-background-task";

pub const DEFAULT_WARMUP_MODELS: &[&str] = &[
    MODEL_GEMINI_3_FLASH,
    MODEL_CLAUDE_SONNET_45,
    MODEL_GEMINI_3_PRO_HIGH,
    MODEL_GEMINI_3_PRO_IMAGE,
];

pub const DEFAULT_QUOTA_MONITORED_MODELS: &[&str] = &[
    MODEL_CLAUDE_SONNET_45,
    MODEL_GEMINI_3_PRO_HIGH,
    MODEL_GEMINI_3_FLASH,
    MODEL_GEMINI_3_PRO_IMAGE,
];

pub const DEFAULT_PINNED_QUOTA_MODELS: &[&str] = &[
    MODEL_GEMINI_3_PRO_HIGH,
    MODEL_GEMINI_3_FLASH,
    MODEL_GEMINI_3_PRO_IMAGE,
    MODEL_CLAUDE_SONNET_45_THINKING,
];

pub const OPENCODE_ANTHROPIC_MODELS: &[&str] = &[
    MODEL_CLAUDE_SONNET_45,
    MODEL_CLAUDE_SONNET_45_THINKING,
    MODEL_CLAUDE_OPUS_45_THINKING,
];

pub const OPENCODE_GOOGLE_MODELS: &[&str] = &[
    MODEL_GEMINI_3_PRO_HIGH,
    MODEL_GEMINI_3_PRO_LOW,
    MODEL_GEMINI_3_FLASH,
    MODEL_GEMINI_30_FLASH,
    MODEL_GEMINI_30_FLASH_THINKING,
    MODEL_GEMINI_30_PRO,
    MODEL_GEMINI_30_PRO_THINKING,
    MODEL_GEMINI_30_ULTRA,
    MODEL_GEMINI_3_PRO_IMAGE,
];

pub fn model_list_to_vec(models: &[&str]) -> Vec<String> {
    models.iter().map(|m| (*m).to_string()).collect()
}

pub fn default_warmup_models() -> Vec<String> {
    model_list_to_vec(DEFAULT_WARMUP_MODELS)
}

pub fn default_quota_monitored_models() -> Vec<String> {
    model_list_to_vec(DEFAULT_QUOTA_MONITORED_MODELS)
}

pub fn default_pinned_quota_models() -> Vec<String> {
    model_list_to_vec(DEFAULT_PINNED_QUOTA_MODELS)
}

pub fn is_openai_gpt_model(model: &str) -> bool {
    model.to_ascii_lowercase().starts_with("gpt-")
}

pub fn is_gemini_model(model: &str) -> bool {
    let lower = model.to_ascii_lowercase();
    lower.starts_with("gemini-") || lower == "gemini"
}

pub fn is_claude_model(model: &str) -> bool {
    let lower = model.to_ascii_lowercase();
    lower.starts_with("claude-") || lower == "claude"
}

pub fn is_image_generation_model(model: &str) -> bool {
    model.to_ascii_lowercase().starts_with(MODEL_GEMINI_3_PRO_IMAGE)
}

pub fn normalize_preview_alias(model: &str) -> String {
    match model {
        MODEL_GEMINI_3_PRO_PREVIEW => MODEL_GEMINI_3_PRO_HIGH.to_string(),
        MODEL_GEMINI_3_PRO_IMAGE_PREVIEW => MODEL_GEMINI_3_PRO_IMAGE.to_string(),
        MODEL_GEMINI_3_FLASH_PREVIEW => MODEL_GEMINI_3_FLASH.to_string(),
        _ => model.to_string(),
    }
}

pub fn web_search_fallback_model() -> &'static str {
    MODEL_GEMINI_30_FLASH
}

pub fn is_high_quality_grounding_candidate(model: &str) -> bool {
    let lower = model.to_ascii_lowercase();
    lower == MODEL_GEMINI_3_FLASH
        || lower == MODEL_GEMINI_30_FLASH
        || lower.starts_with("gemini-3-")
        || lower.starts_with("gemini-3.0-")
        || lower.contains("claude-sonnet-4-")
        || lower.contains("claude-opus-4-")
        || lower.contains("claude-haiku-4-")
}

pub fn model_supports_thinking(model: &str) -> bool {
    let lower = model.to_ascii_lowercase();
    lower.contains("-thinking")
        || lower.starts_with("claude-")
        || lower.contains(MODEL_GEMINI_3_PRO)
        || lower.contains(MODEL_GEMINI_30_PRO)
}

pub fn should_auto_enable_thinking(model: &str) -> bool {
    let lower = model.to_ascii_lowercase();
    lower.contains("-thinking")
        || lower.contains("opus-4-5")
        || lower.contains("opus-4.5")
        || lower.contains("opus-4-6")
        || lower.contains("opus-4.6")
        || lower.contains(MODEL_GEMINI_3_PRO)
        || lower.contains(MODEL_GEMINI_30_PRO)
}

pub fn normalize_claude_retry_model(model: &str) -> String {
    if !is_claude_model(model) {
        return model.to_string();
    }

    let mut normalized = model.replace("-thinking", "");
    if normalized.contains("claude-sonnet-4-6-") {
        normalized = MODEL_CLAUDE_SONNET_46.to_string();
    } else if normalized.contains("claude-sonnet-4-5-") {
        normalized = MODEL_CLAUDE_SONNET_45.to_string();
    } else if normalized.contains("claude-opus-4-6-") {
        normalized = MODEL_CLAUDE_OPUS_46.to_string();
    } else if normalized.contains("claude-opus-4-5-") || normalized.contains("claude-opus-4-") {
        normalized = MODEL_CLAUDE_OPUS_45.to_string();
    }

    normalized
}

pub fn is_signature_family_compatible(cached: &str, target: &str) -> bool {
    let c = cached.to_ascii_lowercase();
    let t = target.to_ascii_lowercase();

    if c == t {
        return true;
    }

    // Claude families are permissive inside the same major line.
    if c.contains("claude-sonnet-4-") && t.contains("claude-sonnet-4-") {
        return true;
    }
    if c.contains("claude-opus-4-") && t.contains("claude-opus-4-") {
        return true;
    }

    // Gemini families are strict.
    if c.contains("gemini-3-pro") && t.contains("gemini-3-pro") {
        return true;
    }
    if c.contains("gemini-3-flash") && t.contains("gemini-3-flash") {
        return true;
    }
    if c.contains("gemini-3.0-pro") && t.contains("gemini-3.0-pro") {
        return true;
    }
    if c.contains("gemini-3.0-flash") && t.contains("gemini-3.0-flash") {
        return true;
    }

    false
}

static CLAUDE_TO_GEMINI: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
    let mut m = HashMap::new();

    // ============================================================================
    // ANTHROPIC CLAUDE MODELS (Expanded)
    // ============================================================================

    // --- Claude 4.6 Opus (Flagship - Feb 2026) ---
    m.insert(MODEL_CLAUDE_OPUS_46, MODEL_CLAUDE_OPUS_46_THINKING);
    m.insert("claude-4-6-opus-latest", MODEL_CLAUDE_OPUS_46_THINKING); // Standard alias
    m.insert("claude-opus-4-6-20260201", MODEL_CLAUDE_OPUS_46_THINKING);
    m.insert(MODEL_CLAUDE_OPUS_46_THINKING, MODEL_CLAUDE_OPUS_46_THINKING); // Extended reasoning mode
    
    // AWS Bedrock & Vertex AI Aliases for 4.6
    m.insert("anthropic.claude-4-6-opus-20260201-v1:0", MODEL_CLAUDE_OPUS_46_THINKING);
    m.insert("claude-4-6-opus@20260201", MODEL_CLAUDE_OPUS_46_THINKING);

    // --- Claude 4.6 Sonnet (Efficiency/Dev Standard) ---
    m.insert(MODEL_CLAUDE_SONNET_46, MODEL_CLAUDE_SONNET_46_THINKING);
    m.insert("claude-sonnet-4-6-20260115", MODEL_CLAUDE_SONNET_46_THINKING);
    m.insert(MODEL_CLAUDE_SONNET_46_THINKING, MODEL_CLAUDE_SONNET_46_THINKING); // "Thinking Sonnet"
    m.insert("anthropic.claude-4-6-sonnet-20260115-v1:0", MODEL_CLAUDE_SONNET_46_THINKING);

    // --- Claude 4.5 Opus (Late 2025 Legacy) ---
    m.insert(MODEL_CLAUDE_OPUS_45, MODEL_CLAUDE_OPUS_45_THINKING);
    m.insert("claude-opus-4-5-20251101", MODEL_CLAUDE_OPUS_45_THINKING);
    m.insert(MODEL_CLAUDE_OPUS_45_THINKING, MODEL_CLAUDE_OPUS_45_THINKING);
    m.insert("anthropic.claude-4-5-opus-20251101-v1:0", MODEL_CLAUDE_OPUS_45_THINKING);

    // --- Claude 4.5 Sonnet & Haiku ---
    m.insert(MODEL_CLAUDE_SONNET_45, MODEL_CLAUDE_SONNET_45_THINKING);
    m.insert("claude-sonnet-4-5-20250929", MODEL_CLAUDE_SONNET_45_THINKING);
    m.insert(MODEL_CLAUDE_HAIKU_45, MODEL_CLAUDE_HAIKU_45);
    m.insert("claude-haiku-4-5-20251001", MODEL_CLAUDE_HAIKU_45);
    // ============================================================================
    // OPENAI MODELS (Expanded with GPT-5.x, Codex, and o-series)
    // ============================================================================
    // --- GPT-5.3 Series (Feb 2026 "Garlic" Release) ---
    // The newest flagship generation
    m.insert("gpt-5.3", MODEL_GEMINI_30_FLASH);              // Standard "High" model
    m.insert("gpt-5.3-chat-latest", MODEL_GEMINI_30_FLASH);  // Always points to newest 5.3 weight
    m.insert("gpt-5.3-preview", MODEL_GEMINI_30_FLASH);
    m.insert("gpt-5.3-thinking", MODEL_GEMINI_30_FLASH);     // Integrated reasoning (System 2)
    m.insert("gpt-5.3-agent", MODEL_GEMINI_30_FLASH);        // Autonomous agent specialized
    m.insert("gpt-5.3-mini", MODEL_GEMINI_30_FLASH);         // Cost-efficient general purpose
    m.insert("gpt-5.3-nano", MODEL_GEMINI_30_FLASH);         // Ultra-low latency / On-device target

    // --- GPT-5.3 Codex Tiers (Coding Specialized) ---
    // Mapped to capability levels: Low, Medium, High, Ultra
    m.insert("gpt-5.3-codex-nano", MODEL_GEMINI_30_FLASH);   // "Low" (Autocomplete/Super-fast)
    m.insert("gpt-5.3-codex-mini", MODEL_GEMINI_30_FLASH);   // "Medium" (Daily Driver/Functions)
    m.insert(MODEL_GPT_53_CODEX, MODEL_GEMINI_30_FLASH);     // "High" (Complex Logic/Standard)
    m.insert("gpt-5.3-codex-pro", MODEL_GEMINI_30_FLASH);    // "Ultra" (Architecture/Refactoring)
    m.insert("gpt-5.3-codex-edit", MODEL_GEMINI_30_FLASH);   // Strict diff/patch generation

    // --- GPT-5.2 Series (Dec 2025 Production Standard) ---
    m.insert("gpt-5.2", MODEL_GEMINI_30_FLASH);
    m.insert("gpt-5.2-chat-latest", MODEL_GEMINI_30_FLASH);
    m.insert("gpt-5.2-pro", MODEL_GEMINI_30_FLASH);          // High-compute context window
    m.insert("gpt-5.2-thinking", MODEL_GEMINI_30_FLASH);
    m.insert("gpt-5.2-codex", MODEL_GEMINI_30_FLASH);        // Previous IDE Standard

    // --- GPT-5.1 & Base GPT-5 Series (Legacy 2025) ---
    m.insert("gpt-5.1", MODEL_GEMINI_30_FLASH);
    m.insert("gpt-5.1-codex", MODEL_GEMINI_30_FLASH);
    m.insert("gpt-5.1-codex-max", MODEL_GEMINI_30_FLASH);
    m.insert(MODEL_GPT_5, MODEL_GEMINI_30_FLASH);
    m.insert("gpt-5-mini", MODEL_GEMINI_30_FLASH);
    m.insert("gpt-5-nano", MODEL_GEMINI_30_FLASH);

    // ============================================================================
    // GOOGLE GEMINI MODELS (Expanded)
    // ============================================================================

    // --- Gemini 3 Series ---
    m.insert(MODEL_GEMINI_3_PRO_PREVIEW, MODEL_GEMINI_3_PRO_PREVIEW);
    m.insert(MODEL_GEMINI_3_PRO, MODEL_GEMINI_3_PRO_PREVIEW);
    m.insert(MODEL_GEMINI_3_PRO_LOW, MODEL_GEMINI_3_PRO_PREVIEW);
    m.insert(MODEL_GEMINI_3_PRO_HIGH, MODEL_GEMINI_3_PRO_PREVIEW);
    m.insert(MODEL_GEMINI_3_PRO_IMAGE, MODEL_GEMINI_3_PRO_IMAGE);
    m.insert(MODEL_GEMINI_3_FLASH, MODEL_GEMINI_3_FLASH);
    m.insert(MODEL_GEMINI_3_FLASH_PREVIEW, MODEL_GEMINI_3_FLASH);
    m.insert(MODEL_GEMINI_3_FLASH_THINKING, MODEL_GEMINI_3_FLASH_THINKING);
    m.insert(MODEL_GEMINI_3_PRO_HIGH_THINKING, MODEL_GEMINI_3_PRO_HIGH_THINKING);
    // --- Gemini 3.0 Flash Thinking ---
    m.insert(MODEL_GEMINI_30_FLASH_THINKING, MODEL_GEMINI_30_FLASH_THINKING);
    m.insert("gemini-3.0-flash-thinking-exp", MODEL_GEMINI_30_FLASH_THINKING);
    m.insert("gemini-3.0-flash-thinking-0121", MODEL_GEMINI_30_FLASH_THINKING);
    // --- Gemini 3.0 Pro Thinking ---
    m.insert(MODEL_GEMINI_30_PRO_THINKING, MODEL_GEMINI_30_PRO_THINKING);
    m.insert("gemini-3.0-pro-thinking-exp", MODEL_GEMINI_30_PRO_THINKING);
    // --- Gemini 3.0 Standard ---
    m.insert(MODEL_GEMINI_30_PRO, MODEL_GEMINI_30_PRO);
    m.insert("gemini-3.0-pro-001", MODEL_GEMINI_30_PRO);
    m.insert(MODEL_GEMINI_30_FLASH, MODEL_GEMINI_30_FLASH);
    m.insert("gemini-3.0-flash-001", MODEL_GEMINI_30_FLASH);
    m.insert(MODEL_GEMINI_30_ULTRA, MODEL_GEMINI_30_ULTRA);
    m.insert("gemini-3.0-pro-search", MODEL_GEMINI_30_PRO);

    // ============================================================================
    // INTERNAL & ALIAS MAPPINGS
    // ============================================================================

    // Generic Aliases
    m.insert("claude", MODEL_CLAUDE_SONNET_45);
    m.insert(MODEL_CLAUDE_SONNET_ALIAS, MODEL_CLAUDE_SONNET_45);
    m.insert("gpt", MODEL_GEMINI_30_FLASH);
    m.insert("gemini", MODEL_GEMINI_30_FLASH);
    m.insert(MODEL_GEMINI_PRO_ALIAS, MODEL_GEMINI_30_FLASH);
    m.insert("text-model", MODEL_GEMINI_30_FLASH);
    m.insert("chat-model", MODEL_GEMINI_30_FLASH);

    m
});


// Map Claude model names to Gemini model names
// 
// # Mapping Strategy
// 1. **Exact Match**: Check the CLAUDE_TO_GEMINI mapping table
// 2. **OpenAI Alias Prefix**: Any gpt-* model maps to gemini-3.0-flash
// 3. **Known Prefix Pass-through**: gemini-* and *-thinking models are passed through directly
// 4. ** Direct Pass-through**: Unknown model IDs are passed directly to the Google API (supporting trial of unreleased models)
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
// assert_eq!(map_claude_model_to_gemini("claude-opus-4-6"), "claude-opus-4-6-thinking");
// 
// // Gemini model pass-through
// assert_eq!(map_claude_model_to_gemini("gemini-3.0-flash"), "gemini-3.0-flash");
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

    // 2. Built-in wildcard alias for OpenAI-style model IDs.
    // Keeps compatibility for current/future GPT variants without constant table updates.
    if is_openai_gpt_model(input) {
        return MODEL_GEMINI_30_FLASH.to_string();
    }

    // 3. Pass-through known prefixes (gemini-, -thinking) to support dynamic suffixes
    if is_gemini_model(input) || input.contains("thinking") {
        return input.to_string();
    }


    // 4. [ENHANCED] Pass through unknown model IDs directly instead of forcing fallback
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
    model_ids.insert(MODEL_GEMINI_3_PRO_LOW.to_string());
    
    // Dynamically generate all Image Gen Combinations
    let base = MODEL_GEMINI_3_PRO_IMAGE;
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

    model_ids.insert(MODEL_GEMINI_30_FLASH.to_string());
    model_ids.insert(MODEL_GEMINI_30_FLASH_THINKING.to_string());
    model_ids.insert(MODEL_GEMINI_30_PRO.to_string());
    model_ids.insert(MODEL_GEMINI_30_PRO_THINKING.to_string());
    model_ids.insert(MODEL_GEMINI_30_ULTRA.to_string());
    model_ids.insert(MODEL_GEMINI_3_FLASH.to_string());
    model_ids.insert(MODEL_GEMINI_3_PRO_HIGH.to_string());
    model_ids.insert(MODEL_GEMINI_3_PRO_LOW.to_string());


    let mut sorted_ids: Vec<_> = model_ids.into_iter().collect();
    sorted_ids.sort();
    sorted_ids
}

// Wildcard matching - supports multiple wildcards
//
// **Note**: Matching is **case-sensitive**. Pattern `GPT-5*` will NOT match `gpt-5.2`.
//
// Examples:
// - `gpt-5*` matches `gpt-5`, `gpt-5.2-chat-latest` ✓
// - `claude-*-sonnet-*` matches `claude-sonnet-4-6-20260115` ✓
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
// - `gemini-3-flash`: All Flash variants (3-flash, etc.)
// - `gemini-3-pro-high`: All Pro variants (3-pro, etc.)
// - `claude-sonnet-4-5`: All Claude 4.5/4.6 and Opus/Haiku variants
// 
// Returns `None` if the model doesn't match any of the 3 protected categories.
pub fn normalize_to_standard_id(model_name: &str) -> Option<String> {
    //  Strict matching based on user-defined groups (Case Insensitive)
    let lower = model_name.to_lowercase();
    match lower.as_str() {
        // Gemini 3 Flash Group
        MODEL_GEMINI_3_FLASH
        | MODEL_GEMINI_3_FLASH_THINKING
        | MODEL_GEMINI_30_FLASH
        | MODEL_GEMINI_30_FLASH_THINKING => Some(MODEL_GEMINI_3_FLASH.to_string()),

        // Gemini 3 Pro High Group
        MODEL_GEMINI_3_PRO
        | MODEL_GEMINI_3_PRO_PREVIEW
        | MODEL_GEMINI_3_PRO_HIGH
        | MODEL_GEMINI_3_PRO_LOW
        | MODEL_GEMINI_30_PRO
        | MODEL_GEMINI_30_PRO_THINKING => Some(MODEL_GEMINI_3_PRO_HIGH.to_string()),

        // Claude 4.5/4.6 Group (includes Sonnet/Opus/Haiku)
        MODEL_CLAUDE_SONNET_45
        | MODEL_CLAUDE_SONNET_45_THINKING
        | MODEL_CLAUDE_SONNET_46
        | MODEL_CLAUDE_SONNET_46_THINKING
        | MODEL_CLAUDE_OPUS_45
        | MODEL_CLAUDE_OPUS_45_THINKING
        | MODEL_CLAUDE_OPUS_46
        | MODEL_CLAUDE_OPUS_46_THINKING
        | MODEL_CLAUDE_HAIKU_45 => Some(MODEL_CLAUDE_SONNET_45.to_string()),

        _ => None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_model_mapping() {
        assert_eq!(
            map_claude_model_to_gemini("claude-opus-4-6"),
            "claude-opus-4-6-thinking"
        );
        assert_eq!(
            map_claude_model_to_gemini("claude-sonnet-4-5"),
            "claude-sonnet-4-5-thinking"
        );
        assert_eq!(
            map_claude_model_to_gemini("gemini-3-flash-mini-test"),
            "gemini-3-flash-mini-test"
        );
        assert_eq!(
            map_claude_model_to_gemini("unknown-model"),
            "unknown-model"
        );
        assert_eq!(
            map_claude_model_to_gemini("gpt-5"),
            "gemini-3.0-flash"
        );
        assert_eq!(
            map_claude_model_to_gemini("GPT-5.3-CODEX-PRO"),
            "gemini-3.0-flash"
        );
    }

    #[test]
    fn test_wildcard_priority() {
        let mut custom = HashMap::new();
        custom.insert("gpt*".to_string(), "fallback".to_string());
        custom.insert("gpt-5*".to_string(), "specific".to_string());
        custom.insert("claude-opus-*".to_string(), "opus-default".to_string());
        custom.insert("claude-opus*thinking".to_string(), "opus-thinking".to_string());

        // More specific pattern wins
        assert_eq!(resolve_model_route("gpt-5.3-codex", &custom), "specific");
        assert_eq!(resolve_model_route("gpt-legacy", &custom), "fallback");
        // Suffix constraint is more specific than prefix-only
        assert_eq!(resolve_model_route("claude-opus-4-6-thinking", &custom), "opus-thinking");
        assert_eq!(resolve_model_route("claude-opus-4-6", &custom), "opus-default");
    }

    #[test]
    fn test_multi_wildcard_support() {
        let mut custom = HashMap::new();
        custom.insert("claude*sonnet-*".to_string(), "sonnet-versioned".to_string());
        custom.insert("gpt-*-*".to_string(), "gpt-multi".to_string());
        custom.insert("*thinking*".to_string(), "has-thinking".to_string());

        // Multi-wildcard patterns should work
        assert_eq!(
            resolve_model_route("claude-sonnet-4-6-20260115", &custom),
            "sonnet-versioned"
        );
        assert_eq!(
            resolve_model_route("gpt-5.2-chat-latest", &custom),
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
