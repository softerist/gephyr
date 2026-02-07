// Claude utility functions
// JSON Schema cleaning, signature processing, etc.

// Removed unused Value imports

// Convert type names in JSON Schema to uppercase (Gemini requirement)
// Example: "string" -> "STRING", "integer" -> "INTEGER"
// Removed unused uppercase_schema_types function

// Get context token limit based on model name
pub fn get_context_limit_for_model(model: &str) -> u32 {
    if model.contains("pro") {
        2_097_152 // 2M for Pro
    } else if model.contains("flash") {
        1_048_576 // 1M for Flash
    } else {
        1_048_576 // Default 1M
    }
}

pub fn to_claude_usage(usage_metadata: &super::models::UsageMetadata, scaling_enabled: bool, context_limit: u32) -> super::models::Usage {
    let prompt_tokens = usage_metadata.prompt_token_count.unwrap_or(0);
    let cached_tokens = usage_metadata.cached_content_token_count.unwrap_or(0);

    // [Improved Smart Threshold Regression Algorithm]
    // Goal: Leverage Gemini's large window while ensuring Claude Code correctly triggers "compact" prompts at high usage.
    //
    // Multi-stage strategy:
    // - 0-50%:  Aggressive compression, enjoy large context
    // - 50-70%: Begin accelerating recovery
    // - 70-85%: Rapidly recover to display 70%+
    // - 85%+:   Near 1:1 display, ensure triggering Claude Code's compact prompt
    let total_raw = prompt_tokens;

    //  Restore low token threshold - don't scale if under 30k tokens
    const SCALING_THRESHOLD: u32 = 30_000;

    let scaled_total = if scaling_enabled && total_raw > SCALING_THRESHOLD {
        const TARGET_MAX: f64 = 195_000.0; // Near Claude's 200k limit

        let ratio = total_raw as f64 / context_limit as f64;

        if ratio <= 0.5 {
            // Stage 1 (0-50%): Aggressive compression, enjoy large context
            // Real 50% -> Display ~30%
            let display_ratio = ratio * 0.6;
            (display_ratio * TARGET_MAX) as u32
        } else if ratio <= 0.7 {
            // Stage 2 (50-70%): Begin accelerating recovery
            // Linearly recover from 30% to 50%
            let progress = (ratio - 0.5) / 0.2;
            let display_ratio = 0.3 + progress * 0.2;
            (display_ratio * TARGET_MAX) as u32
        } else if ratio <= 0.85 {
            // Stage 3 (70-85%): Rapidly recover to display 70%
            // This stage makes user notice context growth
            let progress = (ratio - 0.7) / 0.15;
            let display_ratio = 0.5 + progress * 0.2;
            (display_ratio * TARGET_MAX) as u32
        } else {
            // Stage 4 (85%+): Near 1:1 display, trigger Claude Code's compact prompt
            // 85% real -> 70% display
            // 100% real -> 97% display
            let progress = (ratio - 0.85) / 0.15;
            let display_ratio = 0.7 + progress * 0.27;
            (display_ratio.min(0.97) * TARGET_MAX) as u32
        }
    } else {
        total_raw
    };

    // [Debug Log] For manual verification
    if scaling_enabled && total_raw > 30_000 {
        let ratio = total_raw as f64 / context_limit as f64;
        let display_ratio = scaled_total as f64 / 195_000.0;
        tracing::debug!(
            "[Claude-Scaling] Raw: {} ({:.1}%), Display: {} ({:.1}%), Compression: {:.1}x",
            total_raw, ratio * 100.0, scaled_total, display_ratio * 100.0,
            total_raw as f64 / scaled_total as f64
        );
    }
    
    // Proportional allocation of scaled total to input and cache_read
    let (reported_input, reported_cache) = if total_raw > 0 {
        let cache_ratio = (cached_tokens as f64) / (total_raw as f64);
        let sc_cache = (scaled_total as f64 * cache_ratio) as u32;
        (scaled_total.saturating_sub(sc_cache), Some(sc_cache))
    } else {
        (scaled_total, None)
    };
    
    super::models::Usage {
        input_tokens: reported_input,
        output_tokens: usage_metadata.candidates_token_count.unwrap_or(0),
        cache_read_input_tokens: reported_cache,
        cache_creation_input_tokens: Some(0),
        server_tool_use: None,
    }
}

// Extract thoughtSignature
// Removed unused extract_thought_signature function

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_claude_usage() {
        use super::super::models::UsageMetadata;

        let usage = UsageMetadata {
            prompt_token_count: Some(100),
            candidates_token_count: Some(50),
            total_token_count: Some(150),
            cached_content_token_count: None,
        };

        let claude_usage = to_claude_usage(&usage, true, 1_000_000);
        // 100 tokens is < 30k, minimal scaling
        assert!(claude_usage.input_tokens < 200);
        assert_eq!(claude_usage.output_tokens, 50);

        // Test 50% load (500k) - should display ~30%
        let usage_50 = UsageMetadata {
            prompt_token_count: Some(500_000),
            candidates_token_count: Some(10),
            total_token_count: Some(500_010),
            cached_content_token_count: None,
        };
        let res_50 = to_claude_usage(&usage_50, true, 1_000_000);
        // 50% * 0.6 = 30% of 195k = 58,500
        assert!(res_50.input_tokens > 55_000 && res_50.input_tokens < 62_000);

        // Test 70% load (700k) - should display ~50%
        let usage_70 = UsageMetadata {
            prompt_token_count: Some(700_000),
            candidates_token_count: Some(10),
            total_token_count: Some(700_010),
            cached_content_token_count: None,
        };
        let res_70 = to_claude_usage(&usage_70, true, 1_000_000);
        // 50% of 195k = 97,500
        assert!(res_70.input_tokens > 90_000 && res_70.input_tokens < 105_000);

        // Test 85% load (850k) - should display ~70%
        let usage_85 = UsageMetadata {
            prompt_token_count: Some(850_000),
            candidates_token_count: Some(10),
            total_token_count: Some(850_010),
            cached_content_token_count: None,
        };
        let res_85 = to_claude_usage(&usage_85, true, 1_000_000);
        // 70% of 195k = 136,500
        assert!(res_85.input_tokens > 130_000 && res_85.input_tokens < 145_000);

        // Test 100% load (1M) - should display ~97%
        let usage_100 = UsageMetadata {
            prompt_token_count: Some(1_000_000),
            candidates_token_count: Some(10),
            total_token_count: Some(1_000_010),
            cached_content_token_count: None,
        };
        let res_100 = to_claude_usage(&usage_100, true, 1_000_000);
        // 97% of 195k = 189,150
        assert!(res_100.input_tokens > 185_000 && res_100.input_tokens <= 190_000);
    }
}
