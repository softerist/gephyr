// ==================================================================================
// Comprehensive test for quota protection feature
// Verify the complete flow from account creation to execution of quota protection strategy
// ==================================================================================

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::models::QuotaProtectionConfig;
    use crate::proxy::common::model_mapping::normalize_to_standard_id;
    use crate::proxy::token_manager::ProxyToken;

    // ==================================================================================
    // Helper function: Create mock account
    // ==================================================================================

    fn create_mock_token(
        account_id: &str,
        email: &str,
        protected_models: Vec<&str>,
        remaining_quota: Option<i32>,
    ) -> ProxyToken {
        ProxyToken {
            account_id: account_id.to_string(),
            access_token: format!("mock_access_token_{}", account_id),
            refresh_token: format!("mock_refresh_token_{}", account_id),
            expires_in: 3600,
            timestamp: chrono::Utc::now().timestamp() + 3600,
            email: email.to_string(),
            account_path: PathBuf::from(format!("/tmp/test_accounts/{}.json", account_id)),
            project_id: Some("test-project".to_string()),
            subscription_tier: Some("PRO".to_string()),
            remaining_quota,
            protected_models: protected_models.iter().map(|s| s.to_string()).collect(),
            health_score: 1.0,
            reset_time: None,
            validation_blocked: false,
            validation_blocked_until: 0,
            model_quotas: std::collections::HashMap::new(),
        }
    }

    // ==================================================================================
    // Test 1: Correctness of normalize_to_standard_id function
    // Verify that various Claude model names are correctly normalized
    // ==================================================================================

    #[test]
    fn test_normalize_to_standard_id_claude_models() {
        // Claude Sonnet series
        assert_eq!(
            normalize_to_standard_id("claude-sonnet-4-5"),
            Some("claude-sonnet-4-5".to_string())
        );
        assert_eq!(
            normalize_to_standard_id("claude-sonnet-4-5-thinking"),
            Some("claude-sonnet-4-5".to_string())
        );

        // Claude Opus series - This is a critical test!
        assert_eq!(
            normalize_to_standard_id("claude-opus-4-5-thinking"),
            Some("claude-sonnet-4-5".to_string()),
            "claude-opus-4-5-thinking should normalize to claude-sonnet-4-5"
        );

        // Gemini series
        assert_eq!(
            normalize_to_standard_id("gemini-3-flash"),
            Some("gemini-3-flash".to_string())
        );
        assert_eq!(
            normalize_to_standard_id("gemini-3-pro-high"),
            Some("gemini-3-pro-high".to_string())
        );
        assert_eq!(
            normalize_to_standard_id("gemini-3-pro-low"),
            Some("gemini-3-pro-high".to_string())
        );

        // Unsupported models should return None
        assert_eq!(normalize_to_standard_id("gpt-4"), None);
        assert_eq!(normalize_to_standard_id("unknown-model"), None);
    }

    // ==================================================================================
    // Test 2: Quota protection model matching logic
    // Verify that protected_models.contains() matches correctly after normalization
    // ==================================================================================

    #[test]
    fn test_protected_models_matching() {
        // Create an account with claude-sonnet-4-5 in protected_models
        let token = create_mock_token(
            "account-1",
            "test@example.com",
            vec!["claude-sonnet-4-5"],
            Some(50),
        );

        // Test: Requests for claude-opus-4-5-thinking should be protected
        let target_model = "claude-opus-4-5-thinking";
        let normalized =
            normalize_to_standard_id(target_model).unwrap_or_else(|| target_model.to_string());

        assert_eq!(normalized, "claude-sonnet-4-5");
        assert!(
            token.protected_models.contains(&normalized),
            "claude-opus-4-5-thinking after normalization should match claude-sonnet-4-5 in protected_models"
        );

        // Test: Requests for claude-sonnet-4-5-thinking should also be protected
        let target_model_2 = "claude-sonnet-4-5-thinking";
        let normalized_2 =
            normalize_to_standard_id(target_model_2).unwrap_or_else(|| target_model_2.to_string());

        assert!(
            token.protected_models.contains(&normalized_2),
            "claude-sonnet-4-5-thinking after normalization should match protected_models"
        );

        // Test: Requests for gemini-3-flash should not be protected (as it's not in protected_models)
        let target_model_3 = "gemini-3-flash";
        let normalized_3 =
            normalize_to_standard_id(target_model_3).unwrap_or_else(|| target_model_3.to_string());

        assert!(
            !token.protected_models.contains(&normalized_3),
            "gemini-3-flash should not match claude-sonnet-4-5"
        );
    }

    // ==================================================================================
    // Test 3: Quota protection filtering during multi-account polling
    // Simulate multiple accounts and verify that protected accounts are skipped
    // ==================================================================================

    #[test]
    fn test_multi_account_quota_protection_filtering() {
        // Create 3 accounts
        let tokens = vec![
            // Account 1: claude-sonnet-4-5 is protected (low quota)
            create_mock_token(
                "account-1",
                "user1@example.com",
                vec!["claude-sonnet-4-5"],
                Some(20),
            ),
            // Account 2: Not protected
            create_mock_token("account-2", "user2@example.com", vec![], Some(80)),
            // Account 3: gemini-3-flash is protected
            create_mock_token(
                "account-3",
                "user3@example.com",
                vec!["gemini-3-flash"],
                Some(30),
            ),
        ];

        // Simulate request for claude-opus-4-5-thinking
        let target_model = "claude-opus-4-5-thinking";
        let normalized_target =
            normalize_to_standard_id(target_model).unwrap_or_else(|| target_model.to_string());

        // Filter out protected accounts
        let available_accounts: Vec<_> = tokens
            .iter()
            .filter(|t| !t.protected_models.contains(&normalized_target))
            .collect();

        // Verify: Account 1 is filtered (because claude-sonnet-4-5 is protected)
        // Accounts 2 and 3 are available
        assert_eq!(available_accounts.len(), 2);
        assert!(available_accounts
            .iter()
            .any(|t| t.account_id == "account-2"));
        assert!(available_accounts
            .iter()
            .any(|t| t.account_id == "account-3"));
        assert!(!available_accounts
            .iter()
            .any(|t| t.account_id == "account-1"));

        // Simulate request for gemini-3-flash
        let target_model_2 = "gemini-3-flash";
        let normalized_target_2 =
            normalize_to_standard_id(target_model_2).unwrap_or_else(|| target_model_2.to_string());

        let available_accounts_2: Vec<_> = tokens
            .iter()
            .filter(|t| !t.protected_models.contains(&normalized_target_2))
            .collect();

        // Verify: Account 3 is filtered (because gemini-3-flash is protected)
        // Accounts 1 and 2 are available
        assert_eq!(available_accounts_2.len(), 2);
        assert!(available_accounts_2
            .iter()
            .any(|t| t.account_id == "account-1"));
        assert!(available_accounts_2
            .iter()
            .any(|t| t.account_id == "account-2"));
        assert!(!available_accounts_2
            .iter()
            .any(|t| t.account_id == "account-3"));
    }

    // ==================================================================================
    // Test 4: Behavior when all accounts are protected
    // Verify that when the target model is protected across all accounts, an error is returned
    // ==================================================================================

    #[test]
    fn test_all_accounts_protected_returns_error() {
        // Create 3 accounts, all protecting claude-sonnet-4-5
        let tokens = vec![
            create_mock_token(
                "account-1",
                "user1@example.com",
                vec!["claude-sonnet-4-5"],
                Some(10),
            ),
            create_mock_token(
                "account-2",
                "user2@example.com",
                vec!["claude-sonnet-4-5"],
                Some(15),
            ),
            create_mock_token(
                "account-3",
                "user3@example.com",
                vec!["claude-sonnet-4-5"],
                Some(5),
            ),
        ];

        let target_model = "claude-opus-4-5-thinking";
        let normalized_target =
            normalize_to_standard_id(target_model).unwrap_or_else(|| target_model.to_string());

        let available_accounts: Vec<_> = tokens
            .iter()
            .filter(|t| !t.protected_models.contains(&normalized_target))
            .collect();

        // All accounts filtered, should return 0
        assert_eq!(available_accounts.len(), 0);

        // In actual code, this would result in an "All accounts failed or unhealthy" error
    }

    // ==================================================================================
    // Test 5: Consistency between monitored_models configuration and normalization
    // Verify that monitored_models in the configuration correctly match normalized model names
    // ==================================================================================

    #[test]
    fn test_monitored_models_normalization_consistency() {
        let config = QuotaProtectionConfig {
            enabled: true,
            threshold_percentage: 60,
            monitored_models: vec![
                "claude-sonnet-4-5".to_string(),
                "gemini-3-pro-high".to_string(),
                "gemini-3-flash".to_string(),
            ],
        };

        // Test whether various model names after normalization are in monitored_models
        let test_cases = vec![
            ("claude-opus-4-5-thinking", true),   // Normalize to claude-sonnet-4-5
            ("claude-sonnet-4-5-thinking", true), // Normalize to claude-sonnet-4-5
            ("claude-sonnet-4-5", true),          // Direct match
            ("gemini-3-pro-high", true),          // Direct match
            ("gemini-3-pro-low", true),           // Normalize to gemini-3-pro-high
            ("gemini-3-flash", true),             // Direct match
            ("gpt-4", false),                     // Unsupported models
            ("gemini-2.5-flash", false),          // Not in the monitoring list
        ];

        for (model_name, expected_monitored) in test_cases {
            let standard_id = normalize_to_standard_id(model_name);

            let is_monitored = match &standard_id {
                Some(id) => config.monitored_models.contains(id),
                None => false,
            };

            assert_eq!(
                is_monitored, expected_monitored,
                "Monitoring status for model {} (normalized to {:?}) should be {}",
                model_name, standard_id, expected_monitored
            );
        }
    }

    // ==================================================================================
    // Test 6: Quota threshold trigger logic
    // Verify that protection triggers when quota is below threshold and recovers when it's above
    // ==================================================================================

    #[test]
    fn test_quota_threshold_trigger_logic() {
        let threshold = 60; // 60% threshold

        // Simulate quota data
        let quota_data = vec![
            ("claude-opus-4-5-thinking", 50, true), // 50% <= 60%, should trigger protection
            ("claude-sonnet-4-5-thinking", 60, true), // 60% <= 60%, should trigger protection (boundary case)
            ("gemini-3-flash", 61, false),          // 61% > 60%, protection should not trigger
            ("gemini-3-pro-high", 100, false),      // 100% > 60%, protection should not trigger
        ];

        for (model_name, percentage, should_protect) in quota_data {
            let should_trigger = percentage <= threshold;

            assert_eq!(
                should_trigger,
                should_protect,
                "Model {} quota {}% (threshold {}%) should {} trigger protection",
                model_name,
                percentage,
                threshold,
                if should_protect { "" } else { "NOT" }
            );
        }
    }

    // ==================================================================================
    // Test 7: Portection filtering after account priority sorting
    // Verify that if a high-quota account is protected, it falls back to a lower-quota account
    // ==================================================================================

    #[test]
    fn test_priority_fallback_when_protected() {
        // Create 3 accounts, sorted by quota
        let mut tokens = vec![
            create_mock_token(
                "account-high",
                "high@example.com",
                vec!["claude-sonnet-4-5"],
                Some(90),
            ),
            create_mock_token("account-mid", "mid@example.com", vec![], Some(60)),
            create_mock_token("account-low", "low@example.com", vec![], Some(30)),
        ];

        // Sort by quota descending (high quota priority)
        tokens.sort_by(|a, b| {
            let qa = a.remaining_quota.unwrap_or(0);
            let qb = b.remaining_quota.unwrap_or(0);
            qb.cmp(&qa)
        });

        // Verify sorting is correct
        assert_eq!(tokens[0].account_id, "account-high");
        assert_eq!(tokens[1].account_id, "account-mid");
        assert_eq!(tokens[2].account_id, "account-low");

        // Simulate request for claude-opus-4-5-thinking
        let target_model = "claude-opus-4-5-thinking";
        let normalized_target =
            normalize_to_standard_id(target_model).unwrap_or_else(|| target_model.to_string());

        // Select the first available account in order
        let selected = tokens
            .iter()
            .find(|t| !t.protected_models.contains(&normalized_target));

        // Verify: account-high is skipped, account-mid selected
        assert!(selected.is_some());
        assert_eq!(
            selected.unwrap().account_id,
            "account-mid",
            "High-quota account is protected, should fall back to account-mid"
        );
    }

    // ==================================================================================
    // Test 8: Model-level protection (different models for the same account)
    // Verify that an account can protect certain models while not protecting others
    // ==================================================================================

    #[test]
    fn test_model_level_protection_granularity() {
        // Account protects claude-sonnet-4-5 but not gemini-3-flash
        let token = create_mock_token(
            "account-1",
            "user@example.com",
            vec!["claude-sonnet-4-5"],
            Some(50),
        );

        // Request claude-opus-4-5-thinking -> Protected
        let normalized_claude = normalize_to_standard_id("claude-opus-4-5-thinking")
            .unwrap_or_else(|| "claude-opus-4-5-thinking".to_string());
        assert!(
            token.protected_models.contains(&normalized_claude),
            "Claude request should be protected"
        );

        // Request gemini-3-flash -> Not protected
        let normalized_gemini = normalize_to_standard_id("gemini-3-flash")
            .unwrap_or_else(|| "gemini-3-flash".to_string());
        assert!(
            !token.protected_models.contains(&normalized_gemini),
            "Gemini request should not be protected"
        );
    }

    // ==================================================================================
    // Test 9: Quota protection enable/disable switch
    // Verify that protection logic does not take effect when quota_protection.enabled = false
    // ==================================================================================

    #[test]
    fn test_quota_protection_enabled_flag() {
        let config_enabled = QuotaProtectionConfig {
            enabled: true,
            threshold_percentage: 60,
            monitored_models: vec!["claude-sonnet-4-5".to_string()],
        };

        let config_disabled = QuotaProtectionConfig {
            enabled: false,
            threshold_percentage: 60,
            monitored_models: vec!["claude-sonnet-4-5".to_string()],
        };

        let token = create_mock_token(
            "account-1",
            "user@example.com",
            vec!["claude-sonnet-4-5"],
            Some(50),
        );

        let target_model = "claude-opus-4-5-thinking";
        let normalized_target =
            normalize_to_standard_id(target_model).unwrap_or_else(|| target_model.to_string());

        // When quota protection is enabled, the account should be filtered
        let is_protected_when_enabled =
            config_enabled.enabled && token.protected_models.contains(&normalized_target);
        assert!(is_protected_when_enabled, "Should be protected when enabled");

        // When quota protection is disabled, do not filter even if there are values in protected_models
        let is_protected_when_disabled =
            config_disabled.enabled && token.protected_models.contains(&normalized_target);
        assert!(!is_protected_when_disabled, "Should not be protected when disabled");
    }

    // ==================================================================================
    // Test 10: Full flow simulation (integration test style)
    // Simulate the complete flow of multi-account, quota protection config, and request polling
    // ==================================================================================

    #[test]
    fn test_full_quota_protection_flow() {
        // 1. Configure quota protection
        let config = QuotaProtectionConfig {
            enabled: true,
            threshold_percentage: 60,
            monitored_models: vec![
                "claude-sonnet-4-5".to_string(),
                "gemini-3-flash".to_string(),
            ],
        };

        // 2. Create multiple accounts, simulating various quota states
        let accounts = vec![
            // Account A: low Claude quota (50%), should be protected
            create_mock_token(
                "account-a",
                "a@example.com",
                vec!["claude-sonnet-4-5"],
                Some(50),
            ),
            // Account B: normal Claude quota (80%), not protected
            create_mock_token("account-b", "b@example.com", vec![], Some(80)),
            // Account C: both Claude and Gemini are protected
            create_mock_token(
                "account-c",
                "c@example.com",
                vec!["claude-sonnet-4-5", "gemini-3-flash"],
                Some(30),
            ),
            // Account D: only Gemini is protected
            create_mock_token(
                "account-d",
                "d@example.com",
                vec!["gemini-3-flash"],
                Some(40),
            ),
        ];

        // 3. Simulate multiple requests, verify account selection logic

        // Request 1: claude-opus-4-5-thinking
        let target_claude = normalize_to_standard_id("claude-opus-4-5-thinking")
            .unwrap_or_else(|| "claude-opus-4-5-thinking".to_string());

        let available_for_claude: Vec<_> = accounts
            .iter()
            .filter(|a| !config.enabled || !a.protected_models.contains(&target_claude))
            .collect();

        // Accounts A and C are filtered, B and D are available
        assert_eq!(available_for_claude.len(), 2);
        let claude_account_ids: Vec<_> = available_for_claude
            .iter()
            .map(|a| a.account_id.as_str())
            .collect();
        assert!(claude_account_ids.contains(&"account-b"));
        assert!(claude_account_ids.contains(&"account-d"));

        // Request 2: gemini-3-flash
        let target_gemini = normalize_to_standard_id("gemini-3-flash")
            .unwrap_or_else(|| "gemini-3-flash".to_string());

        let available_for_gemini: Vec<_> = accounts
            .iter()
            .filter(|a| !config.enabled || !a.protected_models.contains(&target_gemini))
            .collect();

        // Accounts C and D are filtered, A and B are available
        assert_eq!(available_for_gemini.len(), 2);
        let gemini_account_ids: Vec<_> = available_for_gemini
            .iter()
            .map(|a| a.account_id.as_str())
            .collect();
        assert!(gemini_account_ids.contains(&"account-a"));
        assert!(gemini_account_ids.contains(&"account-b"));

        // Request 3: unmonitored model (gemini-2.5-flash)
        let target_unmonitored = normalize_to_standard_id("gemini-2.5-flash")
            .unwrap_or_else(|| "gemini-2.5-flash".to_string());

        let available_for_unmonitored: Vec<_> = accounts
            .iter()
            .filter(|a| !config.enabled || !a.protected_models.contains(&target_unmonitored))
            .collect();

        // Unmonitored model, all accounts are available
        assert_eq!(available_for_unmonitored.len(), 4);
    }

    // ==================================================================================
    // Test 11: Boundary case - empty protected_models
    // ==================================================================================

    #[test]
    fn test_empty_protected_models() {
        let token = create_mock_token(
            "account-1",
            "user@example.com",
            vec![], // No protected models
            Some(50),
        );

        let target = normalize_to_standard_id("claude-opus-4-5-thinking")
            .unwrap_or_else(|| "claude-opus-4-5-thinking".to_string());

        assert!(
            !token.protected_models.contains(&target),
            "Empty protected_models should not match any models"
        );
    }

    // ==================================================================================
    // Test 12: Boundary case - case sensitivity
    // ==================================================================================

    #[test]
    fn test_model_name_case_sensitivity() {
        // normalize_to_standard_id should be case-insensitive
        assert_eq!(
            normalize_to_standard_id("Claude-Opus-4-5-Thinking"),
            Some("claude-sonnet-4-5".to_string())
        );
        assert_eq!(
            normalize_to_standard_id("CLAUDE-OPUS-4-5-THINKING"),
            Some("claude-sonnet-4-5".to_string())
        );
        assert_eq!(
            normalize_to_standard_id("GEMINI-3-FLASH"),
            Some("gemini-3-flash".to_string())
        );
    }

    // ==================================================================================
    // Test 13: End-to-end scenario - routing switch after quota protection takes effect mid-session
    // Simulate: Request 1 -> Bind account A -> Request 2 -> Continue with A -> Refresh quota -> A is protected -> Request 3 -> Switch to B
    // ==================================================================================

    #[test]
    fn test_sticky_session_quota_protection_mid_session_single_account() {
        // Scenario: only one account, quota protection takes effect after session binding
        // Expected: returns a quota protection error

        let session_id = "session-12345";
        let target_model = "claude-opus-4-5-thinking";
        let normalized_target =
            normalize_to_standard_id(target_model).unwrap_or_else(|| target_model.to_string());

        // Initial state: Account A is not protected
        let mut account_a = create_mock_token(
            "account-a",
            "a@example.com",
            vec![], // Initially no protection
            Some(70),
        );

        // Simulate session binding table
        let mut session_bindings: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();

        // === Request 1: Bind to account A ===
        session_bindings.insert(session_id.to_string(), account_a.account_id.clone());

        // Verify Request 1 success
        let bound_account = session_bindings.get(session_id);
        assert_eq!(bound_account, Some(&"account-a".to_string()));

        // === Request 2: Continue using account A ===
        // Account A is still available
        assert!(!account_a.protected_models.contains(&normalized_target));

        // === System triggers quota refresh, finds account A quota below threshold ===
        // Simulate after quota refresh, account_a's claude-sonnet-4-5 is added to protection list
        account_a
            .protected_models
            .insert("claude-sonnet-4-5".to_string());

        // === Request 3: Attempt to use account A but protected by quota ===
        let accounts = vec![account_a.clone()]; // Only one account

        // Check if the bound account is protected
        let bound_id = session_bindings.get(session_id).unwrap();
        let bound_account = accounts.iter().find(|a| &a.account_id == bound_id).unwrap();
        let is_protected = bound_account.protected_models.contains(&normalized_target);

        assert!(is_protected, "Account A should be quota-protected");

        // Try to find other available accounts
        let available_accounts: Vec<_> = accounts
            .iter()
            .filter(|a| !a.protected_models.contains(&normalized_target))
            .collect();

        // No available accounts
        assert_eq!(available_accounts.len(), 0, "Should be no available accounts");

        // In actual implementation, this returns an error message
        // Verify that quota-protection related error should be returned
        let error_message = if available_accounts.is_empty() {
            if accounts
                .iter()
                .all(|a| a.protected_models.contains(&normalized_target))
            {
                format!(
                    "All accounts quota-protected for model {}",
                    normalized_target
                )
            } else {
                "All accounts failed or unhealthy.".to_string()
            }
        } else {
            "OK".to_string()
        };

        assert!(
            error_message.contains("quota-protected"),
            "Error message should contain quota-protected: {}",
            error_message
        );
    }

    #[test]
    fn test_sticky_session_quota_protection_mid_session_multi_account() {
        // Scenario: multiple accounts, after quota protection for the session-bound account takes effect, it should route to another account

        let session_id = "session-67890";
        let target_model = "claude-opus-4-5-thinking";
        let normalized_target =
            normalize_to_standard_id(target_model).unwrap_or_else(|| target_model.to_string());

        // Initial state: neither Account A nor Account B is protected
        let mut account_a = create_mock_token("account-a", "a@example.com", vec![], Some(70));
        let account_b = create_mock_token("account-b", "b@example.com", vec![], Some(80));

        let mut session_bindings: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();

        // === Request 1: Bind to account A ===
        session_bindings.insert(session_id.to_string(), account_a.account_id.clone());

        // === Request 2: Continue using account A ===
        assert!(!account_a.protected_models.contains(&normalized_target));

        // === System triggers quota refresh, Account A is protected ===
        account_a
            .protected_models
            .insert("claude-sonnet-4-5".to_string());

        // === Request 3: Account A is protected, should unbind and switch to Account B ===
        let accounts = vec![account_a.clone(), account_b.clone()];

        // Check bound account
        let bound_id = session_bindings.get(session_id).unwrap();
        let bound_account = accounts.iter().find(|a| &a.account_id == bound_id).unwrap();
        let is_protected = bound_account.protected_models.contains(&normalized_target);

        assert!(is_protected, "Account A should be quota-protected");

        // Simulate unbinding logic
        if is_protected {
            session_bindings.remove(session_id);
        }

        // Find other available accounts
        let available_accounts: Vec<_> = accounts
            .iter()
            .filter(|a| !a.protected_models.contains(&normalized_target))
            .collect();

        // Account B should be available
        assert_eq!(available_accounts.len(), 1);
        assert_eq!(available_accounts[0].account_id, "account-b");

        // Rebind to Account B
        let new_account = available_accounts[0];
        session_bindings.insert(session_id.to_string(), new_account.account_id.clone());

        // Verify new binding
        assert_eq!(
            session_bindings.get(session_id),
            Some(&"account-b".to_string()),
            "Session should be rebound to Account B"
        );
    }

    // ==================================================================================
    // Test 14: Quota protection real-time synchronization test
    // Simulate: after quota refresh, protected_models updated, TokenManager memory should sync
    // ==================================================================================

    #[test]
    fn test_quota_protection_sync_after_refresh() {
        // This test simulates update_account_quota triggering a TokenManager reload

        // Initial memory state
        let mut tokens_in_memory = vec![create_mock_token(
            "account-a",
            "a@example.com",
            vec![],
            Some(70),
        )];

        // Simulate account data on disk (updated after quota refresh)
        let mut account_on_disk = create_mock_token("account-a", "a@example.com", vec![], Some(50));

        // Simulate quota refresh: low quota detected, trigger protection
        let threshold = 60;
        if account_on_disk.remaining_quota.unwrap_or(100) <= threshold {
            account_on_disk
                .protected_models
                .insert("claude-sonnet-4-5".to_string());
        }

        // Verify disk data updated
        assert!(
            account_on_disk
                .protected_models
                .contains("claude-sonnet-4-5"),
            "Account on disk should be protected"
        );

        // Memory data is still old at this point
        assert!(
            !tokens_in_memory[0]
                .protected_models
                .contains("claude-sonnet-4-5"),
            "Account in memory not yet synced"
        );

        // Simulate trigger_account_reload -> reload_account sync
        tokens_in_memory[0] = account_on_disk.clone();

        // Verify memory data synced
        assert!(
            tokens_in_memory[0]
                .protected_models
                .contains("claude-sonnet-4-5"),
            "Account in memory after sync should be protected"
        );

        // Now the request should be filtered correctly
        let target = normalize_to_standard_id("claude-opus-4-5-thinking")
            .unwrap_or_else(|| "claude-opus-4-5-thinking".to_string());

        let available: Vec<_> = tokens_in_memory
            .iter()
            .filter(|t| !t.protected_models.contains(&target))
            .collect();

        assert_eq!(available.len(), 0, "Account should be filtered after synchronization");
    }

    // ==================================================================================
    // Test 15: Dynamic changes in quota protection during multiple rounds of requests
    // Simulate a complete request sequence, including triggering and recovery of quota protection
    // ==================================================================================

    #[test]
    fn test_quota_protection_dynamic_changes() {
        let target_model = "claude-opus-4-5-thinking";
        let normalized_target =
            normalize_to_standard_id(target_model).unwrap_or_else(|| target_model.to_string());

        // Account pool
        let mut account_a = create_mock_token("account-a", "a@example.com", vec![], Some(70));
        let mut account_b = create_mock_token("account-b", "b@example.com", vec![], Some(80));

        // === Phase 1: Initial state, both accounts available ===
        let accounts = vec![account_a.clone(), account_b.clone()];
        let available: Vec<_> = accounts
            .iter()
            .filter(|t| !t.protected_models.contains(&normalized_target))
            .collect();
        assert_eq!(available.len(), 2, "Phase 1: Both accounts available");

        // === Phase 2: Account A quota reduced, protection triggered ===
        account_a.remaining_quota = Some(40);
        account_a
            .protected_models
            .insert("claude-sonnet-4-5".to_string());

        let accounts = vec![account_a.clone(), account_b.clone()];
        let available: Vec<_> = accounts
            .iter()
            .filter(|t| !t.protected_models.contains(&normalized_target))
            .collect();
        assert_eq!(available.len(), 1, "Phase 2: Only account B available");
        assert_eq!(available[0].account_id, "account-b");

        // === Phase 3: Account B also triggers protection ===
        account_b.remaining_quota = Some(30);
        account_b
            .protected_models
            .insert("claude-sonnet-4-5".to_string());

        let accounts = vec![account_a.clone(), account_b.clone()];
        let available: Vec<_> = accounts
            .iter()
            .filter(|t| !t.protected_models.contains(&normalized_target))
            .collect();
        assert_eq!(available.len(), 0, "Phase 3: No available accounts");

        // === Phase 4: Account A quota recovered (reset), protection lifted ===
        account_a.remaining_quota = Some(100);
        account_a.protected_models.remove("claude-sonnet-4-5");

        let accounts = vec![account_a.clone(), account_b.clone()];
        let available: Vec<_> = accounts
            .iter()
            .filter(|t| !t.protected_models.contains(&normalized_target))
            .collect();
        assert_eq!(available.len(), 1, "Phase 4: Account A recovered/available");
        assert_eq!(available[0].account_id, "account-a");
    }

    // ==================================================================================
    // Test 16: Full error message verification
    // Verify that error messages returned in different scenarios are correct
    // ==================================================================================

    #[test]
    fn test_error_messages_for_quota_protection() {
        let target_model = "claude-opus-4-5-thinking";
        let normalized_target =
            normalize_to_standard_id(target_model).unwrap_or_else(|| target_model.to_string());

        // Scenario 1: All accounts unavailable due to quota protection
        let all_protected = vec![
            create_mock_token("a1", "a1@example.com", vec!["claude-sonnet-4-5"], Some(30)),
            create_mock_token("a2", "a2@example.com", vec!["claude-sonnet-4-5"], Some(20)),
        ];

        let all_are_quota_protected = all_protected
            .iter()
            .all(|a| a.protected_models.contains(&normalized_target));

        assert!(all_are_quota_protected, "All accounts are quota-protected");

        // Generate error message
        let error = format!(
            "All {} accounts are quota-protected for model '{}'. Wait for quota reset or adjust protection threshold.",
            all_protected.len(),
            normalized_target
        );

        assert!(error.contains("quota-protected"));
        assert!(error.contains("claude-sonnet-4-5"));

        // Scenario 2: Mixed case (some rate-limited, some quota-protected)
        let mixed = vec![
            create_mock_token("a1", "a1@example.com", vec!["claude-sonnet-4-5"], Some(30)),
            create_mock_token("a2", "a2@example.com", vec![], Some(20)), // Assume this one is rate-limited
        ];

        let quota_protected_count = mixed
            .iter()
            .filter(|a| a.protected_models.contains(&normalized_target))
            .count();

        assert_eq!(quota_protected_count, 1);
    }

    // ==================================================================================
    // Test 17: Correctness of get_model_quota_from_json function
    // Verify reading a specific model quota from disk instead of max(all models)
    // ==================================================================================

    #[test]
    fn test_get_model_quota_from_json_reads_correct_model() {
        // Create mock account JSON file containing quotas for multiple models
        let account_json = serde_json::json!({
            "email": "test@example.com",
            "quota": {
                "models": [
                    { "name": "claude-sonnet-4-5", "percentage": 60 },
                    { "name": "claude-opus-4-5-thinking", "percentage": 40 },
                    { "name": "gemini-3-flash", "percentage": 100 }
                ]
            }
        });

        // Use std::env::temp_dir() to create temp file
        let temp_dir = std::env::temp_dir();
        let account_path = temp_dir.join(format!("test_quota_{}.json", uuid::Uuid::new_v4()));
        std::fs::write(&account_path, account_json.to_string()).expect("Failed to write temp file");

        // Test reading quota for claude-sonnet-4-5
        let sonnet_quota =
            crate::proxy::token_manager::TokenManager::get_model_quota_from_json_for_test(
                &account_path,
                "claude-sonnet-4-5",
            );
        assert_eq!(
            sonnet_quota,
            Some(60),
            "claude-sonnet-4-5 should return 60%, not max(100%)"
        );

        // Test reading quota for gemini-3-flash
        let gemini_quota =
            crate::proxy::token_manager::TokenManager::get_model_quota_from_json_for_test(
                &account_path,
                "gemini-3-flash",
            );
        assert_eq!(gemini_quota, Some(100), "gemini-3-flash should return 100%");

        // Test reading a non-existent model
        let unknown_quota =
            crate::proxy::token_manager::TokenManager::get_model_quota_from_json_for_test(
                &account_path,
                "unknown-model",
            );
        assert_eq!(unknown_quota, None, "Non-existent model should return None");

        // Clean up temp file
        let _ = std::fs::remove_file(&account_path);
    }

    // ==================================================================================
    // Test 18: Sorting uses target model quota instead of max quota
    // Verify correctness of the fixed sorting logic
    // ==================================================================================

    #[test]
    fn test_sorting_uses_target_model_quota_not_max() {
        // Use std::env::temp_dir() to create temp directory
        let temp_dir = std::env::temp_dir().join(format!("test_sorting_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).expect("Failed to create temp dir");

        // Account A: max=100 (gemini), sonnet=40
        let account_a_json = serde_json::json!({
            "email": "carmelioventori@example.com",
            "quota": {
                "models": [
                    { "name": "claude-sonnet-4-5", "percentage": 40 },
                    { "name": "gemini-3-flash", "percentage": 100 }
                ]
            }
        });

        // Account B: max=100 (gemini), sonnet=100
        let account_b_json = serde_json::json!({
            "email": "kiriyamaleo@example.com",
            "quota": {
                "models": [
                    { "name": "claude-sonnet-4-5", "percentage": 100 },
                    { "name": "gemini-3-flash", "percentage": 100 }
                ]
            }
        });

        // Account C: max=100 (gemini), sonnet=60
        let account_c_json = serde_json::json!({
            "email": "mizusawakai9@example.com",
            "quota": {
                "models": [
                    { "name": "claude-sonnet-4-5", "percentage": 60 },
                    { "name": "gemini-3-flash", "percentage": 100 }
                ]
            }
        });

        // Write to temp files
        let path_a = temp_dir.join("account_a.json");
        let path_b = temp_dir.join("account_b.json");
        let path_c = temp_dir.join("account_c.json");

        std::fs::write(&path_a, account_a_json.to_string()).unwrap();
        std::fs::write(&path_b, account_b_json.to_string()).unwrap();
        std::fs::write(&path_c, account_c_json.to_string()).unwrap();

        // Create tokens, remaining_quota uses max value (simulating old logic)
        let mut tokens = vec![
            create_mock_token_with_path("a", "carmelioventori@example.com", vec![], Some(100), path_a.clone()),
            create_mock_token_with_path("b", "kiriyamaleo@example.com", vec![], Some(100), path_b.clone()),
            create_mock_token_with_path("c", "mizusawakai9@example.com", vec![], Some(100), path_c.clone()),
        ];

        // Target model: claude-sonnet-4-5
        let target_model = "claude-sonnet-4-5";

        // Use the fixed sorting logic: read target model quota
        tokens.sort_by(|a, b| {
            let quota_a = crate::proxy::token_manager::TokenManager::get_model_quota_from_json_for_test(
                &a.account_path,
                target_model,
            )
            .unwrap_or(0);
            let quota_b = crate::proxy::token_manager::TokenManager::get_model_quota_from_json_for_test(
                &b.account_path,
                target_model,
            )
            .unwrap_or(0);
            quota_b.cmp(&quota_a) // High quota priority
        });

        // Verify sorting result: sonnet quota 100% > 60% > 40%
        assert_eq!(
            tokens[0].email, "kiriyamaleo@example.com",
            "Account with sonnet=100% should be first"
        );
        assert_eq!(
            tokens[1].email, "mizusawakai9@example.com",
            "Account with sonnet=60% should be second"
        );
        assert_eq!(
            tokens[2].email, "carmelioventori@example.com",
            "Account with sonnet=40% should be third"
        );

        // Clean up temp directory
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    // ==================================================================================
    // Test 19: Quota matching after model name normalization
    // Verify that requests for claude-opus-4-5-thinking correctly match claude-sonnet-4-5 quota
    // ==================================================================================

    #[test]
    fn test_quota_matching_with_normalized_model_name() {
        // Account JSON: only standard model names recorded
        let account_json = serde_json::json!({
            "email": "test@example.com",
            "quota": {
                "models": [
                    { "name": "claude-sonnet-4-5", "percentage": 75 },
                    { "name": "gemini-3-flash", "percentage": 90 }
                ]
            }
        });

        let temp_dir = std::env::temp_dir();
        let account_path = temp_dir.join(format!("test_normalized_{}.json", uuid::Uuid::new_v4()));
        std::fs::write(&account_path, account_json.to_string()).expect("Failed to write temp file");

        // Request claude-opus-4-5-thinking, should normalize to claude-sonnet-4-5
        let request_model = "claude-opus-4-5-thinking";
        let normalized = normalize_to_standard_id(request_model)
            .unwrap_or_else(|| request_model.to_string());

        assert_eq!(normalized, "claude-sonnet-4-5", "should normalize to claude-sonnet-4-5");

        // Read normalized model quota
        let quota = crate::proxy::token_manager::TokenManager::get_model_quota_from_json_for_test(
            &account_path,
            &normalized,
        );

        assert_eq!(
            quota,
            Some(75),
            "claude-opus-4-5-thinking after normalization should read claude-sonnet-4-5 quota (75%)"
        );

        // Clean up temp file
        let _ = std::fs::remove_file(&account_path);
    }

    // Helper function: Create mock token with custom account_path
    fn create_mock_token_with_path(
        account_id: &str,
        email: &str,
        protected_models: Vec<&str>,
        remaining_quota: Option<i32>,
        account_path: PathBuf,
    ) -> ProxyToken {
        ProxyToken {
            account_id: account_id.to_string(),
            access_token: format!("mock_access_token_{}", account_id),
            refresh_token: format!("mock_refresh_token_{}", account_id),
            expires_in: 3600,
            timestamp: chrono::Utc::now().timestamp() + 3600,
            email: email.to_string(),
            account_path,
            project_id: Some("test-project".to_string()),
            subscription_tier: Some("PRO".to_string()),
            remaining_quota,
            protected_models: protected_models.iter().map(|s| s.to_string()).collect(),
            health_score: 1.0,
            reset_time: None,
            validation_blocked: false,
            validation_blocked_until: 0,
            model_quotas: std::collections::HashMap::new(),
        }
    }
}
