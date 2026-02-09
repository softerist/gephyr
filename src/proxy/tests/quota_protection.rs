#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::models::QuotaProtectionConfig;
    use crate::proxy::common::model_mapping::normalize_to_standard_id;
    use crate::proxy::token::types::ProxyToken;

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

    #[test]
    fn test_normalize_to_standard_id_claude_models() {
        assert_eq!(
            normalize_to_standard_id("claude-sonnet-4-5"),
            Some("claude-sonnet-4-5".to_string())
        );
        assert_eq!(
            normalize_to_standard_id("claude-sonnet-4-5-thinking"),
            Some("claude-sonnet-4-5".to_string())
        );
        assert_eq!(
            normalize_to_standard_id("claude-opus-4-5-thinking"),
            Some("claude-sonnet-4-5".to_string()),
            "claude-opus-4-5-thinking should normalize to claude-sonnet-4-5"
        );
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
        assert_eq!(normalize_to_standard_id("gpt-5"), None);
        assert_eq!(normalize_to_standard_id("unknown-model"), None);
    }

    #[test]
    fn test_protected_models_matching() {
        let token = create_mock_token(
            "account-1",
            "test@example.com",
            vec!["claude-sonnet-4-5"],
            Some(50),
        );
        let target_model = "claude-opus-4-5-thinking";
        let normalized =
            normalize_to_standard_id(target_model).unwrap_or_else(|| target_model.to_string());

        assert_eq!(normalized, "claude-sonnet-4-5");
        assert!(
            token.protected_models.contains(&normalized),
            "claude-opus-4-5-thinking after normalization should match claude-sonnet-4-5 in protected_models"
        );
        let target_model_2 = "claude-sonnet-4-5-thinking";
        let normalized_2 =
            normalize_to_standard_id(target_model_2).unwrap_or_else(|| target_model_2.to_string());

        assert!(
            token.protected_models.contains(&normalized_2),
            "claude-sonnet-4-5-thinking after normalization should match protected_models"
        );
        let target_model_3 = "gemini-3-flash";
        let normalized_3 =
            normalize_to_standard_id(target_model_3).unwrap_or_else(|| target_model_3.to_string());

        assert!(
            !token.protected_models.contains(&normalized_3),
            "gemini-3-flash should not match claude-sonnet-4-5"
        );
    }

    #[test]
    fn test_multi_account_quota_protection_filtering() {
        let tokens = [
            create_mock_token(
                "account-1",
                "user1@example.com",
                vec!["claude-sonnet-4-5"],
                Some(20),
            ),
            create_mock_token("account-2", "user2@example.com", vec![], Some(80)),
            create_mock_token(
                "account-3",
                "user3@example.com",
                vec!["gemini-3-flash"],
                Some(30),
            ),
        ];
        let target_model = "claude-opus-4-5-thinking";
        let normalized_target =
            normalize_to_standard_id(target_model).unwrap_or_else(|| target_model.to_string());
        let available_accounts: Vec<_> = tokens
            .iter()
            .filter(|t| !t.protected_models.contains(&normalized_target))
            .collect();
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
        let target_model_2 = "gemini-3-flash";
        let normalized_target_2 =
            normalize_to_standard_id(target_model_2).unwrap_or_else(|| target_model_2.to_string());

        let available_accounts_2: Vec<_> = tokens
            .iter()
            .filter(|t| !t.protected_models.contains(&normalized_target_2))
            .collect();
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

    #[test]
    fn test_all_accounts_protected_returns_error() {
        let tokens = [
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
        assert_eq!(available_accounts.len(), 0);
    }

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
        let test_cases = [
            ("claude-opus-4-5-thinking", true),
            ("claude-sonnet-4-5-thinking", true),
            ("claude-sonnet-4-5", true),
            ("gemini-3-pro-high", true),
            ("gemini-3-pro-low", true),
            ("gemini-3-flash", true),
            ("gpt-5", false),
            ("gemini-3-pro-preview", true),
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

    #[test]
    fn test_quota_threshold_trigger_logic() {
        let threshold = 60;
        let quota_data = [
            ("claude-opus-4-5-thinking", 50, true),
            ("claude-sonnet-4-5-thinking", 60, true),
            ("gemini-3-flash", 61, false),
            ("gemini-3-pro-high", 100, false),
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

    #[test]
    fn test_priority_fallback_when_protected() {
        let mut tokens = [
            create_mock_token(
                "account-high",
                "high@example.com",
                vec!["claude-sonnet-4-5"],
                Some(90),
            ),
            create_mock_token("account-mid", "mid@example.com", vec![], Some(60)),
            create_mock_token("account-low", "low@example.com", vec![], Some(30)),
        ];
        tokens.sort_by(|a, b| {
            let qa = a.remaining_quota.unwrap_or(0);
            let qb = b.remaining_quota.unwrap_or(0);
            qb.cmp(&qa)
        });
        assert_eq!(tokens[0].account_id, "account-high");
        assert_eq!(tokens[1].account_id, "account-mid");
        assert_eq!(tokens[2].account_id, "account-low");
        let target_model = "claude-opus-4-5-thinking";
        let normalized_target =
            normalize_to_standard_id(target_model).unwrap_or_else(|| target_model.to_string());
        let selected = tokens
            .iter()
            .find(|t| !t.protected_models.contains(&normalized_target));
        assert!(selected.is_some());
        assert_eq!(
            selected.unwrap().account_id,
            "account-mid",
            "High-quota account is protected, should fall back to account-mid"
        );
    }

    #[test]
    fn test_model_level_protection_granularity() {
        let token = create_mock_token(
            "account-1",
            "user@example.com",
            vec!["claude-sonnet-4-5"],
            Some(50),
        );
        let normalized_claude = normalize_to_standard_id("claude-opus-4-5-thinking")
            .unwrap_or_else(|| "claude-opus-4-5-thinking".to_string());
        assert!(
            token.protected_models.contains(&normalized_claude),
            "Claude request should be protected"
        );
        let normalized_gemini = normalize_to_standard_id("gemini-3-flash")
            .unwrap_or_else(|| "gemini-3-flash".to_string());
        assert!(
            !token.protected_models.contains(&normalized_gemini),
            "Gemini request should not be protected"
        );
    }

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
        let is_protected_when_enabled =
            config_enabled.enabled && token.protected_models.contains(&normalized_target);
        assert!(
            is_protected_when_enabled,
            "Should be protected when enabled"
        );
        let is_protected_when_disabled =
            config_disabled.enabled && token.protected_models.contains(&normalized_target);
        assert!(
            !is_protected_when_disabled,
            "Should not be protected when disabled"
        );
    }

    #[test]
    fn test_full_quota_protection_flow() {
        let config = QuotaProtectionConfig {
            enabled: true,
            threshold_percentage: 60,
            monitored_models: vec![
                "claude-sonnet-4-5".to_string(),
                "gemini-3-flash".to_string(),
            ],
        };
        let accounts = [
            create_mock_token(
                "account-a",
                "a@example.com",
                vec!["claude-sonnet-4-5"],
                Some(50),
            ),
            create_mock_token("account-b", "b@example.com", vec![], Some(80)),
            create_mock_token(
                "account-c",
                "c@example.com",
                vec!["claude-sonnet-4-5", "gemini-3-flash"],
                Some(30),
            ),
            create_mock_token(
                "account-d",
                "d@example.com",
                vec!["gemini-3-flash"],
                Some(40),
            ),
        ];
        let target_claude = normalize_to_standard_id("claude-opus-4-5-thinking")
            .unwrap_or_else(|| "claude-opus-4-5-thinking".to_string());

        let available_for_claude: Vec<_> = accounts
            .iter()
            .filter(|a| !config.enabled || !a.protected_models.contains(&target_claude))
            .collect();
        assert_eq!(available_for_claude.len(), 2);
        let claude_account_ids: Vec<_> = available_for_claude
            .iter()
            .map(|a| a.account_id.as_str())
            .collect();
        assert!(claude_account_ids.contains(&"account-b"));
        assert!(claude_account_ids.contains(&"account-d"));
        let target_gemini = normalize_to_standard_id("gemini-3-flash")
            .unwrap_or_else(|| "gemini-3-flash".to_string());

        let available_for_gemini: Vec<_> = accounts
            .iter()
            .filter(|a| !config.enabled || !a.protected_models.contains(&target_gemini))
            .collect();
        assert_eq!(available_for_gemini.len(), 2);
        let gemini_account_ids: Vec<_> = available_for_gemini
            .iter()
            .map(|a| a.account_id.as_str())
            .collect();
        assert!(gemini_account_ids.contains(&"account-a"));
        assert!(gemini_account_ids.contains(&"account-b"));
        let target_unmonitored = normalize_to_standard_id("gemini-3-pro-preview")
            .unwrap_or_else(|| "gemini-3-pro-preview".to_string());

        let available_for_unmonitored: Vec<_> = accounts
            .iter()
            .filter(|a| !config.enabled || !a.protected_models.contains(&target_unmonitored))
            .collect();
        assert_eq!(available_for_unmonitored.len(), 4);
    }

    #[test]
    fn test_empty_protected_models() {
        let token = create_mock_token("account-1", "user@example.com", vec![], Some(50));

        let target = normalize_to_standard_id("claude-opus-4-5-thinking")
            .unwrap_or_else(|| "claude-opus-4-5-thinking".to_string());

        assert!(
            !token.protected_models.contains(&target),
            "Empty protected_models should not match any models"
        );
    }

    #[test]
    fn test_model_name_case_sensitivity() {
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

    #[test]
    fn test_sticky_session_quota_protection_mid_session_single_account() {
        let session_id = "session-12345";
        let target_model = "claude-opus-4-5-thinking";
        let normalized_target =
            normalize_to_standard_id(target_model).unwrap_or_else(|| target_model.to_string());
        let mut account_a = create_mock_token("account-a", "a@example.com", vec![], Some(70));
        let mut session_bindings: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        session_bindings.insert(session_id.to_string(), account_a.account_id.clone());
        let bound_account = session_bindings.get(session_id);
        assert_eq!(bound_account, Some(&"account-a".to_string()));
        assert!(!account_a.protected_models.contains(&normalized_target));
        account_a
            .protected_models
            .insert("claude-sonnet-4-5".to_string());
        let accounts = [account_a.clone()];
        let bound_id = session_bindings.get(session_id).unwrap();
        let bound_account = accounts.iter().find(|a| &a.account_id == bound_id).unwrap();
        let is_protected = bound_account.protected_models.contains(&normalized_target);

        assert!(is_protected, "Account A should be quota-protected");
        let available_accounts: Vec<_> = accounts
            .iter()
            .filter(|a| !a.protected_models.contains(&normalized_target))
            .collect();
        assert_eq!(
            available_accounts.len(),
            0,
            "Should be no available accounts"
        );
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
        let session_id = "session-67890";
        let target_model = "claude-opus-4-5-thinking";
        let normalized_target =
            normalize_to_standard_id(target_model).unwrap_or_else(|| target_model.to_string());
        let mut account_a = create_mock_token("account-a", "a@example.com", vec![], Some(70));
        let account_b = create_mock_token("account-b", "b@example.com", vec![], Some(80));

        let mut session_bindings: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        session_bindings.insert(session_id.to_string(), account_a.account_id.clone());
        assert!(!account_a.protected_models.contains(&normalized_target));
        account_a
            .protected_models
            .insert("claude-sonnet-4-5".to_string());
        let accounts = [account_a.clone(), account_b.clone()];
        let bound_id = session_bindings.get(session_id).unwrap();
        let bound_account = accounts.iter().find(|a| &a.account_id == bound_id).unwrap();
        let is_protected = bound_account.protected_models.contains(&normalized_target);

        assert!(is_protected, "Account A should be quota-protected");
        if is_protected {
            session_bindings.remove(session_id);
        }
        let available_accounts: Vec<_> = accounts
            .iter()
            .filter(|a| !a.protected_models.contains(&normalized_target))
            .collect();
        assert_eq!(available_accounts.len(), 1);
        assert_eq!(available_accounts[0].account_id, "account-b");
        let new_account = available_accounts[0];
        session_bindings.insert(session_id.to_string(), new_account.account_id.clone());
        assert_eq!(
            session_bindings.get(session_id),
            Some(&"account-b".to_string()),
            "Session should be rebound to Account B"
        );
    }

    #[test]
    fn test_quota_protection_sync_after_refresh() {
        let mut tokens_in_memory = [create_mock_token(
            "account-a",
            "a@example.com",
            vec![],
            Some(70),
        )];
        let mut account_on_disk = create_mock_token("account-a", "a@example.com", vec![], Some(50));
        let threshold = 60;
        if account_on_disk.remaining_quota.unwrap_or(100) <= threshold {
            account_on_disk
                .protected_models
                .insert("claude-sonnet-4-5".to_string());
        }
        assert!(
            account_on_disk
                .protected_models
                .contains("claude-sonnet-4-5"),
            "Account on disk should be protected"
        );
        assert!(
            !tokens_in_memory[0]
                .protected_models
                .contains("claude-sonnet-4-5"),
            "Account in memory not yet synced"
        );
        tokens_in_memory[0] = account_on_disk.clone();
        assert!(
            tokens_in_memory[0]
                .protected_models
                .contains("claude-sonnet-4-5"),
            "Account in memory after sync should be protected"
        );
        let target = normalize_to_standard_id("claude-opus-4-5-thinking")
            .unwrap_or_else(|| "claude-opus-4-5-thinking".to_string());

        let available: Vec<_> = tokens_in_memory
            .iter()
            .filter(|t| !t.protected_models.contains(&target))
            .collect();

        assert_eq!(
            available.len(),
            0,
            "Account should be filtered after synchronization"
        );
    }

    #[test]
    fn test_quota_protection_dynamic_changes() {
        let target_model = "claude-opus-4-5-thinking";
        let normalized_target =
            normalize_to_standard_id(target_model).unwrap_or_else(|| target_model.to_string());
        let mut account_a = create_mock_token("account-a", "a@example.com", vec![], Some(70));
        let mut account_b = create_mock_token("account-b", "b@example.com", vec![], Some(80));
        let accounts = [account_a.clone(), account_b.clone()];
        let available: Vec<_> = accounts
            .iter()
            .filter(|t| !t.protected_models.contains(&normalized_target))
            .collect();
        assert_eq!(available.len(), 2, "Phase 1: Both accounts available");
        account_a.remaining_quota = Some(40);
        account_a
            .protected_models
            .insert("claude-sonnet-4-5".to_string());

        let accounts = [account_a.clone(), account_b.clone()];
        let available: Vec<_> = accounts
            .iter()
            .filter(|t| !t.protected_models.contains(&normalized_target))
            .collect();
        assert_eq!(available.len(), 1, "Phase 2: Only account B available");
        assert_eq!(available[0].account_id, "account-b");
        account_b.remaining_quota = Some(30);
        account_b
            .protected_models
            .insert("claude-sonnet-4-5".to_string());

        let accounts = [account_a.clone(), account_b.clone()];
        let available: Vec<_> = accounts
            .iter()
            .filter(|t| !t.protected_models.contains(&normalized_target))
            .collect();
        assert_eq!(available.len(), 0, "Phase 3: No available accounts");
        account_a.remaining_quota = Some(100);
        account_a.protected_models.remove("claude-sonnet-4-5");

        let accounts = [account_a.clone(), account_b.clone()];
        let available: Vec<_> = accounts
            .iter()
            .filter(|t| !t.protected_models.contains(&normalized_target))
            .collect();
        assert_eq!(available.len(), 1, "Phase 4: Account A recovered/available");
        assert_eq!(available[0].account_id, "account-a");
    }

    #[test]
    fn test_error_messages_for_quota_protection() {
        let target_model = "claude-opus-4-5-thinking";
        let normalized_target =
            normalize_to_standard_id(target_model).unwrap_or_else(|| target_model.to_string());
        let all_protected = [
            create_mock_token("a1", "a1@example.com", vec!["claude-sonnet-4-5"], Some(30)),
            create_mock_token("a2", "a2@example.com", vec!["claude-sonnet-4-5"], Some(20)),
        ];

        let all_are_quota_protected = all_protected
            .iter()
            .all(|a| a.protected_models.contains(&normalized_target));

        assert!(all_are_quota_protected, "All accounts are quota-protected");
        let error = format!(
            "All {} accounts are quota-protected for model '{}'. Wait for quota reset or adjust protection threshold.",
            all_protected.len(),
            normalized_target
        );

        assert!(error.contains("quota-protected"));
        assert!(error.contains("claude-sonnet-4-5"));
        let mixed = [
            create_mock_token("a1", "a1@example.com", vec!["claude-sonnet-4-5"], Some(30)),
            create_mock_token("a2", "a2@example.com", vec![], Some(20)),
        ];

        let quota_protected_count = mixed
            .iter()
            .filter(|a| a.protected_models.contains(&normalized_target))
            .count();

        assert_eq!(quota_protected_count, 1);
    }

    #[test]
    fn test_get_model_quota_from_json_reads_correct_model() {
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
        let temp_dir = std::env::temp_dir();
        let account_path = temp_dir.join(format!("test_quota_{}.json", uuid::Uuid::new_v4()));
        std::fs::write(&account_path, account_json.to_string()).expect("Failed to write temp file");
        let sonnet_quota = crate::proxy::token::TokenManager::get_model_quota_from_json_for_test(
            &account_path,
            "claude-sonnet-4-5",
        );
        assert_eq!(
            sonnet_quota,
            Some(60),
            "claude-sonnet-4-5 should return 60%, not max(100%)"
        );
        let gemini_quota = crate::proxy::token::TokenManager::get_model_quota_from_json_for_test(
            &account_path,
            "gemini-3-flash",
        );
        assert_eq!(gemini_quota, Some(100), "gemini-3-flash should return 100%");
        let unknown_quota = crate::proxy::token::TokenManager::get_model_quota_from_json_for_test(
            &account_path,
            "unknown-model",
        );
        assert_eq!(unknown_quota, None, "Non-existent model should return None");
        let _ = std::fs::remove_file(&account_path);
    }

    #[test]
    fn test_sorting_uses_target_model_quota_not_max() {
        let temp_dir = std::env::temp_dir().join(format!("test_sorting_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).expect("Failed to create temp dir");
        let account_a_json = serde_json::json!({
            "email": "carmelioventori@example.com",
            "quota": {
                "models": [
                    { "name": "claude-sonnet-4-5", "percentage": 40 },
                    { "name": "gemini-3-flash", "percentage": 100 }
                ]
            }
        });
        let account_b_json = serde_json::json!({
            "email": "kiriyamaleo@example.com",
            "quota": {
                "models": [
                    { "name": "claude-sonnet-4-5", "percentage": 100 },
                    { "name": "gemini-3-flash", "percentage": 100 }
                ]
            }
        });
        let account_c_json = serde_json::json!({
            "email": "mizusawakai9@example.com",
            "quota": {
                "models": [
                    { "name": "claude-sonnet-4-5", "percentage": 60 },
                    { "name": "gemini-3-flash", "percentage": 100 }
                ]
            }
        });
        let path_a = temp_dir.join("account_a.json");
        let path_b = temp_dir.join("account_b.json");
        let path_c = temp_dir.join("account_c.json");

        std::fs::write(&path_a, account_a_json.to_string()).unwrap();
        std::fs::write(&path_b, account_b_json.to_string()).unwrap();
        std::fs::write(&path_c, account_c_json.to_string()).unwrap();
        let mut tokens = [
            create_mock_token_with_path(
                "a",
                "carmelioventori@example.com",
                vec![],
                Some(100),
                path_a.clone(),
            ),
            create_mock_token_with_path(
                "b",
                "kiriyamaleo@example.com",
                vec![],
                Some(100),
                path_b.clone(),
            ),
            create_mock_token_with_path(
                "c",
                "mizusawakai9@example.com",
                vec![],
                Some(100),
                path_c.clone(),
            ),
        ];
        let target_model = "claude-sonnet-4-5";
        tokens.sort_by(|a, b| {
            let quota_a = crate::proxy::token::TokenManager::get_model_quota_from_json_for_test(
                &a.account_path,
                target_model,
            )
            .unwrap_or(0);
            let quota_b = crate::proxy::token::TokenManager::get_model_quota_from_json_for_test(
                &b.account_path,
                target_model,
            )
            .unwrap_or(0);
            quota_b.cmp(&quota_a)
        });
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
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_quota_matching_with_normalized_model_name() {
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
        let request_model = "claude-opus-4-5-thinking";
        let normalized =
            normalize_to_standard_id(request_model).unwrap_or_else(|| request_model.to_string());

        assert_eq!(
            normalized, "claude-sonnet-4-5",
            "should normalize to claude-sonnet-4-5"
        );
        let quota = crate::proxy::token::TokenManager::get_model_quota_from_json_for_test(
            &account_path,
            &normalized,
        );

        assert_eq!(
            quota,
            Some(75),
            "claude-opus-4-5-thinking after normalization should read claude-sonnet-4-5 quota (75%)"
        );
        let _ = std::fs::remove_file(&account_path);
    }
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
