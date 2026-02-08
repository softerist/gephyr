
use super::*;
use std::cmp::Ordering;
use std::collections::HashMap;

#[tokio::test]
async fn test_reload_account_purges_cache_when_account_becomes_proxy_disabled() {
    let tmp_root = std::env::temp_dir().join(format!(
        "antigravity-token-manager-test-{}",
        uuid::Uuid::new_v4()
    ));
    let accounts_dir = tmp_root.join("accounts");
    std::fs::create_dir_all(&accounts_dir).unwrap();

    let account_id = "acc1";
    let email = "a@test.com";
    let now = chrono::Utc::now().timestamp();
    let account_path = accounts_dir.join(format!("{}.json", account_id));

    let account_json = serde_json::json!({
        "id": account_id,
        "email": email,
        "token": {
            "access_token": "atk",
            "refresh_token": "rtk",
            "expires_in": 3600,
            "expiry_timestamp": now + 3600
        },
        "disabled": false,
        "proxy_disabled": false,
        "created_at": now,
        "last_used": now
    });
    std::fs::write(
        &account_path,
        serde_json::to_string_pretty(&account_json).unwrap(),
    )
    .unwrap();

    let manager = TokenManager::new(tmp_root.clone());
    manager.load_accounts().await.unwrap();
    assert!(manager.tokens.get(account_id).is_some());
    manager
        .session_accounts
        .insert("sid1".to_string(), account_id.to_string());
    {
        let mut preferred = manager.preferred_account_id.write().await;
        *preferred = Some(account_id.to_string());
    }
    let mut disabled_json = account_json.clone();
    disabled_json["proxy_disabled"] = serde_json::Value::Bool(true);
    disabled_json["proxy_disabled_reason"] = serde_json::Value::String("manual".to_string());
    disabled_json["proxy_disabled_at"] = serde_json::Value::Number(now.into());
    std::fs::write(
        &account_path,
        serde_json::to_string_pretty(&disabled_json).unwrap(),
    )
    .unwrap();

    manager.reload_account(account_id).await.unwrap();

    assert!(manager.tokens.get(account_id).is_none());
    assert!(manager.session_accounts.get("sid1").is_none());
    assert!(manager.preferred_account_id.read().await.is_none());

    let _ = std::fs::remove_dir_all(&tmp_root);
}

#[tokio::test]
async fn test_fixed_account_mode_skips_preferred_when_disabled_on_disk_without_reload() {
    let tmp_root = std::env::temp_dir().join(format!(
        "antigravity-token-manager-test-fixed-mode-{}",
        uuid::Uuid::new_v4()
    ));
    let accounts_dir = tmp_root.join("accounts");
    std::fs::create_dir_all(&accounts_dir).unwrap();

    let now = chrono::Utc::now().timestamp();

    let write_account = |id: &str, email: &str, proxy_disabled: bool| {
        let account_path = accounts_dir.join(format!("{}.json", id));
        let json = serde_json::json!({
            "id": id,
            "email": email,
            "token": {
                "access_token": format!("atk-{}", id),
                "refresh_token": format!("rtk-{}", id),
                "expires_in": 3600,
                "expiry_timestamp": now + 3600,
                "project_id": format!("pid-{}", id)
            },
            "disabled": false,
            "proxy_disabled": proxy_disabled,
            "proxy_disabled_reason": if proxy_disabled { "manual" } else { "" },
            "created_at": now,
            "last_used": now
        });
        std::fs::write(&account_path, serde_json::to_string_pretty(&json).unwrap()).unwrap();
    };
    write_account("acc1", "a@test.com", false);
    write_account("acc2", "b@test.com", false);

    let manager = TokenManager::new(tmp_root.clone());
    manager.load_accounts().await.unwrap();
    manager
        .set_preferred_account(Some("acc1".to_string()))
        .await;
    write_account("acc1", "a@test.com", true);

    let (_token, _project_id, email, account_id, _wait_ms) = manager
        .get_token("gemini", false, Some("sid1"), "gemini-3-flash")
        .await
        .unwrap();
    assert_eq!(account_id, "acc2");
    assert_eq!(email, "b@test.com");
    assert!(manager.tokens.get("acc1").is_none());
    assert!(manager.get_preferred_account().await.is_none());

    let _ = std::fs::remove_dir_all(&tmp_root);
}

#[tokio::test]
async fn test_sticky_session_skips_bound_account_when_disabled_on_disk_without_reload() {
    let tmp_root = std::env::temp_dir().join(format!(
        "antigravity-token-manager-test-sticky-disabled-{}",
        uuid::Uuid::new_v4()
    ));
    let accounts_dir = tmp_root.join("accounts");
    std::fs::create_dir_all(&accounts_dir).unwrap();

    let now = chrono::Utc::now().timestamp();

    let write_account = |id: &str, email: &str, percentage: i64, proxy_disabled: bool| {
        let account_path = accounts_dir.join(format!("{}.json", id));
        let json = serde_json::json!({
            "id": id,
            "email": email,
            "token": {
                "access_token": format!("atk-{}", id),
                "refresh_token": format!("rtk-{}", id),
                "expires_in": 3600,
                "expiry_timestamp": now + 3600,
                "project_id": format!("pid-{}", id)
            },
            "quota": {
                "models": [
                    { "name": "gemini-3-flash", "percentage": percentage }
                ]
            },
            "disabled": false,
            "proxy_disabled": proxy_disabled,
            "proxy_disabled_reason": if proxy_disabled { "manual" } else { "" },
            "created_at": now,
            "last_used": now
        });
        std::fs::write(&account_path, serde_json::to_string_pretty(&json).unwrap()).unwrap();
    };
    write_account("acc1", "a@test.com", 90, false);
    write_account("acc2", "b@test.com", 10, false);

    let manager = TokenManager::new(tmp_root.clone());
    manager.load_accounts().await.unwrap();
    let (_token, _project_id, _email, account_id, _wait_ms) = manager
        .get_token("gemini", false, Some("sid1"), "gemini-3-flash")
        .await
        .unwrap();
    assert_eq!(account_id, "acc1");
    assert_eq!(
        manager.session_accounts.get("sid1").map(|v| v.clone()),
        Some("acc1".to_string())
    );
    write_account("acc1", "a@test.com", 90, true);

    let (_token, _project_id, email, account_id, _wait_ms) = manager
        .get_token("gemini", false, Some("sid1"), "gemini-3-flash")
        .await
        .unwrap();
    assert_eq!(account_id, "acc2");
    assert_eq!(email, "b@test.com");
    assert!(manager.tokens.get("acc1").is_none());
    assert_ne!(
        manager.session_accounts.get("sid1").map(|v| v.clone()),
        Some("acc1".to_string())
    );

    let _ = std::fs::remove_dir_all(&tmp_root);
}
fn create_test_token(
    email: &str,
    tier: Option<&str>,
    health_score: f32,
    reset_time: Option<i64>,
    remaining_quota: Option<i32>,
) -> ProxyToken {
    ProxyToken {
        account_id: email.to_string(),
        access_token: "test_token".to_string(),
        refresh_token: "test_refresh".to_string(),
        expires_in: 3600,
        timestamp: chrono::Utc::now().timestamp() + 3600,
        email: email.to_string(),
        account_path: PathBuf::from("/tmp/test"),
        project_id: None,
        subscription_tier: tier.map(|s| s.to_string()),
        remaining_quota,
        protected_models: HashSet::new(),
        health_score,
        reset_time,
        validation_blocked: false,
        validation_blocked_until: 0,
        model_quotas: HashMap::new(),
    }
}
fn compare_tokens(a: &ProxyToken, b: &ProxyToken) -> Ordering {
    const RESET_TIME_THRESHOLD_SECS: i64 = 600;

    let tier_priority = |tier: &Option<String>| {
        let t = tier.as_deref().unwrap_or("").to_lowercase();
        if t.contains("ultra") {
            0
        } else if t.contains("pro") {
            1
        } else if t.contains("free") {
            2
        } else {
            3
        }
    };
    let tier_cmp = tier_priority(&a.subscription_tier).cmp(&tier_priority(&b.subscription_tier));
    if tier_cmp != Ordering::Equal {
        return tier_cmp;
    }
    let health_cmp = b
        .health_score
        .partial_cmp(&a.health_score)
        .unwrap_or(Ordering::Equal);
    if health_cmp != Ordering::Equal {
        return health_cmp;
    }
    let reset_a = a.reset_time.unwrap_or(i64::MAX);
    let reset_b = b.reset_time.unwrap_or(i64::MAX);
    let reset_diff = (reset_a - reset_b).abs();

    if reset_diff >= RESET_TIME_THRESHOLD_SECS {
        let reset_cmp = reset_a.cmp(&reset_b);
        if reset_cmp != Ordering::Equal {
            return reset_cmp;
        }
    }
    let quota_a = a.remaining_quota.unwrap_or(0);
    let quota_b = b.remaining_quota.unwrap_or(0);
    quota_b.cmp(&quota_a)
}

#[test]
fn test_sorting_tier_priority() {
    let ultra = create_test_token("ultra@test.com", Some("ULTRA"), 1.0, None, Some(50));
    let pro = create_test_token("pro@test.com", Some("PRO"), 1.0, None, Some(50));
    let free = create_test_token("free@test.com", Some("FREE"), 1.0, None, Some(50));

    assert_eq!(compare_tokens(&ultra, &pro), Ordering::Less);
    assert_eq!(compare_tokens(&pro, &free), Ordering::Less);
    assert_eq!(compare_tokens(&ultra, &free), Ordering::Less);
    assert_eq!(compare_tokens(&free, &ultra), Ordering::Greater);
}

#[test]
fn test_sorting_health_score_priority() {
    let high_health = create_test_token("high@test.com", Some("PRO"), 1.0, None, Some(50));
    let low_health = create_test_token("low@test.com", Some("PRO"), 0.5, None, Some(50));

    assert_eq!(compare_tokens(&high_health, &low_health), Ordering::Less);
    assert_eq!(compare_tokens(&low_health, &high_health), Ordering::Greater);
}

#[test]
fn test_sorting_reset_time_priority() {
    let now = chrono::Utc::now().timestamp();
    let soon_reset = create_test_token(
        "soon@test.com",
        Some("PRO"),
        1.0,
        Some(now + 1800),
        Some(50),
    );
    let late_reset = create_test_token(
        "late@test.com",
        Some("PRO"),
        1.0,
        Some(now + 18000),
        Some(50),
    );

    assert_eq!(compare_tokens(&soon_reset, &late_reset), Ordering::Less);
    assert_eq!(compare_tokens(&late_reset, &soon_reset), Ordering::Greater);
}

#[test]
fn test_sorting_reset_time_threshold() {
    let now = chrono::Utc::now().timestamp();
    let reset_a = create_test_token("a@test.com", Some("PRO"), 1.0, Some(now + 1800), Some(80));
    let reset_b = create_test_token("b@test.com", Some("PRO"), 1.0, Some(now + 2100), Some(50));
    assert_eq!(compare_tokens(&reset_a, &reset_b), Ordering::Less);
}

#[test]
fn test_sorting_reset_time_beyond_threshold() {
    let now = chrono::Utc::now().timestamp();
    let soon_low_quota = create_test_token(
        "soon@test.com",
        Some("PRO"),
        1.0,
        Some(now + 1800),
        Some(20),
    );
    let late_high_quota = create_test_token(
        "late@test.com",
        Some("PRO"),
        1.0,
        Some(now + 18000),
        Some(90),
    );
    assert_eq!(
        compare_tokens(&soon_low_quota, &late_high_quota),
        Ordering::Less
    );
}

#[test]
fn test_sorting_quota_fallback() {
    let high_quota = create_test_token("high@test.com", Some("PRO"), 1.0, None, Some(80));
    let low_quota = create_test_token("low@test.com", Some("PRO"), 1.0, None, Some(20));

    assert_eq!(compare_tokens(&high_quota, &low_quota), Ordering::Less);
    assert_eq!(compare_tokens(&low_quota, &high_quota), Ordering::Greater);
}

#[test]
fn test_sorting_missing_reset_time() {
    let now = chrono::Utc::now().timestamp();
    let with_reset = create_test_token(
        "with@test.com",
        Some("PRO"),
        1.0,
        Some(now + 1800),
        Some(50),
    );
    let without_reset = create_test_token("without@test.com", Some("PRO"), 1.0, None, Some(50));

    assert_eq!(compare_tokens(&with_reset, &without_reset), Ordering::Less);
}

#[test]
fn test_full_sorting_integration() {
    let now = chrono::Utc::now().timestamp();

    let mut tokens = vec![
        create_test_token(
            "free_high@test.com",
            Some("FREE"),
            1.0,
            Some(now + 1800),
            Some(90),
        ),
        create_test_token(
            "pro_low_health@test.com",
            Some("PRO"),
            0.5,
            Some(now + 1800),
            Some(90),
        ),
        create_test_token(
            "pro_soon@test.com",
            Some("PRO"),
            1.0,
            Some(now + 1800),
            Some(50),
        ),
        create_test_token(
            "pro_late@test.com",
            Some("PRO"),
            1.0,
            Some(now + 18000),
            Some(90),
        ),
        create_test_token(
            "ultra@test.com",
            Some("ULTRA"),
            1.0,
            Some(now + 36000),
            Some(10),
        ),
    ];

    tokens.sort_by(compare_tokens);
    assert_eq!(tokens[0].email, "ultra@test.com");
    assert_eq!(tokens[1].email, "pro_soon@test.com");
    assert_eq!(tokens[2].email, "pro_late@test.com");
    assert_eq!(tokens[3].email, "pro_low_health@test.com");
    assert_eq!(tokens[4].email, "free_high@test.com");
}

#[test]
fn test_realistic_scenario() {
    let now = chrono::Utc::now().timestamp();

    let account_a = create_test_token(
        "a@test.com",
        Some("PRO"),
        1.0,
        Some(now + 295 * 60),
        Some(80),
    );
    let account_b = create_test_token(
        "b@test.com",
        Some("PRO"),
        1.0,
        Some(now + 31 * 60),
        Some(30),
    );
    assert_eq!(compare_tokens(&account_b, &account_a), Ordering::Less);

    let mut tokens = vec![account_a.clone(), account_b.clone()];
    tokens.sort_by(compare_tokens);

    assert_eq!(tokens[0].email, "b@test.com");
    assert_eq!(tokens[1].email, "a@test.com");
}

#[test]
fn test_extract_earliest_reset_time() {
    let account_with_claude = serde_json::json!({
        "quota": {
            "models": [
                {"name": "gemini-flash", "reset_time": "2025-01-31T10:00:00Z"},
                {"name": "claude-sonnet", "reset_time": "2025-01-31T08:00:00Z"},
                {"name": "claude-opus", "reset_time": "2025-01-31T08:00:00Z"}
            ]
        }
    });

    let result = crate::proxy::token::loader::extract_earliest_reset_time(&account_with_claude);
    assert!(result.is_some());
    let expected_ts = chrono::DateTime::parse_from_rfc3339("2025-01-31T08:00:00Z")
        .unwrap()
        .timestamp();
    assert_eq!(result.unwrap(), expected_ts);
}

#[test]
fn test_extract_reset_time_no_claude() {
    let account_no_claude = serde_json::json!({
        "quota": {
            "models": [
                {"name": "gemini-flash", "reset_time": "2025-01-31T10:00:00Z"},
                {"name": "gemini-pro", "reset_time": "2025-01-31T08:00:00Z"}
            ]
        }
    });

    let result = crate::proxy::token::loader::extract_earliest_reset_time(&account_no_claude);
    assert!(result.is_some());
    let expected_ts = chrono::DateTime::parse_from_rfc3339("2025-01-31T08:00:00Z")
        .unwrap()
        .timestamp();
    assert_eq!(result.unwrap(), expected_ts);
}

#[test]
fn test_extract_reset_time_missing_quota() {
    let account_no_quota = serde_json::json!({
        "email": "test@test.com"
    });

    assert!(crate::proxy::token::loader::extract_earliest_reset_time(&account_no_quota).is_none());
}
fn create_test_token_with_protected(
    email: &str,
    remaining_quota: Option<i32>,
    protected_models: HashSet<String>,
) -> ProxyToken {
    ProxyToken {
        account_id: email.to_string(),
        access_token: "test_token".to_string(),
        refresh_token: "test_refresh".to_string(),
        expires_in: 3600,
        timestamp: chrono::Utc::now().timestamp() + 3600,
        email: email.to_string(),
        account_path: PathBuf::from("/tmp/test"),
        project_id: None,
        subscription_tier: Some("PRO".to_string()),
        remaining_quota,
        protected_models,
        health_score: 1.0,
        reset_time: None,
        validation_blocked: false,
        validation_blocked_until: 0,
        model_quotas: HashMap::new(),
    }
}

#[test]
fn test_p2c_selects_higher_quota() {
    let low_quota = create_test_token("low@test.com", Some("PRO"), 1.0, None, Some(20));
    let high_quota = create_test_token("high@test.com", Some("PRO"), 1.0, None, Some(80));

    let candidates = vec![low_quota, high_quota];
    let attempted: HashSet<String> = HashSet::new();
    for _ in 0..10 {
        let result = crate::proxy::token::pool::select_with_p2c(
            &candidates,
            &attempted,
            "claude-sonnet",
            false,
        );
        assert!(result.is_some());
        assert_eq!(result.unwrap().email, "high@test.com");
    }
}

#[test]
fn test_p2c_skips_attempted() {
    let token_a = create_test_token("a@test.com", Some("PRO"), 1.0, None, Some(80));
    let token_b = create_test_token("b@test.com", Some("PRO"), 1.0, None, Some(50));

    let candidates = vec![token_a, token_b];
    let mut attempted: HashSet<String> = HashSet::new();
    attempted.insert("a@test.com".to_string());

    let result =
        crate::proxy::token::pool::select_with_p2c(&candidates, &attempted, "claude-sonnet", false);
    assert!(result.is_some());
    assert_eq!(result.unwrap().email, "b@test.com");
}

#[test]
fn test_p2c_skips_protected_models() {
    let mut protected = HashSet::new();
    protected.insert("claude-sonnet".to_string());

    let protected_account =
        create_test_token_with_protected("protected@test.com", Some(90), protected);
    let normal_account =
        create_test_token_with_protected("normal@test.com", Some(50), HashSet::new());

    let candidates = vec![protected_account, normal_account];
    let attempted: HashSet<String> = HashSet::new();

    let result =
        crate::proxy::token::pool::select_with_p2c(&candidates, &attempted, "claude-sonnet", true);
    assert!(result.is_some());
    assert_eq!(result.unwrap().email, "normal@test.com");
}

#[test]
fn test_p2c_single_candidate() {
    let token = create_test_token("single@test.com", Some("PRO"), 1.0, None, Some(50));
    let candidates = vec![token];
    let attempted: HashSet<String> = HashSet::new();

    let result =
        crate::proxy::token::pool::select_with_p2c(&candidates, &attempted, "claude-sonnet", false);
    assert!(result.is_some());
    assert_eq!(result.unwrap().email, "single@test.com");
}

#[test]
fn test_p2c_empty_candidates() {
    let candidates: Vec<ProxyToken> = vec![];
    let attempted: HashSet<String> = HashSet::new();

    let result =
        crate::proxy::token::pool::select_with_p2c(&candidates, &attempted, "claude-sonnet", false);
    assert!(result.is_none());
}

#[test]
fn test_p2c_all_attempted() {
    let token_a = create_test_token("a@test.com", Some("PRO"), 1.0, None, Some(80));
    let token_b = create_test_token("b@test.com", Some("PRO"), 1.0, None, Some(50));

    let candidates = vec![token_a, token_b];
    let mut attempted: HashSet<String> = HashSet::new();
    attempted.insert("a@test.com".to_string());
    attempted.insert("b@test.com".to_string());

    let result =
        crate::proxy::token::pool::select_with_p2c(&candidates, &attempted, "claude-sonnet", false);
    assert!(result.is_none());
}
