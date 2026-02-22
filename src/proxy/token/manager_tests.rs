use super::{ProxyToken, TokenManager};
use futures::StreamExt;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

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

#[tokio::test]
async fn test_sticky_session_keeps_binding_within_wait_window() {
    let tmp_root = std::env::temp_dir().join(format!(
        "antigravity-token-manager-test-sticky-wait-window-{}",
        uuid::Uuid::new_v4()
    ));
    let accounts_dir = tmp_root.join("accounts");
    std::fs::create_dir_all(&accounts_dir).unwrap();
    let now = chrono::Utc::now().timestamp();

    let write_account = |id: &str, email: &str, quota_percentage: i64| {
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
                    { "name": "gemini-3-flash", "percentage": quota_percentage }
                ]
            },
            "disabled": false,
            "proxy_disabled": false,
            "created_at": now,
            "last_used": now
        });
        std::fs::write(&account_path, serde_json::to_string_pretty(&json).unwrap()).unwrap();
    };

    write_account("acc1", "a@test.com", 90);
    write_account("acc2", "b@test.com", 10);

    let manager = TokenManager::new(tmp_root.clone());
    manager.load_accounts().await.unwrap();
    manager
        .update_sticky_config(crate::proxy::sticky_config::StickySessionConfig {
            mode: crate::proxy::sticky_config::SchedulingMode::Balance,
            max_wait_seconds: 60,
        })
        .await;
    manager
        .session_accounts
        .insert("sid-keep".to_string(), "acc1".to_string());

    manager.rate_limit_tracker.set_lockout_until(
        "acc1",
        std::time::SystemTime::now() + std::time::Duration::from_secs(5),
        crate::proxy::rate_limit::RateLimitReason::RateLimitExceeded,
        Some("gemini-3-flash".to_string()),
    );

    let (_token, _project_id, _email, account_id, _wait_ms) = manager
        .get_token("gemini", false, Some("sid-keep"), "gemini-3-flash")
        .await
        .unwrap();
    assert_eq!(account_id, "acc2");
    assert_eq!(
        manager.session_accounts.get("sid-keep").map(|v| v.clone()),
        Some("acc1".to_string())
    );
    let snapshot_after_fallback = manager.get_sticky_debug_snapshot();
    assert!(snapshot_after_fallback
        .recent_events
        .iter()
        .any(|e| { e.session_id == "sid-keep" && e.action == "kept_binding_short_wait" }));
    assert!(snapshot_after_fallback.recent_events.iter().any(|e| {
        e.session_id == "sid-keep" && e.action == "kept_existing_binding_fallback_selected"
    }));

    manager.rate_limit_tracker.clear_all();

    let (_token, _project_id, _email, account_id, _wait_ms) = manager
        .get_token("gemini", false, Some("sid-keep"), "gemini-3-flash")
        .await
        .unwrap();
    assert_eq!(account_id, "acc1");
    let snapshot_after_reuse = manager.get_sticky_debug_snapshot();
    assert!(snapshot_after_reuse
        .recent_events
        .iter()
        .any(|e| { e.session_id == "sid-keep" && e.action == "reused_bound_account" }));

    let _ = std::fs::remove_dir_all(&tmp_root);
}

#[tokio::test]
async fn test_sticky_session_rebinds_when_wait_exceeds_window() {
    let tmp_root = std::env::temp_dir().join(format!(
        "antigravity-token-manager-test-sticky-rebind-window-{}",
        uuid::Uuid::new_v4()
    ));
    let accounts_dir = tmp_root.join("accounts");
    std::fs::create_dir_all(&accounts_dir).unwrap();
    let now = chrono::Utc::now().timestamp();

    let write_account = |id: &str, email: &str, quota_percentage: i64| {
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
                    { "name": "gemini-3-flash", "percentage": quota_percentage }
                ]
            },
            "disabled": false,
            "proxy_disabled": false,
            "created_at": now,
            "last_used": now
        });
        std::fs::write(&account_path, serde_json::to_string_pretty(&json).unwrap()).unwrap();
    };

    write_account("acc1", "a@test.com", 90);
    write_account("acc2", "b@test.com", 10);

    let manager = TokenManager::new(tmp_root.clone());
    manager.load_accounts().await.unwrap();
    manager
        .update_sticky_config(crate::proxy::sticky_config::StickySessionConfig {
            mode: crate::proxy::sticky_config::SchedulingMode::Balance,
            max_wait_seconds: 2,
        })
        .await;
    manager
        .session_accounts
        .insert("sid-rebind".to_string(), "acc1".to_string());

    manager.rate_limit_tracker.set_lockout_until(
        "acc1",
        std::time::SystemTime::now() + std::time::Duration::from_secs(15),
        crate::proxy::rate_limit::RateLimitReason::RateLimitExceeded,
        Some("gemini-3-flash".to_string()),
    );

    let (_token, _project_id, _email, account_id, _wait_ms) = manager
        .get_token("gemini", false, Some("sid-rebind"), "gemini-3-flash")
        .await
        .unwrap();
    assert_eq!(account_id, "acc2");
    assert_eq!(
        manager
            .session_accounts
            .get("sid-rebind")
            .map(|v| v.clone()),
        Some("acc2".to_string())
    );
    let snapshot = manager.get_sticky_debug_snapshot();
    assert!(snapshot
        .recent_events
        .iter()
        .any(|e| e.session_id == "sid-rebind" && e.action == "unbound_long_wait"));
    assert!(snapshot
        .recent_events
        .iter()
        .any(|e| e.session_id == "sid-rebind" && e.action == "bound_new_session"));

    let _ = std::fs::remove_dir_all(&tmp_root);
}

#[tokio::test]
async fn test_session_bindings_persist_and_restore_across_restart() {
    let tmp_root = std::env::temp_dir().join(format!(
        "antigravity-token-manager-test-session-persist-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(tmp_root.join("accounts")).unwrap();

    let manager1 = TokenManager::new(tmp_root.clone());
    manager1.update_session_binding_persistence(true);
    manager1.tokens.insert(
        "acc1".to_string(),
        create_test_token("acc1", Some("PRO"), 1.0, None, Some(100)),
    );
    manager1
        .session_accounts
        .insert("sid-persist".to_string(), "acc1".to_string());
    manager1.persist_session_bindings_internal();

    let bound_1 = manager1
        .session_accounts
        .get("sid-persist")
        .map(|v| v.clone())
        .unwrap();
    assert!(tmp_root.join("session_bindings.json").exists());

    let manager2 = TokenManager::new(tmp_root.clone());
    manager2.update_session_binding_persistence(true);
    manager2.tokens.insert(
        "acc1".to_string(),
        create_test_token("acc1", Some("PRO"), 1.0, None, Some(100)),
    );
    manager2.restore_persisted_session_bindings();

    let bound_2 = manager2
        .session_accounts
        .get("sid-persist")
        .map(|v| v.clone())
        .unwrap();
    assert_eq!(bound_2, bound_1);

    let _ = std::fs::remove_dir_all(&tmp_root);
}

#[tokio::test]
async fn test_restore_session_bindings_drops_missing_accounts() {
    let tmp_root = std::env::temp_dir().join(format!(
        "antigravity-token-manager-test-session-prune-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(tmp_root.join("accounts")).unwrap();

    let manager1 = TokenManager::new(tmp_root.clone());
    manager1.update_session_binding_persistence(true);
    manager1.tokens.insert(
        "acc1".to_string(),
        create_test_token("acc1", Some("PRO"), 1.0, None, Some(100)),
    );
    manager1
        .session_accounts
        .insert("sid-prune".to_string(), "acc1".to_string());
    manager1.persist_session_bindings_internal();
    assert!(manager1.session_accounts.get("sid-prune").is_some());

    let manager2 = TokenManager::new(tmp_root.clone());
    manager2.update_session_binding_persistence(true);
    manager2.tokens.insert(
        "acc2".to_string(),
        create_test_token("acc2", Some("PRO"), 1.0, None, Some(100)),
    );
    manager2.restore_persisted_session_bindings();

    assert!(manager2.session_accounts.get("sid-prune").is_none());
    let persisted: HashMap<String, String> = serde_json::from_str(
        &std::fs::read_to_string(tmp_root.join("session_bindings.json")).unwrap(),
    )
    .unwrap();
    assert!(!persisted.contains_key("sid-prune"));

    let _ = std::fs::remove_dir_all(&tmp_root);
}

#[tokio::test]
async fn test_compliance_retry_cap_applies_when_enabled() {
    let manager = TokenManager::new(std::env::temp_dir());
    let default_attempts = manager.effective_retry_attempts(5).await;
    assert_eq!(default_attempts, 5);

    manager
        .update_compliance_config(crate::proxy::config::ComplianceConfig {
            enabled: true,
            max_global_requests_per_minute: 120,
            max_account_requests_per_minute: 20,
            max_account_concurrency: 2,
            risk_cooldown_seconds: 60,
            cooldown_on_http_429: false,
            max_retry_attempts: 1,
        })
        .await;

    let capped_attempts = manager.effective_retry_attempts(5).await;
    assert_eq!(capped_attempts, 1);
}

#[tokio::test]
async fn test_compliance_guard_enforces_account_rpm() {
    let manager = TokenManager::new(std::env::temp_dir());
    manager
        .update_compliance_config(crate::proxy::config::ComplianceConfig {
            enabled: true,
            max_global_requests_per_minute: 120,
            max_account_requests_per_minute: 1,
            max_account_concurrency: 2,
            risk_cooldown_seconds: 60,
            cooldown_on_http_429: false,
            max_retry_attempts: 2,
        })
        .await;

    let guard = manager
        .try_acquire_compliance_guard("acc-rpm")
        .await
        .expect("first acquire should succeed");
    assert!(guard.is_some());
    drop(guard);

    let second = manager.try_acquire_compliance_guard("acc-rpm").await;
    assert!(second.is_err());
}

#[tokio::test]
async fn test_compliance_guard_enforces_account_concurrency() {
    let manager = TokenManager::new(std::env::temp_dir());
    manager
        .update_compliance_config(crate::proxy::config::ComplianceConfig {
            enabled: true,
            max_global_requests_per_minute: 120,
            max_account_requests_per_minute: 20,
            max_account_concurrency: 1,
            risk_cooldown_seconds: 60,
            cooldown_on_http_429: false,
            max_retry_attempts: 2,
        })
        .await;

    let guard = manager
        .try_acquire_compliance_guard("acc-concurrency")
        .await
        .expect("first acquire should succeed");
    assert!(guard.is_some());

    let second = manager
        .try_acquire_compliance_guard("acc-concurrency")
        .await;
    assert!(second.is_err());
}

#[tokio::test]
async fn test_compliance_risk_signal_cooldown_expires() {
    let manager = TokenManager::new(std::env::temp_dir());
    manager
        .update_compliance_config(crate::proxy::config::ComplianceConfig {
            enabled: true,
            max_global_requests_per_minute: 120,
            max_account_requests_per_minute: 20,
            max_account_concurrency: 2,
            risk_cooldown_seconds: 1,
            cooldown_on_http_429: false,
            max_retry_attempts: 2,
        })
        .await;

    manager
        .mark_compliance_risk_signal("acc-cooldown", 403)
        .await;
    let blocked = manager.try_acquire_compliance_guard("acc-cooldown").await;
    assert!(blocked.is_err());

    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let allowed = manager
        .try_acquire_compliance_guard("acc-cooldown")
        .await
        .expect("acquire should succeed after cooldown");
    assert!(allowed.is_some());
}

#[tokio::test]
async fn test_compliance_debug_snapshot_reports_live_state() {
    let manager = TokenManager::new(std::env::temp_dir());
    manager
        .update_compliance_config(crate::proxy::config::ComplianceConfig {
            enabled: true,
            max_global_requests_per_minute: 120,
            max_account_requests_per_minute: 20,
            max_account_concurrency: 2,
            risk_cooldown_seconds: 60,
            cooldown_on_http_429: true,
            max_retry_attempts: 2,
        })
        .await;

    let guard = manager
        .try_acquire_compliance_guard("acc-debug")
        .await
        .expect("first acquire should succeed");
    assert!(guard.is_some());
    manager.mark_compliance_risk_signal("acc-debug", 429).await;

    let snapshot = manager.get_compliance_debug_snapshot().await;
    assert!(snapshot.config.enabled);
    assert!(snapshot.global_requests_in_last_minute >= 1);
    assert_eq!(
        snapshot
            .account_requests_in_last_minute
            .get("acc-debug")
            .copied()
            .unwrap_or(0),
        1
    );
    assert_eq!(
        snapshot
            .account_in_flight
            .get("acc-debug")
            .copied()
            .unwrap_or(0),
        1
    );
    assert!(
        snapshot
            .account_cooldown_seconds_remaining
            .get("acc-debug")
            .copied()
            .unwrap_or(0)
            > 0
    );
    assert!(snapshot.risk_signals_last_minute >= 1);
    assert_eq!(
        snapshot
            .account_429_in_last_minute
            .get("acc-debug")
            .copied()
            .unwrap_or(0),
        1
    );
    assert_eq!(
        snapshot
            .account_403_in_last_minute
            .get("acc-debug")
            .copied()
            .unwrap_or(0),
        0
    );
}

#[tokio::test]
async fn test_compliance_in_flight_persists_for_stream_lifetime() {
    let manager = TokenManager::new(std::env::temp_dir());
    manager
        .update_compliance_config(crate::proxy::config::ComplianceConfig {
            enabled: true,
            max_global_requests_per_minute: 120,
            max_account_requests_per_minute: 20,
            max_account_concurrency: 1,
            risk_cooldown_seconds: 60,
            cooldown_on_http_429: false,
            max_retry_attempts: 2,
        })
        .await;

    let guard = manager
        .try_acquire_compliance_guard("acc-stream")
        .await
        .expect("initial compliance acquire should succeed");
    assert!(guard.is_some());

    let stream = async_stream::stream! {
        yield Ok::<bytes::Bytes, String>(bytes::Bytes::from_static(b"chunk-1"));
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        yield Ok::<bytes::Bytes, String>(bytes::Bytes::from_static(b"chunk-2"));
    };
    let mut wrapped = crate::proxy::handlers::streaming::attach_guard_to_stream(stream, guard);

    let first = wrapped.next().await;
    assert!(matches!(first, Some(Ok(_))));

    let snapshot_mid = manager.get_compliance_debug_snapshot().await;
    assert_eq!(
        snapshot_mid
            .account_in_flight
            .get("acc-stream")
            .copied()
            .unwrap_or(0),
        1
    );

    let blocked_while_stream_alive = manager.try_acquire_compliance_guard("acc-stream").await;
    assert!(
        blocked_while_stream_alive.is_err(),
        "concurrency should remain enforced until stream/guard is dropped"
    );

    drop(wrapped);

    let snapshot_after_drop = manager.get_compliance_debug_snapshot().await;
    assert_eq!(
        snapshot_after_drop
            .account_in_flight
            .get("acc-stream")
            .copied()
            .unwrap_or(0),
        0
    );

    let allowed_after_drop = manager
        .try_acquire_compliance_guard("acc-stream")
        .await
        .expect("acquire should succeed after stream drops");
    assert!(allowed_after_drop.is_some());
}

#[tokio::test]
async fn test_account_switch_event_is_reported_in_compliance_snapshot() {
    let manager = TokenManager::new(std::env::temp_dir());
    manager.record_account_switch_event(Some("acc-a"), "acc-b");

    let snapshot = manager.get_compliance_debug_snapshot().await;
    assert_eq!(snapshot.account_switches_last_minute, 1);
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

    let mut tokens = [
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

    let mut tokens = [account_a.clone(), account_b.clone()];
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

    let candidates = [low_quota, high_quota];
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

    let candidates = [token_a, token_b];
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

    let candidates = [protected_account, normal_account];
    let attempted: HashSet<String> = HashSet::new();

    let result =
        crate::proxy::token::pool::select_with_p2c(&candidates, &attempted, "claude-sonnet", true);
    assert!(result.is_some());
    assert_eq!(result.unwrap().email, "normal@test.com");
}

#[test]
fn test_p2c_single_candidate() {
    let token = create_test_token("single@test.com", Some("PRO"), 1.0, None, Some(50));
    let candidates = [token];
    let attempted: HashSet<String> = HashSet::new();

    let result =
        crate::proxy::token::pool::select_with_p2c(&candidates, &attempted, "claude-sonnet", false);
    assert!(result.is_some());
    assert_eq!(result.unwrap().email, "single@test.com");
}

#[test]
fn test_p2c_empty_candidates() {
    let candidates: Vec<ProxyToken> = Vec::new();
    let attempted: HashSet<String> = HashSet::new();

    let result =
        crate::proxy::token::pool::select_with_p2c(&candidates, &attempted, "claude-sonnet", false);
    assert!(result.is_none());
}

#[test]
fn test_p2c_all_attempted() {
    let token_a = create_test_token("a@test.com", Some("PRO"), 1.0, None, Some(80));
    let token_b = create_test_token("b@test.com", Some("PRO"), 1.0, None, Some(50));

    let candidates = [token_a, token_b];
    let mut attempted: HashSet<String> = HashSet::new();
    attempted.insert("a@test.com".to_string());
    attempted.insert("b@test.com".to_string());

    let result =
        crate::proxy::token::pool::select_with_p2c(&candidates, &attempted, "claude-sonnet", false);
    assert!(result.is_none());
}

#[tokio::test]
async fn test_compliance_risk_signal_503_does_not_trigger_cooldown() {
    let manager = TokenManager::new(std::env::temp_dir());
    manager
        .update_compliance_config(crate::proxy::config::ComplianceConfig {
            enabled: true,
            max_global_requests_per_minute: 120,
            max_account_requests_per_minute: 20,
            max_account_concurrency: 2,
            risk_cooldown_seconds: 60,
            cooldown_on_http_429: false,
            max_retry_attempts: 2,
        })
        .await;

    manager
        .mark_compliance_risk_signal("acc-503-no-cooldown", 503)
        .await;
    let allowed = manager
        .try_acquire_compliance_guard("acc-503-no-cooldown")
        .await
        .expect("503 should not trigger compliance cooldown");
    assert!(allowed.is_some());
}



