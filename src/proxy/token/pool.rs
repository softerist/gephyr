use std::collections::HashSet;

use crate::proxy::token::types::ProxyToken;
const P2C_POOL_SIZE: usize = 5;

#[inline]
pub(crate) fn requires_explicit_model_support(
    tokens: &[ProxyToken],
    normalized_target: &str,
) -> bool {
    tokens
        .iter()
        .any(|t| t.model_quotas.contains_key(normalized_target))
}

#[inline]
pub(crate) fn supports_target_model(
    token: &ProxyToken,
    normalized_target: &str,
    require_explicit_model_support: bool,
) -> bool {
    !require_explicit_model_support || token.model_quotas.contains_key(normalized_target)
}

pub(crate) fn select_with_p2c<'a>(
    candidates: &'a [ProxyToken],
    attempted: &HashSet<String>,
    normalized_target: &str,
    quota_protection_enabled: bool,
) -> Option<&'a ProxyToken> {
    use rand::Rng;
    let require_explicit_model_support =
        requires_explicit_model_support(candidates, normalized_target);
    let available: Vec<&ProxyToken> = candidates
        .iter()
        .filter(|t| !attempted.contains(&t.account_id))
        .filter(|t| !quota_protection_enabled || !t.protected_models.contains(normalized_target))
        .filter(|t| {
            supports_target_model(t, normalized_target, require_explicit_model_support)
        })
        .collect();

    if available.is_empty() {
        return None;
    }
    if available.len() == 1 {
        return Some(available[0]);
    }
    let pool_size = available.len().min(P2C_POOL_SIZE);
    let mut rng = rand::thread_rng();

    let pick1 = rng.gen_range(0..pool_size);
    let pick2 = rng.gen_range(0..pool_size);
    let pick2 = if pick2 == pick1 {
        (pick1 + 1) % pool_size
    } else {
        pick2
    };

    let c1 = available[pick1];
    let c2 = available[pick2];
    let selected = if c1.remaining_quota.unwrap_or(0) >= c2.remaining_quota.unwrap_or(0) {
        c1
    } else {
        c2
    };

    tracing::debug!(
        "🎲 [P2C] Selected {} ({}%) from [{}({}%), {}({}%)]",
        selected.email,
        selected.remaining_quota.unwrap_or(0),
        c1.email,
        c1.remaining_quota.unwrap_or(0),
        c2.email,
        c2.remaining_quota.unwrap_or(0)
    );

    Some(selected)
}
pub(crate) fn sort_tokens_for_target(tokens: &mut [ProxyToken], normalized_target: &str) {
    const RESET_TIME_THRESHOLD_SECS: i64 = 600;
    let require_explicit_model_support = requires_explicit_model_support(tokens, normalized_target);

    tokens.sort_by(|a, b| {
        let quota_a = if require_explicit_model_support {
            a.model_quotas.get(normalized_target).copied().unwrap_or(-1)
        } else {
            a.model_quotas
                .get(normalized_target)
                .copied()
                .unwrap_or(a.remaining_quota.unwrap_or(0))
        };
        let quota_b = if require_explicit_model_support {
            b.model_quotas.get(normalized_target).copied().unwrap_or(-1)
        } else {
            b.model_quotas
                .get(normalized_target)
                .copied()
                .unwrap_or(b.remaining_quota.unwrap_or(0))
        };

        let quota_cmp = quota_b.cmp(&quota_a);
        if quota_cmp != std::cmp::Ordering::Equal {
            return quota_cmp;
        }
        let health_cmp = b
            .health_score
            .partial_cmp(&a.health_score)
            .unwrap_or(std::cmp::Ordering::Equal);
        if health_cmp != std::cmp::Ordering::Equal {
            return health_cmp;
        }
        let tier_priority = |tier: &Option<String>| {
            let t = tier.as_deref().unwrap_or("").to_ascii_lowercase();
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
        let tier_cmp =
            tier_priority(&a.subscription_tier).cmp(&tier_priority(&b.subscription_tier));
        if tier_cmp != std::cmp::Ordering::Equal {
            return tier_cmp;
        }
        let reset_a = a.reset_time.unwrap_or(i64::MAX);
        let reset_b = b.reset_time.unwrap_or(i64::MAX);
        if (reset_a - reset_b).abs() >= RESET_TIME_THRESHOLD_SECS {
            reset_a.cmp(&reset_b)
        } else {
            std::cmp::Ordering::Equal
        }
    });
}

pub(crate) fn debug_rotation_rows(tokens: &[ProxyToken], normalized_target: &str) -> Vec<String> {
    tokens
        .iter()
        .map(|t| {
            format!(
                "{}(quota={}%, reset={:?}, health={:.2})",
                t.email,
                t.model_quotas.get(normalized_target).copied().unwrap_or(0),
                t.reset_time.map(|ts| {
                    let now = chrono::Utc::now().timestamp();
                    let diff_secs = ts - now;
                    if diff_secs > 0 {
                        format!("{}m", diff_secs / 60)
                    } else {
                        "now".to_string()
                    }
                }),
                t.health_score
            )
        })
        .collect()
}

#[inline]
pub(crate) fn is_quota_protected(
    token: &ProxyToken,
    normalized_target: &str,
    quota_protection_enabled: bool,
) -> bool {
    quota_protection_enabled && token.protected_models.contains(normalized_target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};
    use std::path::PathBuf;

    fn mk_token(
        account_id: &str,
        email: &str,
        remaining_quota: i32,
        model_quota: Option<(&str, i32)>,
    ) -> ProxyToken {
        let mut model_quotas = HashMap::new();
        if let Some((model, quota)) = model_quota {
            model_quotas.insert(model.to_string(), quota);
        }
        ProxyToken {
            account_id: account_id.to_string(),
            access_token: "access".to_string(),
            refresh_token: "refresh".to_string(),
            expires_in: 3600,
            timestamp: 0,
            email: email.to_string(),
            account_path: PathBuf::from("."),
            project_id: Some("project".to_string()),
            subscription_tier: Some("pro".to_string()),
            remaining_quota: Some(remaining_quota),
            protected_models: HashSet::new(),
            health_score: 1.0,
            reset_time: None,
            validation_blocked: false,
            validation_blocked_until: 0,
            model_quotas,
        }
    }

    #[test]
    fn strict_model_support_is_required_when_any_candidate_has_target_quota() {
        let target = "claude-sonnet-4-6-thinking";
        let tokens = vec![
            mk_token("a", "a@test", 100, None),
            mk_token("b", "b@test", 10, Some((target, 10))),
        ];
        assert!(requires_explicit_model_support(&tokens, target));
    }

    #[test]
    fn select_with_p2c_skips_tokens_without_explicit_target_quota_when_strict() {
        let target = "claude-sonnet-4-6-thinking";
        let tokens = vec![
            mk_token("a", "a@test", 100, None),
            mk_token("b", "b@test", 10, Some((target, 10))),
        ];
        let attempted = HashSet::new();
        let selected = select_with_p2c(&tokens, &attempted, target, false).expect("selected");
        assert_eq!(selected.account_id, "b");
    }

    #[test]
    fn sort_tokens_prioritizes_explicit_target_quota_when_strict() {
        let target = "claude-sonnet-4-6-thinking";
        let mut tokens = vec![
            mk_token("a", "a@test", 100, None),
            mk_token("b", "b@test", 10, Some((target, 10))),
        ];
        sort_tokens_for_target(&mut tokens, target);
        assert_eq!(tokens[0].account_id, "b");
    }
}
