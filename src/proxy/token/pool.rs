use std::collections::HashSet;

use crate::proxy::token::types::ProxyToken;

// Candidate pool size for P2C algorithm - randomly select from the top N best candidates.
const P2C_POOL_SIZE: usize = 5;

// Power of 2 Choices (P2C) selection algorithm.
// Randomly pick 2 from the top 5 candidates, select the one with higher quota.
pub(crate) fn select_with_p2c<'a>(
    candidates: &'a [ProxyToken],
    attempted: &HashSet<String>,
    normalized_target: &str,
    quota_protection_enabled: bool,
) -> Option<&'a ProxyToken> {
    use rand::Rng;

    // Filter available tokens.
    let available: Vec<&ProxyToken> = candidates
        .iter()
        .filter(|t| !attempted.contains(&t.account_id))
        .filter(|t| !quota_protection_enabled || !t.protected_models.contains(normalized_target))
        .collect();

    if available.is_empty() {
        return None;
    }
    if available.len() == 1 {
        return Some(available[0]);
    }

    // P2C: randomly pick 2 from the top min(P2C_POOL_SIZE, len).
    let pool_size = available.len().min(P2C_POOL_SIZE);
    let mut rng = rand::thread_rng();

    let pick1 = rng.gen_range(0..pool_size);
    let pick2 = rng.gen_range(0..pool_size);
    // Ensure two different candidates are selected.
    let pick2 = if pick2 == pick1 {
        (pick1 + 1) % pool_size
    } else {
        pick2
    };

    let c1 = available[pick1];
    let c2 = available[pick2];

    // Select the one with higher quota.
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

// Quota-first sorting: target model quota > health score > subscription tier > reset time.
pub(crate) fn sort_tokens_for_target(tokens: &mut [ProxyToken], normalized_target: &str) {
    const RESET_TIME_THRESHOLD_SECS: i64 = 600; // 10 minutes

    tokens.sort_by(|a, b| {
        // Priority 1: target model quota (higher is better).
        let quota_a = a
            .model_quotas
            .get(normalized_target)
            .copied()
            .unwrap_or(a.remaining_quota.unwrap_or(0));
        let quota_b = b
            .model_quotas
            .get(normalized_target)
            .copied()
            .unwrap_or(b.remaining_quota.unwrap_or(0));

        let quota_cmp = quota_b.cmp(&quota_a);
        if quota_cmp != std::cmp::Ordering::Equal {
            return quota_cmp;
        }

        // Priority 2: health score (higher is better).
        let health_cmp = b
            .health_score
            .partial_cmp(&a.health_score)
            .unwrap_or(std::cmp::Ordering::Equal);
        if health_cmp != std::cmp::Ordering::Equal {
            return health_cmp;
        }

        // Priority 3: subscription tier (ULTRA > PRO > FREE).
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
        let tier_cmp = tier_priority(&a.subscription_tier).cmp(&tier_priority(&b.subscription_tier));
        if tier_cmp != std::cmp::Ordering::Equal {
            return tier_cmp;
        }

        // Priority 4: reset time (earlier is better if difference >= 10 minutes).
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
