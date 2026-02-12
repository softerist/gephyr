use dashmap::DashMap;
use rand::Rng;
use serde::Serialize;
use std::path::Path;
use std::sync::Arc;

use super::types::ProxyToken;

/// Random delay window between startup token refreshes (seconds).
const STARTUP_HEALTH_DELAY_MIN_SECONDS_DEFAULT: u64 = 2;
const STARTUP_HEALTH_DELAY_MAX_SECONDS_DEFAULT: u64 = 8;

/// Tokens expiring within this window (seconds) are proactively refreshed.
const REFRESH_WINDOW_SECS: i64 = 300;

/// Per-account timeout for a single refresh attempt (seconds).
const REFRESH_TIMEOUT_SECS: u64 = 10;

/// Result of a single account health check.
enum HealthCheckOutcome {
    Refreshed,
    Disabled,
    NetworkError,
}

fn startup_health_delay_bounds_seconds() -> (u64, u64) {
    let min = std::env::var("STARTUP_HEALTH_DELAY_MIN_SECONDS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(STARTUP_HEALTH_DELAY_MIN_SECONDS_DEFAULT);
    let max = std::env::var("STARTUP_HEALTH_DELAY_MAX_SECONDS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(STARTUP_HEALTH_DELAY_MAX_SECONDS_DEFAULT);

    if min <= max {
        (min, max)
    } else {
        (max, min)
    }
}

/// Per-account detail returned in the health check summary.
#[derive(Serialize, Clone)]
pub struct AccountHealthResult {
    pub account_id: String,
    pub email: String,
    pub status: String, // "ok", "refreshed", "disabled", "error"
    pub detail: Option<String>,
}

/// Summary returned by the health check.
#[derive(Serialize)]
pub struct HealthCheckSummary {
    pub total: u32,
    pub skipped: u32,
    pub refreshed: u32,
    pub disabled: u32,
    pub network_errors: u32,
    pub accounts: Vec<AccountHealthResult>,
}

/// Runs a lightweight health check on all loaded accounts.
///
/// For each account whose access token is expired or expiring within 5 minutes,
/// attempts a token refresh. On `invalid_grant`, the account is disabled on disk
/// and removed from the in-memory pool. Network errors are logged as warnings
/// but do not disable the account (transient failure).
///
/// Accounts with tokens still valid beyond the window are skipped (no API call).
pub(crate) async fn run_startup_health_check(
    tokens: &Arc<DashMap<String, ProxyToken>>,
    data_dir: &Path,
) -> HealthCheckSummary {
    let now = chrono::Utc::now().timestamp();
    let total = tokens.len() as u32;

    // Collect accounts that need a refresh (expired or expiring soon).
    let candidates: Vec<(String, String, String, std::path::PathBuf)> = tokens
        .iter()
        .filter_map(|entry| {
            let t = entry.value();
            if t.timestamp <= now + REFRESH_WINDOW_SECS {
                Some((
                    t.account_id.clone(),
                    t.refresh_token.clone(),
                    t.email.clone(),
                    t.account_path.clone(),
                ))
            } else {
                None
            }
        })
        .collect();

    // Build results for skipped (healthy) accounts.
    let mut account_results: Vec<AccountHealthResult> = tokens
        .iter()
        .filter(|entry| entry.value().timestamp > now + REFRESH_WINDOW_SECS)
        .map(|entry| AccountHealthResult {
            account_id: entry.value().account_id.clone(),
            email: entry.value().email.clone(),
            status: "ok".to_string(),
            detail: Some("token valid".to_string()),
        })
        .collect();

    let skipped = account_results.len() as u32;

    if candidates.is_empty() {
        tracing::info!(
            "[OK] Health check: all {} account(s) have valid tokens, nothing to refresh",
            tokens.len()
        );
        return HealthCheckSummary {
            total,
            skipped,
            refreshed: 0,
            disabled: 0,
            network_errors: 0,
            accounts: account_results,
        };
    }

    tracing::info!(
        "[Health] Health check: {} account(s) need refresh, {} skipped (tokens valid)",
        candidates.len(),
        skipped
    );

    let candidate_total = candidates.len();
    let (delay_min_seconds, delay_max_seconds) = startup_health_delay_bounds_seconds();
    tracing::info!(
        "[Startup Health] Sequential refresh enabled: {} account(s) will be refreshed one-by-one with random delay {}..{}s between accounts to avoid simultaneous Google connections",
        candidate_total,
        delay_min_seconds,
        delay_max_seconds
    );

    let mut refreshed = 0u32;
    let mut disabled = 0u32;
    let mut network_errors = 0u32;

    for (index, (account_id, refresh_token, email, account_path)) in
        candidates.into_iter().enumerate()
    {
        if index > 0 && delay_max_seconds > 0 {
            let delay_seconds = if delay_min_seconds == delay_max_seconds {
                delay_min_seconds
            } else {
                rand::thread_rng().gen_range(delay_min_seconds..=delay_max_seconds)
            };
            if delay_seconds > 0 {
                tracing::info!(
                    "[Startup Health] Waiting {}s before next account refresh ({}/{})",
                    delay_seconds,
                    index + 1,
                    candidate_total
                );
                tokio::time::sleep(std::time::Duration::from_secs(delay_seconds)).await;
            }
        }

        tracing::info!(
            "[Startup Health] Refreshing account {}/{}: {} ({})",
            index + 1,
            candidate_total,
            email,
            account_id
        );

        let (outcome, detail) = check_single_account(
            &account_id,
            &refresh_token,
            &email,
            &account_path,
            tokens,
            data_dir,
        )
        .await;

        match outcome {
            HealthCheckOutcome::Refreshed => {
                refreshed += 1;
                account_results.push(AccountHealthResult {
                    account_id,
                    email,
                    status: "refreshed".to_string(),
                    detail,
                });
            }
            HealthCheckOutcome::Disabled => {
                disabled += 1;
                account_results.push(AccountHealthResult {
                    account_id,
                    email,
                    status: "disabled".to_string(),
                    detail,
                });
            }
            HealthCheckOutcome::NetworkError => {
                network_errors += 1;
                account_results.push(AccountHealthResult {
                    account_id,
                    email,
                    status: "error".to_string(),
                    detail,
                });
            }
        }
    }

    let ok_count = skipped + refreshed;
    if disabled > 0 || network_errors > 0 {
        tracing::warn!(
            "[WARN] Health check complete: {} OK, {} refreshed, {} disabled (invalid_grant), {} network errors",
            ok_count, refreshed, disabled, network_errors
        );
    } else {
        tracing::info!(
            "[OK] Health check complete: {} OK, {} refreshed, {} disabled",
            ok_count,
            refreshed,
            disabled
        );
    }

    HealthCheckSummary {
        total,
        skipped,
        refreshed,
        disabled,
        network_errors,
        accounts: account_results,
    }
}

async fn check_single_account(
    account_id: &str,
    refresh_token: &str,
    email: &str,
    account_path: &Path,
    tokens: &Arc<DashMap<String, ProxyToken>>,
    _data_dir: &Path,
) -> (HealthCheckOutcome, Option<String>) {
    tracing::debug!(
        "[Health] Health check: refreshing token for {} ({})",
        email,
        account_id
    );

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(REFRESH_TIMEOUT_SECS),
        crate::modules::auth::oauth::refresh_access_token(refresh_token, Some(account_id)),
    )
    .await;

    match result {
        Ok(Ok(token_response)) => {
            // Refresh succeeded — persist to disk and update in-memory token.
            if let Err(e) = crate::proxy::token::persistence::save_refreshed_token(
                account_path,
                &token_response,
            ) {
                tracing::warn!(
                    "Health check: token refreshed for {} but failed to persist: {}",
                    email,
                    e
                );
            }

            // Update the in-memory ProxyToken with new access token + expiry.
            if let Some(mut entry) = tokens.get_mut(account_id) {
                let now = chrono::Utc::now().timestamp();
                entry.access_token = token_response.access_token;
                entry.expires_in = token_response.expires_in;
                entry.timestamp = now + token_response.expires_in;
            }

            tracing::info!(
                "[OK] Health: {} ({}) -- token refreshed successfully",
                email,
                account_id
            );
            (
                HealthCheckOutcome::Refreshed,
                Some("token refreshed".to_string()),
            )
        }
        Ok(Err(e)) => {
            if e.contains("\"invalid_grant\"") || e.contains("invalid_grant") {
                // Refresh token is revoked or expired — disable the account.
                tracing::warn!(
                    "[ERR] Health: {} ({}) -- invalid_grant, disabling account",
                    email,
                    account_id
                );

                if let Err(persist_err) = crate::proxy::token::persistence::disable_account(
                    account_path,
                    &format!("health_check: {}", e),
                ) {
                    tracing::warn!(
                        "Failed to persist disabled state for {}: {}",
                        email,
                        persist_err
                    );
                }

                // Remove from in-memory pool so it won't be used for routing.
                tokens.remove(account_id);

                (
                    HealthCheckOutcome::Disabled,
                    Some(format!("invalid_grant: {}", e)),
                )
            } else {
                // Other error (network issue, server error, etc.) — don't disable.
                tracing::warn!(
                    "[WARN] Health: {} ({}) -- refresh error (not disabling): {}",
                    email,
                    account_id,
                    e
                );
                (HealthCheckOutcome::NetworkError, Some(e))
            }
        }
        Err(_) => {
            // Timeout — treat as network error, don't disable.
            tracing::warn!(
                "[WARN] Health: {} ({}) -- refresh timed out ({}s), skipping",
                email,
                account_id,
                REFRESH_TIMEOUT_SECS
            );
            (
                HealthCheckOutcome::NetworkError,
                Some(format!("timeout ({}s)", REFRESH_TIMEOUT_SECS)),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::startup_health_delay_bounds_seconds;
    use crate::test_utils::{lock_env, ScopedEnvVar};

    #[test]
    fn startup_health_delay_bounds_swap_when_reversed() {
        let _guard = lock_env();
        let _min = ScopedEnvVar::set("STARTUP_HEALTH_DELAY_MIN_SECONDS", "10");
        let _max = ScopedEnvVar::set("STARTUP_HEALTH_DELAY_MAX_SECONDS", "2");

        let (min_seconds, max_seconds) = startup_health_delay_bounds_seconds();
        assert_eq!(min_seconds, 2);
        assert_eq!(max_seconds, 10);
    }

    #[test]
    fn startup_health_delay_bounds_have_defaults() {
        let _guard = lock_env();
        let _min = ScopedEnvVar::unset("STARTUP_HEALTH_DELAY_MIN_SECONDS");
        let _max = ScopedEnvVar::unset("STARTUP_HEALTH_DELAY_MAX_SECONDS");

        let (min_seconds, max_seconds) = startup_health_delay_bounds_seconds();
        assert_eq!(min_seconds, 2);
        assert_eq!(max_seconds, 8);
    }
}
