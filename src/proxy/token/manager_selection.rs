use super::{ProxyToken, TokenManager};
use std::collections::HashSet;

pub(super) struct ModeASelection<'a> {
    pub rotate: bool,
    pub use_sticky_mode: bool,
    pub session_id: Option<&'a str>,
    pub tokens_snapshot: &'a [ProxyToken],
    pub attempted: &'a HashSet<String>,
    pub normalized_target: &'a str,
    pub quota_protection_enabled: bool,
    pub target_model: &'a str,
}

pub(super) struct ModeBSelection<'a> {
    pub rotate: bool,
    pub quota_group: &'a str,
    pub use_sticky_mode: bool,
    pub last_used_account_id: &'a Option<(String, std::time::Instant)>,
    pub tokens_snapshot: &'a [ProxyToken],
    pub attempted: &'a HashSet<String>,
    pub normalized_target: &'a str,
    pub quota_protection_enabled: bool,
    pub session_id: Option<&'a str>,
    pub target_model: &'a str,
}

impl TokenManager {
    pub(super) async fn collect_non_limited_candidates(
        &self,
        tokens_snapshot: &[ProxyToken],
        normalized_target: &str,
    ) -> Vec<ProxyToken> {
        let mut non_limited: Vec<ProxyToken> = Vec::new();
        for t in tokens_snapshot {
            if !self
                .is_rate_limited(&t.account_id, Some(normalized_target))
                .await
            {
                non_limited.push(t.clone());
            }
        }
        non_limited
    }

    pub(super) async fn try_mode_a_sticky(&self, req: ModeASelection<'_>) -> Option<ProxyToken> {
        if req.rotate || !req.use_sticky_mode {
            return None;
        }

        let sid = req.session_id?;
        let bound_id = self.session_accounts.get(sid).map(|v| v.clone())?;
        if let Some(bound_token) = req
            .tokens_snapshot
            .iter()
            .find(|t| t.account_id == bound_id)
        {
            let key =
                crate::proxy::token::lookup::account_id_by_email(&self.tokens, &bound_token.email)
                    .unwrap_or_else(|| bound_token.account_id.clone());
            let reset_sec = self.rate_limit_tracker.get_remaining_wait(&key, None);
            if reset_sec > 0 {
                tracing::debug!(
                    "Sticky Session: Bound account {} is rate-limited ({}s), unbinding and switching.",
                    bound_token.email,
                    reset_sec
                );
                self.session_accounts.remove(sid);
                return None;
            }

            if !req.attempted.contains(&bound_id)
                && !crate::proxy::token::pool::is_quota_protected(
                    bound_token,
                    req.normalized_target,
                    req.quota_protection_enabled,
                )
            {
                tracing::debug!(
                    "Sticky Session: Successfully reusing bound account {} for session {}",
                    bound_token.email,
                    sid
                );
                return Some(bound_token.clone());
            }

            if crate::proxy::token::pool::is_quota_protected(
                bound_token,
                req.normalized_target,
                req.quota_protection_enabled,
            ) {
                tracing::debug!(
                    "Sticky Session: Bound account {} is quota-protected for model {} [{}], unbinding and switching.",
                    bound_token.email,
                    req.normalized_target,
                    req.target_model
                );
                self.session_accounts.remove(sid);
            }

            return None;
        }
        tracing::debug!(
            "Sticky Session: Bound account not found for session {}, unbinding",
            sid
        );
        self.session_accounts.remove(sid);
        None
    }

    pub(super) async fn try_mode_b_locked_or_p2c(
        &self,
        req: ModeBSelection<'_>,
    ) -> (Option<ProxyToken>, Option<(String, std::time::Instant)>) {
        if req.rotate || req.quota_group == "image_gen" || !req.use_sticky_mode {
            return (None, None);
        }
        if let Some((account_id, last_time)) = req.last_used_account_id {
            if last_time.elapsed().as_secs() < 60 && !req.attempted.contains(account_id) {
                if let Some(found) = req
                    .tokens_snapshot
                    .iter()
                    .find(|t| &t.account_id == account_id)
                {
                    if !self
                        .is_rate_limited(&found.account_id, Some(req.normalized_target))
                        .await
                        && !crate::proxy::token::pool::is_quota_protected(
                            found,
                            req.normalized_target,
                            req.quota_protection_enabled,
                        )
                    {
                        tracing::debug!("60s Window: Force reusing last account: {}", found.email);
                        return (Some(found.clone()), None);
                    }

                    if self
                        .is_rate_limited(&found.account_id, Some(req.normalized_target))
                        .await
                    {
                        tracing::debug!(
                            "60s Window: Last account {} is rate-limited, skipping",
                            found.email
                        );
                    } else {
                        tracing::debug!(
                            "60s Window: Last account {} is quota-protected for model {} [{}], skipping",
                            found.email,
                            req.normalized_target,
                            req.target_model
                        );
                    }
                }
            }
        }
        let non_limited = self
            .collect_non_limited_candidates(req.tokens_snapshot, req.normalized_target)
            .await;
        if let Some(selected) = crate::proxy::token::pool::select_with_p2c(
            &non_limited,
            req.attempted,
            req.normalized_target,
            req.quota_protection_enabled,
        ) {
            let selected = selected.clone();
            let update_last_used = Some((selected.account_id.clone(), std::time::Instant::now()));

            if let Some(sid) = req.session_id {
                self.session_accounts
                    .insert(sid.to_string(), selected.account_id.clone());
                tracing::debug!(
                    "Sticky Session: Bound new account {} to session {}",
                    selected.email,
                    sid
                );
            }

            return (Some(selected), update_last_used);
        }

        (None, None)
    }

    pub(super) async fn try_mode_c_p2c(
        &self,
        tokens_snapshot: &[ProxyToken],
        attempted: &HashSet<String>,
        normalized_target: &str,
        quota_protection_enabled: bool,
        total: usize,
        rotate: bool,
    ) -> Option<ProxyToken> {
        tracing::debug!("🔄 [Mode C] P2C selection from {} candidates", total);

        let non_limited = self
            .collect_non_limited_candidates(tokens_snapshot, normalized_target)
            .await;
        let selected = crate::proxy::token::pool::select_with_p2c(
            &non_limited,
            attempted,
            normalized_target,
            quota_protection_enabled,
        )?;
        let selected = selected.clone();

        tracing::debug!("  {} - SELECTED via P2C", selected.email);
        if rotate {
            tracing::debug!("Force Rotation: Switched to account: {}", selected.email);
        }
        Some(selected)
    }
}
