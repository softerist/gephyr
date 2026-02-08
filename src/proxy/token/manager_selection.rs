use super::*;

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

    pub(super) async fn try_mode_a_sticky(
        &self,
        rotate: bool,
        use_sticky_mode: bool,
        session_id: Option<&str>,
        tokens_snapshot: &[ProxyToken],
        attempted: &HashSet<String>,
        normalized_target: &str,
        quota_protection_enabled: bool,
        target_model: &str,
    ) -> Option<ProxyToken> {
        if rotate || !use_sticky_mode {
            return None;
        }

        let sid = session_id?;

        // 1. Check if session is already bound to an account.
        let bound_id = self.session_accounts.get(sid).map(|v| v.clone())?;

        // 2. Convert email -> account_id to check if the bound account is rate-limited.
        if let Some(bound_token) = tokens_snapshot.iter().find(|t| t.account_id == bound_id) {
            let key = crate::proxy::token::lookup::account_id_by_email(&self.tokens, &bound_token.email)
                .unwrap_or_else(|| bound_token.account_id.clone());

            // Pass None for specific model wait time if not applicable.
            let reset_sec = self.rate_limit_tracker.get_remaining_wait(&key, None);
            if reset_sec > 0 {
                // Unbind and switch account immediately; do not block.
                tracing::debug!(
                    "Sticky Session: Bound account {} is rate-limited ({}s), unbinding and switching.",
                    bound_token.email,
                    reset_sec
                );
                self.session_accounts.remove(sid);
                return None;
            }

            if !attempted.contains(&bound_id)
                && !crate::proxy::token::pool::is_quota_protected(
                    bound_token,
                    normalized_target,
                    quota_protection_enabled,
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
                normalized_target,
                quota_protection_enabled,
            ) {
                tracing::debug!(
                    "Sticky Session: Bound account {} is quota-protected for model {} [{}], unbinding and switching.",
                    bound_token.email,
                    normalized_target,
                    target_model
                );
                self.session_accounts.remove(sid);
            }

            return None;
        }

        // Bound account no longer exists (possibly deleted); unbind it.
        tracing::debug!(
            "Sticky Session: Bound account not found for session {}, unbinding",
            sid
        );
        self.session_accounts.remove(sid);
        None
    }

    pub(super) async fn try_mode_b_locked_or_p2c(
        &self,
        rotate: bool,
        quota_group: &str,
        use_sticky_mode: bool,
        last_used_account_id: &Option<(String, std::time::Instant)>,
        tokens_snapshot: &[ProxyToken],
        attempted: &HashSet<String>,
        normalized_target: &str,
        quota_protection_enabled: bool,
        session_id: Option<&str>,
        target_model: &str,
    ) -> (Option<ProxyToken>, Option<(String, std::time::Instant)>) {
        if rotate || quota_group == "image_gen" || !use_sticky_mode {
            return (None, None);
        }

        // Try recent-account lock first.
        if let Some((account_id, last_time)) = last_used_account_id {
            if last_time.elapsed().as_secs() < 60 && !attempted.contains(account_id) {
                if let Some(found) = tokens_snapshot.iter().find(|t| &t.account_id == account_id) {
                    if !self
                        .is_rate_limited(&found.account_id, Some(normalized_target))
                        .await
                        && !crate::proxy::token::pool::is_quota_protected(
                            found,
                            normalized_target,
                            quota_protection_enabled,
                        )
                    {
                        tracing::debug!("60s Window: Force reusing last account: {}", found.email);
                        return (Some(found.clone()), None);
                    }

                    if self
                        .is_rate_limited(&found.account_id, Some(normalized_target))
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
                            normalized_target,
                            target_model
                        );
                    }
                }
            }
        }

        // If no lock candidate, use P2C selection.
        let non_limited = self
            .collect_non_limited_candidates(tokens_snapshot, normalized_target)
            .await;
        if let Some(selected) = crate::proxy::token::pool::select_with_p2c(
            &non_limited,
            attempted,
            normalized_target,
            quota_protection_enabled,
        ) {
            let selected = selected.clone();
            let update_last_used = Some((selected.account_id.clone(), std::time::Instant::now()));

            if let Some(sid) = session_id {
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
