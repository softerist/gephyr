use super::*;

impl TokenManager {
    pub(super) async fn select_token_via_rotation(
        &self,
        quota_group: &str,
        force_rotate: bool,
        session_id: Option<&str>,
        target_model: &str,
        tokens_snapshot: &[ProxyToken],
        total: usize,
        quota_protection_enabled: bool,
        use_sticky_mode: bool,
    ) -> Result<(String, String, String, String, u64), String> {
        // Move lock operations outside the loop to avoid redundant locking
        // Pre-fetch a snapshot of last_used_account to avoid multiple locks in the loop
        let last_used_account_id = if quota_group != "image_gen" {
            let last_used = self.last_used_account.lock().await;
            last_used.clone()
        } else {
            None
        };

        let mut attempted: HashSet<String> = HashSet::new();
        let mut last_error: Option<String> = None;
        let mut need_update_last_used: Option<(String, std::time::Instant)> = None;

        for attempt in 0..total {
            let rotate = force_rotate || attempt > 0;

            // Normalize target model name to standard ID for quota protection check
            let normalized_target =
                crate::proxy::common::model_mapping::normalize_to_standard_id(target_model)
                    .unwrap_or_else(|| target_model.to_string());

            // Mode A: Sticky session processing (CacheFirst or Balance with session_id)
            let mut target_token = self
                .try_mode_a_sticky(
                    rotate,
                    use_sticky_mode,
                    session_id,
                    tokens_snapshot,
                    &attempted,
                    &normalized_target,
                    quota_protection_enabled,
                    target_model,
                )
                .await;

            // Mode B: Atomic 60s global lock + P2C fallback
            if target_token.is_none() {
                let (mode_b_token, mode_b_update_last_used) = self
                    .try_mode_b_locked_or_p2c(
                        rotate,
                        quota_group,
                        use_sticky_mode,
                        &last_used_account_id,
                        tokens_snapshot,
                        &attempted,
                        &normalized_target,
                        quota_protection_enabled,
                        session_id,
                        target_model,
                    )
                    .await;
                target_token = mode_b_token;
                if mode_b_update_last_used.is_some() {
                    need_update_last_used = mode_b_update_last_used;
                }
            }

            // Mode C: P2C Selection (instead of pure round-robin)
            if target_token.is_none() {
                target_token = self
                    .try_mode_c_p2c(
                        tokens_snapshot,
                        &attempted,
                        &normalized_target,
                        quota_protection_enabled,
                        total,
                        rotate,
                    )
                    .await;
            }

            let mut token = match target_token {
                Some(t) => t,
                None => {
                    // Optimistic Reset Strategy: Dual-layer protection mechanism
                    // Compute minimum wait time
                    let min_wait = tokens_snapshot
                        .iter()
                        .filter_map(|t| self.rate_limit_tracker.get_reset_seconds(&t.account_id))
                        .min();

                    // Layer 1: if shortest wait <= 2s, apply buffer delay
                    if let Some(wait_sec) = min_wait {
                        if wait_sec <= 2 {
                            let wait_ms = (wait_sec as f64 * 1000.0) as u64;
                            tracing::warn!(
                                "All accounts rate-limited but shortest wait is {}s. Applying {}ms buffer for state sync...",
                                wait_sec, wait_ms
                            );

                            // Buffer delay
                            tokio::time::sleep(tokio::time::Duration::from_millis(wait_ms)).await;

                            // Retry account selection
                            let retry_token = tokens_snapshot.iter().find(|t| {
                                !attempted.contains(&t.account_id)
                                    && !self.is_rate_limited_sync(&t.account_id, None)
                            });

                            if let Some(t) = retry_token {
                                tracing::info!(
                                    "✅ Buffer delay successful! Found available account: {}",
                                    t.email
                                );
                                t.clone()
                            } else {
                                // Layer 2: still unavailable after buffer, perform optimistic reset
                                tracing::warn!(
                                    "Buffer delay failed. Executing optimistic reset for all {} accounts...",
                                    tokens_snapshot.len()
                                );

                                // Clear all rate-limit records
                                self.rate_limit_tracker.clear_all();

                                // Retry selection again
                                let final_token = tokens_snapshot
                                    .iter()
                                    .find(|t| !attempted.contains(&t.account_id));

                                if let Some(t) = final_token {
                                    tracing::info!(
                                        "✅ Optimistic reset successful! Using account: {}",
                                        t.email
                                    );
                                    t.clone()
                                } else {
                                    return Err("All accounts failed after optimistic reset.".to_string());
                                }
                            }
                        } else {
                            return Err(format!("All accounts limited. Wait {}s.", wait_sec));
                        }
                    } else {
                        return Err("All accounts failed or unhealthy.".to_string());
                    }
                }
            };

            // Safety net: avoid selecting an account that has been disabled on disk but still
            // exists in the in-memory snapshot (e.g. stale cache + sticky session binding).
            match crate::proxy::token::loader::get_account_state_on_disk(&token.account_path).await {
                OnDiskAccountState::Disabled => {
                    tracing::warn!(
                        "Selected account {} is disabled on disk, purging and retrying",
                        token.email
                    );
                    attempted.insert(token.account_id.clone());
                    self.remove_account(&token.account_id);
                    continue;
                }
                OnDiskAccountState::Unknown => {
                    tracing::warn!(
                        "Selected account {} state on disk is unavailable, skipping",
                        token.email
                    );
                    attempted.insert(token.account_id.clone());
                    continue;
                }
                OnDiskAccountState::Enabled => {}
            }

            // 3. Check if token expired (refresh 5 minutes in advance)
            if let Err(e) = self.refresh_rotating_token_if_needed(&mut token).await {
                // Avoid leaking account emails to API clients; details are still in logs.
                last_error = Some(format!("Token refresh failed: {}", e));
                attempted.insert(token.account_id.clone());
                Self::mark_need_clear_last_used_if_selected(
                    quota_group,
                    &last_used_account_id,
                    &token.account_id,
                    &mut need_update_last_used,
                );
                continue;
            }

            // 4. Ensure project_id is present
            let project_id = match self.resolve_project_id_or_err(&mut token).await {
                Ok(pid) => pid,
                Err(e) => {
                    tracing::error!("Failed to fetch project_id for {}: {}", token.email, e);
                    last_error = Some(format!(
                        "Failed to fetch project_id for {}: {}",
                        token.email, e
                    ));
                    attempted.insert(token.account_id.clone());
                    Self::mark_need_clear_last_used_if_selected(
                        quota_group,
                        &last_used_account_id,
                        &token.account_id,
                        &mut need_update_last_used,
                    );
                    continue;
                }
            };

            // [OPTIMIZATION] Uniformly update last_used_account before successful return (if needed)
            self.apply_last_used_update(quota_group, need_update_last_used)
                .await;

            return Ok((token.access_token, project_id, token.email, token.account_id, 0));
        }

        Err(last_error.unwrap_or_else(|| "All accounts failed".to_string()))
    }

    async fn refresh_rotating_token_if_needed(&self, token: &mut ProxyToken) -> Result<(), String> {
        let now = chrono::Utc::now().timestamp();
        if now < token.timestamp - 300 {
            return Ok(());
        }

        tracing::debug!("Token for account {} is about to expire, refreshing...", token.email);
        match crate::modules::oauth::refresh_access_token(&token.refresh_token, Some(&token.account_id))
            .await
        {
            Ok(token_response) => {
                tracing::debug!("Token refresh succeeded!");
                token.access_token = token_response.access_token.clone();
                token.expires_in = token_response.expires_in;
                token.timestamp = now + token_response.expires_in;

                if let Some(mut entry) = self.tokens.get_mut(&token.account_id) {
                    entry.access_token = token.access_token.clone();
                    entry.expires_in = token.expires_in;
                    entry.timestamp = token.timestamp;
                }

                if let Err(e) = crate::proxy::token::persistence::save_refreshed_token(
                    &token.account_path,
                    &token_response,
                ) {
                    tracing::debug!("Failed to persist refreshed token ({}): {}", token.email, e);
                }
                Ok(())
            }
            Err(e) => {
                tracing::error!("Token refresh failed ({}): {}, trying next account", token.email, e);
                if e.contains("\"invalid_grant\"") || e.contains("invalid_grant") {
                    tracing::error!(
                        "Disabling account due to invalid_grant ({}): refresh_token likely revoked/expired",
                        token.email
                    );
                    let _ = crate::proxy::token::persistence::disable_account(
                        &token.account_path,
                        &format!("invalid_grant: {}", e),
                    );
                    self.tokens.remove(&token.account_id);
                }
                Err(e)
            }
        }
    }

    async fn resolve_project_id_or_err(&self, token: &mut ProxyToken) -> Result<String, String> {
        if let Some(pid) = &token.project_id {
            return Ok(pid.clone());
        }

        tracing::debug!("Account {} is missing project_id, attempting to fetch...", token.email);
        let pid = crate::proxy::project_resolver::fetch_project_id(&token.access_token).await?;
        if let Some(mut entry) = self.tokens.get_mut(&token.account_id) {
            entry.project_id = Some(pid.clone());
        }
        let _ = crate::proxy::token::persistence::save_project_id(&token.account_path, &pid);
        Ok(pid)
    }

    fn mark_need_clear_last_used_if_selected(
        quota_group: &str,
        last_used_account_id: &Option<(String, std::time::Instant)>,
        token_account_id: &str,
        need_update_last_used: &mut Option<(String, std::time::Instant)>,
    ) {
        if quota_group != "image_gen"
            && matches!(last_used_account_id, Some((id, _)) if id == token_account_id)
        {
            // Empty string means clear is required.
            *need_update_last_used = Some((String::new(), std::time::Instant::now()));
        }
    }

    async fn apply_last_used_update(
        &self,
        quota_group: &str,
        need_update_last_used: Option<(String, std::time::Instant)>,
    ) {
        if quota_group == "image_gen" {
            return;
        }
        if let Some((new_account_id, new_time)) = need_update_last_used {
            let mut last_used = self.last_used_account.lock().await;
            if new_account_id.is_empty() {
                // Empty string means clear lock is required.
                *last_used = None;
            } else {
                *last_used = Some((new_account_id, new_time));
            }
        }
    }
}
