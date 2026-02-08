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
        let last_used_account_id = self.snapshot_last_used_account(quota_group).await;

        let mut attempted: HashSet<String> = HashSet::new();
        let mut last_error: Option<String> = None;
        let mut need_update_last_used: Option<(String, std::time::Instant)> = None;

        for attempt in 0..total {
            let rotate = force_rotate || attempt > 0;
            let normalized_target =
                crate::proxy::common::model_mapping::normalize_to_standard_id(target_model)
                    .unwrap_or_else(|| target_model.to_string());
            let (target_token, mode_b_update_last_used) = self
                .choose_target_token_for_attempt(
                    rotate,
                    quota_group,
                    use_sticky_mode,
                    session_id,
                    target_model,
                    tokens_snapshot,
                    &attempted,
                    &normalized_target,
                    quota_protection_enabled,
                    total,
                    &last_used_account_id,
                )
                .await;
            if mode_b_update_last_used.is_some() {
                need_update_last_used = mode_b_update_last_used;
            }

            let mut token = self
                .resolve_candidate_token(target_token, tokens_snapshot, &attempted)
                .await?;
            if self
                .should_skip_selected_token(&token, &mut attempted)
                .await
            {
                continue;
            }
            if let Err(e) = self.refresh_rotating_token_if_needed(&mut token).await {
                Self::record_rotation_attempt_failure(
                    quota_group,
                    &last_used_account_id,
                    &token,
                    format!("Token refresh failed: {}", e),
                    &mut last_error,
                    &mut attempted,
                    &mut need_update_last_used,
                );
                continue;
            }
            let project_id = match self.resolve_project_id_or_err(&mut token).await {
                Ok(pid) => pid,
                Err(e) => {
                    tracing::error!("Failed to fetch project_id for {}: {}", token.email, e);
                    Self::record_rotation_attempt_failure(
                        quota_group,
                        &last_used_account_id,
                        &token,
                        format!("Failed to fetch project_id for {}: {}", token.email, e),
                        &mut last_error,
                        &mut attempted,
                        &mut need_update_last_used,
                    );
                    continue;
                }
            };
            self.apply_last_used_update(quota_group, need_update_last_used)
                .await;

            return Ok((
                token.access_token,
                project_id,
                token.email,
                token.account_id,
                0,
            ));
        }

        Err(last_error.unwrap_or_else(|| "All accounts failed".to_string()))
    }

    async fn snapshot_last_used_account(
        &self,
        quota_group: &str,
    ) -> Option<(String, std::time::Instant)> {
        if quota_group == "image_gen" {
            return None;
        }
        let last_used = self.last_used_account.lock().await;
        last_used.clone()
    }

    async fn resolve_candidate_token(
        &self,
        target_token: Option<ProxyToken>,
        tokens_snapshot: &[ProxyToken],
        attempted: &HashSet<String>,
    ) -> Result<ProxyToken, String> {
        match target_token {
            Some(t) => Ok(t),
            None => self
                .select_via_rate_limited_fallback(tokens_snapshot, attempted)
                .await,
        }
    }

    async fn choose_target_token_for_attempt(
        &self,
        rotate: bool,
        quota_group: &str,
        use_sticky_mode: bool,
        session_id: Option<&str>,
        target_model: &str,
        tokens_snapshot: &[ProxyToken],
        attempted: &HashSet<String>,
        normalized_target: &str,
        quota_protection_enabled: bool,
        total: usize,
        last_used_account_id: &Option<(String, std::time::Instant)>,
    ) -> (Option<ProxyToken>, Option<(String, std::time::Instant)>) {
        // Mode A: Sticky session processing (CacheFirst or Balance with session_id)
        let mut target_token = self
            .try_mode_a_sticky(
                rotate,
                use_sticky_mode,
                session_id,
                tokens_snapshot,
                attempted,
                normalized_target,
                quota_protection_enabled,
                target_model,
            )
            .await;
        let mut mode_b_update_last_used: Option<(String, std::time::Instant)> = None;

        // Mode B: Atomic 60s global lock + P2C fallback
        if target_token.is_none() {
            let (mode_b_token, mode_b_update) = self
                .try_mode_b_locked_or_p2c(
                    rotate,
                    quota_group,
                    use_sticky_mode,
                    last_used_account_id,
                    tokens_snapshot,
                    attempted,
                    normalized_target,
                    quota_protection_enabled,
                    session_id,
                    target_model,
                )
                .await;
            target_token = mode_b_token;
            mode_b_update_last_used = mode_b_update;
        }

        // Mode C: P2C Selection (instead of pure round-robin)
        if target_token.is_none() {
            target_token = self
                .try_mode_c_p2c(
                    tokens_snapshot,
                    attempted,
                    normalized_target,
                    quota_protection_enabled,
                    total,
                    rotate,
                )
                .await;
        }

        (target_token, mode_b_update_last_used)
    }

    async fn select_via_rate_limited_fallback(
        &self,
        tokens_snapshot: &[ProxyToken],
        attempted: &HashSet<String>,
    ) -> Result<ProxyToken, String> {
        let min_wait = tokens_snapshot
            .iter()
            .filter_map(|t| self.rate_limit_tracker.get_reset_seconds(&t.account_id))
            .min();
        match min_wait {
            Some(wait_sec) if wait_sec <= 2 => {
                self.try_buffer_delay_pick(tokens_snapshot, attempted, wait_sec)
                    .await
            }
            Some(wait_sec) => Err(format!("All accounts limited. Wait {}s.", wait_sec)),
            None => Err("All accounts failed or unhealthy.".to_string()),
        }
    }

    async fn try_buffer_delay_pick(
        &self,
        tokens_snapshot: &[ProxyToken],
        attempted: &HashSet<String>,
        wait_sec: u64,
    ) -> Result<ProxyToken, String> {
        let wait_ms = (wait_sec as f64 * 1000.0) as u64;
        tracing::warn!(
            "All accounts rate-limited but shortest wait is {}s. Applying {}ms buffer for state sync...",
            wait_sec, wait_ms
        );
        tokio::time::sleep(tokio::time::Duration::from_millis(wait_ms)).await;
        let retry_token = tokens_snapshot.iter().find(|t| {
            !attempted.contains(&t.account_id) && !self.is_rate_limited_sync(&t.account_id, None)
        });

        if let Some(t) = retry_token {
            tracing::info!("✅ Buffer delay successful! Found available account: {}", t.email);
            Ok(t.clone())
        } else {
            self.try_optimistic_reset_pick(tokens_snapshot, attempted)
        }
    }

    fn try_optimistic_reset_pick(
        &self,
        tokens_snapshot: &[ProxyToken],
        attempted: &HashSet<String>,
    ) -> Result<ProxyToken, String> {
        tracing::warn!(
            "Buffer delay failed. Executing optimistic reset for all {} accounts...",
            tokens_snapshot.len()
        );
        self.rate_limit_tracker.clear_all();
        let final_token = tokens_snapshot
            .iter()
            .find(|t| !attempted.contains(&t.account_id));

        if let Some(t) = final_token {
            tracing::info!("✅ Optimistic reset successful! Using account: {}", t.email);
            Ok(t.clone())
        } else {
            Err("All accounts failed after optimistic reset.".to_string())
        }
    }

    async fn should_skip_selected_token(
        &self,
        token: &ProxyToken,
        attempted: &mut HashSet<String>,
    ) -> bool {
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
                true
            }
            OnDiskAccountState::Unknown => {
                tracing::warn!(
                    "Selected account {} state on disk is unavailable, skipping",
                    token.email
                );
                attempted.insert(token.account_id.clone());
                true
            }
            OnDiskAccountState::Enabled => false,
        }
    }

    async fn refresh_rotating_token_if_needed(&self, token: &mut ProxyToken) -> Result<(), String> {
        let now = chrono::Utc::now().timestamp();
        if now < token.timestamp - 300 {
            return Ok(());
        }

        tracing::debug!(
            "Token for account {} is about to expire, refreshing...",
            token.email
        );
        match crate::modules::auth::oauth::refresh_access_token(
            &token.refresh_token,
            Some(&token.account_id),
        )
        .await
        {
            Ok(token_response) => {
                tracing::debug!("Token refresh succeeded!");
                self.apply_refreshed_token(token, &token_response, now);
                Ok(())
            }
            Err(e) => {
                tracing::error!(
                    "Token refresh failed ({}): {}, trying next account",
                    token.email,
                    e
                );
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

        tracing::debug!(
            "Account {} is missing project_id, attempting to fetch...",
            token.email
        );
        let pid = crate::proxy::project_resolver::fetch_project_id(&token.access_token).await?;
        self.apply_project_id(token, &pid);
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
            *need_update_last_used = Some((String::new(), std::time::Instant::now()));
        }
    }

    fn record_rotation_attempt_failure(
        quota_group: &str,
        last_used_account_id: &Option<(String, std::time::Instant)>,
        token: &ProxyToken,
        message: String,
        last_error: &mut Option<String>,
        attempted: &mut HashSet<String>,
        need_update_last_used: &mut Option<(String, std::time::Instant)>,
    ) {
        *last_error = Some(message);
        attempted.insert(token.account_id.clone());
        Self::mark_need_clear_last_used_if_selected(
            quota_group,
            last_used_account_id,
            &token.account_id,
            need_update_last_used,
        );
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
                *last_used = None;
            } else {
                *last_used = Some((new_account_id, new_time));
            }
        }
    }
}
