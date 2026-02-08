use super::*;

impl TokenManager {
    pub(super) async fn try_preferred_account_for_request(
        &self,
        tokens_snapshot: &mut Vec<ProxyToken>,
        total: &mut usize,
        target_model: &str,
        quota_protection_enabled: bool,
    ) -> Result<Option<(String, String, String, String, u64)>, String> {
        let preferred_id = self.preferred_account_id.read().await.clone();
        if let Some(ref pref_id) = preferred_id {
            if let Some(preferred_token) = tokens_snapshot
                .iter()
                .find(|t| &t.account_id == pref_id)
                .cloned()
            {
                match crate::proxy::token::loader::get_account_state_on_disk(
                    &preferred_token.account_path,
                )
                .await
                {
                    OnDiskAccountState::Disabled => {
                        tracing::warn!(
                            "🔒  Preferred account {} is disabled on disk, purging and falling back",
                            preferred_token.email
                        );
                        self.remove_account(&preferred_token.account_id);
                        self.prune_preferred_from_snapshot(
                            tokens_snapshot,
                            total,
                            &preferred_token,
                            true,
                            pref_id,
                        )
                        .await?;
                    }
                    OnDiskAccountState::Unknown => {
                        tracing::warn!(
                            "🔒  Preferred account {} state on disk is unavailable, falling back",
                            preferred_token.email
                        );
                        self.prune_preferred_from_snapshot(
                            tokens_snapshot,
                            total,
                            &preferred_token,
                            false,
                            pref_id,
                        )
                        .await?;
                    }
                    OnDiskAccountState::Enabled => {
                        if self
                            .is_preferred_eligible_for_target(
                                &preferred_token,
                                target_model,
                                quota_protection_enabled,
                            )
                            .await
                        {
                            return Ok(Some(
                                self.build_preferred_response(preferred_token.clone()).await,
                            ));
                        }
                    }
                }
            } else {
                tracing::warn!(
                    "🔒  Preferred account {} not found in pool, falling back to round-robin",
                    pref_id
                );
            }
        }

        Ok(None)
    }

    async fn prune_preferred_from_snapshot(
        &self,
        tokens_snapshot: &mut Vec<ProxyToken>,
        total: &mut usize,
        preferred_token: &ProxyToken,
        clear_preferred: bool,
        pref_id: &str,
    ) -> Result<(), String> {
        tokens_snapshot.retain(|t| t.account_id != preferred_token.account_id);
        *total = tokens_snapshot.len();

        if clear_preferred {
            let mut preferred = self.preferred_account_id.write().await;
            if preferred.as_deref() == Some(pref_id) {
                *preferred = None;
            }
        }

        if *total == 0 {
            return Err("Token pool is empty".to_string());
        }
        Ok(())
    }

    async fn is_preferred_eligible_for_target(
        &self,
        preferred_token: &ProxyToken,
        target_model: &str,
        quota_protection_enabled: bool,
    ) -> bool {
        let normalized_target = crate::proxy::common::model_mapping::normalize_to_standard_id(
            target_model,
        )
        .unwrap_or_else(|| target_model.to_string());

        let is_rate_limited = self
            .is_rate_limited(&preferred_token.account_id, Some(&normalized_target))
            .await;
        let is_quota_protected =
            quota_protection_enabled && preferred_token.protected_models.contains(&normalized_target);

        if !is_rate_limited && !is_quota_protected {
            return true;
        }

        if is_rate_limited {
            tracing::warn!(
                "🔒  Preferred account {} is rate-limited, falling back to round-robin",
                preferred_token.email
            );
        } else {
            tracing::warn!(
                "🔒  Preferred account {} is quota-protected for {}, falling back to round-robin",
                preferred_token.email,
                target_model
            );
        }
        false
    }

    async fn build_preferred_response(
        &self,
        preferred_token: ProxyToken,
    ) -> (String, String, String, String, u64) {
        tracing::info!(
            "🔒  Using preferred account: {} (fixed mode)",
            preferred_token.email
        );
        let mut token = preferred_token;

        let now = chrono::Utc::now().timestamp();
        if now >= token.timestamp - 300 {
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
                    self.apply_refreshed_token(&mut token, &token_response, now);
                }
                Err(e) => {
                    tracing::warn!("Preferred account token refresh failed: {}", e);
                }
            }
        }

        let project_id = if let Some(pid) = &token.project_id {
            pid.clone()
        } else {
            match crate::proxy::project_resolver::fetch_project_id(&token.access_token).await {
                Ok(pid) => {
                    self.apply_project_id(&mut token, &pid);
                    pid
                }
                Err(_) => "bamboo-precept-lgxtn".to_string(),
            }
        };

        (
            token.access_token,
            project_id,
            token.email,
            token.account_id,
            0,
        )
    }
}
