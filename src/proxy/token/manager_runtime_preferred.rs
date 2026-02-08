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
                        tokens_snapshot.retain(|t| t.account_id != preferred_token.account_id);
                        *total = tokens_snapshot.len();

                        {
                            let mut preferred = self.preferred_account_id.write().await;
                            if preferred.as_deref() == Some(pref_id.as_str()) {
                                *preferred = None;
                            }
                        }

                        if *total == 0 {
                            return Err("Token pool is empty".to_string());
                        }
                    }
                    OnDiskAccountState::Unknown => {
                        tracing::warn!(
                            "🔒  Preferred account {} state on disk is unavailable, falling back",
                            preferred_token.email
                        );
                        tokens_snapshot.retain(|t| t.account_id != preferred_token.account_id);
                        *total = tokens_snapshot.len();
                        if *total == 0 {
                            return Err("Token pool is empty".to_string());
                        }
                    }
                    OnDiskAccountState::Enabled => {
                        let normalized_target =
                            crate::proxy::common::model_mapping::normalize_to_standard_id(
                                target_model,
                            )
                            .unwrap_or_else(|| target_model.to_string());

                        let is_rate_limited = self
                            .is_rate_limited(&preferred_token.account_id, Some(&normalized_target))
                            .await;
                        let is_quota_protected = quota_protection_enabled
                            && preferred_token
                                .protected_models
                                .contains(&normalized_target);

                        if !is_rate_limited && !is_quota_protected {
                            tracing::info!(
                                "🔒  Using preferred account: {} (fixed mode)",
                                preferred_token.email
                            );
                            let mut token = preferred_token.clone();
                            let now = chrono::Utc::now().timestamp();
                            if now >= token.timestamp - 300 {
                                tracing::debug!(
                                    "Token for account {} is about to expire, refreshing...",
                                    token.email
                                );
                                match crate::modules::oauth::refresh_access_token(
                                    &token.refresh_token,
                                    Some(&token.account_id),
                                )
                                .await
                                {
                                    Ok(token_response) => {
                                        self.apply_refreshed_token(&mut token, &token_response, now);
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            "Preferred account token refresh failed: {}",
                                            e
                                        );
                                    }
                                }
                            }
                            let project_id = if let Some(pid) = &token.project_id {
                                pid.clone()
                            } else {
                                match crate::proxy::project_resolver::fetch_project_id(
                                    &token.access_token,
                                )
                                .await
                                {
                                    Ok(pid) => {
                                        self.apply_project_id(&mut token, &pid);
                                        pid
                                    }
                                    Err(_) => "bamboo-precept-lgxtn".to_string(),
                                }
                            };

                            return Ok(Some((
                                token.access_token,
                                project_id,
                                token.email,
                                token.account_id,
                                0,
                            )));
                        } else if is_rate_limited {
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
}
