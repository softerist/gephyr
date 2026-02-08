use super::*;
impl TokenManager {
    pub async fn get_token(
        &self,
        quota_group: &str,
        force_rotate: bool,
        session_id: Option<&str>,
        target_model: &str,
    ) -> Result<(String, String, String, String, u64), String> {
        self.sync_pending_account_changes().await;
        let timeout_duration = std::time::Duration::from_secs(5);
        match tokio::time::timeout(
            timeout_duration,
            self.get_token_internal(quota_group, force_rotate, session_id, target_model),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(
                "Token acquisition timeout (5s) - system too busy or deadlock detected".to_string(),
            ),
        }
    }
    pub(super) async fn get_token_internal(
        &self,
        quota_group: &str,
        force_rotate: bool,
        session_id: Option<&str>,
        target_model: &str,
    ) -> Result<(String, String, String, String, u64), String> {
        let mut tokens_snapshot: Vec<ProxyToken> =
            self.tokens.iter().map(|e| e.value().clone()).collect();
        let mut total = tokens_snapshot.len();
        if total == 0 {
            return Err("Token pool is empty".to_string());
        }
        let normalized_target =
            crate::proxy::common::model_mapping::normalize_to_standard_id(target_model)
                .unwrap_or_else(|| target_model.to_string());
        crate::proxy::token::pool::sort_tokens_for_target(&mut tokens_snapshot, &normalized_target);
        tracing::debug!(
            "🔄 [Token Rotation] target={} Accounts: {:?}",
            normalized_target,
            crate::proxy::token::pool::debug_rotation_rows(&tokens_snapshot, &normalized_target)
        );
        let scheduling = self.sticky_config.read().await.clone();
        use crate::proxy::sticky_config::SchedulingMode;
        let quota_protection_enabled = crate::modules::system::config::load_app_config()
            .map(|cfg| cfg.quota_protection.enabled)
            .unwrap_or(false);
        if let Some(result) = self
            .try_preferred_account_for_request(
                &mut tokens_snapshot,
                &mut total,
                target_model,
                quota_protection_enabled,
            )
            .await?
        {
            return Ok(result);
        }
        let use_sticky_mode = scheduling.mode != SchedulingMode::PerformanceFirst;
        self.select_token_via_rotation(
            quota_group,
            force_rotate,
            session_id,
            target_model,
            &tokens_snapshot,
            total,
            quota_protection_enabled,
            use_sticky_mode,
        )
        .await
    }
    async fn sync_pending_account_changes(&self) {
        let pending_reload = crate::proxy::server::take_pending_reload_accounts();
        for account_id in pending_reload {
            if let Err(e) = self.reload_account(&account_id).await {
                tracing::warn!("[Quota] Failed to reload account {}: {}", account_id, e);
            } else {
                tracing::info!(
                    "[Quota] Reloaded account {} (protected_models synced)",
                    account_id
                );
            }
        }
        let pending_delete = crate::proxy::server::take_pending_delete_accounts();
        for account_id in pending_delete {
            self.remove_account(&account_id);
            tracing::info!(
                "[Proxy] Purged deleted account {} from all caches",
                account_id
            );
        }
    }
}
