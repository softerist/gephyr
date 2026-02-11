use super::{StickyEventRecord, TokenManager};

impl TokenManager {
    pub fn len(&self) -> usize {
        self.tokens.len()
    }
    pub async fn get_token_by_email(
        &self,
        email: &str,
    ) -> Result<(String, String, String, String, u64), String> {
        crate::proxy::token::warmup::get_token_by_email(self.tokens.as_ref(), email).await
    }
    pub async fn mark_rate_limited(
        &self,
        email: &str,
        status: u16,
        retry_after_header: Option<&str>,
        error_body: &str,
    ) {
        let key = crate::proxy::token::lookup::account_id_by_email(&self.tokens, email)
            .unwrap_or_else(|| email.to_string());
        crate::proxy::token::rate::mark_rate_limited(
            &self.rate_limit_tracker,
            &self.circuit_breaker_config,
            &key,
            status,
            retry_after_header,
            error_body,
        )
        .await;
    }
    pub async fn is_rate_limited(&self, account_id: &str, model: Option<&str>) -> bool {
        crate::proxy::token::rate::is_rate_limited(
            &self.rate_limit_tracker,
            &self.circuit_breaker_config,
            account_id,
            model,
        )
        .await
    }
    pub fn is_rate_limited_sync(&self, account_id: &str, model: Option<&str>) -> bool {
        crate::proxy::token::rate::is_rate_limited_sync(
            &self.rate_limit_tracker,
            &self.circuit_breaker_config,
            account_id,
            model,
        )
    }
    pub fn clear_rate_limit(&self, account_id: &str) -> bool {
        crate::proxy::token::rate::clear_rate_limit(&self.rate_limit_tracker, account_id)
    }
    pub fn clear_all_rate_limits(&self) {
        crate::proxy::token::rate::clear_all_rate_limits(&self.rate_limit_tracker);
    }
    pub fn mark_account_success(&self, account_id: &str) {
        crate::proxy::token::rate::mark_account_success(&self.rate_limit_tracker, account_id);
    }
    pub async fn has_available_account(&self, _quota_group: &str, target_model: &str) -> bool {
        crate::proxy::token::availability::has_available_account(
            self.tokens.as_ref(),
            &self.rate_limit_tracker,
            &self.circuit_breaker_config,
            target_model,
        )
        .await
    }
    pub fn get_quota_reset_time(&self, account_id: &str) -> Option<String> {
        crate::proxy::token::persistence::get_quota_reset_time(&self.data_dir, account_id)
    }
    pub fn set_precise_lockout(
        &self,
        account_id: &str,
        reason: crate::proxy::rate_limit::RateLimitReason,
        model: Option<String>,
    ) -> bool {
        crate::proxy::token::rate::set_precise_lockout(
            &self.data_dir,
            &self.rate_limit_tracker,
            account_id,
            reason,
            model,
        )
    }
    pub async fn fetch_and_lock_with_realtime_quota(
        &self,
        email: &str,
        reason: crate::proxy::rate_limit::RateLimitReason,
        model: Option<String>,
    ) -> bool {
        crate::proxy::token::rate::fetch_and_lock_with_realtime_quota(
            self.tokens.as_ref(),
            &self.rate_limit_tracker,
            email,
            reason,
            model,
        )
        .await
    }
    pub async fn mark_rate_limited_async(
        &self,
        email: &str,
        status: u16,
        retry_after_header: Option<&str>,
        error_body: &str,
        model: Option<&str>,
    ) {
        crate::proxy::token::rate::mark_rate_limited_async(
            crate::proxy::token::rate::RateLimitedAsyncContext {
                tokens: self.tokens.as_ref(),
                data_dir: &self.data_dir,
                rate_limit_tracker: &self.rate_limit_tracker,
                circuit_breaker_config: &self.circuit_breaker_config,
            },
            crate::proxy::token::rate::RateLimitedEvent {
                email,
                status,
                retry_after_header,
                error_body,
                model,
            },
        )
        .await;
    }
    pub async fn get_sticky_config(&self) -> crate::proxy::sticky_config::StickySessionConfig {
        crate::proxy::token::control::get_sticky_config(&self.sticky_config).await
    }
    pub async fn update_sticky_config(
        &self,
        new_config: crate::proxy::sticky_config::StickySessionConfig,
    ) {
        crate::proxy::token::control::update_sticky_config(&self.sticky_config, new_config).await;
    }
    pub async fn update_circuit_breaker_config(&self, config: crate::models::CircuitBreakerConfig) {
        crate::proxy::token::control::update_circuit_breaker_config(
            &self.circuit_breaker_config,
            config,
        )
        .await;
    }
    pub async fn get_circuit_breaker_config(&self) -> crate::models::CircuitBreakerConfig {
        crate::proxy::token::control::get_circuit_breaker_config(&self.circuit_breaker_config).await
    }
    pub fn update_session_binding_persistence(&self, enabled: bool) {
        self.set_persist_session_bindings_enabled(enabled);
        if !enabled {
            self.clear_persisted_session_bindings_file();
        }
    }
    pub fn restore_persisted_session_bindings(&self) {
        self.restore_session_bindings_internal();
    }
    pub fn clear_all_sessions(&self) {
        crate::proxy::token::control::clear_all_sessions(self.session_accounts.as_ref());
        self.record_sticky_event(StickyEventRecord {
            action: "cleared_all_bindings",
            session_id: "*",
            bound_account_id: None,
            selected_account_id: None,
            model: None,
            wait_seconds: None,
            max_wait_seconds: None,
            reason: Some("admin_clear_or_runtime_clear"),
        });
        self.persist_session_bindings_internal();
    }
    pub fn get_sticky_debug_snapshot(&self) -> super::StickyDebugSnapshot {
        let session_bindings = self
            .session_accounts
            .iter()
            .map(|kv| (kv.key().clone(), kv.value().clone()))
            .collect::<std::collections::HashMap<String, String>>();
        let recent_events = self
            .sticky_events
            .lock()
            .map(|q| q.iter().cloned().collect::<Vec<_>>())
            .unwrap_or_default();

        let scheduling = self
            .sticky_config
            .try_read()
            .map(|g| g.clone())
            .unwrap_or_default();

        super::StickyDebugSnapshot {
            persist_session_bindings: self
                .persist_session_bindings
                .load(std::sync::atomic::Ordering::Relaxed),
            scheduling,
            session_bindings,
            recent_events,
        }
    }
    pub async fn set_preferred_account(&self, account_id: Option<String>) {
        crate::proxy::token::control::set_preferred_account(&self.preferred_account_id, account_id)
            .await;
    }
    pub async fn get_preferred_account(&self) -> Option<String> {
        crate::proxy::token::control::get_preferred_account(&self.preferred_account_id).await
    }
    pub async fn get_user_info(
        &self,
        refresh_token: &str,
    ) -> Result<crate::modules::auth::oauth::UserInfo, String> {
        crate::proxy::token::account_ops::get_user_info(refresh_token).await
    }
    pub async fn add_account(&self, refresh_token: &str) -> Result<(), String> {
        crate::proxy::token::account_ops::add_account(refresh_token).await?;
        self.reload_all_accounts().await.map(|_| ())
    }
    pub fn record_success(&self, account_id: &str) {
        crate::proxy::token::health::record_success(&self.health_scores, account_id);
        tracing::debug!("📈 Health score increased for account {}", account_id);
    }
    pub fn record_failure(&self, account_id: &str) {
        crate::proxy::token::health::record_failure(&self.health_scores, account_id);
        tracing::warn!("📉 Health score decreased for account {}", account_id);
    }
    pub fn get_account_id_by_email(&self, email: &str) -> Option<String> {
        crate::proxy::token::lookup::account_id_by_email(&self.tokens, email)
    }
    pub async fn set_validation_block(
        &self,
        account_id: &str,
        block_until: i64,
        reason: &str,
    ) -> Result<(), String> {
        crate::proxy::token::account_flags::set_validation_block(
            self.tokens.as_ref(),
            self.session_accounts.as_ref(),
            &self.data_dir,
            account_id,
            block_until,
            reason,
        )?;
        self.persist_session_bindings_internal();

        tracing::info!(
            "🚫 Account {} validation blocked until {} (reason: {})",
            account_id,
            block_until,
            reason
        );

        Ok(())
    }
    pub async fn set_validation_block_public(
        &self,
        account_id: &str,
        block_until: i64,
        reason: &str,
    ) -> Result<(), String> {
        self.set_validation_block(account_id, block_until, reason)
            .await
    }
    pub async fn set_forbidden(&self, account_id: &str, reason: &str) -> Result<(), String> {
        crate::proxy::token::account_flags::set_forbidden(
            self.session_accounts.as_ref(),
            &self.data_dir,
            account_id,
        )?;
        self.remove_account(account_id);

        tracing::warn!(
            "🚫 Account {} marked as forbidden (403): {}",
            account_id,
            crate::proxy::token::account_flags::truncate_reason(reason, 100)
        );

        Ok(())
    }
}
