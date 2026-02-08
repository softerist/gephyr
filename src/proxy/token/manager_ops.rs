use super::*;

impl TokenManager {
    pub fn len(&self) -> usize {
        self.tokens.len()
    }

    // Get specific account Token via email (used for warmup and other scenarios requiring a specific account)
    // This method will automatically refresh expired tokens
    pub async fn get_token_by_email(
        &self,
        email: &str,
    ) -> Result<(String, String, String, String, u64), String> {
        crate::proxy::token::warmup::get_token_by_email(self.tokens.as_ref(), email).await
    }

    // ===== Rate Limit Management Methods =====

    // Mark account as rate-limited (called externally, usually in a handler)
    // Parameter is email; internally automatically converts to account_id
    pub async fn mark_rate_limited(
        &self,
        email: &str,
        status: u16,
        retry_after_header: Option<&str>,
        error_body: &str,
    ) {
        // [Alternative] Convert email -> account_id
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

    // Check if account is in rate limit (supports model-level)
    pub async fn is_rate_limited(&self, account_id: &str, model: Option<&str>) -> bool {
        crate::proxy::token::rate::is_rate_limited(
            &self.rate_limit_tracker,
            &self.circuit_breaker_config,
            account_id,
            model,
        )
        .await
    }

    // Check if account is in rate limit (synchronous version, for Iterator only)
    pub fn is_rate_limited_sync(&self, account_id: &str, model: Option<&str>) -> bool {
        crate::proxy::token::rate::is_rate_limited_sync(
            &self.rate_limit_tracker,
            &self.circuit_breaker_config,
            account_id,
            model,
        )
    }

    // Get how many seconds until rate limit reset
    #[allow(dead_code)]
    pub fn get_rate_limit_reset_seconds(&self, account_id: &str) -> Option<u64> {
        crate::proxy::token::rate::get_rate_limit_reset_seconds(&self.rate_limit_tracker, account_id)
    }

    // Clear expired rate limit records
    #[allow(dead_code)]
    pub fn clean_expired_rate_limits(&self) {
        crate::proxy::token::rate::clean_expired_rate_limits(&self.rate_limit_tracker);
    }

    // Clear rate limit records for a specific account
    pub fn clear_rate_limit(&self, account_id: &str) -> bool {
        crate::proxy::token::rate::clear_rate_limit(&self.rate_limit_tracker, account_id)
    }

    // Clear all rate limit records
    pub fn clear_all_rate_limits(&self) {
        crate::proxy::token::rate::clear_all_rate_limits(&self.rate_limit_tracker);
    }

    // Mark account request as successful, reset consecutive failure count
    //
    // Called after successful request completion; resets failure count for the account,
    // next failure starts from the shortest lockout time (smart rate limiting).
    pub fn mark_account_success(&self, account_id: &str) {
        crate::proxy::token::rate::mark_account_success(&self.rate_limit_tracker, account_id);
    }

    // Check if there are available Google accounts
    //
    // For smart judgment in "fallback-only" mode: use external providers only when all Google accounts are unavailable.
    //
    // # Arguments
    // - `quota_group`: Quota group ("claude" or "gemini"), not currently used but reserved for future expansion
    // - `target_model`: Target model name (normalized), used for quota protection check
    //
    // # Returns
    // - `true`: At least one available account (not rate-limited and not quota-protected)
    // - `false`: All accounts unavailable (rate-limited or quota-protected)
    //
    // # Example
    // ```ignore
    // // Check if available accounts exist for claude-sonnet requests
    // let has_available = token_manager.has_available_account("claude", "claude-sonnet-4-20250514").await;
    // if !has_available {
    //     // Switch to external provider
    // }
    // ```
    pub async fn has_available_account(&self, _quota_group: &str, target_model: &str) -> bool {
        crate::proxy::token::availability::has_available_account(
            self.tokens.as_ref(),
            &self.rate_limit_tracker,
            &self.circuit_breaker_config,
            target_model,
        )
        .await
    }

    // Get quota reset time from account file
    //
    // Return the most recent quota reset time string (ISO 8601 format) for the account
    //
    // # Arguments
    // - `account_id`: Account ID (used to locate account file)
    pub fn get_quota_reset_time(&self, account_id: &str) -> Option<String> {
        crate::proxy::token::persistence::get_quota_reset_time(&self.data_dir, account_id)
    }

    // Precisely lock account using quota reset time
    //
    // When API returns 429 but no quotaResetDelay, try using the account's quota reset time
    //
    // # Arguments
    // - `account_id`: Account ID
    // - `reason`: Rate limit reason (QuotaExhausted/ServerError, etc.)
    // - `model`: Optional model name, for model-level rate limiting
    pub fn set_precise_lockout(&self, account_id: &str, reason: crate::proxy::rate_limit::RateLimitReason, model: Option<String>) -> bool {
        crate::proxy::token::rate::set_precise_lockout(
            &self.data_dir,
            &self.rate_limit_tracker,
            account_id,
            reason,
            model,
        )
    }

    // Refresh quota in real-time and precisely lock account
    //
    // Call this method when 429 occurs:
    // 1. Call quota refresh API in real-time to get the latest reset_time
    // 2. Precisely lock account using the latest reset_time
    // 3. If retrieval fails, return false to let caller use fallback strategy
    //
    // # Arguments
    // - `model`: Optional model name, for model-level rate limiting
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

    // Mark account as rate-limited (async version, supports real-time quota refresh)
    //
    // Multi-level fallback strategy:
    // 1. Priority: API returns quotaResetDelay -> use directly
    // 2. Sub-optimal: Real-time quota refresh -> get latest reset_time
    // 3. Backup: Use locally cached quota -> read account file
    // 4. Final fallback: Exponential backoff strategy -> default lockout time
    //
    // # Arguments
    // - `email`: Account email, used to find account info
    // - `status`: HTTP status code (e.g., 429, 500, etc.)
    // - `retry_after_header`: Optional Retry-After response header
    // - `error_body`: Error response body, used to parse quotaResetDelay
    // - `model`: Optional model name, for model-level rate limiting
    pub async fn mark_rate_limited_async(
        &self,
        email: &str,
        status: u16,
        retry_after_header: Option<&str>,
        error_body: &str,
        model: Option<&str>,
    ) {
        crate::proxy::token::rate::mark_rate_limited_async(
            self.tokens.as_ref(),
            &self.data_dir,
            &self.rate_limit_tracker,
            &self.circuit_breaker_config,
            email,
            status,
            retry_after_header,
            error_body,
            model,
        )
        .await;
    }

    // ===== Scheduling Configuration Methods =====

    // Get current scheduling configuration
    pub async fn get_sticky_config(&self) -> crate::proxy::sticky_config::StickySessionConfig {
        crate::proxy::token::control::get_sticky_config(&self.sticky_config).await
    }

    // Update scheduling configuration
    pub async fn update_sticky_config(
        &self,
        new_config: crate::proxy::sticky_config::StickySessionConfig,
    ) {
        crate::proxy::token::control::update_sticky_config(&self.sticky_config, new_config).await;
    }

    // Update circuit breaker configuration
    pub async fn update_circuit_breaker_config(&self, config: crate::models::CircuitBreakerConfig) {
        crate::proxy::token::control::update_circuit_breaker_config(
            &self.circuit_breaker_config,
            config,
        )
        .await;
    }

    // Get circuit breaker configuration
    pub async fn get_circuit_breaker_config(&self) -> crate::models::CircuitBreakerConfig {
        crate::proxy::token::control::get_circuit_breaker_config(&self.circuit_breaker_config).await
    }

    // Clear sticky mapping for a specific session
    #[allow(dead_code)]
    pub fn clear_session_binding(&self, session_id: &str) {
        crate::proxy::token::control::clear_session_binding(self.session_accounts.as_ref(), session_id);
    }

    // Clear sticky mappings for all sessions
    pub fn clear_all_sessions(&self) {
        crate::proxy::token::control::clear_all_sessions(self.session_accounts.as_ref());
    }

    // ===== Fixed Account Mode Methods =====

    // Set preferred account ID (Fixed account mode)
    // Pass Some(account_id) to enable fixed account mode, None to restore round-robin mode
    pub async fn set_preferred_account(&self, account_id: Option<String>) {
        crate::proxy::token::control::set_preferred_account(
            &self.preferred_account_id,
            account_id,
        )
        .await;
    }

    // Get currently preferred account ID
    pub async fn get_preferred_account(&self) -> Option<String> {
        crate::proxy::token::control::get_preferred_account(&self.preferred_account_id).await
    }

    // Note: OAuth code exchange and auth URL generation are handled by `modules::oauth_server`.
    // Keeping OAuth flow state in one place avoids CSRF/state mismatches and reduces attack surface.

    // Get user info (Email, etc.)
    pub async fn get_user_info(
        &self,
        refresh_token: &str,
    ) -> Result<crate::modules::oauth::UserInfo, String> {
        crate::proxy::token::account_ops::get_user_info(refresh_token).await
    }

    // Add new account via server-side flow only.
    pub async fn add_account(&self, email: &str, refresh_token: &str) -> Result<(), String> {
        crate::proxy::token::account_ops::add_account(email, refresh_token).await?;

        // 4. Reload (update memory)
        self.reload_all_accounts().await.map(|_| ())
    }

    // Record successful request, increase health score
    pub fn record_success(&self, account_id: &str) {
        crate::proxy::token::health::record_success(&self.health_scores, account_id);
        tracing::debug!("📈 Health score increased for account {}", account_id);
    }

    // Record failed request, decrease health score
    pub fn record_failure(&self, account_id: &str) {
        crate::proxy::token::health::record_failure(&self.health_scores, account_id);
        tracing::warn!("📉 Health score decreased for account {}", account_id);
    }

    // Helper to find account ID by email
    pub fn get_account_id_by_email(&self, email: &str) -> Option<String> {
        crate::proxy::token::lookup::account_id_by_email(&self.tokens, email)
    }

    // Set validation blocked status for an account (internal)
    pub async fn set_validation_block(&self, account_id: &str, block_until: i64, reason: &str) -> Result<(), String> {
        crate::proxy::token::account_flags::set_validation_block(
            self.tokens.as_ref(),
            self.session_accounts.as_ref(),
            &self.data_dir,
            account_id,
            block_until,
            reason,
        )?;

        tracing::info!(
             "🚫 Account {} validation blocked until {} (reason: {})",
             account_id,
             block_until,
             reason
        );

        Ok(())
    }

    // Public method to set validation block (called from handlers)
    pub async fn set_validation_block_public(&self, account_id: &str, block_until: i64, reason: &str) -> Result<(), String> {
        self.set_validation_block(account_id, block_until, reason).await
    }

    // Set is_forbidden status for an account (called when proxy encounters 403)
    pub async fn set_forbidden(&self, account_id: &str, reason: &str) -> Result<(), String> {
        crate::proxy::token::account_flags::set_forbidden(
            self.session_accounts.as_ref(),
            &self.data_dir,
            account_id,
        )?;

        // Remove account from memory pool to avoid re-selection during retries
        self.remove_account(account_id);

        tracing::warn!(
            "🚫 Account {} marked as forbidden (403): {}",
            account_id,
            crate::proxy::token::account_flags::truncate_reason(reason, 100)
        );

        Ok(())
    }
}
