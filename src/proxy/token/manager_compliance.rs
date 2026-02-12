use super::{ComplianceRequestGuard, ComplianceRuntimeState, TokenManager};
use std::time::{Duration, Instant};

impl TokenManager {
    pub async fn update_compliance_config(&self, config: crate::proxy::config::ComplianceConfig) {
        {
            let mut guard = self.compliance_config.write().await;
            *guard = config.clone();
        }

        if !config.enabled {
            self.clear_compliance_runtime_state();
        }
    }

    pub async fn get_compliance_config(&self) -> crate::proxy::config::ComplianceConfig {
        self.compliance_config.read().await.clone()
    }

    pub async fn get_compliance_debug_snapshot(&self) -> super::ComplianceDebugSnapshot {
        let cfg = self.compliance_config.read().await.clone();
        let now = Instant::now();

        let mut global_requests_in_last_minute = 0usize;
        let mut account_requests_in_last_minute = std::collections::HashMap::new();
        let mut account_in_flight = std::collections::HashMap::new();
        let mut account_cooldown_seconds_remaining = std::collections::HashMap::new();
        let mut risk_signals_last_minute = 0usize;
        let mut account_403_in_last_minute = std::collections::HashMap::new();
        let mut account_429_in_last_minute = std::collections::HashMap::new();
        let mut account_switches_last_minute = 0usize;

        if let Ok(mut state) = self.compliance_state.lock() {
            Self::cleanup_compliance_state_locked(&mut state, now);

            global_requests_in_last_minute = state.global_request_timestamps.len();
            account_requests_in_last_minute = state
                .account_request_timestamps
                .iter()
                .map(|(k, v)| (k.clone(), v.len()))
                .collect();
            account_in_flight = state.account_in_flight.clone();
            account_cooldown_seconds_remaining = state
                .account_cooldown_until
                .iter()
                .filter_map(|(account, until)| {
                    if *until > now {
                        Some((account.clone(), until.duration_since(now).as_secs()))
                    } else {
                        None
                    }
                })
                .collect();
            risk_signals_last_minute = state.risk_signal_timestamps.len();
            account_403_in_last_minute = state
                .account_status_403_timestamps
                .iter()
                .map(|(k, v)| (k.clone(), v.len()))
                .collect();
            account_429_in_last_minute = state
                .account_status_429_timestamps
                .iter()
                .map(|(k, v)| (k.clone(), v.len()))
                .collect();
            account_switches_last_minute = state.account_switch_timestamps.len();
        }

        super::ComplianceDebugSnapshot {
            config: cfg,
            global_requests_in_last_minute,
            account_requests_in_last_minute,
            account_in_flight,
            account_cooldown_seconds_remaining,
            risk_signals_last_minute,
            account_403_in_last_minute,
            account_429_in_last_minute,
            account_switches_last_minute,
        }
    }

    pub async fn effective_retry_attempts(&self, default_attempts: usize) -> usize {
        let cfg = self.compliance_config.read().await.clone();
        if !cfg.enabled {
            return default_attempts.max(1);
        }

        default_attempts.min(cfg.max_retry_attempts.max(1)).max(1)
    }

    pub async fn try_acquire_compliance_guard(
        &self,
        account_id: &str,
    ) -> Result<Option<ComplianceRequestGuard>, String> {
        let cfg = self.compliance_config.read().await.clone();
        if !cfg.enabled {
            return Ok(None);
        }

        let now = Instant::now();
        let mut state = self
            .compliance_state
            .lock()
            .map_err(|_| "Compliance state lock poisoned".to_string())?;
        Self::cleanup_compliance_state_locked(&mut state, now);

        if let Some(until) = state.account_cooldown_until.get(account_id).copied() {
            if until > now {
                let wait_seconds = until.duration_since(now).as_secs();
                return Err(format!(
                    "Compliance cooldown active for account {} ({}s remaining)",
                    account_id, wait_seconds
                ));
            }
        }

        let max_global = cfg.max_global_requests_per_minute.max(1) as usize;
        if state.global_request_timestamps.len() >= max_global {
            return Err("Compliance global RPM cap reached".to_string());
        }

        let max_account = cfg.max_account_requests_per_minute.max(1) as usize;
        let account_rpm_count = state
            .account_request_timestamps
            .get(account_id)
            .map(|q| q.len())
            .unwrap_or(0);
        if account_rpm_count >= max_account {
            return Err(format!(
                "Compliance account RPM cap reached for account {}",
                account_id
            ));
        }

        let max_concurrency = cfg.max_account_concurrency.max(1);
        let in_flight = state
            .account_in_flight
            .get(account_id)
            .copied()
            .unwrap_or(0);
        if in_flight >= max_concurrency {
            return Err(format!(
                "Compliance concurrency cap reached for account {}",
                account_id
            ));
        }

        state.global_request_timestamps.push_back(now);
        let account_queue = state
            .account_request_timestamps
            .entry(account_id.to_string())
            .or_default();
        account_queue.push_back(now);
        state
            .account_in_flight
            .entry(account_id.to_string())
            .and_modify(|v| *v += 1)
            .or_insert(1);

        Ok(Some(ComplianceRequestGuard {
            account_id: account_id.to_string(),
            state: self.compliance_state.clone(),
        }))
    }

    pub async fn mark_compliance_risk_signal(&self, account_id: &str, status: u16) {
        if !matches!(status, 401 | 403 | 429 | 500 | 503 | 529) {
            return;
        }

        let cfg = self.compliance_config.read().await.clone();
        if !cfg.enabled || cfg.risk_cooldown_seconds == 0 {
            return;
        }

        if let Ok(mut state) = self.compliance_state.lock() {
            let now = Instant::now();
            state.risk_signal_timestamps.push_back(now);
            if status == 403 {
                state
                    .account_status_403_timestamps
                    .entry(account_id.to_string())
                    .or_default()
                    .push_back(now);
            } else if status == 429 {
                state
                    .account_status_429_timestamps
                    .entry(account_id.to_string())
                    .or_default()
                    .push_back(now);
            }
            state.account_cooldown_until.insert(
                account_id.to_string(),
                now + Duration::from_secs(cfg.risk_cooldown_seconds),
            );
            Self::cleanup_compliance_state_locked(&mut state, now);
        }
    }

    pub(super) fn record_account_switch_event(
        &self,
        previous_account: Option<&str>,
        selected_account: &str,
    ) {
        if previous_account.is_some_and(|prev| prev == selected_account) {
            return;
        }

        if let Ok(mut state) = self.compliance_state.lock() {
            let now = Instant::now();
            state.account_switch_timestamps.push_back(now);
            Self::cleanup_compliance_state_locked(&mut state, now);
        }
    }

    pub(super) fn clear_compliance_runtime_state(&self) {
        if let Ok(mut state) = self.compliance_state.lock() {
            *state = ComplianceRuntimeState::default();
        }
    }

    fn cleanup_compliance_state_locked(state: &mut ComplianceRuntimeState, now: Instant) {
        let window_start = now.checked_sub(Duration::from_secs(60)).unwrap_or(now);

        while let Some(ts) = state.global_request_timestamps.front() {
            if *ts < window_start {
                state.global_request_timestamps.pop_front();
            } else {
                break;
            }
        }
        while let Some(ts) = state.risk_signal_timestamps.front() {
            if *ts < window_start {
                state.risk_signal_timestamps.pop_front();
            } else {
                break;
            }
        }
        while let Some(ts) = state.account_switch_timestamps.front() {
            if *ts < window_start {
                state.account_switch_timestamps.pop_front();
            } else {
                break;
            }
        }

        state.account_request_timestamps.retain(|_, queue| {
            while let Some(ts) = queue.front() {
                if *ts < window_start {
                    queue.pop_front();
                } else {
                    break;
                }
            }
            !queue.is_empty()
        });
        state.account_status_403_timestamps.retain(|_, queue| {
            while let Some(ts) = queue.front() {
                if *ts < window_start {
                    queue.pop_front();
                } else {
                    break;
                }
            }
            !queue.is_empty()
        });
        state.account_status_429_timestamps.retain(|_, queue| {
            while let Some(ts) = queue.front() {
                if *ts < window_start {
                    queue.pop_front();
                } else {
                    break;
                }
            }
            !queue.is_empty()
        });

        state.account_cooldown_until.retain(|_, until| *until > now);
    }
}
