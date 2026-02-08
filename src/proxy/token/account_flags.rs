use std::path::PathBuf;

use dashmap::DashMap;

use crate::proxy::token::types::ProxyToken;

pub(crate) fn truncate_reason(reason: &str, max_len: usize) -> String {
    if reason.len() <= max_len {
        reason.to_string()
    } else {
        format!("{}...", &reason[..max_len - 3])
    }
}

pub(crate) fn set_validation_block(
    tokens: &DashMap<String, ProxyToken>,
    session_accounts: &DashMap<String, String>,
    data_dir: &PathBuf,
    account_id: &str,
    block_until: i64,
    reason: &str,
) -> Result<(), String> {
    if let Some(mut token) = tokens.get_mut(account_id) {
        token.validation_blocked = true;
        token.validation_blocked_until = block_until;
    }

    crate::proxy::token::persistence::set_validation_block(data_dir, account_id, block_until, reason)?;
    session_accounts.retain(|_, v| *v != account_id);
    Ok(())
}

pub(crate) fn set_forbidden(
    session_accounts: &DashMap<String, String>,
    data_dir: &PathBuf,
    account_id: &str,
) -> Result<(), String> {
    crate::proxy::token::persistence::set_forbidden(data_dir, account_id)?;
    session_accounts.retain(|_, v| *v != account_id);
    Ok(())
}
