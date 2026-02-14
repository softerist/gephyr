use dashmap::DashMap;

use crate::proxy::token::types::ProxyToken;

pub(crate) fn account_id_by_email(
    tokens: &DashMap<String, ProxyToken>,
    email: &str,
) -> Option<String> {
    tokens
        .iter()
        .find(|entry| entry.value().email == email)
        .map(|entry| entry.value().account_id.clone())
}