use super::*;

impl TokenManager {
    pub(super) fn apply_refreshed_token(
        &self,
        token: &mut ProxyToken,
        token_response: &crate::modules::oauth::TokenResponse,
        now: i64,
    ) {
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
            token_response,
        ) {
            tracing::debug!("Failed to persist refreshed token ({}): {}", token.email, e);
        }
    }

    pub(super) fn apply_project_id(&self, token: &mut ProxyToken, project_id: &str) {
        if let Some(mut entry) = self.tokens.get_mut(&token.account_id) {
            entry.project_id = Some(project_id.to_string());
        }
        let _ = crate::proxy::token::persistence::save_project_id(&token.account_path, project_id);
        token.project_id = Some(project_id.to_string());
    }
}
