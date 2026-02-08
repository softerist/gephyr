use dashmap::DashMap;

use crate::proxy::token::types::ProxyToken;

pub(crate) async fn get_token_by_email(
    tokens: &DashMap<String, ProxyToken>,
    email: &str,
) -> Result<(String, String, String, String, u64), String> {
    let token_info = {
        let mut found = None;
        for entry in tokens.iter() {
            let token = entry.value();
            if token.email == email {
                found = Some((
                    token.account_id.clone(),
                    token.access_token.clone(),
                    token.refresh_token.clone(),
                    token.timestamp,
                    token.expires_in,
                    chrono::Utc::now().timestamp(),
                    token.project_id.clone(),
                ));
                break;
            }
        }
        found
    };

    let (
        account_id,
        current_access_token,
        refresh_token,
        timestamp,
        expires_in,
        now,
        project_id_opt,
    ) = match token_info {
        Some(info) => info,
        None => return Err(format!("Account not found: {}", email)),
    };

    let project_id = project_id_opt.unwrap_or_else(|| "bamboo-precept-lgxtn".to_string());

    if now < timestamp + expires_in - 300 {
        return Ok((
            current_access_token,
            project_id,
            email.to_string(),
            account_id,
            0,
        ));
    }

    tracing::info!("[Warmup] Token for {} is expiring, refreshing...", email);

    match crate::modules::auth::oauth::refresh_access_token(&refresh_token, Some(&account_id)).await {
        Ok(token_response) => {
            tracing::info!("[Warmup] Token refresh successful for {}", email);
            let new_now = chrono::Utc::now().timestamp();

            if let Some(mut entry) = tokens.get_mut(&account_id) {
                entry.access_token = token_response.access_token.clone();
                entry.expires_in = token_response.expires_in;
                entry.timestamp = new_now;
            }

            if let Some(entry) = tokens.get(&account_id) {
                let _ = crate::proxy::token::persistence::save_refreshed_token(
                    &entry.account_path,
                    &token_response,
                );
            }

            Ok((
                token_response.access_token,
                project_id,
                email.to_string(),
                account_id,
                0,
            ))
        }
        Err(e) => Err(format!(
            "[Warmup] Token refresh failed for {}: {}",
            email, e
        )),
    }
}
