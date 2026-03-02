use crate::modules::persistence::user_token_db::{self, UserToken};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateTokenRequest {
    pub username: String,
    pub expires_type: String,
    pub description: Option<String>,
    pub max_ips: i32,
    pub curfew_start: Option<String>,
    pub curfew_end: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateTokenRequest {
    pub username: Option<String>,
    pub description: Option<String>,
    pub enabled: Option<bool>,
    pub max_ips: Option<i32>,
    pub curfew_start: Option<Option<String>>,
    pub curfew_end: Option<Option<String>>,
}
pub async fn list_user_tokens() -> Result<Vec<UserToken>, String> {
    user_token_db::list_tokens()
}
pub async fn create_user_token(request: CreateTokenRequest) -> Result<UserToken, String> {
    user_token_db::create_token(
        request.username,
        request.expires_type,
        request.description,
        request.max_ips,
        request.curfew_start,
        request.curfew_end,
    )
}
pub async fn update_user_token(id: String, request: UpdateTokenRequest) -> Result<(), String> {
    user_token_db::update_token(
        &id,
        request.username,
        request.description,
        request.enabled,
        request.max_ips,
        request.curfew_start,
        request.curfew_end,
    )
}
pub async fn delete_user_token(id: String) -> Result<(), String> {
    user_token_db::delete_token(&id)
}
pub async fn renew_user_token(id: String, expires_type: String) -> Result<(), String> {
    user_token_db::renew_token(&id, &expires_type)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserTokenStats {
    pub total_tokens: usize,
    pub active_tokens: usize,
    pub total_users: usize,
    pub today_requests: i64,
}
pub async fn get_user_token_summary() -> Result<UserTokenStats, String> {
    let tokens = user_token_db::list_tokens()?;
    let today_requests = user_token_db::get_today_request_count()?;
    let active_tokens = tokens.iter().filter(|t| t.enabled).count();
    let mut users = std::collections::HashSet::new();
    for t in &tokens {
        users.insert(t.username.clone());
    }

    Ok(UserTokenStats {
        total_tokens: tokens.len(),
        active_tokens,
        total_users: users.len(),
        today_requests,
    })
}
