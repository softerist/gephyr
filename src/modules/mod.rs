pub mod account;
pub mod account_service;
pub mod cache;
pub mod config;
pub mod db;
pub mod device;
pub mod integration;
pub mod log_bridge;
pub mod logger;
pub mod migration;
pub mod oauth;
pub mod oauth_server;
pub mod process;
pub mod proxy_db;
pub mod quota;
pub mod scheduler;
pub mod security_db;
pub mod token_stats;
pub mod update_checker;
pub mod user_token_db;
pub mod validation;

use crate::models;
pub use account::*;
#[allow(unused_imports)]
pub use config::*;
#[allow(unused_imports)]
pub use logger::*;
#[allow(unused_imports)]
pub use quota::*;

pub async fn fetch_quota(
    access_token: &str,
    email: &str,
    account_id: Option<&str>,
) -> crate::error::AppResult<(models::QuotaData, Option<String>)> {
    quota::fetch_quota(access_token, email, account_id).await
}
