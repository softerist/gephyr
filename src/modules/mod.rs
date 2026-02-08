#[path = "auth/account.rs"]
pub mod account;
#[path = "auth/account_service.rs"]
pub mod account_service;
#[path = "system/cache.rs"]
pub mod cache;
#[path = "system/config.rs"]
pub mod config;
#[path = "persistence/db.rs"]
pub mod db;
#[path = "system/device.rs"]
pub mod device;
#[path = "system/integration.rs"]
pub mod integration;
#[path = "system/log_bridge.rs"]
pub mod log_bridge;
#[path = "system/logger.rs"]
pub mod logger;
#[path = "system/migration.rs"]
pub mod migration;
#[path = "auth/oauth.rs"]
pub mod oauth;
#[path = "auth/oauth_server.rs"]
pub mod oauth_server;
#[path = "system/process.rs"]
pub mod process;
#[path = "persistence/proxy_db.rs"]
pub mod proxy_db;
#[path = "system/quota.rs"]
pub mod quota;
#[path = "system/scheduler.rs"]
pub mod scheduler;
#[path = "persistence/security_db.rs"]
pub mod security_db;
#[path = "stats/token_stats.rs"]
pub mod token_stats;
#[path = "system/update_checker.rs"]
pub mod update_checker;
#[path = "persistence/user_token_db.rs"]
pub mod user_token_db;
#[path = "system/validation.rs"]
pub mod validation;
pub mod auth;
pub mod persistence;
pub mod stats;
pub mod system;

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
