use crate::models::AppConfig;
use crate::modules::{
    auth::account,
    persistence::{proxy_db, security_db},
    stats::token_stats,
    system::{config, logger, migration},
};
use crate::proxy::state::AdminState;
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Json},
};
use serde::{Deserialize, Serialize};
use tracing::error;

#[derive(Serialize)]
pub(crate) struct ErrorResponse {
    error: String,
}

include!("admin/accounts.rs");
include!("admin/runtime.rs");
include!("admin/stats.rs");
include!("admin/security.rs");
include!("admin/system.rs");
