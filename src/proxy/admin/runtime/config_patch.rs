use axum::{
    http::{HeaderMap, StatusCode},
    Json,
};

use super::audit;
use crate::proxy::admin::ErrorResponse;
use crate::proxy::state::AdminState;

pub(crate) type AdminError = (StatusCode, Json<ErrorResponse>);

#[derive(Debug, Clone)]
pub(crate) struct ProxyPatchResult {
    pub actor: super::audit_event::ActorIdentity,
    pub before: crate::proxy::config::ProxyConfig,
    pub after: crate::proxy::config::ProxyConfig,
}

pub(crate) async fn patch_proxy_config<F>(
    state: &AdminState,
    headers: &HeaderMap,
    patch_fn: F,
) -> Result<ProxyPatchResult, AdminError>
where
    F: FnOnce(&mut crate::proxy::config::ProxyConfig) -> Result<(), String>,
{
    let actor = audit::resolve_admin_actor(state, headers).await;
    let mut app_config =
        crate::modules::system::config::load_app_config().map_err(internal_error)?;
    let before = app_config.proxy.clone();

    patch_fn(&mut app_config.proxy).map_err(bad_request)?;

    if let Err(errors) = crate::modules::system::validation::validate_app_config(&app_config) {
        let message = errors
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        return Err(bad_request(message));
    }

    crate::modules::system::config::save_app_config(&app_config).map_err(internal_error)?;
    let after = app_config.proxy.clone();

    Ok(ProxyPatchResult {
        actor,
        before,
        after,
    })
}

pub(crate) fn bad_request(error: impl Into<String>) -> AdminError {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorResponse {
            error: error.into(),
        }),
    )
}

pub(crate) fn internal_error(error: impl Into<String>) -> AdminError {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse {
            error: error.into(),
        }),
    )
}
