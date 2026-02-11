pub(crate) async fn get_verified_identity(
    refresh_token: &str,
) -> Result<crate::modules::auth::oauth::VerifiedIdentity, String> {
    let token = crate::modules::auth::oauth::refresh_access_token(refresh_token, None)
        .await
        .map_err(|e| format!("Failed to refresh Access Token: {}", e))?;

    crate::modules::auth::oauth::verify_identity(
        &token.access_token,
        token.id_token.as_deref(),
        None,
    )
    .await
}

pub(crate) async fn add_account(refresh_token: &str) -> Result<(), String> {
    let token_info = crate::modules::auth::oauth::refresh_access_token(refresh_token, None)
        .await
        .map_err(|e| format!("Invalid refresh token: {}", e))?;

    let identity = crate::modules::auth::oauth::verify_identity(
        &token_info.access_token,
        token_info.id_token.as_deref(),
        None,
    )
    .await?;
    let email = identity.email;
    let google_sub = identity.google_sub;

    let project_id =
        crate::proxy::project_resolver::fetch_project_id(&token_info.access_token, None)
            .await
            .unwrap_or_else(|_| "bamboo-precept-lgxtn".to_string());

    let email_clone = email.clone();
    let refresh_token_clone = refresh_token.to_string();
    let google_sub_clone = google_sub.clone();

    tokio::task::spawn_blocking(move || {
        let token_data = crate::models::TokenData::new(
            token_info.access_token,
            refresh_token_clone,
            token_info.expires_in,
            Some(email_clone.clone()),
            Some(project_id),
            None,
        );

        crate::modules::auth::account::upsert_account(
            email_clone,
            None,
            token_data,
            google_sub_clone,
        )
    })
    .await
    .map_err(|e| format!("Task join error: {}", e))?
    .map_err(|e| format!("Failed to save account: {}", e))?;

    Ok(())
}
