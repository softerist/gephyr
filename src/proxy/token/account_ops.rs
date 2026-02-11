pub(crate) async fn get_user_info(
    refresh_token: &str,
) -> Result<crate::modules::auth::oauth::UserInfo, String> {
    let token = crate::modules::auth::oauth::refresh_access_token(refresh_token, None)
        .await
        .map_err(|e| format!("Failed to refresh Access Token: {}", e))?;

    crate::modules::auth::oauth::get_user_info(&token.access_token, None).await
}

pub(crate) async fn add_account(refresh_token: &str) -> Result<(), String> {
    let token_info = crate::modules::auth::oauth::refresh_access_token(refresh_token, None)
        .await
        .map_err(|e| format!("Invalid refresh token: {}", e))?;

    let (email, google_sub) = if let Some(raw_id_token) = token_info.id_token.as_deref() {
        let claims = crate::modules::auth::id_token::validate_id_token(raw_id_token)
            .await
            .map_err(|e| format!("Invalid id_token: {}", e))?;
        (claims.email, Some(claims.sub))
    } else {
        let user_info = crate::modules::auth::oauth::get_user_info(&token_info.access_token, None)
            .await
            .map_err(|e| format!("Failed to fetch user info: {}", e))?;
        if !user_info.is_email_verified() {
            return Err("Google userinfo rejected: email is not verified".to_string());
        }
        let google_sub = user_info.google_sub();
        (user_info.email, google_sub)
    };

    let project_id = crate::proxy::project_resolver::fetch_project_id(&token_info.access_token)
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
