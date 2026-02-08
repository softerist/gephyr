pub(crate) async fn get_user_info(
    refresh_token: &str,
) -> Result<crate::modules::oauth::UserInfo, String> {
    let token = crate::modules::oauth::refresh_access_token(refresh_token, None)
        .await
        .map_err(|e| format!("Failed to refresh Access Token: {}", e))?;

    crate::modules::oauth::get_user_info(&token.access_token, None).await
}

pub(crate) async fn add_account(email: &str, refresh_token: &str) -> Result<(), String> {
    let token_info = crate::modules::oauth::refresh_access_token(refresh_token, None)
        .await
        .map_err(|e| format!("Invalid refresh token: {}", e))?;

    let project_id = crate::proxy::project_resolver::fetch_project_id(&token_info.access_token)
        .await
        .unwrap_or_else(|_| "bamboo-precept-lgxtn".to_string());

    let email_clone = email.to_string();
    let refresh_token_clone = refresh_token.to_string();

    tokio::task::spawn_blocking(move || {
        let token_data = crate::models::TokenData::new(
            token_info.access_token,
            refresh_token_clone,
            token_info.expires_in,
            Some(email_clone.clone()),
            Some(project_id),
            None,
        );

        crate::modules::account::upsert_account(email_clone, None, token_data)
    })
    .await
    .map_err(|e| format!("Task join error: {}", e))?
    .map_err(|e| format!("Failed to save account: {}", e))?;

    Ok(())
}
