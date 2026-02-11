use crate::models::{Account, TokenData};
use crate::modules::auth::{account, oauth, oauth_server};
use crate::modules::system::{logger, quota};

pub struct AccountService {
    pub integration: crate::modules::system::integration::SystemManager,
}

impl AccountService {
    pub fn new(integration: crate::modules::system::integration::SystemManager) -> Self {
        Self { integration }
    }
    pub async fn add_account(&self, refresh_token: &str) -> Result<Account, String> {
        let temp_account_id = uuid::Uuid::new_v4().to_string();
        let token_res = oauth::refresh_access_token(refresh_token, Some(&temp_account_id)).await?;
        let access_token = token_res.access_token.clone();
        let (email, display_name, google_sub) = Self::resolve_identity_from_google(
            &access_token,
            token_res.id_token.as_deref(),
            Some(&temp_account_id),
        )
        .await?;
        let project_id =
            crate::proxy::project_resolver::fetch_project_id(&token_res.access_token, None)
                .await
                .ok();
        let token = TokenData::new(
            token_res.access_token.clone(),
            refresh_token.to_string(),
            token_res.expires_in,
            Some(email.clone()),
            project_id,
            None,
        );
        let mut account = account::upsert_account(email.clone(), display_name, token, google_sub)?;
        let email_for_log = account.email.clone();
        let access_token = token_res.access_token.clone();
        match quota::fetch_quota(&access_token, &email_for_log, Some(&account.id)).await {
            Ok((quota_data, new_project_id)) => {
                account.quota = Some(quota_data);
                if let Some(pid) = new_project_id {
                    account.token.project_id = Some(pid);
                }
                if let Err(e) = account::save_account(&account) {
                    logger::log_warn(&format!(
                        "[Service] Failed to save quota for {}: {}",
                        email_for_log, e
                    ));
                } else {
                    logger::log_info(&format!(
                        "[Service] Fetched quota for new account: {}",
                        email_for_log
                    ));
                }
            }
            Err(e) => {
                logger::log_warn(&format!(
                    "[Service] Failed to fetch quota for {}: {}",
                    email_for_log, e
                ));
            }
        }

        logger::log_info(&format!(
            "[Service] Added/Updated account: {}",
            account.email
        ));
        Ok(account)
    }
    pub fn delete_account(&self, account_id: &str) -> Result<(), String> {
        account::delete_account(account_id)?;
        self.integration.refresh_runtime_state();
        Ok(())
    }
    pub async fn switch_account(&self, account_id: &str) -> Result<(), String> {
        account::switch_account(account_id, &self.integration).await
    }
    pub fn list_accounts(&self) -> Result<Vec<Account>, String> {
        account::list_accounts()
    }
    pub fn get_current_id(&self) -> Result<Option<String>, String> {
        account::get_current_account_id()
    }

    pub async fn prepare_oauth_url(&self) -> Result<String, String> {
        oauth_server::prepare_oauth_url().await
    }

    pub async fn start_oauth_login(&self) -> Result<Account, String> {
        let token_res = oauth_server::start_oauth_flow().await?;
        self.process_oauth_token(token_res).await
    }

    pub async fn complete_oauth_login(&self) -> Result<Account, String> {
        let token_res = oauth_server::complete_oauth_flow().await?;
        self.process_oauth_token(token_res).await
    }

    pub fn cancel_oauth_login(&self) {
        oauth_server::cancel_oauth_flow();
    }

    pub async fn submit_oauth_code(
        &self,
        code: String,
        state: Option<String>,
    ) -> Result<(), String> {
        oauth_server::submit_oauth_code(code, state).await
    }

    async fn process_oauth_token(
        &self,
        token_res: oauth::TokenResponse,
    ) -> Result<Account, String> {
        let refresh_token = token_res.refresh_token.ok_or_else(|| {
            "Refresh Token not found. Please revoke permissions and try again.".to_string()
        })?;
        let temp_account_id = uuid::Uuid::new_v4().to_string();
        let access_token = token_res.access_token.clone();
        let expires_in = token_res.expires_in;
        let (email, display_name, google_sub) = Self::resolve_identity_from_google(
            &access_token,
            token_res.id_token.as_deref(),
            Some(&temp_account_id),
        )
        .await?;
        let project_id =
            crate::proxy::project_resolver::fetch_project_id(&token_res.access_token, None)
                .await
                .ok();

        let token_data = crate::models::TokenData::new(
            access_token,
            refresh_token,
            expires_in,
            Some(email.clone()),
            project_id,
            None,
        );

        let account = account::upsert_account(email, display_name, token_data, google_sub)?;
        self.integration.refresh_runtime_state();

        Ok(account)
    }

    async fn resolve_identity_from_google(
        access_token: &str,
        raw_id_token: Option<&str>,
        account_id: Option<&str>,
    ) -> Result<(String, Option<String>, Option<String>), String> {
        let identity = oauth::verify_identity(access_token, raw_id_token, account_id).await?;
        Ok((identity.email, identity.name, identity.google_sub))
    }
}
