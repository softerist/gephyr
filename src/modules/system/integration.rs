use crate::models::Account;

pub trait SystemIntegration: Send + Sync {
    async fn on_account_switch(&self, account: &Account) -> Result<(), String>;
    fn refresh_runtime_state(&self);
    fn show_notification(&self, title: &str, body: &str);
}

pub struct HeadlessIntegration;

impl SystemIntegration for HeadlessIntegration {
    async fn on_account_switch(&self, account: &Account) -> Result<(), String> {
        crate::modules::system::logger::log_info(&format!(
            "[Headless] Account switched in memory: {}",
            account.email
        ));
        Ok(())
    }

    fn refresh_runtime_state(&self) {}

    fn show_notification(&self, title: &str, body: &str) {
        crate::modules::system::logger::log_info(&format!("[Notification] {}: {}", title, body));
    }
}

#[derive(Clone)]
pub enum SystemManager {
    Headless,
}

impl SystemManager {
    pub async fn on_account_switch(&self, account: &Account) -> Result<(), String> {
        let integration = HeadlessIntegration;
        integration.on_account_switch(account).await
    }

    pub fn refresh_runtime_state(&self) {
        let integration = HeadlessIntegration;
        integration.refresh_runtime_state();
    }

    pub fn show_notification(&self, title: &str, body: &str) {
        let integration = HeadlessIntegration;
        integration.show_notification(title, body);
    }
}

impl SystemIntegration for SystemManager {
    async fn on_account_switch(&self, account: &Account) -> Result<(), String> {
        self.on_account_switch(account).await
    }

    fn refresh_runtime_state(&self) {
        self.refresh_runtime_state();
    }

    fn show_notification(&self, title: &str, body: &str) {
        self.show_notification(title, body);
    }
}
