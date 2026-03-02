use crate::proxy::config::{ProxyAuthMode, ProxyConfig, SecurityMonitorConfig};

#[derive(Debug, Clone)]
pub struct ProxySecurityConfig {
    pub auth_mode: ProxyAuthMode,
    pub api_key: String,
    pub admin_password: Option<String>,
    pub allow_lan_access: bool,
    pub port: u16,
    pub security_monitor: SecurityMonitorConfig,
}

impl ProxySecurityConfig {
    pub fn from_proxy_config(config: &ProxyConfig) -> Self {
        Self {
            auth_mode: config.auth_mode.clone(),
            api_key: config.api_key.clone(),
            admin_password: config.admin_password.clone(),
            allow_lan_access: config.allow_lan_access,
            port: config.port,
            security_monitor: config.security_monitor.clone(),
        }
    }

    pub fn effective_auth_mode(&self) -> ProxyAuthMode {
        self.auth_mode.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_mode_is_preserved() {
        let s = ProxySecurityConfig {
            auth_mode: ProxyAuthMode::Strict,
            api_key: "sk-test".to_string(),
            admin_password: None,
            allow_lan_access: false,
            port: 8080,
            security_monitor: crate::proxy::config::SecurityMonitorConfig::default(),
        };
        assert!(matches!(s.effective_auth_mode(), ProxyAuthMode::Strict));
    }

    #[test]
    fn all_except_health_mode_is_preserved() {
        let s = ProxySecurityConfig {
            auth_mode: ProxyAuthMode::AllExceptHealth,
            api_key: "sk-test".to_string(),
            admin_password: None,
            allow_lan_access: true,
            port: 8080,
            security_monitor: crate::proxy::config::SecurityMonitorConfig::default(),
        };
        assert!(matches!(
            s.effective_auth_mode(),
            ProxyAuthMode::AllExceptHealth
        ));
    }
}
