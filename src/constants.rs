use std::sync::LazyLock;

const FALLBACK_VERSION: &str = env!("CARGO_PKG_VERSION");

pub static USER_AGENT: LazyLock<String> = LazyLock::new(|| {
    tracing::info!(
        version = %FALLBACK_VERSION,
        source = "cargo_pkg_version",
        "User-Agent initialized"
    );

    format!(
        "antigravity/{} {}/{}",
        FALLBACK_VERSION,
        std::env::consts::OS,
        std::env::consts::ARCH
    )
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_agent_uses_cargo_pkg_version() {
        let expected_prefix = format!("antigravity/{FALLBACK_VERSION}");
        assert!(USER_AGENT.starts_with(&expected_prefix));
    }

    #[test]
    fn user_agent_contains_platform_suffix() {
        let platform = format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH);
        assert!(USER_AGENT.ends_with(&platform));
    }
}
