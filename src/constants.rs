use std::sync::LazyLock;

const FALLBACK_VERSION: &str = env!("CARGO_PKG_VERSION");

fn user_agent_platform() -> String {
    let os = std::env::consts::OS;
    let arch = match (os, std::env::consts::ARCH) {
        ("windows", "x86_64") => "amd64",
        ("windows", "aarch64") => "arm64",
        _ => std::env::consts::ARCH,
    };
    format!("{}/{}", os, arch)
}

pub static USER_AGENT: LazyLock<String> = LazyLock::new(|| {
    tracing::info!(
        version = %FALLBACK_VERSION,
        source = "cargo_pkg_version",
        "User-Agent initialized"
    );

    format!("antigravity/{} {}", FALLBACK_VERSION, user_agent_platform())
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
        let platform = user_agent_platform();
        assert!(USER_AGENT.ends_with(&platform));
    }
}
