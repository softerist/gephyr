use regex::Regex;
use std::sync::LazyLock;
const VERSION_URL: &str = "https://antigravity-auto-updater-974169037036.us-central1.run.app";
const CHANGELOG_URL: &str = "https://antigravity.google/changelog";
const FALLBACK_VERSION: &str = env!("CARGO_PKG_VERSION");
static VERSION_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\d+\.\d+\.\d+").expect("Invalid version regex"));
fn parse_version(text: &str) -> Option<String> {
    VERSION_REGEX.find(text).map(|m| m.as_str().to_string())
}
#[derive(Debug, PartialEq)]
enum VersionSource {
    RemoteAPI,
    ChangelogWeb,
    CargoToml,
}
fn fetch_remote_version() -> (String, VersionSource) {
    if let Some(v) = try_fetch_version(VERSION_URL, "version-api-fetch") {
        return (v, VersionSource::RemoteAPI);
    }
    if let Some(v) = try_fetch_version(CHANGELOG_URL, "changelog-scrape") {
        return (v, VersionSource::ChangelogWeb);
    }
    (FALLBACK_VERSION.to_string(), VersionSource::CargoToml)
}
fn try_fetch_version(url: &'static str, thread_name: &str) -> Option<String> {
    let handle = std::thread::Builder::new()
        .name(thread_name.to_string())
        .spawn(move || {
            let client = reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .ok()?;

            let response = client.get(url).send().ok()?;
            let text = response.text().ok()?;
            let scan_text = if url == CHANGELOG_URL && text.len() > 5000 {
                &text[..5000]
            } else {
                &text
            };

            parse_version(scan_text)
        });

    match handle {
        Ok(h) => h.join().ok().flatten(),
        Err(e) => {
            tracing::debug!("Failed to spawn {} thread: {}", thread_name, e);
            None
        }
    }
}
pub static USER_AGENT: LazyLock<String> = LazyLock::new(|| {
    let (version, source) = fetch_remote_version();

    tracing::info!(
        version = %version,
        source = ?source,
        "User-Agent initialized"
    );

    format!(
        "antigravity/{} {}/{}",
        version,
        std::env::consts::OS,
        std::env::consts::ARCH
    )
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_version_from_updater_response() {
        let text = "Auto updater is running. Stable Version: 1.15.8-5724687216017408";
        assert_eq!(parse_version(text), Some("1.15.8".to_string()));
    }

    #[test]
    fn test_parse_version_simple() {
        assert_eq!(parse_version("1.15.8"), Some("1.15.8".to_string()));
        assert_eq!(parse_version("Version: 2.0.0"), Some("2.0.0".to_string()));
        assert_eq!(parse_version("v1.2.3"), Some("1.2.3".to_string()));
    }

    #[test]
    fn test_parse_version_invalid() {
        assert_eq!(parse_version("no version here"), None);
        assert_eq!(parse_version(""), None);
        assert_eq!(parse_version("1.2"), None);
    }

    #[test]
    fn test_parse_version_with_suffix() {
        let text = "antigravity/1.15.8 windows/amd64";
        assert_eq!(parse_version(text), Some("1.15.8".to_string()));
    }
}
