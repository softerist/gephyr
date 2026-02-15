pub const CLOUDCODE_HOST_DAILY: &str = "daily-cloudcode-pa.googleapis.com";
pub const CLOUDCODE_HOST_PUBLIC: &str = "cloudcode-pa.googleapis.com";

pub const USERINFO_OAUTH2_V2: &str = "https://www.googleapis.com/oauth2/v2/userinfo";
pub const USERINFO_OPENIDCONNECT_V1: &str = "https://openidconnect.googleapis.com/v1/userinfo";

pub fn cloudcode_hosts_for_profile(
    profile: crate::proxy::config::GoogleMimicProfile,
) -> Vec<&'static str> {
    match profile {
        crate::proxy::config::GoogleMimicProfile::StrictMimic => {
            vec![CLOUDCODE_HOST_DAILY, CLOUDCODE_HOST_PUBLIC]
        }
        crate::proxy::config::GoogleMimicProfile::Functional => vec![CLOUDCODE_HOST_PUBLIC],
    }
}

pub fn cloudcode_host_strategy(profile: crate::proxy::config::GoogleMimicProfile) -> &'static str {
    match profile {
        crate::proxy::config::GoogleMimicProfile::StrictMimic => {
            "daily-cloudcode-first,fallback-cloudcode"
        }
        crate::proxy::config::GoogleMimicProfile::Functional => "cloudcode-only",
    }
}

pub fn userinfo_endpoints(
    selection: crate::proxy::config::GoogleUserinfoEndpoint,
) -> Vec<&'static str> {
    match selection {
        crate::proxy::config::GoogleUserinfoEndpoint::Oauth2V2 => vec![USERINFO_OAUTH2_V2],
        crate::proxy::config::GoogleUserinfoEndpoint::OpenidconnectV1 => {
            vec![USERINFO_OPENIDCONNECT_V1]
        }
        crate::proxy::config::GoogleUserinfoEndpoint::DualFallback => {
            vec![USERINFO_OAUTH2_V2, USERINFO_OPENIDCONNECT_V1]
        }
    }
}

pub fn endpoint_load_code_assist(host: &str) -> String {
    build_cloudcode_colon_method_endpoint(host, "loadCodeAssist", None)
}

pub fn endpoint_fetch_user_info(host: &str) -> String {
    build_cloudcode_colon_method_endpoint(host, "fetchUserInfo", None)
}

pub fn endpoint_fetch_available_models(host: &str) -> String {
    build_cloudcode_colon_method_endpoint(host, "fetchAvailableModels", None)
}

pub fn endpoint_onboard_user(host: &str) -> String {
    build_cloudcode_colon_method_endpoint(host, "onboardUser", None)
}

pub fn endpoint_cascade_nuxes(host: &str) -> String {
    format!("https://{}/v1internal/cascadeNuxes", host)
}

#[allow(dead_code)]
pub fn endpoint_generate_content(host: &str) -> String {
    build_cloudcode_colon_method_endpoint(host, "generateContent", None)
}

#[allow(dead_code)]
pub fn endpoint_stream_generate_content(host: &str) -> String {
    build_cloudcode_colon_method_endpoint(host, "streamGenerateContent", Some("alt=sse"))
}

fn build_cloudcode_colon_method_endpoint(
    host: &str,
    method: &str,
    query: Option<&str>,
) -> String {
    match query {
        Some(qs) if !qs.trim().is_empty() => {
            format!("https://{}/v1internal:{}?{}", host, method, qs)
        }
        _ => format!("https://{}/v1internal:{}", host, method),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_profile_prefers_daily_cloudcode_host() {
        let hosts =
            cloudcode_hosts_for_profile(crate::proxy::config::GoogleMimicProfile::StrictMimic);
        assert_eq!(
            hosts,
            vec![CLOUDCODE_HOST_DAILY, CLOUDCODE_HOST_PUBLIC]
        );
    }

    #[test]
    fn oauth2_v2_is_primary_userinfo_endpoint() {
        let endpoints = userinfo_endpoints(crate::proxy::config::GoogleUserinfoEndpoint::Oauth2V2);
        assert_eq!(endpoints, vec![USERINFO_OAUTH2_V2]);
    }

    #[test]
    fn dual_fallback_includes_both_userinfo_endpoints() {
        let endpoints =
            userinfo_endpoints(crate::proxy::config::GoogleUserinfoEndpoint::DualFallback);
        assert_eq!(
            endpoints,
            vec![USERINFO_OAUTH2_V2, USERINFO_OPENIDCONNECT_V1]
        );
    }
}
