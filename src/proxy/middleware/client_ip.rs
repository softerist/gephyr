use axum::extract::Request;
use std::net::{IpAddr, SocketAddr};
use std::sync::{OnceLock, RwLock};

#[derive(Debug, Clone, Default)]
struct ClientIpResolverConfig {
    trusted_proxies: Vec<String>,
}

fn resolver_config() -> &'static RwLock<ClientIpResolverConfig> {
    static CONFIG: OnceLock<RwLock<ClientIpResolverConfig>> = OnceLock::new();
    CONFIG.get_or_init(|| RwLock::new(ClientIpResolverConfig::default()))
}

fn current_trusted_proxies() -> Vec<String> {
    resolver_config()
        .read()
        .map(|cfg| cfg.trusted_proxies.clone())
        .unwrap_or_default()
}

pub(crate) fn set_trusted_proxies(trusted_proxies: Vec<String>) {
    let sanitized: Vec<String> = trusted_proxies
        .into_iter()
        .map(|entry| entry.trim().to_string())
        .filter(|entry| !entry.is_empty())
        .collect();

    if let Ok(mut cfg) = resolver_config().write() {
        cfg.trusted_proxies = sanitized;
    }
}

pub(crate) fn extract_client_ip(request: &Request) -> Option<String> {
    let socket_ip = request
        .extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip())?;

    let trusted_proxies = current_trusted_proxies();
    let resolved_ip = resolve_client_ip(socket_ip, request, &trusted_proxies);
    Some(resolved_ip.to_string())
}

fn resolve_client_ip(socket_ip: IpAddr, request: &Request, trusted_proxies: &[String]) -> IpAddr {
    if is_trusted_proxy(&socket_ip, trusted_proxies) {
        if let Some(forwarded_ip) = extract_forwarded_ip(request) {
            return forwarded_ip;
        }
    }
    socket_ip
}

fn is_trusted_proxy(socket_ip: &IpAddr, trusted_proxies: &[String]) -> bool {
    trusted_proxies
        .iter()
        .any(|pattern| ip_matches_pattern(socket_ip, pattern))
}

fn ip_matches_pattern(ip: &IpAddr, pattern: &str) -> bool {
    let pattern = pattern.trim();
    if pattern.is_empty() {
        return false;
    }

    if let Ok(exact_ip) = pattern.parse::<IpAddr>() {
        return &exact_ip == ip;
    }

    let Some((network, prefix_str)) = pattern.split_once('/') else {
        return false;
    };

    let Ok(network_ip) = network.trim().parse::<IpAddr>() else {
        return false;
    };
    let Ok(prefix_len) = prefix_str.trim().parse::<u8>() else {
        return false;
    };

    match (*ip, network_ip) {
        (IpAddr::V4(ipv4), IpAddr::V4(netv4)) if prefix_len <= 32 => {
            cidr_bytes_match(&ipv4.octets(), &netv4.octets(), prefix_len, 32)
        }
        (IpAddr::V6(ipv6), IpAddr::V6(netv6)) if prefix_len <= 128 => {
            cidr_bytes_match(&ipv6.octets(), &netv6.octets(), prefix_len, 128)
        }
        _ => false,
    }
}

fn cidr_bytes_match(ip: &[u8], network: &[u8], prefix_len: u8, total_bits: u8) -> bool {
    if prefix_len == 0 {
        return true;
    }
    if prefix_len > total_bits {
        return false;
    }

    let full_bytes = (prefix_len / 8) as usize;
    let remaining_bits = prefix_len % 8;

    if ip.get(..full_bytes) != network.get(..full_bytes) {
        return false;
    }

    if remaining_bits == 0 {
        return true;
    }

    let mask = 0xFFu8 << (8 - remaining_bits);
    let Some(ip_byte) = ip.get(full_bytes) else {
        return false;
    };
    let Some(net_byte) = network.get(full_bytes) else {
        return false;
    };
    (ip_byte & mask) == (net_byte & mask)
}

fn extract_forwarded_ip(request: &Request) -> Option<IpAddr> {
    if let Some(header_value) = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
    {
        for candidate in header_value.split(',') {
            if let Some(ip) = parse_ip_candidate(candidate) {
                return Some(ip);
            }
        }
    }

    request
        .headers()
        .get("x-real-ip")
        .and_then(|value| value.to_str().ok())
        .and_then(parse_ip_candidate)
}

fn parse_ip_candidate(candidate: &str) -> Option<IpAddr> {
    let trimmed = candidate.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Some(ip);
    }

    if let Ok(socket_addr) = trimmed.parse::<SocketAddr>() {
        return Some(socket_addr.ip());
    }

    None
}

#[cfg(test)]
mod tests {
    use super::{current_trusted_proxies, extract_client_ip, set_trusted_proxies};
    use axum::{body::Body, extract::ConnectInfo, http::Request};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::{Mutex, OnceLock};

    fn with_trusted_proxies<F>(trusted_proxies: Vec<String>, test_fn: F)
    where
        F: FnOnce(),
    {
        static TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let _guard = TEST_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("test lock");

        let original = current_trusted_proxies();
        set_trusted_proxies(trusted_proxies);
        test_fn();
        set_trusted_proxies(original);
    }

    #[test]
    fn returns_socket_ip_when_connect_info_present() {
        with_trusted_proxies(vec![], || {
            let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)), 8080);
            let mut req = Request::builder()
                .uri("/v1/messages")
                .body(Body::empty())
                .expect("request build");
            req.extensions_mut().insert(ConnectInfo(socket));

            assert_eq!(extract_client_ip(&req), Some("10.1.2.3".to_string()));
        });
    }

    #[test]
    fn untrusted_proxy_ignores_forwarded_headers() {
        with_trusted_proxies(vec!["10.0.0.0/8".to_string()], || {
            let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 10, 20)), 9000);
            let mut req = Request::builder()
                .uri("/v1/messages")
                .header("x-forwarded-for", "203.0.113.10, 198.51.100.4")
                .header("x-real-ip", "203.0.113.11")
                .body(Body::empty())
                .expect("request build");
            req.extensions_mut().insert(ConnectInfo(socket));

            assert_eq!(extract_client_ip(&req), Some("192.168.10.20".to_string()));
        });
    }

    #[test]
    fn trusted_proxy_uses_forwarded_for_first_valid_ip() {
        with_trusted_proxies(vec!["192.168.10.20".to_string()], || {
            let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 10, 20)), 9000);
            let mut req = Request::builder()
                .uri("/v1/messages")
                .header("x-forwarded-for", "203.0.113.10, 198.51.100.4")
                .header("x-real-ip", "203.0.113.11")
                .body(Body::empty())
                .expect("request build");
            req.extensions_mut().insert(ConnectInfo(socket));

            assert_eq!(extract_client_ip(&req), Some("203.0.113.10".to_string()));
        });
    }

    #[test]
    fn trusted_proxy_cidr_uses_real_ip_header_when_forwarded_for_invalid() {
        with_trusted_proxies(vec!["192.168.10.0/24".to_string()], || {
            let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 10, 20)), 9000);
            let mut req = Request::builder()
                .uri("/v1/messages")
                .header("x-forwarded-for", "not-an-ip")
                .header("x-real-ip", "203.0.113.11")
                .body(Body::empty())
                .expect("request build");
            req.extensions_mut().insert(ConnectInfo(socket));

            assert_eq!(extract_client_ip(&req), Some("203.0.113.11".to_string()));
        });
    }

    #[test]
    fn returns_none_without_connect_info() {
        with_trusted_proxies(vec!["192.168.10.20".to_string()], || {
            let req = Request::builder()
                .uri("/v1/messages")
                .header("x-forwarded-for", "203.0.113.10")
                .body(Body::empty())
                .expect("request build");

            assert_eq!(extract_client_ip(&req), None);
        });
    }
}
