use axum::extract::Request;

pub(crate) fn extract_client_ip(request: &Request) -> Option<String> {
    request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|info| info.0.ip().to_string())
}

#[cfg(test)]
mod tests {
    use super::extract_client_ip;
    use axum::{body::Body, extract::ConnectInfo, http::Request};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn returns_socket_ip_when_connect_info_present() {
        let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)), 8080);
        let mut req = Request::builder()
            .uri("/v1/messages")
            .body(Body::empty())
            .expect("request build");
        req.extensions_mut().insert(ConnectInfo(socket));

        assert_eq!(extract_client_ip(&req), Some("10.1.2.3".to_string()));
    }

    #[test]
    fn ignores_forwarded_headers_and_prefers_socket_ip() {
        let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 10, 20)), 9000);
        let mut req = Request::builder()
            .uri("/v1/messages")
            .header("x-forwarded-for", "203.0.113.10, 198.51.100.4")
            .header("x-real-ip", "203.0.113.11")
            .body(Body::empty())
            .expect("request build");
        req.extensions_mut().insert(ConnectInfo(socket));

        assert_eq!(extract_client_ip(&req), Some("192.168.10.20".to_string()));
    }

    #[test]
    fn returns_none_without_connect_info() {
        let req = Request::builder()
            .uri("/v1/messages")
            .header("x-forwarded-for", "203.0.113.10")
            .body(Body::empty())
            .expect("request build");

        assert_eq!(extract_client_ip(&req), None);
    }
}
