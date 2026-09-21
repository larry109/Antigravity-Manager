use crate::modules::security_db;
use crate::proxy::server::AppState;
use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};

/// IP 黑白名单过滤中间件
pub async fn ip_filter_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    // 读取安全配置（必须先于 IP 提取：是否信任 XFF 取决于 trusted_proxies）
    // 立即克隆并释放读锁，避免在整个请求（含长流式响应）期间持有锁而阻塞配置热更新
    let security_config = {
        let guard = state.security.read().await;
        guard.security_monitor.clone()
    };

    // 提取客户端 IP
    let client_ip = extract_client_ip_with_trust(&request, &security_config.trusted_proxies);

    if let Some(ip) = &client_ip {
        // 1. 检查白名单 (如果启用白名单模式,只允许白名单 IP)
        if security_config.whitelist.enabled {
            match security_db::is_ip_in_whitelist(ip) {
                Ok(true) => {
                    // 在白名单中,直接放行
                    tracing::debug!("[IP Filter] IP {} is in whitelist, allowing", ip);
                    return next.run(request).await;
                }
                Ok(false) => {
                    // 不在白名单中,且启用了白名单模式,拒绝访问
                    tracing::warn!("[IP Filter] IP {} not in whitelist, blocking", ip);
                    return create_blocked_response(
                        ip,
                        "Access denied. Your IP is not in the whitelist.",
                    );
                }
                Err(e) => {
                    tracing::error!("[IP Filter] Failed to check whitelist: {}", e);
                }
            }
        } else {
            // 白名单优先模式: 如果在白名单中,跳过黑名单检查
            if security_config.whitelist.whitelist_priority {
                match security_db::is_ip_in_whitelist(ip) {
                    Ok(true) => {
                        tracing::debug!("[IP Filter] IP {} is in whitelist (priority mode), skipping blacklist check", ip);
                        return next.run(request).await;
                    }
                    Ok(false) => {
                        // 继续检查黑名单
                    }
                    Err(e) => {
                        tracing::error!("[IP Filter] Failed to check whitelist: {}", e);
                    }
                }
            }
        }

        // 2. 检查黑名单
        if security_config.blacklist.enabled {
            match security_db::get_blacklist_entry_for_ip(ip) {
                Ok(Some(entry)) => {
                    tracing::warn!("[IP Filter] IP {} is in blacklist, blocking", ip);

                    // 构建详细的封禁消息
                    let reason = entry
                        .reason
                        .as_deref()
                        .unwrap_or("Malicious activity detected");
                    let ban_type = if let Some(expires_at) = entry.expires_at {
                        let now = chrono::Utc::now().timestamp();
                        let remaining_seconds = expires_at - now;

                        if remaining_seconds > 0 {
                            let hours = remaining_seconds / 3600;
                            let minutes = (remaining_seconds % 3600) / 60;

                            if hours > 24 {
                                let days = hours / 24;
                                format!("Temporary ban. Please try again after {} day(s).", days)
                            } else if hours > 0 {
                                format!("Temporary ban. Please try again after {} hour(s) and {} minute(s).", hours, minutes)
                            } else {
                                format!(
                                    "Temporary ban. Please try again after {} minute(s).",
                                    minutes
                                )
                            }
                        } else {
                            "Temporary ban (expired, will be removed soon).".to_string()
                        }
                    } else {
                        "Permanent ban.".to_string()
                    };

                    let detailed_message =
                        format!("Access denied. Reason: {}. {}", reason, ban_type);

                    // 记录被封禁的访问日志
                    let log = security_db::IpAccessLog {
                        id: uuid::Uuid::new_v4().to_string(),
                        client_ip: ip.clone(),
                        timestamp: chrono::Utc::now().timestamp(),
                        method: Some(request.method().to_string()),
                        path: Some(request.uri().to_string()),
                        user_agent: request
                            .headers()
                            .get("user-agent")
                            .and_then(|v| v.to_str().ok())
                            .map(|s| s.to_string()),
                        status: Some(403),
                        duration: Some(0),
                        api_key_hash: None,
                        blocked: true,
                        block_reason: Some(format!("IP in blacklist: {}", reason)),
                        username: None,
                    };

                    tokio::spawn(async move {
                        if let Err(e) = security_db::save_ip_access_log(&log) {
                            tracing::error!("[IP Filter] Failed to save blocked access log: {}", e);
                        }
                    });

                    return create_blocked_response(ip, &detailed_message);
                }
                Ok(None) => {
                    // 不在黑名单中,放行
                    tracing::debug!("[IP Filter] IP {} not in blacklist, allowing", ip);
                }
                Err(e) => {
                    tracing::error!("[IP Filter] Failed to check blacklist: {}", e);
                }
            }
        }
    } else {
        tracing::warn!("[IP Filter] Unable to extract client IP from request");
    }

    // 放行请求
    next.run(request).await
}

/// 规范化 IP 地址字符串：
/// - 清理首尾空格及方括号 `[...]`
/// - 剥离客户端端口（例如 `192.168.1.1:54321` 或 `[2409:8a55::1]:8046`）
/// - 将 IPv4 映射的 IPv6 地址（如 `::ffff:192.168.1.1`）还原为原生 IPv4（`192.168.1.1`）
pub fn normalize_ip_str(raw: &str) -> String {
    let trimmed = raw.trim();

    // 优先尝试直接按 IP 地址解析
    let clean = trimmed.trim_matches('[').trim_matches(']');
    if let Ok(ip) = clean.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V6(v6) => {
                if let Some(v4) = v6.to_ipv4_mapped() {
                    v4.to_string()
                } else {
                    v6.to_string()
                }
            }
            std::net::IpAddr::V4(v4) => v4.to_string(),
        };
    }

    // 若带有端口（如 192.168.1.100:12345 或 [::1]:8080），尝试解析为 SocketAddr
    if let Ok(socket_addr) = trimmed.parse::<std::net::SocketAddr>() {
        return match socket_addr.ip() {
            std::net::IpAddr::V6(v6) => {
                if let Some(v4) = v6.to_ipv4_mapped() {
                    v4.to_string()
                } else {
                    v6.to_string()
                }
            }
            std::net::IpAddr::V4(v4) => v4.to_string(),
        };
    }

    // 手动前缀回退检测
    if let Some(stripped) = clean.strip_prefix("::ffff:") {
        if stripped.parse::<std::net::Ipv4Addr>().is_ok() {
            return stripped.to_string();
        }
    }

    clean.to_string()
}

/// 从请求中提取 TCP 连接对端 IP（ConnectInfo），不受任何请求头影响
pub fn extract_peer_ip(request: &Request) -> Option<String> {
    request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|info| match info.0.ip() {
            std::net::IpAddr::V6(v6) => {
                if let Some(v4) = v6.to_ipv4_mapped() {
                    v4.to_string()
                } else {
                    v6.to_string()
                }
            }
            std::net::IpAddr::V4(v4) => v4.to_string(),
        })
}

/// 判断对端是否为本机回环地址
pub fn is_loopback_peer(request: &Request) -> bool {
    request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|info| info.0.ip().is_loopback())
        .unwrap_or(false)
}

/// 从请求中提取客户端 IP，并自动规范化 IPv4/IPv6。
///
/// `X-Forwarded-For` / `X-Real-IP` are attacker-controlled: they are only consulted
/// when the request actually arrives from one of the reverse proxies listed in
/// `security_monitor.trusted_proxies`. Trusting them unconditionally let any client
/// pick its own IP and thereby walk past the blacklist, the whitelist and the
/// per-token IP binding, while poisoning the security logs at the same time.
///
/// When `trusted_proxies` is empty (the default) the peer address of the TCP
/// connection is the only thing that counts.
pub fn extract_client_ip_with_trust(
    request: &Request,
    trusted_proxies: &[String],
) -> Option<String> {
    let peer = extract_peer_ip(request);

    let peer_is_trusted = match peer.as_deref() {
        Some(p) => trusted_proxies
            .iter()
            .map(|t| normalize_ip_str(t))
            .any(|t| !t.is_empty() && t == p),
        None => false,
    };

    if peer_is_trusted {
        // 1. 优先从 X-Forwarded-For 提取 (取第一个 IP)
        let raw = request
            .headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.split(',').next().unwrap_or(s).trim())
            .or_else(|| {
                // 2. 备选从 X-Real-IP 提取
                request
                    .headers()
                    .get("x-real-ip")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.trim())
            });

        if let Some(ip_str) = raw {
            if !ip_str.is_empty() {
                return Some(normalize_ip_str(ip_str));
            }
        }
    } else if peer.is_some()
        && (request.headers().contains_key("x-forwarded-for")
            || request.headers().contains_key("x-real-ip"))
    {
        tracing::debug!(
            peer = ?peer,
            "Ignoring X-Forwarded-For/X-Real-IP from an untrusted peer; \
             add it to security_monitor.trusted_proxies if it is your reverse proxy"
        );
    }

    // 3. 回退到 TCP 连接对端 IP
    peer
}

/// 创建被封禁的响应
fn create_blocked_response(ip: &str, message: &str) -> Response {
    let body = serde_json::json!({
        "error": {
            "message": message,
            "type": "ip_blocked",
            "code": "ip_blocked",
            "ip": ip,
        }
    });

    (
        StatusCode::FORBIDDEN,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        serde_json::to_string(&body).unwrap_or_else(|_| message.to_string()),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_ip_str() {
        assert_eq!(normalize_ip_str("192.168.1.1"), "192.168.1.1");
        assert_eq!(normalize_ip_str("192.168.1.1:8080"), "192.168.1.1");
        assert_eq!(normalize_ip_str("::ffff:192.168.1.1"), "192.168.1.1");
        assert_eq!(normalize_ip_str("[::ffff:192.168.1.1]:8046"), "192.168.1.1");
        assert_eq!(normalize_ip_str("::1"), "::1");
        assert_eq!(normalize_ip_str("[::1]:8046"), "::1");
        assert_eq!(
            normalize_ip_str("2409:8a55:a21:2e60:2e2:69ff:fe17:95cb"),
            "2409:8a55:a21:2e60:2e2:69ff:fe17:95cb"
        );
    }

    fn request_from(peer: &str, forwarded: Option<&str>) -> Request {
        let mut builder = Request::builder().uri("/v1/models");
        if let Some(f) = forwarded {
            builder = builder.header("x-forwarded-for", f);
        }
        let mut req = builder.body(axum::body::Body::empty()).unwrap();
        let addr: std::net::SocketAddr = peer.parse().unwrap();
        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(addr));
        req
    }

    #[test]
    fn xff_is_ignored_when_no_trusted_proxy_is_configured() {
        // The whole point: a client must not be able to pick its own IP.
        let req = request_from("203.0.113.7:51000", Some("1.2.3.4"));
        assert_eq!(
            extract_client_ip_with_trust(&req, &[]),
            Some("203.0.113.7".to_string())
        );
    }

    #[test]
    fn xff_is_ignored_when_peer_is_not_trusted() {
        let req = request_from("203.0.113.7:51000", Some("1.2.3.4"));
        let trusted = vec!["127.0.0.1".to_string()];
        assert_eq!(
            extract_client_ip_with_trust(&req, &trusted),
            Some("203.0.113.7".to_string())
        );
    }

    #[test]
    fn xff_is_honoured_from_a_trusted_proxy() {
        let req = request_from("127.0.0.1:51000", Some("1.2.3.4"));
        let trusted = vec!["127.0.0.1".to_string()];
        assert_eq!(
            extract_client_ip_with_trust(&req, &trusted),
            Some("1.2.3.4".to_string())
        );
    }

    #[test]
    fn first_hop_of_a_forwarded_chain_is_used() {
        let req = request_from("127.0.0.1:51000", Some("1.2.3.4, 10.0.0.1, 10.0.0.2"));
        let trusted = vec!["127.0.0.1".to_string()];
        assert_eq!(
            extract_client_ip_with_trust(&req, &trusted),
            Some("1.2.3.4".to_string())
        );
    }

    #[test]
    fn peer_is_used_when_trusted_proxy_sends_no_forwarding_header() {
        let req = request_from("127.0.0.1:51000", None);
        let trusted = vec!["127.0.0.1".to_string()];
        assert_eq!(
            extract_client_ip_with_trust(&req, &trusted),
            Some("127.0.0.1".to_string())
        );
    }

    #[test]
    fn trusted_proxy_entries_are_normalised_before_comparison() {
        // IPv4-mapped IPv6 peer vs. plain IPv4 entry in the config.
        let req = request_from("[::ffff:127.0.0.1]:51000", Some("1.2.3.4"));
        let trusted = vec!["  127.0.0.1  ".to_string()];
        assert_eq!(
            extract_client_ip_with_trust(&req, &trusted),
            Some("1.2.3.4".to_string())
        );
    }

    #[test]
    fn loopback_peer_is_detected() {
        assert!(is_loopback_peer(&request_from("127.0.0.1:51000", None)));
        assert!(is_loopback_peer(&request_from("[::1]:51000", None)));
        assert!(!is_loopback_peer(&request_from("203.0.113.7:51000", None)));
    }
}
