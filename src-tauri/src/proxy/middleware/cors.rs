// CORS 中间件
use axum::http::{HeaderValue, Method};
use tower_http::cors::{Any, CorsLayer};

/// 创建 CORS layer
///
/// CORS is what stops a random web page you happen to visit from talking to the
/// proxy listening on your own machine. Reflecting every origin (the previous
/// behaviour) meant any site could POST to `http://127.0.0.1:<port>/v1/chat/completions`
/// and read the answer — burning your Google quota and running prompts on your
/// account — because in desktop mode the proxy also defaults to no authentication.
///
/// Only the origins explicitly listed in
/// `security_monitor.cors_allowed_origins` are allowed through. Note that this
/// only ever concerns *browsers*: native clients such as Codex, Claude Code,
/// opencode or droid do not perform preflight requests and are unaffected. The
/// desktop UI talks to the backend over Tauri IPC, and the headless Web UI is
/// served from this very origin, so neither needs an entry here.
pub fn cors_layer(allowed_origins: &[String]) -> CorsLayer {
    let layer = CorsLayer::new()
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::HEAD,
            Method::OPTIONS,
            Method::PATCH,
        ])
        .allow_headers(Any)
        .allow_credentials(false)
        .max_age(std::time::Duration::from_secs(3600));

    let entries: Vec<&str> = allowed_origins
        .iter()
        .map(|o| o.trim())
        .filter(|o| !o.is_empty())
        .collect();

    // Explicit, deliberate opt-in to the old allow-any behaviour.
    if entries.iter().any(|o| *o == "*") {
        tracing::warn!(
            "CORS is configured to allow ANY origin ('*'): any website you visit can \
             call this proxy from your browser. Set security_monitor.cors_allowed_origins \
             to the exact origins you need instead."
        );
        return layer.allow_origin(Any);
    }

    let origins: Vec<HeaderValue> = entries
        .iter()
        .filter_map(|o| match HeaderValue::from_str(o) {
            Ok(v) => Some(v),
            Err(_) => {
                tracing::warn!(origin = %o, "Ignoring invalid CORS origin");
                None
            }
        })
        .collect();

    if origins.is_empty() {
        tracing::info!(
            "CORS: no cross-origin browser client allowed (native clients are unaffected)"
        );
        layer
    } else {
        tracing::info!(count = origins.len(), "CORS: allow-list active");
        layer.allow_origin(origins)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cors_layer_creation() {
        // Default posture: nothing configured => no cross-origin browser access.
        let _layer = cors_layer(&[]);

        // A configured origin is accepted.
        let _layer = cors_layer(&["https://chat.example".to_string()]);

        // Blank entries are ignored rather than producing an invalid header.
        let _layer = cors_layer(&["   ".to_string()]);

        // Wildcard remains reachable for users who knowingly want it back.
        let _layer = cors_layer(&["*".to_string()]);
    }
}
