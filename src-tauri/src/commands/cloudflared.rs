use crate::modules::cloudflared::{CloudflaredConfig, CloudflaredManager, CloudflaredStatus};
use std::sync::Arc;
use tauri::State;
use tokio::sync::RwLock;

/// Cloudflared服务状态管理
#[derive(Clone)]
pub struct CloudflaredState {
    pub manager: Arc<RwLock<Option<CloudflaredManager>>>,
}

impl CloudflaredState {
    pub fn new() -> Self {
        Self {
            manager: Arc::new(RwLock::new(None)),
        }
    }

    /// 确保管理器已初始化
    pub async fn ensure_manager(&self) -> Result<(), String> {
        let mut lock = self.manager.write().await;
        if lock.is_none() {
            let data_dir = crate::modules::account::get_data_dir()?;
            *lock = Some(CloudflaredManager::new(&data_dir));
        }
        Ok(())
    }

    /// 停止隧道（如果已初始化）
    pub async fn stop(&self) -> Result<Option<CloudflaredStatus>, String> {
        let lock = self.manager.read().await;
        if let Some(manager) = lock.as_ref() {
            let status = manager.stop().await?;
            Ok(Some(status))
        } else {
            Ok(None)
        }
    }
}

/// 检查cloudflared是否已安装
#[tauri::command]
pub async fn cloudflared_check(
    state: State<'_, CloudflaredState>,
) -> Result<CloudflaredStatus, String> {
    state.ensure_manager().await?;

    let lock = state.manager.read().await;
    if let Some(manager) = lock.as_ref() {
        let (installed, version) = manager.check_installed().await;
        Ok(CloudflaredStatus {
            installed,
            version,
            running: false,
            url: None,
            error: None,
        })
    } else {
        Err("Manager not initialized".to_string())
    }
}

/// 安装cloudflared
#[tauri::command]
pub async fn cloudflared_install(
    state: State<'_, CloudflaredState>,
) -> Result<CloudflaredStatus, String> {
    state.ensure_manager().await?;

    let lock = state.manager.read().await;
    if let Some(manager) = lock.as_ref() {
        manager.install().await
    } else {
        Err("Manager not initialized".to_string())
    }
}

/// Refuse to open a public tunnel while the proxy accepts unauthenticated requests.
///
/// cloudflared forwards `https://<random>.trycloudflare.com` to `http://localhost:<port>`.
/// Because the tunnel reaches the proxy over loopback, `allow_lan_access` stays false
/// and `auth_mode: auto` therefore resolves to `Off` — i.e. the tunnel used to publish
/// an entirely unauthenticated gateway to every Google account in the pool, to the
/// whole Internet, with no warning.
///
/// The tunnel itself is untouched; it simply refuses to start until a credential exists.
pub fn ensure_tunnel_auth_configured() -> Result<(), String> {
    let config = crate::modules::config::load_app_config()
        .map_err(|e| format!("Failed to load configuration: {}", e))?;

    let security = crate::proxy::ProxySecurityConfig::from_proxy_config(&config.proxy);

    if matches!(
        security.effective_auth_mode(),
        crate::proxy::ProxyAuthMode::Off
    ) {
        return Err(
            "Refusing to open a public tunnel while proxy authentication is disabled. \
             The tunnel URL is reachable by anyone on the Internet and would expose \
             every account in the pool. Set an API key and switch the authentication \
             mode to 'strict' (or 'all_except_health') first."
                .to_string(),
        );
    }

    let has_api_key = !security.api_key.trim().is_empty();
    let has_admin_password = security
        .admin_password
        .as_ref()
        .map(|p| !p.trim().is_empty())
        .unwrap_or(false);

    if !has_api_key && !has_admin_password {
        return Err(
            "Refusing to open a public tunnel: no API key or admin password is set, \
             so every request would be rejected or unauthenticated. Configure a \
             credential first."
                .to_string(),
        );
    }

    Ok(())
}

/// 启动cloudflared隧道
#[tauri::command]
pub async fn cloudflared_start(
    state: State<'_, CloudflaredState>,
    config: CloudflaredConfig,
) -> Result<CloudflaredStatus, String> {
    ensure_tunnel_auth_configured()?;
    state.ensure_manager().await?;

    let lock = state.manager.read().await;
    if let Some(manager) = lock.as_ref() {
        manager.start(config).await
    } else {
        Err("Manager not initialized".to_string())
    }
}

/// 停止cloudflared隧道
#[tauri::command]
pub async fn cloudflared_stop(
    state: State<'_, CloudflaredState>,
) -> Result<CloudflaredStatus, String> {
    state.ensure_manager().await?;

    let lock = state.manager.read().await;
    if let Some(manager) = lock.as_ref() {
        manager.stop().await
    } else {
        Err("Manager not initialized".to_string())
    }
}

/// 获取cloudflared状态
#[tauri::command]
pub async fn cloudflared_get_status(
    state: State<'_, CloudflaredState>,
) -> Result<CloudflaredStatus, String> {
    state.ensure_manager().await?;

    let lock = state.manager.read().await;
    if let Some(manager) = lock.as_ref() {
        let (installed, version) = manager.check_installed().await;
        let mut status = manager.get_status().await;
        status.installed = installed;
        status.version = version;
        if !installed {
            status.running = false;
            status.url = None;
        }
        Ok(status)
    } else {
        Ok(CloudflaredStatus::default())
    }
}
