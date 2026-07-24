use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{info, warn};

const TEMPLATE_RELOAD_INTERVAL_SECS: u64 = 30;

/// ClientHello 自定义模板热加载：按 mtime 轮询模板文件，
/// 变更时原子替换共享字节并失效模板缓存。
pub fn spawn_template_watcher(path: String, bytes: Arc<RwLock<Option<Vec<u8>>>>) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(TEMPLATE_RELOAD_INTERVAL_SECS));
        ticker.tick().await;
        let mut last_mtime = std::time::SystemTime::UNIX_EPOCH;
        loop {
            ticker.tick().await;
            match tokio::fs::metadata(&path).await {
                Ok(meta) => match meta.modified() {
                    Ok(mtime) if mtime > last_mtime => {
                        last_mtime = mtime;
                        match kanotls_tunnel::templates::load_and_validate_custom_template(&path) {
                            Ok(bytes_new) => {
                                *bytes.write().await = Some(bytes_new);
                                kanotls_tunnel::invalidate_client_hello_template_cache();
                                info!("hot-reloaded ClientHello template from {}", path);
                            }
                            Err(e) => {
                                warn!("hot-reload: failed to parse template {}: {} (keeping previous)", path, e);
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(e) => warn!("hot-reload: failed to read mtime of {}: {}", path, e),
                },
                Err(e) => warn!("hot-reload: failed to stat {}: {}", path, e),
            }
        }
    });
}
