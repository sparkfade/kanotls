pub mod client;
pub mod model;
pub mod script;
pub mod server;
mod shared;

pub use model::*;
pub use shared::find_routing_rule;

/// 受支持的 tls.fingerprint 取值名单（config 校验、tunnel 解析、错误信息共用，
/// 避免多处字符串表漂移）。
pub const SUPPORTED_TLS_FINGERPRINTS: &[&str] = &["firefox", "rustls", "python-openssl", "baseline"];

/// 归一化 fingerprint 名称：trim + 小写后映射到族名（`baseline` 是
/// `python-openssl` 的别名）；不支持的值返回 None。
pub fn normalize_tls_fingerprint(name: &str) -> Option<&'static str> {
    match name.trim().to_ascii_lowercase().as_str() {
        "firefox" => Some("firefox"),
        "rustls" => Some("rustls"),
        "python-openssl" | "baseline" => Some("python-openssl"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn normalize_tls_fingerprint_maps_aliases_and_rejects_unknown() {
        assert_eq!(super::normalize_tls_fingerprint("Firefox"), Some("firefox"));
        assert_eq!(super::normalize_tls_fingerprint(" rustls "), Some("rustls"));
        assert_eq!(
            super::normalize_tls_fingerprint("python-openssl"),
            Some("python-openssl")
        );
        assert_eq!(
            super::normalize_tls_fingerprint("baseline"),
            Some("python-openssl")
        );
        assert_eq!(super::normalize_tls_fingerprint("chrome"), None);
        assert!(super::SUPPORTED_TLS_FINGERPRINTS.contains(&"baseline"));
    }
}
