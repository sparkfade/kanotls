//! 带 TTL 的解析缓存。
//!
//! `tokio::net::lookup_host` 每次调用都要 `spawn_blocking` 进 `getaddrinfo`，
//! 而 glibc 默认**不缓存**（除非部署了 nscd / systemd-resolved）。代理的每
//! 条到域名目标的流都会走一次，浏览器对同一域名开 6 条连接就是 6 次系统
//! 解析——对域名目标而言这通常是首要的每连接延迟来源。
//!
//! 本模块只缓存**原始解析结果**，不做任何目的地过滤：不同调用方的放行
//! 策略不同（代理出站用 [`crate::target::is_blocked_destination`]，伪装
//! 端点用另一套私有地址判定），过滤必须留在调用方，否则会把某一方的策略
//! 悄悄套到另一方头上。

use lru::LruCache;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// 条目存活时间。`getaddrinfo` 不暴露记录的真实 TTL，因此取一个足够短、
/// 不会明显滞后于 DNS 变更，又足以覆盖一次页面加载的固定值。
const DNS_CACHE_TTL: Duration = Duration::from_secs(30);
const DNS_CACHE_ENTRIES: usize = 4096;

struct CacheEntry {
    addrs: Arc<[SocketAddr]>,
    expires_at: Instant,
}

fn cache() -> &'static Mutex<LruCache<String, CacheEntry>> {
    static CACHE: OnceLock<Mutex<LruCache<String, CacheEntry>>> = OnceLock::new();
    CACHE.get_or_init(|| {
        Mutex::new(LruCache::new(
            NonZeroUsize::new(DNS_CACHE_ENTRIES).expect("non-zero dns cache size"),
        ))
    })
}

/// 解析 `host:port`，命中未过期缓存时直接返回。
///
/// 返回全部地址（顺序保持 `getaddrinfo` 的 RFC 6724 排序），由调用方过滤
/// 并按序尝试——只取第一个会让一个不可达的首地址拖满整个连接超时。
///
/// 失败不写入缓存：负缓存会把一次瞬时解析故障放大成 TTL 长度的持续故障。
pub async fn resolve(host: &str, port: u16) -> std::io::Result<Arc<[SocketAddr]>> {
    let key = format!("{}:{}", host, port);

    if let Some(hit) = lookup(&key) {
        return Ok(hit);
    }

    let addrs: Arc<[SocketAddr]> = tokio::net::lookup_host((host, port))
        .await?
        .collect::<Vec<_>>()
        .into();

    if !addrs.is_empty() {
        store(key, addrs.clone());
    }
    Ok(addrs)
}

fn lookup(key: &str) -> Option<Arc<[SocketAddr]>> {
    // 锁内不跨 await，临界区只有一次 LRU 查找。
    let mut cache = cache().lock().ok()?;
    let entry = cache.get(key)?;
    if entry.expires_at <= Instant::now() {
        cache.pop(key);
        return None;
    }
    Some(entry.addrs.clone())
}

fn store(key: String, addrs: Arc<[SocketAddr]>) {
    let Ok(mut cache) = cache().lock() else {
        return;
    };
    cache.put(
        key,
        CacheEntry {
            addrs,
            expires_at: Instant::now() + DNS_CACHE_TTL,
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    // 缓存是进程级共享的，而同一测试二进制内的用例并发执行——因此每个
    // 用例使用互不相同的端口作为键，不做全局清空（清空会互相踩踏）。

    #[tokio::test]
    async fn resolves_literals_and_serves_repeat_lookups_from_cache() {
        let first = resolve("127.0.0.1", 18080).await.unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0], "127.0.0.1:18080".parse::<SocketAddr>().unwrap());

        // 第二次必须命中缓存：返回同一个 Arc 分配。
        let second = resolve("127.0.0.1", 18080).await.unwrap();
        assert!(Arc::ptr_eq(&first, &second));
    }

    #[tokio::test]
    async fn port_is_part_of_the_cache_key() {
        let a = resolve("127.0.0.1", 18001).await.unwrap();
        let b = resolve("127.0.0.1", 18002).await.unwrap();
        assert_eq!(a[0].port(), 18001);
        assert_eq!(b[0].port(), 18002);
    }

    #[tokio::test]
    async fn expired_entries_are_refetched() {
        let first = resolve("127.0.0.1", 19999).await.unwrap();
        // 手工把条目置为已过期，模拟 TTL 到期。
        {
            let mut cache = cache().lock().unwrap();
            let entry = cache.get_mut("127.0.0.1:19999").unwrap();
            entry.expires_at = Instant::now() - Duration::from_secs(1);
        }
        let second = resolve("127.0.0.1", 19999).await.unwrap();
        assert!(
            !Arc::ptr_eq(&first, &second),
            "an expired entry must trigger a fresh lookup"
        );
        assert_eq!(first[0], second[0]);
    }

    #[tokio::test]
    async fn failed_lookups_are_not_cached() {
        // RFC 6761 保证 .invalid 不可解析。但部分环境（强制门户、运营商
        // NXDOMAIN 劫持、隔离沙箱）会为任意名字返回伪造地址；那种环境下
        // 无从构造一次失败解析，跳过即可，不要给出假阳性。
        let bad = "nonexistent.invalid";
        let key = format!("{}:443", bad);
        match resolve(bad, 443).await {
            Err(_) => {
                let cache = cache().lock().unwrap();
                assert!(
                    cache.peek(&key).is_none(),
                    "negative results must not be cached — that would turn a transient \
                     resolver failure into a TTL-long outage"
                );
            }
            Ok(addrs) => eprintln!(
                "skipping: this environment's resolver hijacks {} -> {:?}",
                bad, addrs
            ),
        }
    }
}
