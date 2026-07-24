//! 客户端隧道连接池：按浏览器行为节奏调度一组多路复用会话，
//! 向上层提供 `open_stream` 取流能力。
//!
//! 本 crate 属于资源调度层：不感知底层隧道如何建立，
//! 由装配层注入实现 [`TunnelConnector`] 的连接工厂。

mod behavior;
mod connection;
mod pool;

pub use behavior::{PoolBehaviorConfig, PoolBehaviorContext};
pub use pool::ClientPool;

use futures::future::BoxFuture;
use kanotls_session::Stream;
use std::sync::Arc;

/// 隧道连接工厂：由装配层实现，封装一次底层隧道握手 + 会话创建。
pub trait TunnelConnector: Send + Sync + 'static {
    type Session: PoolSession;

    fn connect(&self) -> BoxFuture<'_, Result<Arc<Self::Session>, anyhow::Error>>;
}

/// 池化会话抽象：连接池据此做负载选择与生命周期判定。
pub trait PoolSession: Send + Sync {
    fn open_stream(&self) -> BoxFuture<'_, Result<Stream, anyhow::Error>>;
    fn active_streams(&self) -> usize;
    fn buffered_stream_bytes(&self) -> usize;
    fn is_alive(&self) -> bool;
    fn is_closing(&self) -> bool;
    fn force_close(&self);
}
