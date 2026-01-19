//! 隧道模块
//!
//! 提供完整的内网穿透隧道功能，包括：
//! - 正向 TCP 端口转发
//! - 反向 TCP 端口转发
//! - SOCKS5 代理
//! - 多级跳板链式隧道

pub mod chain;
pub mod config;
pub mod forward;
pub mod models;
pub mod reverse;
pub mod socks5;

pub use chain::ChainTunnel;
pub use config::{TunnelConfig, TunnelType};
pub use forward::ForwardTunnel;
pub use models::{LogEventHandler, TunnelEventHandler};
pub use reverse::ReverseTunnel;
pub use socks5::Socks5Server;

use std::sync::Arc;

/// 隧道管理器
///
/// 提供统一的接口来创建和管理各种类型的隧道
pub struct TunnelManager {
    event_handler: Arc<dyn TunnelEventHandler>,
}

impl TunnelManager {
    /// 创建新的隧道管理器
    pub fn new() -> Self {
        Self {
            event_handler: Arc::new(LogEventHandler::new(true)),
        }
    }

    /// 设置事件处理器
    #[allow(dead_code)]
    pub fn with_event_handler(mut self, handler: Arc<dyn TunnelEventHandler>) -> Self {
        self.event_handler = handler;
        self
    }

    /// 创建正向隧道
    pub fn create_forward_tunnel(&self, config: TunnelConfig) -> ForwardTunnel {
        ForwardTunnel::new(config, self.event_handler.clone())
    }

    /// 创建反向隧道
    pub fn create_reverse_tunnel(&self, config: TunnelConfig) -> ReverseTunnel {
        ReverseTunnel::new(config, self.event_handler.clone())
    }

    /// 创建 SOCKS5 代理
    pub fn create_socks5_server(&self, config: TunnelConfig) -> Socks5Server {
        Socks5Server::new(config, self.event_handler.clone())
    }

    /// 创建链式隧道
    pub fn create_chain_tunnel(&self, config: TunnelConfig) -> ChainTunnel {
        ChainTunnel::new(config, self.event_handler.clone())
    }
}

impl Default for TunnelManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tunnel_manager_creation() {
        let manager = TunnelManager::new();
        // 测试创建成功
        assert_eq!(Arc::strong_count(&manager.event_handler), 1);
    }

    #[test]
    fn test_tunnel_manager_default() {
        let manager = TunnelManager::default();
        // 测试默认创建成功
        assert_eq!(Arc::strong_count(&manager.event_handler), 1);
    }

    #[test]
    fn test_create_forward_tunnel() {
        let manager = TunnelManager::new();
        let local: std::net::SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let config = TunnelConfig::new(TunnelType::Forward, local)
            .with_remote_target("192.168.1.100:80".to_string());

        let tunnel = manager.create_forward_tunnel(config);
        // 测试隧道创建成功
        assert_eq!(
            tunnel.config.remote_target,
            Some("192.168.1.100:80".to_string())
        );
    }

    #[test]
    fn test_create_reverse_tunnel() {
        let manager = TunnelManager::new();
        let local: std::net::SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let config = TunnelConfig::new(TunnelType::Reverse, local)
            .with_remote_target("control.example.com:9999".to_string());

        let tunnel = manager.create_reverse_tunnel(config);
        // 测试隧道创建成功
        assert_eq!(
            tunnel.config.remote_target,
            Some("control.example.com:9999".to_string())
        );
    }

    #[test]
    fn test_create_socks5_server() {
        let manager = TunnelManager::new();
        let local: std::net::SocketAddr = "127.0.0.1:1080".parse().unwrap();
        let config = TunnelConfig::new(TunnelType::Socks5, local);

        let server = manager.create_socks5_server(config);
        // 测试服务器创建成功
        assert_eq!(server.config.tunnel_type, TunnelType::Socks5);
    }

    #[test]
    fn test_create_chain_tunnel() {
        let manager = TunnelManager::new();
        let local: std::net::SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let config = TunnelConfig::new(TunnelType::Chain, local)
            .with_hops(vec!["hop1:2222".to_string()])
            .with_remote_target("target:80".to_string());

        let tunnel = manager.create_chain_tunnel(config);
        // 测试隧道创建成功
        assert_eq!(tunnel.config.hops.len(), 1);
    }
}
