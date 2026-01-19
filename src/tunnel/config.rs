//! 隧道配置模块
//!
//! 定义隧道类型和配置结构

use std::net::SocketAddr;
use std::str::FromStr;

/// 隧道类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelType {
    /// 正向隧道 - 本地端口转发到远程目标
    Forward,
    /// 反向隧道 - 远程连接回本地
    Reverse,
    /// SOCKS5 代理
    Socks5,
    /// 链式隧道 - 多级跳板
    Chain,
}

impl TunnelType {
    /// 获取隧道类型的名称
    #[allow(dead_code)]
    pub fn name(&self) -> &'static str {
        match self {
            TunnelType::Forward => "正向隧道",
            TunnelType::Reverse => "反向隧道",
            TunnelType::Socks5 => "SOCKS5代理",
            TunnelType::Chain => "链式隧道",
        }
    }

    /// 获取隧道类型的命令标识
    pub fn as_str(&self) -> &'static str {
        match self {
            TunnelType::Forward => "forward",
            TunnelType::Reverse => "reverse",
            TunnelType::Socks5 => "socks5",
            TunnelType::Chain => "chain",
        }
    }

    /// 从字符串解析隧道类型
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "forward" | "f" | "fo" => Some(TunnelType::Forward),
            "reverse" | "r" | "re" => Some(TunnelType::Reverse),
            "socks5" | "socks" | "s" | "so" => Some(TunnelType::Socks5),
            "chain" | "c" => Some(TunnelType::Chain),
            _ => None,
        }
    }
}

/// 隧道配置
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct TunnelConfig {
    /// 隧道类型
    pub tunnel_type: TunnelType,
    /// 本地监听地址
    pub local_addr: SocketAddr,
    /// 远程目标 (host:port)
    pub remote_target: Option<String>,
    /// 跳板列表
    pub hops: Vec<String>,
    /// 最大并发连接数
    pub max_connections: usize,
    /// 连接超时（秒）
    pub timeout_secs: u64,
    /// 是否记录日志
    pub enable_log: bool,
    /// SOCKS5 认证用户名（可选）
    pub socks5_username: Option<String>,
    /// SOCKS5 认证密码（可选）
    pub socks5_password: Option<String>,
}

impl TunnelConfig {
    /// 创建新的隧道配置
    pub fn new(tunnel_type: TunnelType, local_addr: SocketAddr) -> Self {
        Self {
            tunnel_type,
            local_addr,
            remote_target: None,
            hops: Vec::new(),
            max_connections: 100,
            timeout_secs: 30,
            enable_log: true,
            socks5_username: None,
            socks5_password: None,
        }
    }

    /// 设置远程目标
    pub fn with_remote_target(mut self, target: String) -> Self {
        self.remote_target = Some(target);
        self
    }

    /// 设置跳板列表
    pub fn with_hops(mut self, hops: Vec<String>) -> Self {
        self.hops = hops;
        self
    }

    /// 设置最大并发连接数
    pub fn with_max_connections(mut self, max: usize) -> Self {
        self.max_connections = max;
        self
    }

    /// 设置超时时间
    pub fn with_timeout(mut self, timeout: u64) -> Self {
        self.timeout_secs = timeout;
        self
    }

    /// 启用/禁用日志
    #[allow(dead_code)]
    pub fn with_log(mut self, enable: bool) -> Self {
        self.enable_log = enable;
        self
    }

    /// 设置 SOCKS5 认证
    pub fn with_socks5_auth(mut self, username: String, password: String) -> Self {
        self.socks5_username = Some(username);
        self.socks5_password = Some(password);
        self
    }

    /// 验证配置
    pub fn validate(&self) -> Result<(), String> {
        match self.tunnel_type {
            TunnelType::Forward => {
                if self.remote_target.is_none() {
                    return Err("正向隧道需要指定远程目标 (-t/--target)".to_string());
                }
            }
            TunnelType::Reverse => {
                if self.remote_target.is_none() {
                    return Err("反向隧道需要指定控制端地址 (-t/--target)".to_string());
                }
            }
            TunnelType::Chain => {
                if self.hops.is_empty() {
                    return Err("链式隧道需要至少一个跳板 (-H/--hop)".to_string());
                }
                if self.remote_target.is_none() {
                    return Err("链式隧道需要指定最终目标 (-t/--target)".to_string());
                }
            }
            TunnelType::Socks5 => {
                // SOCKS5 不需要预先指定目标
            }
        }

        Ok(())
    }
}

/// 解析地址字符串为 SocketAddr
#[allow(dead_code)]
pub fn parse_addr(addr: &str, default_port: u16) -> Result<SocketAddr, String> {
    let addr_str = if addr.contains(':') {
        addr.to_string()
    } else {
        format!("{}:{}", addr, default_port)
    };

    SocketAddr::from_str(&addr_str)
        .map_err(|e| format!("无效的地址格式 '{}': {}", addr, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tunnel_type_from_str() {
        assert_eq!(TunnelType::from_str("forward"), Some(TunnelType::Forward));
        assert_eq!(TunnelType::from_str("f"), Some(TunnelType::Forward));
        assert_eq!(TunnelType::from_str("reverse"), Some(TunnelType::Reverse));
        assert_eq!(TunnelType::from_str("socks5"), Some(TunnelType::Socks5));
        assert_eq!(TunnelType::from_str("chain"), Some(TunnelType::Chain));
        assert_eq!(TunnelType::from_str("invalid"), None);
    }

    #[test]
    fn test_tunnel_config_validation() {
        let local: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        // 正向隧道需要远程目标
        let config = TunnelConfig::new(TunnelType::Forward, local);
        assert!(config.validate().is_err());

        let config = config.clone().with_remote_target("192.168.1.100:80".to_string());
        assert!(config.validate().is_ok());

        // 链式隧道需要跳板和目标
        let config = TunnelConfig::new(TunnelType::Chain, local);
        assert!(config.validate().is_err());

        let config = config
            .clone()
            .with_hops(vec!["hop1:2222".to_string()])
            .with_remote_target("target:80".to_string());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_parse_addr() {
        assert!(parse_addr("127.0.0.1:8080", 80).is_ok());
        assert!(parse_addr("127.0.0.1", 80).is_ok());
        assert!(parse_addr("invalid", 80).is_err());
    }
}
