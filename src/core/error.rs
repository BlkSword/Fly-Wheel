//! 统一错误处理模块
//!
//! 定义了整个项目使用的错误类型

use std::io;
use thiserror::Error;
use trust_dns_resolver::error::ResolveError;

/// Fly-Wheel 统一错误类型
#[derive(Error, Debug)]
pub enum FlyWheelError {
    /// 网络相关错误
    #[error("网络错误: {0}")]
    Network(#[from] io::Error),

    /// DNS 解析失败
    #[error("DNS 解析失败: {host}")]
    Dns { host: String },

    /// 连接超时
    #[error("连接超时: {target}")]
    Timeout { target: String },

    /// 权限不足
    #[error("权限不足: {operation}")]
    Permission { operation: String },

    /// 配置错误
    #[error("配置错误: {reason}")]
    Config { reason: String },

    /// 扫描被中断
    #[error("扫描被用户中断")]
    Interrupted,

    /// 序列化错误
    #[error("序列化错误: {0}")]
    Serialization(#[from] serde_json::Error),

    /// HTTP 请求错误
    #[error("HTTP 请求失败: {url}")]
    Http { url: String },

    /// 无效的目标地址
    #[error("无效的目标地址: {target}")]
    InvalidTarget { target: String },

    /// 无效的端口范围
    #[error("无效的端口范围: {range}")]
    InvalidPortRange { range: String },

    /// 原始套接字操作需要管理员权限
    #[error("原始套接字操作需要管理员权限")]
    PrivilegeRequired,

    /// 不支持的操作
    #[error("不支持的操作: {operation}")]
    Unsupported { operation: String },

    /// 其他错误
    #[error("错误: {message}")]
    Other { message: String },
}

/// 项目统一的 Result 类型
pub type Result<T> = std::result::Result<T, FlyWheelError>;

impl From<reqwest::Error> for FlyWheelError {
    fn from(err: reqwest::Error) -> Self {
        FlyWheelError::Http {
            url: err.url().map(|u| u.to_string()).unwrap_or_default(),
        }
    }
}

impl From<ResolveError> for FlyWheelError {
    fn from(err: ResolveError) -> Self {
        FlyWheelError::Dns {
            host: err.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = FlyWheelError::Timeout {
            target: "192.168.1.1:80".to_string(),
        };
        assert_eq!(err.to_string(), "连接超时: 192.168.1.1:80");
    }

    #[test]
    fn test_network_error_conversion() {
        let io_err = io::Error::new(io::ErrorKind::ConnectionRefused, "连接被拒绝");
        let fw_err: FlyWheelError = io_err.into();
        assert!(matches!(fw_err, FlyWheelError::Network(_)));
    }
}
