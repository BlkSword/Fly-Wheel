//! 统一错误处理模块
//!
//! 定义了整个项目使用的错误类型

use std::io;
use thiserror::Error;

/// IntraSweep 统一错误类型
#[derive(Error, Debug)]
pub enum IntraSweepError {
    /// IO 相关错误
    #[error("IO错误: {0}")]
    Io(#[from] io::Error),

    /// 权限不足
    #[error("权限不足: {operation}")]
    Permission { operation: String },

    /// 序列化错误
    #[error("序列化错误: {0}")]
    Serialization(#[from] serde_json::Error),

    /// CSV错误
    #[error("CSV错误: {0}")]
    Csv(#[from] csv::Error),

    /// YAML解析错误
    #[error("YAML解析错误: {0}")]
    Yaml(#[from] serde_yaml::Error),

    /// 正则表达式错误
    #[error("正则错误: {0}")]
    Regex(#[from] regex::Error),

    /// PoC规则错误
    #[error("PoC规则错误: {message}")]
    PocRule { message: String },

    /// 不支持的操作
    #[error("不支持的操作: {operation}")]
    Unsupported { operation: String },

    /// 网络连接/监听错误
    #[error("网络错误: {message}")]
    Network { message: String },

    /// 超时错误
    #[error("超时: {operation}")]
    Timeout { operation: String },

    /// 配置/验证错误
    #[error("配置错误: {message}")]
    Config { message: String },

    /// 协议握手/解析错误
    #[error("协议错误: {message}")]
    Protocol { message: String },

    /// 其他错误（兜底，逐步迁移到具体变体）
    #[error("错误: {message}")]
    Other { message: String },
}

impl From<String> for IntraSweepError {
    fn from(s: String) -> Self {
        IntraSweepError::Other { message: s }
    }
}

impl From<&str> for IntraSweepError {
    fn from(s: &str) -> Self {
        IntraSweepError::Other {
            message: s.to_string(),
        }
    }
}

/// 项目统一的 Result 类型
pub type Result<T> = std::result::Result<T, IntraSweepError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = IntraSweepError::Unsupported {
            operation: "test".to_string(),
        };
        assert_eq!(err.to_string(), "不支持的操作: test");
    }

    #[test]
    fn test_network_error_conversion() {
        let io_err = io::Error::new(io::ErrorKind::ConnectionRefused, "连接被拒绝");
        let fw_err: IntraSweepError = io_err.into();
        assert!(matches!(fw_err, IntraSweepError::Io(_)));
    }
}
