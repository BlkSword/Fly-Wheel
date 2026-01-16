//! 统一错误处理模块
//!
//! 定义了整个项目使用的错误类型

use std::io;
use thiserror::Error;

/// Fly-Wheel 统一错误类型
#[derive(Error, Debug)]
pub enum FlyWheelError {
    /// IO 相关错误
    #[error("IO错误: {0}")]
    Io(#[from] io::Error),

    /// 权限不足
    #[error("权限不足: {operation}")]
    Permission { operation: String },

    /// 序列化错误
    #[error("序列化错误: {0}")]
    Serialization(#[from] serde_json::Error),

    /// 不支持的操作
    #[error("不支持的操作: {operation}")]
    Unsupported { operation: String },

    /// 其他错误
    #[error("错误: {message}")]
    Other { message: String },
}

/// 项目统一的 Result 类型
pub type Result<T> = std::result::Result<T, FlyWheelError>;


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = FlyWheelError::Unsupported {
            operation: "test".to_string(),
        };
        assert_eq!(err.to_string(), "不支持的操作: test");
    }

    #[test]
    fn test_network_error_conversion() {
        let io_err = io::Error::new(io::ErrorKind::ConnectionRefused, "连接被拒绝");
        let fw_err: FlyWheelError = io_err.into();
        assert!(matches!(fw_err, FlyWheelError::Io(_)));
    }
}
