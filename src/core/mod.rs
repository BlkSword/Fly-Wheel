//! 核心功能模块
//!
//! 包含错误处理、配置管理等核心基础设施

pub mod error;
pub mod config;
pub mod adaptive;

pub use error::{FlyWheelError, Result};
