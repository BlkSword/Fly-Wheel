//! 输出模块
//!
//! 提供美化的终端输出功能

pub mod progress;
pub mod color;

pub use progress::{ScanProgress, LayeredProgress};
pub use color::Color;
