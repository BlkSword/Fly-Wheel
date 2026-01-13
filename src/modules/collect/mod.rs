//! 主机信息收集模块
//!
//! 收集系统、网络、进程、凭据等信息

pub mod system;
pub mod network;
pub mod process;
pub mod credential;
pub mod file;

pub use system::{SystemCollector, SystemInfo};
pub use network::{NetworkCollector, NetworkInterface, RouteEntry, ArpEntry, NetworkConnection};
pub use process::{ProcessCollector, ProcessInfo, ProcessDetails};
pub use credential::{CredentialCollector, HashEntry, Token, SshKey, ApiKey};
pub use file::{FileCollector, SensitiveFile, ConfigFile, FileMatch};
