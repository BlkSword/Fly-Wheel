//! 主机信息收集模块
//!
//! 收集系统、网络、进程、凭据等信息

pub mod credential;
pub mod file;
pub mod network;
pub mod process;
pub mod system;

pub use credential::{
    ApiKey, CredentialCollector, HashEntry, KnownHost, RemoteSession, SshKey, Token,
};
pub use file::{ConfigFile, FileCollector, SensitiveFile};
pub use network::{ArpEntry, NetworkCollector, NetworkConnection, NetworkInterface, RouteEntry};
pub use process::{ProcessCollector, ProcessInfo};
pub use system::{SystemCollector, SystemInfo};
