//! 主机信息收集模块
//!
//! 包含系统、网络、进程、凭据、文件等信息的收集功能

pub mod collect;

pub use collect::system::{SystemCollector, SystemInfo, OsInfo, CurrentUser, PrivilegeLevel, CpuInfo, MemoryInfo, DiskInfo};
pub use collect::network::{NetworkCollector, NetworkInterface, RouteEntry, ArpEntry, NetworkConnection};
pub use collect::process::{ProcessCollector, ProcessInfo, ProcessDetails};
pub use collect::credential::{CredentialCollector, HashEntry, Token, SshKey, ApiKey};
pub use collect::file::{FileCollector, SensitiveFile, ConfigFile, FileMatch};
