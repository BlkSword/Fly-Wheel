pub mod host;
pub mod info;
pub mod persist;
pub mod scan;

// 服务识别模块
pub mod identify;

// 主机信息收集模块
pub mod collect;

pub use identify::{BannerGrabber, BannerResult, FingerprintMatcher, ServiceInfo, ServiceFingerprint};
pub use collect::system::{SystemCollector, SystemInfo, OsInfo, CurrentUser, PrivilegeLevel, CpuInfo, MemoryInfo, DiskInfo};
pub use collect::network::{NetworkCollector, NetworkInterface, RouteEntry, ArpEntry, NetworkConnection};
pub use collect::process::{ProcessCollector, ProcessInfo, ProcessDetails};
pub use collect::credential::{CredentialCollector, HashEntry, Token, SshKey, ApiKey};
pub use collect::file::{FileCollector, SensitiveFile, ConfigFile, FileMatch};
