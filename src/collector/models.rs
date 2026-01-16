//! 系统信息收集数据模型
//!
//! 定义模块化的JSON输出结构

use serde::{Deserialize, Serialize};
use crate::modules::collect::{
    SystemInfo, NetworkInterface, RouteEntry, ArpEntry, NetworkConnection,
    ProcessInfo, HashEntry, Token, SshKey, ApiKey, SensitiveFile, ConfigFile
};

/// 系统报告汇总
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemReport {
    /// 元数据
    pub metadata: ReportMetadata,
    /// 系统信息
    pub system: SystemInfo,
    /// 网络信息
    pub network: NetworkReport,
    /// 进程信息
    pub processes: ProcessReport,
    /// 凭据信息
    pub credentials: CredentialReport,
    /// 文件信息
    pub files: FileReport,
}

/// 报告元数据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportMetadata {
    /// 主机名
    pub hostname: String,
    /// 收集时间戳 (ISO 8601)
    pub timestamp: String,
    /// 收集耗时（秒）
    pub collection_duration_secs: f64,
    /// 收集器版本
    pub collector_version: String,
    /// 操作系统类型
    pub os_type: String,
    /// 操作系统架构
    pub arch: String,
}

/// 网络信息报告
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkReport {
    /// 网络接口列表
    pub interfaces: Vec<NetworkInterface>,
    /// 路由表
    pub routes: Vec<RouteEntry>,
    /// ARP表
    pub arp_table: Vec<ArpEntry>,
    /// 网络连接
    pub connections: Vec<NetworkConnection>,
    /// 网络统计
    pub stats: NetworkStats,
}

/// 网络统计信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStats {
    /// 接口数量
    pub interface_count: usize,
    /// 路由条目数
    pub route_count: usize,
    /// ARP条目数
    pub arp_count: usize,
    /// 活动连接数
    pub connection_count: usize,
}

/// 进程信息报告
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessReport {
    /// 进程总数
    pub total_count: usize,
    /// 进程列表（前100个）
    pub processes: Vec<ProcessInfo>,
    /// 可疑进程
    pub suspicious: Vec<ProcessInfo>,
    /// 高CPU使用率进程
    pub high_cpu: Vec<ProcessInfo>,
    /// 高内存使用率进程
    pub high_memory: Vec<ProcessInfo>,
}

/// 凭据信息报告
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialReport {
    /// 密码哈希
    pub password_hashes: Vec<HashEntry>,
    /// 令牌
    pub tokens: Vec<Token>,
    /// SSH密钥
    pub ssh_keys: Vec<SshKey>,
    /// API密钥
    pub api_keys: Vec<ApiKey>,
    /// 统计信息
    pub stats: CredentialStats,
}

/// 凭据统计
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialStats {
    /// 密码哈希数量
    pub hash_count: usize,
    /// 令牌数量
    pub token_count: usize,
    /// SSH密钥数量
    pub ssh_key_count: usize,
    /// API密钥数量
    pub api_key_count: usize,
}

/// 文件信息报告
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileReport {
    /// 敏感文件
    pub sensitive_files: Vec<SensitiveFile>,
    /// 配置文件
    pub config_files: Vec<ConfigFile>,
    /// 最近修改的文件
    pub recent_files: Vec<RecentFile>,
    /// 文件统计
    pub stats: FileStats,
}

/// 最近修改的文件
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecentFile {
    /// 文件路径
    pub path: String,
    /// 文件名
    pub name: String,
    /// 文件大小（字节）
    pub size: u64,
    /// 最后修改时间
    pub modified: String,
    /// 是否为敏感文件
    pub is_sensitive: bool,
}

/// 文件统计
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileStats {
    /// 敏感文件数量
    pub sensitive_count: usize,
    /// 配置文件数量
    pub config_count: usize,
    /// 最近文件数量
    pub recent_count: usize,
    /// 敏感文件总大小（字节）
    pub sensitive_total_size: u64,
}

impl Default for NetworkReport {
    fn default() -> Self {
        Self {
            interfaces: Vec::new(),
            routes: Vec::new(),
            arp_table: Vec::new(),
            connections: Vec::new(),
            stats: NetworkStats {
                interface_count: 0,
                route_count: 0,
                arp_count: 0,
                connection_count: 0,
            },
        }
    }
}

impl Default for ProcessReport {
    fn default() -> Self {
        Self {
            total_count: 0,
            processes: Vec::new(),
            suspicious: Vec::new(),
            high_cpu: Vec::new(),
            high_memory: Vec::new(),
        }
    }
}

impl Default for CredentialReport {
    fn default() -> Self {
        Self {
            password_hashes: Vec::new(),
            tokens: Vec::new(),
            ssh_keys: Vec::new(),
            api_keys: Vec::new(),
            stats: CredentialStats {
                hash_count: 0,
                token_count: 0,
                ssh_key_count: 0,
                api_key_count: 0,
            },
        }
    }
}

impl Default for FileReport {
    fn default() -> Self {
        Self {
            sensitive_files: Vec::new(),
            config_files: Vec::new(),
            recent_files: Vec::new(),
            stats: FileStats {
                sensitive_count: 0,
                config_count: 0,
                recent_count: 0,
                sensitive_total_size: 0,
            },
        }
    }
}

impl NetworkReport {
    /// 更新统计信息
    pub fn update_stats(&mut self) {
        self.stats = NetworkStats {
            interface_count: self.interfaces.len(),
            route_count: self.routes.len(),
            arp_count: self.arp_table.len(),
            connection_count: self.connections.len(),
        };
    }
}

impl CredentialReport {
    /// 更新统计信息
    pub fn update_stats(&mut self) {
        self.stats = CredentialStats {
            hash_count: self.password_hashes.len(),
            token_count: self.tokens.len(),
            ssh_key_count: self.ssh_keys.len(),
            api_key_count: self.api_keys.len(),
        };
    }
}

impl FileReport {
    /// 更新统计信息
    pub fn update_stats(&mut self) {
        self.stats = FileStats {
            sensitive_count: self.sensitive_files.len(),
            config_count: self.config_files.len(),
            recent_count: self.recent_files.len(),
            sensitive_total_size: self.sensitive_files.iter().map(|f| f.size).sum(),
        };
    }
}

impl ProcessReport {
    /// 更新统计信息
    pub fn update_stats(&mut self) {
        // 过滤可疑进程
        self.suspicious = self.processes.iter()
            .filter(|p| is_suspicious_process(p))
            .cloned()
            .collect();

        // 高CPU使用率进程（>50%）
        self.high_cpu = self.processes.iter()
            .filter(|p| p.cpu_usage > 50.0)
            .cloned()
            .collect();

        // 高内存使用率进程（>1GB）
        self.high_memory = self.processes.iter()
            .filter(|p| p.memory_usage > 1024 * 1024 * 1024)
            .cloned()
            .collect();
    }
}

/// 判断是否为可疑进程
fn is_suspicious_process(process: &ProcessInfo) -> bool {
    let suspicious_names = vec![
        "nc", "netcat", "ncat",
        "meterpreter", "metasploit",
        "powershell", "pwsh",
        "cmd.exe", "powershell.exe",
        "python", "perl", "ruby",
    ];

    let name_lower = process.name.to_lowercase();
    suspicious_names.iter().any(|s| name_lower.contains(s))
}
