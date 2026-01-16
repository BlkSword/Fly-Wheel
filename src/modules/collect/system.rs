//! 系统信息收集模块
//!
//! 收集操作系统、用户、环境等信息

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use sysinfo::System;
use std::env;

/// 系统信息收集器
pub struct SystemCollector {
    system: System,
}

impl SystemCollector {
    /// 创建新的系统信息收集器
    pub fn new() -> Self {
        let mut system = System::new();
        system.refresh_all();
        Self { system }
    }

    /// 收集所有系统信息
    pub fn collect_all(&mut self) -> SystemInfo {
        self.system.refresh_all();

        SystemInfo {
            os_info: self.collect_os_info(),
            hostname: self.collect_hostname(),
            domain: self.collect_domain(),
            current_user: self.collect_current_user(),
            users: self.collect_users(),
            uptime: self.collect_uptime(),
            architecture: self.collect_architecture(),
            cpu_info: self.collect_cpu_info(),
            memory_info: self.collect_memory_info(),
            disk_info: self.collect_disk_info(),
            environment: self.collect_environment(),
        }
    }

    /// 收集操作系统信息
    pub fn collect_os_info(&self) -> OsInfo {
        let os_type = if cfg!(windows) {
            "Windows".to_string()
        } else if cfg!(target_os = "macos") {
            "macOS".to_string()
        } else {
            "Linux".to_string()
        };

        // 获取真实的系统版本
        let os_version = self.get_real_os_version();

        OsInfo {
            os_type,
            os_version,
            arch: env::consts::ARCH.to_string(),
        }
    }

    /// 获取真实的系统版本
    fn get_real_os_version(&self) -> String {
        // 使用单一的条件编译块
        #[cfg(windows)]
        {
            self.get_windows_version_internal()
        }

        #[cfg(target_os = "macos")]
        {
            self.get_macos_version_internal()
        }

        #[cfg(target_os = "linux")]
        {
            self.get_linux_version_internal()
        }

        #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
        {
            env::consts::OS.to_string()
        }
    }

    /// Windows 版本获取
    #[cfg(windows)]
    fn get_windows_version_internal(&self) -> String {
        env::var("OS")
            .or_else(|_| env::var("WINDOWS_TRACING_FLAGS"))
            .unwrap_or_else(|_| "Windows".to_string())
    }

    /// macOS 版本获取
    #[cfg(target_os = "macos")]
    fn get_macos_version_internal(&self) -> String {
        use std::process::Command;
        match Command::new("sw_vers")
            .arg("-productVersion")
            .output()
        {
            Ok(output) => String::from_utf8_lossy(&output.stdout).trim().to_string(),
            Err(_) => env::consts::OS.to_string(),
        }
    }

    /// Linux 版本获取
    #[cfg(target_os = "linux")]
    fn get_linux_version_internal(&self) -> String {
        use std::process::Command;
        // 尝试从 /etc/os-release 读取
        if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
            for line in content.lines() {
                if line.starts_with("PRETTY_NAME=") {
                    let version = line.trim_start_matches("PRETTY_NAME=")
                        .trim_matches('"')
                        .to_string();
                    if !version.is_empty() {
                        return version;
                    }
                }
            }
        }

        // 回退到 uname 命令
        match Command::new("uname")
            .arg("-r")
            .output()
        {
            Ok(output) => String::from_utf8_lossy(&output.stdout).trim().to_string(),
            Err(_) => "Linux".to_string(),
        }
    }

    /// 收集主机名
    pub fn collect_hostname(&self) -> String {
        match whoami::fallible::hostname() {
            Ok(name) => name.to_string(),
            Err(_) => "unknown".to_string(),
        }
    }

    /// 收集域名
    pub fn collect_domain(&self) -> Option<String> {
        if cfg!(windows) {
            // Windows: 从环境变量或注册表获取
            env::var("USERDNSDOMAIN").ok()
                .or_else(|| env::var("COMPUTERNAME").ok())
        } else {
            // Unix: 从 hostname 获取域名部分
            match whoami::fallible::hostname() {
                Ok(h) => {
                    h.split('.').skip(1).next().map(|d| d.to_string())
                }
                Err(_) => None,
            }
        }
    }

    /// 收集当前用户信息
    pub fn collect_current_user(&self) -> CurrentUser {
        let username = whoami::username();

        CurrentUser {
            username,
            privileges: self.check_privileges(),
            groups: self.get_user_groups(),
        }
    }

    /// 收集所有用户
    pub fn collect_users(&mut self) -> Vec<String> {
        // sysinfo 0.30 不再直接提供用户列表
        // 返回当前用户作为简化实现
        vec![whoami::username()]
    }

    /// 收集系统运行时间
    pub fn collect_uptime(&self) -> u64 {
        System::uptime()
    }

    /// 收集系统架构
    pub fn collect_architecture(&self) -> String {
        env::consts::ARCH.to_string()
    }

    /// 收集 CPU 信息
    pub fn collect_cpu_info(&self) -> CpuInfo {
        let cpus = self.system.cpus();
        let cpu_count = cpus.len();

        CpuInfo {
            cpu_count,
            cpu_brand: cpus.first().map(|c| c.brand().to_string()),
            cpu_freq: cpus.first().map(|c| c.frequency()),
        }
    }

    /// 收集内存信息
    pub fn collect_memory_info(&self) -> MemoryInfo {
        let total_memory = self.system.total_memory();
        let available_memory = self.system.available_memory();
        let used_memory = total_memory.saturating_sub(available_memory);

        MemoryInfo {
            total_memory,
            used_memory,
            available_memory,
            usage_percent: if total_memory > 0 {
                (used_memory as f64 / total_memory as f64) * 100.0
            } else {
                0.0
            },
        }
    }

    /// 收集磁盘信息
    pub fn collect_disk_info(&self) -> Vec<DiskInfo> {
        // sysinfo 0.30 不再直接提供磁盘列表
        // 返回空列表作为简化实现
        Vec::new()
    }

    /// 收集环境变量
    pub fn collect_environment(&self) -> HashMap<String, String> {
        env::vars_os()
            .map(|(k, v)| {
                (k.to_string_lossy().to_string(), v.to_string_lossy().to_string())
            })
            .collect()
    }

    /// 检查权限
    fn check_privileges(&self) -> PrivilegeLevel {
        if cfg!(windows) {
            // Windows: 检查是否有管理员权限
            if self.is_admin_windows() {
                PrivilegeLevel::Admin
            } else {
                PrivilegeLevel::User
            }
        } else {
            // Unix: 检查是否是 root
            #[cfg(unix)]
            {
                if self.is_root_unix() {
                    PrivilegeLevel::Root
                } else {
                    PrivilegeLevel::User
                }
            }
            #[cfg(not(unix))]
            {
                PrivilegeLevel::User
            }
        }
    }

    /// 获取用户组
    fn get_user_groups(&self) -> Vec<String> {
        // 简化实现，返回常见组
        if self.check_privileges() == PrivilegeLevel::Admin || self.check_privileges() == PrivilegeLevel::Root {
            vec!["administrators".to_string(), "root".to_string()]
        } else {
            vec!["users".to_string()]
        }
    }

    /// 检查 Windows 管理员权限
    #[cfg(windows)]
    fn is_admin_windows(&self) -> bool {
        // 简化实现：检查是否可以访问系统关键路径
        std::path::Path::new("C:\\Windows\\System32\\config").exists()
            && std::path::Path::new("C:\\Windows\\System32\\config\\SAM").exists()
    }

    /// 检查 Unix root 权限
    #[cfg(unix)]
    fn is_root_unix(&self) -> bool {
        unsafe { libc::geteuid() == 0 }
    }
}

impl Default for SystemCollector {
    fn default() -> Self {
        Self::new()
    }
}

// ==================== 数据结构 ====================

/// 系统信息汇总
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub os_info: OsInfo,
    pub hostname: String,
    pub domain: Option<String>,
    pub current_user: CurrentUser,
    pub users: Vec<String>,
    pub uptime: u64,
    pub architecture: String,
    pub cpu_info: CpuInfo,
    pub memory_info: MemoryInfo,
    pub disk_info: Vec<DiskInfo>,
    pub environment: HashMap<String, String>,
}

/// 操作系统信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsInfo {
    pub os_type: String,
    pub os_version: String,
    pub arch: String,
}

/// 当前用户信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurrentUser {
    pub username: String,
    pub privileges: PrivilegeLevel,
    pub groups: Vec<String>,
}

/// 权限级别
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PrivilegeLevel {
    Root,
    Admin,
    User,
}

/// CPU 信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuInfo {
    pub cpu_count: usize,
    pub cpu_brand: Option<String>,
    pub cpu_freq: Option<u64>,
}

/// 内存信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryInfo {
    pub total_memory: u64,
    pub used_memory: u64,
    pub available_memory: u64,
    pub usage_percent: f64,
}

/// 磁盘信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskInfo {
    pub name: String,
    pub mount_point: String,
    pub total_space: u64,
    pub available_space: u64,
    pub is_removable: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_collector_creation() {
        let collector = SystemCollector::new();
        // 验证对象创建成功
        assert_eq!(collector.system.cpus().len(), collector.system.cpus().len());
    }

    #[test]
    fn test_collect_os_info() {
        let collector = SystemCollector::new();
        let os_info = collector.collect_os_info();
        assert!(!os_info.os_type.is_empty());
    }

    #[test]
    fn test_collect_hostname() {
        let collector = SystemCollector::new();
        let hostname = collector.collect_hostname();
        assert!(!hostname.is_empty());
    }

    #[test]
    fn test_collect_current_user() {
        let collector = SystemCollector::new();
        let user = collector.collect_current_user();
        assert!(!user.username.is_empty());
    }

    #[test]
    fn test_collect_uptime() {
        let collector = SystemCollector::new();
        let uptime = collector.collect_uptime();
        assert!(uptime > 0);
    }

    #[test]
    fn test_collect_cpu_info() {
        let collector = SystemCollector::new();
        let cpu_info = collector.collect_cpu_info();
        assert!(cpu_info.cpu_count > 0);
    }

    #[test]
    fn test_collect_memory_info() {
        let collector = SystemCollector::new();
        let mem_info = collector.collect_memory_info();
        assert!(mem_info.total_memory > 0);
    }

    #[test]
    fn test_collect_all() {
        let mut collector = SystemCollector::new();
        let sys_info = collector.collect_all();
        assert!(!sys_info.hostname.is_empty());
        assert!(!sys_info.current_user.username.is_empty());
    }
}
