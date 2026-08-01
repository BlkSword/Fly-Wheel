//! 系统信息收集模块
//!
//! 收集操作系统、用户、环境等信息

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use sysinfo::System;

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

        let os_version = self.get_real_os_version();

        OsInfo {
            os_type,
            os_version,
            arch: env::consts::ARCH.to_string(),
        }
    }

    /// 获取真实的系统版本
    fn get_real_os_version(&self) -> String {
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

    /// Windows 版本获取（从注册表读取）
    #[cfg(windows)]
    fn get_windows_version_internal(&self) -> String {
        use winreg::enums::*;
        use winreg::RegKey;

        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        if let Ok(key) = hklm.open_subkey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion") {
            let product_name: String = key.get_value("ProductName").unwrap_or_default();
            let display_version: String = key.get_value("DisplayVersion").unwrap_or_default();
            let current_build: String = key.get_value("CurrentBuild").unwrap_or_default();
            let current_version: String = key.get_value("CurrentVersion").unwrap_or_default();

            let mut version = product_name;
            if !display_version.is_empty() {
                version = format!("{} {}", version, display_version);
            }
            if !current_build.is_empty() {
                version = format!("{} (Build {})", version, current_build);
            }
            if !version.is_empty() {
                return version;
            }
            if !current_version.is_empty() {
                return format!("Windows {}", current_version);
            }
        }

        "Windows".to_string()
    }

    /// macOS 版本获取
    #[cfg(target_os = "macos")]
    fn get_macos_version_internal(&self) -> String {
        use std::process::Command;
        match Command::new("sw_vers").arg("-productVersion").output() {
            Ok(output) => String::from_utf8_lossy(&output.stdout).trim().to_string(),
            Err(_) => env::consts::OS.to_string(),
        }
    }

    /// Linux 版本获取
    #[cfg(target_os = "linux")]
    fn get_linux_version_internal(&self) -> String {
        use std::process::Command;
        if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
            for line in content.lines() {
                if line.starts_with("PRETTY_NAME=") {
                    let version = line
                        .trim_start_matches("PRETTY_NAME=")
                        .trim_matches('"')
                        .to_string();
                    if !version.is_empty() {
                        return version;
                    }
                }
            }
        }

        match Command::new("uname").arg("-r").output() {
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
            env::var("USERDNSDOMAIN").ok().or({
                // 尝试从注册表获取域信息
                #[cfg(windows)]
                {
                    use winreg::enums::*;
                    use winreg::RegKey;
                    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
                    hklm.open_subkey("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters")
                        .ok()
                        .and_then(|key| key.get_value("Domain").ok())
                }
                #[cfg(not(windows))]
                {
                    None
                }
            })
        } else {
            match whoami::fallible::hostname() {
                Ok(h) => h.split('.').nth(1).map(|d| d.to_string()),
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
        #[cfg(windows)]
        {
            self.collect_windows_users()
        }

        #[cfg(unix)]
        {
            self.collect_unix_users()
        }

        #[cfg(not(any(windows, unix)))]
        {
            vec![whoami::username()]
        }
    }

    /// Windows: 收集用户列表
    #[cfg(windows)]
    fn collect_windows_users(&self) -> Vec<String> {
        use std::process::Command;
        let mut users = Vec::new();

        // 使用 net user 命令获取用户列表
        if let Ok(output) = Command::new("net").arg("user").output() {
            let content = String::from_utf8_lossy(&output.stdout);
            // 跳过头部和尾部，解析用户列表
            let mut in_user_list = false;
            for line in content.lines() {
                let line = line.trim();
                if line.starts_with("---") {
                    in_user_list = true;
                    continue;
                }
                if line.starts_with("命令") || line.starts_with("The command") {
                    break;
                }
                if in_user_list && !line.is_empty() {
                    for user in line.split_whitespace() {
                        let user = user.to_string();
                        // 过滤系统账户名
                        if !user.starts_with('$') {
                            users.push(user);
                        }
                    }
                }
            }
        }

        if users.is_empty() {
            users.push(whoami::username());
        }

        users
    }

    /// Unix: 收集用户列表
    #[cfg(unix)]
    fn collect_unix_users(&self) -> Vec<String> {
        let mut users = Vec::new();

        if let Ok(content) = std::fs::read_to_string("/etc/passwd") {
            for line in content.lines() {
                if line.starts_with('#') || line.is_empty() {
                    continue;
                }
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 3 {
                    if let Ok(uid) = parts[2].parse::<u32>() {
                        // 包含普通用户 (uid >= 1000) 和 root (uid == 0)
                        if uid == 0 || uid >= 1000 {
                            users.push(parts[0].to_string());
                        }
                    }
                }
            }
        }

        if users.is_empty() {
            users.push(whoami::username());
        }

        users
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
        // sysinfo 0.30+ 使用独立的 Disks 类型
        let mut disks = Vec::new();

        let sys_disks = sysinfo::Disks::new_with_refreshed_list();
        for disk in sys_disks.list() {
            let name = disk.name().to_string_lossy().to_string();
            let mount_point = disk.mount_point().to_string_lossy().to_string();
            let total_space = disk.total_space();
            let available_space = disk.available_space();

            disks.push(DiskInfo {
                name,
                mount_point,
                total_space,
                available_space,
                is_removable: false, // sysinfo 不直接提供此信息
            });
        }

        disks
    }

    /// 收集环境变量
    pub fn collect_environment(&self) -> HashMap<String, String> {
        env::vars_os()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().to_string(),
                    v.to_string_lossy().to_string(),
                )
            })
            .collect()
    }

    /// 检查权限
    fn check_privileges(&self) -> PrivilegeLevel {
        #[cfg(windows)]
        {
            if self.is_admin_windows() {
                PrivilegeLevel::Admin
            } else {
                PrivilegeLevel::User
            }
        }
        #[cfg(not(windows))]
        {
            if self.is_root_unix() {
                PrivilegeLevel::Root
            } else {
                PrivilegeLevel::User
            }
        }
    }

    /// 获取用户组
    fn get_user_groups(&self) -> Vec<String> {
        #[cfg(windows)]
        {
            self.get_windows_groups()
        }

        #[cfg(unix)]
        {
            self.get_unix_groups()
        }

        #[cfg(not(any(windows, unix)))]
        {
            vec!["users".to_string()]
        }
    }

    /// Windows: 获取用户组
    #[cfg(windows)]
    fn get_windows_groups(&self) -> Vec<String> {
        use std::process::Command;
        let mut groups = Vec::new();

        // 使用 whoami /groups 获取组信息
        if let Ok(output) = Command::new("whoami")
            .args(["/groups", "/fo", "csv"])
            .output()
        {
            let content = String::from_utf8_lossy(&output.stdout);
            for line in content.lines().skip(1) {
                // CSV 格式: "组名","类型","SID","属性"
                if let Some(group_name) = line.split(',').next() {
                    let name = group_name.trim_matches('"').to_string();
                    if !name.is_empty() {
                        groups.push(name);
                    }
                }
            }
        }

        if groups.is_empty() {
            // 回退: 根据权限级别推断
            if self.is_admin_windows() {
                groups.push("Administrators".to_string());
            }
            groups.push("Users".to_string());
        }

        groups
    }

    /// Unix: 获取用户组
    #[cfg(unix)]
    fn get_unix_groups(&self) -> Vec<String> {
        let mut groups = Vec::new();

        // 从 /etc/group 读取
        if let Ok(content) = std::fs::read_to_string("/etc/group") {
            let username = whoami::username();
            for line in content.lines() {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 4 {
                    let members = parts[3];
                    if members.split(',').any(|m| m.trim() == username) {
                        groups.push(parts[0].to_string());
                    }
                }
            }
        }

        // 也使用 id 命令获取
        if groups.is_empty() {
            use std::process::Command;
            if let Ok(output) = Command::new("id").arg("-Gn").output() {
                let content = String::from_utf8_lossy(&output.stdout);
                groups = content.split_whitespace().map(|s| s.to_string()).collect();
            }
        }

        if groups.is_empty() {
            if self.is_root_unix() {
                groups.push("root".to_string());
            }
            groups.push(whoami::username());
        }

        groups
    }

    /// 检查 Windows 管理员权限
    #[cfg(windows)]
    fn is_admin_windows(&self) -> bool {
        use std::process::Command;

        // 方法: 尝试执行需要管理员权限的操作
        // 使用 net session 命令检测管理员权限
        if let Ok(output) = Command::new("net").args(["session"]).output() {
            // 如果命令执行成功（退出码 0），说明有管理员权限
            return output.status.success();
        }

        false
    }

    /// 检查 Unix root 权限
    #[cfg(unix)]
    fn is_root_unix(&self) -> bool {
        nix::unistd::geteuid().is_root()
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
        let _collector = SystemCollector::new();
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
    fn test_collect_disk_info() {
        let collector = SystemCollector::new();
        let disks = collector.collect_disk_info();
        // 至少应该有一个磁盘
        assert!(!disks.is_empty());
    }

    #[test]
    fn test_collect_users() {
        let mut collector = SystemCollector::new();
        let users = collector.collect_users();
        assert!(!users.is_empty());
    }

    #[test]
    fn test_collect_all() {
        let mut collector = SystemCollector::new();
        let sys_info = collector.collect_all();
        assert!(!sys_info.hostname.is_empty());
        assert!(!sys_info.current_user.username.is_empty());
    }
}
