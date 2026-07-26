//! 主机详细信息收集模块
//!
//! 为权限提升和漏洞利用提供决策依据。

use serde::{Deserialize, Serialize};

/// 主机详细信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInfo {
    /// 主机名
    pub hostname: String,
    /// 操作系统
    pub os: String,
    /// 架构
    pub arch: String,
    /// CPU信息
    pub cpu: Option<String>,
    /// 内存 (MB)
    pub memory_mb: Option<u64>,
    /// 磁盘信息
    pub disks: Vec<DiskInfo>,
    /// 已安装的软件（重点）
    pub key_software: Vec<KeySoftware>,
    /// 本地用户
    pub local_users: Vec<LocalUser>,
    /// 本地组
    pub local_groups: Vec<LocalGroup>,
    /// 开机时间
    pub uptime: Option<String>,
    /// 系统语言/区域
    pub locale: Option<String>,
}

/// 磁盘信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskInfo {
    pub drive_letter: String,
    pub total_gb: f64,
    pub free_gb: f64,
    pub filesystem: String,
}

/// 关键软件
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeySoftware {
    pub name: String,
    pub version: Option<String>,
    pub vendor: Option<String>,
    pub install_date: Option<String>,
}

/// 本地用户
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalUser {
    pub username: String,
    pub full_name: Option<String>,
    pub is_admin: bool,
    pub is_enabled: bool,
    pub last_logon: Option<String>,
    pub password_required: bool,
    pub password_changeable: bool,
    pub password_expires: Option<String>,
}

/// 本地组
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalGroup {
    pub name: String,
    pub members: Vec<String>,
}

/// 收集主机详细信息
pub fn collect_host_info() -> Result<HostInfo, String> {
    let hostname = whoami::hostname();
    let os = whoami::distro();
    let arch = std::env::consts::ARCH.to_string();

    let cpu = get_cpu_info();
    let memory_mb = get_memory_info();
    let disks = get_disk_info();
    let key_software = get_key_software();
    let local_users = get_local_users();
    let local_groups = get_local_groups();
    let uptime = get_uptime();
    let locale = get_locale();

    Ok(HostInfo {
        hostname,
        os,
        arch,
        cpu,
        memory_mb,
        disks,
        key_software,
        local_users,
        local_groups,
        uptime,
        locale,
    })
}

fn get_cpu_info() -> Option<String> {
    if cfg!(windows) {
        std::env::var("PROCESSOR_IDENTIFIER").ok()
    } else if cfg!(unix) {
        if let Ok(content) = std::fs::read_to_string("/proc/cpuinfo") {
            for line in content.lines() {
                if line.starts_with("model name") {
                    return line.split(':').nth(1).map(|s| s.trim().to_string());
                }
            }
        }
        None
    } else {
        None
    }
}

fn get_memory_info() -> Option<u64> {
    if cfg!(windows) {
        let output = std::process::Command::new("wmic")
            .args(["memorychip", "get", "capacity", "/format:csv"])
            .output()
            .ok()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut total: u64 = 0;
        for line in stdout.lines().skip(1) {
            if let Some(val) = line.split(',').nth(1) {
                if let Ok(bytes) = val.trim().parse::<u64>() {
                    total += bytes;
                }
            }
        }
        if total > 0 {
            Some(total / 1024 / 1024) // 转换为MB
        } else {
            None
        }
    } else if cfg!(unix) {
        if let Ok(content) = std::fs::read_to_string("/proc/meminfo") {
            for line in content.lines() {
                if line.starts_with("MemTotal:") {
                    let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
                    return Some(kb / 1024);
                }
            }
        }
        None
    } else {
        None
    }
}

fn get_disk_info() -> Vec<DiskInfo> {
    let mut disks = Vec::new();

    if cfg!(windows) {
        if let Ok(output) = std::process::Command::new("wmic")
            .args(["logicaldisk", "get", "DeviceID,Size,FreeSpace,FileSystem", "/format:csv"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines().skip(1) {
                let parts: Vec<&str> = line.split(',').collect();
                // CSV格式: Node,DeviceID,FileSystem,FreeSpace,Size
                // wmic CSV第一列始终为Node（本地为空），属性按字母序排列
                if parts.len() >= 5 {
                    let drive = parts[1].trim().to_string();
                    let fs = parts[2].trim().to_string();
                    let free: f64 = parts[3].trim().parse().unwrap_or(0) as f64 / 1024.0 / 1024.0 / 1024.0;
                    let total: f64 = parts[4].trim().parse().unwrap_or(0) as f64 / 1024.0 / 1024.0 / 1024.0;

                    if total > 0.0 {
                        disks.push(DiskInfo {
                            drive_letter: drive,
                            total_gb: (total * 10.0).round() / 10.0,
                            free_gb: (free * 10.0).round() / 10.0,
                            filesystem: fs,
                        });
                    }
                }
            }
        }
    }

    disks
}

fn get_key_software() -> Vec<KeySoftware> {
    let mut software = Vec::new();

    // 重点检查渗透人员关心的软件
    let key_software_patterns = [
        ("Python", None::<&str>),
        ("Java", None::<&str>),
        ("Node.js", None::<&str>),
        ("Ruby", None::<&str>),
        ("Perl", None::<&str>),
        ("PHP", None::<&str>),
        (".NET", None::<&str>),
        ("Visual Studio", None::<&str>),
        ("Git", None::<&str>),
        ("Docker", None::<&str>),
        ("MySQL", None::<&str>),
        ("MariaDB", None::<&str>),
        ("PostgreSQL", None::<&str>),
        ("MongoDB", None::<&str>),
        ("Redis", None::<&str>),
        ("SQL Server", None::<&str>),
        ("Oracle", None::<&str>),
        ("Apache", None::<&str>),
        ("Nginx", None::<&str>),
        ("IIS", None::<&str>),
        ("Tomcat", None::<&str>),
        ("Jenkins", None::<&str>),
        ("FileZilla", None::<&str>),
        ("Putty", None::<&str>),
        ("WinSCP", None::<&str>),
        ("OpenVPN", None::<&str>),
        ("Cisco AnyConnect", None::<&str>),
        ("Pulse Secure", None::<&str>),
    ];

    if cfg!(windows) {
        if let Ok(output) = std::process::Command::new("wmic")
            .args(["product", "get", "Name,Version,Vendor,InstallDate", "/format:csv"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines().skip(1) {
                let parts: Vec<&str> = line.split(',').collect();
                if parts.len() >= 2 {
                    let name = parts[1].trim().to_string();
                    // 只收集关键软件
                    for (pattern, _) in &key_software_patterns {
                        if name.to_lowercase().contains(&pattern.to_lowercase()) {
                            software.push(KeySoftware {
                                name,
                                version: parts.get(3).map(|s| s.trim().to_string()),
                                vendor: parts.get(2).map(|s| s.trim().to_string()),
                                install_date: parts.get(4).map(|s| s.trim().to_string()),
                            });
                            break;
                        }
                    }
                }
            }
        }
    }

    software
}

fn get_local_users() -> Vec<LocalUser> {
    let mut users = Vec::new();

    if cfg!(windows) {
        if let Ok(output) = std::process::Command::new("net").args(["user"]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines().skip(4) {
                let line = line.trim();
                if line.contains("命令成功") || line.contains("The command") {
                    break;
                }
                let parts: Vec<&str> = line.split_whitespace().collect();
                for user in parts {
                    let user = user.trim().to_string();
                    if !user.is_empty() {
                        // 使用net user <name>获取详细信息
                        let detail = get_local_user_detail(&user);
                        users.push(detail);
                    }
                }
            }
        }
    } else if cfg!(unix) {
        if let Ok(content) = std::fs::read_to_string("/etc/passwd") {
            for line in content.lines() {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 7 {
                    let uid: u32 = parts[2].parse().unwrap_or(65535);
                    if uid >= 1000 && uid < 65534 {
                        users.push(LocalUser {
                            username: parts[0].to_string(),
                            full_name: Some(parts[4].to_string()),
                            is_admin: uid == 0,
                            is_enabled: !parts[1].contains('!') && !parts[1].contains('*'),
                            last_logon: None,
                            password_required: !parts[1].is_empty(),
                            password_changeable: true,
                            password_expires: None,
                        });
                    }
                }
            }
        }
    }

    users
}

fn get_local_user_detail(username: &str) -> LocalUser {
    let mut user = LocalUser {
        username: username.to_string(),
        full_name: None,
        is_admin: false,
        is_enabled: true,
        last_logon: None,
        password_required: true,
        password_changeable: true,
        password_expires: None,
    };

    if cfg!(windows) {
        if let Ok(output) = std::process::Command::new("net")
            .args(["user", username])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);

            for line in stdout.lines() {
                let line = line.trim();
                if line.contains("全名") || line.contains("Full Name") {
                    user.full_name = line.split_whitespace().last().map(|s| s.to_string());
                }
                if line.contains("帐户启用") || line.contains("Account active") {
                    user.is_enabled = line.to_lowercase().contains("yes");
                }
                if line.contains("密码到期") || line.contains("Password expires") {
                    user.password_expires = line.split_whitespace().last().map(|s| s.to_string());
                }
            }
        }

        // 检查是否为管理员
        user.is_admin = check_if_local_admin(username);
    }

    user
}

fn check_if_local_admin(username: &str) -> bool {
    if cfg!(windows) {
        let output = std::process::Command::new("net")
            .args(["localgroup", "Administrators"])
            .output();

        if let Ok(o) = output {
            let stdout = String::from_utf8_lossy(&o.stdout);
            stdout.contains(username)
        } else {
            false
        }
    } else if cfg!(unix) {
        username == "root"
    } else {
        false
    }
}

fn get_local_groups() -> Vec<LocalGroup> {
    let mut groups = Vec::new();

    if cfg!(windows) {
        // 重点组
        let important_groups = [
            "Administrators",
            "Remote Desktop Users",
            "Backup Operators",
            "Account Operators",
            "Server Operators",
            "Print Operators",
            "Hyper-V Administrators",
            "Docker Users",
        ];

        for group_name in &important_groups {
            if let Ok(output) = std::process::Command::new("net")
                .args(["localgroup", group_name])
                .output()
            {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let mut members = Vec::new();
                let mut in_members = false;

                for line in stdout.lines() {
                    if line.contains("---") {
                        in_members = true;
                        continue;
                    }
                    if in_members && line.contains("命令成功") {
                        break;
                    }
                    if in_members {
                        let member = line.trim().to_string();
                        if !member.is_empty() {
                            members.push(member);
                        }
                    }
                }

                groups.push(LocalGroup {
                    name: group_name.to_string(),
                    members,
                });
            }
        }
    }

    groups
}

fn get_uptime() -> Option<String> {
    if cfg!(windows) {
        let output = std::process::Command::new("systeminfo")
            .output()
            .ok()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.contains("启动时间") || line.contains("Boot Time") {
                return line.split(':').nth(1).map(|s| s.trim().to_string());
            }
        }
    } else if cfg!(unix) {
        if let Ok(content) = std::fs::read_to_string("/proc/uptime") {
            let uptime_secs: f64 = content.split_whitespace().next()?.parse().ok()?;
            let days = uptime_secs as u64 / 86400;
            let hours = (uptime_secs as u64 % 86400) / 3600;
            return Some(format!("{}天 {}小时", days, hours));
        }
    }
    None
}

fn get_locale() -> Option<String> {
    std::env::var("LANG")
        .or_else(|_| std::env::var("LC_ALL"))
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collect_host_info() {
        let result = collect_host_info();
        assert!(result.is_ok());
        let info = result.unwrap();
        assert!(!info.hostname.is_empty());
        assert!(!info.arch.is_empty());
    }

    #[test]
    fn test_disk_info() {
        let disks = get_disk_info();
        // 可能为空（权限不足）或包含磁盘
        for disk in &disks {
            assert!(!disk.drive_letter.is_empty());
        }
    }

    #[test]
    fn test_local_users() {
        let users = get_local_users();
        // 应该包含当前用户
        let current = whoami::username();
        assert!(users.iter().any(|u| u.username == current));
    }
}
