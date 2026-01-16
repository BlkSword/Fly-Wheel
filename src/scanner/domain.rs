//! 域环境扫描
//!
//! 提供Active Directory域环境信息收集功能

use crate::scanner::config::ScanConfig;
use crate::scanner::models::{DomainTrust, DomainUser, ServicePrincipalName};
use std::collections::HashMap;

/// 域扫描器
pub struct DomainScanner {
    config: ScanConfig,
    /// 当前域名
    domain_name: Option<String>,
    /// 域控制器
    domain_controller: Option<String>,
}

impl DomainScanner {
    /// 创建新的域扫描器
    pub fn new(config: ScanConfig) -> Self {
        Self {
            config,
            domain_name: None,
            domain_controller: None,
        }
    }

    /// 使用默认配置创建
    pub fn with_default_config() -> Self {
        Self::new(ScanConfig::default())
    }

    /// 自动发现域环境
    pub fn auto_discover(&mut self) -> DomainScanResult {
        let mut result = DomainScanResult {
            domain_name: None,
            domain_controller: None,
            is_joined: false,
            current_computer: None,
            current_user: None,
            domain_users: Vec::new(),
            domain_groups: Vec::new(),
            domain_trusts: Vec::new(),
            spn_accounts: Vec::new(),
            admin_accounts: Vec::new(),
        };

        // 尝试检测当前域环境
        if let Ok(domain_info) = self.detect_domain() {
            let domain_name = domain_info.name.clone();
            result.domain_name = Some(domain_name.clone());
            result.is_joined = domain_info.is_joined;
            result.current_computer = domain_info.computer_name;
            result.current_user = domain_info.username;
            self.domain_name = Some(domain_name.clone());

            // 尝试发现域控制器
            if let Ok(dc) = self.find_domain_controller(&domain_name) {
                result.domain_controller = Some(dc.clone());
                self.domain_controller = Some(dc);
            }
        }

        result
    }

    /// 检测当前域环境
    fn detect_domain(&self) -> Result<DomainInfo, Box<dyn std::error::Error>> {
        #[cfg(windows)]
        {
            self.detect_domain_windows()
        }
        #[cfg(not(windows))]
        {
            self.detect_domain_unix()
        }
    }

    /// Windows域检测
    #[cfg(windows)]
    fn detect_domain_windows(&self) -> Result<DomainInfo, Box<dyn std::error::Error>> {
        use std::process::Command;

        // 使用systeminfo获取域信息
        let output = Command::new("systeminfo")
            .output()
            .map_err(|e| format!("执行systeminfo失败: {}", e))?;

        let content = String::from_utf8_lossy(&output.stdout);
        let mut info = DomainInfo {
            name: String::new(),
            is_joined: false,
            computer_name: None,
            username: None,
        };

        // 解析域信息
        for line in content.lines() {
            let line = line.trim();
            if line.contains("域:") {
                if let Some(domain) = line.split(':').nth(1) {
                    let domain = domain.trim();
                    if !domain.is_empty() && domain != "WORKGROUP" {
                        info.name = domain.to_string();
                        info.is_joined = true;
                    }
                }
            }
            if line.contains("计算机名称:") {
                if let Some(computer) = line.split(':').nth(1) {
                    info.computer_name = Some(computer.trim().to_string());
                }
            }
        }

        // 获取当前用户
        if let Ok(user) = std::env::var("USERNAME") {
            info.username = Some(user);
        }

        Ok(info)
    }

    /// Unix域检测
    #[cfg(not(windows))]
    fn detect_domain_unix(&self) -> Result<DomainInfo, Box<dyn std::error::Error>> {
        use std::process::Command;

        let mut info = DomainInfo {
            name: String::new(),
            is_joined: false,
            computer_name: None,
            username: None,
        };

        // 尝试使用realm命令
        if let Ok(output) = Command::new("realm").arg("list").output() {
            let content = String::from_utf8_lossy(&output.stdout);
            for line in content.lines() {
                if line.contains("domain-name:") {
                    if let Some(domain) = line.split(':').nth(1) {
                        info.name = domain.trim().to_string();
                        info.is_joined = true;
                    }
                }
            }
        }

        // 获取主机名
        if let Ok(output) = Command::new("hostname").output() {
            info.computer_name = Some(String::from_utf8_lossy(&output.stdout).trim().to_string());
        }

        // 获取当前用户
        if let Ok(user) = std::env::var("USER") {
            info.username = Some(user);
        }

        Ok(info)
    }

    /// 发现域控制器
    fn find_domain_controller(&self, domain: &str) -> Result<String, Box<dyn std::error::Error>> {
        #[cfg(windows)]
        {
            use std::process::Command;

            // 使用nltest查找域控制器
            if let Ok(output) = Command::new("nltest")
                .args(&["/dclist:", domain])
                .output()
            {
                let content = String::from_utf8_lossy(&output.stdout);
                // 解析域控制器
                for line in content.lines() {
                    if line.contains("DC") {
                        if let Some(dc) = line.split('\\').nth(1) {
                            return Ok(dc.trim().to_string());
                        }
                    }
                }
            }

            // 使用nslookup查询
            if let Ok(output) = Command::new("nslookup")
                .args(&["-type=SRV", "_ldap._tcp.dc._msdcs.", domain])
                .output()
            {
                let content = String::from_utf8_lossy(&output.stdout);
                // 简单解析返回结果
                for line in content.lines() {
                    if line.contains("svr hostname") || line.contains("nameserver") {
                        // 进一步解析逻辑...
                    }
                }
            }

            Err("未找到域控制器".into())
        }
        #[cfg(not(windows))]
        {
            // Unix系统使用dig或host命令
            use std::process::Command;

            if let Ok(output) = Command::new("dig")
                .args(&["-t", "SRV", &format!("_ldap._tcp.dc._msdcs.{}", domain)])
                .output()
            {
                let content = String::from_utf8_lossy(&output.stdout);
                // 解析结果
                for line in content.lines() {
                    // 简单解析逻辑
                }
            }

            Err("Unix域发现功能开发中".into())
        }
    }

    /// 枚举域用户
    pub fn enumerate_users(&self) -> Vec<DomainUser> {
        #[cfg(windows)]
        {
            self.enumerate_users_windows()
        }
        #[cfg(not(windows))]
        {
            Vec::new() // Unix暂不支持
        }
    }

    #[cfg(windows)]
    fn enumerate_users_windows(&self) -> Vec<DomainUser> {
        use std::process::Command;

        let mut users = Vec::new();

        // 使用net user命令
        if let Ok(output) = Command::new("net")
            .args(&["user", "/domain"])
            .output()
        {
            let content = String::from_utf8_lossy(&output.stdout);
            // 解析用户列表
            for line in content.lines() {
                let line = line.trim();
                // 跳过标题和空行
                if line.is_empty()
                    || line.contains("----")
                    || line.contains("用户名")
                    || line.contains("命令成功完成")
                {
                    continue;
                }

                // 提取用户名
                if let Some(username) = line.split_whitespace().next() {
                    users.push(DomainUser {
                        username: username.to_string(),
                        sid: None,
                        description: None,
                        last_logon: None,
                        password_last_set: None,
                    });
                }
            }
        }

        users
    }

    /// 查找域管理员账户
    pub fn find_admin_accounts(&self) -> Vec<String> {
        #[cfg(windows)]
        {
            use std::process::Command;

            let mut admins = Vec::new();

            // 查询域管理员组
            if let Ok(output) = Command::new("net")
                .args(&["group", "\"Domain Admins\"", "/domain"])
                .output()
            {
                let content = String::from_utf8_lossy(&output.stdout);
                for line in content.lines() {
                    let line = line.trim();
                    if line.is_empty()
                        || line.contains("----")
                        || line.contains("成员")
                        || line.contains("命令成功完成")
                    {
                        continue;
                    }

                    if let Some(member) = line.split_whitespace().next() {
                        admins.push(member.to_string());
                    }
                }
            }

            admins
        }
        #[cfg(not(windows))]
        {
            Vec::new()
        }
    }

    /// 获取域信任关系
    pub fn get_domain_trusts(&self) -> Vec<DomainTrust> {
        #[cfg(windows)]
        {
            use std::process::Command;

            let mut trusts = Vec::new();

            if let Ok(output) = Command::new("nltest")
                .args(&["/domain_trusts"])
                .output()
            {
                let content = String::from_utf8_lossy(&output.stdout);
                // 解析域信任关系
                for line in content.lines() {
                    // 简化解析，实际需要更复杂的逻辑
                    if line.contains("域信任") {
                        // 解析逻辑...
                    }
                }
            }

            trusts
        }
        #[cfg(not(windows))]
        {
            Vec::new()
        }
    }

    /// SPN扫描（Kerberoasting目标）
    pub fn spn_scan(&self) -> Vec<ServicePrincipalName> {
        #[cfg(windows)]
        {
            use std::process::Command;

            let mut spns = Vec::new();

            // 使用setspn命令查询服务主体名称
            if let Ok(output) = Command::new("setspn")
                .args(&["-q", "*/*"])
                .output()
            {
                let content = String::from_utf8_lossy(&output.stdout);
                for line in content.lines() {
                    let line = line.trim();
                    if line.is_empty()
                        || line.contains("注册")
                        || line.contains("----")
                        || line.contains("命令")
                    {
                        continue;
                    }

                    // 解析SPN格式: MSSQLSvc/dc1.corp.local:1433
                    if let Some(pos) = line.find('/') {
                        let service_type = line[..pos].to_string();
                        let remainder = &line[pos + 1..];

                        // 提取用户名（通常在最后）
                        if let Some(user_pos) = remainder.rfind(' ') {
                            let username = remainder[user_pos + 1..].to_string();
                            spns.push(ServicePrincipalName {
                                spn: line.to_string(),
                                username,
                                service_type,
                            });
                        }
                    }
                }
            }

            spns
        }
        #[cfg(not(windows))]
        {
            Vec::new()
        }
    }

    /// 获取域密码策略
    pub fn get_password_policy(&self) -> PasswordPolicy {
        #[cfg(windows)]
        {
            use std::process::Command;

            let mut policy = PasswordPolicy::default();

            if let Ok(output) = Command::new("net")
                .args(&["accounts"])
                .output()
            {
                let content = String::from_utf8_lossy(&output.stdout);
                // 解析密码策略
                for line in content.lines() {
                    if line.contains("密码最长期限") {
                        // 解析逻辑...
                    }
                    if line.contains("密码最短长度") {
                        // 解析逻辑...
                    }
                }
            }

            policy
        }
        #[cfg(not(windows))]
        {
            PasswordPolicy::default()
        }
    }
}

impl Default for DomainScanner {
    fn default() -> Self {
        Self::with_default_config()
    }
}

/// 域信息
#[derive(Debug, Clone)]
struct DomainInfo {
    name: String,
    is_joined: bool,
    computer_name: Option<String>,
    username: Option<String>,
}

/// 域扫描结果
#[derive(Debug, Clone)]
pub struct DomainScanResult {
    pub domain_name: Option<String>,
    pub domain_controller: Option<String>,
    pub is_joined: bool,
    pub current_computer: Option<String>,
    pub current_user: Option<String>,
    pub domain_users: Vec<DomainUser>,
    pub domain_groups: Vec<String>,
    pub domain_trusts: Vec<DomainTrust>,
    pub spn_accounts: Vec<ServicePrincipalName>,
    pub admin_accounts: Vec<String>,
}

/// 密码策略
#[derive(Debug, Clone)]
pub struct PasswordPolicy {
    pub max_password_age: Option<u32>,
    pub min_password_age: Option<u32>,
    pub min_password_length: Option<u32>,
    pub password_history: Option<u32>,
    pub lockout_threshold: Option<u32>,
    pub lockout_duration: Option<u32>,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            max_password_age: None,
            min_password_age: None,
            min_password_length: None,
            password_history: None,
            lockout_threshold: None,
            lockout_duration: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_scanner_creation() {
        let scanner = DomainScanner::default();
        assert_eq!(scanner.config.host_timeout_ms, 1000);
    }

    #[test]
    fn test_auto_discover() {
        let mut scanner = DomainScanner::default();
        let result = scanner.auto_discover();

        // 结果应该返回，即使没有域
        assert_eq!(result.is_joined, result.domain_name.is_some());
    }

    #[test]
    fn test_password_policy_default() {
        let policy = PasswordPolicy::default();
        assert!(policy.max_password_age.is_none());
        assert!(policy.min_password_length.is_none());
    }
}
