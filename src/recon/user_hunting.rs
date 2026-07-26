//! 用户会话猎杀模块
//!
//! 这是横向移动的关键侦察步骤。通过找到域管会话，
//! 攻击者可以窃取域管凭据或进行令牌窃取。
//!
//! 技术：
//! - NetWkstaUserEnum / NetSessionEnum
//! - PSLoggedOn / PsExec
//! - 远程注册表查询
//! - PowerView Find-DomainUserSession / Invoke-UserHunter

use serde::{Deserialize, Serialize};

/// 用户会话信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSession {
    /// 用户名
    pub username: String,
    /// 用户域名
    pub domain: String,
    /// 登录的计算机名
    pub computer: String,
    /// 计算机IP
    pub computer_ip: Option<String>,
    /// 会话ID
    pub session_id: u32,
    /// 会话类型（Console, RDP, Network等）
    pub session_type: String,
    /// 是否是域管理员
    pub is_domain_admin: bool,
    /// 是否是本地管理员
    pub is_local_admin: bool,
    /// 登录时间
    pub logon_time: Option<String>,
    /// 空闲时间
    pub idle_time: Option<String>,
}

/// 猎杀域管理员用户会话
pub fn hunt_user_sessions(
    dc: &str,
    domain: &str,
) -> Result<Vec<UserSession>, String> {
    let mut sessions = Vec::new();

    // 1. 首先获取域管理员组成员列表
    let domain_admins = get_domain_admin_users(dc, domain)?;
    tracing::info!("[用户猎杀] 发现 {} 个域管理员账户", domain_admins.len());

    // 2. 获取域内所有计算机
    let domain_computers = get_domain_computers(dc, domain)?;
    tracing::info!("[用户猎杀] 发现 {} 台域计算机", domain_computers.len());

    // 3. 对每台计算机查询登录会话
    for computer in &domain_computers {
        match query_computer_sessions(computer, &domain_admins) {
            Ok(comp_sessions) => {
                for session in comp_sessions {
                    tracing::info!(
                        "[用户猎杀] 🔑 发现域管会话: {} 登录在 {}",
                        session.username, computer
                    );
                    sessions.push(session);
                }
            }
            Err(e) => {
                tracing::debug!("[用户猎杀] 查询 {} 会话失败: {}", computer, e);
            }
        }
    }

    Ok(sessions)
}

/// 获取域管理员组成员
fn get_domain_admin_users(dc: &str, domain: &str) -> Result<Vec<String>, String> {
    let mut admins = Vec::new();

    if cfg!(windows) {
        // net group "Domain Admins" /domain
        let output = std::process::Command::new("net")
            .args(["group", "Domain Admins", "/domain"])
            .output()
            .map_err(|e| format!("net group失败: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut in_member_list = false;
        for line in stdout.lines() {
            let line = line.trim();
            if line.contains("---") {
                in_member_list = true;
                continue;
            }
            if in_member_list && line.contains("命令成功") {
                break;
            }
            if in_member_list && !line.is_empty() {
                let user = line.trim().to_string();
                if !user.is_empty() && !user.starts_with("命令") && !user.starts_with("The command") {
                    admins.push(user);
                }
            }
        }
    }

    // 备用：使用LDAP查询
    if admins.is_empty() {
        let ldap_url = format!("ldap://{}:389", dc);
        if let Ok(mut ldap) = ldap3::LdapConn::new(&ldap_url) {
            if ldap.simple_bind("", "").is_ok() {
                let base = domain.split('.').map(|p| format!("DC={}", p)).collect::<Vec<_>>().join(",");
                let filter = "(&(objectClass=group)(cn=Domain Admins))";
                if let Ok(sr) = ldap.search(&base, ldap3::Scope::Subtree, filter, &["member"]) {
                    for entry in &sr.0 {
                        let entry = ldap3::SearchEntry::construct(entry.clone());
                        if let Some(members) = entry.attrs.get("member") {
                            for dn in members {
                                // 从DN提取CN
                                if let Some(cn) = dn.split(',').next() {
                                    if let Some(name) = cn.strip_prefix("CN=") {
                                        admins.push(name.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(admins)
}

/// 获取域内计算机列表
fn get_domain_computers(_dc: &str, _domain: &str) -> Result<Vec<String>, String> {
    let mut computers = Vec::new();

    if cfg!(windows) {
        // net view
        let output = std::process::Command::new("net")
            .args(["view", "/domain"])
            .output();

        if let Ok(o) = output {
            let stdout = String::from_utf8_lossy(&o.stdout);
            for line in stdout.lines() {
                if line.starts_with("\\\\") {
                    let comp = line.trim().trim_start_matches('\\').to_string();
                    if !comp.is_empty() {
                        computers.push(comp);
                    }
                }
            }
        }

        // 备用: net group "Domain Computers" /domain
        if computers.is_empty() {
            let output = std::process::Command::new("net")
                .args(["group", "Domain Computers", "/domain"])
                .output();

            if let Ok(o) = output {
                let stdout = String::from_utf8_lossy(&o.stdout);
                let mut in_list = false;
                for line in stdout.lines() {
                    if line.contains("---") { in_list = true; continue; }
                    if in_list && !line.trim().is_empty() {
                        let name = line.trim().to_string();
                        if !name.contains("命令") && !name.contains("The command") {
                            computers.push(name);
                        }
                    }
                }
            }
        }
    }

    Ok(computers)
}

/// 查询计算机上的登录会话
fn query_computer_sessions(
    computer: &str,
    domain_admins: &[String],
) -> Result<Vec<UserSession>, String> {
    let mut sessions = Vec::new();

    let clean_computer = computer.trim_start_matches('\\');

    if cfg!(windows) {
        // quser /server:HOSTNAME（必须作为单个参数传递）
        let output = std::process::Command::new("quser")
            .arg(format!("/server:{}", clean_computer))
            .output();

        if let Ok(o) = output {
            let stdout = String::from_utf8_lossy(&o.stdout);
            for line in stdout.lines().skip(1) {
                // quser输出格式: USERNAME  SESSIONNAME  ID  STATE  IDLE TIME  LOGON TIME
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    let username = parts[0].to_string();
                    let session_id: u32 = parts[2].parse().unwrap_or(0);
                    let is_da = domain_admins.iter().any(|a| a.eq_ignore_ascii_case(&username));

                    sessions.push(UserSession {
                        username: username.clone(),
                        domain: String::new(),
                        computer: clean_computer.to_string(),
                        computer_ip: None,
                        session_id,
                        session_type: if parts.len() > 1 && parts[1] == "console" { "Console".to_string() } else { "RDP".to_string() },
                        is_domain_admin: is_da,
                        is_local_admin: false,
                        logon_time: parts.get(5).map(|s| s.to_string()),
                        idle_time: parts.get(4).map(|s| s.to_string()),
                    });
                }
            }
        }

        // 如果没有RDP会话，尝试查询网络会话
        if sessions.is_empty() {
            let net_output = std::process::Command::new("net")
                .args(["session", &format!("\\\\{}", clean_computer)])
                .output();

            if let Ok(o) = net_output {
                let stdout = String::from_utf8_lossy(&o.stdout);
                for line in stdout.lines() {
                    if line.contains("\\") {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if !parts.is_empty() {
                            let user = parts[0].to_string();
                            let is_da = domain_admins.iter().any(|a| user.contains(a));
                            sessions.push(UserSession {
                                username: user,
                                domain: String::new(),
                                computer: clean_computer.to_string(),
                                computer_ip: None,
                                session_id: 0,
                                session_type: "Network".to_string(),
                                is_domain_admin: is_da,
                                is_local_admin: false,
                                logon_time: None,
                                idle_time: None,
                            });
                        }
                    }
                }
            }
        }
    }

    Ok(sessions)
}

/// 快速用户猎杀（仅检查当前可达的主机）
pub fn quick_user_hunt(domain_admins: &[String]) -> Vec<UserSession> {
    let mut sessions = Vec::new();

    if cfg!(windows) {
        // 使用qwinsta或query session本地
        if let Ok(output) = std::process::Command::new("query").args(["session"]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let username = parts[1].to_string();
                    let is_da = domain_admins.iter().any(|a| a.eq_ignore_ascii_case(&username));
                    sessions.push(UserSession {
                        username,
                        domain: String::new(),
                        computer: whoami::hostname(),
                        computer_ip: None,
                        session_id: parts[0].parse().unwrap_or(0),
                        session_type: "Local".to_string(),
                        is_domain_admin: is_da,
                        is_local_admin: false,
                        logon_time: None,
                        idle_time: None,
                    });
                }
            }
        }
    }

    sessions
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_session_creation() {
        let session = UserSession {
            username: "Administrator".to_string(),
            domain: "CORP".to_string(),
            computer: "DC01".to_string(),
            computer_ip: Some("10.0.0.1".to_string()),
            session_id: 1,
            session_type: "Console".to_string(),
            is_domain_admin: true,
            is_local_admin: true,
            logon_time: Some("2024-01-01T08:00:00".to_string()),
            idle_time: Some("5分钟".to_string()),
        };
        assert!(session.is_domain_admin);
        assert_eq!(session.session_type, "Console");
    }

    #[test]
    fn test_quick_user_hunt() {
        let admins = vec!["Administrator".to_string()];
        let sessions = quick_user_hunt(&admins);
        // 在非域环境中可能为空，但匹配到管理员时必须正确标记
        for s in &sessions {
            if s.username.eq_ignore_ascii_case("Administrator") {
                assert!(s.is_domain_admin);
            }
        }
    }
}
