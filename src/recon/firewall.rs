//! 防火墙规则收集模块
//!
//! 帮助攻击者理解网络访问控制策略，规划横向移动路径。

use serde::{Deserialize, Serialize};

/// 防火墙规则
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    /// 规则名称
    pub name: String,
    /// 方向（入站/出站）
    pub direction: FirewallDirection,
    /// 动作（允许/阻止）
    pub action: FirewallAction,
    /// 协议（TCP/UDP/Any）
    pub protocol: String,
    /// 本地端口
    pub local_port: String,
    /// 远程端口
    pub remote_port: String,
    /// 远程地址
    pub remote_address: String,
    /// 是否启用
    pub enabled: bool,
    /// 程序路径
    pub program: Option<String>,
    /// 规则组
    pub group: Option<String>,
}

/// 防火墙方向
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FirewallDirection {
    Inbound,
    Outbound,
}

/// 防火墙动作
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FirewallAction {
    Allow,
    Block,
}

impl std::fmt::Display for FirewallDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FirewallDirection::Inbound => write!(f, "入站"),
            FirewallDirection::Outbound => write!(f, "出站"),
        }
    }
}

impl std::fmt::Display for FirewallAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FirewallAction::Allow => write!(f, "允许"),
            FirewallAction::Block => write!(f, "阻止"),
        }
    }
}

/// 防火墙配置文件状态
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallProfile {
    /// 配置文件名称（Domain/Private/Public）
    pub name: String,
    /// 是否启用
    pub enabled: bool,
    /// 默认入站动作
    pub default_inbound: FirewallAction,
    /// 默认出站动作
    pub default_outbound: FirewallAction,
}

/// 收集防火墙规则
pub fn collect_firewall_rules() -> Result<Vec<FirewallRule>, String> {
    let mut rules = Vec::new();

    if cfg!(windows) {
        match collect_windows_firewall_rules() {
            Ok(windows_rules) => rules.extend(windows_rules),
            Err(e) => tracing::debug!("[防火墙] Windows规则收集失败: {}", e),
        }
    } else if cfg!(unix) {
        match collect_iptables_rules() {
            Ok(iptables_rules) => rules.extend(iptables_rules),
            Err(e) => tracing::debug!("[防火墙] iptables规则收集失败: {}", e),
        }
    }

    Ok(rules)
}

/// 收集Windows防火墙规则
fn collect_windows_firewall_rules() -> Result<Vec<FirewallRule>, String> {
    let mut rules = Vec::new();

    // 使用netsh advfirewall查询
    let output = std::process::Command::new("netsh")
        .args(["advfirewall", "firewall", "show", "rule", "name=all", "verbose"])
        .output()
        .map_err(|e| format!("netsh失败: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    let mut current_rule: Option<FirewallRule> = None;

    for line in stdout.lines() {
        let line = line.trim();

        if line.starts_with("规则名称:") || line.starts_with("Rule Name:") {
            // 保存上一个规则
            if let Some(rule) = current_rule.take() {
                rules.push(rule);
            }
            current_rule = Some(FirewallRule {
                name: line.split(':').nth(1).unwrap_or("").trim().to_string(),
                direction: FirewallDirection::Inbound,
                action: FirewallAction::Allow,
                protocol: "Any".to_string(),
                local_port: "Any".to_string(),
                remote_port: "Any".to_string(),
                remote_address: "Any".to_string(),
                enabled: true,
                program: None,
                group: None,
            });
        }

        if let Some(ref mut rule) = current_rule {
            if line.starts_with("方向:") || line.starts_with("Direction:") {
                let dir = line.split(':').nth(1).unwrap_or("").trim();
                rule.direction = match dir.to_lowercase().as_str() {
                    "in" | "入站" => FirewallDirection::Inbound,
                    "out" | "出站" => FirewallDirection::Outbound,
                    _ => FirewallDirection::Inbound,
                };
            }
            if line.starts_with("操作:") || line.starts_with("Action:") {
                let action = line.split(':').nth(1).unwrap_or("").trim();
                rule.action = match action.to_lowercase().as_str() {
                    "allow" | "允许" => FirewallAction::Allow,
                    "block" | "阻止" => FirewallAction::Block,
                    _ => FirewallAction::Allow,
                };
            }
            if line.starts_with("协议:") || line.starts_with("Protocol:") {
                rule.protocol = line.split(':').nth(1).unwrap_or("Any").trim().to_string();
            }
            if line.starts_with("本地端口:") || line.starts_with("LocalPort:") {
                rule.local_port = line.split(':').nth(1).unwrap_or("Any").trim().to_string();
            }
            if line.starts_with("远程端口:") || line.starts_with("RemotePort:") {
                rule.remote_port = line.split(':').nth(1).unwrap_or("Any").trim().to_string();
            }
            if line.starts_with("远程地址:") || line.starts_with("RemoteAddress:") {
                rule.remote_address = line.split(':').nth(1).unwrap_or("Any").trim().to_string();
            }
            if line.starts_with("已启用:") || line.starts_with("Enabled:") {
                rule.enabled = line.to_lowercase().contains("yes") || line.contains("是");
            }
            if line.starts_with("程序:") || line.starts_with("Program:") {
                rule.program = line.split(':').nth(1).map(|s| s.trim().to_string());
            }
            if line.starts_with("组:") || line.starts_with("Group:") {
                rule.group = line.split(':').nth(1).map(|s| s.trim().to_string());
            }
        }
    }

    // 保存最后一个规则
    if let Some(rule) = current_rule {
        rules.push(rule);
    }

    Ok(rules)
}

/// 收集iptables规则（Linux）
fn collect_iptables_rules() -> Result<Vec<FirewallRule>, String> {
    let mut rules = Vec::new();

    if let Ok(output) = std::process::Command::new("iptables")
        .args(["-L", "-n", "-v", "--line-numbers"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines().skip(2) {
            let line = line.trim();
            if line.is_empty() || line.starts_with("Chain") {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            // iptables -L -n -v --line-numbers 列序:
            // num pkts bytes target prot opt in out source destination
            if parts.len() >= 5 {
                rules.push(FirewallRule {
                    name: format!("iptables-{}", parts[0]),
                    direction: FirewallDirection::Inbound,
                    action: if parts[3] == "ACCEPT" { FirewallAction::Allow } else { FirewallAction::Block },
                    protocol: parts[4].to_string(),
                    local_port: String::new(),
                    remote_port: String::new(),
                    remote_address: parts.get(9).unwrap_or(&"anywhere").to_string(),
                    enabled: true,
                    program: None,
                    group: Some("iptables".to_string()),
                });
            }
        }
    }

    Ok(rules)
}

/// 获取防火墙配置文件状态
pub fn get_firewall_profiles() -> Vec<FirewallProfile> {
    let mut profiles = Vec::new();

    if cfg!(windows) {
        let output = std::process::Command::new("netsh")
            .args(["advfirewall", "show", "allprofiles"])
            .output();

        if let Ok(o) = output {
            let stdout = String::from_utf8_lossy(&o.stdout);
            let mut current_profile = None;

            for line in stdout.lines() {
                let line = line.trim();
                if line.contains("配置文件") || line.contains("Profile") {
                    if let Some(profile) = current_profile.take() {
                        profiles.push(profile);
                    }
                    let name = if line.contains("域") || line.contains("Domain") {
                        "Domain".to_string()
                    } else if line.contains("专用") || line.contains("Private") {
                        "Private".to_string()
                    } else if line.contains("公用") || line.contains("Public") {
                        "Public".to_string()
                    } else {
                        line.to_string()
                    };
                    current_profile = Some(FirewallProfile {
                        name,
                        enabled: false,
                        default_inbound: FirewallAction::Block,
                        default_outbound: FirewallAction::Allow,
                    });
                }

                if let Some(ref mut profile) = current_profile {
                    if line.contains("状态") || line.contains("State") {
                        profile.enabled = line.to_lowercase().contains("on") || line.contains("启用");
                    }
                    if line.contains("入站") || line.contains("Inbound") {
                        profile.default_inbound = if line.to_lowercase().contains("allow") {
                            FirewallAction::Allow
                        } else {
                            FirewallAction::Block
                        };
                    }
                    if line.contains("出站") || line.contains("Outbound") {
                        profile.default_outbound = if line.to_lowercase().contains("allow") {
                            FirewallAction::Allow
                        } else {
                            FirewallAction::Block
                        };
                    }
                }
            }

            if let Some(profile) = current_profile {
                profiles.push(profile);
            }
        }
    }

    profiles
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collect_firewall_rules() {
        let result = collect_firewall_rules();
        assert!(result.is_ok());
    }

    #[test]
    fn test_firewall_rule_creation() {
        let rule = FirewallRule {
            name: "Test Rule".to_string(),
            direction: FirewallDirection::Inbound,
            action: FirewallAction::Allow,
            protocol: "TCP".to_string(),
            local_port: "443".to_string(),
            remote_port: "Any".to_string(),
            remote_address: "10.0.0.0/8".to_string(),
            enabled: true,
            program: None,
            group: Some("Test Group".to_string()),
        };
        assert!(rule.enabled);
        assert_eq!(rule.protocol, "TCP");
    }

    #[test]
    fn test_firewall_direction_display() {
        assert_eq!(FirewallDirection::Inbound.to_string(), "入站");
        assert_eq!(FirewallAction::Allow.to_string(), "允许");
    }

    #[test]
    fn test_get_firewall_profiles() {
        // 仅验证函数可调用且不 panic；profile 数量依赖运行环境（netsh 可用性/权限），
        // 容器或精简系统可能返回空，故不做数量断言。
        let _profiles = get_firewall_profiles();
    }
}
