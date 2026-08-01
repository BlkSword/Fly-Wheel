//! 信息侦察与态势感知模块
//!
//! 本模块整合了报告中描述的所有信息收集需求：
//!
//! - 环境感知：OS、域信息、网络配置、安全软件一键收集
//! - 用户会话猎杀：查找域管理员登录的主机
//! - 文件共享敏感信息搜索：扫描域内共享文件
//! - 自动化BloodHound数据收集：部署SharpHound并收集
//! - ADCS证书服务枚举
//! - VLAN/ACL/防火墙规则发现
//! - EDR/AV安全软件识别
//! - 补丁级别与漏洞关联

pub mod adcs;
pub mod bloodhound_auto;
pub mod edr_detect;
pub mod firewall;
pub mod host_info;
pub mod share_hunting;
pub mod situational;
pub mod user_hunting;
pub mod vlan;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ============================================================
// 侦察结果
// ============================================================

/// 综合侦察报告
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconReport {
    /// 侦察开始时间
    pub start_time: DateTime<Utc>,
    /// 侦察结束时间
    pub end_time: DateTime<Utc>,
    /// 耗时
    pub duration_secs: f64,
    /// 目标主机
    pub hostname: String,
    /// 环境感知结果
    pub situational: Option<SituationalInfo>,
    /// 主机详细信息
    pub host_info: Option<host_info::HostInfo>,
    /// 安全软件检测结果
    pub security_products: Vec<edr_detect::SecurityProduct>,
    /// 用户会话猎杀结果
    pub user_sessions: Vec<user_hunting::UserSession>,
    /// 文件共享搜索结果
    pub share_findings: Vec<share_hunting::ShareFinding>,
    /// 网络拓扑信息
    pub network_topology: Option<NetworkTopologyInfo>,
    /// 防火墙规则
    pub firewall_rules: Vec<firewall::FirewallRule>,
    /// 统计数据
    pub stats: ReconStats,
}

/// 态势感知信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SituationalInfo {
    /// 操作系统
    pub os: String,
    /// 操作系统版本
    pub os_version: String,
    /// 主机名
    pub hostname: String,
    /// 当前用户
    pub current_user: String,
    /// 当前用户权限
    pub privileges: Vec<String>,
    /// 是否在域中
    pub in_domain: bool,
    /// 域名
    pub domain_name: Option<String>,
    /// 域控制器
    pub domain_controllers: Vec<String>,
    /// 本地IP地址
    pub local_ips: Vec<String>,
    /// 网络适配器
    pub network_adapters: Vec<NetworkAdapter>,
    /// 安装的软件
    pub installed_software: Vec<String>,
    /// 运行的服务
    pub running_services: Vec<String>,
    /// 已安装的补丁
    pub installed_patches: Vec<String>,
    /// 潜在漏洞
    pub potential_vulnerabilities: Vec<PotentialVuln>,
}

/// 网络适配器
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAdapter {
    pub name: String,
    pub ip_addresses: Vec<String>,
    pub mac_address: Option<String>,
    pub dns_servers: Vec<String>,
    pub subnet_mask: Option<String>,
    pub default_gateway: Option<String>,
}

/// 潜在漏洞
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PotentialVuln {
    /// 漏洞标识（如KB号或CVE编号）
    pub identifier: String,
    /// 描述
    pub description: String,
    /// 严重程度
    pub severity: VulnSeverity,
    /// 关联的补丁
    pub related_patch: Option<String>,
}

/// 漏洞严重程度
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum VulnSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for VulnSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VulnSeverity::Info => write!(f, "信息"),
            VulnSeverity::Low => write!(f, "低"),
            VulnSeverity::Medium => write!(f, "中"),
            VulnSeverity::High => write!(f, "高"),
            VulnSeverity::Critical => write!(f, "严重"),
        }
    }
}

/// 网络拓扑信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkTopologyInfo {
    /// 发现的子网
    pub subnets: Vec<DiscoveredSubnet>,
    /// 存活主机数
    pub alive_hosts: usize,
    /// 扫描范围
    pub scan_range: Option<String>,
}

/// 发现的子网
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredSubnet {
    /// 子网地址（如 10.10.10.0/24）
    pub subnet: String,
    /// 存活主机数
    pub host_count: usize,
    /// 是否是当前子网
    pub is_current: bool,
    /// 可达性
    pub reachable: bool,
    /// 描述（如 VLAN 10 - 服务器区）
    pub description: Option<String>,
}

/// 侦察统计
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReconStats {
    /// 存活主机数
    pub alive_hosts: usize,
    /// 发现的域用户数
    pub domain_users: usize,
    /// 域管账户数
    pub domain_admins: usize,
    /// 可访问的共享数
    pub accessible_shares: usize,
    /// 找到的敏感文件数
    pub sensitive_files: usize,
    /// 凭据引用数
    pub credential_references: usize,
    /// 安全产品数
    pub security_products: usize,
    /// 潜在漏洞数
    pub potential_vulnerabilities: usize,
    /// 域管会话数
    pub da_sessions: usize,
}

impl ReconReport {
    pub fn new(hostname: &str) -> Self {
        Self {
            start_time: Utc::now(),
            end_time: Utc::now(),
            duration_secs: 0.0,
            hostname: hostname.to_string(),
            situational: None,
            host_info: None,
            security_products: Vec::new(),
            user_sessions: Vec::new(),
            share_findings: Vec::new(),
            network_topology: None,
            firewall_rules: Vec::new(),
            stats: ReconStats::default(),
        }
    }

    /// 计算统计信息
    pub fn compute_stats(&mut self) {
        self.stats.domain_admins = self
            .user_sessions
            .iter()
            .filter(|s| s.is_domain_admin)
            .count();
        self.stats.da_sessions = self.stats.domain_admins;
        self.stats.accessible_shares = self.share_findings.len();
        self.stats.sensitive_files = self
            .share_findings
            .iter()
            .filter(|f| f.is_sensitive)
            .count();
        self.stats.credential_references = self
            .share_findings
            .iter()
            .filter(|f| f.contains_credentials)
            .count();
        self.stats.security_products = self.security_products.len();
        if let Some(ref s) = self.situational {
            self.stats.potential_vulnerabilities = s.potential_vulnerabilities.len();
        }
    }

    /// 获取高价值发现摘要
    pub fn high_value_findings(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.stats.da_sessions > 0 {
            findings.push(format!(
                "🔑 发现 {} 个域管理员会话 — 可窃取凭据",
                self.stats.da_sessions
            ));
        }

        if self.stats.credential_references > 0 {
            findings.push(format!(
                "📄 发现 {} 个文件包含凭据引用",
                self.stats.credential_references
            ));
        }

        if self.stats.security_products > 0 || !self.security_products.is_empty() {
            let count = if self.stats.security_products > 0 {
                self.stats.security_products
            } else {
                self.security_products.len()
            };
            findings.push(format!("🛡️ 检测到 {} 个安全产品 — 需规避", count));
        }

        if self.stats.potential_vulnerabilities > 0 {
            findings.push(format!(
                "⚠️ 发现 {} 个潜在漏洞",
                self.stats.potential_vulnerabilities
            ));
        }

        for session in &self.user_sessions {
            if session.is_domain_admin {
                findings.push(format!(
                    "  ➤ 域管 {} 登录在 {} (会话ID: {})",
                    session.username, session.computer, session.session_id
                ));
            }
        }

        findings
    }
}

// ============================================================
// 侦察引擎
// ============================================================

/// 侦察引擎 — 统一的信息收集入口
pub struct ReconEngine {
    /// 目标主机名
    _hostname: String,
    /// 域名
    domain: Option<String>,
    /// 域控制器
    domain_controller: Option<String>,
    /// 结果
    report: ReconReport,
}

impl ReconEngine {
    /// 创建侦察引擎
    pub fn new(hostname: &str) -> Self {
        Self {
            _hostname: hostname.to_string(),
            domain: None,
            domain_controller: None,
            report: ReconReport::new(hostname),
        }
    }

    /// 设置域信息
    pub fn with_domain(mut self, domain: &str, dc: Option<&str>) -> Self {
        self.domain = Some(domain.to_string());
        self.domain_controller = dc.map(|s| s.to_string());
        self
    }

    /// 运行完整侦察
    pub async fn run_full_recon(&mut self) -> ReconReport {
        let start = Utc::now();

        // 1. 环境态势感知
        if let Ok(info) = situational::collect_situational_awareness() {
            self.report.situational = Some(info);
        }

        // 2. 主机详细信息
        if let Ok(info) = host_info::collect_host_info() {
            self.report.host_info = Some(info);
        }

        // 3. 安全软件检测
        if let Ok(products) = edr_detect::detect_security_products() {
            self.report.security_products = products;
        }

        // 4. 用户会话猎杀（需要域环境）
        if let Some(ref domain) = self.domain {
            if let Some(ref dc) = self.domain_controller {
                if let Ok(sessions) = user_hunting::hunt_user_sessions(dc, domain) {
                    self.report.user_sessions = sessions;
                }
            }
        }

        // 5. 文件共享搜索
        if let Ok(findings) = share_hunting::scan_network_shares() {
            self.report.share_findings = findings;
        }

        // 6. 防火墙规则收集
        if let Ok(rules) = firewall::collect_firewall_rules() {
            self.report.firewall_rules = rules;
        }

        // 7. VLAN发现
        if let Ok(topology) = vlan::discover_network_topology() {
            self.report.network_topology = Some(topology);
        }

        let end = Utc::now();
        self.report.start_time = start;
        self.report.end_time = end;
        self.report.duration_secs = (end - start).num_milliseconds() as f64 / 1000.0;
        self.report.compute_stats();

        self.report.clone()
    }

    /// 获取报告引用
    pub fn get_report(&self) -> &ReconReport {
        &self.report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recon_report_new() {
        let report = ReconReport::new("TEST-PC");
        assert_eq!(report.hostname, "TEST-PC");
        assert!(report.situational.is_none());
        assert!(report.security_products.is_empty());
    }

    #[test]
    fn test_recon_stats_default() {
        let stats = ReconStats::default();
        assert_eq!(stats.alive_hosts, 0);
        assert_eq!(stats.domain_admins, 0);
        assert_eq!(stats.sensitive_files, 0);
    }

    #[test]
    fn test_vuln_severity_display() {
        assert_eq!(VulnSeverity::Critical.to_string(), "严重");
        assert_eq!(VulnSeverity::High.to_string(), "高");
        assert_eq!(VulnSeverity::Info.to_string(), "信息");
    }

    #[test]
    fn test_vuln_severity_ordering() {
        assert!(VulnSeverity::Critical > VulnSeverity::High);
        assert!(VulnSeverity::High > VulnSeverity::Medium);
        assert!(VulnSeverity::Low > VulnSeverity::Info);
    }

    #[test]
    fn test_recon_report_high_value() {
        let mut report = ReconReport::new("TEST-PC");
        report.stats.da_sessions = 3;
        report.stats.credential_references = 5;
        report.stats.security_products = 2;

        let findings = report.high_value_findings();
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.contains("域管理员")));
        assert!(findings.iter().any(|f| f.contains("安全产品")));
    }

    #[test]
    fn test_network_adapter() {
        let adapter = NetworkAdapter {
            name: "Ethernet0".to_string(),
            ip_addresses: vec!["10.10.10.10".to_string()],
            mac_address: Some("00:11:22:33:44:55".to_string()),
            dns_servers: vec!["10.10.10.2".to_string()],
            subnet_mask: Some("255.255.255.0".to_string()),
            default_gateway: Some("10.10.10.1".to_string()),
        };
        assert_eq!(adapter.name, "Ethernet0");
        assert_eq!(adapter.ip_addresses.len(), 1);
    }

    #[test]
    fn test_discovered_subnet() {
        let subnet = DiscoveredSubnet {
            subnet: "10.10.10.0/24".to_string(),
            host_count: 42,
            is_current: true,
            reachable: true,
            description: Some("服务器网段".to_string()),
        };
        assert!(subnet.is_current);
        assert_eq!(subnet.host_count, 42);
    }
}
