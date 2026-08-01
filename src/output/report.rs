//! 专业渗透测试报告生成模块
//!
//! 包含执行摘要、时间线、攻击步骤、发现摘要和修复建议。
//!
//! 输出格式：Markdown（可被pandoc转为PDF/HTML）

use serde::{Deserialize, Serialize};

/// 报告生成器
pub struct ReportGenerator;

/// 报告类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReportType {
    /// 完整渗透测试报告
    Full,
    /// 执行摘要（面向管理层）
    Executive,
    /// 技术详情（面向安全团队）
    Technical,
}

/// 攻击链报告
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackChainReport {
    /// 报告标题
    pub title: String,
    /// 目标组织
    pub target_organization: String,
    /// 报告日期
    pub report_date: String,
    /// 攻击起点
    pub entry_point: String,
    /// 最终目标
    pub final_objective: String,
    /// 攻击步骤
    pub steps: Vec<ReportStep>,
    /// 发现列表
    pub findings: Vec<ReportFinding>,
    /// 时间线
    pub timeline: Vec<TimelineEntry>,
    /// 涉及的主机
    pub compromised_hosts: Vec<CompromisedHost>,
    /// 窃取的凭据
    pub stolen_credentials: usize,
    /// 风险评分
    pub risk_score: u32,
}

/// 攻击步骤
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportStep {
    pub step_number: usize,
    pub phase: String,
    pub title: String,
    pub description: String,
    pub source_host: String,
    pub target_host: Option<String>,
    pub technique: String,
    pub mitre_id: Option<String>,
    pub success: bool,
    pub evidence: Option<String>,
}

/// 报告发现
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportFinding {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: FindingSeverity,
    pub affected_hosts: Vec<String>,
    pub recommendation: String,
    pub cvss_score: Option<f64>,
}

/// 发现严重程度
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum FindingSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for FindingSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FindingSeverity::Info => write!(f, "信息"),
            FindingSeverity::Low => write!(f, "低"),
            FindingSeverity::Medium => write!(f, "中"),
            FindingSeverity::High => write!(f, "高"),
            FindingSeverity::Critical => write!(f, "严重"),
        }
    }
}

/// 时间线条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub timestamp: String,
    pub event: String,
    pub phase: String,
    pub host: Option<String>,
}

/// 被攻陷主机
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompromisedHost {
    pub hostname: String,
    pub ip_address: Option<String>,
    pub os: String,
    pub compromise_method: String,
    pub level: AccessLevel,
    pub credentials_extracted: bool,
}

/// 访问级别
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AccessLevel {
    Limited,
    User,
    LocalAdmin,
    System,
    DomainAdmin,
}

impl std::fmt::Display for AccessLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AccessLevel::Limited => write!(f, "受限用户"),
            AccessLevel::User => write!(f, "普通用户"),
            AccessLevel::LocalAdmin => write!(f, "本地管理员"),
            AccessLevel::System => write!(f, "SYSTEM"),
            AccessLevel::DomainAdmin => write!(f, "域管理员"),
        }
    }
}

impl ReportGenerator {
    /// 生成执行摘要
    pub fn generate_executive_summary(report: &AttackChainReport) -> String {
        let mut summary = String::new();

        summary.push_str("# 渗透测试执行摘要\n\n");
        summary.push_str(&format!("**目标组织**: {}\n", report.target_organization));
        summary.push_str(&format!("**测试日期**: {}\n", report.report_date));
        summary.push_str(&format!("**风险评分**: {}/100\n\n", report.risk_score));

        summary.push_str("## 概述\n\n");
        summary.push_str(&format!(
            "本次渗透测试通过 {} 漏洞进入内网，经过 {} 步攻击操作，\
            最终获得了 {} 的完全控制权限。整个攻击过程涉及 {} 台主机，\
            提取了 {} 个账户凭据。\n\n",
            report.entry_point,
            report.steps.len(),
            report.final_objective,
            report.compromised_hosts.len(),
            report.stolen_credentials,
        ));

        summary.push_str("## 关键发现\n\n");
        let critical_findings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.severity >= FindingSeverity::High)
            .collect();

        if critical_findings.is_empty() {
            summary.push_str("未发现严重或高危漏洞。\n");
        } else {
            for (i, finding) in critical_findings.iter().enumerate() {
                summary.push_str(&format!(
                    "### {}. {} ({}严重)\n{}\n\n**建议**: {}\n\n",
                    i + 1,
                    finding.title,
                    finding.severity,
                    finding.description,
                    finding.recommendation,
                ));
            }
        }

        summary.push_str("## 攻击路径摘要\n\n");
        for step in &report.steps {
            let target = step.target_host.as_deref().unwrap_or("N/A");
            summary.push_str(&format!(
                "{}: {} ({} → {})\n",
                step.step_number, step.description, step.source_host, target
            ));
        }

        summary
    }

    /// 生成完整Markdown报告
    pub fn generate_full_report(report: &AttackChainReport) -> String {
        let mut md = String::new();

        // 标题页
        md.push_str(&format!(
            "# {} 渗透测试报告\n\n",
            report.target_organization
        ));
        md.push_str(&format!("**报告日期**: {}\n\n", report.report_date));
        md.push_str("---\n\n");

        // 目录
        md.push_str("## 目录\n\n");
        md.push_str("1. [执行摘要](#执行摘要)\n");
        md.push_str("2. [攻击链详情](#攻击链详情)\n");
        md.push_str("3. [时间线](#时间线)\n");
        md.push_str("4. [发现清单](#发现清单)\n");
        md.push_str("5. [被攻陷主机](#被攻陷主机)\n");
        md.push_str("6. [修复建议](#修复建议)\n");
        md.push_str("7. [附录: MITRE ATT&CK映射](#附录)\n\n");
        md.push_str("---\n\n");

        // 执行摘要
        md.push_str("# 执行摘要\n\n");
        md.push_str(&Self::generate_executive_summary(report));

        // 攻击链详情
        md.push_str("# 攻击链详情\n\n");
        md.push_str("## 攻击入口\n\n");
        md.push_str(&format!("攻击起点: {}\n\n", report.entry_point));

        md.push_str("## 攻击步骤\n\n");
        for step in &report.steps {
            md.push_str(&format!(
                "### 步骤 {}: {} ({})\n\n",
                step.step_number, step.title, step.phase
            ));
            md.push_str(&format!("**描述**: {}\n\n", step.description));
            md.push_str(&format!("**来源主机**: {}\n", step.source_host));
            if let Some(ref target) = step.target_host {
                md.push_str(&format!("**目标主机**: {}\n", target));
            }
            md.push_str(&format!("**技术**: {}\n", step.technique));
            if let Some(ref mitre) = step.mitre_id {
                md.push_str(&format!("**MITRE ATT&CK**: {}\n", mitre));
            }
            if let Some(ref evidence) = step.evidence {
                md.push_str(&format!("\n**证据**:\n```\n{}\n```\n", evidence));
            }
            md.push('\n');
        }

        // 时间线
        md.push_str("# 时间线\n\n");
        md.push_str("| 时间 | 事件 | 阶段 | 主机 |\n");
        md.push_str("|------|------|------|------|\n");
        for entry in &report.timeline {
            md.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                entry.timestamp,
                entry.event,
                entry.phase,
                entry.host.as_deref().unwrap_or("N/A"),
            ));
        }

        // 发现清单
        md.push_str("\n# 发现清单\n\n");
        for finding in &report.findings {
            let emoji = match finding.severity {
                FindingSeverity::Critical => "🔴",
                FindingSeverity::High => "🟠",
                FindingSeverity::Medium => "🟡",
                FindingSeverity::Low => "🟢",
                FindingSeverity::Info => "🔵",
            };
            md.push_str(&format!(
                "## {} {} - {} ({})\n\n",
                emoji, finding.id, finding.title, finding.severity
            ));
            md.push_str(&format!("**描述**: {}\n\n", finding.description));
            md.push_str(&format!(
                "**影响主机**: {}\n\n",
                finding.affected_hosts.join(", ")
            ));
            if let Some(cvss) = finding.cvss_score {
                md.push_str(&format!("**CVSS评分**: {}\n\n", cvss));
            }
            md.push_str(&format!("**修复建议**: {}\n\n", finding.recommendation));
        }

        // 被攻陷主机
        md.push_str("# 被攻陷主机\n\n");
        md.push_str("| 主机名 | IP | 操作系统 | 入侵方式 | 访问级别 | 凭据提取 |\n");
        md.push_str("|--------|-----|----------|----------|----------|----------|\n");
        for host in &report.compromised_hosts {
            md.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} |\n",
                host.hostname,
                host.ip_address.as_deref().unwrap_or("N/A"),
                host.os,
                host.compromise_method,
                host.level,
                if host.credentials_extracted {
                    "是"
                } else {
                    "否"
                },
            ));
        }

        // 修复建议
        md.push_str("\n# 修复建议\n\n");
        md.push_str("## 即时修复（0-7天）\n\n");
        for finding in report
            .findings
            .iter()
            .filter(|f| f.severity >= FindingSeverity::High)
        {
            md.push_str(&format!("- {}\n", finding.recommendation));
        }

        md.push_str("\n## 短期修复（7-30天）\n\n");
        for finding in report
            .findings
            .iter()
            .filter(|f| f.severity == FindingSeverity::Medium)
        {
            md.push_str(&format!("- {}\n", finding.recommendation));
        }

        md.push_str("\n## 长期改进（30-90天）\n\n");
        md.push_str("- 实施最小权限原则，审计所有特权账户\n");
        md.push_str("- 部署EDR/XDR解决方案，增强终端检测能力\n");
        md.push_str("- 实施网络分段和零信任架构\n");
        md.push_str("- 建立安全监控和事件响应流程\n");
        md.push_str("- 定期进行渗透测试和安全评估\n");

        // MITRE ATT&CK映射
        md.push_str("\n# 附录: MITRE ATT&CK映射\n\n");
        let unique_mitre: std::collections::BTreeSet<_> = report
            .steps
            .iter()
            .filter_map(|s| s.mitre_id.as_ref())
            .collect();

        md.push_str("| 技术ID | 技术名称 |\n");
        md.push_str("|--------|----------|\n");
        for mitre_id in &unique_mitre {
            md.push_str(&format!(
                "| {} | {} |\n",
                mitre_id,
                mitre_technique_name(mitre_id)
            ));
        }

        md
    }

    /// 生成HTML报告（自包含）
    pub fn generate_html_report(report: &AttackChainReport) -> String {
        let md_content = Self::generate_full_report(report);

        // 简单的Markdown到HTML转换
        format!(
            r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>渗透测试报告 - {}</title>
<style>
body {{ font-family: 'Segoe UI', Arial, sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; color: #333; }}
h1 {{ color: #1a1a2e; border-bottom: 3px solid #e94560; padding-bottom: 10px; }}
h2 {{ color: #16213e; border-bottom: 2px solid #0f3460; padding-bottom: 8px; }}
h3 {{ color: #533483; }}
table {{ border-collapse: collapse; width: 100%; margin: 15px 0; }}
th, td {{ border: 1px solid #ddd; padding: 8px 12px; text-align: left; }}
th {{ background-color: #16213e; color: white; }}
tr:nth-child(even) {{ background-color: #f8f9fa; }}
.severity-critical {{ color: #dc3545; font-weight: bold; }}
.severity-high {{ color: #fd7e14; font-weight: bold; }}
.severity-medium {{ color: #ffc107; }}
.severity-low {{ color: #198754; }}
pre {{ background-color: #1a1a2e; color: #0f0; padding: 15px; border-radius: 5px; overflow-x: auto; }}
</style>
</head>
<body>
<pre style="white-space: pre-wrap;">{}</pre>
<footer style="margin-top: 50px; padding-top: 20px; border-top: 1px solid #ddd; text-align: center; color: #666;">
<p>本报告由 IntraSweep 自动生成 | 仅供授权安全评估使用</p>
</footer>
</body>
</html>"#,
            report.target_organization, md_content,
        )
    }

    /// 导出为JSON
    pub fn export_json(report: &AttackChainReport) -> String {
        serde_json::to_string_pretty(report).unwrap_or_default()
    }
}

/// MITRE ATT&CK技术名称映射
fn mitre_technique_name(id: &str) -> String {
    match id {
        "T1003.001" => "LSASS内存凭据窃取".to_string(),
        "T1003.002" => "SAM凭据窃取".to_string(),
        "T1003.006" => "DCSync".to_string(),
        "T1021.002" => "SMB/Windows管理共享".to_string(),
        "T1021.003" => "分布式COM (DCOM)".to_string(),
        "T1021.006" => "WinRM".to_string(),
        "T1047" => "Windows Management Instrumentation (WMI)".to_string(),
        "T1053.005" => "计划任务".to_string(),
        "T1059.001" => "PowerShell".to_string(),
        "T1068" => "特权提升利用".to_string(),
        "T1078" => "有效账户".to_string(),
        "T1082" => "系统信息发现".to_string(),
        "T1087.002" => "域账户发现".to_string(),
        "T1098" => "账户操纵".to_string(),
        "T1134.001" => "令牌窃取/模拟".to_string(),
        "T1136.001" => "创建账户: 本地账户".to_string(),
        "T1190" => "利用面向公众应用".to_string(),
        "T1208" => "Kerberoasting".to_string(),
        "T1482" => "域信任发现".to_string(),
        "T1550.002" => "哈希传递 (Pass-the-Hash)".to_string(),
        "T1550.003" => "票据传递 (Pass-the-Ticket)".to_string(),
        "T1558.001" => "Golden Ticket".to_string(),
        "T1558.002" => "Silver Ticket".to_string(),
        "T1558.003" => "Kerberoasting".to_string(),
        "T1558.004" => "AS-REP Roasting".to_string(),
        "T1574.001" => "DLL搜索顺序劫持".to_string(),
        "T1562.001" => "禁用或修改安全工具".to_string(),
        _ => "未知技术".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_sample_report() -> AttackChainReport {
        AttackChainReport {
            title: "测试渗透报告".to_string(),
            target_organization: "CORP.LOCAL".to_string(),
            report_date: "2026-06-11".to_string(),
            entry_point: "Web服务器文件上传漏洞".to_string(),
            final_objective: "域控制器 (DC01)".to_string(),
            steps: vec![
                ReportStep {
                    step_number: 1,
                    phase: "初始访问".to_string(),
                    title: "Web漏洞利用".to_string(),
                    description: "利用CMS文件上传漏洞获取WebShell".to_string(),
                    source_host: "攻击者 (138.68.164.54)".to_string(),
                    target_host: Some("WEB01 (10.10.10.10)".to_string()),
                    technique: "Metasploit exploit".to_string(),
                    mitre_id: Some("T1190".to_string()),
                    success: true,
                    evidence: Some("Meterpreter session opened".to_string()),
                },
                ReportStep {
                    step_number: 2,
                    phase: "横向移动".to_string(),
                    title: "PsExec横向移动".to_string(),
                    description: "使用获取的Administrator哈希横向到DC01".to_string(),
                    source_host: "WEB01 (10.10.10.10)".to_string(),
                    target_host: Some("DC01 (10.10.10.2)".to_string()),
                    technique: "Pass-the-Hash + PsExec".to_string(),
                    mitre_id: Some("T1550.002".to_string()),
                    success: true,
                    evidence: Some("SYSTEM beacon on DC01".to_string()),
                },
            ],
            findings: vec![
                ReportFinding {
                    id: "F-001".to_string(),
                    title: "文件上传漏洞".to_string(),
                    description: "CMS允许未限制的文件上传".to_string(),
                    severity: FindingSeverity::Critical,
                    affected_hosts: vec!["WEB01".to_string()],
                    recommendation: "实施文件类型验证和上传隔离".to_string(),
                    cvss_score: Some(9.8),
                },
                ReportFinding {
                    id: "F-002".to_string(),
                    title: "密码复用".to_string(),
                    description: "多台服务器使用相同的本地管理员密码".to_string(),
                    severity: FindingSeverity::High,
                    affected_hosts: vec!["WEB01".to_string(), "DC01".to_string()],
                    recommendation: "部署LAPS实施唯一的本地管理员密码".to_string(),
                    cvss_score: Some(7.5),
                },
            ],
            timeline: vec![
                TimelineEntry {
                    timestamp: "09:00".to_string(),
                    event: "发现Web漏洞".to_string(),
                    phase: "侦察".to_string(),
                    host: Some("WEB01".to_string()),
                },
                TimelineEntry {
                    timestamp: "09:15".to_string(),
                    event: "获取WebShell".to_string(),
                    phase: "初始访问".to_string(),
                    host: Some("WEB01".to_string()),
                },
                TimelineEntry {
                    timestamp: "09:45".to_string(),
                    event: "提取凭据".to_string(),
                    phase: "凭据收集".to_string(),
                    host: Some("WEB01".to_string()),
                },
                TimelineEntry {
                    timestamp: "10:10".to_string(),
                    event: "横向移动到DC01".to_string(),
                    phase: "横向移动".to_string(),
                    host: Some("DC01".to_string()),
                },
                TimelineEntry {
                    timestamp: "10:15".to_string(),
                    event: "完全控制域控制器".to_string(),
                    phase: "达成目标".to_string(),
                    host: Some("DC01".to_string()),
                },
            ],
            compromised_hosts: vec![
                CompromisedHost {
                    hostname: "WEB01".to_string(),
                    ip_address: Some("10.10.10.10".to_string()),
                    os: "Windows Server 2016".to_string(),
                    compromise_method: "文件上传漏洞".to_string(),
                    level: AccessLevel::System,
                    credentials_extracted: true,
                },
                CompromisedHost {
                    hostname: "DC01".to_string(),
                    ip_address: Some("10.10.10.2".to_string()),
                    os: "Windows Server 2019".to_string(),
                    compromise_method: "Pass-the-Hash + PsExec".to_string(),
                    level: AccessLevel::DomainAdmin,
                    credentials_extracted: true,
                },
            ],
            stolen_credentials: 5,
            risk_score: 85,
        }
    }

    #[test]
    fn test_executive_summary() {
        let report = create_sample_report();
        let summary = ReportGenerator::generate_executive_summary(&report);
        assert!(summary.contains("CORP.LOCAL"));
        assert!(summary.contains("文件上传漏洞"));
        assert!(summary.contains("85"));
    }

    #[test]
    fn test_full_report() {
        let report = create_sample_report();
        let full = ReportGenerator::generate_full_report(&report);
        assert!(full.contains("# CORP.LOCAL 渗透测试报告"));
        assert!(full.contains("攻击链详情"));
        assert!(full.contains("F-001"));
        assert!(full.contains("T1190"));
        assert!(full.contains("WEB01"));
    }

    #[test]
    fn test_html_report() {
        let report = create_sample_report();
        let html = ReportGenerator::generate_html_report(&report);
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("CORP.LOCAL"));
        assert!(html.contains("<style>"));
    }

    #[test]
    fn test_json_export() {
        let report = create_sample_report();
        let json = ReportGenerator::export_json(&report);
        assert!(json.contains("CORP.LOCAL"));
        assert!(json.contains("WEB01"));
    }

    #[test]
    fn test_mitre_names() {
        assert_eq!(
            mitre_technique_name("T1550.002"),
            "哈希传递 (Pass-the-Hash)"
        );
        assert_eq!(mitre_technique_name("T1208"), "Kerberoasting");
        assert_eq!(mitre_technique_name("T1558.001"), "Golden Ticket");
    }

    #[test]
    fn test_finding_severity_display() {
        assert_eq!(FindingSeverity::Critical.to_string(), "严重");
        assert_eq!(FindingSeverity::High.to_string(), "高");
    }

    #[test]
    fn test_access_level_display() {
        assert_eq!(AccessLevel::DomainAdmin.to_string(), "域管理员");
        assert_eq!(AccessLevel::System.to_string(), "SYSTEM");
    }
}
