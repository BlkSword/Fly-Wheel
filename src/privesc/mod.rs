//! 后渗透提权模块
//!
//! Windows/Linux 提权检查，检测系统配置错误、敏感文件、可利用权限等

pub mod linux;
pub mod windows;

use serde::{Deserialize, Serialize};

/// 提权检查结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivescResult {
    pub hostname: String,
    pub os: String,
    pub current_user: String,
    pub is_admin: bool,
    pub findings: Vec<PrivescFinding>,
    pub stats: PrivescStats,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PrivescStats {
    pub total_checks: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
}

/// 单条提权发现
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivescFinding {
    pub category: String,
    pub severity: PrivescSeverity,
    pub title: String,
    pub description: String,
    pub detail: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrivescSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl PrivescSeverity {
    pub fn display_name(&self) -> &str {
        match self {
            PrivescSeverity::Critical => "严重",
            PrivescSeverity::High => "高危",
            PrivescSeverity::Medium => "中危",
            PrivescSeverity::Low => "低危",
            PrivescSeverity::Info => "信息",
        }
    }

    pub fn color_code(&self) -> &str {
        match self {
            PrivescSeverity::Critical => "\x1b[31m",
            PrivescSeverity::High => "\x1b[33m",
            PrivescSeverity::Medium => "\x1b[36m",
            PrivescSeverity::Low => "\x1b[32m",
            PrivescSeverity::Info => "\x1b[37m",
        }
    }
}

/// 运行所有提权检查
pub fn run_all_checks() -> PrivescResult {
    #[cfg(windows)]
    {
        windows::run_checks()
    }
    #[cfg(not(windows))]
    {
        linux::run_checks()
    }
}

/// 运行指定类别的检查
pub fn run_check(category: &str) -> Vec<PrivescFinding> {
    #[cfg(windows)]
    {
        windows::run_category(category)
    }
    #[cfg(not(windows))]
    {
        linux::run_category(category)
    }
}

/// 获取可用检查类别列表
pub fn available_categories() -> Vec<&'static str> {
    #[cfg(windows)]
    {
        vec![
            "service",
            "credentials",
            "registry",
            "tokens",
            "files",
            "patches",
            "dll",
            "all",
        ]
    }
    #[cfg(not(windows))]
    {
        vec![
            "suid",
            "capabilities",
            "cron",
            "writable",
            "docker",
            "sudo",
            "ssh",
            "kernel",
            "all",
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_finding(severity: PrivescSeverity, category: &str) -> PrivescFinding {
        PrivescFinding {
            category: category.to_string(),
            severity,
            title: "测试发现".to_string(),
            description: "测试描述".to_string(),
            detail: "测试详情".to_string(),
            remediation: "测试修复建议".to_string(),
        }
    }

    #[test]
    fn test_severity_display_name() {
        assert_eq!(PrivescSeverity::Critical.display_name(), "严重");
        assert_eq!(PrivescSeverity::High.display_name(), "高危");
        assert_eq!(PrivescSeverity::Medium.display_name(), "中危");
        assert_eq!(PrivescSeverity::Low.display_name(), "低危");
        assert_eq!(PrivescSeverity::Info.display_name(), "信息");
    }

    #[test]
    fn test_severity_color_code() {
        assert_eq!(PrivescSeverity::Critical.color_code(), "\x1b[31m");
        assert_eq!(PrivescSeverity::High.color_code(), "\x1b[33m");
        assert_eq!(PrivescSeverity::Medium.color_code(), "\x1b[36m");
        assert_eq!(PrivescSeverity::Low.color_code(), "\x1b[32m");
        assert_eq!(PrivescSeverity::Info.color_code(), "\x1b[37m");
    }

    #[test]
    fn test_severity_eq() {
        assert_eq!(PrivescSeverity::Critical, PrivescSeverity::Critical);
        assert_ne!(PrivescSeverity::Critical, PrivescSeverity::High);
        assert_ne!(PrivescSeverity::Low, PrivescSeverity::Info);
    }

    #[test]
    fn test_available_categories_not_empty() {
        let cats = available_categories();
        assert!(!cats.is_empty());
        assert!(cats.contains(&"all"));
    }

    #[test]
    fn test_available_categories_platform() {
        let cats = available_categories();
        // 非 Windows 平台应包含 Linux 特有类别
        #[cfg(not(windows))]
        {
            assert!(cats.contains(&"suid"));
            assert!(cats.contains(&"capabilities"));
            assert!(cats.contains(&"docker"));
            assert!(cats.contains(&"sudo"));
            assert!(cats.contains(&"ssh"));
            assert!(cats.contains(&"kernel"));
        }
        // Windows 平台应包含 Windows 特有类别
        #[cfg(windows)]
        {
            assert!(cats.contains(&"service"));
            assert!(cats.contains(&"registry"));
            assert!(cats.contains(&"tokens"));
            assert!(cats.contains(&"patches"));
        }
    }

    #[test]
    fn test_privesc_stats_default() {
        let stats = PrivescStats::default();
        assert_eq!(stats.total_checks, 0);
        assert_eq!(stats.critical_count, 0);
        assert_eq!(stats.high_count, 0);
        assert_eq!(stats.medium_count, 0);
        assert_eq!(stats.low_count, 0);
        assert_eq!(stats.info_count, 0);
    }

    #[test]
    fn test_privesc_stats_manual() {
        let stats = PrivescStats {
            total_checks: 10,
            critical_count: 2,
            high_count: 3,
            medium_count: 1,
            low_count: 2,
            info_count: 2,
        };
        assert_eq!(stats.total_checks, 10);
        assert_eq!(stats.critical_count, 2);
        assert_eq!(
            stats.high_count
                + stats.medium_count
                + stats.low_count
                + stats.info_count
                + stats.critical_count,
            10
        );
    }

    #[test]
    fn test_privesc_finding_construction() {
        let finding = make_finding(PrivescSeverity::High, "sudo");
        assert_eq!(finding.category, "sudo");
        assert_eq!(finding.severity, PrivescSeverity::High);
        assert_eq!(finding.title, "测试发现");
        assert!(!finding.description.is_empty());
        assert!(!finding.detail.is_empty());
        assert!(!finding.remediation.is_empty());
    }

    #[test]
    fn test_privesc_result_construction() {
        let findings = vec![
            make_finding(PrivescSeverity::Critical, "kernel"),
            make_finding(PrivescSeverity::High, "sudo"),
            make_finding(PrivescSeverity::Medium, "docker"),
            make_finding(PrivescSeverity::Low, "ssh"),
        ];
        let result = PrivescResult {
            hostname: "test-host".to_string(),
            os: "Linux".to_string(),
            current_user: "root".to_string(),
            is_admin: true,
            findings,
            stats: PrivescStats {
                total_checks: 4,
                critical_count: 1,
                high_count: 1,
                medium_count: 1,
                low_count: 1,
                info_count: 0,
            },
        };
        assert_eq!(result.hostname, "test-host");
        assert_eq!(result.os, "Linux");
        assert_eq!(result.current_user, "root");
        assert!(result.is_admin);
        assert_eq!(result.findings.len(), 4);
        assert_eq!(result.stats.total_checks, 4);
    }

    #[test]
    fn test_privesc_result_json_roundtrip() {
        let findings = vec![make_finding(PrivescSeverity::Critical, "kernel")];
        let result = PrivescResult {
            hostname: "test-host".to_string(),
            os: "Linux".to_string(),
            current_user: "admin".to_string(),
            is_admin: true,
            findings,
            stats: PrivescStats::default(),
        };

        let json = serde_json::to_string(&result).expect("序列化应成功");
        let deserialized: PrivescResult = serde_json::from_str(&json).expect("反序列化应成功");

        assert_eq!(deserialized.hostname, "test-host");
        assert_eq!(deserialized.os, "Linux");
        assert_eq!(deserialized.current_user, "admin");
        assert!(deserialized.is_admin);
        assert_eq!(deserialized.findings.len(), 1);
        assert_eq!(deserialized.findings[0].severity, PrivescSeverity::Critical);
    }

    #[test]
    fn test_privesc_finding_json_serialization() {
        let finding = make_finding(PrivescSeverity::High, "sudo");
        let json = serde_json::to_string(&finding).expect("序列化应成功");
        assert!(json.contains("sudo"));
        assert!(json.contains("High"));
        assert!(json.contains("测试发现"));
    }

    #[test]
    fn test_privesc_result_empty_findings() {
        let result = PrivescResult {
            hostname: "empty-host".to_string(),
            os: "Linux".to_string(),
            current_user: "user".to_string(),
            is_admin: false,
            findings: vec![],
            stats: PrivescStats::default(),
        };
        assert_eq!(result.findings.len(), 0);
        assert!(!result.is_admin);
        assert_eq!(result.stats.total_checks, 0);
    }

    #[test]
    fn test_privesc_severity_order() {
        // 验证严重性顺序: Critical > High > Medium > Low > Info
        let severities = [
            PrivescSeverity::Critical,
            PrivescSeverity::High,
            PrivescSeverity::Medium,
            PrivescSeverity::Low,
            PrivescSeverity::Info,
        ];
        for i in 0..severities.len() {
            for j in 0..severities.len() {
                if i == j {
                    assert_eq!(severities[i], severities[j]);
                } else if i < j {
                    assert_ne!(severities[i], severities[j]);
                }
            }
        }
    }
}
