//! 漏洞扫描模块
//!
//! 提供基于 PoC 规则的漏洞扫描引擎，支持 HTTP/TCP/脚本 三种传输方式

pub mod builtin;
pub mod engine;
pub mod loader;
pub mod matchers;
pub mod poc;
pub mod script;
pub mod webprobe;

use chrono::{DateTime, Utc};
use poc::{PoCRule, Severity, Transport};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// 漏洞扫描配置
pub struct VulnScanConfig {
    pub targets: Vec<String>,
    pub pocs: Vec<PoCRule>,
    pub timeout: Duration,
    pub concurrency: usize,
    /// 外部 PoC 文件所在目录 (用于脚本 PoC 相对路径解析)
    pub poc_dir: Option<std::path::PathBuf>,
}

impl VulnScanConfig {
    pub fn new(targets: Vec<String>, pocs: Vec<PoCRule>) -> Self {
        Self {
            targets,
            pocs,
            timeout: Duration::from_secs(10),
            concurrency: 20,
            poc_dir: None,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_concurrency(mut self, concurrency: usize) -> Self {
        self.concurrency = concurrency;
        self
    }

    pub fn with_poc_dir(mut self, dir: std::path::PathBuf) -> Self {
        self.poc_dir = Some(dir);
        self
    }
}

/// 单条漏洞发现
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnResult {
    pub target: String,
    pub port: u16,
    pub vuln_id: String,
    pub vuln_name: String,
    pub severity: Severity,
    pub category: String,
    pub description: String,
    pub evidence: String,
    pub remediation: String,
}

/// 漏洞扫描聚合结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnScanResult {
    pub targets: Vec<String>,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub duration_secs: f64,
    pub findings: Vec<VulnResult>,
    pub stats: VulnScanStats,
}

/// 漏洞扫描统计
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnScanStats {
    pub total_targets: usize,
    pub total_pocs: usize,
    pub total_requests: usize,
    pub vulnerabilities_found: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
}

/// 漏洞扫描器
pub struct VulnScanner {
    config: VulnScanConfig,
}

impl VulnScanner {
    pub fn new(config: VulnScanConfig) -> Self {
        Self { config }
    }

    /// 运行漏洞扫描
    pub async fn scan(&self) -> VulnScanResult {
        let start_time = Utc::now();
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.config.concurrency));
        let mut tasks = Vec::new();

        let total_requests = self.config.targets.len() * self.config.pocs.len();
        let poc_dir = self.config.poc_dir.clone();

        for target in &self.config.targets {
            let (ip, default_port) = parse_target(target);
            for poc in &self.config.pocs {
                let sem = semaphore.clone();
                let ip = ip.clone();
                let poc = poc.clone();
                let timeout = self.config.timeout;
                let poc_dir = poc_dir.clone();

                tasks.push(tokio::spawn(async move {
                    let _permit = sem.acquire().await.ok()?;
                    execute_poc(&ip, default_port, &poc, timeout, poc_dir.as_deref()).await
                }));
            }
        }

        let mut findings = Vec::new();
        let mut completed = 0usize;
        let total = tasks.len();

        for task in tasks {
            if let Ok(Some(result)) = task.await {
                findings.push(result);
            }
            completed += 1;
            if completed.is_multiple_of(50) || completed == total {
                tracing::debug!(
                    "漏洞扫描进度: {}/{} ({:.1}%)",
                    completed,
                    total,
                    completed as f64 / total as f64 * 100.0
                );
            }
        }

        let end_time = Utc::now();
        let duration = (end_time - start_time).num_milliseconds() as f64 / 1000.0;

        let stats = VulnScanStats {
            total_targets: self.config.targets.len(),
            total_pocs: self.config.pocs.len(),
            total_requests,
            vulnerabilities_found: findings.len(),
            critical_count: findings
                .iter()
                .filter(|f| f.severity == Severity::Critical)
                .count(),
            high_count: findings
                .iter()
                .filter(|f| f.severity == Severity::High)
                .count(),
            medium_count: findings
                .iter()
                .filter(|f| f.severity == Severity::Medium)
                .count(),
            low_count: findings
                .iter()
                .filter(|f| f.severity == Severity::Low)
                .count(),
            info_count: findings
                .iter()
                .filter(|f| f.severity == Severity::Info)
                .count(),
        };

        VulnScanResult {
            targets: self.config.targets.clone(),
            start_time,
            end_time,
            duration_secs: duration,
            findings,
            stats,
        }
    }
}

/// 解析目标地址
fn parse_target(target: &str) -> (String, u16) {
    if target.starts_with('[') {
        if let Some(bracket_end) = target.find(']') {
            let ip = target[1..bracket_end].to_string();
            if target.len() > bracket_end + 1 && &target[bracket_end + 1..bracket_end + 2] == ":" {
                if let Ok(port) = target[bracket_end + 2..].parse::<u16>() {
                    return (ip, port);
                }
            }
            return (ip, 0);
        }
    }

    if let Some(idx) = target.rfind(':') {
        if let Ok(port) = target[idx + 1..].parse::<u16>() {
            return (target[..idx].to_string(), port);
        }
    }

    (target.to_string(), 0)
}

/// 执行单个 PoC 检测 (支持 HTTP/TCP/脚本 三种传输 + 多步骤变量传递)
async fn execute_poc(
    target: &str,
    port: u16,
    poc: &PoCRule,
    timeout: Duration,
    poc_dir: Option<&std::path::Path>,
) -> Option<VulnResult> {
    // 脚本 PoC 走独立路径
    if poc.transport == Transport::Script {
        return execute_script_poc(target, port, poc, poc_dir).await;
    }

    // 多步骤 PoC: 步骤间通过 vars 传递变量
    let mut vars = HashMap::new();
    vars.insert("target".to_string(), target.to_string());
    vars.insert("port".to_string(), port.to_string());

    for request in &poc.rules {
        let actual_port = if port > 0 {
            port
        } else {
            poc.default_port.unwrap_or(80)
        };

        let matched = match poc.transport {
            Transport::Http => {
                match engine::execute_http_request(target, actual_port, request, timeout, &vars)
                    .await
                {
                    Ok(ctx) => {
                        // 先提取变量 (无论是否匹配都提取，供后续步骤使用)
                        let extracted = engine::extract_http_vars(&ctx, &request.extractors);
                        vars.extend(extracted);

                        let matched = matchers::match_http_response(
                            &request.matchers,
                            &request.matchers_condition,
                            &ctx,
                        );
                        if matched && poc.rules.last() == Some(request) {
                            let evidence = ctx.body.chars().take(200).collect();
                            return Some(VulnResult {
                                target: target.to_string(),
                                port: actual_port,
                                vuln_id: poc.id.clone(),
                                vuln_name: poc.info.name.clone(),
                                severity: poc.info.severity,
                                category: poc.info.category.clone(),
                                description: poc.info.description.clone(),
                                evidence,
                                remediation: poc.info.remediation.clone(),
                            });
                        }
                        matched
                    }
                    Err(_) => false,
                }
            }
            Transport::Tcp => {
                match engine::execute_tcp_request(target, actual_port, request, timeout, &vars)
                    .await
                {
                    Ok(ctx) => {
                        let extracted = engine::extract_tcp_vars(&ctx.data, &request.extractors);
                        vars.extend(extracted);

                        let matched = matchers::match_tcp_response(
                            &request.matchers,
                            &request.matchers_condition,
                            &ctx.data,
                        );
                        if matched && poc.rules.last() == Some(request) {
                            let evidence: String = String::from_utf8_lossy(&ctx.data)
                                .chars()
                                .take(200)
                                .collect();
                            return Some(VulnResult {
                                target: target.to_string(),
                                port: actual_port,
                                vuln_id: poc.id.clone(),
                                vuln_name: poc.info.name.clone(),
                                severity: poc.info.severity,
                                category: poc.info.category.clone(),
                                description: poc.info.description.clone(),
                                evidence,
                                remediation: poc.info.remediation.clone(),
                            });
                        }
                        matched
                    }
                    Err(_) => false,
                }
            }
            Transport::Script => unreachable!(),
        };

        if !matched {
            return None;
        }
    }
    None
}

/// 执行脚本 PoC
async fn execute_script_poc(
    target: &str,
    port: u16,
    poc: &PoCRule,
    poc_dir: Option<&std::path::Path>,
) -> Option<VulnResult> {
    let script_config = poc.script.as_ref()?;

    let output = script::execute_script(script_config, target, port, poc_dir).await?;

    if output.vulnerable {
        Some(VulnResult {
            target: target.to_string(),
            port: poc.default_port.unwrap_or(port),
            vuln_id: poc.id.clone(),
            vuln_name: poc.info.name.clone(),
            severity: poc.info.severity,
            category: poc.info.category.clone(),
            description: poc.info.description.clone(),
            evidence: output.evidence,
            remediation: poc.info.remediation.clone(),
        })
    } else {
        None
    }
}

/// 解析 CIDR/范围/单个IP 为目标列表
pub fn expand_targets(targets: &[String]) -> Vec<String> {
    let mut expanded = Vec::new();

    for target in targets {
        if target.contains('/') {
            if let Ok(network) = target.parse::<ipnet::Ipv4Net>() {
                for ip in network.hosts() {
                    expanded.push(ip.to_string());
                }
                continue;
            }
        }

        if target.contains('-') && !target.contains(':') {
            let parts: Vec<&str> = target.split('-').collect();
            if parts.len() == 2 {
                // Try parsing as IP range like "192.168.1.1-192.168.1.3"
                if let (Ok(start_ip), Ok(end_ip)) = (
                    parts[0].parse::<std::net::Ipv4Addr>(),
                    parts[1].parse::<std::net::Ipv4Addr>(),
                ) {
                    let start_octets = start_ip.octets();
                    let end_octets = end_ip.octets();
                    if start_octets[0..3] == end_octets[0..3] && start_octets[3] <= end_octets[3] {
                        for last in start_octets[3]..=end_octets[3] {
                            let mut octets = start_octets;
                            octets[3] = last;
                            expanded.push(std::net::Ipv4Addr::from(octets).to_string());
                        }
                        continue;
                    }
                }
                // Fallback: try parsing as pure integer range
                if let (Ok(start), Ok(end)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>()) {
                    for num in start..=end {
                        expanded.push(std::net::Ipv4Addr::from(num).to_string());
                    }
                    continue;
                }
            }
        }

        expanded.push(target.clone());
    }

    expanded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_target_ip_port() {
        let (ip, port) = parse_target("192.168.1.1:8080");
        assert_eq!(ip, "192.168.1.1");
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_parse_target_ip_only() {
        let (ip, port) = parse_target("192.168.1.1");
        assert_eq!(ip, "192.168.1.1");
        assert_eq!(port, 0);
    }

    #[test]
    fn test_expand_targets_cidr() {
        let targets = vec!["192.168.1.0/30".to_string()];
        let expanded = expand_targets(&targets);
        assert_eq!(expanded.len(), 2);
    }

    #[test]
    fn test_expand_targets_range() {
        let targets = vec!["192.168.1.1-192.168.1.3".to_string()];
        let expanded = expand_targets(&targets);
        assert_eq!(expanded.len(), 3);
    }
}
