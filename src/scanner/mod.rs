//! 扫描模块
//!
//! 提供高性能的主机扫描、端口扫描和域环境扫描功能

pub mod config;
pub mod domain;
pub mod host;
pub mod models;
pub mod port;
pub mod service;

pub use config::{ScanConfig, ScanPreset, HostScanMethod, PortScanMethod};
pub use host::HostScanner;
pub use models::{
    DomainTrust, DomainUser, HostResult, PortInfo, PortState, ScanResult, ScanStats, ScanType,
    ServiceInfo, ServicePrincipalName,
};
pub use port::{PortScanner, ProgressCallback};

use chrono::Utc;
use std::path::PathBuf;

/// 统一扫描器
///
/// 提供一站式扫描接口
pub struct Scanner {
    config: ScanConfig,
    progress_callback: Option<ProgressCallback>,
}

impl Scanner {
    /// 创建新的扫描器
    pub fn new(config: ScanConfig) -> Self {
        Self {
            config,
            progress_callback: None,
        }
    }

    /// 使用默认配置创建
    pub fn with_default_config() -> Self {
        Self::new(ScanConfig::default())
    }

    /// 使用快速扫描预设
    pub fn fast_scan() -> Self {
        Self::new(ScanConfig::fast_scan())
    }

    /// 设置进度回调
    pub fn with_progress_callback(mut self, callback: ProgressCallback) -> Self {
        self.progress_callback = Some(callback);
        self
    }

    /// 主机存活扫描
    pub async fn host_discovery(&self, targets: Vec<String>) -> ScanResult {
        let start_time = Utc::now();
        let host_scanner = HostScanner::new(self.config.clone());

        // 解析目标为IP地址
        let ip_targets = self.parse_targets(targets);

        // 执行扫描
        let hosts = host_scanner.discover_hosts(ip_targets).await;
        let end_time = Utc::now();
        let duration = (end_time - start_time).num_milliseconds() as f64 / 1000.0;

        let alive_count = hosts.iter().filter(|h| h.is_alive).count();

        ScanResult {
            scan_type: ScanType::HostDiscovery,
            targets: vec![],
            start_time,
            end_time,
            duration_secs: duration,
            hosts,
            stats: ScanStats {
                total_targets: 0,
                alive_hosts: alive_count,
                total_open_ports: 0,
                services_found: 0,
            },
        }
    }

    /// 端口扫描
    pub async fn port_scan(&self, targets: Vec<String>) -> ScanResult {
        let start_time = Utc::now();
        let mut port_scanner = PortScanner::new(self.config.clone());

        // 设置进度回调
        if let Some(cb) = &self.progress_callback {
            port_scanner = port_scanner.with_progress_callback(cb.clone());
        }

        // 解析目标为IP地址
        let ip_targets = self.parse_targets(targets);
        let ports = self.config.get_ports_to_scan();

        // 执行扫描
        let hosts = port_scanner.scan_hosts_ports(ip_targets, ports).await;
        let end_time = Utc::now();
        let duration = (end_time - start_time).num_milliseconds() as f64 / 1000.0;

        let open_ports_count: usize = hosts.iter().map(|h| h.open_ports.len()).sum();
        let alive_hosts_count = hosts.len();

        ScanResult {
            scan_type: ScanType::PortScan,
            targets: vec![],
            start_time,
            end_time,
            duration_secs: duration,
            hosts,
            stats: ScanStats {
                total_targets: 0,
                alive_hosts: alive_hosts_count,
                total_open_ports: open_ports_count,
                services_found: 0,
            },
        }
    }

    /// 综合扫描（主机发现 + 端口扫描）
    pub async fn comprehensive_scan(&self, targets: Vec<String>) -> ScanResult {
        let start_time = Utc::now();

        // 先进行主机发现
        let discovery_result = self.host_discovery(targets.clone()).await;

        // 过滤出存活主机
        let alive_hosts: Vec<String> = discovery_result
            .hosts
            .iter()
            .filter(|h| h.is_alive)
            .map(|h| h.ip.clone())
            .collect();

        // 对存活主机进行端口扫描
        let mut port_scanner = PortScanner::new(self.config.clone());

        // 设置进度回调
        if let Some(cb) = &self.progress_callback {
            port_scanner = port_scanner.with_progress_callback(cb.clone());
        }

        let ip_targets = self.parse_targets(alive_hosts);
        let ports = self.config.get_ports_to_scan();

        let hosts = port_scanner.scan_hosts_ports(ip_targets, ports).await;

        let end_time = Utc::now();
        let duration = (end_time - start_time).num_milliseconds() as f64 / 1000.0;

        let open_ports_count: usize = hosts.iter().map(|h| h.open_ports.len()).sum();
        let alive_hosts_count = hosts.len();

        ScanResult {
            scan_type: ScanType::Comprehensive,
            targets: vec![],
            start_time,
            end_time,
            duration_secs: duration,
            hosts,
            stats: ScanStats {
                total_targets: 0,
                alive_hosts: alive_hosts_count,
                total_open_ports: open_ports_count,
                services_found: 0,
            },
        }
    }

    /// 域环境扫描
    pub fn domain_scan(&mut self) -> domain::DomainScanResult {
        let mut domain_scanner = domain::DomainScanner::new(self.config.clone());
        domain_scanner.auto_discover()
    }

    /// 解析目标列表为IP地址
    fn parse_targets(&self, targets: Vec<String>) -> Vec<std::net::IpAddr> {
        use ipnet::Ipv4Net;
        use std::net::IpAddr;

        let mut ips = Vec::new();

        for target in targets {
            // 尝试解析为单个IP
            if let Ok(ip) = target.parse::<std::net::IpAddr>() {
                ips.push(ip);
                continue;
            }

            // 尝试解析为CIDR网段
            if let Ok(network) = target.parse::<Ipv4Net>() {
                for ip in network.hosts() {
                    ips.push(IpAddr::V4(ip));
                }
                continue;
            }

            // 尝试解析为IP范围 (start-end)
            if target.contains('-') {
                let parts: Vec<&str> = target.split('-').collect();
                if parts.len() == 2 {
                    if let (Ok(start), Ok(end)) = (
                        parts[0].trim().parse::<std::net::IpAddr>(),
                        parts[1].trim().parse::<std::net::IpAddr>(),
                    ) {
                        if let (IpAddr::V4(start_v4), IpAddr::V4(end_v4)) = (start, end) {
                            let start_num = u32::from(start_v4);
                            let end_num = u32::from(end_v4);
                            for num in start_num..=end_num {
                                ips.push(IpAddr::V4(std::net::Ipv4Addr::from(num)));
                            }
                            continue;
                        }
                    }
                }
            }

            // DNS解析（暂略）
        }

        ips
    }

    /// 保存扫描结果为JSON
    pub fn save_result(&self, result: &ScanResult, path: Option<PathBuf>) -> crate::core::Result<PathBuf> {
        let output_path = path.unwrap_or_else(|| {
            let hostname = if !result.hosts.is_empty() {
                result.hosts[0].ip.clone()
            } else {
                "scan".to_string()
            };
            let timestamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
            PathBuf::from(format!("intrasweep-scan-{}-{}.json", hostname, timestamp))
        });

        let json = serde_json::to_string_pretty(result)?;
        std::fs::write(&output_path, json)?;

        Ok(output_path)
    }
}

impl Default for Scanner {
    fn default() -> Self {
        Self::with_default_config()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_scanner_creation() {
        let scanner = Scanner::default();
        assert_eq!(scanner.config.host_timeout_ms, 1000);
    }

    #[tokio::test]
    async fn test_fast_scanner() {
        let scanner = Scanner::fast_scan();
        assert_eq!(scanner.config.max_concurrent_hosts, 500);
    }

    #[test]
    fn test_parse_targets_single_ip() {
        let scanner = Scanner::default();
        let targets = vec!["192.168.1.1".to_string()];
        let ips = scanner.parse_targets(targets);

        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0].to_string(), "192.168.1.1");
    }

    #[test]
    fn test_parse_targets_cidr() {
        let scanner = Scanner::default();
        let targets = vec!["192.168.1.0/30".to_string()];
        let ips = scanner.parse_targets(targets);

        // /30网段应该有2个可用主机
        assert_eq!(ips.len(), 2);
    }

    #[test]
    fn test_parse_targets_range() {
        let scanner = Scanner::default();
        let targets = vec!["192.168.1.1-192.168.1.3".to_string()];
        let ips = scanner.parse_targets(targets);

        assert_eq!(ips.len(), 3);
    }
}
