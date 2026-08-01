//! 主机存活扫描
//!
//! 提供ICMP、TCP SYN、ARP等多种方式的主机发现功能

use crate::core::Result;
use crate::scanner::config::{HostScanMethod, ScanConfig};
use crate::scanner::models::HostResult;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

/// 主机扫描器
pub struct HostScanner {
    config: ScanConfig,
}

impl HostScanner {
    /// 创建新的主机扫描器
    pub fn new(config: ScanConfig) -> Self {
        Self { config }
    }

    /// 使用默认配置创建
    pub fn with_default_config() -> Self {
        Self::new(ScanConfig::default())
    }

    /// 快速主机发现（根据配置选择扫描方式）
    pub async fn discover_hosts(&self, targets: Vec<IpAddr>) -> Vec<HostResult> {
        match self.config.host_scan_method {
            HostScanMethod::Arp => {
                #[cfg(windows)]
                {
                    let arp_scanner = crate::scanner::arp::ArpScanner::new(self.config.clone());
                    let arp_results = arp_scanner.scan(targets.clone()).await;
                    if !arp_results.is_empty() {
                        return arp_results;
                    }
                    // ARP 扫描无结果时回退到 TCP SYN
                }
                self.tcp_syn_scan(targets).await
            }
            HostScanMethod::Hybrid => {
                let tcp_results = self.tcp_syn_scan(targets.clone()).await;
                #[cfg(windows)]
                {
                    let arp_scanner = crate::scanner::arp::ArpScanner::new(self.config.clone());
                    let arp_results = arp_scanner.scan(targets).await;
                    Self::merge_scan_results(tcp_results, arp_results)
                }
                #[cfg(not(windows))]
                {
                    tcp_results
                }
            }
            HostScanMethod::TcpSyn | HostScanMethod::Icmp => {
                // TCP SYN 和 ICMP（暂用 TCP SYN 代替）都走此分支
                self.tcp_syn_scan(targets).await
            }
        }
    }

    /// 合并 TCP 和 ARP 扫描结果
    ///
    /// ARP 结果提供 MAC 地址，TCP 结果提供端口和延迟信息
    #[cfg(windows)]
    fn merge_scan_results(
        mut tcp_results: Vec<HostResult>,
        arp_results: Vec<HostResult>,
    ) -> Vec<HostResult> {
        // 建立 ARP MAC 地址映射
        let mut mac_map = std::collections::HashMap::new();
        for arp_result in &arp_results {
            if let Some(ref mac) = arp_result.mac {
                mac_map.insert(arp_result.ip.clone(), mac.clone());
            }
            // ARP 发现的主机但 TCP 未发现的，也加入结果
            if !tcp_results.iter().any(|t| t.ip == arp_result.ip) {
                tcp_results.push(HostResult {
                    ip: arp_result.ip.clone(),
                    hostname: None,
                    is_alive: true,
                    latency_ms: None,
                    mac: arp_result.mac.clone(),
                    open_ports: vec![],
                    services: vec![],
                    web_fingerprints: vec![],
                });
            }
        }

        // 为 TCP 结果补充 MAC 地址
        for result in &mut tcp_results {
            if result.mac.is_none() {
                if let Some(mac) = mac_map.get(&result.ip) {
                    result.mac = Some(mac.clone());
                }
            }
        }

        tcp_results
    }

    /// TCP SYN扫描（最通用方式，适用于所有平台）
    async fn tcp_syn_scan(&self, targets: Vec<IpAddr>) -> Vec<HostResult> {
        use futures::stream::{FuturesUnordered, StreamExt};

        let common_ports = vec![80, 443, 22, 23, 3389, 445]; // 常见端口用于探测
        let semaphore = Arc::new(Semaphore::new(self.config.max_concurrent_hosts));
        let mut futures = FuturesUnordered::new();

        for target in targets {
            let semaphore = Arc::clone(&semaphore);
            let ports = common_ports.clone();
            let timeout_dur = Duration::from_millis(self.config.host_timeout_ms);

            futures.push(tokio::spawn(async move {
                let _permit = semaphore.acquire_owned().await;
                Self::check_host_alive(target, &ports, timeout_dur).await
            }));
        }

        let mut results = Vec::new();
        while let Some(result) = futures.next().await {
            if let Ok(host_result) = result {
                results.push(host_result);
            }
        }

        results
    }

    /// 检查单个主机是否存活（并行探测多个端口）
    async fn check_host_alive(target: IpAddr, ports: &[u16], timeout_dur: Duration) -> HostResult {
        // 并行探测所有端口，任一成功即判定存活
        let results = futures::future::join_all(ports.iter().map(|&port| {
            let addr = SocketAddr::new(target, port);
            async move {
                let start = Instant::now();
                timeout(timeout_dur, TcpStream::connect(&addr))
                    .await
                    .ok()
                    .and_then(|r| r.ok())
                    .map(|_| start.elapsed().as_millis() as u64)
            }
        }))
        .await;

        let latency = results.into_iter().find_map(|l| l);

        HostResult {
            ip: target.to_string(),
            hostname: None,
            is_alive: latency.is_some(),
            latency_ms: latency,
            mac: None,
            open_ports: vec![],
            services: vec![],
            web_fingerprints: vec![],
        }
    }

    /// 扫描IP范围
    pub async fn scan_ip_range(&self, start: IpAddr, end: IpAddr) -> Vec<HostResult> {
        let mut targets = Vec::new();

        match (start, end) {
            (IpAddr::V4(start_v4), IpAddr::V4(end_v4)) => {
                let start_num = u32::from(start_v4);
                let end_num = u32::from(end_v4);

                for num in start_num..=end_num {
                    targets.push(IpAddr::V4(Ipv4Addr::from(num)));
                }
            }
            _ => {
                // IPv6暂不支持范围扫描
                targets.push(start);
            }
        }

        self.discover_hosts(targets).await
    }

    /// 扫描CIDR网段
    pub async fn scan_cidr(&self, cidr: &str) -> Result<Vec<HostResult>> {
        use ipnet::Ipv4Net;

        let network: Ipv4Net =
            cidr.parse()
                .map_err(|_| crate::core::error::IntraSweepError::Other {
                    message: format!("无效的CIDR格式: {}", cidr),
                })?;

        let targets: Vec<IpAddr> = network.hosts().map(IpAddr::V4).collect();

        Ok(self.discover_hosts(targets).await)
    }

    /// 获取存活主机列表（仅返回IP）
    pub async fn get_alive_hosts(&self, targets: Vec<IpAddr>) -> Vec<IpAddr> {
        let results = self.discover_hosts(targets).await;
        results
            .into_iter()
            .filter(|r| r.is_alive)
            .filter_map(|r| r.ip.parse().ok())
            .collect()
    }
}

impl Default for HostScanner {
    fn default() -> Self {
        Self::with_default_config()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_host_scanner_creation() {
        let scanner = HostScanner::default();
        assert_eq!(scanner.config.host_timeout_ms, 1000);
    }

    #[tokio::test]
    async fn test_check_localhost() {
        let scanner = HostScanner::default();
        let targets = vec![IpAddr::V4(Ipv4Addr::LOCALHOST)];

        let results = scanner.discover_hosts(targets).await;

        // 本地主机应该是存活的
        assert!(!results.is_empty());
        assert!(results[0].is_alive);
    }

    #[tokio::test]
    async fn test_scan_localhost_range() {
        let scanner = HostScanner::default();
        let start = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let end = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 5));

        let results = scanner.scan_ip_range(start, end).await;

        // 应该至少检测到127.0.0.1
        assert!(!results.is_empty());
    }

    #[test]
    fn test_config_presets() {
        let fast_config = ScanConfig::fast_scan();
        assert_eq!(fast_config.max_concurrent_hosts, 500);

        let stealth_config = ScanConfig::stealth_scan();
        assert_eq!(stealth_config.max_concurrent_hosts, 10);
    }

    /// 验证主机发现返回的结果数量与目标数量一致（P0-1 回归测试）
    ///
    /// 修复前 select_all 只回收第一个完成的任务，/24 网段仅返回 ~3 个结果。
    /// 修复后 FuturesUnordered 正确回收全部任务。
    #[tokio::test]
    async fn test_discover_hosts_returns_all_results() {
        use tokio::net::TcpListener;

        // 在 localhost 上启动 5 个监听端口，确保探测成功
        let mut _listeners = Vec::new();
        for _ in 0..5 {
            if let Ok(l) = TcpListener::bind("127.0.0.1:0").await {
                _listeners.push(l);
            }
        }

        let scanner = HostScanner::default();
        // 扫描 5 个不同的 127.0.0.x 地址
        let targets: Vec<IpAddr> = (1..=5)
            .map(|i| IpAddr::V4(Ipv4Addr::new(127, 0, 0, i)))
            .collect();

        let results = scanner.discover_hosts(targets.clone()).await;

        // 关键断言：结果数量必须等于目标数量（每个目标都有一个 HostResult）
        assert_eq!(
            results.len(),
            targets.len(),
            "主机发现应返回与目标数量相同的结果（每个目标一个 HostResult），\
             期望 {}，实际 {}。如果此测试失败，说明 P0-1（select_all 丢结果）回归。",
            targets.len(),
            results.len()
        );

        // 127.0.0.1 应该是存活的（有监听端口）
        let localhost = results.iter().find(|r| r.ip == "127.0.0.1");
        assert!(localhost.is_some(), "结果中应包含 127.0.0.1");
        assert!(localhost.unwrap().is_alive, "127.0.0.1 应判定为存活");
    }
}
