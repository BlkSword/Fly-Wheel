//! 主机存活扫描
//!
//! 提供ICMP、TCP SYN、ARP等多种方式的主机发现功能

#![allow(dead_code)]

use crate::core::Result;
use crate::scanner::config::ScanConfig;
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

    /// 快速主机发现（ICMP + TCP SYN）
    pub async fn discover_hosts(&self, targets: Vec<IpAddr>) -> Vec<HostResult> {
        let mut results = Vec::new();

        // 使用TCP SYN扫描（更可靠，因为不需要原始socket权限）
        let tcp_results = self.tcp_syn_scan(targets).await;
        results.extend(tcp_results);

        results
    }

    /// TCP SYN扫描（最通用方式，适用于所有平台）
    async fn tcp_syn_scan(&self, targets: Vec<IpAddr>) -> Vec<HostResult> {
        let mut results = Vec::new();
        let common_ports = vec![80, 443, 22, 23, 3389, 445]; // 常见端口用于探测

        // 使用Arc包装信号量以便共享
        let semaphore = Arc::new(Semaphore::new(self.config.max_concurrent_hosts));
        let mut tasks = Vec::new();

        for target in targets {
            let semaphore = Arc::clone(&semaphore);
            let ports = common_ports.clone();
            let timeout_dur = Duration::from_millis(self.config.host_timeout_ms);

            let task = tokio::spawn(async move {
                Self::check_host_alive(target, &ports, timeout_dur, semaphore).await
            });

            tasks.push(task);

            // 控制并发数
            if tasks.len() >= self.config.max_concurrent_hosts {
                if let Some(result) = self.wait_for_tasks(&mut tasks).await {
                    results.push(result);
                }
            }
        }

        // 等待剩余任务完成
        while !tasks.is_empty() {
            if let Some(result) = self.wait_for_tasks(&mut tasks).await {
                results.push(result);
            }
        }

        results
    }

    /// 检查单个主机是否存活
    async fn check_host_alive(
        target: IpAddr,
        ports: &[u16],
        timeout_dur: Duration,
        _semaphore: Arc<Semaphore>,
    ) -> HostResult {
        let mut is_alive = false;
        let mut latency_ms = None;

        // 尝试连接常见端口
        for &port in ports {
            let addr = SocketAddr::new(target, port);
            let connect_start = Instant::now();

            let result = timeout(timeout_dur, TcpStream::connect(&addr)).await;

            match result {
                Ok(Ok(_stream)) => {
                    is_alive = true;
                    latency_ms = Some(connect_start.elapsed().as_millis() as u64);
                    drop(_stream); // 显式关闭连接
                    break; // 只要有一个端口开放就认为主机存活
                }
                Ok(Err(_)) => continue,
                Err(_) => continue, // 超时
            }
        }

        HostResult {
            ip: target.to_string(),
            hostname: None, // 可以添加DNS解析
            is_alive,
            latency_ms,
            mac: None,
            open_ports: vec![],
            services: vec![],
        }
    }

    /// 等待任务完成并返回结果
    async fn wait_for_tasks(&self, tasks: &mut Vec<tokio::task::JoinHandle<HostResult>>) -> Option<HostResult> {
        if tasks.is_empty() {
            return None;
        }

        // 使用futures::future::select_all等待任意任务完成
        let (result, _index, _remaining) = futures::future::select_all(tasks.drain(..).collect::<Vec<_>>()).await;
        result.ok()
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

        let network: Ipv4Net = cidr.parse()
            .map_err(|_| crate::core::error::FlyWheelError::Other {
                message: format!("无效的CIDR格式: {}", cidr),
            })?;

        let targets: Vec<IpAddr> = network.hosts().map(IpAddr::V4).collect();

        Ok(self.discover_hosts(targets).await)
    }

    /// 获取存活主机列表（仅返回IP）
    pub async fn get_alive_hosts(&self, targets: Vec<IpAddr>) -> Vec<IpAddr> {
        let results = self.discover_hosts(targets).await;
        results.into_iter()
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
}
