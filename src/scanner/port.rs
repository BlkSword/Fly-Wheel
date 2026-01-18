//! 端口扫描
//!
//! 提供高性能端口扫描功能

#![allow(dead_code)]

use crate::scanner::config::ScanConfig;
use crate::scanner::models::{HostResult, PortInfo, PortState, ServiceInfo};
use crate::scanner::service::ServiceIdentifier;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

/// 进度回调函数类型
pub type ProgressCallback = Arc<dyn Fn(usize, usize) + Send + Sync>;

/// 端口扫描器
pub struct PortScanner {
    config: ScanConfig,
    service_identifier: ServiceIdentifier,
    progress_callback: Option<ProgressCallback>,
}

impl PortScanner {
    /// 创建新的端口扫描器
    pub fn new(config: ScanConfig) -> Self {
        let service_identifier = ServiceIdentifier::new()
            .with_timeout(config.port_timeout_ms, config.service_timeout_ms);

        Self {
            config,
            service_identifier,
            progress_callback: None,
        }
    }

    /// 使用默认配置创建
    pub fn with_default_config() -> Self {
        Self::new(ScanConfig::default())
    }

    /// 设置进度回调
    pub fn with_progress_callback(mut self, callback: ProgressCallback) -> Self {
        self.progress_callback = Some(callback);
        self
    }

    /// 扫描单个主机的多个端口
    pub async fn scan_host_ports(&self, host: IpAddr, ports: Vec<u16>) -> HostResult {
        let start_time = Instant::now();
        let mut open_ports = Vec::new();

        let semaphore = Arc::new(Semaphore::new(self.config.max_concurrent_ports));
        let mut tasks = Vec::new();

        for port in ports {
            let semaphore = semaphore.clone();
            let host_copy = host;
            let timeout_dur = Duration::from_millis(self.config.port_timeout_ms);

            let task = tokio::spawn(async move {
                Self::scan_single_port(host_copy, port, timeout_dur, semaphore).await
            });

            tasks.push(task);

            // 批处理：控制同时运行的任务数
            if tasks.len() >= self.config.calculate_batch_size() {
                let results = self.wait_for_port_batch(&mut tasks).await;
                open_ports.extend(results);
            }

            // 扫描延迟（隐蔽模式）
            if let Some(delay_ms) = self.config.scan_delay_ms {
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }
        }

        // 等待剩余任务完成
        while !tasks.is_empty() {
            let results = self.wait_for_port_batch(&mut tasks).await;
            open_ports.extend(results);
        }

        // 排序端口
        open_ports.sort_by_key(|p| p.port);

        // 服务探测
        let services = if self.config.service_detection && !open_ports.is_empty() {
            self.detect_services(host, &open_ports).await
        } else {
            vec![]
        };

        HostResult {
            ip: host.to_string(),
            hostname: None,
            is_alive: !open_ports.is_empty(),
            latency_ms: Some(start_time.elapsed().as_millis() as u64),
            mac: None,
            open_ports,
            services,
        }
    }

    /// 服务探测
    async fn detect_services(&self, host: IpAddr, open_ports: &[PortInfo]) -> Vec<ServiceInfo> {
        let mut services = Vec::new();

        // 过滤需要探测的端口
        let ports_to_scan: Vec<u16> = open_ports
            .iter()
            .filter(|p| {
                // 如果设置为仅探测常见端口，则只探测常见端口
                if self.config.service_common_only {
                    self.is_common_port(p.port)
                } else {
                    true
                }
            })
            .map(|p| p.port)
            .collect();

        if ports_to_scan.is_empty() {
            return services;
        }

        // 批量探测服务
        let results = self.service_identifier.identify_batch(host, ports_to_scan).await;

        for (_port, service_info) in results {
            if let Some(info) = service_info {
                // 只保存有额外信息的服务
                if !info.product.is_empty() || !info.version.is_empty() || !info.extra_info.is_empty() {
                    services.push(info);
                }
            }
        }

        services
    }

    /// 判断是否为常见端口
    fn is_common_port(&self, port: u16) -> bool {
        const COMMON_PORTS: &[u16] = &[
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 465,
            587, 593, 636, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 5985,
            5986, 6379, 8000, 8080, 8443, 8888, 9200, 27017,
        ];
        COMMON_PORTS.contains(&port)
    }

    /// 扫描单个端口
    async fn scan_single_port(
        host: IpAddr,
        port: u16,
        timeout_dur: Duration,
        semaphore: Arc<Semaphore>,
    ) -> PortInfo {
        // 获取信号量许可
        let _permit = semaphore.acquire().await.unwrap();

        let addr = SocketAddr::new(host, port);
        let result = timeout(timeout_dur, TcpStream::connect(&addr)).await;

        match result {
            Ok(Ok(_stream)) => {
                // 端口开放 - stream会自动关闭
                drop(_stream);

                PortInfo {
                    port,
                    state: PortState::Open,
                    service: Self::guess_service(port),
                    version: None,
                    banner: None,
                }
            }
            Ok(Err(_)) => PortInfo {
                port,
                state: PortState::Closed,
                service: None,
                version: None,
                banner: None,
            },
            Err(_) => PortInfo {
                port,
                state: PortState::Filtered,
                service: None,
                version: None,
                banner: None,
            },
        }
    }

    /// 等待一批端口扫描任务完成
    async fn wait_for_port_batch(
        &self,
        tasks: &mut Vec<tokio::task::JoinHandle<PortInfo>>,
    ) -> Vec<PortInfo> {
        let mut results = Vec::new();

        // 等待所有任务完成
        for task in tasks.drain(..) {
            if let Ok(result) = task.await {
                // 只返回开放端口
                if result.state == PortState::Open {
                    results.push(result);
                }
            }
        }

        results
    }

    /// 扫描多个主机的常见端口
    pub async fn scan_hosts_common_ports(&self, hosts: Vec<IpAddr>) -> Vec<HostResult> {
        let ports = self.config.get_ports_to_scan();
        self.scan_hosts_ports(hosts, ports).await
    }

    /// 扫描多个主机的指定端口
    pub async fn scan_hosts_ports(&self, hosts: Vec<IpAddr>, ports: Vec<u16>) -> Vec<HostResult> {
        let mut results = Vec::new();
        let total_hosts = hosts.len();
        let completed_count = Arc::new(AtomicUsize::new(0));

        // 并发扫描多个主机
        let semaphore = Arc::new(Semaphore::new(self.config.max_concurrent_hosts));
        let mut tasks = Vec::new();

        for host in hosts {
            let semaphore = semaphore.clone();
            let ports_clone = ports.clone();
            let config = self.config.clone();
            let completed = completed_count.clone();
            let progress_cb = self.progress_callback.clone();

            let task = tokio::spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();
                let scanner = PortScanner::new(config);
                let result = scanner.scan_host_ports(host, ports_clone).await;

                // 更新进度
                let completed_hosts = completed.fetch_add(1, Ordering::Relaxed) + 1;
                if let Some(cb) = progress_cb {
                    cb(completed_hosts, total_hosts);
                }

                result
            });

            tasks.push(task);
        }

        // 收集结果
        for task in tasks {
            if let Ok(result) = task.await {
                results.push(result);
            }
        }

        results
    }

    /// 根据端口号猜测服务
    fn guess_service(port: u16) -> Option<String> {
        let services = std::collections::HashMap::from([
            (21, "ftp"),
            (22, "ssh"),
            (23, "telnet"),
            (25, "smtp"),
            (53, "domain"),
            (80, "http"),
            (110, "pop3"),
            (111, "rpcbind"),
            (135, "msrpc"),
            (139, "netbios-ssn"),
            (143, "imap"),
            (389, "ldap"),
            (443, "https"),
            (445, "microsoft-ds"),
            (465, "smtps"),
            (587, "submission"),
            (593, "http-rpc-epmap"),
            (636, "ldaps"),
            (993, "imaps"),
            (995, "pop3s"),
            (1433, "mssql"),
            (1521, "oracle"),
            (3306, "mysql"),
            (3389, "ms-wbt-server"),
            (5432, "postgresql"),
            (5900, "vnc"),
            (5985, "wsman"),
            (5986, "wsman-ssl"),
            (6379, "redis"),
            (8000, "http-alt"),
            (8080, "http-proxy"),
            (8443, "https-alt"),
            (8888, "http-alt"),
            (9200, "elasticsearch"),
            (27017, "mongodb"),
        ]);

        services.get(&port).map(|s| s.to_string())
    }
}

impl Default for PortScanner {
    fn default() -> Self {
        Self::with_default_config()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_port_scanner_creation() {
        let scanner = PortScanner::default();
        assert_eq!(scanner.config.port_timeout_ms, 1000);
    }

    #[tokio::test]
    async fn test_scan_localhost_common_ports() {
        let scanner = PortScanner::default();
        let hosts = vec![IpAddr::V4(Ipv4Addr::LOCALHOST)];
        let ports = vec![22, 80, 443, 8080];

        let results = scanner.scan_hosts_ports(hosts, ports).await;

        // 应该有一个结果
        assert!(!results.is_empty());
    }

    #[tokio::test]
    async fn test_scan_single_host() {
        let scanner = PortScanner::default();
        let host = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let ports = vec![80, 443, 8080];

        let result = scanner.scan_host_ports(host, ports).await;

        assert_eq!(result.ip, "127.0.0.1");
        // 端口列表应该是排序的
        let mut sorted_ports = result.open_ports.clone();
        sorted_ports.sort_by_key(|p| p.port);
        assert_eq!(result.open_ports, sorted_ports);
    }

    #[test]
    fn test_service_guessing() {
        assert_eq!(PortScanner::guess_service(80), Some("http".to_string()));
        assert_eq!(PortScanner::guess_service(443), Some("https".to_string()));
        assert_eq!(PortScanner::guess_service(22), Some("ssh".to_string()));
        assert_eq!(PortScanner::guess_service(9999), None);
    }
}
