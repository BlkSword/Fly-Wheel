//! 端口扫描
//!
//! 提供高性能端口扫描功能

use crate::scanner::config::ScanConfig;
use crate::scanner::models::{HostResult, PortInfo, PortState};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

/// 端口扫描器
pub struct PortScanner {
    config: ScanConfig,
}

impl PortScanner {
    /// 创建新的端口扫描器
    pub fn new(config: ScanConfig) -> Self {
        Self { config }
    }

    /// 使用默认配置创建
    pub fn with_default_config() -> Self {
        Self::new(ScanConfig::default())
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

        HostResult {
            ip: host.to_string(),
            hostname: None,
            is_alive: !open_ports.is_empty(),
            latency_ms: Some(start_time.elapsed().as_millis() as u64),
            mac: None,
            open_ports,
            services: vec![],
        }
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

        // 并发扫描多个主机
        let semaphore = Arc::new(Semaphore::new(self.config.max_concurrent_hosts));
        let mut tasks = Vec::new();

        for host in hosts {
            let semaphore = semaphore.clone();
            let ports_clone = ports.clone();
            let config = self.config.clone();

            let task = tokio::spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();
                let scanner = PortScanner::new(config);
                scanner.scan_host_ports(host, ports_clone).await
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

use std::sync::Arc;

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
