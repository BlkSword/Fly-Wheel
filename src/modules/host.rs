// 主机存活检测模块

use futures::stream::{FuturesUnordered, StreamExt};
use std::collections::HashSet;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

/// 执行主机存活检测
///
/// # 参数
///
/// * `target_network` - 目标网段
/// * `scan_type` - 扫描类型 ("icmp", "tcp")
///
/// 返回发现的存活主机列表
pub fn discover_hosts(target_network: &str, scan_type: &str) -> String {
    match parse_network(target_network) {
        Ok((network, prefix)) => {
            let active_hosts = tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(scan_hosts(network, prefix, scan_type));

            if active_hosts.is_empty() {
                return format!("No active hosts found in network {}", target_network);
            }

            let mut result = format!("Active hosts in {}:\n", target_network);
            for host in active_hosts {
                result.push_str(&format!("  {}\n", host));
            }

            result
        }
        Err(e) => {
            format!("Error parsing network: {}", e)
        }
    }
}

/// 返回网络地址和前缀长度的元组
fn parse_network(network_str: &str) -> Result<(Ipv4Addr, u8), String> {
    let parts: Vec<&str> = network_str.split('/').collect();
    if parts.len() != 2 {
        return Err("Invalid network format. Use: network_address/prefix".to_string());
    }

    let network: Ipv4Addr = parts[0]
        .trim()
        .parse()
        .map_err(|_| format!("Invalid network address: {}", parts[0]))?;

    let prefix: u8 = parts[1]
        .trim()
        .parse()
        .map_err(|_| format!("Invalid prefix: {}", parts[1]))?;

    if prefix > 32 {
        return Err("Prefix must be between 0 and 32".to_string());
    }

    Ok((network, prefix))
}

/// 执行主机扫描
async fn scan_hosts(network: Ipv4Addr, prefix: u8, scan_type: &str) -> Vec<IpAddr> {
    // 计算要扫描的IP地址
    let target_ips = calculate_target_ips(network, prefix);
    let total_ips = target_ips.len();

    println!("Scanning {} hosts...", total_ips);

    match scan_type {
        "icmp" => icmp_host_scan(target_ips, total_ips).await,
        "tcp" => tcp_host_scan(target_ips, total_ips).await,
        _ => {
            eprintln!("Invalid scan type: {}. Using icmp as default.", scan_type);
            icmp_host_scan(target_ips, total_ips).await
        }
    }
}

/// 使用ICMP探测进行主机扫描
async fn icmp_host_scan(target_ips: Vec<Ipv4Addr>, total_ips: usize) -> Vec<IpAddr> {
    let mut futures = FuturesUnordered::new();
    // 增加并发数以提高扫描速度
    let semaphore = Arc::new(Semaphore::new(100));
    let scanned_count = Arc::new(AtomicUsize::new(0));

    for ip in target_ips {
        let semaphore_clone = semaphore.clone();
        let scanned_count_clone = scanned_count.clone();
        futures.push(tokio::spawn(async move {
            let _permit = semaphore_clone.acquire().await.unwrap();
            let ip_addr = IpAddr::V4(ip);

            let result = if ping_host(ip_addr).await {
                Some(ip_addr)
            } else {
                None
            };

            // 更新进度
            let scanned = scanned_count_clone.fetch_add(1, Ordering::Relaxed) + 1;
            print_progress(scanned, total_ips);

            result
        }));
    }

    let mut active_hosts = HashSet::new();
    while let Some(result) = futures.next().await {
        if let Ok(Some(ip)) = result {
            active_hosts.insert(ip);
        }
    }

    // 完成后换行
    println!();

    active_hosts.into_iter().collect()
}

/// 使用TCP端口探测进行主机扫描
async fn tcp_host_scan(target_ips: Vec<Ipv4Addr>, total_ips: usize) -> Vec<IpAddr> {
    let mut futures = FuturesUnordered::new();
    // 增加并发数以提高扫描速度
    let semaphore = Arc::new(Semaphore::new(100));
    let scanned_count = Arc::new(AtomicUsize::new(0));

    for ip in target_ips {
        let semaphore_clone = semaphore.clone();
        let scanned_count_clone = scanned_count.clone();
        futures.push(tokio::spawn(async move {
            let _permit = semaphore_clone.acquire().await.unwrap();
            let ip_addr = IpAddr::V4(ip);

            let result = if tcp_port_scan(ip_addr).await {
                Some(ip_addr)
            } else {
                None
            };

            // 更新进度
            let scanned = scanned_count_clone.fetch_add(1, Ordering::Relaxed) + 1;
            print_progress(scanned, total_ips);

            result
        }));
    }

    let mut active_hosts = HashSet::new();
    while let Some(result) = futures.next().await {
        if let Ok(Some(ip)) = result {
            active_hosts.insert(ip);
        }
    }

    // 完成后换行
    println!();

    active_hosts.into_iter().collect()
}

/// 打印进度条
fn print_progress(current: usize, total: usize) {
    let progress = (current as f64 / total as f64) * 100.0;
    let filled = (progress as usize) / 2; // 50个字符宽度的进度条
    let bar: String = std::iter::repeat('=')
        .take(filled)
        .chain(std::iter::repeat(' '))
        .take(50)
        .collect();

    print!("\r[{}] {:.1}%", bar, progress);
    std::io::stdout().flush().unwrap();
}

/// 使用ICMP Echo请求探测主机存活
async fn ping_host(ip: IpAddr) -> bool {
    // 使用系统ping命令作为简单实现
    let ip_str = match ip {
        IpAddr::V4(addr) => addr.to_string(),
        IpAddr::V6(addr) => addr.to_string(),
    };

    let output = Command::new("ping")
        .args(&["-n", "1", "-w", "1000", &ip_str])
        .output();

    match output {
        Ok(output) => output.status.success(),
        Err(_) => false,
    }
}

/// 使用TCP端口探测检测主机存活
async fn tcp_port_scan(ip: IpAddr) -> bool {
    // 扩展常见端口列表，包括更多常用服务端口
    let common_ports = vec![
        21,   // FTP
        22,   // SSH
        23,   // Telnet
        25,   // SMTP
        53,   // DNS
        80,   // HTTP
        110,  // POP3
        135,  // RPC
        139,  // NetBIOS
        143,  // IMAP
        443,  // HTTPS
        445,  // SMB
        993,  // IMAPS
        995,  // POP3S
        1433, // SQL Server
        1521, // Oracle
        3306, // MySQL
        3389, // RDP
        5432, // PostgreSQL
        8080, // HTTP Alt
    ];

    // 增加TCP连接并发数
    let semaphore = Arc::new(Semaphore::new(20));

    let mut futures = FuturesUnordered::new();

    for port in common_ports {
        let semaphore_clone = semaphore.clone();
        let addr = SocketAddr::new(ip, port);

        futures.push(tokio::spawn(async move {
            let _permit = semaphore_clone.acquire().await.unwrap();

            match tokio::time::timeout(Duration::from_millis(500), TcpStream::connect(addr)).await {
                Ok(Ok(_)) => Some(true),
                Ok(Err(_)) => Some(false),
                Err(_) => Some(false), // 超时
            }
        }));
    }

    // 等待任意一个端口成功连接
    let mut success = false;
    while let Some(result) = futures.next().await {
        if let Ok(Some(true)) = result {
            success = true;
            break;
        }
    }

    success
}

/// 计算目标网络中的所有IP地址
fn calculate_target_ips(network: Ipv4Addr, prefix: u8) -> Vec<Ipv4Addr> {
    let mut ips = Vec::new();

    // 边界检查
    if prefix > 32 {
        return ips; // 返回空向量
    }

    let network_u32 = u32::from(network);
    let mask = if prefix == 0 {
        0u32
    } else {
        u32::max_value() << (32 - prefix)
    };

    let network_addr = network_u32 & mask;
    let broadcast_addr = network_addr | !mask;

    // 处理特殊情况：/31和/32网络
    if prefix >= 31 {
        // 对于/31网络，RFC 3021允许使用网络地址和广播地址
        if prefix == 31 {
            ips.push(Ipv4Addr::from(network_addr));
            if broadcast_addr != network_addr {
                ips.push(Ipv4Addr::from(broadcast_addr));
            }
        }
        // 对于/32网络，只返回单个地址
        else if prefix == 32 {
            ips.push(Ipv4Addr::from(network_addr));
        }
        return ips;
    }

    // 正常情况：跳过网络地址和广播地址
    let start_addr = network_addr + 1;
    let end_addr = broadcast_addr - 1;

    // 确保不会溢出
    if start_addr <= end_addr {
        for addr in start_addr..=end_addr {
            ips.push(Ipv4Addr::from(addr));
        }
    }

    ips
}
