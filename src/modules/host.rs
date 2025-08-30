// 主机存活检测模块
#[cfg(not(windows))]
use pnet::datalink;
#[cfg(not(windows))]
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
#[cfg(not(windows))]
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
#[cfg(not(windows))]
use pnet::packet::{MutablePacket, Packet};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
#[cfg(windows)]
use tokio::net::TcpStream;

/// 执行主机存活检测
///
/// # 参数 -t
///
/// 返回发现的存活主机列表
pub fn discover_hosts(target_network: &str) -> String {
    match parse_network(target_network) {
        Ok((network, prefix)) => {
            let active_hosts = tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(scan_hosts(network, prefix));

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
async fn scan_hosts(network: Ipv4Addr, prefix: u8) -> Vec<IpAddr> {
    // 计算要扫描的IP地址
    let target_ips = calculate_target_ips(network, prefix);

    // 在Windows上使用ICMP+TCP探测，在其他平台上使用ARP扫描
    #[cfg(windows)]
    {
        windows_host_scan(target_ips).await
    }
    #[cfg(not(windows))]
    {
        arp_scan(network, prefix).await
    }
}

/// 在Windows上使用ICMP和TCP端口探测进行主机扫描
#[cfg(windows)]
async fn windows_host_scan(target_ips: Vec<Ipv4Addr>) -> Vec<IpAddr> {
    use futures::stream::{FuturesUnordered, StreamExt};

    let mut futures = FuturesUnordered::new();
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(50)); // 减少并发数以避免网络拥塞

    for ip in target_ips {
        let semaphore_clone = semaphore.clone();
        futures.push(tokio::spawn(async move {
            let _permit = semaphore_clone.acquire().await.unwrap();
            let ip_addr = IpAddr::V4(ip);

            // 添加小延迟以避免网络拥塞
            tokio::time::sleep(Duration::from_millis(1)).await;

            // 尝试ICMP探测
            if ping_host(ip_addr).await {
                Some(ip_addr)
            } else {
                // 如果ICMP失败，尝试TCP端口探测
                if tcp_port_scan(ip_addr).await {
                    Some(ip_addr)
                } else {
                    None
                }
            }
        }));
    }

    let mut active_hosts = HashSet::new();
    while let Some(result) = futures.next().await {
        match result {
            Ok(Some(ip)) => {
                active_hosts.insert(ip);
            }
            Ok(None) => {} // 主机未响应
            Err(e) => {
                eprintln!("Task failed: {}", e);
            }
        }
    }

    active_hosts.into_iter().collect()
}

/// 使用ICMP Echo请求探测主机存活 (Windows)
#[cfg(windows)]
async fn ping_host(ip: IpAddr) -> bool {
    // 在Windows上，使用系统ping命令作为简单实现
    let ip_str = match ip {
        IpAddr::V4(addr) => addr.to_string(),
        IpAddr::V6(addr) => addr.to_string(),
    };

    let output = std::process::Command::new("ping")
        .args(&["-n", "1", "-w", "1000", &ip_str])
        .output();

    match output {
        Ok(output) => output.status.success(),
        Err(_) => false,
    }
}

/// 使用TCP端口探测检测主机存活 (Windows)
#[cfg(windows)]
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

    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(10)); // 限制TCP并发连接数

    use futures::stream::{FuturesUnordered, StreamExt};
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

/// 执行ARP扫描 (非Windows平台)
#[cfg(not(windows))]
async fn arp_scan(network: Ipv4Addr, prefix: u8) -> Vec<IpAddr> {
    // 获取所有网络接口
    let interfaces = datalink::interfaces();

    // 寻找与目标网络匹配的接口
    let interface = match find_matching_interface(&interfaces, network, prefix) {
        Some(iface) => iface,
        None => {
            eprintln!(
                "No suitable network interface found for target network {}.{}/{}",
                (network.octets()[0]),
                (network.octets()[1]),
                prefix
            );
            return Vec::new();
        }
    };

    // 确保接口有MAC地址
    let source_mac = match interface.mac {
        Some(mac) => mac,
        None => {
            eprintln!("Interface {} does not have a MAC address", interface.name);
            return Vec::new();
        }
    };

    // 获取接口的IPv4地址
    let source_ip = match interface.ips.iter().find_map(|ip_network| {
        if let IpAddr::V4(ip) = ip_network.ip() {
            // 检查IP地址是否与目标网络在同一网段
            if is_same_network(ip, network, prefix) {
                Some(ip)
            } else {
                None
            }
        } else {
            None
        }
    }) {
        Some(ip) => ip,
        None => {
            eprintln!(
                "Interface {} does not have a compatible IPv4 address",
                interface.name
            );
            return Vec::new();
        }
    };

    // 创建数据链路发送器和接收器
    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {
            eprintln!("Unhandled channel type for interface {}", interface.name);
            return Vec::new();
        }
        Err(e) => {
            eprintln!(
                "Error creating datalink channel for {}: {}",
                interface.name, e
            );
            return Vec::new();
        }
    };

    // 计算要扫描的IP地址
    let target_ips = calculate_target_ips(network, prefix);
    let mut active_hosts = HashSet::new();

    eprintln!(
        "Starting ARP scan on interface {} for {} hosts",
        interface.name,
        target_ips.len()
    );

    // 发送ARP请求
    for &target_ip in &target_ips {
        let arp_packet = create_arp_request(source_mac, IpAddr::V4(source_ip), target_ip);
        if let Err(e) = tx.send_to(&arp_packet, None) {
            eprintln!("Failed to send ARP request to {}: {}", target_ip, e);
        }
    }

    // 接收ARP响应
    let start_time = std::time::Instant::now();
    let timeout = Duration::from_secs(3); // 增加超时到3秒
    let mut buffer = vec![0u8; 1024];

    while start_time.elapsed() < timeout {
        match rx.next() {
            Ok(packet) => {
                if packet.len() <= buffer.len() {
                    buffer[..packet.len()].copy_from_slice(&packet);
                    if let Some(arp_pkt) = parse_arp_packet(&buffer[..packet.len()]) {
                        // 检查是否是针对我们的ARP响应
                        if arp_pkt.get_operation() == ArpOperations::Reply
                            && target_ips.contains(&arp_pkt.get_sender_proto_addr())
                        {
                            let sender_ip = arp_pkt.get_sender_proto_addr();
                            eprintln!("Found active host: {}", sender_ip);
                            active_hosts.insert(IpAddr::V4(sender_ip));
                        }
                    }
                }
            }
            Err(e) => {
                // 超时是正常的，其他错误才需要报告
                if e.kind() != std::io::ErrorKind::TimedOut {
                    eprintln!("Error receiving packet: {}", e);
                }
            }
        }
    }

    active_hosts.into_iter().collect()
}

/// 寻找与目标网络匹配的网络接口
#[cfg(not(windows))]
fn find_matching_interface(
    interfaces: &[datalink::NetworkInterface],
    target_network: Ipv4Addr,
    prefix: u8,
) -> Option<datalink::NetworkInterface> {
    for interface in interfaces {
        // 跳过回环和关闭的接口
        if interface.is_loopback() || !interface.is_up() {
            continue;
        }

        // 检查接口是否有IPv4地址
        for ip_network in &interface.ips {
            if let IpAddr::V4(ip) = ip_network.ip() {
                if is_same_network(ip, target_network, prefix) {
                    return Some(interface.clone());
                }
            }
        }
    }
    None
}

/// 检查两个IP地址是否在同一个网络
#[cfg(not(windows))]
fn is_same_network(ip1: Ipv4Addr, ip2: Ipv4Addr, prefix: u8) -> bool {
    let mask = if prefix == 0 {
        0u32
    } else {
        u32::max_value() << (32 - prefix)
    };

    let ip1_u32 = u32::from(ip1);
    let ip2_u32 = u32::from(ip2);

    (ip1_u32 & mask) == (ip2_u32 & mask)
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

/// 创建ARP请求包
#[cfg(not(windows))]
fn create_arp_request(
    source_mac: pnet::datalink::MacAddr,
    source_ip: IpAddr,
    target_ip: Ipv4Addr,
) -> Vec<u8> {
    let source_ipv4 = match source_ip {
        IpAddr::V4(addr) => addr,
        IpAddr::V6(_) => {
            eprintln!("Only IPv4 addresses are supported for ARP requests");
            return Vec::new();
        }
    };

    // 创建完整的以太网帧（14字节以太网头 + 28字节ARP包 = 42字节）
    let mut ethernet_buffer = vec![0u8; 42];

    {
        let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer[..14]).unwrap();
        ethernet_packet.set_destination(pnet::datalink::MacAddr::broadcast());
        ethernet_packet.set_source(source_mac);
        ethernet_packet.set_ethertype(EtherTypes::Arp);
    }

    {
        let mut arp_packet = MutableArpPacket::new(&mut ethernet_buffer[14..]).unwrap();
        arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp_packet.set_protocol_type(EtherTypes::Ipv4);
        arp_packet.set_hw_addr_len(6);
        arp_packet.set_proto_addr_len(4);
        arp_packet.set_operation(ArpOperations::Request);
        arp_packet.set_sender_hw_addr(source_mac);
        arp_packet.set_sender_proto_addr(source_ipv4);
        arp_packet.set_target_hw_addr(pnet::datalink::MacAddr::zero());
        arp_packet.set_target_proto_addr(target_ip);
    }

    ethernet_buffer
}

/// 解析ARP包
#[cfg(not(windows))]
fn parse_arp_packet(packet: &[u8]) -> Option<ArpPacket> {
    // 检查最小长度要求
    if packet.len() < 42 {
        return None;
    }

    // 检查是否为以太网帧
    if packet.len() < 14 {
        return None;
    }

    // 检查是否为ARP包 (EtherType 0x0806)
    let eth_type = u16::from_be_bytes([packet[12], packet[13]]);
    if eth_type != 0x0806 {
        return None;
    }

    // 检查ARP数据长度
    if packet.len() < 42 {
        return None;
    }

    let arp_data = &packet[14..42];
    ArpPacket::new(arp_data)
}
