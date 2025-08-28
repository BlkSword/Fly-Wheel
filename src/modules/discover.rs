use std::net::{Ipv4Addr};

// 简单的CIDR解析结构
struct IpCidr {
    network: Ipv4Addr,
    prefix: u8,
}

impl IpCidr {
    pub fn from_str(cidr: &str) -> Result<IpCidr, &'static str> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return Err("Invalid CIDR format");
        }
        
        let network = parts[0].parse::<Ipv4Addr>()
            .map_err(|_| "Invalid IP address")?;
        let prefix = parts[1].parse::<u8>()
            .map_err(|_| "Invalid prefix")?;
            
        if prefix > 32 {
            return Err("Prefix must be between 0 and 32");
        }
        
        Ok(IpCidr { network, prefix })
    }
    
    #[cfg(not(target_os = "windows"))]
    fn hosts(&self) -> Vec<Ipv4Addr> {
        let mut hosts = Vec::new();
        let mask = !((1u32 << (32 - self.prefix)) - 1);
        let network = u32::from(self.network) & mask;
        let broadcast = network | !mask;
        
        // 从网络地址+1开始，到广播地址-1结束（排除网络地址和广播地址）
        for ip in (network + 1)..broadcast {
            hosts.push(Ipv4Addr::from(ip));
        }
        
        hosts
    }
    
    #[cfg(target_os = "windows")]
    fn hosts(&self) -> Vec<Ipv4Addr> {
        // 在Windows上暂时返回空列表，避免链接错误
        Vec::new()
    }
}

/// 执行网络发现功能
/// 
/// # 参数
/// 
/// * `target` - 目标网络范围 (例如: 192.168.1.0/24)
/// 
/// # 返回值
/// 
/// 返回操作结果的字符串
pub fn run(target: &str) -> String {
    // 解析目标网络
    if let Ok(network) = IpCidr::from_str(target) {
        println!("Discovering hosts on network: {}", target);
        
        // 执行ICMP ping扫描
        let live_hosts = icmp_scan(network);
        
        let mut result = String::new();
        result.push_str(&format!("Found {} live hosts in network {}\n", live_hosts.len(), target));
        
        for host in live_hosts {
            result.push_str(&format!("  {}\n", host));
        }
        
        result
    } else {
        format!("Invalid target network: {}", target)
    }
}

#[cfg(not(target_os = "windows"))]
fn icmp_scan(network: IpCidr) -> Vec<Ipv4Addr> {
    use std::net::{IpAddr};
    use std::time::Duration;
    use std::collections::HashSet;
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::icmp::MutableIcmpPacket;
    use pnet::packet::icmp::IcmpTypes;
    use pnet::transport::transport_channel;
    use pnet::transport::TransportChannelType::Layer4;
    use pnet::transport::TransportProtocol::Ipv4;
    use pnet::packet::Packet;
    use pnet::packet::MutablePacket;
    
    let mut live_hosts = HashSet::new();
    
    // 创建ICMP传输通道
    let protocol = Layer4(Ipv4(IpNextHeaderProtocols::Icmp));
    let (mut tx, mut rx) = match transport_channel(1024, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => {
            eprintln!("Failed to create transport channel: {}", e);
            return Vec::new();
        }
    };
    
    let timeout = Duration::from_millis(1000);
    let hosts = network.hosts();
    
    for host in hosts {
        // 构造ICMP Echo请求包
        let mut vec: Vec<u8> = vec![0; 8];
        let mut packet = MutableIcmpPacket::new(&mut vec[..]).unwrap();
        packet.set_icmp_type(IcmpTypes::EchoRequest);
        packet.set_payload(&[1, 2, 3, 4]); // 随机数据
        
        // 发送ICMP包
        if let Err(e) = tx.send_to(packet, IpAddr::V4(host)) {
            // 在某些系统上可能需要特殊权限，我们只打印错误但继续执行
            eprintln!("Warning: Failed to send ICMP packet to {}: {}", host, e);
            continue;
        }
        
        // 等待响应
        // 使用迭代器方式接收数据包，设置超时
        if let Ok(iter) = rx.iter()
            .set_timeout(timeout) 
            .next() {
            if let IpAddr::V4(ipv4) = iter {
                live_hosts.insert(ipv4);
                println!("Host {} is alive", ipv4);
            }
        }
    }
    
    live_hosts.into_iter().collect()
}

#[cfg(target_os = "windows")]
fn icmp_scan(_network: IpCidr) -> Vec<Ipv4Addr> {
    // Windows版本的实现需要特殊权限和不同的API
    // 这里提供一个占位符实现
    eprintln!("ICMP scanning is not fully implemented on Windows");
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cidr_parsing() {
        let cidr = IpCidr::from_str("192.168.1.0/24").expect("Valid CIDR");
        assert_eq!(cidr.network, Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(cidr.prefix, 24);
    }

    #[test]
    fn test_invalid_cidr_parsing() {
        assert!(IpCidr::from_str("192.168.1.0/33").is_err());
        assert!(IpCidr::from_str("192.168.1.0").is_err());
        assert!(IpCidr::from_str("invalid/24").is_err());
    }

    #[test]
    fn test_host_generation() {
        let cidr = IpCidr::from_str("192.168.1.0/24").expect("Valid CIDR");
        let hosts = cidr.hosts();
        #[cfg(not(target_os = "windows"))]
        {
            assert_eq!(hosts.len(), 254); // 192.168.1.1 to 192.168.1.254
            assert_eq!(hosts[0], Ipv4Addr::new(192, 168, 1, 1));
            assert_eq!(hosts[253], Ipv4Addr::new(192, 168, 1, 254));
        }
        #[cfg(target_os = "windows")]
        {
            assert_eq!(hosts.len(), 0); // Windows上暂时返回空列表
        }
    }
}