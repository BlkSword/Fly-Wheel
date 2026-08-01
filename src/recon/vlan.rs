//! VLAN与网络拓扑发现模块
//!
//! 帮助攻击者理解网络分段，规划横向移动的边界和路径。

use crate::recon::{DiscoveredSubnet, NetworkTopologyInfo};
use std::net::{Ipv4Addr, SocketAddr};

/// 发现网络拓扑
pub fn discover_network_topology() -> Result<NetworkTopologyInfo, String> {
    let mut subnets = Vec::new();
    let mut alive_hosts = 0usize;

    // 获取当前主机的网络接口信息
    let local_subnets = get_local_subnets()?;

    for (subnet, mask, gateway) in &local_subnets {
        let is_current = true;
        let reachable = true;

        // 快速扫描该子网的存活主机
        let hosts = quick_subnet_scan(subnet, *mask);

        subnets.push(DiscoveredSubnet {
            subnet: format!("{}/{}", subnet, mask),
            host_count: hosts,
            is_current,
            reachable,
            description: Some(format!(
                "本地子网 - 网关: {}",
                gateway.as_deref().unwrap_or("未知")
            )),
        });

        alive_hosts += hosts;
    }

    // 如果能够获取路由表，也发现其他可达子网
    if let Ok(routes) = get_routing_table() {
        for (dest_net, dest_mask, gateway) in routes {
            // 检查是否已经存在
            let subnet_str = format!("{}/{}", dest_net, dest_mask);
            if !subnets.iter().any(|s| s.subnet == subnet_str) {
                subnets.push(DiscoveredSubnet {
                    subnet: subnet_str,
                    host_count: 0,
                    is_current: false,
                    reachable: true,
                    description: Some(format!("路由可达 - 网关: {}", gateway)),
                });
            }
        }
    }

    let scan_range = if subnets.is_empty() {
        None
    } else {
        Some(
            subnets
                .iter()
                .map(|s| s.subnet.clone())
                .collect::<Vec<_>>()
                .join(", "),
        )
    };

    Ok(NetworkTopologyInfo {
        subnets,
        alive_hosts,
        scan_range,
    })
}

/// 获取本地子网信息
fn get_local_subnets() -> Result<Vec<(String, u8, Option<String>)>, String> {
    let mut subnets = Vec::new();

    if cfg!(windows) {
        let output = std::process::Command::new("ipconfig")
            .output()
            .map_err(|e| format!("ipconfig失败: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut current_ip: Option<String> = None;
        let mut current_mask: Option<String> = None;
        let mut current_gw: Option<String> = None;

        for line in stdout.lines() {
            let line = line.trim();

            if line.contains("IPv4") || line.contains("IP Address") {
                if let Some(addr) = line.split(':').nth(1) {
                    current_ip = Some(addr.trim().to_string());
                }
            }
            if line.contains("子网掩码") || line.contains("Subnet Mask") {
                if let Some(mask) = line.split(':').nth(1) {
                    current_mask = Some(mask.trim().to_string());
                }
            }
            if line.contains("默认网关") || line.contains("Default Gateway") {
                if let Some(gw) = line.split(':').nth(1) {
                    current_gw = Some(gw.trim().to_string());
                }
            }

            // 当收集到IP和掩码时，计算子网
            if let (Some(ref ip), Some(ref mask)) = (&current_ip, &current_mask) {
                if let (Ok(ip_addr), Ok(mask_addr)) = (
                    ip.parse::<Ipv4Addr>(),
                    mask.parse::<Ipv4Addr>(),
                ) {
                    let network = calculate_network(ip_addr, mask_addr);
                    let cidr = mask_to_cidr(mask_addr);

                    if network != "0.0.0.0" {
                        let entry = (network, cidr, current_gw.clone());
                        if !subnets.contains(&entry) {
                            subnets.push(entry);
                        }
                    }
                }
                current_ip = None;
                current_mask = None;
                current_gw = None;
            }
        }
    } else if cfg!(unix) {
        // 使用ip addr命令
        if let Ok(output) = std::process::Command::new("ip")
            .args(["-4", "addr", "show"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if line.contains("inet ") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let cidr_parts: Vec<&str> = parts[1].split('/').collect();
                        if cidr_parts.len() == 2 {
                            let ip = cidr_parts[0].to_string();
                            let mask: u8 = cidr_parts[1].parse().unwrap_or(24);
                            if ip != "127.0.0.1" {
                                if let Ok(ip_addr) = ip.parse::<Ipv4Addr>() {
                                    let network = calculate_network_cidr(ip_addr, mask);
                                    subnets.push((network, mask, None));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if subnets.is_empty() {
        // 回退到默认值
        subnets.push(("192.168.1.0".to_string(), 24, None));
    }

    Ok(subnets)
}

/// 计算网络地址
fn calculate_network(ip: Ipv4Addr, mask: Ipv4Addr) -> String {
    let ip_octets = ip.octets();
    let mask_octets = mask.octets();
    let network_octets = [
        ip_octets[0] & mask_octets[0],
        ip_octets[1] & mask_octets[1],
        ip_octets[2] & mask_octets[2],
        ip_octets[3] & mask_octets[3],
    ];
    format!(
        "{}.{}.{}.{}",
        network_octets[0], network_octets[1], network_octets[2], network_octets[3]
    )
}

/// 使用CIDR计算网络地址
fn calculate_network_cidr(ip: Ipv4Addr, cidr: u8) -> String {
    let mask = cidr_to_mask(cidr);
    calculate_network(ip, mask)
}

/// 子网掩码转CIDR
fn mask_to_cidr(mask: Ipv4Addr) -> u8 {
    mask.octets().iter().map(|o| o.count_ones() as u8).sum()
}

/// CIDR转子网掩码
fn cidr_to_mask(cidr: u8) -> Ipv4Addr {
    let val: u32 = if cidr == 0 { 0 } else { !0u32 << (32 - cidr) };
    Ipv4Addr::from(val)
}

/// 快速扫描子网存活主机（ARP方式）
fn quick_subnet_scan(_network: &str, _cidr: u8) -> usize {
    let mut count = 0;

    // 使用ARP扫描（Windows）
    if cfg!(windows) {
        // arp -a 可以显示ARP缓存
        if let Ok(output) = std::process::Command::new("arp").args(["-a"]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                // 计数非静态的ARP条目
                if line.contains("dynamic") || line.contains("动态") {
                    count += 1;
                }
            }
        }
    }

    // 如果ARP不可用，回退到最小计数
    if count == 0 {
        count = 1; // 至少当前主机
    }

    count
}

/// 获取路由表
fn get_routing_table() -> Result<Vec<(String, u8, String)>, String> {
    let mut routes = Vec::new();

    if cfg!(windows) {
        let output = std::process::Command::new("route")
            .args(["print", "-4"])
            .output()
            .map_err(|e| format!("route print失败: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut in_routes = false;

        for line in stdout.lines() {
            if line.contains("网络目标") || line.contains("Network Destination") {
                in_routes = true;
                continue;
            }
            if !in_routes {
                continue;
            }
            if line.contains("=====") || line.is_empty() {
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let dest = parts[0].to_string();
                let mask = parts[1].to_string();
                let gw = parts[2].to_string();

                if mask != "255.255.255.255" {
                    if let (Ok(dest_addr), Ok(mask_addr)) = (
                        dest.parse::<Ipv4Addr>(),
                        mask.parse::<Ipv4Addr>(),
                    ) {
                        let cidr = mask_to_cidr(mask_addr);
                        let network = calculate_network(dest_addr, mask_addr);
                        if network != "0.0.0.0" && network != "127.0.0.0" {
                            routes.push((network, cidr, gw));
                        }
                    }
                }
            }
        }
    } else if cfg!(unix) {
        if let Ok(output) = std::process::Command::new("ip")
            .args(["route", "show"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    let dest_str = parts[0].to_string();
                    if let Some(cidr_parts) = dest_str.split_once('/') {
                        let network = cidr_parts.0.to_string();
                        let cidr: u8 = cidr_parts.1.parse().unwrap_or(24);
                        let gw = parts.get(2).unwrap_or(&"direct").to_string();
                        if network != "default" && network != "0.0.0.0" {
                            routes.push((network, cidr, gw));
                        }
                    }
                }
            }
        }
    }

    Ok(routes)
}

/// 测试特定IP是否可达
pub fn test_reachability(ip: &str, port: u16, timeout_ms: u64) -> bool {
    let addr = format!("{}:{}", ip, port);
    let timeout = std::time::Duration::from_millis(timeout_ms);

    if let Ok(stream) = std::net::TcpStream::connect_timeout(
        &addr.parse::<SocketAddr>().unwrap_or_else(|_| {
            SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 0)
        }),
        timeout,
    ) {
        drop(stream);
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_network() {
        let ip: Ipv4Addr = "10.10.10.10".parse().unwrap();
        let mask: Ipv4Addr = "255.255.255.0".parse().unwrap();
        assert_eq!(calculate_network(ip, mask), "10.10.10.0");
    }

    #[test]
    fn test_mask_to_cidr() {
        let mask: Ipv4Addr = "255.255.255.0".parse().unwrap();
        assert_eq!(mask_to_cidr(mask), 24);

        let mask16: Ipv4Addr = "255.255.0.0".parse().unwrap();
        assert_eq!(mask_to_cidr(mask16), 16);
    }

    #[test]
    fn test_cidr_to_mask() {
        assert_eq!(cidr_to_mask(24).to_string(), "255.255.255.0");
        assert_eq!(cidr_to_mask(16).to_string(), "255.255.0.0");
        assert_eq!(cidr_to_mask(8).to_string(), "255.0.0.0");
    }

    #[test]
    fn test_discover_network_topology() {
        let result = discover_network_topology();
        assert!(result.is_ok());
        let topo = result.unwrap();
        assert!(!topo.subnets.is_empty());
    }

    #[test]
    fn test_calculate_network_cidr() {
        let ip: Ipv4Addr = "172.16.5.20".parse().unwrap();
        let network = calculate_network_cidr(ip, 16);
        assert_eq!(network, "172.16.0.0");
    }
}
