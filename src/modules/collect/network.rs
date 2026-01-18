//! 网络配置收集模块
//!
//! 收集网络接口、路由、ARP 表、网络连接等信息

#![allow(dead_code)]

use serde::{Deserialize, Serialize};

/// 网络信息收集器
pub struct NetworkCollector;

impl NetworkCollector {
    /// 创建新的网络信息收集器
    pub fn new() -> Self {
        Self
    }

    /// 收集所有网络接口
    pub fn collect_interfaces(&self) -> Vec<NetworkInterface> {
        if cfg!(windows) {
            self.collect_windows_interfaces()
        } else if cfg!(target_os = "linux") {
            self.collect_linux_interfaces()
        } else if cfg!(target_os = "macos") {
            self.collect_macos_interfaces()
        } else {
            // 回退到通用实现
            self.collect_generic_interfaces()
        }
    }

    /// 收集路由表
    pub fn collect_routes(&self) -> Vec<RouteEntry> {
        if cfg!(windows) {
            self.collect_windows_routes()
        } else if cfg!(target_os = "linux") {
            self.collect_linux_routes()
        } else if cfg!(target_os = "macos") {
            self.collect_macos_routes()
        } else {
            self.collect_generic_routes()
        }
    }

    /// 收集 ARP 表
    pub fn collect_arp_table(&self) -> Vec<ArpEntry> {
        self.collect_arp_table_internal()
    }

    #[cfg(windows)]
    fn collect_arp_table_internal(&self) -> Vec<ArpEntry> {
        self.collect_windows_arp()
    }

    #[cfg(unix)]
    fn collect_arp_table_internal(&self) -> Vec<ArpEntry> {
        self.collect_unix_arp()
    }

    #[cfg(not(any(windows, unix)))]
    fn collect_arp_table_internal(&self) -> Vec<ArpEntry> {
        Vec::new()
    }

    /// 收集网络连接
    pub fn collect_connections(&self) -> Vec<NetworkConnection> {
        self.collect_connections_internal()
    }

    #[cfg(windows)]
    fn collect_connections_internal(&self) -> Vec<NetworkConnection> {
        self.collect_windows_connections()
    }

    #[cfg(unix)]
    fn collect_connections_internal(&self) -> Vec<NetworkConnection> {
        self.collect_unix_connections()
    }

    #[cfg(not(any(windows, unix)))]
    fn collect_connections_internal(&self) -> Vec<NetworkConnection> {
        Vec::new()
    }

    // ==================== Windows 实现 ====================

    #[cfg(windows)]
    fn collect_windows_interfaces(&self) -> Vec<NetworkInterface> {
        let mut interfaces = Vec::new();

        // 尝试获取本地IP地址
        if let Ok(ip) = local_ip_address::local_ip() {
            interfaces.push(NetworkInterface {
                name: "default".to_string(),
                ip: ip.to_string(),
                netmask: "255.255.255.0".to_string(),
                mac: None,
                ipv6: None,
                is_up: true,
                gateway: None,
                dns_servers: Vec::new(),
            });
        }

        interfaces
    }

    #[cfg(windows)]
    fn collect_windows_routes(&self) -> Vec<RouteEntry> {
        vec![
            RouteEntry {
                destination: "0.0.0.0/0".to_string(),
                gateway: "unknown".to_string(),
                netmask: "0.0.0.0".to_string(),
                metric: 0,
                interface: "default".to_string(),
            }
        ]
    }

    #[cfg(windows)]
    fn collect_windows_arp(&self) -> Vec<ArpEntry> {
        // Windows: 可以使用 arp -a 命令
        use std::process::Command;
        let mut arp_table = Vec::new();

        if let Ok(output) = Command::new("arp")
            .args(&["-a"])
            .output()
        {
            let content = String::from_utf8_lossy(&output.stdout);
            // 解析 arp -a 输出
            for line in content.lines() {
                if line.contains("dynamic") || line.contains("static") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        arp_table.push(ArpEntry {
                            ip: parts[0].to_string(),
                            mac: parts[1].to_string(),
                            interface: "default".to_string(),
                            interface_ip: None,
                            state: "dynamic".to_string(),
                        });
                    }
                }
            }
        }

        arp_table
    }

    #[cfg(windows)]
    fn collect_windows_connections(&self) -> Vec<NetworkConnection> {
        // Windows: 使用 netstat 命令
        use std::process::Command;
        let mut connections = Vec::new();

        if let Ok(output) = Command::new("netstat")
            .args(&["-ano"])
            .output()
        {
            let content = String::from_utf8_lossy(&output.stdout);
            // 解析 netstat -ano 输出
            for line in content.lines().skip(4) {
                // 跳过前4行标题
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 5 {
                    let protocol = parts[0].to_string();
                    if protocol == "TCP" || protocol == "UDP" {
                        let (local_addr, local_port) = parse_addr_port(parts[1]);
                        let (remote_addr, remote_port) = parse_addr_port(parts[2]);
                        let state = if protocol == "TCP" { parts[3].to_string() } else { "N/A".to_string() };
                        let pid = parts[4].parse::<u32>().ok();

                        connections.push(NetworkConnection {
                            protocol,
                            local_addr,
                            local_port,
                            remote_addr,
                            remote_port,
                            state,
                            pid,
                        });
                    }
                }
            }
        }

        connections
    }

    // ==================== Linux 实现 ====================

    #[cfg(target_os = "linux")]
    fn collect_linux_interfaces(&self) -> Vec<NetworkInterface> {
        let mut interfaces = Vec::new();

        // 尝试读取 /proc/net/dev
        if let Ok(content) = std::fs::read_to_string("/proc/net/dev") {
            for line in content.lines().skip(2) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let iface_name = parts[0].trim_end_matches(':').to_string();

                    // 尝试从 /sys/class/net/<iface>/address 获取 MAC 地址
                    let mac_path = format!("/sys/class/net/{}/address", iface_name);
                    let mac = std::fs::read_to_string(&mac_path)
                        .ok()
                        .map(|m| m.trim().to_string());

                    interfaces.push(NetworkInterface {
                        name: iface_name,
                        ip: "unknown".to_string(),
                        netmask: "unknown".to_string(),
                        mac,
                        ipv6: None,
                        is_up: true,
                        gateway: None,
                        dns_servers: Vec::new(),
                    });
                }
            }
        }

        // 如果没有找到接口，尝试通用方法
        if interfaces.is_empty() {
            interfaces = self.collect_generic_interfaces();
        }

        interfaces
    }

    #[cfg(target_os = "linux")]
    fn collect_linux_routes(&self) -> Vec<RouteEntry> {
        let mut routes = Vec::new();

        // 尝试读取 /proc/net/route
        if let Ok(content) = std::fs::read_to_string("/proc/net/route") {
            for line in content.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 8 {
                    let dest = hex_to_ip(parts[1]);
                    let gateway = hex_to_ip(parts[2]);
                    routes.push(RouteEntry {
                        destination: format!("{}/24", dest),
                        gateway,
                        netmask: "255.255.255.0".to_string(),
                        metric: parts[3].parse().unwrap_or(0),
                        interface: parts[0].to_string(),
                    });
                }
            }
        }

        // 添加默认路由
        if routes.is_empty() {
            routes.push(RouteEntry {
                destination: "0.0.0.0/0".to_string(),
                gateway: "unknown".to_string(),
                netmask: "0.0.0.0".to_string(),
                metric: 0,
                interface: "default".to_string(),
            });
        }

        routes
    }

    #[cfg(target_os = "linux")]
    fn collect_unix_arp(&self) -> Vec<ArpEntry> {
        let mut arp_table = Vec::new();

        // 尝试读取 /proc/net/arp
        if let Ok(content) = std::fs::read_to_string("/proc/net/arp") {
            for line in content.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 6 {
                    arp_table.push(ArpEntry {
                        ip: parts[0].to_string(),
                        mac: parts[3].to_string(),
                        interface: parts[5].to_string(),
                        interface_ip: None,
                        state: parts[2].to_string(),
                    });
                }
            }
        }

        arp_table
    }

    #[cfg(target_os = "linux")]
    fn collect_unix_connections(&self) -> Vec<NetworkConnection> {
        let mut connections = Vec::new();

        // 读取 TCP 连接
        if let Ok(content) = std::fs::read_to_string("/proc/net/tcp") {
            connections.extend(parse_linux_tcp(&content, "TCP"));
        }

        // 读取 UDP 连接
        if let Ok(content) = std::fs::read_to_string("/proc/net/udp") {
            connections.extend(parse_linux_tcp(&content, "UDP"));
        }

        connections
    }

    // ==================== macOS 实现 ====================

    #[cfg(target_os = "macos")]
    fn collect_macos_interfaces(&self) -> Vec<NetworkInterface> {
        use std::process::Command;

        let mut interfaces = Vec::new();

        if let Ok(output) = Command::new("ifconfig")
            .arg("-a")
            .output()
        {
            let content = String::from_utf8_lossy(&output.stdout);
            interfaces = parse_macos_ifconfig(&content);
        }

        if interfaces.is_empty() {
            interfaces = self.collect_generic_interfaces();
        }

        interfaces
    }

    #[cfg(target_os = "macos")]
    fn collect_macos_routes(&self) -> Vec<RouteEntry> {
        use std::process::Command;
        let mut routes = Vec::new();

        if let Ok(output) = Command::new("netstat")
            .args(&["-rn"])
            .output()
        {
            let content = String::from_utf8_lossy(&output.stdout);
            // 解析 macOS netstat -rn 输出
            for line in content.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 6 {
                    routes.push(RouteEntry {
                        destination: parts[0].to_string(),
                        gateway: parts[1].to_string(),
                        netmask: parts[2].to_string(),
                        metric: 0,
                        interface: parts[5].to_string(),
                    });
                }
            }
        }

        if routes.is_empty() {
            routes = self.collect_generic_routes();
        }

        routes
    }

    #[cfg(target_os = "macos")]
    fn collect_unix_arp(&self) -> Vec<ArpEntry> {
        use std::process::Command;
        let mut arp_table = Vec::new();

        if let Ok(output) = Command::new("arp")
            .arg("-a")
            .output()
        {
            let content = String::from_utf8_lossy(&output.stdout);
            for line in content.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 {
                    arp_table.push(ArpEntry {
                        ip: parts[1].trim_end_matches(')').to_string(),
                        mac: parts[3].to_string(),
                        interface: parts[5].to_string(),
                        interface_ip: None,
                        state: "dynamic".to_string(),
                    });
                }
            }
        }

        arp_table
    }

    #[cfg(target_os = "macos")]
    fn collect_unix_connections(&self) -> Vec<NetworkConnection> {
        use std::process::Command;
        let mut connections = Vec::new();

        if let Ok(output) = Command::new("netstat")
            .args(&["-an"])
            .output()
        {
            let content = String::from_utf8_lossy(&output.stdout);
            for line in content.lines() {
                if line.starts_with("tcp") || line.starts_with("udp") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 6 {
                        let protocol = parts[0].to_string();
                        let (local_addr, local_port) = parse_addr_port(parts[3]);
                        let (remote_addr, remote_port) = parse_addr_port(parts[4]);
                        let state = if protocol == "tcp" { parts[5].to_string() } else { "N/A".to_string() };

                        connections.push(NetworkConnection {
                            protocol,
                            local_addr,
                            local_port,
                            remote_addr,
                            remote_port,
                            state,
                            pid: None,
                        });
                    }
                }
            }
        }

        connections
    }

    // ==================== Unix 通用实现 ====================

    #[cfg(unix)]
    fn collect_unix_connections(&self) -> Vec<NetworkConnection> {
        Vec::new()
    }

    #[cfg(unix)]
    fn collect_unix_arp(&self) -> Vec<ArpEntry> {
        Vec::new()
    }

    // ==================== 通用实现（回退） ====================

    #[cfg(not(windows))]
    fn collect_windows_interfaces(&self) -> Vec<NetworkInterface> {
        self.collect_generic_interfaces()
    }

    #[cfg(not(windows))]
    fn collect_windows_routes(&self) -> Vec<RouteEntry> {
        self.collect_generic_routes()
    }

    #[cfg(not(windows))]
    fn collect_windows_arp(&self) -> Vec<ArpEntry> {
        Vec::new()
    }

    #[cfg(not(windows))]
    fn collect_windows_connections(&self) -> Vec<NetworkConnection> {
        Vec::new()
    }

    #[cfg(not(target_os = "macos"))]
    fn collect_macos_interfaces(&self) -> Vec<NetworkInterface> {
        self.collect_generic_interfaces()
    }

    #[cfg(not(target_os = "macos"))]
    fn collect_macos_routes(&self) -> Vec<RouteEntry> {
        self.collect_generic_routes()
    }

    #[cfg(not(target_os = "linux"))]
    fn collect_linux_interfaces(&self) -> Vec<NetworkInterface> {
        self.collect_generic_interfaces()
    }

    #[cfg(not(target_os = "linux"))]
    fn collect_linux_routes(&self) -> Vec<RouteEntry> {
        self.collect_generic_routes()
    }

    fn collect_generic_interfaces(&self) -> Vec<NetworkInterface> {
        local_ip_address::local_ip()
            .ok()
            .map(|ip| vec![NetworkInterface {
                name: "default".to_string(),
                ip: ip.to_string(),
                netmask: "255.255.255.0".to_string(),
                mac: None,
                ipv6: None,
                is_up: true,
                gateway: None,
                dns_servers: Vec::new(),
            }])
            .unwrap_or_default()
    }

    fn collect_generic_routes(&self) -> Vec<RouteEntry> {
        vec![
            RouteEntry {
                destination: "0.0.0.0/0".to_string(),
                gateway: "unknown".to_string(),
                netmask: "0.0.0.0".to_string(),
                metric: 0,
                interface: "default".to_string(),
            }
        ]
    }
}

impl Default for NetworkCollector {
    fn default() -> Self {
        Self::new()
    }
}

// ==================== 辅助函数 ====================

/// 解析地址和端口
fn parse_addr_port(addr_str: &str) -> (String, u16) {
    let parts: Vec<&str> = addr_str.rsplitn(2, ':').collect();
    if parts.len() == 2 {
        let addr = if parts.len() > 1 { parts[1].to_string() } else { "0.0.0.0".to_string() };
        let port = parts[0].parse::<u16>().unwrap_or(0);
        (addr, port)
    } else {
        (addr_str.to_string(), 0)
    }
}

/// 将十六进制转换为 IP 地址
fn hex_to_ip(hex: &str) -> String {
    if let Ok(num) = u32::from_str_radix(hex, 16) {
        format!("{}.{}.{}.{}", num & 0xFF, (num >> 8) & 0xFF, (num >> 16) & 0xFF, (num >> 24) & 0xFF)
    } else {
        "unknown".to_string()
    }
}

/// 解析 macOS ifconfig 输出
#[cfg(target_os = "macos")]
fn parse_macos_ifconfig(content: &str) -> Vec<NetworkInterface> {
    let mut interfaces = Vec::new();
    let lines: Vec<&str> = content.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i];

        // 检查是否是接口定义行
        if line.contains(": flags=") {
            let parts: Vec<&str> = line.split(':').collect();
            let iface_name = parts[0].to_string();

            let mut ip = String::new();
            let mut mac = String::new();
            let mut netmask = String::new();

            // 查找后续行中的 IP 地址和 MAC 地址
            let mut j = i + 1;
            while j < lines.len() && !lines[j].contains(": flags=") && lines[j].trim() != "" {
                let info_line = lines[j].trim();

                if info_line.starts_with("inet ") {
                    let addr_parts: Vec<&str> = info_line.split_whitespace().collect();
                    if addr_parts.len() >= 2 {
                        ip = addr_parts[1].to_string();
                        if addr_parts.len() >= 4 {
                            netmask = addr_parts[3].to_string();
                        }
                    }
                } else if info_line.starts_with("ether ") {
                    let addr_parts: Vec<&str> = info_line.split_whitespace().collect();
                    if addr_parts.len() >= 2 {
                        mac = addr_parts[1].to_string();
                    }
                }

                j += 1;
            }

            interfaces.push(NetworkInterface {
                name: iface_name,
                ip: if ip.is_empty() { "unknown".to_string() } else { ip },
                netmask: if netmask.is_empty() { "255.255.255.0".to_string() } else { netmask },
                mac: if mac.is_empty() { None } else { Some(mac) },
                ipv6: None,
                is_up: line.contains("UP") || line.contains("RUNNING"),
                gateway: None,
                dns_servers: Vec::new(),
            });

            i = j;
        } else {
            i += 1;
        }
    }

    interfaces
}

/// 解析 Linux TCP/UDP 连接
#[cfg(target_os = "linux")]
fn parse_linux_tcp(content: &str, protocol: &str) -> Vec<NetworkConnection> {
    let mut connections = Vec::new();

    for line in content.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 10 {
            let local_addr = hex_to_ip_addr(parts[1]);
            let remote_addr = hex_to_ip_addr(parts[2]);
            let state = if protocol == "TCP" {
                tcp_state_to_string(parts[3].parse().unwrap_or(0))
            } else {
                "N/A".to_string()
            };

            connections.push(NetworkConnection {
                protocol: protocol.to_string(),
                local_addr: local_addr.0,
                local_port: local_addr.1,
                remote_addr: remote_addr.0,
                remote_port: remote_addr.1,
                state,
                pid: None,
            });
        }
    }

    connections
}

#[cfg(target_os = "linux")]
fn hex_to_ip_addr(hex: &str) -> (String, u16) {
    let parts: Vec<&str> = hex.split(':').collect();
    if parts.len() == 2 {
        let ip_hex = parts[0];
        let port_hex = parts[1];

        if let Ok(port) = u16::from_str_radix(port_hex, 16) {
            let ip = if ip_hex.len() == 8 {
                let a = u8::from_str_radix(&ip_hex[6..8], 16).unwrap_or(0);
                let b = u8::from_str_radix(&ip_hex[4..6], 16).unwrap_or(0);
                let c = u8::from_str_radix(&ip_hex[2..4], 16).unwrap_or(0);
                let d = u8::from_str_radix(&ip_hex[0..2], 16).unwrap_or(0);
                format!("{}.{}.{}.{}", d, c, b, a)
            } else {
                "unknown".to_string()
            };

            return (ip, port);
        }
    }

    ("unknown".to_string(), 0)
}

#[cfg(target_os = "linux")]
fn tcp_state_to_string(state: u64) -> String {
    match state {
        1 => "ESTABLISHED".to_string(),
        2 => "SYN_SENT".to_string(),
        3 => "SYN_RECV".to_string(),
        4 => "FIN_WAIT1".to_string(),
        5 => "FIN_WAIT2".to_string(),
        6 => "TIME_WAIT".to_string(),
        7 => "CLOSE".to_string(),
        8 => "CLOSE_WAIT".to_string(),
        9 => "LAST_ACK".to_string(),
        10 => "LISTEN".to_string(),
        11 => "CLOSING".to_string(),
        _ => "UNKNOWN".to_string(),
    }
}

// ==================== 数据结构 ====================

/// 网络接口信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub ip: String,
    pub netmask: String,
    pub mac: Option<String>,
    pub ipv6: Option<String>,
    pub is_up: bool,
    pub gateway: Option<String>,
    pub dns_servers: Vec<String>,
}

/// 路由条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteEntry {
    pub destination: String,
    pub gateway: String,
    pub netmask: String,
    pub metric: u32,
    pub interface: String,
}

/// ARP 条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArpEntry {
    pub ip: String,
    pub mac: String,
    pub interface: String,
    pub interface_ip: Option<String>,
    pub state: String,
}

/// 网络连接
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub protocol: String,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: String,
    pub pid: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_collector_creation() {
        let collector = NetworkCollector::new();
        let interfaces = collector.collect_interfaces();
        // 至少应该有一个默认接口
        assert!(!interfaces.is_empty());
    }

    #[test]
    fn test_collect_routes() {
        let collector = NetworkCollector::new();
        let routes = collector.collect_routes();
        // 至少应该有默认路由
        assert!(!routes.is_empty());
    }

    #[test]
    fn test_hex_to_ip() {
        assert_eq!(hex_to_ip("0100007F"), "127.0.0.1");
        assert_eq!(hex_to_ip("0000A8C0"), "192.168.0.0");
    }

    #[test]
    fn test_parse_addr_port() {
        let (addr, port) = parse_addr_port("192.168.1.1:80");
        assert_eq!(addr, "192.168.1.1");
        assert_eq!(port, 80);
    }
}
