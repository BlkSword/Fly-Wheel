//! 网络拓扑可视化模块
//!
//! 基于扫描结果生成网络拓扑图，支持 ASCII 和 HTML 两种输出格式。
//!
//! 功能:
//! - 自动识别网络段和网关
//! - 显示主机存活状态和开放端口
//! - HTML 输出包含交互式展开/折叠
//! - ASCII 输出适合终端直接查看

use crate::scanner::{HostResult, ScanResult};
use std::collections::HashMap;

/// 拓扑节点
#[derive(Debug, Clone)]
pub struct TopoNode {
    pub ip: String,
    pub hostname: Option<String>,
    pub is_alive: bool,
    pub is_gateway: bool,
    pub open_ports: Vec<u16>,
    pub services: Vec<String>,
    pub children: Vec<String>, // 连接的 IP
}

/// 拓扑网络段
#[derive(Debug, Clone)]
pub struct TopoSubnet {
    pub cidr: String,
    pub gateway: Option<String>,
    pub nodes: Vec<TopoNode>,
}

/// 拓扑图生成器
pub struct TopologyGenerator {
    pub title: String,
    subnets: Vec<TopoSubnet>,
}

impl TopologyGenerator {
    /// 从扫描结果创建拓扑生成器
    pub fn from_scan_result(result: &ScanResult) -> Self {
        let mut subnets = Vec::new();

        // 按 /24 网段分组
        let mut subnet_map: HashMap<String, Vec<&HostResult>> = HashMap::new();
        for host in &result.hosts {
            let subnet = extract_subnet_24(&host.ip);
            subnet_map.entry(subnet).or_default().push(host);
        }

        for (cidr, hosts) in &subnet_map {
            let gateway = find_gateway(hosts);
            let nodes: Vec<TopoNode> = hosts
                .iter()
                .map(|host| {
                    let services: Vec<String> = host
                        .open_ports
                        .iter()
                        .map(|p| {
                            p.service
                                .clone()
                                .unwrap_or_else(|| format!("{}", p.port))
                        })
                        .collect();

                    let is_gw = gateway == Some(&host.ip);

                    TopoNode {
                        ip: host.ip.clone(),
                        hostname: host.hostname.clone(),
                        is_alive: host.is_alive,
                        is_gateway: is_gw,
                        open_ports: host.open_ports.iter().map(|p| p.port).collect(),
                        services,
                        children: Vec::new(),
                    }
                })
                .collect();

            subnets.push(TopoSubnet {
                cidr: cidr.clone(),
                gateway: gateway.map(|s| s.to_string()),
                nodes,
            });
        }

        Self {
            title: format!("网络拓扑 - {}", result.scan_type.name()),
            subnets,
        }
    }

    /// 生成 ASCII 拓扑图
    pub fn to_ascii(&self) -> String {
        let mut output = String::new();

        output.push_str(&format!("┌{}\n", "─".repeat(78)));
        output.push_str(&format!("│ {}: {}\n", "网络拓扑图", self.title));
        output.push_str(&format!("├{}\n", "─".repeat(78)));

        for subnet in &self.subnets {
            output.push_str("│\n");
            output.push_str(&format!("│ ▶ {} ({} 主机)\n", subnet.cidr, subnet.nodes.len()));
            output.push_str(&format!("│ ┌{}\n", "─".repeat(74)));

            if let Some(gw) = &subnet.gateway {
                output.push_str(&format!("│ │ ★ 网关: {}\n", gw));
            }

            for node in &subnet.nodes {
                let status = if node.is_alive { "✓ 存活" } else { "✗ 离线" };
                let gw_mark = if node.is_gateway { " [GW]" } else { "" };
                let hostname = node
                    .hostname
                    .as_deref()
                    .map(|h| format!(" ({})", h))
                    .unwrap_or_default();

                if node.open_ports.is_empty() {
                    output.push_str(&format!(
                        "│ │   {} {}{}{} — 无开放端口\n",
                        status, node.ip, hostname, gw_mark
                    ));
                } else {
                    let ports: Vec<String> = node
                        .open_ports
                        .iter()
                        .zip(node.services.iter())
                        .map(|(p, s)| format!("{}/{}", p, s))
                        .collect();
                    output.push_str(&format!(
                        "│ │   {} {}{}{}\n│ │     └ 端口: {}\n",
                        status,
                        node.ip,
                        hostname,
                        gw_mark,
                        ports.join(", ")
                    ));
                }
            }

            output.push_str(&format!("│ └{}\n", "─".repeat(74)));
        }

        output.push_str(&format!(
            "├{}\n│ 总计: {} 网段, {} 主机\n└{}\n",
            "─".repeat(78),
            self.subnets.len(),
            self.total_hosts(),
            "─".repeat(78)
        ));

        output
    }

    /// 生成 HTML 拓扑图
    pub fn to_html(&self) -> String {
        let mut html = String::new();

        html.push_str("<!DOCTYPE html>\n<html lang=\"zh\">\n<head>\n");
        html.push_str("<meta charset=\"UTF-8\">\n");
        html.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
        html.push_str(&format!("<title>{}</title>\n", self.title));
        html.push_str("<style>\n");
        html.push_str(include_str!("topology_styles.css"));
        html.push_str("</style>\n</head>\n<body>\n");

        html.push_str("<div class=\"container\">\n");
        html.push_str(&format!("<h1>{}</h1>\n", self.title));
        html.push_str(&format!(
            "<p class=\"summary\">{} 网段 · {} 主机</p>\n",
            self.subnets.len(),
            self.total_hosts()
        ));

        for subnet in &self.subnets {
            html.push_str(&format!(
                "<div class=\"subnet\">\n<h2 class=\"subnet-title\" onclick=\"toggleSubnet(this)\">▼ {} <span class=\"host-count\">({} 主机)</span></h2>\n",
                subnet.cidr,
                subnet.nodes.len()
            ));
            html.push_str("<div class=\"subnet-content\">\n");

            if let Some(gw) = &subnet.gateway {
                html.push_str(&format!(
                    "<div class=\"node gateway\">\n<span class=\"icon\">★</span> 网关: {}\n</div>\n",
                    gw
                ));
            }

            for node in &subnet.nodes {
                let status_class = if node.is_alive { "alive" } else { "dead" };
                let gw_class = if node.is_gateway { " gateway" } else { "" };

                html.push_str(&format!(
                    "<div class=\"node {}{}\">\n<div class=\"node-header\">\n<span class=\"status-dot\"></span>\n<span class=\"ip\">{}</span>\n",
                    status_class, gw_class, node.ip
                ));

                if let Some(h) = &node.hostname {
                    html.push_str(&format!("<span class=\"hostname\">{}</span>\n", h));
                }

                if !node.open_ports.is_empty() {
                    html.push_str("<div class=\"ports\">\n");
                    for (port, service) in node.open_ports.iter().zip(node.services.iter()) {
                        html.push_str(&format!(
                            "<span class=\"port-tag\">{} / {}</span>\n",
                            port, service
                        ));
                    }
                    html.push_str("</div>\n");
                }

                html.push_str("</div>\n</div>\n");
            }

            html.push_str("</div>\n</div>\n");
        }

        html.push_str("<script>\n");
        html.push_str("function toggleSubnet(el) {\n");
        html.push_str("  const content = el.nextElementSibling;\n");
        html.push_str("  const icon = el.textContent[0];\n");
        html.push_str("  if (content.style.display === 'none') {\n");
        html.push_str("    content.style.display = 'block';\n");
        html.push_str("    el.textContent = '▼' + el.textContent.substring(1);\n");
        html.push_str("  } else {\n");
        html.push_str("    content.style.display = 'none';\n");
        html.push_str("    el.textContent = '▶' + el.textContent.substring(1);\n");
        html.push_str("  }\n}\n");
        html.push_str("</script>\n");
        html.push_str("</div>\n</body>\n</html>");

        html
    }

    /// 导出 JSON 拓扑数据（供外部处理）
    pub fn to_json(&self) -> String {
        let mut out = String::from("{\n  \"title\": \"");
        out.push_str(&self.title);
        out.push_str("\",\n  \"subnets\": [\n");

        for (i, subnet) in self.subnets.iter().enumerate() {
            out.push_str(&format!("    {{\n      \"cidr\": \"{}\",\n", subnet.cidr));
            if let Some(gw) = &subnet.gateway {
                out.push_str(&format!("      \"gateway\": \"{}\",\n", gw));
            }
            out.push_str("      \"nodes\": [\n");

            for (j, node) in subnet.nodes.iter().enumerate() {
                out.push_str(&format!(
                    "        {{\"ip\": \"{}\", \"alive\": {}, \"ports\": [{}]}}{}",
                    node.ip,
                    node.is_alive,
                    node.open_ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", "),
                    if j < subnet.nodes.len() - 1 { "," } else { "" }
                ));
                out.push('\n');
            }

            out.push_str("      ]\n    }");
            if i < self.subnets.len() - 1 {
                out.push(',');
            }
            out.push('\n');
        }

        out.push_str("  ]\n}");
        out
    }

    fn total_hosts(&self) -> usize {
        self.subnets.iter().map(|s| s.nodes.len()).sum()
    }
}

/// 提取 /24 网段
fn extract_subnet_24(ip: &str) -> String {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() == 4 {
        format!("{}.{}.{}.0/24", parts[0], parts[1], parts[2])
    } else {
        format!("{}/24", ip)
    }
}

/// 查找网段的网关（通常是 .1 或 .254）
fn find_gateway<'a>(hosts: &[&'a HostResult]) -> Option<&'a str> {
    // 优先查找 .1 结尾的存活主机
    for host in hosts {
        if host.is_alive && host.ip.ends_with(".1") {
            return Some(&host.ip);
        }
    }
    // 其次查找 .254
    for host in hosts {
        if host.is_alive && host.ip.ends_with(".254") {
            return Some(&host.ip);
        }
    }
    // 第一个存活主机作为备选
    hosts.iter().find(|h| h.is_alive).map(|h| h.ip.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_subnet_24() {
        assert_eq!(extract_subnet_24("192.168.1.100"), "192.168.1.0/24");
        assert_eq!(extract_subnet_24("10.0.0.1"), "10.0.0.0/24");
        assert_eq!(extract_subnet_24("172.16.5.254"), "172.16.5.0/24");
    }

    #[test]
    fn test_extract_subnet_non_standard() {
        assert_eq!(extract_subnet_24("single"), "single/24");
    }

    #[test]
    fn test_topology_ascii_basic() {
        // 使用最小拓扑数据测试 ASCII 输出
        let topo = TopologyGenerator {
            title: "测试拓扑".to_string(),
            subnets: vec![TopoSubnet {
                cidr: "192.168.1.0/24".to_string(),
                gateway: Some("192.168.1.1".to_string()),
                nodes: vec![
                    TopoNode {
                        ip: "192.168.1.1".to_string(),
                        hostname: Some("gateway".to_string()),
                        is_alive: true,
                        is_gateway: true,
                        open_ports: vec![22, 80, 443],
                        services: vec!["ssh".to_string(), "http".to_string(), "https".to_string()],
                        children: vec![],
                    },
                    TopoNode {
                        ip: "192.168.1.100".to_string(),
                        hostname: Some("webserver".to_string()),
                        is_alive: true,
                        is_gateway: false,
                        open_ports: vec![80],
                        services: vec!["http".to_string()],
                        children: vec![],
                    },
                ],
            }],
        };

        let ascii = topo.to_ascii();
        assert!(ascii.contains("192.168.1.0/24"));
        assert!(ascii.contains("★ 网关"));
        assert!(ascii.contains("192.168.1.1"));
        assert!(ascii.contains("192.168.1.100"));
        assert!(ascii.contains("80/http"));
        assert!(ascii.contains("22/ssh"));
    }

    #[test]
    fn test_topology_html_basic() {
        let topo = TopologyGenerator {
            title: "测试".to_string(),
            subnets: vec![TopoSubnet {
                cidr: "10.0.0.0/24".to_string(),
                gateway: None,
                nodes: vec![],
            }],
        };

        let html = topo.to_html();
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("10.0.0.0/24"));
        assert!(html.contains("toggleSubnet"));
    }

    #[test]
    fn test_topology_json_basic() {
        let topo = TopologyGenerator {
            title: "测试".to_string(),
            subnets: vec![TopoSubnet {
                cidr: "192.168.1.0/24".to_string(),
                gateway: Some("192.168.1.1".to_string()),
                nodes: vec![TopoNode {
                    ip: "192.168.1.100".to_string(),
                    hostname: None,
                    is_alive: true,
                    is_gateway: false,
                    open_ports: vec![80],
                    services: vec!["http".to_string()],
                    children: vec![],
                }],
            }],
        };

        let json = topo.to_json();
        assert!(json.contains("\"title\": \"测试\""));
        assert!(json.contains("\"192.168.1.0/24\""));
        assert!(json.contains("\"gateway\": \"192.168.1.1\""));
    }

    #[test]
    fn test_topology_empty() {
        let topo = TopologyGenerator {
            title: "空拓扑".to_string(),
            subnets: vec![],
        };

        assert_eq!(topo.total_hosts(), 0);
        let ascii = topo.to_ascii();
        assert!(ascii.contains("0 网段"));
    }
}
