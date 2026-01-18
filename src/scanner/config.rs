//! 扫描器配置
//!
//! 定义扫描器的配置选项和默认值

#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use clap::ValueEnum;

/// 主机扫描方式
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
pub enum HostScanMethod {
    /// TCP SYN 扫描（默认，兼容性好）
    #[serde(rename = "tcp_syn")]
    #[clap(name = "tcp-syn")]
    TcpSyn,

    /// ICMP Ping 扫描
    #[serde(rename = "icmp")]
    Icmp,

    /// ARP 扫描（仅本地网络）
    #[serde(rename = "arp")]
    Arp,

    /// 混合模式（TCP SYN + ICMP）
    #[serde(rename = "hybrid")]
    #[clap(name = "hybrid")]
    Hybrid,
}

impl HostScanMethod {
    pub fn name(&self) -> &str {
        match self {
            HostScanMethod::TcpSyn => "tcp-syn",
            HostScanMethod::Icmp => "icmp",
            HostScanMethod::Arp => "arp",
            HostScanMethod::Hybrid => "hybrid",
        }
    }

    pub fn display_name(&self) -> &str {
        match self {
            HostScanMethod::TcpSyn => "TCP SYN",
            HostScanMethod::Icmp => "ICMP",
            HostScanMethod::Arp => "ARP",
            HostScanMethod::Hybrid => "混合模式",
        }
    }
}

/// 端口扫描方式
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
pub enum PortScanMethod {
    /// TCP Connect 扫描（默认，兼容性最好）
    #[serde(rename = "tcp_connect")]
    #[clap(name = "tcp-connect")]
    TcpConnect,

    /// TCP SYN 扫描（需要管理员权限）
    #[serde(rename = "tcp_syn")]
    #[clap(name = "tcp-syn")]
    TcpSyn,

    /// UDP 扫描
    #[serde(rename = "udp")]
    Udp,

    /// SCTP 扫描
    #[serde(rename = "sctp")]
    Sctp,
}

impl PortScanMethod {
    pub fn name(&self) -> &str {
        match self {
            PortScanMethod::TcpConnect => "tcp-connect",
            PortScanMethod::TcpSyn => "tcp-syn",
            PortScanMethod::Udp => "udp",
            PortScanMethod::Sctp => "sctp",
        }
    }

    pub fn display_name(&self) -> &str {
        match self {
            PortScanMethod::TcpConnect => "TCP Connect",
            PortScanMethod::TcpSyn => "TCP SYN",
            PortScanMethod::Udp => "UDP",
            PortScanMethod::Sctp => "SCTP",
        }
    }
}

/// 扫描器配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    // 扫描方式
    /// 主机扫描方式
    #[serde(default = "default_host_scan_method")]
    pub host_scan_method: HostScanMethod,
    /// 端口扫描方式
    #[serde(default = "default_port_scan_method")]
    pub port_scan_method: PortScanMethod,

    // 并发配置
    /// 主机并发数（默认100）
    pub max_concurrent_hosts: usize,
    /// 端口并发数（默认3000）
    pub max_concurrent_ports: usize,
    /// 最大socket数（默认10000）
    pub max_concurrent_sockets: usize,

    // 超时配置
    /// 主机超时（默认1000ms）
    pub host_timeout_ms: u64,
    /// 端口超时（默认1000ms）
    pub port_timeout_ms: u64,
    /// Ping超时（默认500ms）
    pub ping_timeout_ms: u64,

    // 性能优化
    /// 自适应批处理（开启）
    pub adaptive_batching: bool,
    /// 连接复用（开启）
    pub connection_reuse: bool,
    /// 扫描延迟（隐蔽模式，None表示不延迟）
    pub scan_delay_ms: Option<u64>,

    // 扫描范围
    /// 仅常见端口（Top 1000）
    pub common_ports_only: bool,
    /// 自定义端口列表
    pub custom_ports: Vec<u16>,

    // 输出配置
    /// 显示详细输出
    pub verbose: bool,
    /// 保存JSON结果
    pub save_json: bool,
    /// 输出目录
    pub output_dir: Option<String>,

    // 服务探测
    /// 启用服务版本探测
    pub service_detection: bool,
    /// 服务探测超时（毫秒）
    pub service_timeout_ms: u64,
    /// 仅探测常见端口的服务
    pub service_common_only: bool,
}

/// 默认主机扫描方式
fn default_host_scan_method() -> HostScanMethod {
    HostScanMethod::TcpSyn
}

/// 默认端口扫描方式
fn default_port_scan_method() -> PortScanMethod {
    PortScanMethod::TcpConnect
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            host_scan_method: default_host_scan_method(),
            port_scan_method: default_port_scan_method(),
            max_concurrent_hosts: 100,
            max_concurrent_ports: 3000,
            max_concurrent_sockets: 10000,
            host_timeout_ms: 1000,
            port_timeout_ms: 1000,
            ping_timeout_ms: 500,
            adaptive_batching: true,
            connection_reuse: true,
            scan_delay_ms: None,
            common_ports_only: true,
            custom_ports: Vec::new(),
            verbose: false,
            save_json: true,
            output_dir: None,
            service_detection: false,
            service_timeout_ms: 5000,
            service_common_only: true,
        }
    }
}

impl ScanConfig {
    /// 创建默认配置
    pub fn new() -> Self {
        Self::default()
    }

    /// 创建快速扫描配置（高并发，短超时）
    pub fn fast_scan() -> Self {
        Self {
            max_concurrent_hosts: 500,
            max_concurrent_ports: 5000,
            max_concurrent_sockets: 20000,
            host_timeout_ms: 500,
            port_timeout_ms: 500,
            ping_timeout_ms: 200,
            ..Default::default()
        }
    }

    /// 创建隐蔽扫描配置（低并发，有延迟）
    pub fn stealth_scan() -> Self {
        Self {
            max_concurrent_hosts: 10,
            max_concurrent_ports: 50,
            max_concurrent_sockets: 100,
            host_timeout_ms: 2000,
            port_timeout_ms: 2000,
            ping_timeout_ms: 1000,
            scan_delay_ms: Some(100),
            ..Default::default()
        }
    }

    /// 创建深度扫描配置（全端口扫描）
    pub fn deep_scan() -> Self {
        Self {
            max_concurrent_hosts: 50,
            max_concurrent_ports: 1000,
            max_concurrent_sockets: 5000,
            host_timeout_ms: 1500,
            port_timeout_ms: 1500,
            ping_timeout_ms: 800,
            common_ports_only: false,
            ..Default::default()
        }
    }

    /// 设置自定义端口
    pub fn with_ports(mut self, ports: Vec<u16>) -> Self {
        self.custom_ports = ports;
        self
    }

    /// 设置超时时间
    pub fn with_timeout(mut self, host_ms: u64, port_ms: u64) -> Self {
        self.host_timeout_ms = host_ms;
        self.port_timeout_ms = port_ms;
        self
    }

    /// 设置并发数
    pub fn with_concurrency(mut self, hosts: usize, ports: usize) -> Self {
        self.max_concurrent_hosts = hosts;
        self.max_concurrent_ports = ports;
        self
    }

    /// 获取要扫描的端口列表
    pub fn get_ports_to_scan(&self) -> Vec<u16> {
        if !self.custom_ports.is_empty() {
            return self.custom_ports.clone();
        }

        if self.common_ports_only {
            Self::get_common_ports()
        } else {
            Self::get_all_ports()
        }
    }

    /// 获取常见端口列表（Top 100）
    fn get_common_ports() -> Vec<u16> {
        vec![
            // 常见服务端口
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
            // Windows特定
            143, 389, 443, 445, 465, 587, 593, 636, 993, 995,
            // 更多常见端口
            1025, 1433, 1521, 1723, 3306, 3389, 5432, 5900,
            5985, 5986, 6379, 8000, 8080, 8443, 8888, 9200,
            // 数据库和其他服务
            27017, 27018, 27019,
        ]
    }

    /// 获取所有端口（1-65535）
    fn get_all_ports() -> Vec<u16> {
        (1u16..=65535).collect()
    }

    /// 计算最优批处理大小
    pub fn calculate_batch_size(&self) -> usize {
        if self.adaptive_batching {
            // 根据并发数自动计算
            let base = self.max_concurrent_ports;
            // 限制在合理范围内
            base.min(5000).max(100)
        } else {
            // 固定批处理大小
            1000
        }
    }
}

/// 扫描预设配置
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanPreset {
    /// 快速扫描（仅常见端口，高并发）
    Fast,
    /// 标准扫描（默认配置）
    Standard,
    /// 深度扫描（全端口）
    Deep,
    /// 隐蔽扫描（低并发，有延迟）
    Stealth,
}

impl ScanPreset {
    /// 获取对应的配置
    pub fn to_config(&self) -> ScanConfig {
        match self {
            ScanPreset::Fast => ScanConfig::fast_scan(),
            ScanPreset::Standard => ScanConfig::default(),
            ScanPreset::Deep => ScanConfig::deep_scan(),
            ScanPreset::Stealth => ScanConfig::stealth_scan(),
        }
    }

    /// 获取预设名称
    pub fn name(&self) -> &str {
        match self {
            ScanPreset::Fast => "快速扫描",
            ScanPreset::Standard => "标准扫描",
            ScanPreset::Deep => "深度扫描",
            ScanPreset::Stealth => "隐蔽扫描",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ScanConfig::default();
        assert_eq!(config.max_concurrent_hosts, 100);
        assert_eq!(config.port_timeout_ms, 1000);
    }

    #[test]
    fn test_fast_scan_config() {
        let config = ScanConfig::fast_scan();
        assert_eq!(config.max_concurrent_hosts, 500);
        assert_eq!(config.host_timeout_ms, 500);
    }

    #[test]
    fn test_stealth_scan_config() {
        let config = ScanConfig::stealth_scan();
        assert_eq!(config.max_concurrent_hosts, 10);
        assert!(config.scan_delay_ms.is_some());
        assert_eq!(config.scan_delay_ms, Some(100));
    }

    #[test]
    fn test_with_ports() {
        let config = ScanConfig::default().with_ports(vec![80, 443, 8080]);
        assert_eq!(config.custom_ports, vec![80, 443, 8080]);
    }

    #[test]
    fn test_common_ports() {
        let ports = ScanConfig::get_common_ports();
        assert!(ports.contains(&80));
        assert!(ports.contains(&443));
        assert!(ports.contains(&22));
        assert!(ports.len() < 1000);
    }

    #[test]
    fn test_all_ports() {
        let ports = ScanConfig::get_all_ports();
        assert_eq!(ports.len(), 65535);
        assert_eq!(ports[0], 1);
        assert_eq!(ports[65534], 65535);
    }

    #[test]
    fn test_scan_preset() {
        assert_eq!(ScanPreset::Fast.name(), "快速扫描");
        let config = ScanPreset::Fast.to_config();
        assert_eq!(config.max_concurrent_hosts, 500);
    }
}
