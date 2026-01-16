//! 扫描模块数据模型
//!
//! 定义扫描器使用的所有数据结构

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// 扫描类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScanType {
    /// 主机存活扫描
    HostDiscovery,
    /// 端口扫描
    PortScan,
    /// 域环境扫描
    DomainScan,
    /// 综合扫描
    Comprehensive,
}

impl ScanType {
    /// 获取扫描类型名称
    pub fn name(&self) -> &str {
        match self {
            ScanType::HostDiscovery => "主机存活扫描",
            ScanType::PortScan => "端口扫描",
            ScanType::DomainScan => "域环境扫描",
            ScanType::Comprehensive => "综合扫描",
        }
    }
}

/// 扫描结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// 扫描类型
    pub scan_type: ScanType,
    /// 目标列表
    pub targets: Vec<String>,
    /// 开始时间
    pub start_time: DateTime<Utc>,
    /// 结束时间
    pub end_time: DateTime<Utc>,
    /// 扫描耗时（秒）
    pub duration_secs: f64,
    /// 主机扫描结果
    pub hosts: Vec<HostResult>,
    /// 扫描统计
    pub stats: ScanStats,
}

/// 扫描统计信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStats {
    /// 总目标数
    pub total_targets: usize,
    /// 存活主机数
    pub alive_hosts: usize,
    /// 开放端口总数
    pub total_open_ports: usize,
    /// 发现的服务数
    pub services_found: usize,
}

/// 主机扫描结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostResult {
    /// IP地址
    pub ip: String,
    /// 主机名
    pub hostname: Option<String>,
    /// 是否存活
    pub is_alive: bool,
    /// 延迟（毫秒）
    pub latency_ms: Option<u64>,
    /// MAC地址
    pub mac: Option<String>,
    /// 开放端口列表
    pub open_ports: Vec<PortInfo>,
    /// 识别的服务
    pub services: Vec<ServiceInfo>,
}

/// 端口信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortInfo {
    /// 端口号
    pub port: u16,
    /// 端口状态
    pub state: PortState,
    /// 服务名称
    pub service: Option<String>,
    /// 版本信息
    pub version: Option<String>,
    /// Banner信息
    pub banner: Option<String>,
}

/// 端口状态
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PortState {
    /// 开放
    Open,
    /// 关闭
    Closed,
    /// 过滤
    Filtered,
    /// 未过滤
    Unfiltered,
    /// 开放|过滤
    OpenFiltered,
    /// 关闭|过滤
    ClosedFiltered,
}

impl PortState {
    /// 获取状态名称（中文）
    pub fn zh_name(&self) -> &str {
        match self {
            PortState::Open => "开放",
            PortState::Closed => "关闭",
            PortState::Filtered => "过滤",
            PortState::Unfiltered => "未过滤",
            PortState::OpenFiltered => "开放|过滤",
            PortState::ClosedFiltered => "关闭|过滤",
        }
    }

    /// 获取状态颜色代码（用于终端输出）
    pub fn color_code(&self) -> &str {
        match self {
            PortState::Open => "\x1b[32m",     // 绿色
            PortState::Closed => "\x1b[31m",   // 红色
            PortState::Filtered => "\x1b[33m", // 黄色
            _ => "\x1b[37m",                   // 白色
        }
    }
}

/// 服务信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    /// 服务名称
    pub name: String,
    /// 版本
    pub version: String,
    /// 产品
    pub product: String,
    /// 额外信息
    pub extra_info: String,
}

impl ServiceInfo {
    /// 创建空服务信息
    pub fn empty() -> Self {
        Self {
            name: String::new(),
            version: String::new(),
            product: String::new(),
            extra_info: String::new(),
        }
    }
}

impl Default for ServiceInfo {
    fn default() -> Self {
        Self::empty()
    }
}

/// 域用户信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainUser {
    /// 用户名
    pub username: String,
    /// SID
    pub sid: Option<String>,
    /// 描述
    pub description: Option<String>,
    /// 最后登录时间
    pub last_logon: Option<DateTime<Utc>>,
    /// 密码最后设置时间
    pub password_last_set: Option<DateTime<Utc>>,
}

/// SPN信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServicePrincipalName {
    /// SPN名称
    pub spn: String,
    /// 关联的用户
    pub username: String,
    /// 服务类型
    pub service_type: String,
}

/// 域信任关系
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainTrust {
    /// 域名
    pub domain_name: String,
    /// 信任方向
    pub trust_direction: String,
    /// 信任类型
    pub trust_type: String,
    /// 信任属性
    pub trust_attributes: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_type_names() {
        assert_eq!(ScanType::HostDiscovery.name(), "主机存活扫描");
        assert_eq!(ScanType::PortScan.name(), "端口扫描");
    }

    #[test]
    fn test_port_state() {
        assert_eq!(PortState::Open.zh_name(), "开放");
        assert_eq!(PortState::Closed.zh_name(), "关闭");
        assert!(PortState::Filtered.color_code().contains("\x1b[33m"));
    }

    #[test]
    fn test_host_result_creation() {
        let host = HostResult {
            ip: "192.168.1.1".to_string(),
            hostname: None,
            is_alive: true,
            latency_ms: Some(10),
            mac: None,
            open_ports: vec![],
            services: vec![],
        };
        assert_eq!(host.ip, "192.168.1.1");
        assert!(host.is_alive);
    }

    #[test]
    fn test_service_info_empty() {
        let service = ServiceInfo::empty();
        assert!(service.name.is_empty());
        assert!(service.version.is_empty());
    }
}
