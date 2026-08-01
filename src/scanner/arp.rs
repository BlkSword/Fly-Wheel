//! ARP 扫描模块 (Windows)
//!
//! 使用 Windows SendARP API 进行局域网主机发现

#[cfg(windows)]
use std::net::{IpAddr, Ipv4Addr};

#[cfg(windows)]
use std::sync::Arc;

#[cfg(windows)]
use std::time::Duration;

#[cfg(windows)]
use tokio::sync::Semaphore;

#[cfg(windows)]
use crate::scanner::config::ScanConfig;
#[cfg(windows)]
use crate::scanner::models::HostResult;

/// ARP 扫描器 (仅 Windows)
#[cfg(windows)]
pub struct ArpScanner {
    config: ScanConfig,
}

#[cfg(windows)]
impl ArpScanner {
    /// 创建新的 ARP 扫描器
    pub fn new(config: ScanConfig) -> Self {
        Self { config }
    }

    /// 扫描一组 IP 目标
    pub async fn scan(&self, targets: Vec<IpAddr>) -> Vec<HostResult> {
        let semaphore = Arc::new(Semaphore::new(self.config.max_concurrent_hosts));
        let mut tasks = Vec::new();

        for target in targets {
            let semaphore = Arc::clone(&semaphore);
            let timeout_ms = self.config.host_timeout_ms;

            let task = tokio::task::spawn_blocking(move || {
                // 获取信号量
                let rt = tokio::runtime::Handle::current();
                let _permit = rt.block_on(async {
                    tokio::time::timeout(Duration::from_millis(timeout_ms), semaphore.acquire())
                        .await
                });

                // 执行 ARP 探测
                if let IpAddr::V4(ipv4) = target {
                    probe_host(ipv4)
                } else {
                    // ARP 只支持 IPv4
                    None
                }
            });

            tasks.push(task);
        }

        let mut results = Vec::new();
        for task in tasks {
            if let Ok(Some((ip, mac))) = task.await {
                results.push(HostResult {
                    ip: ip.to_string(),
                    hostname: None,
                    is_alive: true,
                    latency_ms: Some(0),
                    mac: Some(mac),
                    open_ports: vec![],
                    services: vec![],
                    web_fingerprints: vec![],
                });
            }
        }

        results
    }
}

/// 发送 ARP 请求探测单个主机
///
/// 返回 (IP, MAC) 如果主机存活
#[cfg(windows)]
fn probe_host(target: Ipv4Addr) -> Option<(Ipv4Addr, String)> {
    use std::ffi::CString;
    use windows::Win32::Networking::WinSock::inet_addr;

    // 将 IP 转换为网络字节序
    let ip_str = CString::new(target.to_string()).ok()?;
    let dest_ip = unsafe { inet_addr(windows::core::PCSTR(ip_str.as_ptr() as *const u8)) };
    if dest_ip == 0 {
        return None;
    }

    let mut mac_addr = [0u8; 8];
    let mut mac_len = 6u32;

    // 调用 SendARP
    let result = unsafe {
        SendARP(
            dest_ip,
            0,
            mac_addr.as_mut_ptr() as *mut core::ffi::c_void,
            &mut mac_len,
        )
    };

    if result == 0 && mac_len == 6 {
        // 成功获取 MAC 地址
        let mac = format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]
        );
        Some((target, mac))
    } else {
        None
    }
}

/// Windows SendARP API 声明
///
/// 来自 windows crate 的 Win32::NetworkManagement::IpHelper
#[cfg(windows)]
use windows::Win32::NetworkManagement::IpHelper::SendARP;

#[cfg(test)]
#[cfg(windows)]
mod tests {
    use super::*;

    #[test]
    fn test_arp_scanner_creation() {
        let scanner = ArpScanner::new(ScanConfig::default());
        assert_eq!(scanner.config.host_timeout_ms, 1000);
    }

    #[test]
    fn test_probe_localhost() {
        // 127.0.0.1 的 ARP 可能成功也可能失败（取决于系统）
        let result = probe_host(Ipv4Addr::LOCALHOST);
        // 只要不崩溃就算通过
        let _ = result;
    }
}
