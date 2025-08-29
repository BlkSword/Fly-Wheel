// 端口扫描模块

use futures::stream::{FuturesUnordered, StreamExt};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::sync::Semaphore;

// 默认批处理大小
const AVERAGE_BATCH_SIZE: usize = 3000;

/// 执行端口扫描功能
///
/// # 参数
///
/// * `target` - 目标主机 (例如: 192.168.1.1)
/// * `ports` - 端口范围 (例如: "1-1000", "22,80,443" 或 None 表示全端口扫描)
///
/// # 返回值
///
/// 返回操作结果的字符串
pub fn run(target: &str, ports: Option<&str>) -> String {
    // 解析目标地址
    let ip: IpAddr = match target.parse() {
        Ok(ip) => ip,
        Err(_) => {
            return format!("Invalid target IP address: {}", target);
        }
    };

    // 解析端口范围
    let ports_to_scan = match parse_ports(ports) {
        Ok(ports) => ports,
        Err(e) => {
            return format!("Error parsing ports: {}", e);
        }
    };

    println!("Scanning {} ports on {}", ports_to_scan.len(), target);

    // 获取系统优化后的批处理大小
    let batch_size = get_optimal_batch_size();
    println!("Using batch size: {}", batch_size);

    // 使用异步运行时执行扫描
    let open_ports = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(scan_ports_async(ip, &ports_to_scan, batch_size));

    if open_ports.is_empty() {
        return format!("No open ports found on {}", target);
    }

    let mut result = format!("Open ports on {}:\n", target);
    for port in open_ports {
        result.push_str(&format!("  {}\n", port));
    }

    result
}

/// 解析端口参数
///
/// # 参数
///
/// * `ports` - 端口参数字符串，可以是:
///   - None: 表示扫描所有端口 (1-65535)
///   - "1-1000": 表示扫描范围端口
///   - "22,80,443": 表示扫描指定端口列表
///
/// # 返回值
///
/// 返回解析后的端口向量
fn parse_ports(ports: Option<&str>) -> Result<Vec<u16>, String> {
    match ports {
        None => {
            // 默认扫描所有端口
            Ok((1..=65535).collect())
        }
        Some(port_str) => {
            if port_str.contains('-') {
                // 范围端口，例如 "1-1000"
                let parts: Vec<&str> = port_str.split('-').collect();
                if parts.len() != 2 {
                    return Err("Invalid port range format. Use: start-end".to_string());
                }

                let start = parts[0]
                    .parse::<u16>()
                    .map_err(|_| "Invalid start port".to_string())?;
                let end = parts[1]
                    .parse::<u16>()
                    .map_err(|_| "Invalid end port".to_string())?;

                if start > end {
                    return Err("Start port must be less than or equal to end port".to_string());
                }

                Ok((start..=end).collect())
            } else if port_str.contains(',') {
                // 端口列表，例如 "22,80,443"
                let mut ports = Vec::new();
                for port_str in port_str.split(',') {
                    let port = port_str
                        .parse::<u16>()
                        .map_err(|_| format!("Invalid port: {}", port_str))?;
                    ports.push(port);
                }
                Ok(ports)
            } else {
                // 单个端口
                let port = port_str
                    .parse::<u16>()
                    .map_err(|_| format!("Invalid port: {}", port_str))?;
                Ok(vec![port])
            }
        }
    }
}

/// 异步扫描指定端口列表
async fn scan_ports_async(target: IpAddr, ports: &[u16], batch_size: usize) -> Vec<u16> {
    let mut open_ports = Vec::new();
    let semaphore = std::sync::Arc::new(Semaphore::new(batch_size));
    let mut futures = FuturesUnordered::new();

    for &port in ports {
        let semaphore_clone = semaphore.clone();
        let target_clone = target.clone();

        futures.push(tokio::spawn(async move {
            let _permit = semaphore_clone.acquire().await.unwrap();
            let addr = SocketAddr::new(target_clone, port);
            let is_open = is_port_open_async(addr).await;
            (port, is_open)
        }));
    }

    while let Some(result) = futures.next().await {
        if let Ok((port, is_open)) = result {
            if is_open {
                println!("Port {} is open", port);
                open_ports.push(port);
            }
        }
    }

    open_ports
}

/// 异步检查端口是否开放
async fn is_port_open_async(addr: SocketAddr) -> bool {
    tokio::task::spawn_blocking(move || is_port_open(addr))
        .await
        .unwrap_or(false)
}

/// 检查端口是否开放
fn is_port_open(addr: SocketAddr) -> bool {
    // 创建socket
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let socket = match Socket::new(domain, Type::STREAM, Some(Protocol::TCP)) {
        Ok(sock) => sock,
        Err(_) => return false,
    };

    // 设置超时时间
    let timeout = Duration::from_millis(1000);

    // 尝试连接
    socket.connect_timeout(&addr.into(), timeout).is_ok()
}

/// 根据系统限制获取最优批处理大小
fn get_optimal_batch_size() -> usize {
    let batch_size = AVERAGE_BATCH_SIZE;

    // 尝试获取系统文件描述符限制
    cfg_if::cfg_if! {
        if #[cfg(unix)] {
            match get_fd_limit() {
                Some(limit) => {
                    // 保留一些文件描述符给系统使用
                    let safe_limit = (limit as usize).saturating_sub(100);
                    batch_size.min(safe_limit)
                },
                None => batch_size
            }
        } else {
            batch_size
        }
    }
}

/// 获取文件描述符限制
#[cfg(unix)]
fn get_fd_limit() -> Option<u64> {
    let mut rl = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };

    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) } == 0 {
        Some(rl.rlim_cur)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_target() {
        let result = run("invalid_target", None);
        assert!(result.contains("Invalid target IP address"));
    }

    #[test]
    fn test_parse_ports_none() {
        let ports = parse_ports(None).unwrap();
        assert_eq!(ports.len(), 65535);
        assert_eq!(ports[0], 1);
        assert_eq!(ports[65534], 65535);
    }

    #[test]
    fn test_parse_ports_range() {
        let ports = parse_ports(Some("80-85")).unwrap();
        assert_eq!(ports, vec![80, 81, 82, 83, 84, 85]);
    }

    #[test]
    fn test_parse_ports_list() {
        let ports = parse_ports(Some("22,80,443")).unwrap();
        assert_eq!(ports, vec![22, 80, 443]);
    }

    #[test]
    fn test_parse_ports_single() {
        let ports = parse_ports(Some("22")).unwrap();
        assert_eq!(ports, vec![22]);
    }

    #[test]
    fn test_parse_ports_invalid_range() {
        assert!(parse_ports(Some("100-50")).is_err());
        assert!(parse_ports(Some("abc-100")).is_err());
        assert!(parse_ports(Some("100-def")).is_err());
    }

    #[test]
    fn test_parse_ports_invalid_list() {
        assert!(parse_ports(Some("22,abc,443")).is_err());
    }

    #[test]
    fn test_parse_ports_invalid_range_out_of_bounds() {
        assert!(parse_ports(Some("0-100")).is_err());
        assert!(parse_ports(Some("60000-70000")).is_err());
        assert!(parse_ports(Some("1-65536")).is_err());
    }
}
