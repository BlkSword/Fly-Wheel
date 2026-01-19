//! 链式隧道模块
//!
//! 实现多级跳板的链式隧道

use crate::core::error::{FlyWheelError, Result};
use crate::tunnel::config::TunnelConfig;
use crate::tunnel::models::{ConnectionInfo, TunnelEvent, TunnelEventHandler, TunnelStatus};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::{timeout, Duration};

/// 链式隧道
pub struct ChainTunnel {
    config: TunnelConfig,
    status: Arc<tokio::sync::RwLock<TunnelStatus>>,
    event_handler: Arc<dyn TunnelEventHandler>,
}

impl ChainTunnel {
    /// 创建新的链式隧道
    pub fn new(
        config: TunnelConfig,
        event_handler: Arc<dyn TunnelEventHandler>,
    ) -> Self {
        Self {
            config,
            status: Arc::new(tokio::sync::RwLock::new(TunnelStatus::new())),
            event_handler,
        }
    }

    /// 启动链式隧道
    pub async fn start(&self) -> Result<()> {
        // 验证配置
        self.config.validate()
            .map_err(|e| FlyWheelError::Other { message: e })?;

        let target = self.config.remote_target.clone().unwrap();

        {
            let mut status = self.status.write().await;
            status.start();
        }

        self.event_handler.on_event(TunnelEvent::Started);
        println!();
        println!("╔════════════════════════════════════════════════════════════════════════════╗");
        println!("║  {}", format!("链式隧道启动"));
        println!("║  {}", format!("监听地址: {}", self.config.local_addr));
        println!("║  {}", format!("跳板数量: {}", self.config.hops.len()));
        for (i, hop) in self.config.hops.iter().enumerate() {
            println!("║  {}", format!("  跳板 {}: {}", i + 1, hop));
        }
        println!("║  {}", format!("最终目标: {}", target));
        println!("╚════════════════════════════════════════════════════════════════════════════╝");
        println!();
        println!("按 Ctrl+C 停止隧道");
        println!();

        let listener = TcpListener::bind(&self.config.local_addr).await
            .map_err(|e| FlyWheelError::Other {
                message: format!("绑定端口 {} 失败: {}", self.config.local_addr, e),
            })?;

        let semaphore = Arc::new(Semaphore::new(self.config.max_connections));
        let mut counter = 0u64;

        loop {
            match listener.accept().await {
                Ok((client, addr)) => {
                    // 检查并发限制
                    let permit = match semaphore.clone().try_acquire_owned() {
                        Ok(p) => p,
                        Err(_) => {
                            eprintln!("[警告] 连接数已达上限，拒绝: {}", addr);
                            drop(client);
                            continue;
                        }
                    };

                    counter += 1;
                    let conn_id = format!("chain-{}", counter);

                    let local_addr = self.config.local_addr;
                    let hops = self.config.hops.clone();
                    let target = target.clone();
                    let timeout_dur = Duration::from_secs(self.config.timeout_secs);
                    let event_handler = self.event_handler.clone();
                    let status = self.status.clone();

                    tokio::spawn(async move {
                        event_handler.on_event(TunnelEvent::Connected {
                            id: conn_id.clone(),
                            local_addr,
                            remote_addr: addr,
                        });

                        {
                            let mut st = status.write().await;
                            st.add_connection(ConnectionInfo::new(
                                conn_id.clone(),
                                local_addr,
                                addr,
                            ));
                        }

                        // 通过跳板链建立连接
                        let result = Self::connect_through_hops(&hops, &target, timeout_dur).await;

                        match result {
                            Ok(target_stream) => {
                                // 双向转发
                                let stats = Self::relay(client, target_stream).await;

                                {
                                    let mut st = status.write().await;
                                    st.update_connection(&conn_id, stats.sent, stats.received);
                                    st.remove_connection(&conn_id);
                                }

                                event_handler.on_event(TunnelEvent::DataTransferred {
                                    id: conn_id.clone(),
                                    sent: stats.sent,
                                    received: stats.received,
                                });
                            }
                            Err(e) => {
                                event_handler.on_event(TunnelEvent::Error {
                                    message: format!("建立链式连接失败: {}", e),
                                });
                                {
                                    let mut st = status.write().await;
                                    st.remove_connection(&conn_id);
                                }
                            }
                        }

                        event_handler.on_event(TunnelEvent::Disconnected {
                            id: conn_id.clone(),
                        });

                        drop(permit);
                    });
                }
                Err(e) => {
                    self.event_handler.on_event(TunnelEvent::Error {
                        message: format!("接受连接失败: {}", e),
                    });
                }
            }
        }
    }

    /// 通过跳板链建立连接
    async fn connect_through_hops(
        hops: &[String],
        target: &str,
        timeout_dur: Duration,
    ) -> Result<TcpStream> {
        if hops.is_empty() {
            // 没有跳板，直接连接目标
            return timeout(timeout_dur, TcpStream::connect(target))
                .await
                .map_err(|_| FlyWheelError::Other {
                    message: format!("连接目标 {} 超时", target),
                })?
                .map_err(|e| FlyWheelError::Other {
                    message: format!("连接目标 {} 失败: {}", target, e),
                });
        }

        // 逐个连接跳板
        let mut current_stream = timeout(timeout_dur, TcpStream::connect(&hops[0]))
            .await
            .map_err(|_| FlyWheelError::Other {
                message: format!("连接跳板 1 ({}) 超时", hops[0]),
            })?
            .map_err(|e| FlyWheelError::Other {
                message: format!("连接跳板 1 ({}) 失败: {}", hops[0], e),
            })?;

        println!("[链式] 已连接到跳板 1/{}: {}", hops.len(), hops[0]);

        // 对于后续跳板，通过前一个跳板连接
        for (i, hop) in hops.iter().skip(1).enumerate() {
            // 这里实现一个简化的协议
            // 实际应用中需要更复杂的协议来处理多级跳板

            // 发送连接下一个跳板的指令
            // 格式: 0x10 + 地址长度(1字节) + 地址 + 端口(2字节)
            let addr_parts: Vec<&str> = hop.split(':').collect();
            if addr_parts.len() != 2 {
                return Err(FlyWheelError::Other {
                    message: format!("无效的跳板地址格式: {}", hop),
                });
            }

            let host = addr_parts[0];
            let port: u16 = addr_parts[1].parse()
                .map_err(|_| FlyWheelError::Other {
                    message: format!("无效的端口号: {}", addr_parts[1]),
                })?;

            let mut packet = vec![0u8; 4 + host.len()];
            packet[0] = 0x10; // 连接下一跳指令
            packet[1] = host.len() as u8;
            packet[2..2 + host.len()].copy_from_slice(host.as_bytes());
            packet[2 + host.len()..4 + host.len()].copy_from_slice(&port.to_be_bytes());

            if let Err(e) = current_stream.write_all(&packet).await {
                return Err(FlyWheelError::Other {
                    message: format!("发送连接指令到跳板 {} 失败: {}", i + 2, e),
                });
            }

            // 读取响应 (简化版，实际需要超时)
            let mut resp = [0u8; 1];
            if let Err(e) = current_stream.read_exact(&mut resp).await {
                return Err(FlyWheelError::Other {
                    message: format!("读取跳板 {} 响应失败: {}", i + 2, e),
                });
            }

            if resp[0] != 0x00 {
                return Err(FlyWheelError::Other {
                    message: format!("跳板 {} 返回错误: 0x{:02x}", i + 2, resp[0]),
                });
            }

            println!("[链式] 已连接到跳板 {}/{}: {}", i + 2, hops.len(), hop);
        }

        // 连接到最终目标
        let addr_parts: Vec<&str> = target.split(':').collect();
        if addr_parts.len() != 2 {
            return Err(FlyWheelError::Other {
                message: format!("无效的目标地址格式: {}", target),
            });
        }

        let host = addr_parts[0];
        let port: u16 = addr_parts[1].parse()
            .map_err(|_| FlyWheelError::Other {
                message: format!("无效的端口号: {}", addr_parts[1]),
            })?;

        let mut packet = vec![0u8; 4 + host.len()];
        packet[0] = 0x11; // 连接目标指令
        packet[1] = host.len() as u8;
        packet[2..2 + host.len()].copy_from_slice(host.as_bytes());
        packet[2 + host.len()..4 + host.len()].copy_from_slice(&port.to_be_bytes());

        if let Err(e) = current_stream.write_all(&packet).await {
            return Err(FlyWheelError::Other {
                message: format!("发送连接目标指令失败: {}", e),
            });
        }

        // 读取响应
        let mut resp = [0u8; 1];
        if let Err(e) = current_stream.read_exact(&mut resp).await {
            return Err(FlyWheelError::Other {
                message: format!("读取连接目标响应失败: {}", e),
            });
        }

        if resp[0] != 0x00 {
            return Err(FlyWheelError::Other {
                message: format!("连接目标失败: 0x{:02x}", resp[0]),
            });
        }

        println!("[链式] 已连接到最终目标: {}", target);

        Ok(current_stream)
    }

    /// 双向流量转发
    async fn relay(mut client: TcpStream, mut target: TcpStream) -> TransferStats {
        let mut client_buf = vec![0u8; 8192];
        let mut target_buf = vec![0u8; 8192];
        let mut sent = 0u64;
        let mut received = 0u64;

        loop {
            tokio::select! {
                result = client.read(&mut client_buf) => {
                    match result {
                        Ok(0) => break,
                        Ok(n) => {
                            if let Err(e) = target.write_all(&client_buf[..n]).await {
                                eprintln!("[错误] 写入目标失败: {}", e);
                                break;
                            }
                            sent += n as u64;
                        }
                        Err(e) => {
                            eprintln!("[错误] 读取客户端失败: {}", e);
                            break;
                        }
                    }
                }
                result = target.read(&mut target_buf) => {
                    match result {
                        Ok(0) => break,
                        Ok(n) => {
                            if let Err(e) = client.write_all(&target_buf[..n]).await {
                                eprintln!("[错误] 写入客户端失败: {}", e);
                                break;
                            }
                            received += n as u64;
                        }
                        Err(e) => {
                            eprintln!("[错误] 读取目标失败: {}", e);
                            break;
                        }
                    }
                }
            }
        }

        TransferStats { sent, received }
    }

    /// 获取隧道状态
    #[allow(dead_code)]
    pub async fn get_status(&self) -> TunnelStatus {
        self.status.read().await.clone()
    }

    /// 停止隧道
    #[allow(dead_code)]
    pub async fn stop(&self) {
        let mut status = self.status.write().await;
        status.stop();
        self.event_handler.on_event(TunnelEvent::Stopped);
    }
}

/// 传输统计
#[derive(Debug, Default)]
struct TransferStats {
    sent: u64,
    received: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::models::LogEventHandler;

    #[tokio::test]
    async fn test_chain_tunnel_creation() {
        let local: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let config = TunnelConfig::new(
            crate::tunnel::config::TunnelType::Chain,
            local,
        )
        .with_hops(vec!["hop1:2222".to_string(), "hop2:3333".to_string()])
        .with_remote_target("target:80".to_string());

        let event_handler = Arc::new(LogEventHandler::new(true));
        let tunnel = ChainTunnel::new(config, event_handler);

        // 测试创建成功
        assert_eq!(tunnel.config.hops.len(), 2);
        assert_eq!(tunnel.config.remote_target, Some("target:80".to_string()));
    }

    #[tokio::test]
    async fn test_chain_tunnel_validation() {
        let local: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let config = TunnelConfig::new(
            crate::tunnel::config::TunnelType::Chain,
            local,
        );

        // 链式隧道需要跳板和目标
        assert!(config.validate().is_err());

        let config = config.clone().with_hops(vec!["hop1:2222".to_string()]);
        assert!(config.validate().is_err());

        let config = config.with_remote_target("target:80".to_string());
        assert!(config.validate().is_ok());
    }
}
