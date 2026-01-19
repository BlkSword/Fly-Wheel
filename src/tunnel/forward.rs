//! 正向隧道模块
//!
//! 实现本地端口转发到远程目标

use crate::core::error::{FlyWheelError, Result};
use crate::tunnel::config::TunnelConfig;
use crate::tunnel::models::{ConnectionInfo, TunnelEvent, TunnelEventHandler, TunnelStatus};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::{timeout, Duration};

/// 正向隧道
pub struct ForwardTunnel {
    pub config: TunnelConfig,
    status: Arc<tokio::sync::RwLock<TunnelStatus>>,
    event_handler: Arc<dyn TunnelEventHandler>,
}

impl ForwardTunnel {
    /// 创建新的正向隧道
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

    /// 启动正向隧道
    pub async fn start(&self) -> Result<()> {
        // 验证配置
        self.config.validate()
            .map_err(|e| FlyWheelError::Other { message: e })?;

        let target = self.config.remote_target.clone().unwrap();

        let listener = TcpListener::bind(&self.config.local_addr).await
            .map_err(|e| FlyWheelError::Other {
                message: format!("绑定端口 {} 失败: {}", self.config.local_addr, e),
            })?;

        {
            let mut status = self.status.write().await;
            status.start();
        }

        self.event_handler.on_event(TunnelEvent::Started);
        println!();
        println!("╔════════════════════════════════════════════════════════════════════════════╗");
        println!("║  {}", format!("正向隧道启动: 监听 {}", self.config.local_addr));
        println!("║  {}", format!("转发目标: {}", target));
        println!("║  {}", format!("最大连接: {}", self.config.max_connections));
        println!("╚════════════════════════════════════════════════════════════════════════════╝");
        println!();
        println!("按 Ctrl+C 停止隧道");
        println!();

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
                    let conn_id = format!("forward-{}", counter);

                    let local_addr = self.config.local_addr;
                    let remote_addr = addr;

                    self.event_handler.on_event(TunnelEvent::Connected {
                        id: conn_id.clone(),
                        local_addr,
                        remote_addr,
                    });

                    {
                        let mut status = self.status.write().await;
                        status.add_connection(ConnectionInfo::new(
                            conn_id.clone(),
                            self.config.local_addr,
                            addr,
                        ));
                    }

                    let target = target.clone();
                    let timeout_dur = Duration::from_secs(self.config.timeout_secs);
                    let event_handler = self.event_handler.clone();
                    let status = self.status.clone();

                    // 在新任务中处理连接
                    tokio::spawn(async move {
                        // 连接到目标
                        let result = timeout(timeout_dur, TcpStream::connect(&target)).await;

                        match result {
                            Ok(Ok(target_stream)) => {
                                // 双向转发
                                let stats = Self::relay(client, target_stream).await;

                                // 更新统计
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
                            Ok(Err(e)) => {
                                event_handler.on_event(TunnelEvent::Error {
                                    message: format!("连接目标 {} 失败: {}", target, e),
                                });
                                {
                                    let mut st = status.write().await;
                                    st.remove_connection(&conn_id);
                                }
                            }
                            Err(_) => {
                                event_handler.on_event(TunnelEvent::Error {
                                    message: format!("连接目标 {} 超时", target),
                                });
                                {
                                    let mut st = status.write().await;
                                    st.remove_connection(&conn_id);
                                }
                            }
                        }

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

    /// 双向流量转发
    async fn relay(mut client: TcpStream, mut target: TcpStream) -> TransferStats {
        let mut client_buf = vec![0u8; 8192];
        let mut target_buf = vec![0u8; 8192];
        let mut sent = 0u64;
        let mut received = 0u64;

        loop {
            // 使用 select! 同时处理两个方向的数据
            tokio::select! {
                // 客户端 -> 目标
                result = client.read(&mut client_buf) => {
                    match result {
                        Ok(0) => break, // 客户端关闭连接
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
                // 目标 -> 客户端
                result = target.read(&mut target_buf) => {
                    match result {
                        Ok(0) => break, // 目标关闭连接
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

/// 数据传输统计
#[derive(Debug, Clone, Copy)]
struct TransferStats {
    sent: u64,
    received: u64,
}
