//! 反向隧道模块
//!
//! 实现从内网主机建立反向连接到控制端

use crate::core::error::{FlyWheelError, Result};
use crate::tunnel::config::TunnelConfig;
use crate::tunnel::models::{ConnectionInfo, TunnelEvent, TunnelEventHandler, TunnelStatus};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::{sleep, Duration};
use uuid::Uuid;

/// 反向隧道
pub struct ReverseTunnel {
    pub config: TunnelConfig,
    status: Arc<tokio::sync::RwLock<TunnelStatus>>,
    event_handler: Arc<dyn TunnelEventHandler>,
}

impl ReverseTunnel {
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

    /// 启动反向隧道（客户端模式 - 在目标主机上运行）
    pub async fn start_client(&self) -> Result<()> {
        // 验证配置
        self.config.validate()
            .map_err(|e| FlyWheelError::Other { message: e })?;

        let control_addr = self.config.remote_target.clone().unwrap();

        {
            let mut status = self.status.write().await;
            status.start();
        }

        self.event_handler.on_event(TunnelEvent::Started);
        println!();
        println!("╔════════════════════════════════════════════════════════════════════════════╗");
        println!("║  {}", format!("反向隧道启动（客户端模式）"));
        println!("║  {}", format!("控制端地址: {}", control_addr));
        println!("║  {}", format!("监听端口: {}", self.config.local_addr.port()));
        println!("║  {}", format!("重连间隔: 5 秒"));
        println!("╚════════════════════════════════════════════════════════════════════════════╝");
        println!();
        println!("按 Ctrl+C 停止隧道");
        println!();

        let mut retry_count = 0u64;

        loop {
            match self.connect_to_control(&control_addr).await {
                Ok(_) => {
                    retry_count = 0;
                }
                Err(e) => {
                    retry_count += 1;
                    self.event_handler.on_event(TunnelEvent::Error {
                        message: format!("连接失败 (尝试 #{}): {}", retry_count, e),
                    });

                    // 等待后重试
                    sleep(Duration::from_secs(5)).await;
                }
            }
        }
    }

    /// 连接到控制端并处理隧道
    async fn connect_to_control(&self, control_addr: &str) -> Result<()> {
        let timeout_dur = Duration::from_secs(self.config.timeout_secs);

        // 连接到控制端
        let control_stream = tokio::time::timeout(
            timeout_dur,
            TcpStream::connect(control_addr)
        ).await
        .map_err(|_| FlyWheelError::Other {
            message: format!("连接超时: {}", control_addr),
        })?
        .map_err(|e| FlyWheelError::Other {
            message: format!("无法连接到 {}: {}", control_addr, e),
        })?;

        let local_addr = control_stream.local_addr()
            .map_err(|e| FlyWheelError::Other {
                message: format!("获取本地地址失败: {}", e),
            })?;

        let conn_id = format!("reverse-{}", Uuid::new_v4());

        self.event_handler.on_event(TunnelEvent::Connected {
            id: conn_id.clone(),
            local_addr,
            remote_addr: control_addr.parse().unwrap_or(local_addr),
        });

        {
            let mut status = self.status.write().await;
            status.add_connection(ConnectionInfo::new(
                conn_id.clone(),
                local_addr,
                control_addr.parse().unwrap_or(local_addr),
            ));
        }

        println!("[连接] 已连接到控制端: {}", control_addr);

        // 处理控制端的指令
        let result = self.handle_control_connection(control_stream, &conn_id).await;

        {
            let mut status = self.status.write().await;
            status.remove_connection(&conn_id);
        }

        self.event_handler.on_event(TunnelEvent::Disconnected {
            id: conn_id.clone(),
        });

        println!("[断开] 与控制端的连接已断开");

        result
    }

    /// 处理控制端连接
    async fn handle_control_connection(
        &self,
        mut control_stream: TcpStream,
        _conn_id: &str,
    ) -> Result<()> {
        let mut buf = vec![0u8; 8192];

        loop {
            // 读取控制端指令
            let n = tokio::time::timeout(
                Duration::from_secs(60),
                control_stream.read(&mut buf)
            ).await
            .map_err(|_| FlyWheelError::Other {
                message: "读取控制端指令超时".to_string(),
            })?
            .map_err(|e| FlyWheelError::Other {
                message: format!("读取控制端指令失败: {}", e),
            })?;

            if n == 0 {
                // 控制端关闭连接
                break;
            }

            // 解析指令 (简化协议: 命令类型 + 数据)
            if n < 1 {
                continue;
            }

            match buf[0] {
                // 0x01: 心跳
                0x01 => {
                    // 响应心跳
                    if let Err(e) = control_stream.write_all(&[0x01]).await {
                        eprintln!("[错误] 发送心跳响应失败: {}", e);
                        break;
                    }
                }
                // 0x02: 转发数据到本地端口
                0x02 => {
                    // 格式: 0x02 + 端口(2字节) + 数据
                    if n >= 3 {
                        let port = u16::from_be_bytes([buf[1], buf[2]]);
                        let data = &buf[3..n];

                        // 连接到本地端口并转发数据
                        if let Err(e) = self.forward_to_local(port, data, &mut control_stream).await {
                            eprintln!("[错误] 转发到本地端口 {} 失败: {}", port, e);
                        }
                    }
                }
                // 未知命令
                cmd => {
                    eprintln!("[警告] 未知命令: 0x{:02x}", cmd);
                }
            }
        }

        Ok(())
    }

    /// 转发数据到本地端口
    async fn forward_to_local(
        &self,
        port: u16,
        data: &[u8],
        control_stream: &mut TcpStream,
    ) -> Result<()> {
        let local_target = format!("127.0.0.1:{}", port);

        let mut local_stream = TcpStream::connect(&local_target).await
            .map_err(|e| FlyWheelError::Other {
                message: format!("连接本地 {} 失败: {}", local_target, e),
            })?;

        // 发送数据
        local_stream.write_all(data).await
            .map_err(|e| FlyWheelError::Other {
                message: format!("写入本地端口失败: {}", e),
            })?;

        // 读取响应并转发回控制端
        let mut response_buf = vec![0u8; 8192];
        loop {
            let n = tokio::time::timeout(
                Duration::from_secs(30),
                local_stream.read(&mut response_buf)
            ).await
            .map_err(|_| FlyWheelError::Other {
                message: "读取本地端口响应超时".to_string(),
            })?
            .map_err(|e| FlyWheelError::Other {
                message: format!("读取本地端口响应失败: {}", e),
            })?;

            if n == 0 {
                break;
            }

            // 转发回控制端 (格式: 0x03 + 数据)
            let mut packet = vec![0u8; n + 1];
            packet[0] = 0x03; // 响应标记
            packet[1..].copy_from_slice(&response_buf[..n]);

            control_stream.write_all(&packet).await
                .map_err(|e| FlyWheelError::Other {
                    message: format!("发送响应到控制端失败: {}", e),
                })?;
        }

        Ok(())
    }

    /// 启动反向隧道（服务端模式 - 在控制端运行）
    #[allow(dead_code)]
    pub async fn start_server(&self) -> Result<()> {
        use tokio::net::TcpListener;

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
        println!("║  {}", format!("反向隧道启动（服务端模式）"));
        println!("║  {}", format!("监听端口: {}", self.config.local_addr.port()));
        println!("║  {}", format!("等待目标主机连接..."));
        println!("╚════════════════════════════════════════════════════════════════════════════╝");
        println!();
        println!("按 Ctrl+C 停止隧道");
        println!();

        let semaphore = Arc::new(Semaphore::new(self.config.max_connections));
        let mut counter = 0u64;

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    // 检查并发限制
                    let permit = match semaphore.clone().try_acquire_owned() {
                        Ok(p) => p,
                        Err(_) => {
                            eprintln!("[警告] 连接数已达上限，拒绝: {}", addr);
                            drop(stream);
                            continue;
                        }
                    };

                    counter += 1;
                    let conn_id = format!("reverse-server-{}", counter);

                    let local_addr = self.config.local_addr;

                    self.event_handler.on_event(TunnelEvent::Connected {
                        id: conn_id.clone(),
                        local_addr,
                        remote_addr: addr,
                    });

                    {
                        let mut status = self.status.write().await;
                        status.add_connection(ConnectionInfo::new(
                            conn_id.clone(),
                            self.config.local_addr,
                            addr,
                        ));
                    }

                    println!("[连接] 目标主机已连接: {}", addr);

                    // 这里可以处理来自目标主机的连接
                    // 实际应用中需要实现协议来转发流量

                    drop(permit);
                }
                Err(e) => {
                    self.event_handler.on_event(TunnelEvent::Error {
                        message: format!("接受连接失败: {}", e),
                    });
                }
            }
        }
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
