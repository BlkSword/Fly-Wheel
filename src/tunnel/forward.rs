//! 正向隧道模块
//!
//! 实现本地端口转发到远程目标

use crate::core::error::{IntraSweepError, Result};
use crate::tunnel::config::TunnelConfig;
use crate::tunnel::models::{ConnectionInfo, TunnelEvent, TunnelEventHandler, TunnelStatus};
use crate::tunnel::relay;
use crate::tunnel::shutdown::Shutdown;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::{timeout, Duration};
use tracing;

/// 正向隧道
pub struct ForwardTunnel {
    pub config: TunnelConfig,
    status: Arc<tokio::sync::RwLock<TunnelStatus>>,
    event_handler: Arc<dyn TunnelEventHandler>,
}

impl ForwardTunnel {
    /// 创建新的正向隧道
    pub fn new(config: TunnelConfig, event_handler: Arc<dyn TunnelEventHandler>) -> Self {
        Self {
            config,
            status: Arc::new(tokio::sync::RwLock::new(TunnelStatus::new())),
            event_handler,
        }
    }

    /// 启动正向隧道
    pub async fn start(&self) -> Result<()> {
        // 验证配置
        self.config.validate()?;

        let target = self
            .config
            .remote_target
            .clone()
            .ok_or_else(|| IntraSweepError::Config {
                message: "正向隧道需要指定远程目标".to_string(),
            })?;

        let listener = TcpListener::bind(&self.config.local_addr)
            .await
            .map_err(|e| IntraSweepError::Network {
                message: format!("绑定端口 {} 失败: {}", self.config.local_addr, e),
            })?;

        {
            let mut status = self.status.write().await;
            status.start();
        }

        self.event_handler.on_event(TunnelEvent::Started);
        println!();
        println!("╔════════════════════════════════════════════════════════════════════════════╗");
        println!("║  正向隧道启动: 监听 {}", self.config.local_addr);
        println!("║  转发目标: {}", target);
        println!("║  最大连接: {}", self.config.max_connections);
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
                            tracing::warn!("连接数已达上限，拒绝: {}", addr);
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
                                let stats = relay::relay(client, target_stream).await;

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

    /// 启动正向隧道（支持优雅关闭）
    pub async fn start_with_shutdown(&self, shutdown: &Shutdown) -> Result<()> {
        self.config.validate()?;

        let target = self
            .config
            .remote_target
            .clone()
            .ok_or_else(|| IntraSweepError::Config {
                message: "正向隧道需要指定远程目标".to_string(),
            })?;

        let listener = TcpListener::bind(&self.config.local_addr)
            .await
            .map_err(|e| IntraSweepError::Network {
                message: format!("绑定端口 {} 失败: {}", self.config.local_addr, e),
            })?;

        {
            let mut status = self.status.write().await;
            status.start();
        }

        let encrypted = self.config.encryption_key.is_some();

        self.event_handler.on_event(TunnelEvent::Started);
        println!();
        println!("╔════════════════════════════════════════════════════════════════════════════╗");
        println!("║  正向隧道启动: 监听 {}", self.config.local_addr);
        println!("║  转发目标: {}", target);
        println!("║  最大连接: {}", self.config.max_connections);
        println!(
            "║  加密: {}",
            if encrypted {
                "XChaCha20-Poly1305"
            } else {
                "无"
            }
        );
        println!("╚════════════════════════════════════════════════════════════════════════════╝");
        println!();
        println!("按 Ctrl+C 优雅关闭隧道");
        println!();

        let semaphore = Arc::new(Semaphore::new(self.config.max_connections));
        let mut counter = 0u64;

        // 初始化加密层（如果配置了密钥）
        let crypto = self.config.encryption_key.as_ref().map(|k| {
            std::sync::Arc::new(crate::tunnel::crypto::CryptoLayer::new(
                &crate::tunnel::crypto::derive_key(k),
            ))
        });

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((client, addr)) => {
                            let permit = match semaphore.clone().try_acquire_owned() {
                                Ok(p) => p,
                                Err(_) => {
                                    tracing::warn!("连接数已达上限，拒绝: {}", addr);
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
                            let crypto = crypto.clone();

                            tokio::spawn(async move {
                                let result = timeout(timeout_dur, TcpStream::connect(&target)).await;
                                match result {
                                    Ok(Ok(target_stream)) => {
                                        let stats = if let Some(c) = &crypto {
                                            let enc_client = crate::tunnel::crypto::EncryptedStream::new(
                                                client, c.clone(),
                                            );
                                            relay::relay(enc_client, target_stream).await
                                        } else {
                                            relay::relay(client, target_stream).await
                                        };
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
                _ = shutdown.wait() => {
                    break;
                }
            }
        }

        self.event_handler.on_event(TunnelEvent::Stopped);
        println!("正向隧道已关闭");
        Ok(())
    }
}
