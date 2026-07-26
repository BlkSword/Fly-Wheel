//! HTTP/HTTPS 隧道模块
//!
//! 基于 HTTP CONNECT 方法的正向隧道，支持代理穿透和 TLS 加密传输。
//! 可穿透仅允许 HTTP/HTTPS 出站的企业防火墙。

use crate::core::error::{IntraSweepError, Result};
use crate::tunnel::config::TunnelConfig;
use crate::tunnel::models::{ConnectionInfo, TunnelEvent, TunnelEventHandler, TunnelStatus};
use crate::tunnel::relay;
use crate::tunnel::shutdown::Shutdown;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::{timeout, Duration};

/// HTTP 隧道 — 通过 HTTP CONNECT 代理进行端口转发
///
/// 工作原理：
/// 1. 本地监听端口接受客户端连接
/// 2. 通过 HTTP CONNECT 请求建立到目标服务器的隧道
/// 3. 将本地连接的流量双向转发到隧道
pub struct HttpTunnel {
    pub config: TunnelConfig,
    status: Arc<tokio::sync::RwLock<TunnelStatus>>,
    event_handler: Arc<dyn TunnelEventHandler>,
}

impl HttpTunnel {
    pub fn new(config: TunnelConfig, event_handler: Arc<dyn TunnelEventHandler>) -> Self {
        Self {
            config,
            status: Arc::new(tokio::sync::RwLock::new(TunnelStatus::new())),
            event_handler,
        }
    }

    /// 通过 HTTP CONNECT 代理连接到目标
    async fn connect_via_proxy(
        proxy_addr: &str,
        target: &str,
        timeout_dur: Duration,
    ) -> std::result::Result<TcpStream, String> {
        // 连接代理
        let mut proxy = timeout(timeout_dur, TcpStream::connect(proxy_addr))
            .await
            .map_err(|_| format!("连接代理 {} 超时", proxy_addr))?
            .map_err(|e| format!("连接代理 {} 失败: {}", proxy_addr, e))?;

        use tokio::io::AsyncWriteExt;

        // 发送 HTTP CONNECT 请求
        let connect_req = format!(
            "CONNECT {} HTTP/1.1\r\nHost: {}\r\nProxy-Connection: Keep-Alive\r\n\r\n",
            target, target
        );
        timeout(timeout_dur, proxy.write_all(connect_req.as_bytes()))
            .await
            .map_err(|_| "发送 CONNECT 请求超时".to_string())?
            .map_err(|e| format!("发送 CONNECT 请求失败: {}", e))?;

        // 读取代理响应
        use tokio::io::AsyncReadExt;
        let mut response = vec![0u8; 4096];
        let n = timeout(timeout_dur, proxy.read(&mut response))
            .await
            .map_err(|_| "读取代理响应超时".to_string())?
            .map_err(|e| format!("读取代理响应失败: {}", e))?;

        let resp_str = String::from_utf8_lossy(&response[..n]);
        if !resp_str.starts_with("HTTP/1.1 200") && !resp_str.starts_with("HTTP/1.0 200") {
            let status_line = resp_str.lines().next().unwrap_or("未知状态");
            return Err(format!("代理拒绝连接: {}", status_line));
        }

        Ok(proxy)
    }

    /// 启动 HTTP 隧道（支持优雅关闭）
    pub async fn start_with_shutdown(&self, shutdown: &Shutdown) -> Result<()> {
        self.config.validate()?;

        let target = self.config.remote_target.clone()
            .ok_or_else(|| IntraSweepError::Config {
                message: "HTTP 隧道需要指定远程目标".to_string(),
            })?;

        // 解析代理地址（从 hops 取第一个作为代理，或使用 remote_target 作为目标）
        let proxy = self.config.hops.first().cloned()
            .ok_or_else(|| IntraSweepError::Config {
                message: "HTTP 隧道需要指定代理地址 (-H/--hop)".to_string(),
            })?;

        let listener = TcpListener::bind(&self.config.local_addr).await
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
        println!("║  HTTP 隧道启动: 监听 {}", self.config.local_addr);
        println!("║  代理地址: {}", proxy);
        println!("║  转发目标: {}", target);
        println!("║  最大连接: {}", self.config.max_connections);
        println!("╚════════════════════════════════════════════════════════════════════════════╝");
        println!();
        println!("按 Ctrl+C 停止隧道");
        println!();

        let semaphore = Arc::new(Semaphore::new(self.config.max_connections));
        let mut counter = 0u64;

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((client, addr)) => {
                            let permit = match semaphore.clone().try_acquire_owned() {
                                Ok(p) => p,
                                Err(_) => {
                                    tracing::warn!("HTTP隧道 连接数已达上限，拒绝: {}", addr);
                                    drop(client);
                                    continue;
                                }
                            };

                            counter += 1;
                            let conn_id = format!("http-{}", counter);
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

                            let target = target.clone();
                            let proxy = proxy.clone();
                            let timeout_dur = Duration::from_secs(self.config.timeout_secs);
                            let event_handler = self.event_handler.clone();
                            let status = self.status.clone();

                            tokio::spawn(async move {
                                // 通过 HTTP CONNECT 代理连接到目标
                                match Self::connect_via_proxy(&proxy, &target, timeout_dur).await {
                                    Ok(target_stream) => {
                                        let stats = relay::relay(client, target_stream).await;
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
                                            message: format!("HTTP CONNECT 失败: {}", e),
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
        println!("HTTP 隧道已关闭");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_tunnel_creation() {
        let local: std::net::SocketAddr = "127.0.0.1:8888".parse().unwrap();
        let config = TunnelConfig::new(
            crate::tunnel::config::TunnelType::Forward,
            local,
        )
        .with_remote_target("internal.corp.local:80".to_string())
        .with_hops(vec!["proxy.corp.local:8080".to_string()]);

        let handler = crate::tunnel::models::LogEventHandler::new(true);
        let tunnel = HttpTunnel::new(config, Arc::new(handler));
        assert_eq!(tunnel.config.hops.len(), 1);
        assert_eq!(
            tunnel.config.remote_target,
            Some("internal.corp.local:80".to_string())
        );
    }
}
