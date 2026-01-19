//! SOCKS5 代理模块
//!
//! 实现 RFC 1928 SOCKS5 协议

use crate::core::error::{FlyWheelError, Result};
use crate::tunnel::config::TunnelConfig;
use crate::tunnel::models::{ConnectionInfo, TunnelEvent, TunnelEventHandler, TunnelStatus};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::{timeout, Duration};
use uuid::Uuid;

// SOCKS5 协议常量
const SOCKS5_VERSION: u8 = 0x05;

// 认证方法
const AUTH_NONE: u8 = 0x00;
const AUTH_USERPASS: u8 = 0x02;

// 命令类型
const CMD_CONNECT: u8 = 0x01;
#[allow(dead_code)]
const CMD_BIND: u8 = 0x02;
#[allow(dead_code)]
const CMD_UDP_ASSOCIATE: u8 = 0x03;

// 地址类型
const ADDR_IPV4: u8 = 0x01;
const ADDR_DOMAIN: u8 = 0x03;
const ADDR_IPV6: u8 = 0x04;

// 响应代码
const REP_SUCCESS: u8 = 0x00;
#[allow(dead_code)]
const REP_GENERAL_FAILURE: u8 = 0x01;
#[allow(dead_code)]
const REP_CONNECTION_NOT_ALLOWED: u8 = 0x02;
#[allow(dead_code)]
const REP_NETWORK_UNREACHABLE: u8 = 0x03;
#[allow(dead_code)]
const REP_HOST_UNREACHABLE: u8 = 0x04;
#[allow(dead_code)]
const REP_CONNECTION_REFUSED: u8 = 0x05;
#[allow(dead_code)]
const REP_TTL_EXPIRED: u8 = 0x06;
const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const REP_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;

/// SOCKS5 代理服务器
pub struct Socks5Server {
    config: TunnelConfig,
    status: Arc<tokio::sync::RwLock<TunnelStatus>>,
    event_handler: Arc<dyn TunnelEventHandler>,
}

impl Socks5Server {
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

    /// 启动 SOCKS5 代理
    pub async fn start(&self) -> Result<()> {
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
        println!("║  {}", format!("SOCKS5 代理启动"));
        println!("║  {}", format!("监听地址: {}", self.config.local_addr));
        println!("║  {}", format!("认证方式: {}", if self.config.socks5_username.is_some() { "用户名/密码" } else { "无需认证" }));
        println!("║  {}", format!("最大连接: {}", self.config.max_connections));
        println!("╚════════════════════════════════════════════════════════════════════════════╝");
        println!();
        println!("按 Ctrl+C 停止代理");
        println!();

        let semaphore = Arc::new(Semaphore::new(self.config.max_connections));

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

                    let conn_id = format!("socks5-{}", Uuid::new_v4());
                    let event_handler = self.event_handler.clone();
                    let status = self.status.clone();
                    let config = self.config.clone();

                    tokio::spawn(async move {
                        Self::handle_client(
                            client,
                            addr,
                            conn_id,
                            event_handler,
                            status,
                            config,
                        ).await;

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

    /// 处理客户端连接
    async fn handle_client(
        mut client: TcpStream,
        addr: std::net::SocketAddr,
        conn_id: String,
        event_handler: Arc<dyn TunnelEventHandler>,
        status: Arc<tokio::sync::RwLock<TunnelStatus>>,
        config: TunnelConfig,
    ) {
        {
            let local_addr = client.local_addr().unwrap_or(addr);
            let remote_addr = addr;

            event_handler.on_event(TunnelEvent::Connected {
                id: conn_id.clone(),
                local_addr,
                remote_addr,
            });

            status.write().await.add_connection(ConnectionInfo::new(
                conn_id.clone(),
                local_addr,
                addr,
            ));
        }

        // SOCKS5 握手
        let result = Self::socks5_handshake(&mut client, &config).await;

        match result {
            Ok(target_addr) => {
                // 连接到目标
                let timeout_dur = Duration::from_secs(config.timeout_secs);

                match timeout(timeout_dur, TcpStream::connect(&target_addr)).await {
                    Ok(Ok(target_stream)) => {
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
                    Ok(Err(e)) => {
                        event_handler.on_event(TunnelEvent::Error {
                            message: format!("连接目标 {} 失败: {}", target_addr, e),
                        });
                        {
                            let mut st = status.write().await;
                            st.remove_connection(&conn_id);
                        }
                    }
                    Err(_) => {
                        event_handler.on_event(TunnelEvent::Error {
                            message: format!("连接目标 {} 超时", target_addr),
                        });
                        {
                            let mut st = status.write().await;
                            st.remove_connection(&conn_id);
                        }
                    }
                }
            }
            Err(e) => {
                event_handler.on_event(TunnelEvent::Error {
                    message: format!("SOCKS5 握手失败: {}", e),
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
    }

    /// SOCKS5 握手协议
    async fn socks5_handshake(
        stream: &mut TcpStream,
        config: &TunnelConfig,
    ) -> Result<String> {
        let mut buf = [0u8; 256];

        // 读取版本和认证方法
        stream.read_exact(&mut buf[0..2]).await
            .map_err(|_| FlyWheelError::Other {
                message: "读取握手请求失败".to_string(),
            })?;

        if buf[0] != SOCKS5_VERSION {
            return Err(FlyWheelError::Other {
                message: format!("不支持的 SOCKS 版本: {}", buf[0]),
            });
        }

        let n_methods = buf[1] as usize;

        // 读取支持的认证方法列表
        stream.read_exact(&mut buf[0..n_methods]).await
            .map_err(|_| FlyWheelError::Other {
                message: "读取认证方法失败".to_string(),
            })?;

        // 选择认证方法
        let auth_method = if config.socks5_username.is_some() {
            if buf[0..n_methods].contains(&AUTH_USERPASS) {
                AUTH_USERPASS
            } else {
                AUTH_NONE
            }
        } else {
            AUTH_NONE
        };

        // 发送认证方法选择
        stream.write_all(&[SOCKS5_VERSION, auth_method]).await
            .map_err(|e| FlyWheelError::Other {
                message: format!("发送认证方法失败: {}", e),
            })?;

        // 如果需要用户名密码认证
        if auth_method == AUTH_USERPASS {
            let username = config.socks5_username.as_ref().unwrap();
            let password = config.socks5_password.as_ref().unwrap();

            let mut buf = [0u8; 256];
            stream.read_exact(&mut buf[0..2]).await
                .map_err(|_| FlyWheelError::Other {
                    message: "读取认证请求失败".to_string(),
                })?;

            let ulen = buf[1] as usize;
            stream.read_exact(&mut buf[0..ulen]).await
                .map_err(|_| FlyWheelError::Other {
                    message: "读取用户名失败".to_string(),
                })?;

            stream.read_exact(&mut buf[0..1]).await
                .map_err(|_| FlyWheelError::Other {
                    message: "读取密码长度失败".to_string(),
                })?;

            let plen = buf[0] as usize;
            stream.read_exact(&mut buf[0..plen]).await
                .map_err(|_| FlyWheelError::Other {
                    message: "读取密码失败".to_string(),
                })?;

            // 验证用户名和密码
            let recv_username = std::str::from_utf8(&buf[0..ulen])
                .map_err(|_| FlyWheelError::Other {
                    message: "用户名格式错误".to_string(),
                })?;

            let recv_password = std::str::from_utf8(&buf[ulen + 1..ulen + 1 + plen])
                .map_err(|_| FlyWheelError::Other {
                    message: "密码格式错误".to_string(),
                })?;

            if recv_username == username && recv_password == password {
                // 认证成功
                stream.write_all(&[0x01, 0x00]).await
                    .map_err(|e| FlyWheelError::Other {
                        message: format!("发送认证响应失败: {}", e),
                    })?;
            } else {
                // 认证失败
                stream.write_all(&[0x01, 0x01]).await
                    .map_err(|e| FlyWheelError::Other {
                        message: format!("发送认证失败响应失败: {}", e),
                    })?;
                return Err(FlyWheelError::Other {
                    message: "认证失败".to_string(),
                });
            }
        }

        // 读取连接请求
        stream.read_exact(&mut buf[0..4]).await
            .map_err(|_| FlyWheelError::Other {
                message: "读取连接请求失败".to_string(),
            })?;

        if buf[0] != SOCKS5_VERSION {
            return Err(FlyWheelError::Other {
                message: "SOCKS 版本不匹配".to_string(),
            });
        }

        let cmd = buf[1];
        let addr_type = buf[3];

        if cmd != CMD_CONNECT {
            // 只支持 CONNECT 命令
            stream.write_all(&[0x05, REP_COMMAND_NOT_SUPPORTED, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]).await
                .map_err(|_| FlyWheelError::Other {
                    message: "发送错误响应失败".to_string(),
                })?;
            return Err(FlyWheelError::Other {
                message: "不支持的命令".to_string(),
            });
        }

        // 解析目标地址
        let target_addr = match addr_type {
            ADDR_IPV4 => {
                // IPv4 地址
                stream.read_exact(&mut buf[0..6]).await
                    .map_err(|_| FlyWheelError::Other {
                        message: "读取 IPv4 地址失败".to_string(),
                    })?;

                let ip = std::net::Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                let port = u16::from_be_bytes([buf[4], buf[5]]);
                format!("{}:{}", ip, port)
            }
            ADDR_DOMAIN => {
                // 域名地址
                let domain_len = buf[1] as usize;
                stream.read_exact(&mut buf[0..domain_len + 2]).await
                    .map_err(|_| FlyWheelError::Other {
                        message: "读取域名地址失败".to_string(),
                    })?;

                let domain = std::str::from_utf8(&buf[0..domain_len])
                    .map_err(|_| FlyWheelError::Other {
                        message: "域名格式错误".to_string(),
                    })?;

                let port = u16::from_be_bytes([buf[domain_len], buf[domain_len + 1]]);
                format!("{}:{}", domain, port)
            }
            ADDR_IPV6 => {
                // IPv6 地址
                stream.write_all(&[0x05, REP_ADDRESS_TYPE_NOT_SUPPORTED, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).await
                    .map_err(|_| FlyWheelError::Other {
                        message: "发送错误响应失败".to_string(),
                    })?;
                return Err(FlyWheelError::Other {
                    message: "不支持 IPv6 地址".to_string(),
                });
            }
            _ => {
                stream.write_all(&[0x05, REP_ADDRESS_TYPE_NOT_SUPPORTED, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).await
                    .map_err(|_| FlyWheelError::Other {
                        message: "发送错误响应失败".to_string(),
                    })?;
                return Err(FlyWheelError::Other {
                    message: "不支持的地址类型".to_string(),
                });
            }
        };

        // 发送成功响应
        stream.write_all(&[0x05, REP_SUCCESS, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).await
            .map_err(|e| FlyWheelError::Other {
                message: format!("发送成功响应失败: {}", e),
            })?;

        Ok(target_addr)
    }

    /// 双向流量转发
    async fn relay(mut client: TcpStream, mut target: TcpStream) -> TransferStats {
        let mut client_buf = vec![0u8; 8192];
        let mut target_buf = vec![0u8; 8192];
        let mut sent = 0u64;
        let mut received = 0u64;

        loop {
            tokio::select! {
                // 客户端 -> 目标
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
                // 目标 -> 客户端
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

    /// 获取代理状态
    #[allow(dead_code)]
    pub async fn get_status(&self) -> TunnelStatus {
        self.status.read().await.clone()
    }

    /// 停止代理
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
