//! SOCKS5 代理模块
//!
//! 实现 RFC 1928 SOCKS5 协议

use crate::core::error::{IntraSweepError, Result};
use crate::tunnel::config::TunnelConfig;
use crate::tunnel::models::{ConnectionInfo, TunnelEvent, TunnelEventHandler, TunnelStatus};
use crate::tunnel::relay;
use crate::tunnel::shutdown::Shutdown;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::{timeout, Duration};
use tracing;
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
    pub config: TunnelConfig,
    status: Arc<tokio::sync::RwLock<TunnelStatus>>,
    event_handler: Arc<dyn TunnelEventHandler>,
}

impl Socks5Server {
    pub fn new(config: TunnelConfig, event_handler: Arc<dyn TunnelEventHandler>) -> Self {
        Self {
            config,
            status: Arc::new(tokio::sync::RwLock::new(TunnelStatus::new())),
            event_handler,
        }
    }

    /// 启动 SOCKS5 代理
    pub async fn start(&self) -> Result<()> {
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
        println!("║  SOCKS5 代理启动");
        println!("║  监听地址: {}", self.config.local_addr);
        println!(
            "║  认证方式: {}",
            if self.config.socks5_username.is_some() {
                "用户名/密码"
            } else {
                "无需认证"
            }
        );
        println!("║  最大连接: {}", self.config.max_connections);
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
                            tracing::warn!("连接数已达上限，拒绝: {}", addr);
                            drop(client);
                            continue;
                        }
                    };

                    let conn_id = format!("socks5-{}", Uuid::new_v4());
                    let event_handler = self.event_handler.clone();
                    let status = self.status.clone();
                    let config = self.config.clone();

                    tokio::spawn(async move {
                        Self::handle_client(client, addr, conn_id, event_handler, status, config)
                            .await;

                        drop(permit);
                    });
                }
                Err(e) => {
                    self.event_handler.on_event(TunnelEvent::Error {
                        message: format!("接受连接失败: {}", e),
                    });
                    // listener 异常时退避，避免错误风暴下 CPU 空转
                    tokio::time::sleep(Duration::from_millis(500)).await;
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
                // 连接到目标（带瞬时错误重试）
                let timeout_dur = Duration::from_secs(config.timeout_secs);

                match Self::connect_with_retry(&target_addr, timeout_dur).await {
                    Ok(target_stream) => {
                        // 双向转发
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
                            message: format!("连接目标 {} 失败: {}", target_addr, e),
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

    /// 连接目标地址，对超时/连接重置等瞬时错误进行有限重试
    ///
    /// 连接被拒绝（目标无服务）通常是确定性的，不重试；仅对可能因网络抖动
    /// 产生的瞬时错误重试最多 MAX_RETRIES 次，提升不稳定链路上的隧道可用性。
    async fn connect_with_retry(
        target_addr: &str,
        timeout_dur: Duration,
    ) -> std::io::Result<TcpStream> {
        const MAX_RETRIES: usize = 2;
        for attempt in 0..=MAX_RETRIES {
            match timeout(timeout_dur, TcpStream::connect(target_addr)).await {
                Ok(Ok(stream)) => return Ok(stream),
                Ok(Err(e)) => {
                    if attempt < MAX_RETRIES && is_transient_io(&e) {
                        tracing::warn!(
                            "[SOCKS5] 连接目标 {} 失败({}), 重试 {}/{}",
                            target_addr,
                            e,
                            attempt + 1,
                            MAX_RETRIES
                        );
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        continue;
                    }
                    return Err(e);
                }
                Err(_) => {
                    if attempt < MAX_RETRIES {
                        tracing::warn!(
                            "[SOCKS5] 连接目标 {} 超时, 重试 {}/{}",
                            target_addr,
                            attempt + 1,
                            MAX_RETRIES
                        );
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        continue;
                    }
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "连接目标超时",
                    ));
                }
            }
        }
        // 循环正常会在上面的 return 退出，兜底
        Err(std::io::Error::other("重试耗尽"))
    }

    /// SOCKS5 握手协议
    async fn socks5_handshake(stream: &mut TcpStream, config: &TunnelConfig) -> Result<String> {
        let mut buf = [0u8; 256];

        // 读取版本和认证方法
        stream
            .read_exact(&mut buf[0..2])
            .await
            .map_err(|_| IntraSweepError::Protocol {
                message: "读取握手请求失败".to_string(),
            })?;

        if buf[0] != SOCKS5_VERSION {
            return Err(IntraSweepError::Protocol {
                message: format!("不支持的 SOCKS 版本: {}", buf[0]),
            });
        }

        let n_methods = buf[1] as usize;

        // 读取支持的认证方法列表
        stream
            .read_exact(&mut buf[0..n_methods])
            .await
            .map_err(|_| IntraSweepError::Protocol {
                message: "读取认证方法失败".to_string(),
            })?;

        // 选择认证方法
        let auth_method = if config.socks5_username.is_some() {
            if buf[0..n_methods].contains(&AUTH_USERPASS) {
                AUTH_USERPASS
            } else {
                // RFC 1928: 客户端未提供所需认证方法时返回 0xFF
                stream
                    .write_all(&[SOCKS5_VERSION, 0xFF])
                    .await
                    .map_err(|e| IntraSweepError::Protocol {
                        message: format!("发送认证方法失败: {}", e),
                    })?;
                return Err(IntraSweepError::Protocol {
                    message: "客户端不支持所需的用户名密码认证".to_string(),
                });
            }
        } else {
            AUTH_NONE
        };

        // 发送认证方法选择
        stream
            .write_all(&[SOCKS5_VERSION, auth_method])
            .await
            .map_err(|e| IntraSweepError::Protocol {
                message: format!("发送认证方法失败: {}", e),
            })?;

        // 如果需要用户名密码认证 (RFC 1929)
        if auth_method == AUTH_USERPASS {
            let username =
                config
                    .socks5_username
                    .as_deref()
                    .ok_or_else(|| IntraSweepError::Config {
                        message: "SOCKS5 认证配置错误：缺少用户名".to_string(),
                    })?;
            let password =
                config
                    .socks5_password
                    .as_deref()
                    .ok_or_else(|| IntraSweepError::Config {
                        message: "SOCKS5 认证配置错误：缺少密码".to_string(),
                    })?;

            // RFC 1929: VER(1) ULEN(1) UNAME(ULEN) PLEN(1) PASSWD(PLEN)
            let mut auth_hdr = [0u8; 2];
            stream
                .read_exact(&mut auth_hdr)
                .await
                .map_err(|_| IntraSweepError::Protocol {
                    message: "读取认证请求失败".to_string(),
                })?;

            let ulen = auth_hdr[1] as usize;
            let mut recv_username_buf = vec![0u8; ulen];
            stream
                .read_exact(&mut recv_username_buf)
                .await
                .map_err(|_| IntraSweepError::Protocol {
                    message: "读取用户名失败".to_string(),
                })?;

            let mut plen_buf = [0u8; 1];
            stream
                .read_exact(&mut plen_buf)
                .await
                .map_err(|_| IntraSweepError::Protocol {
                    message: "读取密码长度失败".to_string(),
                })?;

            let plen = plen_buf[0] as usize;
            let mut recv_password_buf = vec![0u8; plen];
            stream
                .read_exact(&mut recv_password_buf)
                .await
                .map_err(|_| IntraSweepError::Protocol {
                    message: "读取密码失败".to_string(),
                })?;

            // 验证用户名和密码
            let recv_username =
                std::str::from_utf8(&recv_username_buf).map_err(|_| IntraSweepError::Protocol {
                    message: "用户名格式错误".to_string(),
                })?;

            let recv_password =
                std::str::from_utf8(&recv_password_buf).map_err(|_| IntraSweepError::Protocol {
                    message: "密码格式错误".to_string(),
                })?;

            if recv_username == username && recv_password == password {
                // 认证成功
                stream
                    .write_all(&[0x01, 0x00])
                    .await
                    .map_err(|e| IntraSweepError::Protocol {
                        message: format!("发送认证响应失败: {}", e),
                    })?;
            } else {
                // 认证失败
                stream
                    .write_all(&[0x01, 0x01])
                    .await
                    .map_err(|e| IntraSweepError::Protocol {
                        message: format!("发送认证失败响应失败: {}", e),
                    })?;
                return Err(IntraSweepError::Protocol {
                    message: "认证失败".to_string(),
                });
            }
        }

        // 读取连接请求
        stream
            .read_exact(&mut buf[0..4])
            .await
            .map_err(|_| IntraSweepError::Protocol {
                message: "读取连接请求失败".to_string(),
            })?;

        if buf[0] != SOCKS5_VERSION {
            return Err(IntraSweepError::Protocol {
                message: "SOCKS 版本不匹配".to_string(),
            });
        }

        let cmd = buf[1];
        let addr_type = buf[3];

        if cmd != CMD_CONNECT {
            stream
                .write_all(&[
                    0x05,
                    REP_COMMAND_NOT_SUPPORTED,
                    0x00,
                    0x01,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                ])
                .await
                .map_err(|_| IntraSweepError::Protocol {
                    message: "发送错误响应失败".to_string(),
                })?;
            return Err(IntraSweepError::Protocol {
                message: "不支持的命令".to_string(),
            });
        }

        // 解析目标地址
        let target_addr =
            match addr_type {
                ADDR_IPV4 => {
                    stream.read_exact(&mut buf[0..6]).await.map_err(|_| {
                        IntraSweepError::Protocol {
                            message: "读取 IPv4 地址失败".to_string(),
                        }
                    })?;

                    let ip = std::net::Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                    let port = u16::from_be_bytes([buf[4], buf[5]]);
                    format!("{}:{}", ip, port)
                }
                ADDR_DOMAIN => {
                    // RFC 1928: ATYP=0x03 时，后续为 LEN(1) + DOMAIN(LEN) + PORT(2)
                    let mut len_buf = [0u8; 1];
                    stream.read_exact(&mut len_buf).await.map_err(|_| {
                        IntraSweepError::Protocol {
                            message: "读取域名长度失败".to_string(),
                        }
                    })?;
                    let domain_len = len_buf[0] as usize;

                    let mut domain_and_port = vec![0u8; domain_len + 2];
                    stream.read_exact(&mut domain_and_port).await.map_err(|_| {
                        IntraSweepError::Protocol {
                            message: "读取域名地址失败".to_string(),
                        }
                    })?;

                    let domain =
                        std::str::from_utf8(&domain_and_port[0..domain_len]).map_err(|_| {
                            IntraSweepError::Protocol {
                                message: "域名格式错误".to_string(),
                            }
                        })?;

                    let port = u16::from_be_bytes([
                        domain_and_port[domain_len],
                        domain_and_port[domain_len + 1],
                    ]);
                    format!("{}:{}", domain, port)
                }
                ADDR_IPV6 => {
                    stream
                        .write_all(&[
                            0x05,
                            REP_ADDRESS_TYPE_NOT_SUPPORTED,
                            0x00,
                            0x01,
                            0x00,
                            0x00,
                            0x00,
                            0x00,
                            0x00,
                            0x00,
                        ])
                        .await
                        .map_err(|_| IntraSweepError::Protocol {
                            message: "发送错误响应失败".to_string(),
                        })?;
                    return Err(IntraSweepError::Protocol {
                        message: "不支持 IPv6 地址".to_string(),
                    });
                }
                _ => {
                    stream
                        .write_all(&[
                            0x05,
                            REP_ADDRESS_TYPE_NOT_SUPPORTED,
                            0x00,
                            0x01,
                            0x00,
                            0x00,
                            0x00,
                            0x00,
                            0x00,
                            0x00,
                        ])
                        .await
                        .map_err(|_| IntraSweepError::Protocol {
                            message: "发送错误响应失败".to_string(),
                        })?;
                    return Err(IntraSweepError::Protocol {
                        message: "不支持的地址类型".to_string(),
                    });
                }
            };

        // 发送成功响应
        stream
            .write_all(&[
                0x05,
                REP_SUCCESS,
                0x00,
                0x01,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
            ])
            .await
            .map_err(|e| IntraSweepError::Protocol {
                message: format!("发送成功响应失败: {}", e),
            })?;

        Ok(target_addr)
    }

    /// 启动 SOCKS5 代理（支持优雅关闭）
    pub async fn start_with_shutdown(&self, shutdown: &Shutdown) -> Result<()> {
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
        println!("║  SOCKS5 代理启动");
        println!("║  监听地址: {}", self.config.local_addr);
        println!(
            "║  认证方式: {}",
            if self.config.socks5_username.is_some() {
                "用户名/密码"
            } else {
                "无需认证"
            }
        );
        println!("║  最大连接: {}", self.config.max_connections);
        println!("╚════════════════════════════════════════════════════════════════════════════╝");
        println!();
        println!("按 Ctrl+C 优雅关闭代理");
        println!();

        let semaphore = Arc::new(Semaphore::new(self.config.max_connections));

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

                            let conn_id = format!("socks5-{}", Uuid::new_v4());
                            let event_handler = self.event_handler.clone();
                            let status = self.status.clone();
                            let config = self.config.clone();

                            tokio::spawn(async move {
                                Self::handle_client(
                                    client, addr, conn_id,
                                    event_handler, status, config,
                                ).await;
                                drop(permit);
                            });
                        }
                        Err(e) => {
                            self.event_handler.on_event(TunnelEvent::Error {
                                message: format!("接受连接失败: {}", e),
                            });
                            // listener 异常时退避，避免错误风暴下 CPU 空转
                            tokio::time::sleep(Duration::from_millis(500)).await;
                        }
                    }
                }
                _ = shutdown.wait() => {
                    break;
                }
            }
        }

        self.event_handler.on_event(TunnelEvent::Stopped);
        println!("SOCKS5 代理已关闭");
        Ok(())
    }
}

/// 判断 IO 错误是否为瞬时错误（值得重试）
///
/// 连接被拒绝（目标无服务）通常是确定性的，不重试；其余瞬时错误可重试。
fn is_transient_io(e: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    matches!(
        e.kind(),
        ErrorKind::TimedOut
            | ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::Interrupted
            | ErrorKind::UnexpectedEof
            | ErrorKind::WouldBlock
    )
}
