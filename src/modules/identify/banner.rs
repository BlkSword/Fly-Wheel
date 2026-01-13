//! Banner 抓取模块
//!
//! 从开放端口抓取服务 Banner 信息

use crate::core::error::{FlyWheelError, Result};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Banner 抓取器
#[derive(Debug, Clone)]
pub struct BannerGrabber {
    /// 连接超时时间
    timeout: Duration,
    /// 最大读取字节数
    max_read: usize,
    /// 发送探测数据
    send_probes: bool,
}

impl BannerGrabber {
    /// 创建新的 Banner 抓取器
    pub fn new(timeout: Duration, max_read: usize) -> Self {
        Self {
            timeout,
            max_read,
            send_probes: true,
        }
    }

    /// 使用默认配置创建
    pub fn with_defaults() -> Self {
        Self::new(Duration::from_secs(3), 4096)
    }

    /// 设置是否发送探测数据
    pub fn send_probes(mut self, send: bool) -> Self {
        self.send_probes = send;
        self
    }

    /// 抓取 Banner
    pub async fn grab(&self, addr: SocketAddr) -> Result<BannerResult> {
        // 连接到目标
        let mut stream = timeout(
            self.timeout,
            TcpStream::connect(addr)
        )
        .await
        .map_err(|_| FlyWheelError::Timeout {
            target: addr.to_string(),
        })?
        .map_err(|e| FlyWheelError::Network(e))?;

        // 发送探测数据
        if self.send_probes {
            self.send_probe(&mut stream, addr.port()).await?;
        }

        // 读取响应
        let banner = self.read_banner(&mut stream).await?;

        Ok(BannerResult {
            address: addr,
            banner,
        })
    }

    /// 发送探测数据
    async fn send_probe(&self, stream: &mut TcpStream, port: u16) -> Result<()> {
        let probe_data = self.get_probe_data(port);

        if !probe_data.is_empty() {
            timeout(
                Duration::from_millis(500),
                stream.write_all(&probe_data)
            )
            .await
            .map_err(|_| FlyWheelError::Timeout {
                target: format!("端口 {}: 发送探测数据", port),
            })?
            .map_err(|e| FlyWheelError::Network(e))?;
        }

        Ok(())
    }

    /// 获取端口对应的探测数据
    fn get_probe_data(&self, port: u16) -> Vec<u8> {
        match port {
            // HTTP - 发送简单的 GET 请求
            80 | 8080 | 8000 | 8888 => b"GET / HTTP/1.0\r\n\r\n".to_vec(),

            // HTTPS - 发送 ClientHello（简化）
            443 | 8443 => {
                // 简单的 TLS ClientHello
                vec![
                    0x16,  // Handshake
                    0x03, 0x01,  // TLS 1.0
                    0x00, 0x4d,  // Length
                    0x01,  // ClientHello
                    0x00, 0x00, 0x49,  // Length
                    0x03, 0x03,  // TLS 1.2
                    // ... 简化的 ClientHello
                ]
            }

            // FTP - 不需要探测数据，服务器会主动发送 banner
            21 => vec![],

            // SSH - 不需要探测数据
            22 => vec![],

            // SMTP - 发送 EHLO
            25 | 587 => b"EHLO example.com\r\n".to_vec(),

            // POP3
            110 | 995 => vec![],

            // IMAP
            143 | 993 => vec![],

            // MySQL
            3306 => vec![],

            // PostgreSQL
            5432 => vec![],

            // RDP
            3389 => vec![],

            // VNC
            5900 => vec![],

            _ => vec![],
        }
    }

    /// 读取 Banner
    async fn read_banner(&self, stream: &mut TcpStream) -> Result<Option<String>> {
        let mut reader = BufReader::new(stream);
        let mut buffer = vec![0u8; self.max_read];

        match timeout(self.timeout, reader.read(&mut buffer)).await {
            Ok(Ok(n)) => {
                if n == 0 {
                    Ok(None)
                } else {
                    // 尝试转换为 UTF-8 字符串
                    let banner = String::from_utf8_lossy(&buffer[..n]).to_string();
                    // 清理 banner（移除控制字符）
                    let cleaned = Self::clean_banner(&banner);
                    Ok(Some(cleaned))
                }
            }
            Ok(Err(e)) => Err(FlyWheelError::Network(e)),
            Err(_) => Ok(None),
        }
    }

    /// 清理 Banner 字符串
    fn clean_banner(banner: &str) -> String {
        // 移除控制字符，但保留换行符
        banner
            .chars()
            .map(|c| {
                if c.is_control() && c != '\n' && c != '\r' && c != '\t' {
                    ' '
                } else {
                    c
                }
            })
            .collect::<String>()
            .lines()
            .map(|line| line.trim())
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>()
            .join(" | ")
    }

    /// 批量抓取多个端口的 Banner
    pub async fn grab_multiple(&self, addrs: Vec<SocketAddr>) -> Vec<BannerResult> {
        let mut results = Vec::new();

        for addr in addrs {
            match self.grab(addr).await {
                Ok(result) => results.push(result),
                Err(_) => continue,
            }
        }

        results
    }
}

/// Banner 抓取结果
#[derive(Debug, Clone)]
pub struct BannerResult {
    /// 地址
    pub address: SocketAddr,
    /// Banner 内容
    pub banner: Option<String>,
}

impl BannerResult {
    /// 获取 Banner 文本
    pub fn banner_text(&self) -> Option<&str> {
        self.banner.as_deref()
    }

    /// 检查是否包含特定关键字
    pub fn contains(&self, keyword: &str) -> bool {
        self.banner
            .as_ref()
            .map(|b| b.to_lowercase().contains(&keyword.to_lowercase()))
            .unwrap_or(false)
    }

    /// 提取服务器信息
    pub fn extract_server(&self) -> Option<String> {
        self.banner.as_ref().and_then(|b| {
            b.lines()
                .find(|line| {
                    let line_lower = line.to_lowercase();
                    line_lower.starts_with("server:")
                        || line_lower.contains("server")
                        || line_lower.starts_with("ssh-")
                })
                .map(|line| line.to_string())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_banner_grabber_creation() {
        let grabber = BannerGrabber::with_defaults();
        assert_eq!(grabber.max_read, 4096);
    }

    #[test]
    fn test_get_probe_data() {
        let grabber = BannerGrabber::with_defaults();

        // HTTP 端口应该返回探测数据
        let http_probe = grabber.get_probe_data(80);
        assert!(!http_probe.is_empty());

        // SSH 端口不应该返回探测数据
        let ssh_probe = grabber.get_probe_data(22);
        assert!(ssh_probe.is_empty());
    }

    #[test]
    fn test_clean_banner() {
        let dirty = "SSH-2.0-OpenSSH_8.2p1\r\nProtocol mismatch.\x00\x01";
        let clean = BannerGrabber::clean_banner(dirty);
        assert!(clean.contains("SSH-2.0-OpenSSH"));
        assert!(!clean.contains("\x00"));
    }

    #[test]
    fn test_banner_result_contains() {
        let result = BannerResult {
            address: "127.0.0.1:22".parse().unwrap(),
            banner: Some("SSH-2.0-OpenSSH_8.2p1 Ubuntu".to_string()),
        };

        assert!(result.contains("openssh"));
        assert!(result.contains("ubuntu"));
        assert!(!result.contains("apache"));
    }

    #[test]
    fn test_extract_server() {
        let result = BannerResult {
            address: "127.0.0.1:80".parse().unwrap(),
            banner: Some("HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n".to_string()),
        };

        let server = result.extract_server();
        assert!(server.is_some());
        assert!(server.unwrap().contains("nginx"));
    }
}
