//! 服务识别模块
//!
//! 提供端口服务识别和Banner抓取功能

use crate::scanner::models::ServiceInfo;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// 服务识别器
pub struct ServiceIdentifier {
    /// 连接超时时间
    connect_timeout: Duration,
    /// Banner抓取超时时间
    banner_timeout: Duration,
}

impl ServiceIdentifier {
    /// 创建新的服务识别器
    pub fn new() -> Self {
        Self {
            connect_timeout: Duration::from_millis(1000),
            banner_timeout: Duration::from_millis(3000),
        }
    }

    /// 设置超时时间
    pub fn with_timeout(mut self, connect_ms: u64, banner_ms: u64) -> Self {
        self.connect_timeout = Duration::from_millis(connect_ms);
        self.banner_timeout = Duration::from_millis(banner_ms);
        self
    }

    /// 识别端口服务（同步版本）
    pub fn identify_service(&self, ip: IpAddr, port: u16) -> Option<ServiceInfo> {
        // 使用tokio运行时
        let rt = tokio::runtime::Runtime::new().ok()?;
        rt.block_on(self.identify_service_async(ip, port))
    }

    /// 识别端口服务（异步版本）
    pub async fn identify_service_async(&self, ip: IpAddr, port: u16) -> Option<ServiceInfo> {
        // 首先根据端口号猜测服务
        let service_name = Self::guess_service_by_port(port);
        let banner = self.grab_banner_async(ip, port).await;

        // 解析banner获取详细信息
        let mut info = ServiceInfo {
            name: service_name.unwrap_or_else(|| "unknown".to_string()),
            version: String::new(),
            product: String::new(),
            extra_info: banner.clone().unwrap_or_default(),
        };

        // 尝试从banner中提取版本信息
        if let Some(banner_text) = &banner {
            Self::parse_version_info(&mut info, banner_text, port);
        }

        Some(info)
    }

    /// 抓取Banner（同步版本）
    pub fn grab_banner(&self, ip: IpAddr, port: u16) -> Option<String> {
        let rt = tokio::runtime::Runtime::new().ok()?;
        rt.block_on(self.grab_banner_async(ip, port))
    }

    /// 抓取Banner（异步版本）
    pub async fn grab_banner_async(&self, ip: IpAddr, port: u16) -> Option<String> {
        let addr = SocketAddr::new(ip, port);

        // 尝试连接
        let mut stream = match timeout(self.connect_timeout, TcpStream::connect(&addr)).await {
            Ok(Ok(s)) => s,
            _ => return None,
        };

        // 根据端口发送探测数据
        let probe_data = Self::get_probe_data(port);
        if !probe_data.is_empty() {
            if timeout(self.banner_timeout, tokio::io::AsyncWriteExt::write_all(&mut stream, probe_data.as_bytes()))
                .await
                .is_err()
            {
                // 写入失败，继续尝试读取
            }
        }

        // 读取响应
        let mut buffer = vec![0u8; 4096];
        let n = match timeout(self.banner_timeout, tokio::io::AsyncReadExt::read(&mut stream, &mut buffer)).await {
            Ok(Ok(n)) => n,
            _ => 0,
        };

        if n > 0 {
            buffer.truncate(n);
            // 尝试转换为UTF-8字符串
            String::from_utf8(buffer).ok()
        } else {
            None
        }
    }

    /// 获取端口探测数据
    fn get_probe_data(port: u16) -> &'static str {
        match port {
            // HTTP/HTTPS
            80 | 8080 | 8000 => "GET / HTTP/1.0\r\n\r\n",
            443 | 8443 => "GET / HTTP/1.0\r\n\r\n", // HTTPS需要TLS，这里尝试普通连接
            // FTP
            21 => "",
            // SSH
            22 => "",
            // SMTP
            25 | 587 => "",
            // POP3
            110 => "",
            // IMAP
            143 => "",
            // Telnet
            23 => "\r\n",
            // VNC
            5900 => "",
            // MySQL
            3306 => "",
            // PostgreSQL
            5432 => "",
            // Redis
            6379 => "*1\r\n$4\r\nPING\r\n",
            // MongoDB
            27017 => "",
            // Elasticsearch
            9200 => "GET / HTTP/1.0\r\n\r\n",
            // RDP
            3389 => "",
            // SMB
            445 => "",
            _ => "",
        }
    }

    /// 根据端口号猜测服务
    fn guess_service_by_port(port: u16) -> Option<String> {
        let services = [
            (21, "ftp"),
            (22, "ssh"),
            (23, "telnet"),
            (25, "smtp"),
            (53, "dns"),
            (80, "http"),
            (110, "pop3"),
            (111, "rpcbind"),
            (135, "msrpc"),
            (139, "netbios-ssn"),
            (143, "imap"),
            (389, "ldap"),
            (443, "https"),
            (445, "smb"),
            (465, "smtps"),
            (587, "submission"),
            (593, "http-rpc-epmap"),
            (636, "ldaps"),
            (993, "imaps"),
            (995, "pop3s"),
            (1433, "mssql"),
            (1521, "oracle"),
            (3306, "mysql"),
            (3389, "rdp"),
            (5432, "postgresql"),
            (5900, "vnc"),
            (5985, "wsman"),
            (5986, "wsman-ssl"),
            (6379, "redis"),
            (8000, "http-alt"),
            (8080, "http-proxy"),
            (8443, "https-alt"),
            (8888, "http-alt"),
            (9200, "elasticsearch"),
            (27017, "mongodb"),
        ];

        services.iter()
            .find(|(p, _)| *p == port)
            .map(|(_, name)| name.to_string())
    }

    /// 从Banner中解析版本信息
    fn parse_version_info(info: &mut ServiceInfo, banner: &str, port: u16) {
        let banner_lower = banner.to_lowercase();

        // HTTP服务
        if port == 80 || port == 8080 || port == 8000 {
            if let Some(line) = banner.lines().next() {
                if line.contains("Server:") {
                    info.product = "HTTP Server".to_string();
                } else if line.starts_with("HTTP/") {
                    info.version = line.to_string();
                }
            }

            // 尝试识别具体的服务器
            if banner_lower.contains("nginx") {
                info.product = "nginx".to_string();
                if let Some(pos) = banner_lower.find("nginx/") {
                    let remaining = &banner[pos + 6..];
                    if let Some(end) = remaining.find(|c: char| !c.is_numeric() && c != '.') {
                        info.version = remaining[..end].to_string();
                    }
                }
            } else if banner_lower.contains("apache") {
                info.product = "Apache".to_string();
                if let Some(pos) = banner_lower.find("apache/") {
                    let remaining = &banner[pos + 7..];
                    if let Some(end) = remaining.find(|c: char| !c.is_numeric() && c != '.') {
                        info.version = remaining[..end].to_string();
                    }
                }
            } else if banner_lower.contains("iis") {
                info.product = "IIS".to_string();
            }
        }

        // SSH服务
        if port == 22 {
            if banner.contains("SSH-") {
                info.product = "SSH".to_string();
                if let Some(pos) = banner.find("SSH-") {
                    let remaining = &banner[pos + 4..];
                    info.version = remaining.split_whitespace().next().unwrap_or("").to_string();
                }
            }

            // OpenSSH
            if banner_lower.contains("openssh") {
                info.product = "OpenSSH".to_string();
            }
        }

        // FTP服务
        if port == 21 {
            if banner_lower.contains("vsftpd") {
                info.product = "vsftpd".to_string();
            } else if banner_lower.contains("proftpd") {
                info.product = "ProFTPD".to_string();
            } else if banner_lower.contains("pure-ftpd") {
                info.product = "Pure-FTPd".to_string();
            } else if banner_lower.contains("filezilla") {
                info.product = "FileZilla Server".to_string();
            } else if banner_lower.contains("microsoft") {
                info.product = "Microsoft FTP".to_string();
            }
        }

        // SMTP服务
        if port == 25 || port == 587 {
            if banner_lower.contains("postfix") {
                info.product = "Postfix".to_string();
            } else if banner_lower.contains("sendmail") {
                info.product = "Sendmail".to_string();
            } else if banner_lower.contains("exim") {
                info.product = "Exim".to_string();
            } else if banner_lower.contains("exchange") {
                info.product = "Microsoft Exchange".to_string();
            }
        }

        // 数据库服务
        if port == 3306 {
            // MySQL
            if banner_lower.contains("mysql") {
                info.product = "MySQL".to_string();
            }
            // 解析MySQL版本：5.7.25-0ubuntu0.18.04.2
            if let Some(pos) = banner_lower.find("5.") {
                let remaining = &banner[pos..];
                if let Some(end) = remaining.find(|c: char| c == '\n' || c == '\r') {
                    info.version = remaining[..end].to_string();
                }
            }
        }

        if port == 5432 {
            // PostgreSQL
            info.product = "PostgreSQL".to_string();
        }

        if port == 1433 {
            // MSSQL
            info.product = "Microsoft SQL Server".to_string();
        }

        if port == 6379 {
            // Redis
            if banner.contains("PONG") {
                info.product = "Redis".to_string();
            }
        }

        if port == 9200 {
            // Elasticsearch
            info.product = "Elasticsearch".to_string();
            // 尝试从JSON响应中提取版本
            if let Some(pos) = banner.find("\"number\" : \"") {
                let remaining = &banner[pos + 12..];
                if let Some(end) = remaining.find('"') {
                    info.version = remaining[..end].to_string();
                }
            }
        }

        if port == 27017 {
            // MongoDB
            info.product = "MongoDB".to_string();
        }

        // VNC
        if port == 5900 {
            if banner_lower.contains("rfb") {
                info.product = "VNC".to_string();
                info.version = banner.split_whitespace().nth(1).unwrap_or("").to_string();
            }
        }

        // RDP
        if port == 3389 {
            info.product = "Microsoft RDP".to_string();
        }
    }

    /// 批量识别多个端口的服务
    pub async fn identify_batch(&self, ip: IpAddr, ports: Vec<u16>) -> Vec<(u16, Option<ServiceInfo>)> {
        let mut results = Vec::new();

        for port in ports {
            let info = self.identify_service_async(ip, port).await;
            results.push((port, info));
        }

        results
    }
}

impl Default for ServiceIdentifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_identifier_creation() {
        let identifier = ServiceIdentifier::new();
        assert_eq!(identifier.connect_timeout.as_millis(), 1000);
    }

    #[test]
    fn test_with_timeout() {
        let identifier = ServiceIdentifier::new()
            .with_timeout(500, 2000);
        assert_eq!(identifier.connect_timeout.as_millis(), 500);
        assert_eq!(identifier.banner_timeout.as_millis(), 2000);
    }

    #[test]
    fn test_guess_service_by_port() {
        assert_eq!(ServiceIdentifier::guess_service_by_port(80), Some("http".to_string()));
        assert_eq!(ServiceIdentifier::guess_service_by_port(443), Some("https".to_string()));
        assert_eq!(ServiceIdentifier::guess_service_by_port(22), Some("ssh".to_string()));
        assert_eq!(ServiceIdentifier::guess_service_by_port(99999), None);
    }

    #[test]
    fn test_get_probe_data() {
        assert_eq!(ServiceIdentifier::get_probe_data(80), "GET / HTTP/1.0\r\n\r\n");
        assert_eq!(ServiceIdentifier::get_probe_data(22), "");
        assert_eq!(ServiceIdentifier::get_probe_data(6379), "*1\r\n$4\r\nPING\r\n");
    }
}
