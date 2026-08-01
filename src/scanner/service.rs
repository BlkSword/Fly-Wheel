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
        if !probe_data.is_empty()
            && timeout(
                self.banner_timeout,
                tokio::io::AsyncWriteExt::write_all(&mut stream, probe_data.as_bytes()),
            )
            .await
            .is_err()
        {
            // 写入失败，继续尝试读取
        }

        // 读取响应
        let mut buffer = vec![0u8; 4096];
        let n = match timeout(
            self.banner_timeout,
            tokio::io::AsyncReadExt::read(&mut stream, &mut buffer),
        )
        .await
        {
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
            80 | 8080 | 8000 | 8888 => "GET / HTTP/1.0\r\nHost: \r\n\r\n",
            443 | 8443 => "GET / HTTP/1.0\r\nHost: \r\n\r\n",
            // FTP — 服务器主动发送 banner，无需探测数据
            21 => "",
            // SSH — 服务器主动发送 banner
            22 => "",
            // SMTP — 服务器主动发送 banner
            25 | 587 => "",
            // POP3 — 服务器主动发送 banner
            110 => "",
            // IMAP — 服务器主动发送 banner
            143 => "",
            // Telnet
            23 => "\r\n",
            // DNS
            53 => "",
            // LDAP — 发送搜索请求
            389 => "",
            // SMB — 服务器主动发送 negotiate response
            445 => "",
            // VNC — 服务器主动发送 RFB 版本
            5900 => "",
            // MySQL — 服务器主动发送 handshake
            3306 => "",
            // PostgreSQL — 服务器主动发送 handshake
            5432 => "",
            // Redis
            6379 => "*1\r\n$4\r\nPING\r\n",
            // MongoDB — 发送 ismaster 命令
            27017 => "",
            // Elasticsearch
            9200 => "GET / HTTP/1.0\r\nHost: \r\n\r\n",
            // RDP — 服务器主动发送 X.224
            3389 => "",
            // MSSQL — 服务器主动发送 prelogin response
            1433 => "",
            // WinRM
            5985 | 5986 => "",
            // Oracle
            1521 => "",
            // RPC
            135 => "",
            // NetBIOS
            139 => "",
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

        services
            .iter()
            .find(|(p, _)| *p == port)
            .map(|(_, name)| name.to_string())
    }

    /// 从Banner中解析版本信息
    fn parse_version_info(info: &mut ServiceInfo, banner: &str, port: u16) {
        let banner_lower = banner.to_lowercase();

        // 通用: 检查所有 HTTP 端口的 Server 头
        let http_ports = [80, 443, 8080, 8000, 8443, 8888, 9200];
        if http_ports.contains(&port) {
            Self::parse_http_banner(info, banner, &banner_lower);
        }

        // SSH服务
        if port == 22 {
            Self::parse_ssh_banner(info, banner, &banner_lower);
        }

        // FTP服务
        if port == 21 {
            Self::parse_ftp_banner(info, banner, &banner_lower);
        }

        // SMTP服务
        if port == 25 || port == 587 {
            Self::parse_smtp_banner(info, banner, &banner_lower);
        }

        // POP3
        if port == 110 && (banner_lower.contains("pop3") || banner.starts_with('+')) {
            info.product = "POP3".to_string();
            if banner_lower.contains("dovecot") {
                info.product = "Dovecot POP3".to_string();
            } else if banner_lower.contains("courier") {
                info.product = "Courier POP3".to_string();
            } else if banner_lower.contains("exchange") {
                info.product = "Microsoft Exchange POP3".to_string();
            }
        }

        // IMAP
        if port == 143 && (banner_lower.contains("imap") || banner.starts_with('*')) {
            info.product = "IMAP".to_string();
            if banner_lower.contains("dovecot") {
                info.product = "Dovecot IMAP".to_string();
            } else if banner_lower.contains("courier") {
                info.product = "Courier IMAP".to_string();
            } else if banner_lower.contains("exchange") {
                info.product = "Microsoft Exchange IMAP".to_string();
            }
            // 提取版本号
            if let Some(pos) = banner.find("IMAP4rev1 ") {
                let remaining = &banner[pos + 10..];
                info.version = remaining
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .to_string();
            }
        }

        // 数据库服务
        if port == 3306 {
            Self::parse_mysql_banner(info, banner, &banner_lower);
        }

        if port == 5432 {
            info.product = "PostgreSQL".to_string();
            // PostgreSQL 不发送可读 banner，尝试从二进制中检测
        }

        if port == 1433 {
            info.product = "Microsoft SQL Server".to_string();
        }

        if port == 6379 {
            if banner.contains("PONG") {
                info.product = "Redis".to_string();
            } else if banner.contains("-NOAUTH") {
                info.product = "Redis".to_string();
                info.extra_info = "需要认证".to_string();
            } else if banner.contains("-DENIED") {
                info.product = "Redis".to_string();
                info.extra_info = "访问被拒绝".to_string();
            }
        }

        if port == 27017 {
            info.product = "MongoDB".to_string();
            // 尝试从响应中提取版本信息
            if let Some(pos) = banner.find("\"version\" : \"") {
                let remaining = &banner[pos + 12..];
                if let Some(end) = remaining.find('"') {
                    info.version = remaining[..end].to_string();
                }
            } else if let Some(pos) = banner.find("\"version\":\"") {
                let remaining = &banner[pos + 11..];
                if let Some(end) = remaining.find('"') {
                    info.version = remaining[..end].to_string();
                }
            }
        }

        // VNC
        if port == 5900 && banner_lower.contains("rfb") {
            info.product = "VNC".to_string();
            // RFB 协议版本: RFB 003.008
            if let Some(pos) = banner.find("RFB ") {
                let remaining = &banner[pos + 4..];
                info.version = remaining
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .to_string();
            }
        }

        // RDP
        if port == 3389 {
            info.product = "Microsoft RDP".to_string();
            // RDP 通常不发送可读文本 banner
        }

        // LDAP
        if port == 389 {
            info.product = "LDAP".to_string();
            if banner_lower.contains("microsoft") {
                info.product = "Active Directory LDAP".to_string();
            } else if banner_lower.contains("openldap") {
                info.product = "OpenLDAP".to_string();
            }
        }

        // LDAPS
        if port == 636 {
            info.product = "LDAPS".to_string();
        }

        // SMB
        if port == 445 {
            info.product = "SMB".to_string();
            if banner_lower.contains("windows") {
                info.product = "Windows SMB".to_string();
            } else if banner_lower.contains("samba") {
                info.product = "Samba".to_string();
                if let Some(pos) = banner_lower.find("samba ") {
                    let remaining = &banner[pos + 6..];
                    info.version = remaining
                        .split_whitespace()
                        .next()
                        .unwrap_or("")
                        .to_string();
                }
            }
        }

        // WinRM
        if port == 5985 || port == 5986 {
            info.product = "WinRM".to_string();
            if banner.contains("WSMAN") || banner.contains("wsman") {
                info.version = "2.0".to_string();
            }
        }

        // Oracle
        if port == 1521 {
            info.product = "Oracle TNS".to_string();
        }

        // MSSQL
        if port == 1433 {
            info.product = "Microsoft SQL Server".to_string();
            // TDS 协议预登录响应包含版本信息
        }

        // DNS
        if port == 53 {
            info.product = "DNS".to_string();
            if banner_lower.contains("bind") {
                info.product = "BIND DNS".to_string();
            }
        }

        // 通用 Telnet 检测
        if port == 23 && banner_lower.contains("login:") {
            info.product = "Telnet".to_string();
        }
    }

    /// 解析 HTTP Banner
    fn parse_http_banner(info: &mut ServiceInfo, banner: &str, banner_lower: &str) {
        // 提取状态行
        if let Some(line) = banner.lines().next() {
            if line.starts_with("HTTP/") {
                info.version = line.to_string();
            }
        }

        // 查找 Server 头
        for line in banner.lines() {
            if line.to_lowercase().starts_with("server:") {
                let server_value = line.split(':').nth(1).unwrap_or("").trim();
                info.product = server_value.to_string();

                // 进一步识别具体服务器
                if banner_lower.contains("nginx") {
                    info.product = "nginx".to_string();
                    Self::extract_version_after(info, banner_lower, "nginx/");
                } else if banner_lower.contains("apache") || banner_lower.contains("httpd") {
                    info.product = "Apache".to_string();
                    Self::extract_version_after(info, banner_lower, "apache/");
                } else if banner_lower.contains("iis") {
                    info.product = "Microsoft IIS".to_string();
                } else if banner_lower.contains("tomcat") {
                    info.product = "Apache Tomcat".to_string();
                } else if banner_lower.contains("jetty") {
                    info.product = "Jetty".to_string();
                } else if banner_lower.contains("express") {
                    info.product = "Express".to_string();
                } else if banner_lower.contains("gunicorn") {
                    info.product = "Gunicorn".to_string();
                } else if banner_lower.contains("openresty") {
                    info.product = "OpenResty".to_string();
                    Self::extract_version_after(info, banner_lower, "openresty/");
                }
                break;
            }
        }
    }

    /// 从字符串中提取 "prefix" 之后的版本号
    fn extract_version_after(info: &mut ServiceInfo, text: &str, prefix: &str) {
        if let Some(pos) = text.find(prefix) {
            let remaining = &text[pos + prefix.len()..];
            let end = remaining
                .find(|c: char| !c.is_numeric() && c != '.')
                .unwrap_or(remaining.len());
            if end > 0 {
                info.version = remaining[..end].to_string();
            }
        }
    }

    /// 解析 SSH Banner
    fn parse_ssh_banner(info: &mut ServiceInfo, banner: &str, _banner_lower: &str) {
        if banner.contains("SSH-") {
            info.product = "SSH".to_string();
            if let Some(pos) = banner.find("SSH-") {
                let remaining = &banner[pos + 4..];
                // SSH-2.0-OpenSSH_8.9p1 Ubuntu-3
                if let Some(ver_end) = remaining.find('-') {
                    info.version = remaining[..ver_end].to_string();
                    let server_info = &remaining[ver_end + 1..];
                    let server_name = server_info.split_whitespace().next().unwrap_or("");

                    if server_name.to_lowercase().starts_with("openssh") {
                        info.product = "OpenSSH".to_string();
                        if let Some(vpos) = server_name.find('_') {
                            info.version =
                                format!("SSH-{} {}", info.version, &server_name[vpos + 1..]);
                        }
                    } else if server_name.to_lowercase().starts_with("dropbear") {
                        info.product = "Dropbear SSH".to_string();
                    } else if server_name.to_lowercase().starts_with("libssh") {
                        info.product = "libssh".to_string();
                    }
                }
            }
        }
    }

    /// 解析 FTP Banner
    fn parse_ftp_banner(info: &mut ServiceInfo, banner: &str, banner_lower: &str) {
        // FTP banner 格式: 220 <server info>
        if banner.starts_with("220") {
            let server_info = banner.trim_start_matches("220").trim();
            info.extra_info = server_info.to_string();
        }

        if banner_lower.contains("vsftpd") {
            info.product = "vsftpd".to_string();
            Self::extract_version_after(info, banner_lower, "vsftpd ");
        } else if banner_lower.contains("proftpd") {
            info.product = "ProFTPD".to_string();
            Self::extract_version_after(info, banner_lower, "proftpd ");
        } else if banner_lower.contains("pure-ftpd") {
            info.product = "Pure-FTPd".to_string();
        } else if banner_lower.contains("filezilla") {
            info.product = "FileZilla Server".to_string();
        } else if banner_lower.contains("microsoft") {
            info.product = "Microsoft FTP".to_string();
        } else if banner_lower.contains("wu-ftpd") || banner_lower.contains("wu-ftp") {
            info.product = "WU-FTPD".to_string();
        }
    }

    /// 解析 SMTP Banner
    fn parse_smtp_banner(info: &mut ServiceInfo, banner: &str, banner_lower: &str) {
        // SMTP banner 格式: 220 <server info>
        if banner.starts_with("220") {
            let server_info = banner.trim_start_matches("220").trim();
            info.extra_info = server_info.to_string();
        }

        if banner_lower.contains("postfix") {
            info.product = "Postfix".to_string();
        } else if banner_lower.contains("sendmail") {
            info.product = "Sendmail".to_string();
        } else if banner_lower.contains("exim") {
            info.product = "Exim".to_string();
            Self::extract_version_after(info, banner_lower, "exim ");
        } else if banner_lower.contains("exchange") {
            info.product = "Microsoft Exchange".to_string();
        } else if banner_lower.contains("hmailserver") {
            info.product = "hMailServer".to_string();
        }
    }

    /// 解析 MySQL Banner
    fn parse_mysql_banner(info: &mut ServiceInfo, _banner: &str, banner_lower: &str) {
        info.product = "MySQL".to_string();
        // MySQL 服务器握手包是二进制的，但有些版本信息可能在文本中
        for ver_prefix in &[
            "5.0", "5.1", "5.5", "5.6", "5.7", "8.0", "8.1", "8.2", "8.3", "8.4",
        ] {
            if let Some(pos) = banner_lower.find(*ver_prefix) {
                let remaining = &banner_lower[pos..];
                if let Some(end) = remaining.find(['\n', '\r', '\0']) {
                    info.version = remaining[..end].to_string();
                } else {
                    info.version = remaining.to_string();
                }
                break;
            }
        }

        if banner_lower.contains("mariadb") {
            info.product = "MariaDB".to_string();
        } else if banner_lower.contains("percona") {
            info.product = "Percona Server".to_string();
        }
    }

    /// 批量识别多个端口的服务（并行探测）
    pub async fn identify_batch(
        &self,
        ip: IpAddr,
        ports: Vec<u16>,
    ) -> Vec<(u16, Option<ServiceInfo>)> {
        let probes: Vec<_> = ports
            .into_iter()
            .map(|port| async move {
                let info = self.identify_service_async(ip, port).await;
                (port, info)
            })
            .collect();

        futures::future::join_all(probes).await
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
        let identifier = ServiceIdentifier::new().with_timeout(500, 2000);
        assert_eq!(identifier.connect_timeout.as_millis(), 500);
        assert_eq!(identifier.banner_timeout.as_millis(), 2000);
    }

    #[test]
    fn test_guess_service_by_port() {
        assert_eq!(
            ServiceIdentifier::guess_service_by_port(80),
            Some("http".to_string())
        );
        assert_eq!(
            ServiceIdentifier::guess_service_by_port(443),
            Some("https".to_string())
        );
        assert_eq!(
            ServiceIdentifier::guess_service_by_port(22),
            Some("ssh".to_string())
        );
        assert_eq!(ServiceIdentifier::guess_service_by_port(0), None);
    }

    #[test]
    fn test_get_probe_data() {
        assert_eq!(
            ServiceIdentifier::get_probe_data(80),
            "GET / HTTP/1.0\r\nHost: \r\n\r\n"
        );
        assert_eq!(ServiceIdentifier::get_probe_data(22), "");
        assert_eq!(
            ServiceIdentifier::get_probe_data(6379),
            "*1\r\n$4\r\nPING\r\n"
        );
    }
}
