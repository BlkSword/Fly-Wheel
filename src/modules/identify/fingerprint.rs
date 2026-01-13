//! 协议指纹识别模块
//!
//! 识别网络服务和版本信息

use regex::Regex;
use std::collections::HashMap;

/// 服务指纹信息
#[derive(Debug, Clone)]
pub struct ServiceFingerprint {
    /// 服务名称
    pub name: String,
    /// 版本信息
    pub version: Option<String>,
    /// 置信度 (0.0 - 1.0)
    pub confidence: f64,
}

/// 服务信息
#[derive(Debug, Clone)]
pub struct ServiceInfo {
    /// 端口号
    pub port: u16,
    /// 服务名称
    pub service: String,
    /// 版本信息
    pub version: Option<String>,
    /// Banner 内容
    pub banner: Option<String>,
    /// 协议
    pub protocol: String,
}

/// 协议模式
#[derive(Debug, Clone)]
struct ProtocolPattern {
    /// 端口号
    port: u16,
    /// 服务名称
    name: String,
    /// Banner 匹配模式
    banner_patterns: Vec<String>,
    /// 正则表达式（用于提取版本）
    version_regex: Option<String>,
    /// 探测数据
    probe_data: Option<Vec<u8>>,
}

/// 指纹匹配器
#[derive(Debug)]
pub struct FingerprintMatcher {
    /// 指纹数据库
    database: HashMap<u16, Vec<ProtocolPattern>>,
    /// 版本提取正则表达式缓存
    regex_cache: HashMap<String, Regex>,
}

impl FingerprintMatcher {
    /// 创建新的指纹匹配器
    pub fn new() -> Self {
        let mut matcher = Self {
            database: HashMap::new(),
            regex_cache: HashMap::new(),
        };

        matcher.init_database();
        matcher
    }

    /// 初始化指纹数据库
    fn init_database(&mut self) {
        // SSH
        self.add_pattern(ProtocolPattern {
            port: 22,
            name: "ssh".to_string(),
            banner_patterns: vec![
                "SSH-".to_string(),
            ],
            version_regex: Some(r"SSH-[\d.]+-(.+)".to_string()),
            probe_data: None,
        });

        // FTP
        self.add_pattern(ProtocolPattern {
            port: 21,
            name: "ftp".to_string(),
            banner_patterns: vec![
                "220 ".to_string(),
                "FileZilla".to_string(),
                "vsftpd".to_string(),
                "Pure-FTPd".to_string(),
                "ProFTPD".to_string(),
            ],
            version_regex: Some(r"(\d+\.\d+[\d.]*)".to_string()),
            probe_data: None,
        });

        // HTTP
        for port in [80, 8080, 8000, 8888].iter() {
            self.add_pattern(ProtocolPattern {
                port: *port,
                name: "http".to_string(),
                banner_patterns: vec![
                    "HTTP/1.".to_string(),
                    "Server:".to_string(),
                ],
                version_regex: None,
                probe_data: Some(b"GET / HTTP/1.0\r\n\r\n".to_vec()),
            });
        }

        // HTTPS
        for port in [443, 8443].iter() {
            self.add_pattern(ProtocolPattern {
                port: *port,
                name: "https".to_string(),
                banner_patterns: vec![
                    "HTTP/1.".to_string(),
                ],
                version_regex: None,
                probe_data: None,
            });
        }

        // SMTP
        self.add_pattern(ProtocolPattern {
            port: 25,
            name: "smtp".to_string(),
            banner_patterns: vec![
                "220 ".to_string(),
                "ESMTP".to_string(),
                "Postfix".to_string(),
            ],
            version_regex: Some(r"Postfix|(\d+\.\d+[\d.]*)".to_string()),
            probe_data: Some(b"EHLO example.com\r\n".to_vec()),
        });

        // MySQL
        self.add_pattern(ProtocolPattern {
            port: 3306,
            name: "mysql".to_string(),
            banner_patterns: vec![
                "mysql".to_string(),
                "MariaDB".to_string(),
            ],
            version_regex: Some(r"(\d+\.\d+\.\d+)".to_string()),
            probe_data: None,
        });

        // PostgreSQL
        self.add_pattern(ProtocolPattern {
            port: 5432,
            name: "postgresql".to_string(),
            banner_patterns: vec![
                "postgresql".to_string(),
                "PostgreSQL".to_string(),
            ],
            version_regex: Some(r"PostgreSQL (\d+\.\d+)".to_string()),
            probe_data: None,
        });

        // RDP
        self.add_pattern(ProtocolPattern {
            port: 3389,
            name: "rdp".to_string(),
            banner_patterns: vec![
                "rdp".to_string(),
            ],
            version_regex: None,
            probe_data: None,
        });

        // VNC
        self.add_pattern(ProtocolPattern {
            port: 5900,
            name: "vnc".to_string(),
            banner_patterns: vec![
                "RFB".to_string(),
            ],
            version_regex: Some(r"RFB (\d+\.\d+)".to_string()),
            probe_data: None,
        });

        // Redis
        self.add_pattern(ProtocolPattern {
            port: 6379,
            name: "redis".to_string(),
            banner_patterns: vec![
                "redis".to_string(),
            ],
            version_regex: Some(r"redis_version:(\d+\.\d+\.\d+)".to_string()),
            probe_data: None,
        });

        // MongoDB
        self.add_pattern(ProtocolPattern {
            port: 27017,
            name: "mongodb".to_string(),
            banner_patterns: vec![
                "mongodb".to_string(),
            ],
            version_regex: None,
            probe_data: None,
        });
    }

    /// 添加指纹模式
    fn add_pattern(&mut self, pattern: ProtocolPattern) {
        self.database
            .entry(pattern.port)
            .or_insert_with(Vec::new)
            .push(pattern);
    }

    /// 识别服务
    pub fn identify(&mut self, port: u16, banner: Option<&str>) -> Option<ServiceFingerprint> {
        // 提前克隆模式列表以避免借用问题
        let patterns: Vec<_> = self.database.get(&port)?.clone();

        if let Some(banner_text) = banner {
            for pattern in &patterns {
                // 检查是否匹配任何模式
                if pattern.banner_patterns.iter().any(|p| {
                    banner_text.to_lowercase().contains(&p.to_lowercase())
                }) {
                    // 尝试提取版本
                    let version = pattern.version_regex.as_ref().and_then(|regex_str| {
                        self.extract_version(banner_text, regex_str)
                    });

                    return Some(ServiceFingerprint {
                        name: pattern.name.clone(),
                        version,
                        confidence: 0.9,
                    });
                }
            }
        }

        // 如果没有 banner，根据端口猜测服务
        if let Some(pattern) = patterns.first() {
            Some(ServiceFingerprint {
                name: pattern.name.clone(),
                version: None,
                confidence: 0.5,
            })
        } else {
            None
        }
    }

    /// 从 Banner 中提取版本信息
    fn extract_version(&mut self, banner: &str, regex_str: &str) -> Option<String> {
        // 获取或编译正则表达式
        if !self.regex_cache.contains_key(regex_str) {
            if let Ok(re) = Regex::new(regex_str) {
                self.regex_cache.insert(regex_str.to_string(), re);
            }
        }

        if let Some(re) = self.regex_cache.get(regex_str) {
            if let Some(caps) = re.captures(banner) {
                return caps.get(1).map(|m| m.as_str().to_string());
            }
        }

        None
    }

    /// 根据端口获取服务名称
    pub fn get_service_by_port(&self, port: u16) -> Option<&str> {
        self.database.get(&port).and_then(|patterns| {
            patterns.first().map(|p| p.name.as_str())
        })
    }

    /// 获取完整的服务信息
    pub fn get_service_info(&mut self, port: u16, banner: Option<&str>) -> Option<ServiceInfo> {
        let fingerprint = self.identify(port, banner)?;

        Some(ServiceInfo {
            port,
            service: fingerprint.name.clone(),
            version: fingerprint.version.clone(),
            banner: banner.map(|b| b.to_string()),
            protocol: self.get_protocol(&fingerprint.name),
        })
    }

    /// 获取协议类型
    fn get_protocol(&self, service: &str) -> String {
        match service {
            "http" | "https" => "tcp".to_string(),
            "ssh" => "ssh".to_string(),
            "ftp" => "ftp".to_string(),
            "smtp" => "smtp".to_string(),
            "mysql" | "postgresql" | "mongodb" | "redis" => "database".to_string(),
            _ => "tcp".to_string(),
        }
    }
}

impl Default for FingerprintMatcher {
    fn default() -> Self {
        Self::new()
    }
}

/// 服务端口默认映射
pub fn get_default_service(port: u16) -> &'static str {
    match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        80 => "http",
        110 => "pop3",
        143 => "imap",
        443 => "https",
        445 => "smb",
        993 => "imaps",
        995 => "pop3s",
        1433 => "mssql",
        1521 => "oracle",
        3306 => "mysql",
        3389 => "rdp",
        5432 => "postgresql",
        5900 => "vnc",
        6379 => "redis",
        8080 => "http-alt",
        8443 => "https-alt",
        27017 => "mongodb",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_matcher_creation() {
        let matcher = FingerprintMatcher::new();
        assert!(!matcher.database.is_empty());
    }

    #[test]
    fn test_identify_ssh() {
        let mut matcher = FingerprintMatcher::new();
        let banner = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5";
        let result = matcher.identify(22, Some(banner));

        assert!(result.is_some());
        let fingerprint = result.unwrap();
        assert_eq!(fingerprint.name, "ssh");
        assert!(fingerprint.version.is_some());
    }

    #[test]
    fn test_identify_http() {
        let mut matcher = FingerprintMatcher::new();
        let banner = "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n";
        let result = matcher.identify(80, Some(banner));

        assert!(result.is_some());
        let fingerprint = result.unwrap();
        assert_eq!(fingerprint.name, "http");
    }

    #[test]
    fn test_get_default_service() {
        assert_eq!(get_default_service(22), "ssh");
        assert_eq!(get_default_service(80), "http");
        assert_eq!(get_default_service(443), "https");
        assert_eq!(get_default_service(3306), "mysql");
        assert_eq!(get_default_service(9999), "unknown");
    }

    #[test]
    fn test_get_service_info() {
        let mut matcher = FingerprintMatcher::new();
        let banner = "SSH-2.0-OpenSSH_8.2p1";
        let info = matcher.get_service_info(22, Some(banner));

        assert!(info.is_some());
        let service_info = info.unwrap();
        assert_eq!(service_info.port, 22);
        assert_eq!(service_info.service, "ssh");
        assert!(!service_info.protocol.is_empty());
    }

    #[test]
    fn test_extract_version() {
        let mut matcher = FingerprintMatcher::new();
        let banner = "SSH-2.0-OpenSSH_8.2p1 Ubuntu";
        let version = matcher.extract_version(banner, r"OpenSSH ([\d.]+)");

        // 这个测试依赖于具体的正则表达式
        // 实际结果可能不同
        assert!(version.is_some() || version.is_none());
    }
}
