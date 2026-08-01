//! WinRM 爆破模块
//!
//! 支持 Basic 和 NTLM 两种认证方式

use async_trait::async_trait;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::cracker::base;
use crate::cracker::ntlm;
use crate::cracker::service::{CrackConfig, CrackResult, CrackService, Cracker};

/// WinRM SOAP 请求体
const WINRM_SOAP_BODY: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd">
  <s:Body>
    <wsmid:Identify/>
  </s:Body>
</s:Envelope>"#;

/// WinRM 爆破器
pub struct WinrmCracker;

impl WinrmCracker {
    pub fn new() -> Self {
        Self
    }
}

impl Default for WinrmCracker {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Cracker for WinrmCracker {
    async fn crack(&self, config: &CrackConfig) -> CrackResult {
        base::run_crack(
            config,
            CrackService::Winrm,
            "WinRM (HTTP)",
            |username, password, target, port, timeout| {
                let username = username.unwrap_or_else(|| "Administrator".to_string());
                Self::try_connect_sync(&target, port, &username, &password, timeout)
            },
        )
        .await
    }

    async fn verify(
        &self,
        target: &str,
        port: u16,
        username: Option<&str>,
        password: &str,
    ) -> bool {
        let username = username.unwrap_or("Administrator");
        Self::try_connect_sync(target, port, username, password, Duration::from_secs(10))
    }
}

impl WinrmCracker {
    /// 尝试连接 WinRM 服务并认证
    fn try_connect_sync(
        target: &str,
        port: u16,
        username: &str,
        password: &str,
        timeout: Duration,
    ) -> bool {
        // 先尝试 Basic 认证
        if Self::try_winrm_basic(target, port, username, password, timeout) {
            return true;
        }
        // 回退到 NTLM 认证
        Self::try_winrm_ntlm(target, port, username, password, timeout)
    }

    /// WinRM Basic 认证
    fn try_winrm_basic(
        target: &str,
        port: u16,
        username: &str,
        password: &str,
        timeout: Duration,
    ) -> bool {
        let addr = format!("{}:{}", target, port);

        let socket_addrs = match addr.to_socket_addrs() {
            Ok(addrs) => addrs,
            Err(_) => return false,
        };

        for sockaddr in socket_addrs {
            let mut stream = match TcpStream::connect_timeout(&sockaddr, timeout) {
                Ok(s) => s,
                Err(_) => continue,
            };

            if stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .is_err()
                || stream
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .is_err()
            {
                continue;
            }

            // 构造 Basic 认证头
            let credentials = base64_encode(format!("{}:{}", username, password));
            let request = format!(
                "POST /wsman HTTP/1.1\r\n\
                 Host: {}:{}\r\n\
                 Content-Type: application/soap+xml;charset=UTF-8\r\n\
                 Authorization: Basic {}\r\n\
                 Content-Length: {}\r\n\
                 \r\n\
                 {}",
                target,
                port,
                credentials,
                WINRM_SOAP_BODY.len(),
                WINRM_SOAP_BODY
            );

            if stream.write_all(request.as_bytes()).is_err() {
                continue;
            }

            // 读取响应
            let mut buffer = [0u8; 4096];
            match stream.read(&mut buffer) {
                Ok(n) if n > 0 => {
                    let response = String::from_utf8_lossy(&buffer[..n]);
                    // HTTP 200 表示认证成功
                    if response.starts_with("HTTP/1.1 200") || response.starts_with("HTTP/1.0 200")
                    {
                        return true;
                    }
                }
                _ => {}
            }
        }

        false
    }

    /// WinRM NTLM 认证
    fn try_winrm_ntlm(
        target: &str,
        port: u16,
        username: &str,
        password: &str,
        timeout: Duration,
    ) -> bool {
        let addr = format!("{}:{}", target, port);

        let socket_addrs = match addr.to_socket_addrs() {
            Ok(addrs) => addrs,
            Err(_) => return false,
        };

        for sockaddr in socket_addrs {
            let mut stream = match TcpStream::connect_timeout(&sockaddr, timeout) {
                Ok(s) => s,
                Err(_) => continue,
            };

            if stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .is_err()
                || stream
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .is_err()
            {
                continue;
            }

            // 阶段 1: 发送初始请求获取 NTLM 挑战
            let type1 = ntlm::build_type1("WORKSTATION", "");
            let type1_b64 = base64_encode_bytes(&type1);

            let request = format!(
                "POST /wsman HTTP/1.1\r\n\
                 Host: {}:{}\r\n\
                 Content-Type: application/soap+xml;charset=UTF-8\r\n\
                 Authorization: NTLM {}\r\n\
                 Content-Length: 0\r\n\
                 \r\n",
                target, port, type1_b64
            );

            if stream.write_all(request.as_bytes()).is_err() {
                continue;
            }

            let mut buffer = [0u8; 8192];
            let n = match stream.read(&mut buffer) {
                Ok(n) if n > 0 => n,
                _ => continue,
            };

            let response = String::from_utf8_lossy(&buffer[..n]);

            // 检查 401 响应中是否包含 NTLM 挑战
            let type2_bytes = match extract_ntlm_challenge(&response) {
                Some(bytes) => bytes,
                None => continue,
            };

            // 阶段 2: 解析 Type 2 挑战
            let challenge = match ntlm::parse_type2(&type2_bytes) {
                Ok(c) => c,
                Err(_) => continue,
            };

            // 阶段 3: 计算 Type 3 响应
            let type3 = ntlm::build_type3(username, password, "", "WORKSTATION", &challenge);
            let type3_b64 = base64_encode_bytes(&type3);

            // 构造新连接（WinRM 通常要求新连接发送 Type 3）
            drop(stream);
            let mut stream2 = match TcpStream::connect_timeout(&sockaddr, timeout) {
                Ok(s) => s,
                Err(_) => continue,
            };

            if stream2
                .set_read_timeout(Some(Duration::from_secs(5)))
                .is_err()
                || stream2
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .is_err()
            {
                continue;
            }

            let auth_request = format!(
                "POST /wsman HTTP/1.1\r\n\
                 Host: {}:{}\r\n\
                 Content-Type: application/soap+xml;charset=UTF-8\r\n\
                 Authorization: NTLM {}\r\n\
                 Content-Length: {}\r\n\
                 \r\n\
                 {}",
                target,
                port,
                type3_b64,
                WINRM_SOAP_BODY.len(),
                WINRM_SOAP_BODY
            );

            if stream2.write_all(auth_request.as_bytes()).is_err() {
                continue;
            }

            let mut buffer2 = [0u8; 4096];
            match stream2.read(&mut buffer2) {
                Ok(n) if n > 0 => {
                    let response2 = String::from_utf8_lossy(&buffer2[..n]);
                    if response2.starts_with("HTTP/1.1 200")
                        || response2.starts_with("HTTP/1.0 200")
                    {
                        return true;
                    }
                }
                _ => {}
            }
        }

        false
    }

    /// 检查端口是否开放
    pub async fn check_port_open(target: &str, port: u16, timeout: Duration) -> bool {
        let target = target.to_string();

        tokio::task::spawn_blocking(move || {
            let addr = format!("{}:{}", target, port);
            match addr.to_socket_addrs() {
                Ok(addrs) => {
                    for sockaddr in addrs {
                        if TcpStream::connect_timeout(&sockaddr, timeout).is_ok() {
                            return true;
                        }
                    }
                    false
                }
                Err(_) => false,
            }
        })
        .await
        .unwrap_or(false)
    }
}

/// 从 HTTP 响应中提取 NTLM Type 2 挑战
fn extract_ntlm_challenge(response: &str) -> Option<Vec<u8>> {
    // 查找 WWW-Authenticate: NTLM 头
    for line in response.lines() {
        if line.to_lowercase().starts_with("www-authenticate:") {
            let value = line.split(':').nth(1)?;
            let value = value.trim();

            // 格式: NTLM <base64>
            if let Some(b64) = value.strip_prefix("NTLM ") {
                return base64_decode_bytes(b64);
            }
            // 有些服务器直接返回 base64
            if !value.is_empty() && value != "NTLM" {
                return base64_decode_bytes(value);
            }
        }
    }
    None
}

/// Base64 编码字符串
fn base64_encode(input: String) -> String {
    use base64::prelude::*;
    BASE64_STANDARD.encode(input.as_bytes())
}

/// Base64 编码字节
fn base64_encode_bytes(input: &[u8]) -> String {
    use base64::prelude::*;
    BASE64_STANDARD.encode(input)
}

/// Base64 解码为字节
fn base64_decode_bytes(input: &str) -> Option<Vec<u8>> {
    use base64::prelude::*;
    BASE64_STANDARD.decode(input).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_encode_decode() {
        let data = b"hello world";
        let encoded = base64_encode_bytes(data);
        let decoded = base64_decode_bytes(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_base64_encode_string() {
        let encoded = base64_encode("Administrator:password".to_string());
        let decoded = base64_decode_bytes(&encoded).unwrap();
        assert_eq!(
            String::from_utf8(decoded).unwrap(),
            "Administrator:password"
        );
    }

    #[test]
    fn test_extract_ntlm_challenge() {
        let response = "HTTP/1.1 401 Unauthorized\r\n\
                        WWW-Authenticate: NTLM TlRMTVNTUAACAAAAADAAMADgAAAA1gor4sfQ0+UZvQcAAAAAAAAAAFQAVgBMAAAAAAAA";
        let result = extract_ntlm_challenge(response);
        assert!(result.is_some());
    }

    #[test]
    fn test_extract_ntlm_challenge_no_header() {
        let response = "HTTP/1.1 200 OK\r\nContent-Length: 0";
        let result = extract_ntlm_challenge(response);
        assert!(result.is_none());
    }

    #[test]
    fn test_winrm_cracker_creation() {
        let cracker = WinrmCracker::new();
        let _ = cracker;
    }
}
