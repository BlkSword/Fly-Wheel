//! DNS 隧道模块
//!
//! 基于 DNS 查询的数据隧道，适用于极度受限的出站网络环境。
//! 通过将数据编码为 DNS 子域名查询来绕过仅开放 DNS 出站的防火墙。
//!
//! 协议设计：
//! - 编码: Base32 编码二进制数据为 DNS 安全字符集
//! - 分片: 长数据拆分为多段 DNS 查询（每段最多 63 字符标签）
//! - 会话: 使用 TXT/CNAME/AAAA 响应携带反向数据
//! - 心跳: 定期 NULL 查询保持会话

/// DNS 隧道编码器 — 将数据编码/解码为 DNS 安全域名标签
pub struct DnsEncoder {
    /// 域名后缀（如 tunnel.example.com）
    pub domain: String,
    /// 会话 ID（区分不同隧道实例）
    pub session_id: u32,
}

impl DnsEncoder {
    /// 创建新的 DNS 编码器
    pub fn new(domain: &str, session_id: u32) -> Self {
        Self {
            domain: domain.to_string(),
            session_id,
        }
    }

    /// 将数据编码为 DNS 查询域名列表
    ///
    /// 格式: `<seq>.<session>.<payload>.<domain>`
    /// 每段标签最大 63 字符，使用 Base32 编码
    pub fn encode(&self, data: &[u8], seq: u16) -> Vec<String> {
        let encoded = base32_encode(data);
        let mut queries = Vec::new();

        // 分片：每段最多 50 字符 payload（留空间给 seq+session）
        for chunk in encoded.as_bytes().chunks(50) {
            let chunk_str = String::from_utf8_lossy(chunk);
            let query = format!(
                "{:04x}.{:08x}.{}.{}",
                seq, self.session_id, chunk_str, self.domain
            );
            queries.push(query);
        }

        queries
    }

    /// 从 DNS 查询域名解码数据
    pub fn decode_query(&self, query: &str) -> Option<(u16, Vec<u8>)> {
        // 解析格式: <seq>.<session>.<payload>.<domain>
        let prefix = query.strip_suffix(&format!(".{}", self.domain))?;
        let parts: Vec<&str> = prefix.rsplitn(3, '.').collect();
        if parts.len() < 3 {
            return None;
        }

        let _payload = parts[0]; // Base32 payload
        let _session_hex = parts[1];
        let _seq_hex = parts[2];

        // Parse session ID
        let _sid = u32::from_str_radix(_session_hex, 16).ok()?;

        // Parse sequence number
        let seq = u16::from_str_radix(_seq_hex, 16).ok()?;

        // Decode payload
        let decoded = base32_decode(_payload)?;

        Some((seq, decoded))
    }

    /// 创建心跳查询域名
    pub fn heartbeat_query(&self) -> String {
        format!("ping.{:08x}.{}", self.session_id, self.domain)
    }

    /// 判断是否为心跳查询
    pub fn is_heartbeat(query: &str) -> bool {
        query.starts_with("ping.")
    }
}

/// Base32 编码（RFC 4648，URL 安全字符集，无填充）
fn base32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut result = String::new();
    let mut buffer = 0u32;
    let mut bits = 0u32;

    for &byte in data {
        buffer = (buffer << 8) | byte as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1F) as usize;
            result.push(ALPHABET[idx] as char);
        }
    }

    // 剩余位
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1F) as usize;
        result.push(ALPHABET[idx] as char);
    }

    result
}

/// Base32 解码
fn base32_decode(encoded: &str) -> Option<Vec<u8>> {
    let mut result = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0u32;

    for c in encoded.chars() {
        let value = match c.to_ascii_lowercase() {
            'a'..='z' => (c as u8 - b'a') as u32,
            '2'..='7' => (c as u8 - b'2' + 26) as u32,
            _ => return None,
        };

        buffer = (buffer << 5) | value;
        bits += 5;

        while bits >= 8 {
            bits -= 8;
            result.push(((buffer >> bits) & 0xFF) as u8);
        }
    }

    // 舍去填充位
    Some(result)
}

/// 生成唯一的 DNS 隧道会话 ID
pub fn generate_session_id() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base32_encode_empty() {
        assert_eq!(base32_encode(b""), "");
    }

    #[test]
    fn test_base32_encode_hello() {
        // "hello" in Base32 = "nbswy3dp"
        let encoded = base32_encode(b"hello");
        assert_eq!(encoded, "nbswy3dp");
    }

    #[test]
    fn test_base32_roundtrip_simple() {
        let data = b"hello world";
        let encoded = base32_encode(data);
        let decoded = base32_decode(&encoded).expect("解码应成功");
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_base32_roundtrip_binary() {
        let data: Vec<u8> = (0..64).collect(); // 0..63
        let encoded = base32_encode(&data);
        let decoded = base32_decode(&encoded).expect("解码应成功");
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_base32_roundtrip_single_byte() {
        let data = b"\xff";
        let encoded = base32_encode(data);
        let decoded = base32_decode(&encoded).expect("解码应成功");
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_base32_decode_invalid() {
        assert!(base32_decode("!!!").is_none());
    }

    #[test]
    fn test_dns_encoder_basic() {
        let encoder = DnsEncoder::new("tunnel.example.com", 0x12345678);
        let queries = encoder.encode(b"test", 1);

        assert!(!queries.is_empty());
        for q in &queries {
            assert!(q.ends_with(".tunnel.example.com"));
            assert!(q.contains("0001.")); // seq=1 → "0001"
            assert!(q.contains("12345678.")); // session
        }
    }

    #[test]
    fn test_dns_encoder_large_data() {
        let encoder = DnsEncoder::new("t.example.com", 1);
        let data = vec![0x41u8; 200]; // 200 字节
        let queries = encoder.encode(&data, 0);

        // 大数据应分片为多个查询
        assert!(queries.len() >= 2);
        for q in &queries {
            assert!(q.ends_with(".t.example.com"));
        }
    }

    #[test]
    fn test_dns_heartbeat() {
        let encoder = DnsEncoder::new("tunnel.example.com", 0xDEADBEEF);
        let hb = encoder.heartbeat_query();
        assert!(DnsEncoder::is_heartbeat(&hb));
        assert!(hb.contains("deadbeef"));
    }

    #[test]
    fn test_generate_session_id() {
        let id1 = generate_session_id();
        let id2 = generate_session_id();
        assert!(id1 > 0);
        assert_eq!(id1, id2); // 在同一秒内应相同
    }
}
