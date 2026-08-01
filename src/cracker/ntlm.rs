//! NTLMv2 认证模块
//!
//! 提供完整的 NTLMSSP 协议实现，支持 NTLMv2 响应计算。
//! RDP (CredSSP/NLA) 和 WinRM (NTLM over HTTP) 共享此模块。

use hmac::{Hmac, Mac};
use md5::Md5;

type HmacMd5 = Hmac<Md5>;

/// NTLMSSP 签名
const NTLMSSP_SIGNATURE: &[u8; 8] = b"NTLMSSP\0";

/// NTLMSSP 消息类型
const MSG_TYPE_NEGOTIATE: u32 = 1;
const MSG_TYPE_CHALLENGE: u32 = 2;
const MSG_TYPE_AUTHENTICATE: u32 = 3;

/// NTLMSSP 协商标志
const NTLMSSP_NEGOTIATE_UNICODE: u32 = 0x00000001;
const NTLMSSP_NEGOTIATE_NTLM: u32 = 0x00000200;
const NTLMSSP_NEGOTIATE_ALWAYS_SIGN: u32 = 0x00008000;
const NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY: u32 = 0x00080000;
const NTLMSSP_NEGOTIATE_128: u32 = 0x20000000;
const NTLMSSP_NEGOTIATE_56: u32 = 0x80000000;

/// NTLMSSP Type 2 Challenge 解析结果
#[derive(Debug)]
pub struct NtlmChallenge {
    /// 服务器挑战（8 字节）
    pub server_challenge: [u8; 8],
    /// 目标信息块
    pub target_info: Vec<u8>,
    /// 协商标志
    pub negotiate_flags: u32,
}

// ==================== NT Hash 计算 ====================

/// 计算 NT Hash: MD4(UTF-16LE(password))
pub fn nt_hash(password: &str) -> [u8; 16] {
    let utf16le: Vec<u8> = password
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();

    md4_hash(&utf16le)
}

/// 计算 NTLMv2 Hash: HMAC-MD5(NT_Hash, Unicode(uppercase(username) + domain))
pub fn ntlmv2_hash(nt_hash: &[u8], username: &str, domain: &str) -> [u8; 16] {
    let identity: Vec<u8> = format!("{}{}", username.to_uppercase(), domain.to_uppercase())
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();

    let mut mac = HmacMd5::new_from_slice(nt_hash).expect("HMAC key length is valid");
    mac.update(&identity);
    let result = mac.finalize().into_bytes();
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&result);
    hash
}

/// 计算 NTLMv2 响应
pub fn ntlmv2_response(ntlmv2_hash: &[u8], server_challenge: &[u8], target_info: &[u8]) -> Vec<u8> {
    // 构造 blob
    let blob = build_ntlmv2_blob(target_info);

    // NTProofStr = HMAC-MD5(NTLMv2_Hash, ServerChallenge + Blob)
    let mut mac = HmacMd5::new_from_slice(ntlmv2_hash).expect("HMAC key length is valid");
    mac.update(server_challenge);
    mac.update(&blob);
    let nt_proof_str = mac.finalize().into_bytes();

    // 响应 = NTProofStr + Blob
    let mut response = Vec::with_capacity(16 + blob.len());
    response.extend_from_slice(&nt_proof_str);
    response.extend_from_slice(&blob);
    response
}

/// 构造 NTLMv2 Blob
fn build_ntlmv2_blob(target_info: &[u8]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(32 + target_info.len());

    // Blob 签名 (0x01010000)
    blob.extend_from_slice(&[0x01, 0x01, 0x00, 0x00]);
    // 保留
    blob.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    // 时间戳 (64-bit，从 1601-01-01 起的 100ns 间隔)
    let timestamp = get_nt_timestamp();
    blob.extend_from_slice(&timestamp.to_le_bytes());

    // Client Challenge (8 字节随机数)
    let client_challenge = generate_client_challenge();
    blob.extend_from_slice(&client_challenge);

    // 保留
    blob.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    // Target Info (从 Type 2 消息中获取)
    blob.extend_from_slice(target_info);

    // 末尾 Terminator
    blob.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    blob
}

/// 获取 Windows NT 时间戳（从 1601-01-01 UTC 起的 100 纳秒间隔数）
fn get_nt_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    // Unix epoch (1970) 到 NT epoch (1601) 的间隔: 11644473600 秒
    const EPOCH_DIFF_SECS: u64 = 11644473600;

    (duration.as_secs() + EPOCH_DIFF_SECS) * 10_000_000 + duration.subsec_nanos() as u64 / 100
}

/// 生成 8 字节 Client Challenge（密码学安全随机数）
fn generate_client_challenge() -> [u8; 8] {
    use rand::RngCore;
    let mut challenge = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut challenge);
    challenge
}

// ==================== NTLMSSP 消息构建/解析 ====================

/// 构建 NTLMSSP Type 1 (Negotiate) 消息
pub fn build_type1(hostname: &str, domain: &str) -> Vec<u8> {
    let flags = NTLMSSP_NEGOTIATE_UNICODE
        | NTLMSSP_NEGOTIATE_NTLM
        | NTLMSSP_NEGOTIATE_ALWAYS_SIGN
        | NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        | NTLMSSP_NEGOTIATE_128
        | NTLMSSP_NEGOTIATE_56;

    let hostname_upper = hostname.to_uppercase();
    let domain_upper = domain.to_uppercase();

    let hostname_bytes: Vec<u8> = hostname_upper
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let domain_bytes: Vec<u8> = domain_upper
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();

    // 消息结构: 签名(8) + 类型(4) + 标志(4) + 域名安全缓冲(8) + 主机名安全缓冲(8) = 32 字节头
    // 安全缓冲格式: Len(u16) + MaxLen(u16) + Offset(u32) = 8 字节
    let header_len = 32u32;
    let domain_offset = header_len;
    let host_offset = header_len + domain_bytes.len() as u32;

    let mut msg = Vec::with_capacity(host_offset as usize + hostname_bytes.len());

    // 签名
    msg.extend_from_slice(NTLMSSP_SIGNATURE);
    // 消息类型
    msg.extend_from_slice(&MSG_TYPE_NEGOTIATE.to_le_bytes());
    // 标志
    msg.extend_from_slice(&flags.to_le_bytes());

    // 域名安全缓冲 (Len u16, MaxLen u16, Offset u32)
    msg.extend_from_slice(&(domain_bytes.len() as u16).to_le_bytes());
    msg.extend_from_slice(&(domain_bytes.len() as u16).to_le_bytes());
    msg.extend_from_slice(&domain_offset.to_le_bytes());

    // 主机名安全缓冲 (Len u16, MaxLen u16, Offset u32)
    msg.extend_from_slice(&(hostname_bytes.len() as u16).to_le_bytes());
    msg.extend_from_slice(&(hostname_bytes.len() as u16).to_le_bytes());
    msg.extend_from_slice(&host_offset.to_le_bytes());

    // 数据
    msg.extend_from_slice(&domain_bytes);
    msg.extend_from_slice(&hostname_bytes);

    msg
}

/// 解析 NTLMSSP Type 2 (Challenge) 消息
pub fn parse_type2(data: &[u8]) -> Result<NtlmChallenge, String> {
    if data.len() < 48 {
        return Err("Type 2 消息太短".to_string());
    }

    // 验证签名
    if &data[0..8] != NTLMSSP_SIGNATURE {
        return Err("无效的 NTLMSSP 签名".to_string());
    }

    // 验证消息类型
    let msg_type = u32::from_le_bytes(data[8..12].try_into().unwrap_or([0; 4]));
    if msg_type != MSG_TYPE_CHALLENGE {
        return Err(format!("期望 Type 2 消息，收到类型 {}", msg_type));
    }

    // 读取协商标志 (offset 20, 4 字节)
    // Type 2 布局: Signature(8) + MessageType(4) + TargetNameFields(8) + NegotiateFlags(4) + ServerChallenge(8) + Reserved(8) + TargetInfoFields(8)
    let negotiate_flags = u32::from_le_bytes(data[20..24].try_into().unwrap_or([0; 4]));

    // 读取服务器挑战 (offset 24, 8 字节)
    let mut server_challenge = [0u8; 8];
    server_challenge.copy_from_slice(&data[24..32]);

    // 读取 Target Info 安全缓冲 (offset 40, length at 40, offset at 44)
    let target_info = if data.len() >= 48 {
        let ti_len = u16::from_le_bytes(data[40..42].try_into().unwrap_or([0; 2])) as usize;
        let ti_offset = u16::from_le_bytes(data[44..46].try_into().unwrap_or([0; 2])) as usize;

        if ti_offset + ti_len <= data.len() {
            data[ti_offset..ti_offset + ti_len].to_vec()
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    Ok(NtlmChallenge {
        server_challenge,
        target_info,
        negotiate_flags,
    })
}

/// 构建 NTLMSSP Type 3 (Authenticate) 消息
pub fn build_type3(
    username: &str,
    password: &str,
    domain: &str,
    hostname: &str,
    challenge: &NtlmChallenge,
) -> Vec<u8> {
    // 计算 NT 响应
    let nt_h = nt_hash(password);
    let ntlmv2_h = ntlmv2_hash(&nt_h, username, domain);
    let nt_response = ntlmv2_response(
        &ntlmv2_h,
        &challenge.server_challenge,
        &challenge.target_info,
    );

    // LM 响应 (NTLMv2 中 LM 响应为 8 字节零 + client challenge，或直接空)
    let lm_response = vec![0u8; 24];

    let flags = challenge.negotiate_flags | NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_NEGOTIATE_NTLM;

    // Unicode 编码
    let domain_upper = domain.to_uppercase();
    let username_upper = username; // 用户名保留原始大小写
    let hostname_upper = hostname.to_uppercase();

    let domain_bytes: Vec<u8> = domain_upper
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let username_bytes: Vec<u8> = username_upper
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let hostname_bytes: Vec<u8> = hostname_upper
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();

    // 消息头部: 签名(8) + 类型(4) + LM缓冲(8) + NT缓冲(8) + 域名缓冲(8) + 用户名缓冲(8) + 主机名缓冲(8) + 会话缓冲(8) + 标志(4) = 64
    let header_len = 64u32;
    let data_offset = header_len
        + lm_response.len() as u32
        + nt_response.len() as u32
        + domain_bytes.len() as u32
        + username_bytes.len() as u32
        + hostname_bytes.len() as u32;

    let mut msg = Vec::with_capacity(data_offset as usize);

    // 签名
    msg.extend_from_slice(NTLMSSP_SIGNATURE);
    // 消息类型
    msg.extend_from_slice(&MSG_TYPE_AUTHENTICATE.to_le_bytes());

    // LM Response 安全缓冲
    let mut offset = header_len;
    append_security_buffer(&mut msg, &lm_response, &mut offset);

    // NT Response 安全缓冲
    append_security_buffer(&mut msg, &nt_response, &mut offset);

    // 域名安全缓冲
    append_security_buffer(&mut msg, &domain_bytes, &mut offset);

    // 用户名安全缓冲
    append_security_buffer(&mut msg, &username_bytes, &mut offset);

    // 主机名安全缓冲
    append_security_buffer(&mut msg, &hostname_bytes, &mut offset);

    // 会话密钥安全缓冲 (空)
    append_security_buffer(&mut msg, &[], &mut offset);

    // 标志
    msg.extend_from_slice(&flags.to_le_bytes());

    // 数据部分
    msg.extend_from_slice(&lm_response);
    msg.extend_from_slice(&nt_response);
    msg.extend_from_slice(&domain_bytes);
    msg.extend_from_slice(&username_bytes);
    msg.extend_from_slice(&hostname_bytes);

    msg
}

/// 附加安全缓冲描述符 (Len u16, MaxLen u16, Offset u32)
fn append_security_buffer(msg: &mut Vec<u8>, data: &[u8], offset: &mut u32) {
    msg.extend_from_slice(&(data.len() as u16).to_le_bytes());
    msg.extend_from_slice(&(data.len() as u16).to_le_bytes());
    msg.extend_from_slice(&offset.to_le_bytes());
    *offset += data.len() as u32;
}

// ==================== TSRequest (CredSSP) ASN.1 编解码 ====================

/// 编码 CredSSP TSRequest (ASN.1 DER)
///
/// TSRequest ::= SEQUENCE {
///     version    [0] INTEGER,
///     negoTokens [1] SEQUENCE OF SEQUENCE { negoToken [0] OCTET STRING } OPTIONAL,
/// }
pub fn encode_ts_request(version: u32, nego_token: &[u8]) -> Vec<u8> {
    // 内层 OCTET STRING 包裹 negoToken
    let nego_token_octet_string = der_wrap(0x04, nego_token);
    // [0] EXPLICIT 包裹
    let nego_token_wrapped = der_wrap(0xA0, &nego_token_octet_string);
    // SEQUENCE 包裹
    let nego_token_seq_inner = der_wrap(0x30, &nego_token_wrapped);
    let nego_token_seq_outer = der_wrap(0x30, &nego_token_seq_inner);
    // [1] EXPLICIT 包裹
    let nego_tokens = der_wrap(0xA1, &nego_token_seq_outer);

    // version [0] EXPLICIT INTEGER
    let version_bytes = if version < 128 {
        vec![0x02, 0x01, version as u8]
    } else {
        vec![0x02, 0x02, (version >> 8) as u8, (version & 0xFF) as u8]
    };
    let version_wrapped = der_wrap(0xA0, &version_bytes);

    // 最外层 SEQUENCE
    let mut inner = Vec::new();
    inner.extend_from_slice(&version_wrapped);
    inner.extend_from_slice(&nego_tokens);

    der_wrap(0x30, &inner)
}

/// 解码 CredSSP TSRequest，提取 negoToken
pub fn decode_ts_request(data: &[u8]) -> Result<Vec<u8>, String> {
    if data.is_empty() {
        return Err("空的 TSRequest 数据".to_string());
    }

    // 查找 [1] negoTokens 标签 (0xA1)
    let mut pos = 0;
    while pos < data.len() {
        if data[pos] == 0xA1 {
            // 找到 negoTokens
            let (_, content_start) = der_read_length(&data[pos + 1..])?;
            let nego_tokens_data = &data[pos + 1 + content_start.consumed..];

            // 跳过外层 SEQUENCE
            if nego_tokens_data.is_empty() || nego_tokens_data[0] != 0x30 {
                return Err("期望 SEQUENCE".to_string());
            }
            let (_, seq_start) = der_read_length(&nego_tokens_data[1..])?;
            let seq_data = &nego_tokens_data[1 + seq_start.consumed..];

            // 跳过内层 SEQUENCE
            if seq_data.is_empty() || seq_data[0] != 0x30 {
                return Err("期望内层 SEQUENCE".to_string());
            }
            let (_, inner_start) = der_read_length(&seq_data[1..])?;
            let inner_data = &seq_data[1 + inner_start.consumed..];

            // 跳过 [0] 标签
            if inner_data.is_empty() || inner_data[0] != 0xA0 {
                return Err("期望 [0] OCTET STRING 标签".to_string());
            }
            let (_, a0_start) = der_read_length(&inner_data[1..])?;
            let octet_data = &inner_data[1 + a0_start.consumed..];

            // 读取 OCTET STRING
            if octet_data.is_empty() || octet_data[0] != 0x04 {
                return Err("期望 OCTET STRING".to_string());
            }
            let (len_info, str_start) = der_read_length(&octet_data[1..])?;
            return Ok(
                octet_data[1 + str_start.consumed..1 + str_start.consumed + len_info.value]
                    .to_vec(),
            );
        }
        pos += 1;
    }

    Err("未找到 negoToken".to_string())
}

/// DER 编码包裹
fn der_wrap(tag: u8, data: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(2 + data.len());
    result.push(tag);
    der_write_length(&mut result, data.len());
    result.extend_from_slice(data);
    result
}

/// DER 写入长度
fn der_write_length(buf: &mut Vec<u8>, len: usize) {
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

/// DER 读取长度，返回 (LengthInfo { bytes_consumed, length }, data_start_offset)
fn der_read_length(data: &[u8]) -> Result<(LengthInfo, LengthInfo), String> {
    if data.is_empty() {
        return Err("数据为空".to_string());
    }

    let first = data[0];
    if first < 128 {
        Ok((
            LengthInfo {
                consumed: 1,
                value: first as usize,
            },
            LengthInfo {
                consumed: 1,
                value: first as usize,
            },
        ))
    } else if first == 0x81 {
        if data.len() < 2 {
            return Err("长度字段不完整".to_string());
        }
        Ok((
            LengthInfo {
                consumed: 2,
                value: data[1] as usize,
            },
            LengthInfo {
                consumed: 2,
                value: data[1] as usize,
            },
        ))
    } else if first == 0x82 {
        if data.len() < 3 {
            return Err("长度字段不完整".to_string());
        }
        let len = ((data[1] as usize) << 8) | (data[2] as usize);
        Ok((
            LengthInfo {
                consumed: 3,
                value: len,
            },
            LengthInfo {
                consumed: 3,
                value: len,
            },
        ))
    } else {
        Err(format!("不支持的 DER 长度格式: 0x{:02X}", first))
    }
}

struct LengthInfo {
    consumed: usize,
    value: usize,
}

// ==================== MD4 哈希自实现 ====================

/// MD4 哈希函数（RFC 1320）
///
/// 用于 NTLM 的 NT Hash 计算。 crates.io 上没有官方 MD4 crate，因此自行实现。
fn md4_hash(input: &[u8]) -> [u8; 16] {
    // 填充
    let mut data = input.to_vec();
    let bit_len = (input.len() as u64) * 8;

    // 追加 0x80
    data.push(0x80);

    // 填充到 56 mod 64 字节
    while data.len() % 64 != 56 {
        data.push(0);
    }

    // 追加原始长度 (little-endian, 64-bit)
    data.extend_from_slice(&bit_len.to_le_bytes());

    // 初始状态
    let mut a: u32 = 0x67452301;
    let mut b: u32 = 0xEFCDAB89;
    let mut c: u32 = 0x98BADCFE;
    let mut d: u32 = 0x10325476;

    // 处理每个 64 字节块
    for chunk in data.chunks_exact(64) {
        let m: [u32; 16] = std::array::from_fn(|i| {
            u32::from_le_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ])
        });

        let (aa, bb, cc, dd) = (a, b, c, d);

        // Round 1
        for i in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15] {
            a = a.wrapping_add(f(b, c, d)).wrapping_add(m[i]);
            a = rotate_left(
                a,
                if i % 4 == 0 {
                    3
                } else if i % 4 == 1 {
                    7
                } else if i % 4 == 2 {
                    11
                } else {
                    19
                },
            );
            let tmp = d;
            d = c;
            c = b;
            b = a;
            a = tmp;
        }

        // Round 2 — 按 step index 确定移位量: 0→3, 1→5, 2→9, 3→13
        for (j, i) in [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
            .iter()
            .enumerate()
        {
            let s = match j % 4 {
                0 => 3,
                1 => 5,
                2 => 9,
                _ => 13,
            };
            a = a
                .wrapping_add(g(b, c, d))
                .wrapping_add(m[*i])
                .wrapping_add(0x5A827999);
            a = rotate_left(a, s);
            let tmp = d;
            d = c;
            c = b;
            b = a;
            a = tmp;
        }

        // Round 3 — 按 step index 确定移位量: 0→3, 1→9, 2→11, 3→15
        for (j, i) in [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
            .iter()
            .enumerate()
        {
            let s = match j % 4 {
                0 => 3,
                1 => 9,
                2 => 11,
                _ => 15,
            };
            a = a
                .wrapping_add(h(b, c, d))
                .wrapping_add(m[*i])
                .wrapping_add(0x6ED9EBA1);
            a = rotate_left(a, s);
            let tmp = d;
            d = c;
            c = b;
            b = a;
            a = tmp;
        }

        a = a.wrapping_add(aa);
        b = b.wrapping_add(bb);
        c = c.wrapping_add(cc);
        d = d.wrapping_add(dd);
    }

    let mut result = [0u8; 16];
    result[0..4].copy_from_slice(&a.to_le_bytes());
    result[4..8].copy_from_slice(&b.to_le_bytes());
    result[8..12].copy_from_slice(&c.to_le_bytes());
    result[12..16].copy_from_slice(&d.to_le_bytes());
    result
}

#[inline]
fn f(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (!x & z)
}

#[inline]
fn g(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (x & z) | (y & z)
}

#[inline]
fn h(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

#[inline]
fn rotate_left(x: u32, n: u32) -> u32 {
    x.rotate_left(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nt_hash_empty() {
        // 空密码的 NT Hash 已知向量
        let hash = nt_hash("");
        let expected: [u8; 16] = [
            0x31, 0xD6, 0xCF, 0xE0, 0xD1, 0x6A, 0xE9, 0x31, 0xB7, 0x3C, 0x59, 0xD7, 0xE0, 0xC0,
            0x89, 0xC0,
        ];
        assert_eq!(hash, expected, "空密码 NT Hash 不匹配");
    }

    #[test]
    fn test_nt_hash_password() {
        let hash = nt_hash("password");
        let expected: [u8; 16] = [
            0x88, 0x46, 0xF7, 0xEA, 0xEE, 0x8F, 0xB1, 0x17, 0xAD, 0x06, 0xBD, 0xD8, 0x30, 0xB7,
            0x58, 0x6C,
        ];
        assert_eq!(hash, expected, "\"password\" NT Hash 不匹配");
    }

    #[test]
    fn test_nt_hash_securesecret() {
        let hash = nt_hash("SecREt01");
        let expected: [u8; 16] = [
            0xCD, 0x06, 0xCA, 0x7C, 0x7E, 0x10, 0xC9, 0x9B, 0x1D, 0x33, 0xB7, 0x48, 0x5A, 0x2E,
            0xD8, 0x08,
        ];
        assert_eq!(hash, expected, "\"SecREt01\" NT Hash 不匹配");
    }

    #[test]
    fn test_build_type1_basic() {
        let msg = build_type1("workstation", "domain");
        // 验证签名
        assert_eq!(&msg[0..8], NTLMSSP_SIGNATURE);
        // 验证类型
        let msg_type = u32::from_le_bytes(msg[8..12].try_into().unwrap());
        assert_eq!(msg_type, MSG_TYPE_NEGOTIATE);
    }

    #[test]
    fn test_parse_type2_valid() {
        // 构造一个最小的 Type 2 消息
        // NTLM Type2: sig(8) + type(4) + target_name_buf(8) + flags(4) + challenge(8) + reserved(8) + target_info_buf(8) = 48
        let mut msg = Vec::new();
        msg.extend_from_slice(NTLMSSP_SIGNATURE); // 签名
        msg.extend_from_slice(&MSG_TYPE_CHALLENGE.to_le_bytes()); // 类型
        msg.extend_from_slice(&[0u8; 8]); // 目标名安全缓冲 (8 bytes: len+maxlen+offset)
        let mut flags = [0u8; 4];
        flags[0] = 0x01; // NTLMSSP_NEGOTIATE_UNICODE
        msg.extend_from_slice(&flags); // 标志 (offset 20)
        msg.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]); // 挑战 (offset 24)
        msg.extend_from_slice(&[0u8; 8]); // 保留 (offset 32)
        msg.extend_from_slice(&[0u8; 8]); // 目标信息安全缓冲 (空, offset 40)

        let result = parse_type2(&msg).unwrap();
        assert_eq!(result.server_challenge, [1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn test_parse_type2_invalid_signature() {
        let msg = vec![0u8; 48];
        let result = parse_type2(&msg);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_type2_too_short() {
        let msg = vec![0u8; 20];
        let result = parse_type2(&msg);
        assert!(result.is_err());
    }

    #[test]
    fn test_ts_request_roundtrip() {
        let token = b"test_nego_token_data";
        let encoded = encode_ts_request(2, token);
        let decoded = decode_ts_request(&encoded).unwrap();
        assert_eq!(decoded, token);
    }

    #[test]
    fn test_der_wrap() {
        let data = b"hello";
        let wrapped = der_wrap(0x04, data);
        assert_eq!(wrapped[0], 0x04); // tag
        assert_eq!(wrapped[1], 5); // length
        assert_eq!(&wrapped[2..7], data);
    }

    #[test]
    fn test_ntlmv2_response_not_empty() {
        let nt_h = nt_hash("password");
        let ntlmv2_h = ntlmv2_hash(&nt_h, "user", "DOMAIN");
        let server_challenge = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let target_info = vec![
            0x02, 0x00, 0x0C, 0x00, // AvPair: NetBIOS domain name
            0x44, 0x00, 0x4F, 0x00, 0x4D, 0x00, 0x41, 0x00, 0x49, 0x00, 0x4E, 0x00, 0x00, 0x00,
            0x00, 0x00, // AvPair terminator
        ];
        let response = ntlmv2_response(&ntlmv2_h, &server_challenge, &target_info);
        // NTProofStr (16 bytes) + Blob
        assert!(response.len() > 16);
    }

    #[test]
    fn test_build_type3_full() {
        let challenge = NtlmChallenge {
            server_challenge: [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF],
            target_info: vec![0x00, 0x00, 0x00, 0x00], // 最小 target info
            negotiate_flags: NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_NEGOTIATE_NTLM,
        };

        let msg = build_type3("user", "password", "DOMAIN", "WORKSTATION", &challenge);

        // 验证签名
        assert_eq!(&msg[0..8], NTLMSSP_SIGNATURE);
        // 验证类型
        let msg_type = u32::from_le_bytes(msg[8..12].try_into().unwrap());
        assert_eq!(msg_type, MSG_TYPE_AUTHENTICATE);
    }

    // ==================== 字节级布局测试（对照 MS-NLMP 规范） ====================

    #[test]
    fn test_type1_byte_layout() {
        // MS-NLMP 3.1.5.1.1: Type 1 消息布局
        // Signature(8) + MessageType(4) + NegotiateFlags(4) + DomainNameFields(8) + WorkstationFields(8) = 32 字节头
        let msg = build_type1("WS", "DOM");

        // 头部总长 32 字节
        assert!(msg.len() >= 32, "Type1 消息至少 32 字节头");

        // [0..8] 签名
        assert_eq!(&msg[0..8], b"NTLMSSP\0", "签名字段错误");

        // [8..12] 消息类型 = 1
        assert_eq!(
            u32::from_le_bytes(msg[8..12].try_into().unwrap()),
            1,
            "消息类型应为 1"
        );

        // [12..16] 协商标志 (u32)
        let flags = u32::from_le_bytes(msg[12..16].try_into().unwrap());
        assert!(
            flags & NTLMSSP_NEGOTIATE_UNICODE != 0,
            "应设置 UNICODE 标志"
        );
        assert!(flags & NTLMSSP_NEGOTIATE_NTLM != 0, "应设置 NTLM 标志");

        // [16..24] DomainNameFields: Len(u16) + MaxLen(u16) + BufferOffset(u32)
        let dom_len = u16::from_le_bytes(msg[16..18].try_into().unwrap());
        let dom_maxlen = u16::from_le_bytes(msg[18..20].try_into().unwrap());
        let dom_offset = u32::from_le_bytes(msg[20..24].try_into().unwrap());
        assert_eq!(dom_len, dom_maxlen, "Len 应等于 MaxLen");
        assert_eq!(dom_offset, 32, "Domain 数据偏移应为 32（头部之后）");

        // [24..32] WorkstationFields: Len(u16) + MaxLen(u16) + BufferOffset(u32)
        let ws_len = u16::from_le_bytes(msg[24..26].try_into().unwrap());
        let ws_offset = u32::from_le_bytes(msg[28..32].try_into().unwrap());
        assert_eq!(
            ws_offset,
            32 + dom_len as u32,
            "Workstation 偏移应紧跟 Domain 数据"
        );

        // 验证 payload 中的 Domain 数据（UTF-16LE "DOM"）
        let dom_data = &msg[dom_offset as usize..dom_offset as usize + dom_len as usize];
        let dom_str: Vec<u16> = dom_data
            .chunks(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        assert_eq!(String::from_utf16(&dom_str).unwrap(), "DOM");

        // 验证 payload 中的 Workstation 数据（UTF-16LE "WS"）
        let ws_data = &msg[ws_offset as usize..ws_offset as usize + ws_len as usize];
        let ws_str: Vec<u16> = ws_data
            .chunks(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        assert_eq!(String::from_utf16(&ws_str).unwrap(), "WS");
    }

    #[test]
    fn test_type2_byte_layout_flags_at_offset_20() {
        // MS-NLMP 3.1.5.1.2: Type 2 消息布局
        // Signature(8) + MessageType(4) + TargetNameFields(8) + NegotiateFlags(4) + ServerChallenge(8) + Reserved(8) + TargetInfoFields(8) = 48
        // 关键：NegotiateFlags 在偏移 20，不是 12
        let mut msg = Vec::new();
        msg.extend_from_slice(b"NTLMSSP\0"); // [0..8] 签名
        msg.extend_from_slice(&2u32.to_le_bytes()); // [8..12] 类型 = 2
                                                    // [12..20] TargetNameFields (Len=0, MaxLen=0, Offset=0)
        msg.extend_from_slice(&0u16.to_le_bytes());
        msg.extend_from_slice(&0u16.to_le_bytes());
        msg.extend_from_slice(&0u32.to_le_bytes());
        // [20..24] NegotiateFlags — 设置 UNICODE | NTLM | EXTENDED_SESSIONSECURITY
        let test_flags: u32 = 0x00080201;
        msg.extend_from_slice(&test_flags.to_le_bytes());
        // [24..32] ServerChallenge
        msg.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22]);
        // [32..40] Reserved
        msg.extend_from_slice(&[0u8; 8]);
        // [40..48] TargetInfoFields (空)
        msg.extend_from_slice(&0u16.to_le_bytes());
        msg.extend_from_slice(&0u16.to_le_bytes());
        msg.extend_from_slice(&0u32.to_le_bytes());

        let result = parse_type2(&msg).unwrap();

        // 验证 flags 从偏移 20 正确读取
        assert_eq!(
            result.negotiate_flags, test_flags,
            "flags 应从偏移 20 读取，期望 0x{:08X}，实际 0x{:08X}",
            test_flags, result.negotiate_flags
        );

        // 验证 challenge 从偏移 24 正确读取
        assert_eq!(
            result.server_challenge,
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22]
        );
    }

    #[test]
    fn test_type2_with_target_info() {
        // 构造含 TargetInfo 的 Type 2 消息
        let target_info: Vec<u8> = vec![
            0x02, 0x00, 0x08, 0x00, // AvId=2 (NetBIOS domain), Len=8
            0x44, 0x00, 0x4F, 0x00, 0x4D, 0x00, 0x41, 0x00, // "DOMA"
            0x00, 0x00, 0x00, 0x00, // AvPair terminator
        ];

        let mut msg = Vec::new();
        msg.extend_from_slice(b"NTLMSSP\0");
        msg.extend_from_slice(&2u32.to_le_bytes());
        // TargetNameFields: 指向 payload 中的目标名
        let target_name: Vec<u8> = "DOMAIN"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let tn_offset = 48u32;
        msg.extend_from_slice(&(target_name.len() as u16).to_le_bytes());
        msg.extend_from_slice(&(target_name.len() as u16).to_le_bytes());
        msg.extend_from_slice(&tn_offset.to_le_bytes());
        // Flags
        msg.extend_from_slice(&0x00080201u32.to_le_bytes());
        // Challenge
        msg.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        // Reserved
        msg.extend_from_slice(&[0u8; 8]);
        // TargetInfoFields
        let ti_offset = 48u32 + target_name.len() as u32;
        msg.extend_from_slice(&(target_info.len() as u16).to_le_bytes());
        msg.extend_from_slice(&(target_info.len() as u16).to_le_bytes());
        msg.extend_from_slice(&ti_offset.to_le_bytes());
        // Payload
        msg.extend_from_slice(&target_name);
        msg.extend_from_slice(&target_info);

        let result = parse_type2(&msg).unwrap();
        assert_eq!(result.server_challenge, [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(
            result.target_info, target_info,
            "TargetInfo 应从正确偏移提取"
        );
    }

    #[test]
    fn test_type3_byte_layout() {
        // MS-NLMP 3.1.5.1.3: Type 3 消息布局
        // Signature(8) + MessageType(4) + LmChallengeResponse(8) + NtChallengeResponse(8)
        // + DomainName(8) + UserName(8) + Workstation(8) + EncryptedRandomSessionKey(8) + NegotiateFlags(4) = 64 字节头
        let challenge = NtlmChallenge {
            server_challenge: [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF],
            target_info: vec![0x00, 0x00, 0x00, 0x00],
            negotiate_flags: NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_NEGOTIATE_NTLM,
        };

        let msg = build_type3("User", "Password", "Domain", "Workstation", &challenge);

        // 头部至少 64 字节
        assert!(
            msg.len() >= 64,
            "Type3 消息至少 64 字节头，实际 {}",
            msg.len()
        );

        // [0..8] 签名
        assert_eq!(&msg[0..8], b"NTLMSSP\0");

        // [8..12] 类型 = 3
        assert_eq!(u32::from_le_bytes(msg[8..12].try_into().unwrap()), 3);

        // 验证 6 个安全缓冲的偏移字段都是 u32（4 字节）
        // 每个安全缓冲: Len(u16) + MaxLen(u16) + Offset(u32) = 8 字节
        // LM: [12..20], NT: [20..28], Domain: [28..36], User: [36..44], WS: [44..52], Session: [52..60]
        let lm_len = u16::from_le_bytes(msg[12..14].try_into().unwrap());
        let lm_offset = u32::from_le_bytes(msg[16..20].try_into().unwrap());
        assert_eq!(lm_offset, 64, "LM 响应偏移应为 64（头部之后）");
        assert_eq!(lm_len, 24, "LM 响应应为 24 字节");

        let nt_len = u16::from_le_bytes(msg[20..22].try_into().unwrap());
        let nt_offset = u32::from_le_bytes(msg[24..28].try_into().unwrap());
        assert_eq!(nt_offset, 64 + lm_len as u32, "NT 响应偏移应紧跟 LM");
        assert!(nt_len > 24, "NTLMv2 响应应大于 24 字节");

        let dom_len = u16::from_le_bytes(msg[28..30].try_into().unwrap());
        let dom_offset = u32::from_le_bytes(msg[32..36].try_into().unwrap());
        assert_eq!(dom_offset, 64 + lm_len as u32 + nt_len as u32);

        let user_len = u16::from_le_bytes(msg[36..38].try_into().unwrap());
        let user_offset = u32::from_le_bytes(msg[40..44].try_into().unwrap());
        assert_eq!(user_offset, dom_offset + dom_len as u32);

        // [60..64] 协商标志
        let flags = u32::from_le_bytes(msg[60..64].try_into().unwrap());
        assert!(flags & NTLMSSP_NEGOTIATE_UNICODE != 0);

        // 验证用户名 payload（UTF-16LE "User"）
        let user_data = &msg[user_offset as usize..user_offset as usize + user_len as usize];
        let user_str: Vec<u16> = user_data
            .chunks(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        assert_eq!(String::from_utf16(&user_str).unwrap(), "User");
    }

    #[test]
    fn test_type1_empty_domain_workstation() {
        // 空域名和工作站名：安全缓冲 Len=0, Offset 仍为 u32
        let msg = build_type1("", "");
        assert_eq!(msg.len(), 32, "空 payload 时 Type1 应恰好 32 字节");

        let dom_len = u16::from_le_bytes(msg[16..18].try_into().unwrap());
        assert_eq!(dom_len, 0);
        let dom_offset = u32::from_le_bytes(msg[20..24].try_into().unwrap());
        assert_eq!(dom_offset, 32);
    }
}
