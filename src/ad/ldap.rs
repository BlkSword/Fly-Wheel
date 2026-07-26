//! LDAP 查询引擎
//!
//! 通过 ldap3 crate 连接域控执行 LDAP 查询

use crate::ad::{
    AdComputer, AdEnumResult, AdEnumStats, AdGroup, AdTrust, AdUser, AsrepTarget, KerberoastTarget,
};
use ldap3::adapters::{Adapter, EntriesOnly, PagedResults as PagedResultsAdapter};
use std::time::Duration;

/// LDAP 连接配置
#[derive(Clone)]
pub struct LdapConfig {
    pub domain_controller: String,
    pub port: u16,
    pub use_ssl: bool,
    pub username: Option<String>,
    pub password: Option<String>,
    pub domain: String,
    pub timeout: Duration,
}

impl LdapConfig {
    pub fn new(dc: &str, domain: &str) -> Self {
        Self {
            domain_controller: dc.to_string(),
            port: 389,
            use_ssl: false,
            username: None,
            password: None,
            domain: domain.to_string(),
            timeout: Duration::from_secs(30),
        }
    }

    pub fn with_credentials(mut self, username: &str, password: &str) -> Self {
        self.username = Some(username.to_string());
        self.password = Some(password.to_string());
        self
    }

    pub fn use_ssl(mut self, ssl: bool) -> Self {
        self.port = if ssl { 636 } else { 389 };
        self.use_ssl = ssl;
        self
    }
}

/// AD 深度枚举器
pub struct AdEnumerator {
    config: LdapConfig,
}

impl AdEnumerator {
    pub fn new(config: LdapConfig) -> Self {
        Self { config }
    }

    /// 执行完整 AD 枚举
    pub async fn enumerate_all(&self) -> Result<AdEnumResult, String> {
        // 在独立线程中执行同步 LDAP 操作
        let config = self.config.clone();
        tokio::task::spawn_blocking(move || enumerate_all_sync(&config))
            .await
            .map_err(|e| format!("任务执行失败: {}", e))?
    }

    /// 仅执行 Kerberoasting
    pub async fn kerberoast(&self) -> Result<Vec<KerberoastTarget>, String> {
        let config = self.config.clone();
        tokio::task::spawn_blocking(move || {
            let mut ldap = connect(&config)?;
            let base_dn = domain_to_dn(&config.domain);
            query_kerberoast_targets(&mut ldap, &base_dn)
        })
        .await
        .map_err(|e| format!("任务执行失败: {}", e))?
    }

    /// 仅执行 AS-REP Roasting
    pub async fn asrep_roast(&self) -> Result<Vec<AsrepTarget>, String> {
        let config = self.config.clone();
        tokio::task::spawn_blocking(move || {
            let mut ldap = connect(&config)?;
            let base_dn = domain_to_dn(&config.domain);
            query_asrep_targets(&mut ldap, &base_dn)
        })
        .await
        .map_err(|e| format!("任务执行失败: {}", e))?
    }
}

fn ldap_url(config: &LdapConfig) -> String {
    let scheme = if config.use_ssl { "ldaps" } else { "ldap" };
    format!("{}://{}:{}", scheme, config.domain_controller, config.port)
}

fn connect(config: &LdapConfig) -> Result<ldap3::LdapConn, String> {
    ldap3::LdapConn::new(&ldap_url(config)).map_err(|e| format!("LDAP连接失败: {}", e))
}

fn bind(ldap: &mut ldap3::LdapConn, config: &LdapConfig) -> Result<(), String> {
    match (&config.username, &config.password) {
        (Some(user), Some(pass)) => {
            let bind_dn = if user.contains('=') {
                user.clone()
            } else {
                format!("{}@{}", user, config.domain)
            };
            ldap.simple_bind(&bind_dn, pass)
                .map_err(|e| format!("LDAP认证失败: {}", e))?;
        }
        _ => {
            ldap.simple_bind("", "")
                .map_err(|e| format!("LDAP匿名绑定失败: {}", e))?;
        }
    }
    Ok(())
}

/// 同步执行完整枚举
fn enumerate_all_sync(config: &LdapConfig) -> Result<AdEnumResult, String> {
    let start_time = chrono::Utc::now();
    let mut result = AdEnumResult {
        domain_name: config.domain.clone(),
        domain_controller: Some(config.domain_controller.clone()),
        start_time,
        end_time: start_time,
        ..Default::default()
    };

    let mut ldap = connect(config)?;
    bind(&mut ldap, config)?;

    let base_dn = domain_to_dn(&config.domain);
    tracing::info!("LDAP基础DN: {}", base_dn);

    result.users = query_users(&mut ldap, &base_dn).unwrap_or_default();
    result.groups = query_groups(&mut ldap, &base_dn).unwrap_or_default();
    result.computers = query_computers(&mut ldap, &base_dn).unwrap_or_default();
    result.kerberoast_targets = query_kerberoast_targets(&mut ldap, &base_dn).unwrap_or_default();
    result.asrep_targets = query_asrep_targets(&mut ldap, &base_dn).unwrap_or_default();
    result.trusts = query_trusts(&mut ldap, &base_dn).unwrap_or_default();
    result.gpos = query_gpos(&mut ldap, &base_dn).unwrap_or_default();

    let _ = ldap.unbind();

    let end_time = chrono::Utc::now();
    result.end_time = end_time;
    result.duration_secs = (end_time - start_time).num_milliseconds() as f64 / 1000.0;

    result.stats = AdEnumStats {
        users_found: result.users.len(),
        groups_found: result.groups.len(),
        computers_found: result.computers.len(),
        kerberoast_targets: result.kerberoast_targets.len(),
        asrep_targets: result.asrep_targets.len(),
        gpos_found: result.gpos.len(),
        trusts_found: result.trusts.len(),
        admin_accounts: result.users.iter().filter(|u| u.admin_count).count(),
        da_accounts: result.users.iter().filter(|u| u.member_of.iter().any(|m| m.contains("Domain Admins"))).count(),
    };

    Ok(result)
}

fn search_attrs(
    ldap: &mut ldap3::LdapConn,
    base_dn: &str,
    filter: &str,
    attrs: &[&str],
) -> Result<Vec<ldap3::SearchEntry>, String> {
    let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
        Box::new(EntriesOnly::new()),
        Box::new(PagedResultsAdapter::new(1000)),
    ];
    let mut search = ldap
        .streaming_search_with(adapters, base_dn, ldap3::Scope::Subtree, filter, attrs)
        .map_err(|e| format!("LDAP查询失败: {}", e))?;
    let mut entries = Vec::new();
    while let Some(entry) = search.next().map_err(|e| format!("LDAP查询失败: {}", e))? {
        entries.push(ldap3::SearchEntry::construct(entry));
    }
    search
        .result()
        .success()
        .map_err(|e| format!("LDAP查询失败: {}", e))?;
    Ok(entries)
}

fn get_attr(entry: &ldap3::SearchEntry, name: &str) -> Option<String> {
    entry.attrs.get(name).and_then(|v| v.first().cloned()).filter(|v| !v.is_empty())
}

fn get_attr_multi(entry: &ldap3::SearchEntry, name: &str) -> Vec<String> {
    entry.attrs.get(name).cloned().unwrap_or_default()
}

/// 从二进制 LDAP 属性中读取 objectSid 并解析为字符串
fn get_sid_attr(entry: &ldap3::SearchEntry) -> Option<String> {
    entry
        .bin_attrs
        .get("objectSid")
        .and_then(|v| v.first())
        .and_then(|bytes| parse_sid(bytes))
}

/// 将二进制 SID 转换为字符串格式 (S-1-5-21-xxx-xxx-xxx-rid)
///
/// SID 二进制格式: Revision(1) + SubAuthorityCount(1) + IdentifierAuthority(6) + SubAuthorities(4×count)
fn parse_sid(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 8 {
        return None;
    }
    let revision = bytes[0];
    let sub_authority_count = bytes[1] as usize;

    // IdentifierAuthority: 6 字节大端序
    let authority = ((bytes[2] as u64) << 40)
        | ((bytes[3] as u64) << 32)
        | ((bytes[4] as u64) << 24)
        | ((bytes[5] as u64) << 16)
        | ((bytes[6] as u64) << 8)
        | (bytes[7] as u64);

    let expected_len = 8 + sub_authority_count * 4;
    if bytes.len() < expected_len {
        return None;
    }

    let mut sid = if authority < 0x1_0000_0000 {
        format!("S-{}-{}", revision, authority)
    } else {
        format!("S-{}-0x{:x}", revision, authority)
    };

    for i in 0..sub_authority_count {
        let offset = 8 + i * 4;
        let sub_authority = u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]);
        sid.push_str(&format!("-{}", sub_authority));
    }

    Some(sid)
}

fn query_users(ldap: &mut ldap3::LdapConn, base_dn: &str) -> Result<Vec<AdUser>, String> {
    let rs = search_attrs(ldap, base_dn,
        "(&(objectClass=user)(objectCategory=person))",
        &["sAMAccountName","displayName","distinguishedName","description","mail","adminCount",
          "userAccountControl","memberOf","servicePrincipalName","objectSid"])?;

    Ok(rs.iter().map(|entry| {
        let uac: u32 = get_attr(entry, "userAccountControl").and_then(|v| v.parse().ok()).unwrap_or(512);
        AdUser {
            sam_account_name: get_attr(entry, "sAMAccountName").unwrap_or_default(),
            display_name: get_attr(entry, "displayName"),
            dn: get_attr(entry, "distinguishedName").unwrap_or_default(),
            description: get_attr(entry, "description"),
            email: get_attr(entry, "mail"),
            admin_count: get_attr(entry, "adminCount").is_some(),
            enabled: uac & 2 == 0,
            password_expired: uac & 0x800000 != 0,
            last_logon: None,
            member_of: get_attr_multi(entry, "memberOf"),
            spn: get_attr_multi(entry, "servicePrincipalName"),
            sid: get_sid_attr(entry),
        }
    }).collect())
}

fn query_groups(ldap: &mut ldap3::LdapConn, base_dn: &str) -> Result<Vec<AdGroup>, String> {
    let rs = search_attrs(ldap, base_dn, "(objectClass=group)",
        &["cn","distinguishedName","description","member","adminCount","objectSid"])?;

    Ok(rs.iter().map(|entry| AdGroup {
        name: get_attr(entry, "cn").unwrap_or_default(),
        dn: get_attr(entry, "distinguishedName").unwrap_or_default(),
        description: get_attr(entry, "description"),
        members: get_attr_multi(entry, "member"),
        admin_count: get_attr(entry, "adminCount").is_some(),
        sid: get_sid_attr(entry),
    }).collect())
}

fn query_computers(ldap: &mut ldap3::LdapConn, base_dn: &str) -> Result<Vec<AdComputer>, String> {
    let rs = search_attrs(ldap, base_dn, "(objectClass=computer)",
        &["cn","distinguishedName","dNSHostName","operatingSystem","operatingSystemVersion","userAccountControl","objectSid"])?;

    Ok(rs.iter().map(|entry| {
        let uac: u32 = get_attr(entry, "userAccountControl").and_then(|v| v.parse().ok()).unwrap_or(4096);
        AdComputer {
            name: get_attr(entry, "cn").unwrap_or_default(),
            dn: get_attr(entry, "distinguishedName").unwrap_or_default(),
            dns_hostname: get_attr(entry, "dNSHostName"),
            os: get_attr(entry, "operatingSystem"),
            os_version: get_attr(entry, "operatingSystemVersion"),
            enabled: uac & 2 == 0,
            last_logon: None,
            sid: get_sid_attr(entry),
        }
    }).collect())
}

fn query_kerberoast_targets(ldap: &mut ldap3::LdapConn, base_dn: &str) -> Result<Vec<KerberoastTarget>, String> {
    let rs = search_attrs(ldap, base_dn,
        "(&(servicePrincipalName=*)(objectClass=user)(!(objectClass=computer)))",
        &["sAMAccountName","distinguishedName","servicePrincipalName","adminCount",
          "userAccountControl","description"])?;

    let mut targets = Vec::new();
    for entry in &rs {
        let username = get_attr(entry, "sAMAccountName").unwrap_or_default();
        let dn = get_attr(entry, "distinguishedName").unwrap_or_default();
        let spns = get_attr_multi(entry, "servicePrincipalName");
        let admin_count = get_attr(entry, "adminCount").is_some();
        let uac: u32 = get_attr(entry, "userAccountControl").and_then(|v| v.parse().ok()).unwrap_or(0);
        let enabled = uac & 2 == 0;
        let description = get_attr(entry, "description");

        for spn in spns {
            let service_type = spn.split('/').next().unwrap_or("").to_string();
            targets.push(KerberoastTarget {
                username: username.clone(),
                dn: dn.clone(),
                spn,
                service_type,
                admin_count,
                enabled,
                description: description.clone(),
            });
        }
    }

    Ok(targets)
}

fn query_asrep_targets(ldap: &mut ldap3::LdapConn, base_dn: &str) -> Result<Vec<AsrepTarget>, String> {
    let rs = search_attrs(ldap, base_dn,
        "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
        &["sAMAccountName","distinguishedName","userAccountControl","description"])?;

    Ok(rs.iter().map(|entry| {
        let uac: u32 = get_attr(entry, "userAccountControl").and_then(|v| v.parse().ok()).unwrap_or(0);
        AsrepTarget {
            username: get_attr(entry, "sAMAccountName").unwrap_or_default(),
            dn: get_attr(entry, "distinguishedName").unwrap_or_default(),
            enabled: uac & 2 == 0,
            description: get_attr(entry, "description"),
        }
    }).collect())
}

fn query_trusts(ldap: &mut ldap3::LdapConn, base_dn: &str) -> Result<Vec<AdTrust>, String> {
    let rs = search_attrs(ldap, &format!("CN=System,{}", base_dn),
        "(objectClass=trustedDomain)",
        &["cn","trustType","trustDirection","trustAttributes"])?;

    Ok(rs.iter().map(|entry| {
        AdTrust {
            domain: get_attr(entry, "cn").unwrap_or_default(),
            trust_type: get_attr(entry, "trustType").map(|v| match v.as_str() {
                "1" => "Windows NT".to_string(),
                "2" => "Windows 2000".to_string(),
                "3" => "Kerberos".to_string(),
                _ => v,
            }).unwrap_or_else(|| "未知".to_string()),
            trust_direction: get_attr(entry, "trustDirection").map(|v| match v.as_str() {
                "0" => "禁用".to_string(),
                "1" => "入站".to_string(),
                "2" => "出站".to_string(),
                "3" => "双向".to_string(),
                _ => v,
            }).unwrap_or_else(|| "未知".to_string()),
            trust_attributes: get_attr(entry, "trustAttributes")
                .map(|v| parse_trust_attributes(&v))
                .unwrap_or_else(|| "未知".to_string()),
        }
    }).collect())
}

/// 按位掩码解析 trustAttributes (MS-ADTS)
fn parse_trust_attributes(value: &str) -> String {
    let flags: u32 = match value.parse() {
        Ok(v) => v,
        Err(_) => return value.to_string(),
    };

    let mut parts = Vec::new();
    if flags & 0x0000_0001 != 0 { parts.push("NON_TRANSITIVE"); }
    if flags & 0x0000_0002 != 0 { parts.push("UPLEVEL_ONLY"); }
    if flags & 0x0000_0004 != 0 { parts.push("QUARANTINED_DOMAIN"); }
    if flags & 0x0000_0008 != 0 { parts.push("FOREST_TRANSITIVE"); }
    if flags & 0x0000_0010 != 0 { parts.push("CROSS_ORGANIZATION"); }
    if flags & 0x0000_0020 != 0 { parts.push("WITHIN_FOREST"); }
    if flags & 0x0000_0040 != 0 { parts.push("TREAT_AS_EXTERNAL"); }
    if flags & 0x0000_0080 != 0 { parts.push("USES_RC4_ENCRYPTION"); }

    if parts.is_empty() {
        format!("0x{:08X}", flags)
    } else {
        parts.join(" | ")
    }
}

fn query_gpos(ldap: &mut ldap3::LdapConn, base_dn: &str) -> Result<Vec<String>, String> {
    let rs = search_attrs(ldap, base_dn, "(objectClass=groupPolicyContainer)",
        &["cn","displayName"])?;

    Ok(rs.iter().map(|entry| {
        get_attr(entry, "displayName").unwrap_or_else(|| get_attr(entry, "cn").unwrap_or_default())
    }).collect())
}

/// 域密码策略 (通过 LDAP 查询域对象的属性)
#[derive(Debug, Clone, Default)]
pub struct LdapPasswordPolicy {
    /// 密码最长期限 (分钟), None 表示无限制
    pub max_password_age_mins: Option<u32>,
    /// 密码最短期限 (分钟)
    pub min_password_age_mins: Option<u32>,
    /// 密码最小长度
    pub min_password_length: Option<u32>,
    /// 密码历史记录数
    pub password_history_length: Option<u32>,
    /// 账户锁定阈值 (0 = 不锁定)
    pub lockout_threshold: Option<u32>,
    /// 账户锁定时间 (分钟)
    pub lockout_duration_mins: Option<u32>,
    /// 账户锁定观察窗口 (分钟)
    pub lockout_observation_window_mins: Option<u32>,
}

/// 将 AD LargeInteger (100ns 间隔, 通常为负值) 转换为分钟
fn large_integer_to_mins(value: i64) -> Option<u32> {
    if value == 0 {
        return None; // 0 表示无限制
    }
    let abs_val = value.unsigned_abs();
    Some((abs_val / 10_000_000 / 60) as u32)
}

/// 查询域密码策略 (读取域根对象的密码策略属性)
pub fn query_password_policy(
    ldap: &mut ldap3::LdapConn,
    base_dn: &str,
) -> Result<LdapPasswordPolicy, String> {
    let rs = search_attrs(
        ldap,
        base_dn,
        "(objectClass=domain)",
        &[
            "maxPwdAge",
            "minPwdAge",
            "minPwdLength",
            "pwdHistoryLength",
            "lockoutThreshold",
            "lockoutDuration",
            "lockoutObservationWindow",
        ],
    )?;

    let entry = rs.first().ok_or_else(|| "未找到域对象".to_string())?;

    let parse_i64 = |name: &str| -> Option<i64> {
        get_attr(entry, name).and_then(|v| v.parse().ok())
    };
    let parse_u32 = |name: &str| -> Option<u32> {
        get_attr(entry, name).and_then(|v| v.parse().ok())
    };

    Ok(LdapPasswordPolicy {
        max_password_age_mins: parse_i64("maxPwdAge").and_then(large_integer_to_mins),
        min_password_age_mins: parse_i64("minPwdAge").and_then(large_integer_to_mins),
        min_password_length: parse_u32("minPwdLength"),
        password_history_length: parse_u32("pwdHistoryLength"),
        lockout_threshold: parse_u32("lockoutThreshold"),
        lockout_duration_mins: parse_i64("lockoutDuration").and_then(large_integer_to_mins),
        lockout_observation_window_mins: parse_i64("lockoutObservationWindow")
            .and_then(large_integer_to_mins),
    })
}

/// 域名转 DN 格式 (corp.local → DC=corp,DC=local)
pub fn domain_to_dn(domain: &str) -> String {
    domain.split('.').map(|p| format!("DC={}", p)).collect::<Vec<_>>().join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_to_dn() {
        assert_eq!(domain_to_dn("corp.local"), "DC=corp,DC=local");
        assert_eq!(domain_to_dn("sub.corp.local"), "DC=sub,DC=corp,DC=local");
    }

    #[test]
    fn test_ldap_config_builder() {
        let config = LdapConfig::new("10.0.0.1", "corp.local")
            .with_credentials("admin", "password")
            .use_ssl(true);
        assert_eq!(config.port, 636);
        assert!(config.use_ssl);
    }

    #[test]
    fn test_parse_sid_typical_domain_sid() {
        // S-1-5-21-1004336348-1177238915-682003330-512
        // Revision=1, Count=5, Authority=5, SubAuthorities: 21, 1004336348, 1177238915, 682003330, 512
        let bytes: Vec<u8> = vec![
            0x01, // Revision
            0x05, // SubAuthorityCount = 5
            0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // IdentifierAuthority = 5 (big-endian)
            0x15, 0x00, 0x00, 0x00, // SubAuthority[0] = 21 (little-endian)
            0xDC, 0xF4, 0xDC, 0x3B, // SubAuthority[1] = 1004336348 (0x3BDCF4DC LE)
            0x83, 0x3D, 0x2B, 0x46, // SubAuthority[2] = 1177238915 (0x462B3D83 LE)
            0x82, 0x8B, 0xA6, 0x28, // SubAuthority[3] = 682003330 (0x28A68B82 LE)
            0x00, 0x02, 0x00, 0x00, // SubAuthority[4] = 512
        ];
        assert_eq!(
            parse_sid(&bytes),
            Some("S-1-5-21-1004336348-1177238915-682003330-512".to_string())
        );
    }

    #[test]
    fn test_parse_sid_builtin_administrators() {
        // S-1-5-32-544 (BUILTIN\Administrators)
        let bytes: Vec<u8> = vec![
            0x01, // Revision
            0x02, // SubAuthorityCount = 2
            0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // IdentifierAuthority = 5
            0x20, 0x00, 0x00, 0x00, // SubAuthority[0] = 32
            0x20, 0x02, 0x00, 0x00, // SubAuthority[1] = 544
        ];
        assert_eq!(parse_sid(&bytes), Some("S-1-5-32-544".to_string()));
    }

    #[test]
    fn test_parse_sid_too_short() {
        assert_eq!(parse_sid(&[0x01, 0x00]), None);
        assert_eq!(parse_sid(&[]), None);
    }

    #[test]
    fn test_parse_sid_truncated_sub_authorities() {
        // Claims 2 sub-authorities but only has room for 1
        let bytes: Vec<u8> = vec![
            0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00,
        ];
        assert_eq!(parse_sid(&bytes), None);
    }

    #[test]
    fn test_parse_trust_attributes_single_flag() {
        assert_eq!(parse_trust_attributes("1"), "NON_TRANSITIVE");
        assert_eq!(parse_trust_attributes("4"), "QUARANTINED_DOMAIN");
        assert_eq!(parse_trust_attributes("8"), "FOREST_TRANSITIVE");
    }

    #[test]
    fn test_parse_trust_attributes_bitmask() {
        // 0x00000028 = WITHIN_FOREST | FOREST_TRANSITIVE
        assert_eq!(
            parse_trust_attributes("40"),
            "FOREST_TRANSITIVE | WITHIN_FOREST"
        );
        // 0x00000018 = FOREST_TRANSITIVE | CROSS_ORGANIZATION
        assert_eq!(
            parse_trust_attributes("24"),
            "FOREST_TRANSITIVE | CROSS_ORGANIZATION"
        );
    }

    #[test]
    fn test_parse_trust_attributes_zero() {
        assert_eq!(parse_trust_attributes("0"), "0x00000000");
    }

    #[test]
    fn test_parse_trust_attributes_non_numeric() {
        assert_eq!(parse_trust_attributes("abc"), "abc");
    }

    #[test]
    fn test_large_integer_to_mins() {
        // -36288000000000 = -42 days in 100ns intervals → 60480 mins
        assert_eq!(large_integer_to_mins(-36_288_000_000_000), Some(60480));
        // 0 means no limit
        assert_eq!(large_integer_to_mins(0), None);
        // -18000000000 = -30 mins
        assert_eq!(large_integer_to_mins(-1_800_000_000), Some(3));
    }
}
