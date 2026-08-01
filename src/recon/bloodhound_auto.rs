//! 自动化BloodHound数据收集模块
//!
//! 自动部署SharpHound收集器，收集域内关系数据，
//! 生成BloodHound兼容的JSON输出。

use serde::{Deserialize, Serialize};

/// BloodHound收集配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BloodHoundCollectConfig {
    /// 域控制器
    pub domain_controller: String,
    /// 域名
    pub domain: String,
    /// 收集方法（SharpHound/ldap/stealth）
    pub method: CollectionMethod,
    /// 是否收集会话信息
    pub collect_sessions: bool,
    /// 是否收集ACL
    pub collect_acls: bool,
    /// 是否收集本地管理员
    pub collect_local_admin: bool,
    /// 是否收集计算机信息
    pub collect_computers: bool,
    /// 输出目录
    pub output_dir: Option<String>,
}

/// 收集方法
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CollectionMethod {
    /// 使用SharpHound.exe (Windows)
    SharpHound,
    /// 使用LDAP查询（跨平台）
    Ldap,
    /// 隐形模式（仅LDAP，不触发日志）
    Stealth,
}

impl Default for BloodHoundCollectConfig {
    fn default() -> Self {
        Self {
            domain_controller: String::new(),
            domain: String::new(),
            method: CollectionMethod::Ldap,
            collect_sessions: true,
            collect_acls: true,
            collect_local_admin: true,
            collect_computers: true,
            output_dir: None,
        }
    }
}

/// BloodHound收集结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BloodHoundCollectResult {
    /// 收集的域对象
    pub domain_name: String,
    /// 用户JSON数据
    pub users_json: Option<String>,
    /// 组JSON数据
    pub groups_json: Option<String>,
    /// 计算机JSON数据
    pub computers_json: Option<String>,
    /// 容器/OU JSON数据
    pub containers_json: Option<String>,
    /// GPO JSON数据
    pub gpos_json: Option<String>,
    /// 输出文件路径
    pub output_files: Vec<String>,
    /// 统计概要
    pub summary: BloodHoundSummary,
}

/// BloodHound收集统计
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BloodHoundSummary {
    pub users: usize,
    pub groups: usize,
    pub computers: usize,
    pub sessions: usize,
    pub acls: usize,
    pub gpos: usize,
    pub ous: usize,
    pub trusts: usize,
}

/// 执行BloodHound数据收集
pub async fn collect_bloodhound_data(
    config: &BloodHoundCollectConfig,
) -> Result<BloodHoundCollectResult, String> {
    tracing::info!(
        "[BloodHound] 开始收集AD数据 (方法: {}, 域: {})",
        match config.method {
            CollectionMethod::SharpHound => "SharpHound",
            CollectionMethod::Ldap => "LDAP",
            CollectionMethod::Stealth => "Stealth",
        },
        config.domain,
    );

    match config.method {
        CollectionMethod::SharpHound => collect_via_sharphound(config),
        CollectionMethod::Ldap | CollectionMethod::Stealth => collect_via_ldap(config).await,
    }
}

/// 通过SharpHound收集数据
fn collect_via_sharphound(
    config: &BloodHoundCollectConfig,
) -> Result<BloodHoundCollectResult, String> {
    let temp_dir = std::env::temp_dir();
    let output_dir = config
        .output_dir
        .as_deref()
        .map(|d| d.to_string())
        .unwrap_or_else(|| temp_dir.to_string_lossy().to_string());

    // 检查SharpHound是否存在
    let sharphound_paths = [
        "SharpHound.exe",
        "SharpHound64.exe",
        ".\\SharpHound.exe",
        ".\\SharpHound64.exe",
    ];

    let mut sharphound_path = None;
    for path in &sharphound_paths {
        if std::path::Path::new(path).exists() {
            sharphound_path = Some(path.to_string());
            break;
        }
    }

    if sharphound_path.is_none() {
        return Err("SharpHound.exe未找到。请将SharpHound放入工作目录，\
            或使用LDAP收集方法。\n\
            下载地址: https://github.com/BloodHoundAD/SharpHound/releases"
            .to_string());
    }

    let sharphound = sharphound_path.unwrap();

    // 构造SharpHound参数
    let mut args = vec![
        "-c".to_string(),
        build_collection_flags(config),
        "-d".to_string(),
        config.domain.clone(),
        "--outputdirectory".to_string(),
        output_dir.clone(),
    ];

    if let CollectionMethod::Stealth = config.method {
        args.push("--stealth".to_string());
        args.push("--throttle".to_string());
        args.push("500".to_string());
    }

    tracing::info!("[BloodHound] 执行 {} {}", sharphound, args.join(" "));

    let output = std::process::Command::new(&sharphound)
        .args(&args)
        .output()
        .map_err(|e| format!("SharpHound执行失败: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("SharpHound执行错误: {}", stderr));
    }

    // 查找生成的JSON文件
    let output_files = find_bloodhound_files(&output_dir)?;

    Ok(BloodHoundCollectResult {
        domain_name: config.domain.clone(),
        users_json: None,
        groups_json: None,
        computers_json: None,
        containers_json: None,
        gpos_json: None,
        output_files,
        summary: BloodHoundSummary::default(),
    })
}

/// 通过LDAP收集数据
async fn collect_via_ldap(
    config: &BloodHoundCollectConfig,
) -> Result<BloodHoundCollectResult, String> {
    // 使用ad模块的LdapConn查询
    let mut result = BloodHoundCollectResult {
        domain_name: config.domain.clone(),
        users_json: None,
        groups_json: None,
        computers_json: None,
        containers_json: None,
        gpos_json: None,
        output_files: Vec::new(),
        summary: BloodHoundSummary::default(),
    };

    let ldap_url = format!("ldap://{}:389", config.domain_controller);
    let mut ldap = ldap3::LdapConn::new(&ldap_url).map_err(|e| format!("LDAP连接失败: {}", e))?;

    ldap.simple_bind("", "")
        .map_err(|e| format!("LDAP绑定失败: {}", e))?;

    let base_dn = domain_to_dn(&config.domain);

    // 收集用户数据
    if let Ok(users) = collect_users_json(&mut ldap, &base_dn, config.collect_sessions) {
        result.summary.users = users.len();
        result.users_json = Some(serde_json::to_string_pretty(&users).unwrap_or_default());
    }

    // 收集组数据
    if let Ok(groups) = collect_groups_json(&mut ldap, &base_dn) {
        result.summary.groups = groups.len();
        result.groups_json = Some(serde_json::to_string_pretty(&groups).unwrap_or_default());
    }

    // 收集计算机数据
    if let Ok(computers) = collect_computers_json(&mut ldap, &base_dn, config.collect_sessions) {
        result.summary.computers = computers.len();
        result.computers_json = Some(serde_json::to_string_pretty(&computers).unwrap_or_default());
    }

    // 输出到文件
    let output_dir = config
        .output_dir
        .as_deref()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);

    let timestamp = chrono::Utc::now().format("%Y%m%d%H%M%S");

    if let Some(ref json) = result.users_json {
        let f = output_dir.join(format!("{}_users.json", timestamp));
        if std::fs::write(&f, json).is_ok() {
            result.output_files.push(f.to_string_lossy().to_string());
        }
    }
    if let Some(ref json) = result.groups_json {
        let f = output_dir.join(format!("{}_groups.json", timestamp));
        if std::fs::write(&f, json).is_ok() {
            result.output_files.push(f.to_string_lossy().to_string());
        }
    }
    if let Some(ref json) = result.computers_json {
        let f = output_dir.join(format!("{}_computers.json", timestamp));
        if std::fs::write(&f, json).is_ok() {
            result.output_files.push(f.to_string_lossy().to_string());
        }
    }

    Ok(result)
}

/// 构造收集标志
fn build_collection_flags(config: &BloodHoundCollectConfig) -> String {
    let mut flags = Vec::new();
    if config.collect_sessions {
        flags.push("Session");
    }
    if config.collect_acls {
        flags.push("ACL");
    }
    if config.collect_local_admin {
        flags.push("LocalAdmin");
    }
    if config.collect_computers {
        flags.push("ComputerOnly");
    }
    flags.push("Group");
    flags.push("Trusts");

    flags.join(",")
}

/// 查找BloodHound输出文件
fn find_bloodhound_files(dir: &str) -> Result<Vec<String>, String> {
    let mut files = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.ends_with("_BloodHound.zip") || name_str.contains("BloodHound") {
                files.push(entry.path().to_string_lossy().to_string());
            }
        }
    }
    Ok(files)
}

/// 收集用户JSON (BloodHound格式)
fn collect_users_json(
    ldap: &mut ldap3::LdapConn,
    base_dn: &str,
    include_sessions: bool,
) -> Result<Vec<serde_json::Value>, String> {
    let attrs = vec![
        "sAMAccountName",
        "displayName",
        "distinguishedName",
        "description",
        "mail",
        "adminCount",
        "userAccountControl",
        "memberOf",
        "servicePrincipalName",
        "objectSid",
        "lastLogonTimestamp",
    ];
    if include_sessions {
        // NetSessionEnum需要单独做
    }

    let sr = ldap
        .search(
            base_dn,
            ldap3::Scope::Subtree,
            "(&(objectClass=user)(objectCategory=person))",
            &attrs,
        )
        .map_err(|e| format!("LDAP用户查询失败: {}", e))?;

    let users: Vec<serde_json::Value> = sr.0.iter().map(|entry| {
        let entry = ldap3::SearchEntry::construct(entry.clone());
        let sam = get_attr(&entry, "sAMAccountName").unwrap_or_default();
        serde_json::json!({
            "Name": sam,
            "DisplayName": get_attr(&entry, "displayName"),
            "DistinguishedName": get_attr(&entry, "distinguishedName"),
            "Description": get_attr(&entry, "description"),
            "Email": get_attr(&entry, "mail"),
            "AdminCount": get_attr(&entry, "adminCount").is_some(),
            "Enabled": !get_attr(&entry, "userAccountControl").map(|u| u.parse::<u32>().unwrap_or(512) & 2 == 2).unwrap_or(false),
            "MemberOf": get_attr_multi(&entry, "memberOf"),
            "ServicePrincipalNames": get_attr_multi(&entry, "servicePrincipalName"),
            "ObjectSid": get_attr(&entry, "objectSid"),
            "LastLogon": get_attr(&entry, "lastLogonTimestamp"),
            "Properties": {
                "domain": base_dn,
            }
        })
    }).collect();

    Ok(users)
}

/// 收集组JSON
fn collect_groups_json(
    ldap: &mut ldap3::LdapConn,
    base_dn: &str,
) -> Result<Vec<serde_json::Value>, String> {
    let attrs = &[
        "cn",
        "distinguishedName",
        "description",
        "member",
        "adminCount",
    ];

    let sr = ldap
        .search(base_dn, ldap3::Scope::Subtree, "(objectClass=group)", attrs)
        .map_err(|e| format!("LDAP组查询失败: {}", e))?;

    let groups: Vec<serde_json::Value> =
        sr.0.iter()
            .map(|entry| {
                let entry = ldap3::SearchEntry::construct(entry.clone());
                serde_json::json!({
                    "Name": get_attr(&entry, "cn").unwrap_or_default(),
                    "DistinguishedName": get_attr(&entry, "distinguishedName"),
                    "Description": get_attr(&entry, "description"),
                    "Members": get_attr_multi(&entry, "member"),
                    "AdminCount": get_attr(&entry, "adminCount").is_some(),
                    "Properties": {
                        "domain": base_dn,
                    }
                })
            })
            .collect();

    Ok(groups)
}

/// 收集计算机JSON
fn collect_computers_json(
    ldap: &mut ldap3::LdapConn,
    base_dn: &str,
    include_sessions: bool,
) -> Result<Vec<serde_json::Value>, String> {
    let attrs = vec![
        "cn",
        "distinguishedName",
        "dNSHostName",
        "operatingSystem",
        "operatingSystemVersion",
        "userAccountControl",
    ];

    let _ = include_sessions;

    let sr = ldap
        .search(
            base_dn,
            ldap3::Scope::Subtree,
            "(objectClass=computer)",
            &attrs,
        )
        .map_err(|e| format!("LDAP计算机查询失败: {}", e))?;

    let computers: Vec<serde_json::Value> = sr.0.iter().map(|entry| {
        let entry = ldap3::SearchEntry::construct(entry.clone());
        serde_json::json!({
            "Name": get_attr(&entry, "cn").unwrap_or_default(),
            "DistinguishedName": get_attr(&entry, "distinguishedName"),
            "DNSHostName": get_attr(&entry, "dNSHostName"),
            "OperatingSystem": get_attr(&entry, "operatingSystem"),
            "OperatingSystemVersion": get_attr(&entry, "operatingSystemVersion"),
            "Enabled": !get_attr(&entry, "userAccountControl").map(|u| u.parse::<u32>().unwrap_or(4096) & 2 == 2).unwrap_or(false),
            "Properties": {
                "domain": base_dn,
            }
        })
    }).collect();

    Ok(computers)
}

fn domain_to_dn(domain: &str) -> String {
    domain
        .split('.')
        .map(|p| format!("DC={}", p))
        .collect::<Vec<_>>()
        .join(",")
}

fn get_attr(entry: &ldap3::SearchEntry, name: &str) -> Option<String> {
    entry
        .attrs
        .get(name)
        .and_then(|v| v.first().cloned())
        .filter(|v| !v.is_empty())
}

fn get_attr_multi(entry: &ldap3::SearchEntry, name: &str) -> Vec<String> {
    entry.attrs.get(name).cloned().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collection_method_default() {
        let config = BloodHoundCollectConfig::default();
        assert_eq!(config.method, CollectionMethod::Ldap);
        assert!(config.collect_sessions);
    }

    #[test]
    fn test_build_collection_flags() {
        let config = BloodHoundCollectConfig::default();
        let flags = build_collection_flags(&config);
        assert!(flags.contains("Session"));
        assert!(flags.contains("ACL"));
        assert!(flags.contains("Group"));
    }

    #[test]
    fn test_bloodhound_summary_default() {
        let summary = BloodHoundSummary::default();
        assert_eq!(summary.users, 0);
        assert_eq!(summary.groups, 0);
    }
}
