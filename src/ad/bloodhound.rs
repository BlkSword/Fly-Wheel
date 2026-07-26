//! BloodHound JSON 输出
//!
//! 生成 BloodHound 兼容的 JSON 格式，可被 BloodHound 导入

// BloodHound JSON 格式要求 PascalCase 字段名
#![allow(non_snake_case)]

use crate::ad::{AdComputer, AdEnumResult, AdGroup, AdUser};
use serde::Serialize;
use std::path::Path;

/// BloodHound 用户条目
#[derive(Serialize, Clone)]
struct BhUser {
    #[serde(rename = "ObjectIdentifier")]
    object_identifier: String,
    #[serde(rename = "ObjectType")]
    object_type: String,
    Properties: BhUserProps,
    #[serde(rename = "ACEs")]
    aces: Vec<BhAce>,
}

#[derive(Serialize, Clone)]
struct BhUserProps {
    name: String,
    domain: String,
    distinguishedname: String,
    description: Option<String>,
    email: Option<String>,
    #[serde(rename = "admincount")]
    admin_count: bool,
    enabled: bool,
    #[serde(rename = "pwdneverexpires")]
    pwd_never_expires: bool,
    #[serde(rename = "sensitive")]
    sensitive: bool,
    #[serde(rename = "dontreqpreauth")]
    dont_req_preauth: bool,
    #[serde(rename = "passwordnotreqd")]
    password_not_reqd: bool,
    spn_targets: Vec<BhSpnTarget>,
    #[serde(rename = "hasspn")]
    has_spn: bool,
}

#[derive(Serialize, Clone)]
struct BhSpnTarget {
    #[serde(rename = "SPNService")]
    service: String,
    #[serde(rename = "SPNString")]
    spn: String,
}

/// BloodHound 组条目
#[derive(Serialize, Clone)]
struct BhGroup {
    #[serde(rename = "ObjectIdentifier")]
    object_identifier: String,
    #[serde(rename = "ObjectType")]
    object_type: String,
    Properties: BhGroupProps,
    Members: Vec<BhMember>,
    #[serde(rename = "ACEs")]
    aces: Vec<BhAce>,
}

#[derive(Serialize, Clone)]
struct BhGroupProps {
    name: String,
    domain: String,
    distinguishedname: String,
    description: Option<String>,
    #[serde(rename = "admincount")]
    admin_count: bool,
}

#[derive(Serialize, Clone)]
struct BhMember {
    #[serde(rename = "ObjectIdentifier")]
    object_identifier: String,
    #[serde(rename = "ObjectType")]
    object_type: String,
}

/// BloodHound 计算机条目
#[derive(Serialize, Clone)]
struct BhComputer {
    #[serde(rename = "ObjectIdentifier")]
    object_identifier: String,
    #[serde(rename = "ObjectType")]
    object_type: String,
    Properties: BhComputerProps,
    #[serde(rename = "ACEs")]
    aces: Vec<BhAce>,
    #[serde(rename = "LocalGroups")]
    local_groups: Vec<BhLocalGroup>,
}

#[derive(Serialize, Clone)]
struct BhComputerProps {
    name: String,
    domain: String,
    distinguishedname: String,
    #[serde(rename = "operatingsystem")]
    os: Option<String>,
    enabled: bool,
}

#[derive(Serialize, Clone)]
struct BhLocalGroup {
    Name: String,
    Members: Vec<BhMember>,
}

#[derive(Serialize, Clone)]
struct BhAce {
    #[serde(rename = "RightName")]
    right_name: String,
    #[serde(rename = "PrincipalSID")]
    principal_sid: String,
    #[serde(rename = "PrincipalType")]
    principal_type: String,
}

/// BloodHound 域条目
#[derive(Serialize, Clone)]
struct BhDomain {
    #[serde(rename = "ObjectIdentifier")]
    object_identifier: String,
    #[serde(rename = "ObjectType")]
    object_type: String,
    Properties: BhDomainProps,
    #[serde(rename = "Trusts")]
    trusts: Vec<BhDomainTrust>,
    #[serde(rename = "ACEs")]
    aces: Vec<BhAce>,
}

#[derive(Serialize, Clone)]
struct BhDomainProps {
    name: String,
    domain: String,
    distinguishedname: String,
    #[serde(rename = "functionallevel")]
    functional_level: String,
}

#[derive(Serialize, Clone)]
struct BhDomainTrust {
    #[serde(rename = "TargetDomain")]
    target_domain: String,
    #[serde(rename = "TargetDomainSid")]
    target_domain_sid: String,
    #[serde(rename = "IsTransitive")]
    is_transitive: bool,
    #[serde(rename = "TrustDirection")]
    trust_direction: String,
    #[serde(rename = "TrustType")]
    trust_type: String,
}

/// 导出 BloodHound JSON 文件集
pub fn export_bloodhound(result: &AdEnumResult, output_dir: &Path) -> crate::core::Result<()> {
    std::fs::create_dir_all(output_dir)?;

    let domain = &result.domain_name;
    let meta = BhMeta {
        methods: 0,
        version: 5,
    };

    // 用户
    let users: Vec<BhUser> = result.users.iter().map(|u| user_to_bh(u, domain)).collect();
    write_bh_file(&output_dir.join("users.json"), &meta, &users)?;

    // 组
    let groups: Vec<BhGroup> = result.groups.iter().map(|g| group_to_bh(g, domain)).collect();
    write_bh_file(&output_dir.join("groups.json"), &meta, &groups)?;

    // 计算机
    let computers: Vec<BhComputer> = result
        .computers
        .iter()
        .map(|c| computer_to_bh(c, domain))
        .collect();
    write_bh_file(&output_dir.join("computers.json"), &meta, &computers)?;

    // 域
    let domains = vec![domain_to_bh(result)];
    write_bh_file(&output_dir.join("domains.json"), &meta, &domains)?;

    Ok(())
}

#[derive(Serialize, Clone)]
struct BhMeta {
    methods: u32,
    version: u32,
}

fn write_bh_file<T: Serialize + Clone>(
    path: &Path,
    meta: &BhMeta,
    data: &[T],
) -> crate::core::Result<()> {
    #[derive(Serialize)]
    struct BhFile<T: Serialize + Clone> {
        meta: BhMeta,
        data: Vec<T>,
    }

    let file = BhFile {
        meta: meta.clone(),
        data: data.to_vec(),
    };
    let json = serde_json::to_string_pretty(&file)?;
    std::fs::write(path, json)?;
    Ok(())
}

fn user_to_bh(user: &AdUser, domain: &str) -> BhUser {
    let dont_req_preauth = !user
        .spn
        .is_empty(); // simplified; actual check needs UAC flag
    let has_spn = !user.spn.is_empty();

    BhUser {
        // 使用真实 objectSid（来自 LDAP），无 SID 时回退到伪造标识
        object_identifier: user.sid.clone()
            .unwrap_or_else(|| format!("S-1-5-21-UNKNOWN-{}", user.sam_account_name)),
        object_type: "User".to_string(),
        Properties: BhUserProps {
            name: format!("{}@{}", user.sam_account_name, domain).to_uppercase(),
            domain: domain.to_uppercase(),
            distinguishedname: user.dn.clone(),
            description: user.description.clone(),
            email: user.email.clone(),
            admin_count: user.admin_count,
            enabled: user.enabled,
            pwd_never_expires: false,
            sensitive: false,
            dont_req_preauth,
            password_not_reqd: false,
            spn_targets: user
                .spn
                .iter()
                .map(|s| BhSpnTarget {
                    service: s.split('/').next().unwrap_or("").to_uppercase(),
                    spn: s.clone(),
                })
                .collect(),
            has_spn,
        },
        aces: vec![],
    }
}

fn group_to_bh(group: &AdGroup, domain: &str) -> BhGroup {
    BhGroup {
        object_identifier: group.sid.clone()
            .unwrap_or_else(|| format!("S-1-5-21-UNKNOWN-{}", group.name)),
        object_type: "Group".to_string(),
        Properties: BhGroupProps {
            name: format!("{}@{}", group.name, domain).to_uppercase(),
            domain: domain.to_uppercase(),
            distinguishedname: group.dn.clone(),
            description: group.description.clone(),
            admin_count: group.admin_count,
        },
        Members: group
            .members
            .iter()
            .map(|m| BhMember {
                object_identifier: format!("S-1-5-21-{}", extract_cn(m)),
                object_type: if m.contains("OU=Users") || m.contains("CN=Users") {
                    "User".to_string()
                } else {
                    "Group".to_string()
                },
            })
            .collect(),
        aces: vec![],
    }
}

fn computer_to_bh(computer: &AdComputer, domain: &str) -> BhComputer {
    let name = computer.name.trim_end_matches('$');
    BhComputer {
        object_identifier: computer.sid.clone()
            .unwrap_or_else(|| format!("S-1-5-21-UNKNOWN-{}", computer.name)),
        object_type: "Computer".to_string(),
        Properties: BhComputerProps {
            name: format!("{}.{}", name, domain).to_uppercase(),
            domain: domain.to_uppercase(),
            distinguishedname: computer.dn.clone(),
            os: computer.os.clone(),
            enabled: computer.enabled,
        },
        aces: vec![],
        local_groups: vec![],
    }
}

fn domain_to_bh(result: &AdEnumResult) -> BhDomain {
    let domain = &result.domain_name;
    let dn = ldap_domain_dn(domain);

    BhDomain {
        object_identifier: format!("S-1-5-21-{}", domain),
        object_type: "Domain".to_string(),
        Properties: BhDomainProps {
            name: domain.to_uppercase(),
            domain: domain.to_uppercase(),
            distinguishedname: dn,
            functional_level: "Unknown".to_string(),
        },
        trusts: result
            .trusts
            .iter()
            .map(|t| BhDomainTrust {
                target_domain: t.domain.to_uppercase(),
                target_domain_sid: format!("S-1-5-21-{}", t.domain),
                is_transitive: t.trust_attributes.contains("可传递"),
                trust_direction: t.trust_direction.clone(),
                trust_type: t.trust_type.clone(),
            })
            .collect(),
        aces: vec![],
    }
}

fn extract_cn(dn: &str) -> String {
    dn.split(',')
        .next()
        .unwrap_or("")
        .trim_start_matches("CN=")
        .to_string()
}

fn ldap_domain_dn(domain: &str) -> String {
    domain
        .split('.')
        .map(|p| format!("DC={}", p))
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_cn() {
        assert_eq!(extract_cn("CN=Admin,CN=Users,DC=corp,DC=local"), "Admin");
        assert_eq!(extract_cn("CN=Domain Admins,CN=Users,DC=corp"), "Domain Admins");
    }

    #[test]
    fn test_ldap_domain_dn() {
        assert_eq!(ldap_domain_dn("corp.local"), "DC=corp,DC=local");
    }
}
