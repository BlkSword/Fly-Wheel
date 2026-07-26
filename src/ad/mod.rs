//! Active Directory 深度枚举模块
//!
//! 提供 LDAP 查询、Kerberoasting、AS-REP Roasting 和 BloodHound 输出

pub mod bloodhound;
pub mod ldap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// AD 枚举结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdEnumResult {
    pub domain_name: String,
    pub domain_controller: Option<String>,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub duration_secs: f64,
    pub users: Vec<AdUser>,
    pub groups: Vec<AdGroup>,
    pub computers: Vec<AdComputer>,
    pub kerberoast_targets: Vec<KerberoastTarget>,
    pub asrep_targets: Vec<AsrepTarget>,
    pub gpos: Vec<String>,
    pub trusts: Vec<AdTrust>,
    pub stats: AdEnumStats,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AdEnumStats {
    pub users_found: usize,
    pub groups_found: usize,
    pub computers_found: usize,
    pub kerberoast_targets: usize,
    pub asrep_targets: usize,
    pub gpos_found: usize,
    pub trusts_found: usize,
    pub admin_accounts: usize,
    pub da_accounts: usize,
}

/// AD 用户
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdUser {
    pub sam_account_name: String,
    pub display_name: Option<String>,
    pub dn: String,
    pub description: Option<String>,
    pub email: Option<String>,
    pub admin_count: bool,
    pub enabled: bool,
    pub password_expired: bool,
    pub last_logon: Option<String>,
    pub member_of: Vec<String>,
    pub spn: Vec<String>,
    pub sid: Option<String>,
}

/// AD 组
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdGroup {
    pub name: String,
    pub dn: String,
    pub description: Option<String>,
    pub members: Vec<String>,
    pub admin_count: bool,
    pub sid: Option<String>,
}

/// AD 计算机
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdComputer {
    pub name: String,
    pub dn: String,
    pub dns_hostname: Option<String>,
    pub os: Option<String>,
    pub os_version: Option<String>,
    pub enabled: bool,
    pub last_logon: Option<String>,
    pub sid: Option<String>,
}

/// Kerberoasting 目标
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KerberoastTarget {
    pub username: String,
    pub dn: String,
    pub spn: String,
    pub service_type: String,
    pub admin_count: bool,
    pub enabled: bool,
    pub description: Option<String>,
}

/// AS-REP Roasting 目标
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsrepTarget {
    pub username: String,
    pub dn: String,
    pub enabled: bool,
    pub description: Option<String>,
}

/// AD 信任关系
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdTrust {
    pub domain: String,
    pub trust_type: String,
    pub trust_direction: String,
    pub trust_attributes: String,
}

impl Default for AdEnumResult {
    fn default() -> Self {
        Self {
            domain_name: String::new(),
            domain_controller: None,
            start_time: Utc::now(),
            end_time: Utc::now(),
            duration_secs: 0.0,
            users: Vec::new(),
            groups: Vec::new(),
            computers: Vec::new(),
            kerberoast_targets: Vec::new(),
            asrep_targets: Vec::new(),
            gpos: Vec::new(),
            trusts: Vec::new(),
            stats: AdEnumStats::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // === 辅助函数 ===

    fn make_user(name: &str, admin: bool) -> AdUser {
        AdUser {
            sam_account_name: name.to_string(),
            display_name: Some(format!("Display {}", name)),
            dn: format!("CN={},CN=Users,DC=corp,DC=local", name),
            description: Some("测试用户".to_string()),
            email: Some(format!("{}@corp.local", name)),
            admin_count: admin,
            enabled: true,
            password_expired: false,
            last_logon: Some("2024-01-01T00:00:00Z".to_string()),
            member_of: vec!["CN=Domain Admins,CN=Users,DC=corp,DC=local".to_string()],
            spn: vec![],
            sid: Some("S-1-5-21-3623811015-3361044348-30300820-1013".to_string()),
        }
    }

    fn make_group(name: &str) -> AdGroup {
        AdGroup {
            name: name.to_string(),
            dn: format!("CN={},CN=Users,DC=corp,DC=local", name),
            description: Some("测试组".to_string()),
            members: vec!["CN=Administrator,CN=Users,DC=corp,DC=local".to_string()],
            admin_count: name.contains("Admin"),
            sid: None,
        }
    }

    fn make_computer(name: &str) -> AdComputer {
        AdComputer {
            name: name.to_string(),
            dn: format!("CN={},CN=Computers,DC=corp,DC=local", name),
            dns_hostname: Some(format!("{}.corp.local", name)),
            os: Some("Windows Server 2022".to_string()),
            os_version: Some("10.0 (20348)".to_string()),
            enabled: true,
            last_logon: Some("2024-01-01T00:00:00Z".to_string()),
            sid: None,
        }
    }

    // === AdEnumStats ===

    #[test]
    fn test_ad_enum_stats_default() {
        let stats = AdEnumStats::default();
        assert_eq!(stats.users_found, 0);
        assert_eq!(stats.groups_found, 0);
        assert_eq!(stats.computers_found, 0);
        assert_eq!(stats.kerberoast_targets, 0);
        assert_eq!(stats.asrep_targets, 0);
        assert_eq!(stats.gpos_found, 0);
        assert_eq!(stats.trusts_found, 0);
        assert_eq!(stats.admin_accounts, 0);
        assert_eq!(stats.da_accounts, 0);
    }

    #[test]
    fn test_ad_enum_stats_json_roundtrip() {
        let stats = AdEnumStats {
            users_found: 100,
            groups_found: 50,
            computers_found: 30,
            kerberoast_targets: 5,
            asrep_targets: 2,
            gpos_found: 20,
            trusts_found: 3,
            admin_accounts: 10,
            da_accounts: 5,
        };
        let json = serde_json::to_string(&stats).expect("序列化应成功");
        let deserialized: AdEnumStats = serde_json::from_str(&json).expect("反序列化应成功");
        assert_eq!(deserialized.users_found, 100);
        assert_eq!(deserialized.da_accounts, 5);
    }

    // === AdUser ===

    #[test]
    fn test_ad_user_construction() {
        let user = make_user("Administrator", true);
        assert_eq!(user.sam_account_name, "Administrator");
        assert!(user.admin_count);
        assert!(user.enabled);
        assert!(!user.password_expired);
        assert!(user.member_of.iter().any(|m| m.contains("Domain Admins")));
        assert!(user.sid.is_some());
    }

    #[test]
    fn test_ad_user_json_roundtrip() {
        let user = make_user("testuser", false);
        let json = serde_json::to_string(&user).expect("序列化应成功");
        assert!(json.contains("testuser"));
        assert!(json.contains("corp.local"));
        let deserialized: AdUser = serde_json::from_str(&json).expect("反序列化应成功");
        assert_eq!(deserialized.sam_account_name, "testuser");
        assert!(!deserialized.admin_count);
    }

    #[test]
    fn test_ad_user_disabled() {
        let user = AdUser {
            sam_account_name: "disabled_user".to_string(),
            display_name: None,
            dn: "CN=Disabled,CN=Users,DC=corp,DC=local".to_string(),
            description: None,
            email: None,
            admin_count: false,
            enabled: false,
            password_expired: true,
            last_logon: None,
            member_of: vec![],
            spn: vec![],
            sid: None,
        };
        assert!(!user.enabled);
        assert!(user.password_expired);
        assert!(user.display_name.is_none());
    }

    // === AdGroup ===

    #[test]
    fn test_ad_group_construction() {
        let group = make_group("Domain Admins");
        assert_eq!(group.name, "Domain Admins");
        assert!(group.admin_count);
        assert!(!group.members.is_empty());
    }

    #[test]
    fn test_ad_group_json_roundtrip() {
        let group = make_group("IT Team");
        let json = serde_json::to_string(&group).expect("序列化应成功");
        assert!(json.contains("IT Team"));
        let deserialized: AdGroup = serde_json::from_str(&json).expect("反序列化应成功");
        assert_eq!(deserialized.name, "IT Team");
    }

    // === AdComputer ===

    #[test]
    fn test_ad_computer_construction() {
        let computer = make_computer("DC01");
        assert_eq!(computer.name, "DC01");
        assert_eq!(computer.dns_hostname.as_deref(), Some("DC01.corp.local"));
        assert!(computer.enabled);
        assert!(computer.os.is_some());
    }

    #[test]
    fn test_ad_computer_json_roundtrip() {
        let computer = make_computer("WS001");
        let json = serde_json::to_string(&computer).expect("序列化应成功");
        assert!(json.contains("WS001"));
        assert!(json.contains("Windows"));
        let deserialized: AdComputer = serde_json::from_str(&json).expect("反序列化应成功");
        assert_eq!(deserialized.name, "WS001");
    }

    // === KerberoastTarget ===

    #[test]
    fn test_kerberoast_target_construction() {
        let target = KerberoastTarget {
            username: "svc_sql".to_string(),
            dn: "CN=svc_sql,CN=Users,DC=corp,DC=local".to_string(),
            spn: "MSSQLSvc/sql01.corp.local:1433".to_string(),
            service_type: "MSSQLSvc".to_string(),
            admin_count: false,
            enabled: true,
            description: Some("SQL Service Account".to_string()),
        };
        assert_eq!(target.username, "svc_sql");
        assert_eq!(target.service_type, "MSSQLSvc");
        assert!(target.enabled);
        assert!(!target.admin_count);
    }

    #[test]
    fn test_kerberoast_target_json_roundtrip() {
        let target = KerberoastTarget {
            username: "svc_web".to_string(),
            dn: "CN=svc_web,CN=Users,DC=corp,DC=local".to_string(),
            spn: "HTTP/webserver.corp.local".to_string(),
            service_type: "HTTP".to_string(),
            admin_count: true,
            enabled: false,
            description: None,
        };
        let json = serde_json::to_string(&target).expect("序列化应成功");
        assert!(json.contains("svc_web"));
        assert!(json.contains("HTTP"));
        let deserialized: KerberoastTarget = serde_json::from_str(&json).expect("反序列化应成功");
        assert_eq!(deserialized.spn, "HTTP/webserver.corp.local");
        assert!(!deserialized.enabled);
    }

    // === AsrepTarget ===

    #[test]
    fn test_asrep_target_construction() {
        let target = AsrepTarget {
            username: "no_preauth_user".to_string(),
            dn: "CN=no_preauth_user,CN=Users,DC=corp,DC=local".to_string(),
            enabled: true,
            description: Some("不需要 Kerberos 预认证".to_string()),
        };
        assert_eq!(target.username, "no_preauth_user");
        assert!(target.enabled);
        assert!(target.description.is_some());
    }

    // === AdTrust ===

    #[test]
    fn test_ad_trust_construction() {
        let trust = AdTrust {
            domain: "child.corp.local".to_string(),
            trust_type: "ParentChild".to_string(),
            trust_direction: "Bidirectional".to_string(),
            trust_attributes: "TRANSITIVE".to_string(),
        };
        assert_eq!(trust.domain, "child.corp.local");
        assert_eq!(trust.trust_type, "ParentChild");
    }

    // === AdEnumResult ===

    #[test]
    fn test_ad_enum_result_default() {
        let result = AdEnumResult::default();
        assert!(result.domain_name.is_empty());
        assert!(result.users.is_empty());
        assert!(result.groups.is_empty());
        assert_eq!(result.duration_secs, 0.0);
        assert!(result.domain_controller.is_none());
    }

    #[test]
    fn test_ad_enum_result_full() {
        let mut result = AdEnumResult::default();
        result.domain_name = "corp.local".to_string();
        result.domain_controller = Some("192.168.1.10".to_string());
        result.users = vec![make_user("admin", true), make_user("user1", false)];
        result.groups = vec![make_group("Domain Admins"), make_group("Users")];
        result.computers = vec![make_computer("DC01"), make_computer("WS001")];
        result.kerberoast_targets = vec![KerberoastTarget {
            username: "svc_sql".to_string(), dn: "CN=svc_sql,CN=Users,DC=corp,DC=local".to_string(),
            spn: "MSSQLSvc/sql01.corp.local:1433".to_string(), service_type: "MSSQLSvc".to_string(),
            admin_count: false, enabled: true, description: None,
        }];
        result.asrep_targets = vec![AsrepTarget {
            username: "no_preauth".to_string(), dn: "CN=no_preauth,CN=Users,DC=corp,DC=local".to_string(),
            enabled: true, description: None,
        }];
        result.gpos = vec!["Default Domain Policy".to_string()];
        result.trusts = vec![AdTrust {
            domain: "child.corp.local".to_string(), trust_type: "ParentChild".to_string(),
            trust_direction: "Bidirectional".to_string(), trust_attributes: "TRANSITIVE".to_string(),
        }];

        assert_eq!(result.domain_name, "corp.local");
        assert_eq!(result.users.len(), 2);
        assert_eq!(result.groups.len(), 2);
        assert_eq!(result.computers.len(), 2);
        assert_eq!(result.kerberoast_targets.len(), 1);
        assert_eq!(result.asrep_targets.len(), 1);
        assert_eq!(result.gpos.len(), 1);
        assert_eq!(result.trusts.len(), 1);
    }

    #[test]
    fn test_ad_enum_result_json_roundtrip() {
        let mut result = AdEnumResult::default();
        result.domain_name = "corp.local".to_string();
        result.users = vec![make_user("admin", true)];
        result.groups = vec![make_group("Domain Admins")];
        result.computers = vec![make_computer("DC01")];

        let json = serde_json::to_string(&result).expect("序列化应成功");
        assert!(json.contains("corp.local"));
        assert!(json.contains("admin"));
        assert!(json.contains("Domain Admins"));
        assert!(json.contains("DC01"));

        let deserialized: AdEnumResult = serde_json::from_str(&json).expect("反序列化应成功");
        assert_eq!(deserialized.domain_name, "corp.local");
        assert_eq!(deserialized.users.len(), 1);
        assert_eq!(deserialized.groups.len(), 1);
        assert_eq!(deserialized.computers.len(), 1);
    }

    // === domain_to_dn 函数 ===

    #[test]
    fn test_domain_to_dn_single_label() {
        let dn = crate::ad::ldap::domain_to_dn("corp");
        assert_eq!(dn, "DC=corp");
    }

    #[test]
    fn test_domain_to_dn_standard() {
        let dn = crate::ad::ldap::domain_to_dn("corp.local");
        assert_eq!(dn, "DC=corp,DC=local");
    }

    #[test]
    fn test_domain_to_dn_subdomain() {
        let dn = crate::ad::ldap::domain_to_dn("child.parent.local");
        assert_eq!(dn, "DC=child,DC=parent,DC=local");
    }

    #[test]
    fn test_domain_to_dn_empty() {
        let dn = crate::ad::ldap::domain_to_dn("");
        assert_eq!(dn, "DC=");
    }
}
