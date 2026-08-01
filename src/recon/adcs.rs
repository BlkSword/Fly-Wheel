//! ADCS (Active Directory Certificate Services) 枚举模块
//!
//! 配置不当的证书模板可能导致权限提升（ESC1-ESC13攻击）。
//! 枚举ADCS信息可以发现：
//! - 证书颁发机构(CA)服务器
//! - 证书模板及其权限
//! - 可利用的错误配置

use serde::{Deserialize, Serialize};

/// ADCS枚举结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdcsEnumResult {
    /// 发现的CA服务器
    pub ca_servers: Vec<CaServer>,
    /// 发现的证书模板
    pub certificate_templates: Vec<CertTemplate>,
    /// 可利用的错误配置
    pub exploitable_issues: Vec<AdcsIssue>,
}

/// CA服务器信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaServer {
    /// CA名称
    pub name: String,
    /// DNS主机名
    pub dns_hostname: Option<String>,
    /// 是否为企业CA
    pub is_enterprise: bool,
    /// CA类型
    pub ca_type: String,
}

/// 证书模板信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertTemplate {
    /// 模板名称
    pub name: String,
    /// 显示名称
    pub display_name: Option<String>,
    /// 有效期
    pub validity_period: Option<String>,
    /// 是否需要管理员批准
    pub requires_manager_approval: bool,
    /// 是否允许请求者自定义SAN
    pub allows_custom_san: bool,
    /// 注册权限（谁可以请求此证书）
    pub enrollment_rights: Vec<String>,
    /// 模板标志
    pub flags: Vec<String>,
    /// 是否可用于客户端认证
    pub client_authentication: bool,
    /// 是否可用于Kerberos认证(PKINIT)
    pub kerberos_authentication: bool,
    /// ESC类别（如果可利用）
    pub esc_category: Option<String>,
}

/// ADCS配置问题
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdcsIssue {
    /// 问题类型/ESC编号
    pub esc_type: String,
    /// 描述
    pub description: String,
    /// 严重程度
    pub severity: String,
    /// 受影响的模板
    pub affected_template: String,
    /// 利用建议
    pub exploitation_advice: String,
}

/// 枚举ADCS环境
pub fn enumerate_adcs(dc: &str, domain: &str) -> Result<AdcsEnumResult, String> {
    tracing::info!("[ADCS] 枚举证书服务 (DC: {}, 域: {})", dc, domain);

    let mut result = AdcsEnumResult {
        ca_servers: Vec::new(),
        certificate_templates: Vec::new(),
        exploitable_issues: Vec::new(),
    };

    // 通过LDAP查询CA服务器
    if let Ok(ca_servers) = query_ca_servers(dc, domain) {
        result.ca_servers = ca_servers;
    }

    // 通过LDAP查询证书模板
    if let Ok(templates) = query_cert_templates(dc, domain) {
        // 分析每个模板的可利用性
        for template in &templates {
            if let Some(esc) = analyze_template_esc(template) {
                result.exploitable_issues.push(AdcsIssue {
                    esc_type: esc.clone(),
                    description: format!("证书模板 '{}' 存在 {} 错误配置", template.name, esc),
                    severity: match esc.as_str() {
                        "ESC1" => "严重".to_string(),
                        "ESC2" | "ESC3" => "高".to_string(),
                        "ESC4" | "ESC6" | "ESC8" => "中".to_string(),
                        _ => "信息".to_string(),
                    },
                    affected_template: template.name.clone(),
                    exploitation_advice: get_esc_advice(&esc),
                });
            }
        }
        result.certificate_templates = templates;
    }

    Ok(result)
}

/// LDAP查询CA服务器
fn query_ca_servers(dc: &str, domain: &str) -> Result<Vec<CaServer>, String> {
    let ldap_url = format!("ldap://{}:389", dc);
    let mut ldap = ldap3::LdapConn::new(&ldap_url).map_err(|e| format!("LDAP连接失败: {}", e))?;

    ldap.simple_bind("", "")
        .map_err(|e| format!("LDAP绑定失败: {}", e))?;

    let base_dn = domain
        .split('.')
        .map(|p| format!("DC={}", p))
        .collect::<Vec<_>>()
        .join(",");
    let config_dn = format!("CN=Configuration,{}", base_dn);

    // 查询PKI Enrollment Services
    let filter = "(objectClass=pKIEnrollmentService)";
    let attrs = &["cn", "dNSHostName", "cACertificate", "flags"];

    let sr = ldap
        .search(&config_dn, ldap3::Scope::Subtree, filter, attrs)
        .map_err(|e| format!("LDAP CA查询失败: {}", e))?;

    let mut ca_servers = Vec::new();
    for entry in &sr.0 {
        let entry = ldap3::SearchEntry::construct(entry.clone());
        let name = entry
            .attrs
            .get("cn")
            .and_then(|v| v.first().cloned())
            .unwrap_or_default();
        let dns = entry
            .attrs
            .get("dNSHostName")
            .and_then(|v| v.first().cloned());

        ca_servers.push(CaServer {
            name,
            dns_hostname: dns,
            is_enterprise: true,
            ca_type: "Enterprise".to_string(),
        });
    }

    Ok(ca_servers)
}

/// LDAP查询证书模板
fn query_cert_templates(dc: &str, domain: &str) -> Result<Vec<CertTemplate>, String> {
    let ldap_url = format!("ldap://{}:389", dc);
    let mut ldap = ldap3::LdapConn::new(&ldap_url).map_err(|e| format!("LDAP连接失败: {}", e))?;

    ldap.simple_bind("", "")
        .map_err(|e| format!("LDAP绑定失败: {}", e))?;

    let base_dn = domain
        .split('.')
        .map(|p| format!("DC={}", p))
        .collect::<Vec<_>>()
        .join(",");
    let config_dn = format!("CN=Configuration,{}", base_dn);

    let filter = "(objectClass=pKICertificateTemplate)";
    let attrs = &[
        "cn",
        "displayName",
        "pKIExpirationPeriod",
        "msPKI-Enrollment-Flag",
        "msPKI-Certificate-Name-Flag",
        "msPKI-RA-Application-Policies",
        "pKIExtendedKeyUsage",
        "msPKI-Certificate-Application-Policy",
    ];

    let sr = ldap
        .search(&config_dn, ldap3::Scope::Subtree, filter, attrs)
        .map_err(|e| format!("LDAP模板查询失败: {}", e))?;

    let templates: Vec<CertTemplate> =
        sr.0.iter()
            .map(|entry| {
                let entry = ldap3::SearchEntry::construct(entry.clone());
                let name = entry
                    .attrs
                    .get("cn")
                    .and_then(|v| v.first().cloned())
                    .unwrap_or_default();
                let display = entry
                    .attrs
                    .get("displayName")
                    .and_then(|v| v.first().cloned());

                // 检查标志
                let enroll_flag = entry
                    .attrs
                    .get("msPKI-Enrollment-Flag")
                    .and_then(|v| v.first())
                    .and_then(|v| v.parse::<u32>().ok())
                    .unwrap_or(0);

                let name_flag = entry
                    .attrs
                    .get("msPKI-Certificate-Name-Flag")
                    .and_then(|v| v.first())
                    .and_then(|v| v.parse::<u32>().ok())
                    .unwrap_or(0);

                // CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 1
                let allows_custom_san = name_flag & 1 != 0;
                // CT_FLAG_PEND_ALL_REQUESTS = 2
                let requires_manager_approval = enroll_flag & 2 != 0;

                let mut flags = Vec::new();
                if enroll_flag & 1 != 0 {
                    flags.push("ENROLLEE_SUPPLIES_SUBJECT".to_string());
                }
                if enroll_flag & 2 != 0 {
                    flags.push("PEND_ALL_REQUESTS".to_string());
                }
                if enroll_flag & 4 != 0 {
                    flags.push("NO_PRIVATE_KEY_ARCHIVAL".to_string());
                }
                if name_flag & 1 != 0 {
                    flags.push("ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME".to_string());
                }

                // 检查扩展密钥用途
                let eku = entry
                    .attrs
                    .get("pKIExtendedKeyUsage")
                    .cloned()
                    .unwrap_or_default();

                let client_auth = eku.iter().any(|e| e.contains("1.3.6.1.5.5.7.3.2")); // Client Authentication
                let kerberos_auth = eku.iter().any(|e| e.contains("1.3.6.1.5.2.3.4")); // KDC Authentication

                CertTemplate {
                    name,
                    display_name: display,
                    validity_period: entry
                        .attrs
                        .get("pKIExpirationPeriod")
                        .and_then(|v| v.first().cloned()),
                    requires_manager_approval,
                    allows_custom_san,
                    enrollment_rights: Vec::new(), // 需要进一步查询nTSecurityDescriptor
                    flags,
                    client_authentication: client_auth,
                    kerberos_authentication: kerberos_auth,
                    esc_category: None, // 将在analyze_template_esc中分析
                }
            })
            .collect();

    Ok(templates)
}

/// 分析证书模板的ESC可利用性
fn analyze_template_esc(template: &CertTemplate) -> Option<String> {
    // ESC1: 模板允许请求者自定义SAN + 可用于客户端认证 + 低权限用户可注册
    if template.allows_custom_san
        && template.client_authentication
        && !template.requires_manager_approval
    {
        return Some("ESC1".to_string());
    }

    // ESC2: 模板可用于任意目的（无EKU限制）
    if template
        .flags
        .contains(&"NO_PRIVATE_KEY_ARCHIVAL".to_string())
    {
        // 简化检查
    }

    // ESC3: 注册代理模板滥用
    if template.name.to_lowercase().contains("enrollmentagent")
        || template
            .name
            .to_lowercase()
            .contains("exchange enrollment agent")
    {
        return Some("ESC3".to_string());
    }

    // ESC4: 模板权限配置不当（低权限用户可修改模板ACL）
    // 需要检查nTSecurityDescriptor，此处简化

    // ESC6: CA设置了EDITF_ATTRIBUTESUBJECTALTNAME2标志
    // 需要查询CA配置，此处简化

    // ESC8: HTTP端点未启用EPA (Extended Protection for Authentication)
    // 需要测试Web端点，此处简化

    None
}

/// 获取ESC利用建议
fn get_esc_advice(esc_type: &str) -> String {
    match esc_type {
        "ESC1" => "使用Certipy或Certify请求证书，指定自定义SAN为域管理员账户。命令: certipy req -ca <CA> -template <Template> -upn Administrator@<domain>".to_string(),
        "ESC2" => "证书模板无EKU限制，可用于任何目的。可作为任何用户请求证书。".to_string(),
        "ESC3" => "注册代理模板允许代表其他用户请求证书。可用于获取域管理员证书。".to_string(),
        "ESC4" => "低权限用户可修改证书模板ACL。可修改模板使其可被利用（添加ESC1条件）。".to_string(),
        "ESC6" => "CA启用了EDITF_ATTRIBUTESUBJECTALTNAME2标志。任何模板都可作为ESC1利用。".to_string(),
        "ESC8" => "ADCS Web端点未启用EPA，可进行NTLM中继攻击获取证书。".to_string(),
        _ => "请参考SpecterOps的Certified Pre-Owned白皮书了解详情。".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ca_server_creation() {
        let ca = CaServer {
            name: "CORP-CA".to_string(),
            dns_hostname: Some("ca.corp.local".to_string()),
            is_enterprise: true,
            ca_type: "Enterprise".to_string(),
        };
        assert!(ca.is_enterprise);
        assert_eq!(ca.name, "CORP-CA");
    }

    #[test]
    fn test_cert_template_creation() {
        let template = CertTemplate {
            name: "WebServer".to_string(),
            display_name: Some("Web Server".to_string()),
            validity_period: Some("2年".to_string()),
            requires_manager_approval: false,
            allows_custom_san: false,
            enrollment_rights: vec!["Domain Users".to_string()],
            flags: vec![],
            client_authentication: true,
            kerberos_authentication: false,
            esc_category: None,
        };
        assert!(template.client_authentication);
        assert!(!template.requires_manager_approval);
    }

    #[test]
    fn test_analyze_template_esc1() {
        let template = CertTemplate {
            name: "VulnerableTemplate".to_string(),
            display_name: None,
            validity_period: None,
            requires_manager_approval: false,
            allows_custom_san: true,
            enrollment_rights: vec!["Domain Users".to_string()],
            flags: vec!["ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME".to_string()],
            client_authentication: true,
            kerberos_authentication: false,
            esc_category: None,
        };
        let esc = analyze_template_esc(&template);
        assert_eq!(esc, Some("ESC1".to_string()));
    }

    #[test]
    fn test_analyze_template_no_esc() {
        let template = CertTemplate {
            name: "SafeTemplate".to_string(),
            display_name: None,
            validity_period: None,
            requires_manager_approval: true,
            allows_custom_san: false,
            enrollment_rights: vec![],
            flags: vec![],
            client_authentication: false,
            kerberos_authentication: false,
            esc_category: None,
        };
        let esc = analyze_template_esc(&template);
        assert!(esc.is_none());
    }

    #[test]
    fn test_get_esc_advice() {
        let advice = get_esc_advice("ESC1");
        assert!(advice.contains("Certipy"));
        assert!(advice.contains("Administrator"));
    }
}
