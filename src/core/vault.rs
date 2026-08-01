//! 凭据安全存储模块 (Credential Vault)
//!
//! 提供 XChaCha20-Poly1305 加密的凭据本地存储。
//! 爆破结果和收集到的凭据加密存储到文件，防止明文泄露。
//!
//! 密钥派生: HMAC-SHA256 萃取器 (与隧道加密一致)
//! 加密: XChaCha20-Poly1305 AEAD

use crate::core::error::{IntraSweepError, Result};
use rand::Rng;
use serde::{Deserialize, Serialize};

/// 从密码和盐派生 32 字节密钥
fn derive_vault_key(password: &str, salt: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    // 简化的密钥派生: SHA-256(password || salt)
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(salt);
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

// ============================================================
// 凭据保险库
// ============================================================

/// 凭据条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEntry {
    /// 服务名称
    pub service: String,
    /// 目标主机
    pub target: String,
    /// 端口
    pub port: u16,
    /// 用户名
    pub username: Option<String>,
    /// 密码/凭据
    pub credential: String,
    /// 发现时间 (ISO 8601)
    pub discovered_at: String,
    /// 来源（爆破/收集/手动）
    pub source: String,
    /// 备注
    pub note: Option<String>,
}

/// 凭据保险库
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vault {
    /// 凭据条目列表
    pub entries: Vec<VaultEntry>,
    /// 保险库创建时间
    pub created_at: String,
    /// 保险库版本
    pub version: String,
}

impl Vault {
    /// 创建新的空保险库
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            created_at: chrono::Utc::now().to_rfc3339(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    /// 添加凭据条目
    pub fn add_entry(&mut self, entry: VaultEntry) {
        self.entries.push(entry);
    }

    /// 获取凭据数量
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// 按服务过滤凭据
    pub fn filter_by_service(&self, service: &str) -> Vec<&VaultEntry> {
        self.entries
            .iter()
            .filter(|e| e.service.eq_ignore_ascii_case(service))
            .collect()
    }

    /// 按目标过滤凭据
    pub fn filter_by_target(&self, target: &str) -> Vec<&VaultEntry> {
        self.entries
            .iter()
            .filter(|e| e.target.contains(target))
            .collect()
    }

    /// 搜索凭据（模糊匹配所有字段）
    pub fn search(&self, query: &str) -> Vec<&VaultEntry> {
        let query_lower = query.to_lowercase();
        self.entries
            .iter()
            .filter(|e| {
                e.service.to_lowercase().contains(&query_lower)
                    || e.target.to_lowercase().contains(&query_lower)
                    || e.username
                        .as_deref()
                        .map(|u| u.to_lowercase().contains(&query_lower))
                        .unwrap_or(false)
                    || e.credential.to_lowercase().contains(&query_lower)
            })
            .collect()
    }

    /// 序列化为 JSON
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(IntraSweepError::Serialization)
    }

    /// 从 JSON 反序列化
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(IntraSweepError::Serialization)
    }

    /// 加密并保存到文件
    pub fn save_encrypted(&self, path: &std::path::Path, password: &str) -> Result<()> {
        let json = self.to_json()?;
        let encrypted = encrypt_data(&json.into_bytes(), password)?;
        std::fs::write(path, &encrypted).map_err(IntraSweepError::Io)?;
        Ok(())
    }

    /// 从加密文件加载
    pub fn load_encrypted(path: &std::path::Path, password: &str) -> Result<Self> {
        let encrypted = std::fs::read(path).map_err(IntraSweepError::Io)?;
        let decrypted = decrypt_data(&encrypted, password)?;
        let json = String::from_utf8(decrypted).map_err(|e| IntraSweepError::Other {
            message: format!("UTF-8 解码失败: {}", e),
        })?;
        Self::from_json(&json)
    }
}

impl Default for Vault {
    fn default() -> Self {
        Self::new()
    }
}

/// 加密数据
fn encrypt_data(data: &[u8], password: &str) -> Result<Vec<u8>> {
    let mut rng = rand::thread_rng();

    let mut salt = [0u8; 32];
    rng.fill(&mut salt);

    let key = derive_vault_key(password, &salt);
    let crypto = crate::tunnel::crypto::CryptoLayer::new(&key);
    let frame = crypto.encrypt(data).map_err(|e| IntraSweepError::Other {
        message: format!("加密失败: {}", e),
    })?;

    // frame: [4B len][24B nonce][ciphertext+tag]
    // vault: magic(24) || salt(32) || frame
    let mut result = Vec::new();
    // 24 字节 magic header
    result.extend_from_slice(b"INTRASWEEP_VAULT_V1\0\0\0\0\0");
    result.extend_from_slice(&salt);
    result.extend_from_slice(&frame);
    Ok(result)
}

/// 解密数据
fn decrypt_data(encrypted: &[u8], password: &str) -> Result<Vec<u8>> {
    if encrypted.len() < 60 {
        return Err(IntraSweepError::Other {
            message: "加密数据格式无效：数据太短".to_string(),
        });
    }

    let magic = &encrypted[..24];
    if !magic.starts_with(b"INTRASWEEP_VAULT_V1") {
        return Err(IntraSweepError::Other {
            message: "加密数据格式无效：未知的头部标记".to_string(),
        });
    }

    let salt: [u8; 32] = encrypted[24..56]
        .try_into()
        .map_err(|_| IntraSweepError::Other {
            message: "数据格式错误".to_string(),
        })?;
    let frame = &encrypted[56..];

    let key = derive_vault_key(password, &salt);
    let crypto = crate::tunnel::crypto::CryptoLayer::new(&key);

    // frame: [4B len][24B nonce][ciphertext+tag]
    if frame.len() < 4 {
        return Err(IntraSweepError::Other {
            message: "加密数据损坏".to_string(),
        });
    }
    let nonce_and_ct = &frame[4..];
    let plaintext = crypto
        .decrypt_frame(nonce_and_ct)
        .map_err(|e| IntraSweepError::Other {
            message: format!("解密失败: {}", e),
        })?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_creation() {
        let vault = Vault::new();
        assert_eq!(vault.entry_count(), 0);
        assert!(!vault.created_at.is_empty());
    }

    #[test]
    fn test_vault_add_entry() {
        let mut vault = Vault::new();
        vault.add_entry(VaultEntry {
            service: "SSH".to_string(),
            target: "192.168.1.100".to_string(),
            port: 22,
            username: Some("root".to_string()),
            credential: "toor".to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
            source: "爆破".to_string(),
            note: None,
        });
        assert_eq!(vault.entry_count(), 1);
    }

    #[test]
    fn test_vault_filter_by_service() {
        let mut vault = Vault::new();
        vault.add_entry(VaultEntry {
            service: "SSH".to_string(),
            target: "host1".to_string(),
            port: 22,
            username: Some("root".to_string()),
            credential: "pass1".to_string(),
            discovered_at: "".to_string(),
            source: "".to_string(),
            note: None,
        });
        vault.add_entry(VaultEntry {
            service: "RDP".to_string(),
            target: "host2".to_string(),
            port: 3389,
            username: Some("admin".to_string()),
            credential: "pass2".to_string(),
            discovered_at: "".to_string(),
            source: "".to_string(),
            note: None,
        });

        let ssh = vault.filter_by_service("ssh");
        assert_eq!(ssh.len(), 1);
        assert_eq!(ssh[0].target, "host1");
    }

    #[test]
    fn test_vault_search() {
        let mut vault = Vault::new();
        vault.add_entry(VaultEntry {
            service: "MySQL".to_string(),
            target: "db-server".to_string(),
            port: 3306,
            username: Some("root".to_string()),
            credential: "mysql_pass".to_string(),
            discovered_at: "".to_string(),
            source: "".to_string(),
            note: None,
        });

        let results = vault.search("mysql");
        assert_eq!(results.len(), 1);

        let results = vault.search("nonexistent");
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_vault_json_roundtrip() {
        let mut vault = Vault::new();
        vault.add_entry(VaultEntry {
            service: "SSH".to_string(),
            target: "test".to_string(),
            port: 22,
            username: Some("user".to_string()),
            credential: "pass".to_string(),
            discovered_at: "2024-01-01T00:00:00Z".to_string(),
            source: "test".to_string(),
            note: None,
        });

        let json = vault.to_json().expect("序列化");
        let loaded = Vault::from_json(&json).expect("反序列化");
        assert_eq!(loaded.entry_count(), 1);
        assert_eq!(loaded.entries[0].service, "SSH");
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        // 使用 tunnel 模块的 CryptoLayer 进行端到端测试
        let key = [0x42u8; 32];
        let crypto = crate::tunnel::crypto::CryptoLayer::new(&key);
        let data = b"test data for roundtrip";
        let frame = crypto.encrypt(data).expect("encrypt");
        // frame format: [4B len][24B nonce][ciphertext+tag]
        let nonce_and_ct = &frame[4..];
        let decrypted = crypto.decrypt_frame(nonce_and_ct).expect("decrypt");
        assert_eq!(decrypted, data);

        // 验证密钥派生的确定性
        let salt = [0xABu8; 32];
        let key1 = derive_vault_key("test-password", &salt);
        let key2 = derive_vault_key("test-password", &salt);
        assert_eq!(key1, key2, "密钥派生应该确定");

        // 然后用 vault 的 encrypt_data/decrypt_data
        let password = "my-secret-vault-key";
        let data2 = b"vault test data";
        let encrypted = encrypt_data(data2, password).expect("vault encrypt");
        assert!(encrypted.starts_with(b"INTRASWEEP_VAULT_V1"));
        let decrypted = decrypt_data(&encrypted, password).expect("vault decrypt");
        assert_eq!(decrypted, data2);
    }

    #[test]
    fn test_encrypt_decrypt_empty() {
        let data = b"";
        let password = "key";

        let encrypted = encrypt_data(data, password).expect("加密");
        let decrypted = decrypt_data(&encrypted, password).expect("解密");
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_decrypt_wrong_password() {
        let data = b"secret";
        let encrypted = encrypt_data(data, "right-password").expect("加密");

        assert!(decrypt_data(&encrypted, "wrong-password").is_err());
    }

    #[test]
    fn test_decrypt_corrupted_data() {
        let data = b"secret";
        let encrypted = encrypt_data(data, "key").expect("加密");

        let mut corrupted = encrypted.clone();
        if corrupted.len() > 64 {
            corrupted[64] ^= 0xFF;
        }

        assert!(decrypt_data(&corrupted, "key").is_err());
    }

    #[test]
    fn test_vault_save_load_encrypted() {
        let mut vault = Vault::new();
        vault.add_entry(VaultEntry {
            service: "RDP".to_string(),
            target: "10.0.0.1".to_string(),
            port: 3389,
            username: Some("Administrator".to_string()),
            credential: "Admin123!".to_string(),
            discovered_at: "2024-06-01T12:00:00Z".to_string(),
            source: "喷射".to_string(),
            note: Some("域控".to_string()),
        });

        let temp = std::env::temp_dir().join("test_vault.bin");
        vault.save_encrypted(&temp, "vault-password").expect("保存");

        let loaded = Vault::load_encrypted(&temp, "vault-password").expect("加载");
        assert_eq!(loaded.entry_count(), 1);
        assert_eq!(loaded.entries[0].service, "RDP");
        assert_eq!(loaded.entries[0].credential, "Admin123!");

        let _ = std::fs::remove_file(&temp);
    }
}
