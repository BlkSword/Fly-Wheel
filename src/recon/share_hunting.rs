//! 文件共享敏感信息搜索模块
//!
//! - 配置文件（web.config, app.config, .env）
//! - 密码文件（passwords.txt, credentials.xlsx）
//! - 脚本文件（.ps1, .bat, .sh）可能含硬编码凭据
//! - SSH密钥和证书
//! - 数据库备份文件

use serde::{Deserialize, Serialize};

/// 文件共享发现结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareFinding {
    /// 共享路径
    pub share_path: String,
    /// 文件名
    pub filename: String,
    /// 完整路径
    pub full_path: String,
    /// 文件大小
    pub file_size: u64,
    /// 文件类型
    pub file_type: FileType,
    /// 是否包含凭据
    pub contains_credentials: bool,
    /// 是否敏感文件
    pub is_sensitive: bool,
    /// 匹配的关键词
    pub matched_keywords: Vec<String>,
    /// 发现时间
    pub discovered_at: String,
}

/// 文件类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FileType {
    ConfigFile,
    ScriptFile,
    PasswordFile,
    KeyFile,
    BackupFile,
    DatabaseFile,
    DocumentFile,
    Other,
}

impl std::fmt::Display for FileType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileType::ConfigFile => write!(f, "配置文件"),
            FileType::ScriptFile => write!(f, "脚本文件"),
            FileType::PasswordFile => write!(f, "密码文件"),
            FileType::KeyFile => write!(f, "密钥文件"),
            FileType::BackupFile => write!(f, "备份文件"),
            FileType::DatabaseFile => write!(f, "数据库文件"),
            FileType::DocumentFile => write!(f, "文档文件"),
            FileType::Other => write!(f, "其他"),
        }
    }
}

/// 敏感文件扩展名列表
const SENSITIVE_EXTENSIONS: &[(&str, FileType)] = &[
    // 配置文件
    (".config", FileType::ConfigFile),
    ("web.config", FileType::ConfigFile),
    ("app.config", FileType::ConfigFile),
    (".env", FileType::ConfigFile),
    (".ini", FileType::ConfigFile),
    (".conf", FileType::ConfigFile),
    (".yaml", FileType::ConfigFile),
    (".yml", FileType::ConfigFile),
    (".toml", FileType::ConfigFile),
    (".json", FileType::ConfigFile),
    ("site.config", FileType::ConfigFile),
    ("connectionStrings.config", FileType::ConfigFile),
    // 脚本文件
    (".ps1", FileType::ScriptFile),
    (".bat", FileType::ScriptFile),
    (".cmd", FileType::ScriptFile),
    (".vbs", FileType::ScriptFile),
    (".sh", FileType::ScriptFile),
    (".py", FileType::ScriptFile),
    (".rb", FileType::ScriptFile),
    // 密码/凭据文件
    ("passwords", FileType::PasswordFile),
    ("credentials", FileType::PasswordFile),
    ("secret", FileType::PasswordFile),
    ("accounts", FileType::PasswordFile),
    // 密钥文件
    (".pem", FileType::KeyFile),
    (".key", FileType::KeyFile),
    (".pfx", FileType::KeyFile),
    (".p12", FileType::KeyFile),
    ("id_rsa", FileType::KeyFile),
    ("id_ed25519", FileType::KeyFile),
    // 备份文件
    (".bak", FileType::BackupFile),
    (".backup", FileType::BackupFile),
    (".old", FileType::BackupFile),
    (".save", FileType::BackupFile),
    // 数据库文件
    (".mdf", FileType::DatabaseFile),
    (".ldf", FileType::DatabaseFile),
    (".sql", FileType::DatabaseFile),
    (".sqlite", FileType::DatabaseFile),
    (".db", FileType::DatabaseFile),
    // 文档文件
    (".doc", FileType::DocumentFile),
    (".docx", FileType::DocumentFile),
    (".xls", FileType::DocumentFile),
    (".xlsx", FileType::DocumentFile),
    (".pdf", FileType::DocumentFile),
    (".txt", FileType::DocumentFile),
    (".csv", FileType::DocumentFile),
];

/// 凭据相关关键词
const CREDENTIAL_KEYWORDS: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "credential",
    "secret",
    "token",
    "connectionString",
    "connection string",
    "User ID=",
    "UserID=",
    "uid=",
    "Password=",
    "Pwd=",
    "pwd=",
    "sa",
    "admin",
    "PRIVATE KEY",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "NTLM",
    "hash",
    "DSN=",
    "Provider=",
];

/// 扫描网络共享
pub fn scan_network_shares() -> Result<Vec<ShareFinding>, String> {
    let mut findings = Vec::new();

    // 获取可用的网络共享列表
    let shares = enumerate_network_shares()?;

    for share in &shares {
        match scan_share_recursive(share, 3, &mut findings) {
            Ok(count) => {
                tracing::info!("[共享搜索] {}: 发现 {} 个敏感文件", share, count);
            }
            Err(e) => {
                tracing::debug!("[共享搜索] {} 扫描失败: {}", share, e);
            }
        }
    }

    // 也搜索本地敏感路径
    if let Ok(local) = scan_local_sensitive_paths() {
        findings.extend(local);
    }

    Ok(findings)
}

/// 枚举网络共享
fn enumerate_network_shares() -> Result<Vec<String>, String> {
    let mut shares = Vec::new();

    if cfg!(windows) {
        // 1. net view 获取可用的计算机
        let output = std::process::Command::new("net")
            .args(["view"])
            .output()
            .map_err(|e| format!("net view失败: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let line = line.trim();
            if line.starts_with("\\\\") {
                shares.push(line.to_string());
            }
        }

        // 2. 枚举每台计算机的共享
        let mut all_shares = Vec::new();
        for computer in &shares {
            let output = std::process::Command::new("net")
                .args(["view", computer])
                .output();

            if let Ok(o) = output {
                let stdout = String::from_utf8_lossy(&o.stdout);
                for line in stdout.lines() {
                    if line.contains("Disk") {
                        if let Some(share_name) = line.split_whitespace().next() {
                            let full_share = format!("{}\\{}", computer, share_name);
                            all_shares.push(full_share);
                        }
                    }
                }
            }
        }

        shares = all_shares;

        // 3. 如果没找到网络共享，至少检查本地共享
        if shares.is_empty() {
            // 检查常见的默认共享
            for drive in &["C$", "D$", "ADMIN$"] {
                let share = format!("\\\\localhost\\{}", drive);
                shares.push(share);
            }
        }
    }

    // 4. 至少扫描本地系统
    shares.push("C:\\Users".to_string());
    shares.push("C:\\ProgramData".to_string());
    shares.push("C:\\inetpub".to_string());

    Ok(shares)
}

/// 递归扫描共享目录
fn scan_share_recursive(
    share_path: &str,
    max_depth: u32,
    findings: &mut Vec<ShareFinding>,
) -> Result<usize, String> {
    let mut count = 0;

    if max_depth == 0 {
        return Ok(0);
    }

    let path = std::path::Path::new(share_path);
    if !path.exists() {
        return Ok(0);
    }

    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let file_path = entry.path();

            if file_path.is_dir() {
                // 跳过系统目录
                let dir_name = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if dir_name.starts_with("System")
                    || dir_name == "Windows"
                    || dir_name == "$Recycle.Bin"
                {
                    continue;
                }

                // 递归进入子目录
                if let Ok(sub_count) =
                    scan_share_recursive(&file_path.to_string_lossy(), max_depth - 1, findings)
                {
                    count += sub_count;
                }
            } else if file_path.is_file() {
                if let Some(finding) = check_file_sensitive(&file_path, share_path) {
                    findings.push(finding);
                    count += 1;
                }
            }
        }
    }

    Ok(count)
}

/// 检查单个文件是否敏感
fn check_file_sensitive(file_path: &std::path::Path, share_base: &str) -> Option<ShareFinding> {
    let filename = file_path.file_name()?.to_str()?.to_lowercase();
    let full_path = file_path.to_string_lossy().to_string();

    // 检查扩展名
    let (file_type, is_sensitive) = SENSITIVE_EXTENSIONS
        .iter()
        .find(|(ext, _)| filename.contains(ext))
        .map(|(_, ft)| (ft.clone(), true))
        .unwrap_or((FileType::Other, false));

    if !is_sensitive {
        return None;
    }

    // 检查文件大小（跳过空文件和大文件）
    let file_size = std::fs::metadata(file_path).ok()?.len();
    if file_size == 0 || file_size > 50 * 1024 * 1024 {
        // 50MB限制
        return None;
    }

    // 检查文件内容是否包含凭据
    let (contains_credentials, matched_keywords) = if file_size < 1024 * 1024 {
        // 仅对小于1MB的文件检查内容
        match std::fs::read_to_string(file_path) {
            Ok(content) => {
                let content_lower = content.to_lowercase();
                let keywords: Vec<String> = CREDENTIAL_KEYWORDS
                    .iter()
                    .filter(|kw| content_lower.contains(&kw.to_lowercase()))
                    .map(|s| s.to_string())
                    .collect();
                (!keywords.is_empty(), keywords)
            }
            Err(_) => (false, Vec::new()),
        }
    } else {
        (false, Vec::new())
    };

    Some(ShareFinding {
        share_path: share_base.to_string(),
        filename: file_path.file_name()?.to_str()?.to_string(),
        full_path,
        file_size,
        file_type,
        contains_credentials,
        is_sensitive: is_sensitive || contains_credentials,
        matched_keywords,
        discovered_at: chrono::Utc::now().to_rfc3339(),
    })
}

/// 扫描本地敏感路径
fn scan_local_sensitive_paths() -> Result<Vec<ShareFinding>, String> {
    let mut findings = Vec::new();

    let sensitive_dirs = [
        r"C:\Users\*\Desktop",
        r"C:\Users\*\Documents",
        r"C:\Users\*\Downloads",
        r"C:\temp",
        r"C:\tmp",
        r"C:\ProgramData",
        r"C:\inetpub\wwwroot",
        r"C:\xampp\htdocs",
    ];

    for dir in &sensitive_dirs {
        if dir.contains('*') {
            // 通配符路径需要用glob展开，Path::exists无法匹配字面量'*'
            if let Ok(paths) = glob::glob(dir) {
                for entry in paths.flatten() {
                    if entry.is_dir() {
                        let _ = scan_share_recursive(&entry.to_string_lossy(), 2, &mut findings);
                    }
                }
            }
        } else {
            let path = std::path::Path::new(dir);
            if path.exists() {
                let _ = scan_share_recursive(dir, 2, &mut findings);
            }
        }
    }

    Ok(findings)
}

/// 搜索特定关键词的文件
pub fn search_files_by_keyword(
    base_path: &str,
    keyword: &str,
    max_files: usize,
) -> Result<Vec<ShareFinding>, String> {
    let mut findings = Vec::new();
    let mut count = 0;

    fn search_dir(
        dir: &std::path::Path,
        keyword_lower: &str,
        max_files: usize,
        count: &mut usize,
        findings: &mut Vec<ShareFinding>,
        base_path: &str,
        keyword: &str,
    ) {
        if *count >= max_files {
            return;
        }

        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                if *count >= max_files {
                    break;
                }
                let path = entry.path();
                if path.is_dir() {
                    // 跳过系统目录
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        if name == "System32" || name == "Windows" || name.starts_with('.') {
                            continue;
                        }
                    }
                    search_dir(
                        &path,
                        keyword_lower,
                        max_files,
                        count,
                        findings,
                        base_path,
                        keyword,
                    );
                } else if path.is_file() {
                    if let Ok(metadata) = std::fs::metadata(&path) {
                        if metadata.len() < 1024 * 1024 {
                            if let Ok(content) = std::fs::read_to_string(&path) {
                                if content.to_lowercase().contains(keyword_lower) {
                                    findings.push(ShareFinding {
                                        share_path: base_path.to_string(),
                                        filename: path
                                            .file_name()
                                            .unwrap_or_default()
                                            .to_string_lossy()
                                            .to_string(),
                                        full_path: path.to_string_lossy().to_string(),
                                        file_size: metadata.len(),
                                        file_type: FileType::Other,
                                        contains_credentials: true,
                                        is_sensitive: true,
                                        matched_keywords: vec![keyword.to_string()],
                                        discovered_at: chrono::Utc::now().to_rfc3339(),
                                    });
                                    *count += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    search_dir(
        std::path::Path::new(base_path),
        &keyword.to_lowercase(),
        max_files,
        &mut count,
        &mut findings,
        base_path,
        keyword,
    );

    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_type_display() {
        assert_eq!(FileType::ConfigFile.to_string(), "配置文件");
        assert_eq!(FileType::PasswordFile.to_string(), "密码文件");
    }

    #[test]
    fn test_share_finding_creation() {
        let finding = ShareFinding {
            share_path: "\\\\DC01\\SYSVOL".to_string(),
            filename: "Groups.xml".to_string(),
            full_path: "\\\\DC01\\SYSVOL\\corp.local\\Policies\\{GUID}\\Machine\\Preferences\\Groups\\Groups.xml".to_string(),
            file_size: 2048,
            file_type: FileType::ConfigFile,
            contains_credentials: true,
            is_sensitive: true,
            matched_keywords: vec!["cpassword".to_string(), "password".to_string()],
            discovered_at: "2024-01-01T00:00:00Z".to_string(),
        };
        assert!(finding.contains_credentials);
        assert_eq!(finding.matched_keywords.len(), 2);
    }

    #[test]
    fn test_sensitive_extensions() {
        assert!(SENSITIVE_EXTENSIONS.len() >= 10);
    }

    #[test]
    fn test_credential_keywords() {
        assert!(CREDENTIAL_KEYWORDS.contains(&"password"));
        assert!(CREDENTIAL_KEYWORDS.contains(&"connectionString"));
    }
}
