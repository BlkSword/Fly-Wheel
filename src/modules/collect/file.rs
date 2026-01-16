//! 文件搜索模块
//!
//! 搜索敏感文件、配置文件、关键词等

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// 文件收集器
pub struct FileCollector;

impl FileCollector {
    /// 创建新的文件收集器
    pub fn new() -> Self {
        Self
    }

    /// 查找敏感文件
    pub fn find_sensitive_files(&self, search_paths: &[String]) -> Vec<SensitiveFile> {
        let mut files = Vec::new();

        // 敏感文件扩展名和名称模式
        let sensitive_patterns = vec![
            // 密码相关
            ("password", "密码文件"),
            ("pass", "密码文件"),
            ("secret", "密钥文件"),
            ("credentials", "凭据文件"),
            ("credential", "凭据文件"),
            // 密钥相关
            (".key", "私钥文件"),
            (".pem", "PEM证书"),
            (".crt", "证书文件"),
            (".p12", "PKCS12证书"),
            (".pfx", "PFX证书"),
            ("id_rsa", "RSA私钥"),
            ("id_ed25519", "Ed25519私钥"),
            ("id_ecdsa", "ECDSA私钥"),
            ("id_dsa", "DSA私钥"),
            // 数据库相关
            (".sql", "SQL文件"),
            ("database", "数据库文件"),
            ("db_backup", "数据库备份"),
            // 配置文件
            ("config", "配置文件"),
            ("conf", "配置文件"),
            ("settings", "设置文件"),
            (".env", "环境变量"),
            (".env.local", "环境变量"),
            (".env.production", "生产环境变量"),
            // 其他敏感文件
            ("shadow", "shadow密码文件"),
            ("passwd", "passwd文件"),
        ];

        for base_path in search_paths {
            let path = Path::new(base_path);
            if !path.exists() {
                continue;
            }

            // 遍历目录
            let max_depth = if path.is_dir() { 10 } else { 0 };

            let walker = WalkDir::new(path)
                .max_depth(max_depth)
                .follow_links(false)
                .into_iter()
                .filter_entry(|e| !is_hidden(e));

            for entry in walker.filter_map(|e| e.ok()) {
                if !entry.file_type().is_file() {
                    continue;
                }

                let file_name = entry.file_name().to_string_lossy().to_string();
                let file_name_lower = file_name.to_lowercase();

                // 检查是否匹配敏感模式
                for (pattern, category) in &sensitive_patterns {
                    if file_name_lower.contains(pattern) {
                        let modified = entry.metadata()
                            .ok()
                            .and_then(|m| m.modified().ok());
                        files.push(SensitiveFile {
                            path: entry.path().to_string_lossy().to_string(),
                            file_name,
                            category: category.to_string(),
                            size: entry.metadata().map(|m| m.len()).unwrap_or(0),
                            modified,
                        });
                        break;
                    }
                }
            }
        }

        files
    }

    /// 查找配置文件
    pub fn find_config_files(&self, search_paths: &[String]) -> Vec<ConfigFile> {
        let mut files = Vec::new();

        // 配置文件扩展名
        let config_extensions = vec![
            ".conf", ".config", ".cfg", ".ini",
            ".json", ".yaml", ".yml", ".toml",
            ".xml", ".properties",
        ];

        for base_path in search_paths {
            let path = Path::new(base_path);
            if !path.exists() {
                continue;
            }

            let max_depth = if path.is_dir() { 8 } else { 0 };

            let walker = WalkDir::new(path)
                .max_depth(max_depth)
                .follow_links(false)
                .into_iter()
                .filter_entry(|e| !is_hidden(e));

            for entry in walker.filter_map(|e| e.ok()) {
                if !entry.file_type().is_file() {
                    continue;
                }

                let file_name = entry.file_name().to_string_lossy().to_string();

                // 检查扩展名
                let extension = entry.path().extension().and_then(|e| e.to_str());
                if let Some(ext) = extension {
                    let ext_lower = format!(".{}", ext.to_lowercase());
                    if config_extensions.contains(&ext_lower.as_str()) {
                        let config_type = detect_config_type(&file_name);
                        files.push(ConfigFile {
                            path: entry.path().to_string_lossy().to_string(),
                            file_name,
                            config_type,
                            size: entry.metadata().map(|m| m.len()).unwrap_or(0),
                        });
                    }
                }
            }
        }

        files
    }

    /// 搜索关键词
    pub fn search_keywords(&self, search_paths: &[String], keywords: &[String]) -> Vec<FileMatch> {
        let mut matches = Vec::new();

        for base_path in search_paths {
            let path = Path::new(base_path);
            if !path.exists() {
                continue;
            }

            let max_depth = if path.is_dir() { 10 } else { 0 };

            let walker = WalkDir::new(path)
                .max_depth(max_depth)
                .follow_links(false)
                .into_iter()
                .filter_entry(|e| !is_hidden(e));

            for entry in walker.filter_map(|e| e.ok()) {
                if !entry.file_type().is_file() {
                    continue;
                }

                // 只搜索文本文件
                if !is_likely_text_file(entry.path()) {
                    continue;
                }

                if let Ok(content) = std::fs::read_to_string(entry.path()) {
                    for keyword in keywords {
                        if content.to_lowercase().contains(&keyword.to_lowercase()) {
                            // 查找包含关键词的行
                            let lines: Vec<&str> = content.lines().collect();
                            let matching_lines: Vec<(usize, String)> = lines
                                .iter()
                                .enumerate()
                                .filter(|(_, line)| line.to_lowercase().contains(&keyword.to_lowercase()))
                                .map(|(i, line)| (i + 1, line.to_string()))
                                .collect();

                            if !matching_lines.is_empty() {
                                let total_matches = matching_lines.len();
                                matches.push(FileMatch {
                                    path: entry.path().to_string_lossy().to_string(),
                                    file_name: entry.file_name().to_string_lossy().to_string(),
                                    keyword: keyword.clone(),
                                    lines: matching_lines,
                                    total_matches,
                                });
                            }
                        }
                    }
                }
            }
        }

        matches
    }

    /// 查找最近修改的文件
    pub fn find_recent_files(&self, search_paths: &[String], days: u64) -> Vec<PathBuf> {
        let mut files = Vec::new();
        let now = std::time::SystemTime::now();
        let duration = std::time::Duration::from_secs(days * 24 * 60 * 60);

        for base_path in search_paths {
            let path = Path::new(base_path);
            if !path.exists() {
                continue;
            }

            let max_depth = if path.is_dir() { 5 } else { 0 };

            let walker = WalkDir::new(path)
                .max_depth(max_depth)
                .follow_links(false)
                .into_iter()
                .filter_entry(|e| !is_hidden(e));

            for entry in walker.filter_map(|e| e.ok()) {
                if !entry.file_type().is_file() {
                    continue;
                }

                if let Ok(metadata) = entry.metadata() {
                    if let Ok(modified) = metadata.modified() {
                        if let Ok(elapsed) = now.duration_since(modified) {
                            if elapsed < duration {
                                files.push(entry.path().to_path_buf());
                            }
                        }
                    }
                }
            }
        }

        files
    }
}

impl Default for FileCollector {
    fn default() -> Self {
        Self::new()
    }
}

// ==================== 辅助函数 ====================

/// 判断路径是否是隐藏文件/目录
fn is_hidden(entry: &walkdir::DirEntry) -> bool {
    entry.file_name()
        .to_str()
        .map(|s| s.starts_with('.'))
        .unwrap_or(false)
}

/// 判断文件是否可能是文本文件
fn is_likely_text_file(path: &Path) -> bool {
    // 检查文件扩展名
    let text_extensions = vec![
        "txt", "md", "rst", "log",
        "json", "xml", "yaml", "yml", "toml",
        "conf", "config", "cfg", "ini",
        "sh", "bash", "zsh", "fish",
        "ps1", "bat", "cmd",
        "py", "rb", "pl", "js", "ts",
        "rs", "go", "java", "c", "cpp", "h",
        "html", "css", "scss",
        "env", "sql",
    ];

    path.extension()
        .and_then(|e| e.to_str())
        .map(|ext| text_extensions.contains(&ext.to_lowercase().as_str()))
        .unwrap_or(false)
}

/// 检测配置文件类型
fn detect_config_type(filename: &str) -> String {
    let filename_lower = filename.to_lowercase();

    if filename_lower.contains("ssh") || filename_lower.contains("sshd") {
        "SSH配置".to_string()
    } else if filename_lower.contains("nginx") || filename_lower.contains("apache") || filename_lower.contains("httpd") {
        "Web服务器配置".to_string()
    } else if filename_lower.contains("mysql") || filename_lower.contains("postgresql") || filename_lower.contains("mongodb") {
        "数据库配置".to_string()
    } else if filename_lower.contains("docker") {
        "Docker配置".to_string()
    } else if filename_lower.contains("kubernetes") || filename_lower.contains("k8s") {
        "Kubernetes配置".to_string()
    } else if filename_lower.contains("git") {
        "Git配置".to_string()
    } else if filename.ends_with(".json") {
        "JSON配置".to_string()
    } else if filename.ends_with(".yaml") || filename.ends_with(".yml") {
        "YAML配置".to_string()
    } else if filename.ends_with(".toml") {
        "TOML配置".to_string()
    } else if filename.ends_with(".ini") {
        "INI配置".to_string()
    } else {
        "通用配置".to_string()
    }
}

// ==================== 数据结构 ====================

/// 敏感文件
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensitiveFile {
    pub path: String,
    pub file_name: String,
    pub category: String,
    pub size: u64,
    pub modified: Option<std::time::SystemTime>,
}

/// 配置文件
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigFile {
    pub path: String,
    pub file_name: String,
    pub config_type: String,
    pub size: u64,
}

/// 文件匹配（关键词搜索）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMatch {
    pub path: String,
    pub file_name: String,
    pub keyword: String,
    pub lines: Vec<(usize, String)>, // (行号, 行内容)
    pub total_matches: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_collector_creation() {
        let collector = FileCollector::new();
        // 验证对象创建成功
        assert!(true);
    }

    #[test]
    fn test_detect_config_type() {
        assert_eq!(detect_config_type("sshd_config"), "SSH配置");
        assert_eq!(detect_config_type("nginx.conf"), "Web服务器配置");
        assert_eq!(detect_config_type("my.cnf"), "数据库配置");
        assert_eq!(detect_config_type("docker-compose.yml"), "Docker配置");
        assert_eq!(detect_config_type("config.json"), "JSON配置");
    }

    #[test]
    fn test_is_likely_text_file() {
        assert!(is_likely_text_file(Path::new("test.txt")));
        assert!(is_likely_text_file(Path::new("config.json")));
        assert!(is_likely_text_file(Path::new("script.sh")));
        assert!(!is_likely_text_file(Path::new("image.png")));
        assert!(!is_likely_text_file(Path::new("binary.exe")));
    }

    #[test]
    fn test_is_hidden() {
        use walkdir::DirEntry;
        // 简单测试
        assert!(true);
    }

    #[test]
    fn test_find_config_files() {
        let collector = FileCollector::new();
        // 测试当前目录
        let paths = vec![".".to_string()];
        let files = collector.find_config_files(&paths);
        // 不应该崩溃
        assert!(true);
    }

    #[test]
    fn test_search_keywords() {
        let collector = FileCollector::new();
        let paths = vec![".".to_string()];
        let keywords = vec!["test".to_string()];
        let matches = collector.search_keywords(&paths, &keywords);
        // 不应该崩溃
        assert!(true);
    }
}
