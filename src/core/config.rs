//! 配置文件支持模块
//!
//! 支持 YAML 格式的配置文件，用于预设扫描、爆破、隧道参数。
//! CLI 显式参数优先级高于配置文件。

use serde::Deserialize;
use std::path::Path;

/// 应用配置
#[derive(Debug, Clone, Deserialize, Default)]
pub struct AppConfig {
    /// 全局默认值
    #[serde(default)]
    pub defaults: DefaultConfig,
    /// 扫描预设
    #[serde(default)]
    pub scan: Option<ScanProfile>,
    /// 爆破预设
    #[serde(default)]
    pub crack: Option<CrackProfile>,
    /// 隧道预设
    #[serde(default)]
    pub tunnel: Option<TunnelProfile>,
}

/// 全局默认配置
#[derive(Debug, Clone, Deserialize, Default)]
pub struct DefaultConfig {
    pub concurrency: Option<usize>,
    pub timeout: Option<u64>,
    pub format: Option<String>,
}

/// 扫描配置预设
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ScanProfile {
    pub targets: Option<Vec<String>>,
    #[serde(rename = "type")]
    pub scan_type: Option<String>,
    pub fast: Option<bool>,
    pub webfinger: Option<bool>,
}

/// 爆破配置预设
#[derive(Debug, Clone, Deserialize, Default)]
pub struct CrackProfile {
    pub username_file: Option<String>,
    pub password_file: Option<String>,
    pub concurrency: Option<usize>,
    pub timeout: Option<u64>,
}

/// 隧道配置预设
#[derive(Debug, Clone, Deserialize, Default)]
pub struct TunnelProfile {
    pub encryption_key: Option<String>,
    pub max_connections: Option<usize>,
    pub timeout: Option<u64>,
}

/// 从 YAML 文件加载配置
pub fn load_config(path: &Path) -> crate::core::Result<AppConfig> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        crate::core::error::IntraSweepError::Config {
            message: format!("读取配置文件 {} 失败: {}", path.display(), e),
        }
    })?;

    let config: AppConfig = serde_yaml::from_str(&content).map_err(|e| {
        crate::core::error::IntraSweepError::Config {
            message: format!("解析配置文件失败: {}", e),
        }
    })?;

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_config() {
        let yaml = r#"
defaults:
  concurrency: 50
  timeout: 10
"#;
        let config: AppConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.defaults.concurrency, Some(50));
        assert_eq!(config.defaults.timeout, Some(10));
    }

    #[test]
    fn test_parse_full_config() {
        let yaml = r#"
defaults:
  concurrency: 50
  timeout: 10
  format: json

scan:
  targets:
    - 192.168.1.0/24
  type: comprehensive
  webfinger: true

crack:
  username_file: ./dict/users.txt
  password_file: ./dict/passwords.txt

tunnel:
  encryption_key: "my-secret"
  max_connections: 200
"#;
        let config: AppConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.defaults.concurrency, Some(50));
        assert_eq!(config.scan.as_ref().unwrap().scan_type, Some("comprehensive".to_string()));
        assert_eq!(config.crack.as_ref().unwrap().username_file, Some("./dict/users.txt".to_string()));
        assert_eq!(config.tunnel.as_ref().unwrap().encryption_key, Some("my-secret".to_string()));
    }
}
