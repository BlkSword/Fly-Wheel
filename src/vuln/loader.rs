//! 外部 PoC 文件加载器
//!
//! 支持 YAML 和 JSON 格式的 PoC 规则文件加载

use crate::core::error::IntraSweepError;
use crate::core::Result;
use crate::vuln::poc::PoCRule;
use std::path::Path;

/// 从文件或目录加载 PoC 规则
pub fn load_pocs_from_path(path: &Path) -> Result<Vec<PoCRule>> {
    if path.is_dir() {
        load_pocs_from_directory(path)
    } else {
        load_pocs_from_file(path).map(|p| vec![p])
    }
}

fn load_pocs_from_file(path: &Path) -> Result<PoCRule> {
    let content = std::fs::read_to_string(path)?;
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

    match ext.to_lowercase().as_str() {
        "yaml" | "yml" => serde_yaml::from_str(&content).map_err(IntraSweepError::Yaml),
        "json" => serde_json::from_str(&content).map_err(IntraSweepError::Serialization),
        _ => Err(IntraSweepError::PocRule {
            message: format!("不支持的PoC文件格式: {}", ext),
        }),
    }
}

fn load_pocs_from_directory(dir: &Path) -> Result<Vec<PoCRule>> {
    let mut pocs = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if matches!(ext, "yaml" | "yml" | "json") {
                match load_pocs_from_file(&path) {
                    Ok(poc) => {
                        tracing::debug!("加载PoC: {} ({})", poc.id, poc.info.name);
                        pocs.push(poc);
                    }
                    Err(e) => {
                        tracing::warn!("加载PoC文件失败 {:?}: {}", path, e);
                    }
                }
            }
        }
    }
    Ok(pocs)
}

/// 验证 PoC 规则完整性
pub fn validate_poc(poc: &PoCRule) -> Result<()> {
    if poc.id.is_empty() {
        return Err(IntraSweepError::PocRule {
            message: "PoC id不能为空".to_string(),
        });
    }
    if poc.info.name.is_empty() {
        return Err(IntraSweepError::PocRule {
            message: format!("PoC {} 的name不能为空", poc.id),
        });
    }
    if poc.rules.is_empty() {
        return Err(IntraSweepError::PocRule {
            message: format!("PoC {} 缺少rules", poc.id),
        });
    }
    for (i, rule) in poc.rules.iter().enumerate() {
        if rule.matchers.is_empty() {
            return Err(IntraSweepError::PocRule {
                message: format!("PoC {} 的第{}条规则缺少matchers", poc.id, i + 1),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_load_yaml_file() {
        let dir = std::env::temp_dir().join("intrasweep_test_poc");
        let _ = fs::create_dir_all(&dir);
        let file_path = dir.join("test.yaml");

        let yaml_content = r#"
id: test-yaml
info:
  name: Test YAML PoC
  severity: high
transport: http
rules:
  - method: GET
    path: "/test"
    matchers:
      - type: word
        words:
          - "test"
"#;
        fs::write(&file_path, yaml_content).unwrap();

        let pocs = load_pocs_from_path(&file_path).unwrap();
        assert_eq!(pocs.len(), 1);
        assert_eq!(pocs[0].id, "test-yaml");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_json_file() {
        let dir = std::env::temp_dir().join("intrasweep_test_poc_json");
        let _ = fs::create_dir_all(&dir);
        let file_path = dir.join("test.json");

        let json_content = r#"{
            "id": "test-json",
            "info": {"name": "Test JSON PoC", "severity": "medium"},
            "transport": "http",
            "rules": [{"method": "GET", "path": "/", "matchers": [{"type": "status", "status": [200]}]}]
        }"#;
        fs::write(&file_path, json_content).unwrap();

        let pocs = load_pocs_from_path(&file_path).unwrap();
        assert_eq!(pocs.len(), 1);
        assert_eq!(pocs[0].id, "test-json");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_directory() {
        let dir = std::env::temp_dir().join("intrasweep_test_poc_dir");
        let _ = fs::create_dir_all(&dir);

        let yaml1 = r#"
id: poc1
info:
  name: PoC 1
  severity: high
transport: http
rules:
  - method: GET
    path: "/"
    matchers:
      - type: word
        words: ["test"]
"#;
        let yaml2 = r#"
id: poc2
info:
  name: PoC 2
  severity: critical
transport: http
rules:
  - method: GET
    path: "/admin"
    matchers:
      - type: status
        status: [200]
"#;
        fs::write(dir.join("poc1.yaml"), yaml1).unwrap();
        fs::write(dir.join("poc2.yaml"), yaml2).unwrap();
        fs::write(dir.join("readme.txt"), "not a poc").unwrap();

        let pocs = load_pocs_from_path(&dir).unwrap();
        assert_eq!(pocs.len(), 2);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_validate_poc() {
        let valid_yaml = r#"
id: valid
info:
  name: Valid PoC
transport: http
rules:
  - method: GET
    path: "/"
    matchers:
      - type: word
        words: ["test"]
"#;
        let poc: PoCRule = serde_yaml::from_str(valid_yaml).unwrap();
        assert!(validate_poc(&poc).is_ok());

        let empty_id_yaml = r#"
id: ""
info:
  name: Empty ID
transport: http
rules:
  - method: GET
    path: "/"
    matchers:
      - type: word
        words: ["test"]
"#;
        let poc2: PoCRule = serde_yaml::from_str(empty_id_yaml).unwrap();
        assert!(validate_poc(&poc2).is_err());
    }

    #[test]
    fn test_unsupported_format() {
        let dir = std::env::temp_dir().join("intrasweep_test_bad_format");
        let _ = fs::create_dir_all(&dir);
        let file_path = dir.join("test.txt");
        fs::write(&file_path, "not a poc").unwrap();

        let result = load_pocs_from_path(&file_path);
        assert!(result.is_err());

        let _ = fs::remove_dir_all(&dir);
    }
}
