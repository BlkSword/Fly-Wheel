//! PoC 规则数据模型
//!
//! 定义 PoC 规则的 serde 反序列化结构体，支持 YAML 和 JSON 格式

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// 漏洞严重性级别
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord, Default,
)]
pub enum Severity {
    #[serde(rename = "info")]
    Info,
    #[serde(rename = "low")]
    Low,
    #[serde(rename = "medium")]
    #[default]
    Medium,
    #[serde(rename = "high")]
    High,
    #[serde(rename = "critical")]
    Critical,
}

impl Severity {
    pub fn display_name(&self) -> &str {
        match self {
            Severity::Critical => "严重",
            Severity::High => "高危",
            Severity::Medium => "中危",
            Severity::Low => "低危",
            Severity::Info => "信息",
        }
    }

    pub fn color_code(&self) -> &str {
        match self {
            Severity::Critical => "\x1b[31m",
            Severity::High => "\x1b[33m",
            Severity::Medium => "\x1b[36m",
            Severity::Low => "\x1b[32m",
            Severity::Info => "\x1b[37m",
        }
    }

    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "critical" | "严重" => Some(Severity::Critical),
            "high" | "高危" => Some(Severity::High),
            "medium" | "中危" => Some(Severity::Medium),
            "low" | "低危" => Some(Severity::Low),
            "info" | "信息" => Some(Severity::Info),
            _ => None,
        }
    }
}

/// 传输协议类型
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum Transport {
    #[default]
    Http,
    Tcp,
    Script,
}

/// PoC 规则完整定义
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PoCRule {
    pub id: String,
    pub info: PoCInfo,
    #[serde(default)]
    pub transport: Transport,
    #[serde(rename = "default-port", default)]
    pub default_port: Option<u16>,
    #[serde(default)]
    pub rules: Vec<PoCRequest>,
    /// 脚本配置 (transport: script 时使用)
    #[serde(default)]
    pub script: Option<ScriptConfig>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptConfig {
    /// 解释器: python3, python, powershell, bash, sh
    #[serde(default = "default_interpreter")]
    pub interpreter: String,
    /// 外部脚本文件路径 (相对于 PoC 文件目录)
    #[serde(default)]
    pub file: Option<String>,
    /// 内联脚本代码
    #[serde(default)]
    pub code: Option<String>,
    /// 传递给脚本的参数 (支持 {{target}}, {{port}} 变量)
    #[serde(default)]
    pub args: Vec<String>,
    /// 脚本执行超时(秒)
    #[serde(default = "default_script_timeout")]
    pub timeout: u64,
}

fn default_interpreter() -> String {
    "python3".to_string()
}

fn default_script_timeout() -> u64 {
    30
}

/// PoC 元信息
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PoCInfo {
    pub name: String,
    #[serde(default)]
    pub severity: Severity,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub remediation: String,
}

/// 单个请求规则
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PoCRequest {
    #[serde(default = "default_method")]
    pub method: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub data: Option<String>,
    #[serde(rename = "read-size", default)]
    pub read_size: Option<usize>,
    #[serde(rename = "matchers-condition", default = "default_matchers_condition")]
    pub matchers_condition: String,
    #[serde(default)]
    pub matchers: Vec<Matcher>,
    /// 变量提取器 (从响应中提取值供后续步骤使用)
    #[serde(default)]
    pub extractors: Vec<Extractor>,
}

impl Default for PoCRequest {
    fn default() -> Self {
        Self {
            method: default_method(),
            path: String::new(),
            headers: HashMap::new(),
            body: None,
            data: None,
            read_size: None,
            matchers_condition: default_matchers_condition(),
            matchers: Vec::new(),
            extractors: Vec::new(),
        }
    }
}

fn default_method() -> String {
    "GET".to_string()
}

fn default_matchers_condition() -> String {
    "and".to_string()
}

/// 变量提取器
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Extractor {
    /// 变量名
    pub name: String,
    /// 提取类型
    #[serde(rename = "type", default = "default_extractor_type")]
    pub extractor_type: ExtractorType,
    /// 提取来源: body, header, all
    #[serde(default = "default_part")]
    pub part: String,
    /// 正则表达式 (regex 类型)
    #[serde(default)]
    pub regex: Option<String>,
    /// 捕获组索引 (默认 1)
    #[serde(default = "default_group")]
    pub group: usize,
    /// 提取的值在内部使用时的内部匹配
    #[serde(default)]
    pub internal: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExtractorType {
    Regex,
    Kodex,
}

fn default_extractor_type() -> ExtractorType {
    ExtractorType::Regex
}

fn default_group() -> usize {
    1
}

/// 匹配器类型
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MatcherType {
    Word,
    Regex,
    Status,
    Binary,
}

/// 匹配器定义
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Matcher {
    #[serde(rename = "type")]
    pub matcher_type: MatcherType,
    #[serde(default = "default_part")]
    pub part: String,
    #[serde(default)]
    pub words: Vec<String>,
    #[serde(default)]
    pub regex: Vec<String>,
    #[serde(default)]
    pub status: Vec<u16>,
    #[serde(default)]
    pub binary: Vec<String>,
    #[serde(default)]
    pub negative: bool,
}

fn default_part() -> String {
    "body".to_string()
}

/// 变量替换 — 将 {{var}} 占位符替换为实际值
pub fn substitute_vars(template: &str, vars: &HashMap<String, String>) -> String {
    let mut result = template.to_string();
    for (key, value) in vars {
        result = result.replace(&format!("{{{{{}}}}}", key), value);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn test_severity_from_str() {
        assert_eq!(Severity::from_str_opt("critical"), Some(Severity::Critical));
        assert_eq!(Severity::from_str_opt("high"), Some(Severity::High));
        assert_eq!(Severity::from_str_opt("unknown"), None);
    }

    #[test]
    fn test_deserialize_http_poc() {
        let yaml = r#"
id: test-poc
info:
  name: Test PoC
  severity: high
  category: test
transport: http
rules:
  - method: GET
    path: "/test"
    matchers:
      - type: word
        words:
          - "test_string"
"#;
        let poc: PoCRule = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(poc.id, "test-poc");
        assert_eq!(poc.info.severity, Severity::High);
        assert_eq!(poc.transport, Transport::Http);
    }

    #[test]
    fn test_deserialize_script_poc() {
        let yaml = r#"
id: script-test
info:
  name: Script Test
  severity: critical
transport: script
script:
  interpreter: python3
  code: |
    import json, sys
    print(json.dumps({"vulnerable": True, "evidence": "test"}))
"#;
        let poc: PoCRule = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(poc.transport, Transport::Script);
        assert!(poc.script.is_some());
        let script = poc.script.unwrap();
        assert_eq!(script.interpreter, "python3");
        assert!(script.code.is_some());
    }

    #[test]
    fn test_deserialize_extractors() {
        let yaml = r#"
id: multi-step
info:
  name: Multi Step Test
transport: http
rules:
  - method: GET
    path: "/login"
    extractors:
      - name: token
        type: regex
        part: body
        regex: 'token=([a-f0-9]+)'
    matchers:
      - type: status
        status: [200]
  - method: GET
    path: "/api?token={{token}}"
    matchers:
      - type: word
        words: ["admin"]
"#;
        let poc: PoCRule = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(poc.rules.len(), 2);
        assert_eq!(poc.rules[0].extractors.len(), 1);
        assert_eq!(poc.rules[0].extractors[0].name, "token");
        assert_eq!(poc.rules[1].path, "/api?token={{token}}");
    }

    #[test]
    fn test_substitute_vars() {
        let mut vars = HashMap::new();
        vars.insert("target".to_string(), "192.168.1.1".to_string());
        vars.insert("port".to_string(), "8080".to_string());

        let result = substitute_vars("http://{{target}}:{{port}}/api", &vars);
        assert_eq!(result, "http://192.168.1.1:8080/api");

        let result2 = substitute_vars("no vars here", &vars);
        assert_eq!(result2, "no vars here");
    }

    #[test]
    fn test_deserialize_json_poc() {
        let json = r#"{
            "id": "json-test",
            "info": {"name": "JSON Test", "severity": "low"},
            "transport": "http",
            "rules": [{"method": "POST", "path": "/api", "matchers": [{"type": "status", "status": [200]}]}]
        }"#;
        let poc: PoCRule = serde_json::from_str(json).unwrap();
        assert_eq!(poc.id, "json-test");
        assert_eq!(poc.info.severity, Severity::Low);
    }
}
