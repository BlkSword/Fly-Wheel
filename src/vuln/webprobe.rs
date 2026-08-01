//! Web 漏洞主动探测模块
//!
//! 在 Web 指纹识别基础上，进行轻量级主动漏洞探测。
//! 针对内网常见的 Web 应用进行非破坏性检测。
//!
//! 检测类型:
//! - SQL 注入 (基于时间的盲注)
//! - XSS (反射型)
//! - 命令注入 (盲测)
//! - 路径遍历
//! - 默认凭据
//! - 信息泄露

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// Web 漏洞发现结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebVuln {
    /// 漏洞 ID
    pub vuln_id: String,
    /// 漏洞名称
    pub name: String,
    /// 目标 URL
    pub target_url: String,
    /// 检测参数
    pub parameter: String,
    /// 漏洞类型
    pub vuln_type: WebVulnType,
    /// 严重性
    pub severity: WebSeverity,
    /// 证据
    pub evidence: String,
    /// 修复建议
    pub remediation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WebVulnType {
    /// SQL 注入 (盲注/时间盲注)
    SqlInjection,
    /// 反射型 XSS
    Xss,
    /// 命令注入
    CommandInjection,
    /// 路径遍历
    PathTraversal,
    /// 默认凭据
    DefaultCredentials,
    /// 信息泄露
    InformationDisclosure,
    /// 未授权访问
    UnauthorizedAccess,
}

impl WebVulnType {
    pub fn display_name(&self) -> &str {
        match self {
            WebVulnType::SqlInjection => "SQL注入",
            WebVulnType::Xss => "XSS",
            WebVulnType::CommandInjection => "命令注入",
            WebVulnType::PathTraversal => "路径遍历",
            WebVulnType::DefaultCredentials => "默认凭据",
            WebVulnType::InformationDisclosure => "信息泄露",
            WebVulnType::UnauthorizedAccess => "未授权访问",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WebSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl WebSeverity {
    pub fn display_name(&self) -> &str {
        match self {
            WebSeverity::Critical => "严重",
            WebSeverity::High => "高危",
            WebSeverity::Medium => "中危",
            WebSeverity::Low => "低危",
            WebSeverity::Info => "信息",
        }
    }
}

/// SQL 注入 Payload（时间盲注）
const SQLI_PAYLOADS: &[(&str, &str)] = &[
    ("' OR SLEEP(3)-- ", "MySQL 时间盲注 (SLEEP)"),
    ("'; WAITFOR DELAY '0:0:3'-- ", "MSSQL 时间盲注 (WAITFOR)"),
    ("' OR pg_sleep(3)-- ", "PostgreSQL 时间盲注 (pg_sleep)"),
    ("' AND 1=1-- ", "通用布尔盲注 (永真)"),
    ("' AND 1=2-- ", "通用布尔盲注 (永假)"),
];

/// XSS Payload
const XSS_PAYLOADS: &[(&str, &str)] = &[
    ("<script>alert(1)</script>", "基础 script 标签"),
    ("\"><img src=x onerror=alert(1)>", "HTML 属性注入"),
    ("'><img src=x onerror=alert(1)>", "单引号属性注入"),
    ("<svg/onload=alert(1)>", "SVG 事件注入"),
];

/// 命令注入 Payload
const CMDI_PAYLOADS: &[(&str, &str)] = &[
    ("; sleep 3", "分号命令分隔 (Unix)"),
    ("| sleep 3", "管道命令注入 (Unix)"),
    ("`sleep 3`", "反引号命令执行 (Unix)"),
    ("$(sleep 3)", "美元符号命令执行 (Unix)"),
    ("& ping -n 3 127.0.0.1", "& 命令分隔 (Windows)"),
];

/// 路径遍历 Payload
const PATH_TRAVERSAL_PATHS: &[&str] = &[
    "../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
];

/// 信息泄露路径
const INFO_LEAK_PATHS: &[(&str, &str)] = &[
    ("/.git/HEAD", "Git 仓库泄露"),
    ("/.env", "环境变量文件"),
    ("/phpinfo.php", "PHP 信息页面"),
    ("/actuator", "Spring Boot Actuator"),
    ("/.DS_Store", "macOS 目录文件"),
    ("/swagger-ui.html", "Swagger API 文档"),
    ("/api-docs", "Springfox API 文档"),
    ("/debug/pprof/", "Go pprof 调试端点"),
];

/// 常见默认凭据
const DEFAULT_CREDENTIALS: &[(&str, &str, &str)] = &[
    ("admin", "admin", "通用管理员"),
    ("root", "root", "Linux 通用"),
    ("admin", "password", "弱密码变体"),
    ("tomcat", "tomcat", "Apache Tomcat"),
    ("weblogic", "weblogic1", "Oracle WebLogic"),
    ("sa", "", "MSSQL SA 账户"),
];

/// Web 漏洞检测引擎
pub struct WebVulnScanner {
    /// 目标基础 URL
    pub base_url: String,
    /// HTTP 客户端超时
    pub timeout: Duration,
    /// 请求头
    pub headers: HashMap<String, String>,
}

impl WebVulnScanner {
    /// 创建新的扫描器
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            timeout: Duration::from_secs(5),
            headers: HashMap::from([
                (
                    "User-Agent".to_string(),
                    "Mozilla/5.0 Intranet Scanner".to_string(),
                ),
                ("Accept".to_string(), "*/*".to_string()),
            ]),
        }
    }

    /// 设置超时
    pub fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout = Duration::from_secs(secs);
        self
    }

    /// 添加自定义请求头
    pub fn with_header(mut self, key: &str, value: &str) -> Self {
        self.headers.insert(key.to_string(), value.to_string());
        self
    }

    /// 搜索可能存在注入的参数
    pub fn find_test_parameters(&self, url: &str) -> Vec<String> {
        let mut params = Vec::new();

        // 从 URL 中提取查询参数
        if let Some(query) = url.split('?').nth(1) {
            for pair in query.split('&') {
                if let Some(name) = pair.split('=').next() {
                    params.push(name.to_string());
                }
            }
        }

        // 添加通用测试参数
        if params.is_empty() {
            params.extend_from_slice(&[
                "id".to_string(),
                "search".to_string(),
                "q".to_string(),
                "page".to_string(),
                "query".to_string(),
                "name".to_string(),
                "file".to_string(),
                "path".to_string(),
                "dir".to_string(),
            ]);
        }

        params
    }

    /// 生成 SQL 注入测试向量
    pub fn generate_sqli_tests(&self, url: &str) -> Vec<WebVulnTest> {
        let params = self.find_test_parameters(url);
        let mut tests = Vec::new();

        for param in &params {
            for (payload, desc) in SQLI_PAYLOADS {
                let test_url = inject_param(url, param, payload);
                tests.push(WebVulnTest {
                    vuln_type: WebVulnType::SqlInjection,
                    url: test_url,
                    parameter: param.clone(),
                    payload: payload.to_string(),
                    description: desc.to_string(),
                    method: "GET".to_string(),
                });
            }
        }

        tests
    }

    /// 生成 XSS 测试向量
    pub fn generate_xss_tests(&self, url: &str) -> Vec<WebVulnTest> {
        let params = self.find_test_parameters(url);
        let mut tests = Vec::new();

        for param in &params {
            for (payload, desc) in XSS_PAYLOADS {
                let test_url = inject_param(url, param, payload);
                tests.push(WebVulnTest {
                    vuln_type: WebVulnType::Xss,
                    url: test_url,
                    parameter: param.clone(),
                    payload: payload.to_string(),
                    description: desc.to_string(),
                    method: "GET".to_string(),
                });
            }
        }

        tests
    }

    /// 生成命令注入测试向量
    pub fn generate_cmdi_tests(&self, url: &str) -> Vec<WebVulnTest> {
        let params = self.find_test_parameters(url);
        let mut tests = Vec::new();

        for param in &params {
            for (payload, desc) in CMDI_PAYLOADS {
                let test_url = inject_param(url, param, payload);
                tests.push(WebVulnTest {
                    vuln_type: WebVulnType::CommandInjection,
                    url: test_url,
                    parameter: param.clone(),
                    payload: payload.to_string(),
                    description: desc.to_string(),
                    method: "GET".to_string(),
                });
            }
        }

        tests
    }

    /// 生成路径遍历测试向量
    pub fn generate_path_traversal_tests(&self) -> Vec<WebVulnTest> {
        let mut tests = Vec::new();

        for path in PATH_TRAVERSAL_PATHS {
            let test_url = format!("{}/{}", self.base_url, path);
            tests.push(WebVulnTest {
                vuln_type: WebVulnType::PathTraversal,
                url: test_url,
                parameter: "path".to_string(),
                payload: path.to_string(),
                description: "路径遍历探测".to_string(),
                method: "GET".to_string(),
            });
        }

        // 也测试已知的文件参数
        for param in &["file", "path", "include", "template"] {
            for path in PATH_TRAVERSAL_PATHS.iter().take(1) {
                let test_url = format!("{}?{}={}", self.base_url, param, path);
                tests.push(WebVulnTest {
                    vuln_type: WebVulnType::PathTraversal,
                    url: test_url,
                    parameter: param.to_string(),
                    payload: path.to_string(),
                    description: "路径遍历参数注入".to_string(),
                    method: "GET".to_string(),
                });
            }
        }

        tests
    }

    /// 生成信息泄露测试向量
    pub fn generate_info_leak_tests(&self) -> Vec<WebVulnTest> {
        let mut tests = Vec::new();

        for (path, desc) in INFO_LEAK_PATHS {
            let test_url = format!("{}{}", self.base_url, path);
            tests.push(WebVulnTest {
                vuln_type: WebVulnType::InformationDisclosure,
                url: test_url,
                parameter: String::new(),
                payload: path.to_string(),
                description: desc.to_string(),
                method: "GET".to_string(),
            });
        }

        tests
    }

    /// 生成默认凭据测试向量
    pub fn generate_default_cred_tests(&self) -> Vec<WebVulnTest> {
        let mut tests = Vec::new();

        for (username, password, desc) in DEFAULT_CREDENTIALS {
            tests.push(WebVulnTest {
                vuln_type: WebVulnType::DefaultCredentials,
                url: format!("{}/login", self.base_url),
                parameter: "credentials".to_string(),
                payload: format!("{}:{}", username, password),
                description: format!("{} ({}/{})", desc, username, password),
                method: "POST".to_string(),
            });
        }

        tests
    }

    /// 生成所有测试向量
    pub fn generate_all_tests(&self, url: &str) -> Vec<WebVulnTest> {
        let mut all = Vec::new();
        all.extend(self.generate_sqli_tests(url));
        all.extend(self.generate_xss_tests(url));
        all.extend(self.generate_cmdi_tests(url));
        all.extend(self.generate_path_traversal_tests());
        all.extend(self.generate_info_leak_tests());
        all.extend(self.generate_default_cred_tests());
        all
    }
}

/// Web 漏洞测试向量
#[derive(Debug, Clone)]
pub struct WebVulnTest {
    pub vuln_type: WebVulnType,
    pub url: String,
    pub parameter: String,
    pub payload: String,
    pub description: String,
    pub method: String,
}

/// 向 URL 参数注入 payload
fn inject_param(url: &str, param: &str, payload: &str) -> String {
    // URL 编码 payload
    let encoded = urlencoding(payload);

    if url.contains('?') {
        // 替换已有参数的值
        let parts: Vec<&str> = url.splitn(2, '?').collect();
        let base = parts[0];
        let query = parts[1];

        let mut new_params = Vec::new();
        let mut found = false;

        for pair in query.split('&') {
            if let Some(name) = pair.split('=').next() {
                if name == param {
                    new_params.push(format!("{}={}", name, encoded));
                    found = true;
                } else {
                    new_params.push(pair.to_string());
                }
            }
        }

        if found {
            format!("{}?{}", base, new_params.join("&"))
        } else {
            format!("{}&{}={}", url, param, encoded)
        }
    } else {
        format!("{}?{}={}", url, param, encoded)
    }
}

/// 简单 URL 编码
fn urlencoding(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 3);
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(byte as char);
            }
            b' ' => result.push('+'),
            _ => result.push_str(&format!("%{:02X}", byte)),
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_web_vuln_scanner_creation() {
        let scanner = WebVulnScanner::new("http://example.com");
        assert_eq!(scanner.base_url, "http://example.com");
        assert_eq!(scanner.timeout, Duration::from_secs(5));
    }

    #[test]
    fn test_find_parameters_from_url() {
        let scanner = WebVulnScanner::new("http://test.com");
        let params = scanner.find_test_parameters("http://test.com?id=1&name=test&page=2");
        assert!(params.contains(&"id".to_string()));
        assert!(params.contains(&"name".to_string()));
        assert!(params.contains(&"page".to_string()));
    }

    #[test]
    fn test_find_parameters_no_query() {
        let scanner = WebVulnScanner::new("http://test.com");
        let params = scanner.find_test_parameters("http://test.com/page");
        // 应返回默认参数
        assert!(!params.is_empty());
        assert!(params.contains(&"id".to_string()));
    }

    #[test]
    fn test_inject_param_existing() {
        let result = inject_param("http://test.com?id=1&name=test", "id", "' OR 1=1--");
        assert!(result.contains("id="));
        assert!(result.contains("27+OR+1%3D1--"));
    }

    #[test]
    fn test_inject_param_new() {
        let result = inject_param("http://test.com/page", "q", "<script>");
        assert!(result.contains("q=%3Cscript%3E"));
    }

    #[test]
    fn test_generate_sqli_tests() {
        let scanner = WebVulnScanner::new("http://test.com");
        let tests = scanner.generate_sqli_tests("http://test.com?id=1");
        assert!(!tests.is_empty());
        for test in &tests {
            assert_eq!(test.vuln_type, WebVulnType::SqlInjection);
            assert_eq!(test.parameter, "id");
        }
    }

    #[test]
    fn test_generate_xss_tests() {
        let scanner = WebVulnScanner::new("http://test.com");
        let tests = scanner.generate_xss_tests("http://test.com?search=test");
        assert!(!tests.is_empty());
        for test in &tests {
            assert_eq!(test.vuln_type, WebVulnType::Xss);
        }
    }

    #[test]
    fn test_generate_path_traversal_tests() {
        let scanner = WebVulnScanner::new("http://test.com");
        let tests = scanner.generate_path_traversal_tests();
        assert!(tests.len() >= PATH_TRAVERSAL_PATHS.len());
    }

    #[test]
    fn test_generate_info_leak_tests() {
        let scanner = WebVulnScanner::new("http://test.com");
        let tests = scanner.generate_info_leak_tests();
        assert_eq!(tests.len(), INFO_LEAK_PATHS.len());
    }

    #[test]
    fn test_generate_default_cred_tests() {
        let scanner = WebVulnScanner::new("http://test.com");
        let tests = scanner.generate_default_cred_tests();
        assert_eq!(tests.len(), DEFAULT_CREDENTIALS.len());
    }

    #[test]
    fn test_url_encoding_special_chars() {
        let encoded = urlencoding("<script>alert(1)</script>");
        assert!(!encoded.contains('<'));
        assert!(!encoded.contains('>'));
        assert!(encoded.contains("%3C"));
        assert!(encoded.contains("%3E"));
    }

    #[test]
    fn test_url_encoding_alphanumeric() {
        let encoded = urlencoding("abc123ABC");
        assert_eq!(encoded, "abc123ABC");
    }

    #[test]
    fn test_web_vuln_type_display() {
        assert_eq!(WebVulnType::SqlInjection.display_name(), "SQL注入");
        assert_eq!(WebVulnType::Xss.display_name(), "XSS");
        assert_eq!(WebVulnType::PathTraversal.display_name(), "路径遍历");
    }

    #[test]
    fn test_web_severity_display() {
        assert_eq!(WebSeverity::Critical.display_name(), "严重");
        assert_eq!(WebSeverity::Info.display_name(), "信息");
    }
}
