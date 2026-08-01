//! PoC 执行引擎
//!
//! HTTP 传输通过 reqwest 执行，TCP 传输通过 tokio TcpStream 执行

use crate::core::Result;
use crate::vuln::matchers::HttpResponseContext;
use crate::vuln::poc::{substitute_vars, Extractor, PoCRequest};
use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 全局共享的 HTTP 客户端 (避免每次请求都创建新 Client)
fn global_http_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::limited(3))
            .no_proxy()
            .build()
            .expect("构建HTTP客户端失败")
    })
}

/// 执行 HTTP PoC 请求 (支持变量替换)
pub async fn execute_http_request(
    target: &str,
    port: u16,
    request: &PoCRequest,
    timeout: Duration,
    vars: &HashMap<String, String>,
) -> Result<HttpResponseContext> {
    let path = substitute_vars(&request.path, vars);
    let headers: HashMap<String, String> = request
        .headers
        .iter()
        .map(|(k, v)| (k.clone(), substitute_vars(v, vars)))
        .collect();
    let body = request.body.as_ref().map(|b| substitute_vars(b, vars));

    let client = global_http_client();

    let scheme = if matches!(port, 443 | 8443 | 9443) {
        "https"
    } else {
        "http"
    };
    let url = format!("{}://{}:{}{}", scheme, target, port, path);

    let mut builder = match request.method.to_uppercase().as_str() {
        "POST" => client.post(&url),
        "PUT" => client.put(&url),
        "DELETE" => client.delete(&url),
        "HEAD" => client.head(&url),
        "OPTIONS" => client.request(reqwest::Method::OPTIONS, &url),
        "PATCH" => client.patch(&url),
        _ => client.get(&url),
    };

    builder = builder.timeout(timeout);

    builder = builder.header(
        "User-Agent",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    );

    for (key, value) in &headers {
        builder = builder.header(key.as_str(), value.as_str());
    }

    if let Some(body) = body {
        builder = builder.body(body);
    }

    let resp = builder
        .send()
        .await
        .map_err(|e| crate::core::error::IntraSweepError::Other {
            message: format!("HTTP请求失败: {}", e),
        })?;

    let status_code = resp.status().as_u16();
    let headers_str = resp
        .headers()
        .iter()
        .map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or("")))
        .collect::<Vec<_>>()
        .join("\n");
    let resp_body = resp.text().await.unwrap_or_default();

    Ok(HttpResponseContext {
        status_code,
        headers: headers_str,
        body: resp_body,
    })
}

/// TCP 响应数据
pub struct TcpResponseData {
    pub data: Vec<u8>,
}

/// 执行 TCP PoC 请求 (支持变量替换)
pub async fn execute_tcp_request(
    target: &str,
    port: u16,
    request: &PoCRequest,
    timeout: Duration,
    vars: &HashMap<String, String>,
) -> Result<TcpResponseData> {
    use crate::core::error::IntraSweepError;

    let data = request
        .data
        .as_ref()
        .map(|d| substitute_vars(d, vars))
        .unwrap_or_default();

    let addr = format!("{}:{}", target, port);
    let mut stream = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr))
        .await
        .map_err(|_| IntraSweepError::Other {
            message: format!("TCP连接超时: {}", addr),
        })??;

    if !data.is_empty() {
        tokio::time::timeout(timeout, stream.write_all(data.as_bytes()))
            .await
            .map_err(|_| IntraSweepError::Other {
                message: "TCP写入超时".to_string(),
            })??;
    }

    let read_size = request.read_size.unwrap_or(4096);
    let mut buf = vec![0u8; read_size];
    let n = tokio::time::timeout(timeout, stream.read(&mut buf))
        .await
        .map_err(|_| IntraSweepError::Other {
            message: "TCP读取超时".to_string(),
        })??;
    buf.truncate(n);

    Ok(TcpResponseData { data: buf })
}

/// 从 HTTP 响应中提取变量
pub fn extract_http_vars(
    ctx: &HttpResponseContext,
    extractors: &[Extractor],
) -> HashMap<String, String> {
    let mut vars = HashMap::new();

    for ext in extractors {
        let target_text = match ext.part.as_str() {
            "header" => &ctx.headers,
            "all" => {
                // 对 "all" 模式，组合 header + body
                let combined = format!("{}\n{}", ctx.headers, ctx.body);
                extract_regex(&combined, &ext.regex, ext.group)
                    .into_iter()
                    .for_each(|(k, v)| {
                        vars.insert(k, v);
                    });
                continue;
            }
            _ => &ctx.body,
        };

        if let Some(value) = extract_regex_single(target_text, &ext.regex, ext.group) {
            vars.insert(ext.name.clone(), value);
        }
    }

    vars
}

/// 从 TCP 响应中提取变量
pub fn extract_tcp_vars(data: &[u8], extractors: &[Extractor]) -> HashMap<String, String> {
    let text = String::from_utf8_lossy(data);
    let mut vars = HashMap::new();

    for ext in extractors {
        if let Some(value) = extract_regex_single(&text, &ext.regex, ext.group) {
            vars.insert(ext.name.clone(), value);
        }
    }

    vars
}

fn extract_regex_single(text: &str, pattern: &Option<String>, group: usize) -> Option<String> {
    let pattern = pattern.as_ref()?;
    let re = regex::Regex::new(pattern).ok()?;
    let caps = re.captures(text)?;
    caps.get(group).map(|m| m.as_str().to_string())
}

fn extract_regex(text: &str, pattern: &Option<String>, group: usize) -> Vec<(String, String)> {
    let pattern = match pattern {
        Some(p) => p,
        None => return vec![],
    };
    let re = match regex::Regex::new(pattern) {
        Ok(r) => r,
        Err(_) => return vec![],
    };

    re.captures(text)
        .and_then(|caps| caps.get(group).map(|m| m.as_str().to_string()))
        .map(|v| vec![("value".to_string(), v)])
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vuln::poc::ExtractorType;

    #[test]
    fn test_scheme_selection() {
        assert_eq!(
            if matches!(443u16, 443 | 8443 | 9443) {
                "https"
            } else {
                "http"
            },
            "https"
        );
    }

    #[test]
    fn test_extract_vars_from_http() {
        let ctx = HttpResponseContext {
            status_code: 200,
            headers: "x-csrf-token: abc123def".to_string(),
            body: r#"{"token":"xyz789","user":"admin"}"#.to_string(),
        };

        let extractors = vec![
            Extractor {
                name: "csrf_token".to_string(),
                extractor_type: ExtractorType::Regex,
                part: "header".to_string(),
                regex: Some(r"x-csrf-token: (\w+)".to_string()),
                group: 1,
                internal: vec![],
            },
            Extractor {
                name: "api_token".to_string(),
                extractor_type: ExtractorType::Regex,
                part: "body".to_string(),
                regex: Some(r#""token":"(\w+)""#.to_string()),
                group: 1,
                internal: vec![],
            },
        ];

        let vars = extract_http_vars(&ctx, &extractors);
        assert_eq!(vars.get("csrf_token"), Some(&"abc123def".to_string()));
        assert_eq!(vars.get("api_token"), Some(&"xyz789".to_string()));
    }

    #[test]
    fn test_extract_vars_from_tcp() {
        let data = b"Session ID: ABC-123-XYZ\r\n";

        let extractors = vec![Extractor {
            name: "session_id".to_string(),
            extractor_type: ExtractorType::Regex,
            part: String::new(),
            regex: Some(r"Session ID: ([A-Z0-9-]+)".to_string()),
            group: 1,
            internal: vec![],
        }];

        let vars = extract_tcp_vars(data, &extractors);
        assert_eq!(vars.get("session_id"), Some(&"ABC-123-XYZ".to_string()));
    }

    #[test]
    fn test_substitute_vars_in_request() {
        let mut vars = HashMap::new();
        vars.insert("token".to_string(), "abc123".to_string());

        let result = substitute_vars("/api?token={{token}}&page=1", &vars);
        assert_eq!(result, "/api?token=abc123&page=1");
    }
}
