//! Web 指纹探测引擎
//!
//! 对 HTTP/HTTPS 端口进行深度探测，提取页面信息和 Web 应用指纹

use crate::scanner::models::{WebAppMatch, WebFingerprint};
use crate::scanner::webfinger_db::FINGERPRINT_DB;
use std::net::IpAddr;
use std::time::Duration;

/// 常见 HTTP 端口列表
const HTTP_PORTS: &[u16] = &[
    80, 443, 8000, 8080, 8443, 8888, 3000, 5000, 7001, 7002, 8081, 9090, 9080, 9443,
];

/// 判断端口是否可能是 HTTP/HTTPS 服务
pub fn is_http_port(port: u16) -> bool {
    HTTP_PORTS.contains(&port)
}

/// HTTPS 默认端口
const HTTPS_PORTS: &[u16] = &[443, 8443, 9443];

/// HTTP 响应信息
struct HttpResponse {
    status_code: u16,
    headers: Vec<(String, String)>,
    body: String,
}

/// Web 指纹扫描器
pub struct WebFingerScanner {
    client: reqwest::Client,
    timeout: Duration,
}

impl WebFingerScanner {
    /// 创建新的扫描器
    pub fn new(timeout_ms: u64) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(timeout_ms))
            .pool_max_idle_per_host(4)
            .pool_idle_timeout(Duration::from_secs(30))
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self {
            client,
            timeout: Duration::from_millis(timeout_ms),
        }
    }

    /// 并行探测主机的所有 HTTP 端口
    pub async fn probe_host_all(&self, ip: IpAddr, ports: &[u16]) -> Vec<WebFingerprint> {
        let probes: Vec<_> = ports
            .iter()
            .map(|&port| self.probe_port(ip, port))
            .collect();

        let results = futures::future::join_all(probes).await;
        results.into_iter().flatten().collect()
    }

    /// 探测单个端口（同时尝试 HTTP 和 HTTPS，取先成功的）
    async fn probe_port(&self, ip: IpAddr, port: u16) -> Option<WebFingerprint> {
        let is_https = HTTPS_PORTS.contains(&port);

        let (primary, fallback) = if is_https {
            ("https", "http")
        } else {
            ("http", "https")
        };

        let url_primary = format!("{}://{}:{}", primary, ip, port);
        let url_fallback = format!("{}://{}:{}", fallback, ip, port);

        // 并行探测两个协议
        let (resp_primary, resp_fallback) = tokio::join!(
            self.fetch_response(&url_primary),
            self.fetch_response(&url_fallback),
        );

        // 优先使用主协议的结果
        let (response, url, is_https_actual) = if let Some(resp) = resp_primary {
            (resp, url_primary, is_https)
        } else {
            let resp = resp_fallback?;
            (resp, url_fallback, !is_https)
        };

        let title = Self::extract_title(&response.body);
        let server = Self::extract_header(&response.headers, "server");
        let favicon_hash = self.fetch_favicon_hash(&url).await;
        let web_apps = Self::match_fingerprints(&response);

        if !web_apps.is_empty() || response.status_code == 200 {
            tracing::info!(
                "发现 Web 服务: {}:{} - 标题: '{}', 应用: {:?}",
                ip,
                port,
                title,
                web_apps.iter().map(|a| a.name.as_str()).collect::<Vec<_>>()
            );

            Some(WebFingerprint {
                url,
                status_code: response.status_code,
                title,
                server,
                favicon_hash,
                web_apps,
                body_length: response.body.len(),
                is_https: is_https_actual,
            })
        } else {
            None
        }
    }

    /// 发送 HTTP GET 请求
    async fn fetch_response(&self, url: &str) -> Option<HttpResponse> {
        let resp = tokio::time::timeout(self.timeout, async {
            self.client
                .get(url)
                .header(
                    "User-Agent",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                )
                .header(
                    "Accept",
                    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                )
                .send()
                .await
        })
        .await
        .ok()?
        .ok()?;

        let status_code = resp.status().as_u16();
        let headers: Vec<(String, String)> = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();

        let body = resp.text().await.unwrap_or_default();

        Some(HttpResponse {
            status_code,
            headers,
            body,
        })
    }

    /// 获取 favicon hash
    async fn fetch_favicon_hash(&self, base_url: &str) -> Option<i32> {
        let favicon_url = format!("{}/favicon.ico", base_url.trim_end_matches('/'));
        let resp = tokio::time::timeout(self.timeout, async {
            self.client.get(&favicon_url).send().await
        })
        .await
        .ok()?
        .ok()?;

        if resp.status().is_success() {
            let bytes = resp.bytes().await.ok()?;
            if bytes.len() < 10 {
                return None;
            }
            let hash = mur3::murmurhash3_x86_32(&bytes, 0) as i32;
            Some(hash)
        } else {
            None
        }
    }

    /// 匹配指纹数据库（避免构建中间字符串）
    fn match_fingerprints(response: &HttpResponse) -> Vec<WebAppMatch> {
        let mut matches = Vec::new();
        let body_lower = response.body.to_lowercase();

        for rule in FINGERPRINT_DB {
            let header_match = rule.header_patterns.iter().any(|p| {
                response.headers.iter().any(|(k, v)| {
                    k.as_str().eq_ignore_ascii_case(p)
                        || v.to_lowercase().contains(&p.to_lowercase())
                })
            });
            let body_match = rule
                .body_patterns
                .iter()
                .any(|p| body_lower.contains(&p.to_lowercase()));

            if header_match || body_match {
                matches.push(WebAppMatch {
                    name: rule.name.to_string(),
                    confidence: rule.confidence,
                    version: None,
                    category: rule.category.to_string(),
                });
            }
        }

        matches
    }

    /// 提取页面标题
    fn extract_title(body: &str) -> String {
        let lower = body.to_lowercase();
        if let Some(start) = lower.find("<title>") {
            if let Some(end) = lower.find("</title>") {
                let content_start = start + 7;
                if content_start < end {
                    return body[content_start..end].trim().to_string();
                }
            }
        }
        String::new()
    }

    /// 提取指定响应头
    fn extract_header(headers: &[(String, String)], name: &str) -> Option<String> {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_title() {
        assert_eq!(
            WebFingerScanner::extract_title("<html><title>Test Page</title></html>"),
            "Test Page"
        );
        assert_eq!(
            WebFingerScanner::extract_title("<html><TITLE>Hello World</TITLE></html>"),
            "Hello World"
        );
        assert_eq!(WebFingerScanner::extract_title("<html>no title</html>"), "");
        assert_eq!(
            WebFingerScanner::extract_title("<title>  Spaces  </title>"),
            "Spaces"
        );
    }

    #[test]
    fn test_is_http_port() {
        assert!(is_http_port(80));
        assert!(is_http_port(443));
        assert!(is_http_port(8080));
        assert!(is_http_port(3000));
        assert!(!is_http_port(22));
        assert!(!is_http_port(3306));
    }

    #[test]
    fn test_match_fingerprints_empty() {
        let response = HttpResponse {
            status_code: 200,
            headers: vec![],
            body: "Just some random page".to_string(),
        };
        let matches = WebFingerScanner::match_fingerprints(&response);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_match_fingerprints_nginx() {
        let response = HttpResponse {
            status_code: 200,
            headers: vec![("server".to_string(), "nginx/1.18.0".to_string())],
            body: "Welcome to nginx!".to_string(),
        };
        let matches = WebFingerScanner::match_fingerprints(&response);
        assert!(matches.iter().any(|m| m.name == "Nginx"));
    }

    #[test]
    fn test_match_fingerprints_jenkins() {
        let response = HttpResponse {
            status_code: 200,
            headers: vec![("x-jenkins".to_string(), "2.300".to_string())],
            body: "[Jenkins] Dashboard".to_string(),
        };
        let matches = WebFingerScanner::match_fingerprints(&response);
        assert!(matches.iter().any(|m| m.name == "Jenkins"));
    }

    #[test]
    fn test_match_fingerprints_baota() {
        let response = HttpResponse {
            status_code: 200,
            headers: vec![],
            body: "<html><title>宝塔面板</title></html>".to_string(),
        };
        let matches = WebFingerScanner::match_fingerprints(&response);
        assert!(matches.iter().any(|m| m.name == "宝塔面板"));
    }

    #[test]
    fn test_webfinger_scanner_creation() {
        let _scanner = WebFingerScanner::new(5000);
    }
}
