//! 响应匹配逻辑
//!
//! 实现 word, regex, status, binary 四种匹配器

use crate::vuln::poc::{Matcher, MatcherType};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// 全局正则表达式缓存 (Regex 内部基于 Arc，clone 开销极低)
fn get_or_compile_regex(pattern: &str) -> Option<regex::Regex> {
    static CACHE: OnceLock<Mutex<HashMap<String, regex::Regex>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = cache.lock().unwrap();
    if let Some(re) = map.get(pattern) {
        return Some(re.clone());
    }
    let re = regex::Regex::new(pattern).ok()?;
    map.insert(pattern.to_string(), re.clone());
    Some(re)
}

/// HTTP 响应匹配上下文
pub struct HttpResponseContext {
    pub status_code: u16,
    pub headers: String,
    pub body: String,
}

/// 对 HTTP 响应执行匹配器列表
pub fn match_http_response(matchers: &[Matcher], condition: &str, ctx: &HttpResponseContext) -> bool {
    let results: Vec<bool> = matchers.iter().map(|m| match_http_matcher(m, ctx)).collect();

    match condition {
        "or" => results.iter().any(|&r| r),
        _ => results.iter().all(|&r| r),
    }
}

fn match_http_matcher(m: &Matcher, ctx: &HttpResponseContext) -> bool {
    let result = match m.matcher_type {
        MatcherType::Status => m.status.contains(&ctx.status_code),
        MatcherType::Word => match m.part.as_str() {
            "header" => m.words.iter().any(|w| ctx.headers.contains(w)),
            "all" => m
                .words
                .iter()
                .any(|w| ctx.body.contains(w) || ctx.headers.contains(w)),
            _ => m.words.iter().any(|w| ctx.body.contains(w)),
        },
        MatcherType::Regex => {
            let target = match m.part.as_str() {
                "header" => &ctx.headers,
                _ => &ctx.body,
            };
            m.regex.iter().any(|pattern| {
                get_or_compile_regex(pattern)
                    .map(|re| re.is_match(target))
                    .unwrap_or(false)
            })
        }
        MatcherType::Binary => {
            // HTTP Binary 匹配：在响应 body 的原始字节中搜索十六进制模式
            let body_bytes = ctx.body.as_bytes();
            m.binary
                .iter()
                .any(|hex| hex_decode(hex).map(|bytes| find_subsequence(body_bytes, &bytes)).unwrap_or(false))
        }
    };

    if m.negative {
        !result
    } else {
        result
    }
}

/// 对 TCP 响应执行匹配器列表
pub fn match_tcp_response(matchers: &[Matcher], condition: &str, data: &[u8]) -> bool {
    let results: Vec<bool> = matchers.iter().map(|m| match_tcp_matcher(m, data)).collect();

    match condition {
        "or" => results.iter().any(|&r| r),
        _ => results.iter().all(|&r| r),
    }
}

fn match_tcp_matcher(m: &Matcher, data: &[u8]) -> bool {
    let result = match m.matcher_type {
        MatcherType::Word => {
            let data_str = String::from_utf8_lossy(data);
            m.words.iter().any(|w| data_str.contains(w))
        }
        MatcherType::Binary => m
            .binary
            .iter()
            .any(|hex| hex_decode(hex).map(|bytes| find_subsequence(data, &bytes)).unwrap_or(false)),
        MatcherType::Regex => {
            let data_str = String::from_utf8_lossy(data);
            m.regex.iter().any(|pattern| {
                get_or_compile_regex(pattern)
                    .map(|re| re.is_match(&data_str))
                    .unwrap_or(false)
            })
        }
        // TCP 无 HTTP 状态码概念，Status 匹配器在 TCP 上下文中不适用
        MatcherType::Status => false,
    };

    if m.negative {
        !result
    } else {
        result
    }
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for chunk in hex.as_bytes().chunks(2) {
        let high = char::from(chunk[0]).to_digit(16)?;
        let low = char::from(chunk[1]).to_digit(16)?;
        bytes.push((high << 4 | low) as u8);
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_word_matcher(part: &str, words: Vec<&str>) -> Matcher {
        Matcher {
            matcher_type: MatcherType::Word,
            part: part.to_string(),
            words: words.into_iter().map(|s| s.to_string()).collect(),
            regex: vec![],
            status: vec![],
            binary: vec![],
            negative: false,
        }
    }

    fn make_status_matcher(status: Vec<u16>) -> Matcher {
        Matcher {
            matcher_type: MatcherType::Status,
            part: "status_code".to_string(),
            words: vec![],
            regex: vec![],
            status,
            binary: vec![],
            negative: false,
        }
    }

    fn make_regex_matcher(part: &str, regex: Vec<&str>) -> Matcher {
        Matcher {
            matcher_type: MatcherType::Regex,
            part: part.to_string(),
            words: vec![],
            regex: regex.into_iter().map(|s| s.to_string()).collect(),
            status: vec![],
            binary: vec![],
            negative: false,
        }
    }

    #[test]
    fn test_word_matcher_body() {
        let ctx = HttpResponseContext {
            status_code: 200,
            headers: String::new(),
            body: "Hello World Test Page".to_string(),
        };
        let m = make_word_matcher("body", vec!["Test"]);
        assert!(match_http_matcher(&m, &ctx));
    }

    #[test]
    fn test_word_matcher_header() {
        let ctx = HttpResponseContext {
            status_code: 200,
            headers: "set-cookie: rememberMe=deleteMe\nserver: Apache".to_string(),
            body: String::new(),
        };
        let m = make_word_matcher("header", vec!["rememberMe=deleteMe"]);
        assert!(match_http_matcher(&m, &ctx));
    }

    #[test]
    fn test_status_matcher() {
        let ctx = HttpResponseContext {
            status_code: 200,
            headers: String::new(),
            body: String::new(),
        };
        let m = make_status_matcher(vec![200, 301]);
        assert!(match_http_matcher(&m, &ctx));

        let m2 = make_status_matcher(vec![404, 500]);
        assert!(!match_http_matcher(&m2, &ctx));
    }

    #[test]
    fn test_regex_matcher() {
        let ctx = HttpResponseContext {
            status_code: 200,
            headers: String::new(),
            body: "version: 1.2.3".to_string(),
        };
        let m = make_regex_matcher("body", vec![r"version: \d+\.\d+"]);
        assert!(match_http_matcher(&m, &ctx));
    }

    #[test]
    fn test_negative_matcher() {
        let ctx = HttpResponseContext {
            status_code: 200,
            headers: String::new(),
            body: "Hello World".to_string(),
        };
        let mut m = make_word_matcher("body", vec!["error"]);
        m.negative = true;
        assert!(match_http_matcher(&m, &ctx));
    }

    #[test]
    fn test_and_condition() {
        let ctx = HttpResponseContext {
            status_code: 200,
            headers: "server: nginx".to_string(),
            body: "Welcome".to_string(),
        };
        let matchers = vec![
            make_status_matcher(vec![200]),
            make_word_matcher("body", vec!["Welcome"]),
        ];
        assert!(match_http_response(&matchers, "and", &ctx));
    }

    #[test]
    fn test_or_condition() {
        let ctx = HttpResponseContext {
            status_code: 404,
            headers: String::new(),
            body: "Welcome".to_string(),
        };
        let matchers = vec![
            make_status_matcher(vec![200]),
            make_word_matcher("body", vec!["Welcome"]),
        ];
        assert!(match_http_response(&matchers, "or", &ctx));
        assert!(!match_http_response(&matchers, "and", &ctx));
    }

    #[test]
    fn test_tcp_word_matcher() {
        let data = b"redis_version:7.0.0\r\n";
        let m = make_word_matcher("body", vec!["redis_version"]);
        assert!(match_tcp_matcher(&m, data));
    }

    #[test]
    fn test_tcp_binary_matcher() {
        let data = b"\x00\x00\x00\x2d\xffSMB";
        let mut m = Matcher {
            matcher_type: MatcherType::Binary,
            part: String::new(),
            words: vec![],
            regex: vec![],
            status: vec![],
            binary: vec!["ff534d42".to_string()],
            negative: false,
        };
        assert!(match_tcp_matcher(&m, data));

        m.binary = vec!["deadbeef".to_string()];
        assert!(!match_tcp_matcher(&m, data));
    }

    #[test]
    fn test_hex_decode() {
        assert_eq!(hex_decode("ff534d42"), Some(vec![0xff, 0x53, 0x4d, 0x42]));
        assert_eq!(hex_decode("00"), Some(vec![0x00]));
        assert_eq!(hex_decode("invalid"), None);
        assert_eq!(hex_decode("fff"), None); // odd length
    }
}
