//! 脚本 PoC 执行器
//!
//! 支持 Python / PowerShell / Bash 脚本作为 PoC 执行

use crate::vuln::poc::ScriptConfig;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

/// 脚本输出结果 (JSON 格式)
#[derive(Debug, Deserialize, Default)]
pub struct ScriptOutput {
    #[serde(default)]
    pub vulnerable: bool,
    #[serde(default)]
    pub evidence: String,
    #[serde(default)]
    pub detail: String,
}

/// 执行脚本 PoC
pub async fn execute_script(
    config: &ScriptConfig,
    target: &str,
    port: u16,
    poc_dir: Option<&Path>,
) -> Option<ScriptOutput> {
    let timeout = Duration::from_secs(config.timeout);
    let target_owned = target.to_string();
    let port_str = port.to_string();

    let (cmd, args) = build_command(config, target, port, poc_dir)?;

    tracing::debug!("执行脚本: {} {:?}", cmd, args);

    let output = tokio::time::timeout(timeout, async {
        tokio::task::spawn_blocking(move || {
            std::process::Command::new(&cmd)
                .args(&args)
                .env("TARGET", &target_owned)
                .env("PORT", &port_str)
                .output()
        })
        .await
    })
    .await;

    match output {
        Ok(Ok(Ok(out))) => {
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();

            tracing::debug!(
                "脚本输出 stdout: {} chars, stderr: {} chars",
                stdout.len(),
                stderr.len()
            );

            if !out.status.success() && stdout.trim().is_empty() {
                tracing::debug!(
                    "脚本执行失败 (exit {:?}): {}",
                    out.status.code(),
                    stderr.trim()
                );
                return None;
            }

            parse_script_output(&stdout)
        }
        Ok(Ok(Err(e))) => {
            tracing::debug!("脚本启动失败: {}", e);
            None
        }
        Ok(Err(e)) => {
            tracing::debug!("脚本执行任务失败: {}", e);
            None
        }
        Err(_) => {
            tracing::debug!("脚本执行超时 ({}s)", config.timeout);
            None
        }
    }
}

/// 构建命令行
fn build_command(
    config: &ScriptConfig,
    target: &str,
    port: u16,
    poc_dir: Option<&Path>,
) -> Option<(String, Vec<String>)> {
    // 变量替换
    let mut vars = HashMap::new();
    vars.insert("target".to_string(), target.to_string());
    vars.insert("port".to_string(), port.to_string());

    let substitute = |s: &str| -> String {
        let mut result = s.to_string();
        for (k, v) in &vars {
            result = result.replace(&format!("{{{{{}}}}}", k), v);
        }
        result
    };

    match config.interpreter.to_lowercase().as_str() {
        "python3" | "python" => {
            if let Some(ref file) = config.file {
                let script_path = if let Some(dir) = poc_dir {
                    dir.join(file).to_string_lossy().to_string()
                } else {
                    file.clone()
                };

                let mut args = vec!["-u".to_string(), script_path];
                for arg in &config.args {
                    args.push(substitute(arg));
                }
                Some((find_python(), args))
            } else if let Some(ref code) = config.code {
                let mut args = vec!["-u".to_string(), "-c".to_string(), code.clone()];
                for arg in &config.args {
                    args.push(substitute(arg));
                }
                Some((find_python(), args))
            } else {
                None
            }
        }
        "powershell" | "pwsh" => {
            let exe = if cfg!(windows) {
                "powershell".to_string()
            } else {
                "pwsh".to_string()
            };

            if let Some(ref file) = config.file {
                let script_path = if let Some(dir) = poc_dir {
                    dir.join(file).to_string_lossy().to_string()
                } else {
                    file.clone()
                };
                let mut args = vec![
                    "-NoProfile".to_string(),
                    "-ExecutionPolicy".to_string(),
                    "Bypass".to_string(),
                    "-File".to_string(),
                    script_path,
                ];
                for arg in &config.args {
                    args.push(substitute(arg));
                }
                Some((exe, args))
            } else if let Some(ref code) = config.code {
                let mut args = vec![
                    "-NoProfile".to_string(),
                    "-ExecutionPolicy".to_string(),
                    "Bypass".to_string(),
                    "-Command".to_string(),
                    code.clone(),
                ];
                for arg in &config.args {
                    args.push(substitute(arg));
                }
                Some((exe, args))
            } else {
                None
            }
        }
        "bash" | "sh" => {
            let exe = config.interpreter.clone();
            if let Some(ref file) = config.file {
                let script_path = if let Some(dir) = poc_dir {
                    dir.join(file).to_string_lossy().to_string()
                } else {
                    file.clone()
                };
                let mut args = vec![script_path];
                for arg in &config.args {
                    args.push(substitute(arg));
                }
                Some((exe, args))
            } else if let Some(ref code) = config.code {
                let mut args = vec!["-c".to_string(), code.clone()];
                for arg in &config.args {
                    args.push(substitute(arg));
                }
                Some((exe, args))
            } else {
                None
            }
        }
        _ => {
            tracing::warn!("不支持的解释器: {}", config.interpreter);
            None
        }
    }
}

/// 查找可用的 Python 解释器
fn find_python() -> String {
    for cmd in &["python3", "python"] {
        if std::process::Command::new(cmd)
            .arg("--version")
            .output()
            .is_ok()
        {
            return cmd.to_string();
        }
    }
    "python3".to_string()
}

/// 解析脚本 JSON 输出
fn parse_script_output(stdout: &str) -> Option<ScriptOutput> {
    let stdout = stdout.trim();

    // 尝试直接解析整个输出为 JSON
    if let Ok(output) = serde_json::from_str::<ScriptOutput>(stdout) {
        return Some(output);
    }

    // 尝试从多行输出中找 JSON 行
    for line in stdout.lines().rev() {
        let line = line.trim();
        if line.starts_with('{') {
            if let Ok(output) = serde_json::from_str::<ScriptOutput>(line) {
                return Some(output);
            }
        }
    }

    // 尝试宽松匹配: 包含 "vulnerable": true
    if stdout.contains("\"vulnerable\"") && stdout.contains("true") {
        return Some(ScriptOutput {
            vulnerable: true,
            evidence: stdout.chars().take(500).collect(),
            detail: String::new(),
        });
    }

    None
}

/// 脚本 PoC 模板 (Python)
pub fn python_template() -> &'static str {
    r#"#!/usr/bin/env python3
"""PoC 模板 - 输出 JSON 结果"""
import json, sys

def check(target, port):
    # 在这里实现漏洞检测逻辑
    # ...
    result = {
        "vulnerable": False,
        "evidence": "",
        "detail": ""
    }

    # 检测成功时设置:
    # result["vulnerable"] = True
    # result["evidence"] = "发现漏洞的证据"

    print(json.dumps(result, ensure_ascii=False))

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    check(target, port)
"#
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_json_output() {
        let output = r#"{"vulnerable": true, "evidence": "found vuln", "detail": "test"}"#;
        let result = parse_script_output(output).unwrap();
        assert!(result.vulnerable);
        assert_eq!(result.evidence, "found vuln");
    }

    #[test]
    fn test_parse_json_with_prefix() {
        let output = "some debug info\n{\"vulnerable\": true, \"evidence\": \"test\"}";
        let result = parse_script_output(output).unwrap();
        assert!(result.vulnerable);
    }

    #[test]
    fn test_parse_not_vulnerable() {
        let output = r#"{"vulnerable": false, "evidence": ""}"#;
        let result = parse_script_output(output).unwrap();
        assert!(!result.vulnerable);
    }

    #[test]
    fn test_parse_invalid_output() {
        let output = "not json at all";
        assert!(parse_script_output(output).is_none());
    }

    #[test]
    fn test_build_python_command_inline() {
        let config = ScriptConfig {
            interpreter: "python3".to_string(),
            file: None,
            code: Some("print('hello')".to_string()),
            args: vec!["{{target}}".to_string()],
            timeout: 30,
        };

        let (cmd, args) = build_command(&config, "192.168.1.1", 80, None).unwrap();
        assert!(cmd.contains("python"));
        assert!(args.contains(&"-c".to_string()));
        assert!(args.contains(&"192.168.1.1".to_string()));
    }

    #[test]
    fn test_build_python_command_file() {
        let config = ScriptConfig {
            interpreter: "python3".to_string(),
            file: Some("poc.py".to_string()),
            code: None,
            args: vec![],
            timeout: 30,
        };

        let dir = std::path::Path::new("/tmp/pocs");
        let (_cmd, args) = build_command(&config, "10.0.0.1", 445, Some(dir)).unwrap();
        assert!(args[1].contains("poc.py"));
    }

    #[test]
    fn test_substitute_in_args() {
        let config = ScriptConfig {
            interpreter: "python3".to_string(),
            file: None,
            code: Some("pass".to_string()),
            args: vec![
                "--target".to_string(),
                "{{target}}".to_string(),
                "--port".to_string(),
                "{{port}}".to_string(),
            ],
            timeout: 30,
        };

        let (_, args) = build_command(&config, "192.168.1.1", 445, None).unwrap();
        assert_eq!(args[4], "192.168.1.1");
        assert_eq!(args[6], "445");
    }
}
