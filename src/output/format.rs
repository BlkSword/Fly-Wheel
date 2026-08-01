//! 输出格式化模块
//!
//! 支持 JSON 和 CSV 格式的扫描结果输出

use crate::core::Result;
use crate::scanner::models::ScanResult;
use std::path::Path;

/// 输出格式
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum OutputFormat {
    #[default]
    Json,
    Csv,
}

impl OutputFormat {
    /// 从字符串解析
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "json" => Some(OutputFormat::Json),
            "csv" => Some(OutputFormat::Csv),
            _ => None,
        }
    }

    /// 获取文件扩展名
    pub fn extension(&self) -> &str {
        match self {
            OutputFormat::Json => ".json",
            OutputFormat::Csv => ".csv",
        }
    }
}

/// 导出扫描结果
pub fn export_result(result: &ScanResult, path: &Path, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => export_json(result, path),
        OutputFormat::Csv => export_csv(result, path),
    }
}

/// 导出为 JSON
pub fn export_json(result: &ScanResult, path: &Path) -> Result<()> {
    let json = serde_json::to_string_pretty(result)?;
    std::fs::write(path, json)?;
    Ok(())
}

/// 导出为 CSV
pub fn export_csv(result: &ScanResult, path: &Path) -> Result<()> {
    let mut wtr = csv::Writer::from_path(path)?;

    wtr.write_record([
        "IP",
        "端口",
        "状态",
        "服务",
        "版本",
        "Banner",
        "Web应用",
        "Web版本",
        "Web类别",
        "标题",
        "URL",
        "FaviconHash",
    ])?;

    for host in &result.hosts {
        // 无开放端口但有指纹的主机
        if host.open_ports.is_empty() && !host.web_fingerprints.is_empty() {
            for wf in &host.web_fingerprints {
                for app in &wf.web_apps {
                    wtr.write_record([
                        &host.ip,
                        "",
                        "",
                        "",
                        "",
                        "",
                        &app.name,
                        app.version.as_deref().unwrap_or(""),
                        &app.category,
                        &wf.title,
                        &wf.url,
                        wf.favicon_hash
                            .map_or(String::new(), |h| h.to_string())
                            .as_str(),
                    ])?;
                }
                if wf.web_apps.is_empty() {
                    wtr.write_record([
                        &host.ip,
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        &wf.title,
                        &wf.url,
                        wf.favicon_hash
                            .map_or(String::new(), |h| h.to_string())
                            .as_str(),
                    ])?;
                }
            }
            continue;
        }

        for port in &host.open_ports {
            // 查找关联的指纹
            let port_str = port.port.to_string();
            let related_fps: Vec<_> = host
                .web_fingerprints
                .iter()
                .filter(|wf| wf.url.contains(&port_str) || wf.url.contains(&host.ip))
                .collect();

            if related_fps.is_empty() {
                wtr.write_record([
                    &host.ip,
                    &port_str,
                    port.state.zh_name(),
                    port.service.as_deref().unwrap_or(""),
                    port.version.as_deref().unwrap_or(""),
                    port.banner.as_deref().unwrap_or(""),
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                ])?;
            } else {
                for wf in related_fps {
                    for app in &wf.web_apps {
                        wtr.write_record([
                            &host.ip,
                            &port_str,
                            port.state.zh_name(),
                            port.service.as_deref().unwrap_or(""),
                            port.version.as_deref().unwrap_or(""),
                            port.banner.as_deref().unwrap_or(""),
                            &app.name,
                            app.version.as_deref().unwrap_or(""),
                            &app.category,
                            &wf.title,
                            &wf.url,
                            wf.favicon_hash
                                .map_or(String::new(), |h| h.to_string())
                                .as_str(),
                        ])?;
                    }
                    if wf.web_apps.is_empty() {
                        wtr.write_record([
                            &host.ip,
                            &port_str,
                            port.state.zh_name(),
                            port.service.as_deref().unwrap_or(""),
                            port.version.as_deref().unwrap_or(""),
                            port.banner.as_deref().unwrap_or(""),
                            "",
                            "",
                            "",
                            &wf.title,
                            &wf.url,
                            wf.favicon_hash
                                .map_or(String::new(), |h| h.to_string())
                                .as_str(),
                        ])?;
                    }
                }
            }
        }
    }

    wtr.flush()?;
    Ok(())
}

/// 生成默认输出文件名
pub fn generate_output_filename(base_name: &str, format: OutputFormat) -> String {
    let timestamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
    format!(
        "intrasweep-{}-{}{}",
        base_name,
        timestamp,
        format.extension()
    )
}

/// 导出漏洞扫描结果为 JSON
pub fn export_vuln_json(result: &crate::vuln::VulnScanResult, path: &Path) -> Result<()> {
    let json = serde_json::to_string_pretty(result)?;
    std::fs::write(path, json)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_output_format_from_str() {
        assert_eq!(OutputFormat::parse("json"), Some(OutputFormat::Json));
        assert_eq!(OutputFormat::parse("csv"), Some(OutputFormat::Csv));
        assert_eq!(OutputFormat::parse("JSON"), Some(OutputFormat::Json));
        assert_eq!(OutputFormat::parse("CSV"), Some(OutputFormat::Csv));
        assert_eq!(OutputFormat::parse("xml"), None);
    }

    #[test]
    fn test_output_format_default() {
        assert_eq!(OutputFormat::default(), OutputFormat::Json);
    }

    #[test]
    fn test_output_format_extension() {
        assert_eq!(OutputFormat::Json.extension(), ".json");
        assert_eq!(OutputFormat::Csv.extension(), ".csv");
    }

    #[test]
    fn test_generate_output_filename() {
        let name = generate_output_filename("scan", OutputFormat::Json);
        assert!(name.starts_with("intrasweep-scan-"));
        assert!(name.ends_with(".json"));

        let name = generate_output_filename("scan", OutputFormat::Csv);
        assert!(name.ends_with(".csv"));
    }
}
