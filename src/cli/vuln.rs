//! 漏洞扫描 CLI

use crate::cli::{print_banner, InteractiveMenu};
use crate::core::Result;
use crate::output::color::{print_error, print_info, print_success};
use crate::output::format::OutputFormat;
use std::path::PathBuf;

pub fn run_vuln_cmd(
    targets: Option<Vec<String>>,
    poc_file: Option<PathBuf>,
    severity: Option<String>,
    category: Option<String>,
    format: &str,
    output: Option<PathBuf>,
    concurrency: usize,
    timeout: u64,
    web_probe: bool,
) -> Result<()> {
    let output_fmt = OutputFormat::parse(format).unwrap_or(OutputFormat::Json);

    match targets {
        Some(targets) => run_vuln_scan(
            targets,
            poc_file,
            severity,
            category,
            output_fmt,
            output,
            concurrency,
            timeout,
            web_probe,
        ),
        None => run_interactive_vuln(
            poc_file,
            severity,
            category,
            output_fmt,
            output,
            concurrency,
            timeout,
            web_probe,
        ),
    }
}

fn run_vuln_scan(
    targets: Vec<String>,
    poc_file: Option<PathBuf>,
    severity: Option<String>,
    category: Option<String>,
    output_fmt: OutputFormat,
    output: Option<PathBuf>,
    concurrency: usize,
    timeout: u64,
    web_probe: bool,
) -> Result<()> {
    print_banner();
    println!();

    let vuln_label = crate::core::obfstr::sensitive::vuln_label();
    print_info(&format!("开始{}...", vuln_label));

    let mut pocs = crate::vuln::builtin::get_builtin_pocs();

    if let Some(ref poc_path) = poc_file {
        match crate::vuln::loader::load_pocs_from_path(poc_path) {
            Ok(external_pocs) => {
                print_success(&format!("已加载 {} 条外部PoC", external_pocs.len()));
                pocs.extend(external_pocs);
            }
            Err(e) => {
                print_error(&format!("加载外部PoC失败: {}", e));
            }
        }
    }

    let sev_filter = severity
        .as_deref()
        .and_then(crate::vuln::poc::Severity::from_str_opt);
    if sev_filter.is_some() || category.is_some() {
        pocs = crate::vuln::builtin::filter_builtin_pocs(sev_filter, category.as_deref());
        if let Some(ref sev) = sev_filter {
            println!("严重性过滤: {}", sev.display_name());
        }
        if let Some(ref cat) = category {
            println!("类别过滤: {}", cat);
        }
    }

    let expanded = crate::vuln::expand_targets(&targets);

    println!("目标数: {}", expanded.len());
    println!("PoC规则数: {}", pocs.len());
    println!("并发数: {}", concurrency);
    println!();

    let config = crate::vuln::VulnScanConfig::new(expanded, pocs)
        .with_timeout(std::time::Duration::from_secs(timeout))
        .with_concurrency(concurrency);

    let scanner = crate::vuln::VulnScanner::new(config);
    let rt = tokio::runtime::Runtime::new()?;
    let result = rt.block_on(scanner.scan());

    print_vuln_results(&result);

    let web_findings = if web_probe {
        let findings = rt.block_on(run_web_probe(&result.targets, timeout));
        if !findings.is_empty() {
            print_web_vuln_results(&findings);
        } else {
            print_info("Web 主动探测未发现明显问题");
        }
        findings
    } else {
        Vec::new()
    };

    let web_findings_ref = &web_findings;
    let path = output.unwrap_or_else(|| {
        let base = if !result.targets.is_empty() {
            result.targets[0].replace(['.', ':'], "_")
        } else {
            "vuln".to_string()
        };
        PathBuf::from(crate::output::format::generate_output_filename(
            &base, output_fmt,
        ))
    });

    match output_fmt {
        OutputFormat::Json => {
            if web_findings_ref.is_empty() {
                let json = serde_json::to_string_pretty(&result)?;
                std::fs::write(&path, json)?;
            } else {
                #[derive(serde::Serialize)]
                struct CombinedVulnResult {
                    #[serde(rename = "poc_scan")]
                    poc_scan: crate::vuln::VulnScanResult,
                    #[serde(rename = "web_probe")]
                    web_probe: Vec<crate::vuln::webprobe::WebVuln>,
                }
                let combined = CombinedVulnResult {
                    poc_scan: result,
                    web_probe: web_findings_ref.to_vec(),
                };
                let json = serde_json::to_string_pretty(&combined)?;
                std::fs::write(&path, json)?;
            }
        }
        OutputFormat::Csv => {
            export_vuln_csv(&result, &path)?;
            if !web_findings_ref.is_empty() {
                let web_path = path.with_extension("web.csv");
                export_web_vuln_csv(web_findings_ref, &web_path)?;
                print_success(&format!("Web 探测结果已保存: {}", web_path.display()));
            }
        }
    }

    print_success(&format!("结果已保存: {}", path.display()));
    Ok(())
}

fn run_interactive_vuln(
    _poc_file: Option<PathBuf>,
    severity: Option<String>,
    category: Option<String>,
    output_fmt: OutputFormat,
    output: Option<PathBuf>,
    concurrency: usize,
    timeout: u64,
    web_probe: bool,
) -> Result<()> {
    print_banner();
    println!();
    let vuln_label = crate::core::obfstr::sensitive::vuln_label();
    print_info(&format!("IntraSweep 交互式{}向导", vuln_label));
    println!();

    // 步骤 1: 目标输入
    InteractiveMenu::print_step(1, 5, "扫描目标");
    println!("输入格式: IP, CIDR, IP范围, host:port (逗号分隔)");
    println!();
    println!("示例: 192.168.1.0/24 | 10.0.0.1:8080 | 192.168.1.1,192.168.1.2");
    println!();

    let targets_input =
        InteractiveMenu::read_input_required("请输入扫描目标: ", "目标不能为空，请重新输入");
    let targets: Vec<String> = targets_input
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();
    print_success(&format!("已设置 {} 个目标", targets.len()));

    // 步骤 2: PoC 规则
    InteractiveMenu::print_step(2, 5, "PoC 规则");
    println!(
        "  1. 使用内置PoC规则 ({} 条)",
        crate::vuln::builtin::get_builtin_pocs().len()
    );
    println!("  2. 加载外部PoC文件");
    println!("  3. 内置 + 外部");
    println!();

    let choice = InteractiveMenu::read_number_opt("请选择 [1-3, 默认 1]: ", 1, 3, 1);
    let external_path = if choice >= 2 {
        let path = InteractiveMenu::read_input_required("请输入PoC文件/目录路径: ", "路径不能为空");
        print_success(&format!("外部PoC路径: {}", path));
        Some(PathBuf::from(path))
    } else {
        None
    };

    // 步骤 3: 严重性过滤
    InteractiveMenu::print_step(3, 5, "严重性过滤 (可选)");
    println!("  可选: critical, high, medium, low, info (留空不过滤)");
    println!();
    let valid_severities = ["critical", "high", "medium", "low", "info"];
    let sev_input = InteractiveMenu::read_input("严重性 [留空=不过滤]: ");
    let final_severity = if sev_input.is_empty() {
        severity
    } else {
        let sev_lower = sev_input.to_lowercase();
        if valid_severities.contains(&sev_lower.as_str()) {
            print_success(&format!("已选择严重性: {}", sev_lower));
            Some(sev_lower)
        } else {
            print_error(&format!("无效严重性 '{}'，已忽略过滤", sev_input));
            None
        }
    };

    // 步骤 4: 高级选项
    InteractiveMenu::print_step(4, 5, "高级选项 (可选)");
    println!("留空则使用默认值");
    println!();

    let cat_input = InteractiveMenu::read_input("类别过滤 (例: 未授权, 反序列化): ");
    let final_category = if cat_input.is_empty() {
        category
    } else {
        print_success(&format!("已设置类别过滤: {}", cat_input));
        Some(cat_input)
    };

    let conc_input = InteractiveMenu::read_input(&format!("并发数 (默认: {}): ", concurrency));
    let final_concurrency = if conc_input.is_empty() {
        concurrency
    } else {
        conc_input.parse::<usize>().unwrap_or(concurrency)
    };

    let timeout_input = InteractiveMenu::read_input(&format!("超时秒数 (默认: {}): ", timeout));
    let final_timeout = if timeout_input.is_empty() {
        timeout
    } else {
        timeout_input.parse::<u64>().unwrap_or(timeout)
    };

    let web_probe_input =
        InteractiveMenu::read_input("是否启用 Web 主动探测 (SQLi/XSS/命令注入/路径穿越)? [y/N]: ");
    let final_web_probe = web_probe || web_probe_input.to_lowercase() == "y";

    // 步骤 5: 确认
    InteractiveMenu::print_step(5, 5, "确认配置");
    println!("  目标: {}", targets.join(", "));
    println!("  并发数: {}", final_concurrency);
    println!("  超时: {}s", final_timeout);
    if let Some(ref sev) = final_severity {
        println!("  严重性过滤: {}", sev);
    }
    if let Some(ref cat) = final_category {
        println!("  类别过滤: {}", cat);
    }
    if let Some(ref ext) = external_path {
        println!("  外部PoC: {}", ext.display());
    }
    println!(
        "  Web主动探测: {}",
        if final_web_probe { "启用" } else { "禁用" }
    );
    println!();

    if !InteractiveMenu::confirm("确认开始扫描? [Y/n]: ") {
        print_info("已取消扫描");
        return Ok(());
    }

    run_vuln_scan(
        targets,
        external_path,
        final_severity,
        final_category,
        output_fmt,
        output,
        final_concurrency,
        final_timeout,
        final_web_probe,
    )
}

fn print_vuln_results(result: &crate::vuln::VulnScanResult) {
    println!();
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  {} 结果", crate::core::obfstr::sensitive::vuln_label());
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();

    println!("  扫描目标: {}", result.stats.total_targets);
    println!("  PoC规则数: {}", result.stats.total_pocs);
    println!("  总请求数: {}", result.stats.total_requests);
    println!("  耗时: {:.2}s", result.duration_secs);
    println!();

    if result.findings.is_empty() {
        print_info("未发现漏洞");
        return;
    }

    println!("  发现漏洞: {}", result.stats.vulnerabilities_found);
    if result.stats.critical_count > 0 {
        println!("  \x1b[31m■严重: {}\x1b[0m", result.stats.critical_count);
    }
    if result.stats.high_count > 0 {
        println!("  \x1b[33m■高危: {}\x1b[0m", result.stats.high_count);
    }
    if result.stats.medium_count > 0 {
        println!("  \x1b[36m■中危: {}\x1b[0m", result.stats.medium_count);
    }
    if result.stats.low_count > 0 {
        println!("  \x1b[32m■低危: {}\x1b[0m", result.stats.low_count);
    }
    println!();

    println!("┌────────────────────────────────────────────────────────────────────────────┐");
    println!(
        "│ {:<18} {:<6} {:<15} {:<8} {:<20} │",
        "目标", "端口", "漏洞ID", "严重性", "名称"
    );
    println!("├────────────────────────────────────────────────────────────────────────────┤");

    for finding in &result.findings {
        let severity_str = format!(
            "{}{}{}",
            finding.severity.color_code(),
            finding.severity.display_name(),
            "\x1b[0m"
        );
        let target = if finding.target.len() > 16 {
            format!("{}...", &finding.target[..13])
        } else {
            finding.target.clone()
        };
        let name = if finding.vuln_name.len() > 18 {
            format!("{}...", &finding.vuln_name[..15])
        } else {
            finding.vuln_name.clone()
        };

        println!(
            "│ {:<18} {:<6} {:<15} {:<4}    {:<20} │",
            target, finding.port, finding.vuln_id, severity_str, name
        );
    }

    println!("└────────────────────────────────────────────────────────────────────────────┘");
    println!();

    for finding in &result.findings {
        println!(
            "  {}[{}] {} {}\x1b[0m - {}:{}",
            finding.severity.color_code(),
            finding.severity.display_name(),
            finding.vuln_id,
            finding.vuln_name,
            finding.target,
            finding.port
        );
        if !finding.description.is_empty() {
            println!("    {}", finding.description);
        }
        if !finding.evidence.is_empty() {
            let evidence: String = finding.evidence.chars().take(100).collect();
            println!(
                "    证据: {}",
                evidence.replace('\n', " ").replace('\r', "")
            );
        }
        if !finding.remediation.is_empty() {
            println!("    修复: {}", finding.remediation);
        }
        println!();
    }
}

/// 对目标列表执行轻量级 Web 主动探测
async fn run_web_probe(targets: &[String], timeout: u64) -> Vec<crate::vuln::webprobe::WebVuln> {
    let mut findings = Vec::new();

    for target in targets {
        let Some(url) = normalize_web_target(target) else {
            continue;
        };

        let scanner = crate::vuln::webprobe::WebVulnScanner::new(&url).with_timeout(timeout.max(5));
        findings.extend(scanner.scan_all(&url).await);
    }

    findings
}

/// 将目标格式化为可探测的 HTTP(S) URL；仅支持显式端口或完整 URL
fn normalize_web_target(target: &str) -> Option<String> {
    if target.contains("://") {
        return Some(target.to_string());
    }

    let (host, port) = target.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    if matches!(port, 80 | 443 | 8000 | 8080 | 8443 | 8888 | 9200 | 9443) {
        let scheme = if matches!(port, 443 | 8443 | 9443) {
            "https"
        } else {
            "http"
        };
        Some(format!("{}://{}:{}", scheme, host, port))
    } else {
        None
    }
}

fn print_web_vuln_results(findings: &[crate::vuln::webprobe::WebVuln]) {
    println!();
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  Web 主动探测结果");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();

    if findings.is_empty() {
        print_info("未发现明显 Web 漏洞");
        return;
    }

    for finding in findings {
        println!(
            "  [{}] {} - {} ({})",
            finding.severity.display_name(),
            finding.vuln_type.display_name(),
            finding.target_url,
            finding.parameter
        );
        if !finding.evidence.is_empty() {
            println!("    证据: {}", finding.evidence);
        }
        println!("    修复: {}", finding.remediation);
        println!();
    }
}

fn export_web_vuln_csv(
    findings: &[crate::vuln::webprobe::WebVuln],
    path: &std::path::Path,
) -> Result<()> {
    let mut wtr = csv::Writer::from_path(path)?;

    wtr.write_record(["目标URL", "参数", "漏洞类型", "严重性", "证据", "修复建议"])?;

    for finding in findings {
        wtr.write_record([
            &finding.target_url,
            &finding.parameter,
            finding.vuln_type.display_name(),
            finding.severity.display_name(),
            &finding.evidence,
            &finding.remediation,
        ])?;
    }

    wtr.flush()?;
    Ok(())
}

fn export_vuln_csv(result: &crate::vuln::VulnScanResult, path: &std::path::Path) -> Result<()> {
    let mut wtr = csv::Writer::from_path(path)?;

    wtr.write_record([
        "目标",
        "端口",
        "漏洞ID",
        "漏洞名称",
        "严重性",
        "类别",
        "描述",
        "证据",
        "修复建议",
    ])?;

    for finding in &result.findings {
        wtr.write_record([
            &finding.target,
            &finding.port.to_string(),
            &finding.vuln_id,
            &finding.vuln_name,
            finding.severity.display_name(),
            &finding.category,
            &finding.description,
            &finding.evidence,
            &finding.remediation,
        ])?;
    }

    wtr.flush()?;
    Ok(())
}
