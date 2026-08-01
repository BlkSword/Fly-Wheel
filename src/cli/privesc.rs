//! 提权检测 CLI

use crate::cli::{print_banner, InteractiveMenu};
use crate::core::Result;
use crate::output::color::{print_info, print_success};
use crate::output::format::OutputFormat;
use std::path::PathBuf;

pub fn run_privesc_cmd(check: Option<String>, format: &str, output: Option<PathBuf>) -> Result<()> {
    let output_fmt = OutputFormat::parse(format).unwrap_or(OutputFormat::Json);

    // 无参数时进入交互式模式
    let selected = match check {
        Some(check) => check,
        None => run_interactive_privesc()?,
    };

    // 交互式模式下用户取消时返回空字符串，直接退出
    if selected.is_empty() {
        return Ok(());
    }

    print_banner();
    println!();

    let privesc_label = crate::core::obfstr::sensitive::privesc_label();
    print_info(&format!("开始{}...", privesc_label));
    println!();

    // 执行检查
    let result = if selected == "all" {
        crate::privesc::run_all_checks()
    } else {
        let findings = crate::privesc::run_check(&selected);
        crate::privesc::PrivescResult {
            hostname: whoami::fallible::hostname().unwrap_or_else(|_| "unknown".to_string()),
            os: std::env::consts::OS.to_string(),
            current_user: whoami::username(),
            is_admin: false,
            findings,
            stats: Default::default(),
        }
    };

    // 打印结果
    print_privesc_results(&result);

    // 保存结果
    let path = output.unwrap_or_else(|| {
        PathBuf::from(crate::output::format::generate_output_filename(
            &result.hostname,
            output_fmt,
        ))
    });

    match output_fmt {
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&result)?;
            std::fs::write(&path, json)?;
        }
        OutputFormat::Csv => {
            export_privesc_csv(&result, &path)?;
        }
    }
    print_success(&format!("结果已保存: {}", path.display()));

    Ok(())
}

fn run_interactive_privesc() -> Result<String> {
    print_banner();
    println!();
    print_info("IntraSweep 交互式提权检测向导");
    println!();

    let categories = crate::privesc::available_categories();
    let all_idx = categories.iter().position(|&c| c == "all").unwrap_or(0);

    InteractiveMenu::print_step(1, 2, "选择检查类别");
    for (i, cat) in categories.iter().enumerate() {
        if *cat == "all" {
            println!("  {}. 全部检查 — 运行所有提权检测项目", i + 1);
        } else {
            let desc = match *cat {
                "service" => "服务配置检查",
                "credentials" => "凭据存储检查",
                "registry" => "注册表策略检查",
                "tokens" => "令牌特权检查",
                "files" => "敏感文件检查",
                "patches" => "补丁审计",
                "suid" => "SUID 二进制检查",
                "capabilities" => "文件 Capabilities",
                "cron" => "Cron 任务检查",
                "writable" => "可写文件检查",
                "docker" => "Docker 组检查",
                "sudo" => "Sudo 规则检查",
                "ssh" => "SSH 密钥检查",
                "kernel" => "内核漏洞检查",
                "dll" => "DLL 劫持检查",
                _ => "",
            };
            println!("  {}. [{}] {}", i + 1, cat, desc);
        }
    }
    println!();

    let choice = InteractiveMenu::read_number_opt(
        &format!(
            "请选择 [1-{}, 默认 {} 全部]: ",
            categories.len(),
            all_idx + 1
        ),
        1,
        categories.len(),
        all_idx + 1,
    );

    let selected = categories[choice - 1].to_string();
    print_success(&format!("已选择: {}", selected));

    InteractiveMenu::print_step(2, 2, "确认");
    if InteractiveMenu::confirm("确认开始提权检测? [Y/n]: ") {
        Ok(selected)
    } else {
        print_info("已取消");
        Ok(String::new())
    }
}

fn print_privesc_results(result: &crate::privesc::PrivescResult) {
    println!();
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  {} 结果", crate::core::obfstr::sensitive::privesc_label());
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();
    println!("  主机名: {}", result.hostname);
    println!("  系统: {}", result.os);
    println!(
        "  当前用户: {} {}",
        result.current_user,
        if result.is_admin { "[管理员]" } else { "" }
    );
    println!();

    if result.findings.is_empty() {
        print_success("未发现提权风险");
        return;
    }

    // 统计
    let stats = &result.stats;
    println!("  发现风险: {}", stats.total_checks);
    if stats.critical_count > 0 {
        println!("  \x1b[31m■严重: {}\x1b[0m", stats.critical_count);
    }
    if stats.high_count > 0 {
        println!("  \x1b[33m■高危: {}\x1b[0m", stats.high_count);
    }
    if stats.medium_count > 0 {
        println!("  \x1b[36m■中危: {}\x1b[0m", stats.medium_count);
    }
    println!();

    // 详细发现
    for finding in &result.findings {
        println!(
            "  {}[{}] {} [{}]\x1b[0m",
            finding.severity.color_code(),
            finding.severity.display_name(),
            finding.title,
            finding.category
        );
        if !finding.description.is_empty() {
            println!("    {}", finding.description);
        }
        if !finding.detail.is_empty() {
            let detail: String = finding.detail.chars().take(200).collect();
            println!("    详情: {}", detail.replace('\n', " "));
        }
        if !finding.remediation.is_empty() {
            println!("    修复: {}", finding.remediation);
        }
        println!();
    }
}

fn export_privesc_csv(
    result: &crate::privesc::PrivescResult,
    path: &std::path::Path,
) -> Result<()> {
    let mut wtr = csv::Writer::from_path(path)?;

    wtr.write_record([
        "主机名",
        "系统",
        "当前用户",
        "类别",
        "严重性",
        "标题",
        "描述",
        "详情",
        "修复建议",
    ])?;

    for finding in &result.findings {
        wtr.write_record([
            &result.hostname,
            &result.os,
            &result.current_user,
            &finding.category,
            finding.severity.display_name(),
            &finding.title,
            &finding.description,
            &finding.detail,
            &finding.remediation,
        ])?;
    }

    wtr.flush()?;
    Ok(())
}
