//! 本地凭据收集 CLI
//!
//! 对接 cred::CredManager，一键收集本机浏览器/WiFi/应用/SAM/LSASS/GPP 凭据。

use crate::cli::{print_banner, InteractiveMenu};
use crate::core::Result;
use crate::output::color::{print_error, print_info, print_success, Color};
use crate::output::format::OutputFormat;
use std::path::PathBuf;

pub fn run_cred_cmd(
    dc: Option<String>,
    domain: Option<String>,
    username: Option<String>,
    password: Option<String>,
    format: &str,
    output: Option<PathBuf>,
) -> Result<()> {
    let output_fmt = OutputFormat::parse(format).unwrap_or(OutputFormat::Json);

    // 无任何有效参数时进入交互式模式
    let (dc, domain, username, password) = match (dc, domain, username, password) {
        (None, None, None, None) => run_interactive_cred()?,
        (dc_opt, domain_opt, username_opt, password_opt) => {
            (dc_opt, domain_opt, username_opt, password_opt)
        }
    };

    let mut manager = crate::cred::CredManager::new(
        &whoami::fallible::hostname().unwrap_or_else(|_| "unknown".to_string()),
    );
    if let (Some(ref d), Some(ref dc_ip)) = (&domain, &dc) {
        manager = manager.with_domain(d, Some(dc_ip));
    }

    print_banner();
    println!();
    print_info("开始本地凭据收集...");
    println!();

    let rt = tokio::runtime::Runtime::new()?;
    let result = rt.block_on(manager.harvest_all());

    print_cred_results(&result);

    let path = output.unwrap_or_else(|| {
        PathBuf::from(crate::output::format::generate_output_filename(
            &format!("intrasweep-cred-{}", result.hostname),
            output_fmt,
        ))
    });

    match output_fmt {
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&result)?;
            std::fs::write(&path, json)?;
        }
        OutputFormat::Csv => {
            export_cred_csv(&result, &path)?;
        }
    }

    print_success(&format!("结果已保存: {}", path.display()));
    Ok(())
}

fn run_interactive_cred() -> Result<(Option<String>, Option<String>, Option<String>, Option<String>)> {
    print_banner();
    println!();
    print_info("IntraSweep 交互式本地凭据收集向导");
    println!();

    InteractiveMenu::print_step(1, 4, "认证凭据 (可选)");
    println!("凭据用于域环境 GPP 解密；本机浏览器/WiFi/应用凭据无需凭据即可提取。");
    println!();
    let username = {
        let u = InteractiveMenu::read_input("用户名 (留空=仅本机提取): ");
        if u.is_empty() {
            None
        } else {
            Some(u)
        }
    };
    let password = if username.is_some() {
        let p = InteractiveMenu::read_input("密码: ");
        if p.is_empty() {
            None
        } else {
            Some(p)
        }
    } else {
        None
    };

    InteractiveMenu::print_step(2, 4, "域信息 (可选)");
    println!("提供域信息后可尝试从 SYSVOL 解密 GPP 密码 (留空跳过)");
    println!();
    let domain = InteractiveMenu::read_input("域名 (例: corp.local, 留空=跳过): ");
    let domain = if domain.is_empty() { None } else { Some(domain) };
    let dc = InteractiveMenu::read_input("域控地址 (留空=跳过): ");
    let dc = if dc.is_empty() { None } else { Some(dc) };

    InteractiveMenu::print_step(3, 4, "执行内容确认");
    println!("  本机提取: 浏览器 / WiFi / 应用 / SAM / LSASS 凭据");
    if let (Some(ref d), Some(ref c)) = (&domain, &dc) {
        println!("  GPP解密:   域 {} 域控 {}", d, c);
    } else {
        println!("  GPP解密:   跳过");
    }

    InteractiveMenu::print_step(4, 4, "确认");
    if !InteractiveMenu::confirm("确认开始收集? [Y/n]: ") {
        print_info("已取消");
        return Ok((None, None, None, None));
    }

    Ok((dc, domain, username, password))
}

fn print_cred_results(result: &crate::cred::CredHarvestResult) {
    println!();
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  凭据收集结果 (主机: {})", result.hostname);
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();
    println!("  收集耗时: {:.2}s", result.duration_secs);
    println!();
    println!("  总计:      {}", result.stats.total);
    println!("  明文密码:  {}", result.stats.cleartext_passwords);
    println!("  NTLM哈希:  {}", result.stats.ntlm_hashes);
    println!("  浏览器:    {}", result.stats.browser_passwords);
    println!("  WiFi:      {}", result.stats.wifi_passwords);
    println!("  应用凭据:  {}", result.stats.app_credentials);
    println!("  Kerberos:  {}", result.stats.kerberos_tickets);
    if result.stats.high_value > 0 {
        println!(
            "  {}",
            crate::cli::colorize(
                &format!("高价值凭据: {}", result.stats.high_value),
                Color::BrightRed
            )
        );
    }
    println!();

    if result.credentials.is_empty() {
        print_info("未收集到凭据");
        return;
    }

    println!("┌────────────────────────────────────────────────────────────────────────────┐");
    println!("│ {:<18} {:<10} {:<12} {:<30} │",
        "类型", "用户名", "目标", "来源");
    println!("├────────────────────────────────────────────────────────────────────────────┤");

    let mut shown = 0;
    for cred in &result.credentials {
        let username = cred.username.as_deref().unwrap_or("-");
        let target = cred.target.as_deref().unwrap_or("-");
        println!(
            "│ {:<16}  {:<10} {:<12} {:<28}  │",
            format!("{}", cred.cred_type).chars().take(16).collect::<String>(),
            username.chars().take(10).collect::<String>(),
            target.chars().take(12).collect::<String>(),
            cred.source.chars().take(28).collect::<String>(),
        );
        shown += 1;
        if shown >= 50 {
            println!("│ ... 还有 {} 条", result.credentials.len() - 50);
            break;
        }
    }

    println!("└────────────────────────────────────────────────────────────────────────────┘");
    println!();
}

fn export_cred_csv(result: &crate::cred::CredHarvestResult, path: &std::path::Path) -> Result<()> {
    let mut wtr = csv::Writer::from_path(path)?;

    wtr.write_record([
        "类型", "用户名", "密码", "NTLM哈希", "域名", "目标", "来源",
    ])?;

    for cred in &result.credentials {
        wtr.write_record([
            &format!("{}", cred.cred_type),
            cred.username.as_deref().unwrap_or(""),
            cred.password.as_deref().unwrap_or(""),
            cred.ntlm_hash.as_deref().unwrap_or(""),
            cred.domain.as_deref().unwrap_or(""),
            cred.target.as_deref().unwrap_or(""),
            &cred.source,
        ])?;
    }

    wtr.flush()?;
    Ok(())
}
