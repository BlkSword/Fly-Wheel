//! 信息侦察 CLI
//!
//! 对接 crate::recon::ReconEngine，提供 EDR 检测、情境感知、共享搜索、防火墙/VLAN 发现等侦察能力。

use crate::cli::{print_banner, InteractiveMenu};
use crate::core::Result;
use crate::output::color::{print_info, print_success};
use crate::output::format::OutputFormat;
use std::path::PathBuf;

/// 支持的侦察模式
const RECON_MODES: &[&str] = &["full", "edr", "situational", "shares", "firewall", "vlan", "host"];

pub fn run_recon_cmd(
    dc: Option<String>,
    domain: Option<String>,
    mode: String,
    format: &str,
    output: Option<PathBuf>,
) -> Result<()> {
    let output_fmt = OutputFormat::parse(format).unwrap_or(OutputFormat::Json);

    // 无任何有效参数时进入交互式模式
    let (dc, domain, mode) = match (dc, domain) {
        (None, None) if mode == "full" => run_interactive_recon()?,
        (dc_opt, domain_opt) => (dc_opt, domain_opt, mode),
    };

    let mode = if RECON_MODES.contains(&mode.as_str()) {
        mode
    } else {
        return Err(crate::core::error::IntraSweepError::Config {
            message: format!("未知侦察模式: {}，可选: {}", mode, RECON_MODES.join(", ")),
        });
    };

    print_banner();
    println!();
    print_info(&format!("开始{}侦察...", mode_label(&mode)));
    println!();

    let hostname = whoami::fallible::hostname().unwrap_or_else(|_| "unknown".to_string());
    let rt = tokio::runtime::Runtime::new()?;

    let result = if mode == "full" {
        let mut engine = crate::recon::ReconEngine::new(&hostname);
        if let (Some(ref d), Some(ref dc_ip)) = (&domain, &dc) {
            engine = engine.with_domain(d, Some(dc_ip));
        }
        rt.block_on(engine.run_full_recon())
    } else {
        rt.block_on(run_single_mode(&hostname, &mode, &dc, &domain))
    };

    print_recon_results(&result);

    let path = output.unwrap_or_else(|| {
        PathBuf::from(crate::output::format::generate_output_filename(
            &format!("intrasweep-recon-{}-{}", mode, result.hostname),
            output_fmt,
        ))
    });

    match output_fmt {
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&result)?;
            std::fs::write(&path, json)?;
        }
        OutputFormat::Csv => {
            export_recon_csv(&result, &path)?;
        }
    }

    print_success(&format!("结果已保存: {}", path.display()));
    Ok(())
}

/// 单模式侦察：组装 ReconReport 并填充对应字段
async fn run_single_mode(
    hostname: &str,
    mode: &str,
    dc: &Option<String>,
    domain: &Option<String>,
) -> crate::recon::ReconReport {
    let mut report = crate::recon::ReconReport::new(hostname);

    match mode {
        "edr" => {
            if let Ok(products) = crate::recon::edr_detect::detect_security_products() {
                report.security_products = products;
            }
        }
        "situational" => {
            if let Ok(info) = crate::recon::situational::collect_situational_awareness() {
                report.situational = Some(info);
            }
        }
        "host" => {
            if let Ok(info) = crate::recon::host_info::collect_host_info() {
                report.host_info = Some(info);
            }
        }
        "shares" => {
            if let Ok(findings) = crate::recon::share_hunting::scan_network_shares() {
                report.share_findings = findings;
            }
        }
        "firewall" => {
            if let Ok(rules) = crate::recon::firewall::collect_firewall_rules() {
                report.firewall_rules = rules;
            }
        }
        "vlan" => {
            if let Ok(topology) = crate::recon::vlan::discover_network_topology() {
                report.network_topology = Some(topology);
            }
        }
        _ => {}
    }

    if let (Some(ref d), Some(ref dc_ip)) = (domain, dc) {
        if let Ok(sessions) = crate::recon::user_hunting::hunt_user_sessions(dc_ip, d) {
            report.user_sessions = sessions;
        }
    }

    report.compute_stats();
    report
}

fn mode_label(mode: &str) -> &str {
    match mode {
        "full" => "完整信息",
        "edr" => "EDR/AV 安全软件",
        "situational" => "情境感知",
        "host" => "主机详情",
        "shares" => "文件共享",
        "firewall" => "防火墙",
        "vlan" => "VLAN/拓扑",
        _ => mode,
    }
}

fn run_interactive_recon() -> Result<(Option<String>, Option<String>, String)> {
    print_banner();
    println!();
    print_info("IntraSweep 交互式信息侦察向导");
    println!();

    InteractiveMenu::print_step(1, 3, "侦察模式");
    println!("  1. full       - 完整侦察（EDR/情境/共享/防火墙/VLAN）");
    println!("  2. edr        - EDR/AV 安全软件检测");
    println!("  3. situational- 环境态势感知（OS/域/网络/补丁）");
    println!("  4. host       - 主机详细信息");
    println!("  5. shares     - 文件共享敏感信息搜索");
    println!("  6. firewall   - 防火墙规则收集");
    println!("  7. vlan       - VLAN/网络拓扑发现");
    println!();

    let choice = InteractiveMenu::read_number_opt("请选择 [1-7, 默认 1]: ", 1, 7, 1);
    let mode = match choice {
        1 => "full".to_string(),
        2 => "edr".to_string(),
        3 => "situational".to_string(),
        4 => "host".to_string(),
        5 => "shares".to_string(),
        6 => "firewall".to_string(),
        7 => "vlan".to_string(),
        _ => "full".to_string(),
    };

    InteractiveMenu::print_step(2, 3, "域信息 (可选)");
    println!("仅用户会话猎杀需要域环境，其余模式无需 (留空跳过)");
    println!();
    let domain = InteractiveMenu::read_input("域名 (例: corp.local, 留空=跳过): ");
    let domain = if domain.is_empty() { None } else { Some(domain) };
    let dc = InteractiveMenu::read_input("域控地址 (留空=跳过): ");
    let dc = if dc.is_empty() { None } else { Some(dc) };

    InteractiveMenu::print_step(3, 3, "确认");
    println!("  模式: {}", mode_label(&mode));
    if let (Some(ref d), Some(ref c)) = (&domain, &dc) {
        println!("  域:   {} / {}", d, c);
    }
    println!();

    if !InteractiveMenu::confirm("确认开始侦察? [Y/n]: ") {
        print_info("已取消");
        return Ok((None, None, "full".to_string()));
    }

    Ok((dc, domain, mode))
}

fn print_recon_results(result: &crate::recon::ReconReport) {
    println!();
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  侦察结果 (主机: {})", result.hostname);
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();
    println!("  耗时: {:.2}s", result.duration_secs);

    if let Some(ref s) = result.situational {
        println!();
        println!("  [情境感知]");
        println!("    OS:       {} {}", s.os, s.os_version);
        println!("    主机名:   {}", s.hostname);
        println!("    当前用户: {} ({:?})", s.current_user, s.privileges);
        if s.in_domain {
            println!(
                "    域:       {} (域控: {})",
                s.domain_name.as_deref().unwrap_or("-"),
                s.domain_controllers.join(", ")
            );
        } else {
            println!("    域:       未加入域");
        }
        println!(
            "    软件:     {} 已安装 | 补丁: {}",
            s.installed_software.len(),
            s.installed_patches.len()
        );
    }

    if let Some(ref info) = result.host_info {
        println!();
        println!("  [主机详情]");
        println!("    主机名:   {}", info.hostname);
        println!("    OS:       {} {}", info.os, info.arch);
        if let Some(ref cpu) = info.cpu {
            println!("    CPU:      {}", cpu);
        }
        if let Some(mem) = info.memory_mb {
            println!("    内存:     {} MB", mem);
        }
    }

    if !result.security_products.is_empty() {
        println!();
        println!("  [EDR/AV 检测] 共 {} 个安全产品", result.security_products.len());
        for p in &result.security_products {
            println!(
                "    - {} ({}): 方法={} 运行中={}",
                p.name, p.product_type, p.detection_method, p.is_running
            );
        }
    }

    if !result.share_findings.is_empty() {
        println!();
        println!("  [文件共享] 共 {} 个发现", result.share_findings.len());
        for f in result.share_findings.iter().take(10) {
            println!(
                "    - {} [{}]",
                f.full_path,
                if f.is_sensitive { "敏感" } else { "普通" }
            );
        }
    }

    if !result.firewall_rules.is_empty() {
        println!();
        println!("  [防火墙规则] 共 {} 条", result.firewall_rules.len());
    }

    if let Some(ref topo) = result.network_topology {
        println!();
        println!("  [VLAN/拓扑] 共 {} 个子网", topo.subnets.len());
        for s in topo.subnets.iter().take(10) {
            println!(
                "    - {} ({} 主机, {})",
                s.subnet,
                s.host_count,
                if s.reachable { "可达" } else { "不可达" }
            );
        }
    }

    if !result.user_sessions.is_empty() {
        println!();
        println!("  [用户会话] 共 {} 个", result.user_sessions.len());
        for s in result.user_sessions.iter().take(10) {
            println!(
                "    - {} @ {}{}",
                s.username,
                s.computer,
                if s.is_domain_admin { " [域管]" } else { "" }
            );
        }
    }

    println!();
}

fn export_recon_csv(result: &crate::recon::ReconReport, path: &std::path::Path) -> Result<()> {
    let mut wtr = csv::Writer::from_path(path)?;

    wtr.write_record(["类别", "名称", "详情"])?;

    for p in &result.security_products {
        wtr.write_record(["EDR/AV", &p.name, &format!("{}", p.product_type)])?;
    }
    for f in &result.share_findings {
        wtr.write_record([
            "共享",
            &f.full_path,
            &format!("敏感: {}", f.is_sensitive),
        ])?;
    }
    for r in &result.firewall_rules {
        wtr.write_record(["防火墙", &r.name, &format!("{:?}", r.direction)])?;
    }
    for s in &result.user_sessions {
        wtr.write_record([
            "会话",
            &s.username,
            &format!("{} @ {}", s.computer, s.session_id),
        ])?;
    }

    wtr.flush()?;
    Ok(())
}
