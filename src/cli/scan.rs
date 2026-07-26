//! 扫描 CLI
//!
//! 处理扫描子命令的交互式配置向导和直接模式

use crate::cli::{
    colorize, parse_scan_type, print_banner, print_scan_types, InteractiveMenu, save_scan_result,
};
use crate::core::Result;
use crate::output::color::*;
use crate::output::format::OutputFormat;
use crate::output::progress::ScanProgress;
use crate::scanner::*;
use std::path::PathBuf;
use std::sync::Arc;

/// 扫描命令入口
pub fn run_scan(
    targets: Option<Vec<String>>,
    scan_type: Option<String>,
    fast: bool,
    webfinger: bool,
    format: &str,
    output: Option<PathBuf>,
) -> Result<()> {
    let output_fmt = OutputFormat::parse(format).unwrap_or(OutputFormat::Json);

    // 如果没有提供目标或扫描类型，进入交互式模式
    match (&targets, &scan_type) {
        (Some(targets), Some(scan_type)) => {
            // 快速模式：使用默认配置
            let preset = if fast {
                ScanPreset::Fast
            } else {
                ScanPreset::Standard
            };

            match parse_scan_type(scan_type) {
                Some("host") => {
                    if targets.is_empty() {
                        print_error("主机扫描需要指定目标");
                        std::process::exit(1);
                    }
                    run_host_scan(targets.clone(), preset, None, output)
                }
                Some("port") => {
                    if targets.is_empty() {
                        print_error("端口扫描需要指定目标");
                        std::process::exit(1);
                    }
                    run_port_scan_simple(targets.clone(), preset, webfinger, output_fmt, output)
                }
                Some("comprehensive") => {
                    if targets.is_empty() {
                        print_error("综合扫描需要指定目标");
                        std::process::exit(1);
                    }
                    run_comprehensive_scan_simple(targets.clone(), preset, webfinger, output_fmt, output)
                }
                _ => {
                    print_error(&format!("未知的扫描类型: {}", scan_type));
                    print_scan_types();
                    std::process::exit(1);
                }
            }
        }
        _ => run_interactive_scan(targets, scan_type, fast, webfinger, output_fmt, output),
    }
}

/// 运行交互式扫描向导
fn run_interactive_scan(
    initial_targets: Option<Vec<String>>,
    initial_type: Option<String>,
    fast: bool,
    initial_webfinger: bool,
    output_fmt: OutputFormat,
    output: Option<PathBuf>,
) -> Result<()> {
    print_banner();
    println!();
    print_info("IntraSweep 交互式扫描配置向导");
    println!();

    // 步骤 1: 扫描目标
    let targets = if let Some(t) = initial_targets {
        InteractiveMenu::print_step(1, 6, "扫描目标");
        println!("已指定目标: {}", t.join(", "));
        println!();
        t
    } else {
        InteractiveMenu::print_step(1, 6, "扫描目标");
        println!("输入格式示例:");
        println!("  单个IP:       192.168.1.1");
        println!("  IP范围:       192.168.1.1-192.168.1.100");
        println!("  CIDR网段:     192.168.1.0/24");
        println!("  多个目标:     192.168.1.1,192.168.1.2,192.168.1.0/24");
        println!();

        let input = InteractiveMenu::read_input_required("请输入扫描目标: ", "目标不能为空，请重新输入");
        let targets: Vec<String> = input.split(',').map(|s| s.trim().to_string()).collect();
        print_success(&format!("已设置 {} 个目标", targets.len()));
        targets
    };

    // 步骤 2: 扫描类型
    let scan_type = if let Some(st) = initial_type {
        InteractiveMenu::print_step(2, 6, "扫描类型");
        println!("已指定: {}", format_scan_type(&st));
        println!();
        st
    } else {
        InteractiveMenu::print_step(2, 6, "扫描类型");
        println!("  1. 端口扫描       - 扫描指定主机的开放端口");
        println!("  2. 主机存活       - 检测网段内的存活主机");
        println!("  3. 综合扫描       - 主机发现 + 端口扫描");
        println!();

        let choice = InteractiveMenu::read_number_opt("请选择扫描类型 [1-3, 默认 1]: ", 1, 3, 1);
        let scan_type = match choice {
            1 => "port".to_string(),
            2 => "host".to_string(),
            3 => "comprehensive".to_string(),
            _ => "port".to_string(),
        };
        print_success(&format!("已选择: {}", format_scan_type(&scan_type)));
        scan_type
    };

    // 步骤 3: 扫描预设
    InteractiveMenu::print_step(3, 6, "扫描预设");
    println!("  1. Fast       - 快速扫描 (高并发，短超时)");
    println!("  2. Standard   - 标准扫描 (平衡速度和准确性)");
    println!("  3. Deep       - 深度扫描 (全端口扫描)");
    println!("  4. Stealth    - 隐蔽扫描 (低并发，有延迟)");
    println!();

    let default_preset = if fast { 1 } else { 2 };
    let preset_choice = InteractiveMenu::read_number_opt(
        &format!("请选择扫描预设 [1-4, 默认 {}]: ", if fast { "1(Fast)" } else { "2(Standard)" }),
        1, 4, default_preset,
    );
    let config = match preset_choice {
        1 => {
            print_success("已选择: Fast (快速扫描)");
            ScanPreset::Fast.to_config()
        }
        2 => {
            print_success("已选择: Standard (标准扫描)");
            ScanPreset::Standard.to_config()
        }
        3 => {
            print_success("已选择: Deep (深度扫描)");
            ScanPreset::Deep.to_config()
        }
        4 => {
            print_success("已选择: Stealth (隐蔽扫描)");
            ScanPreset::Stealth.to_config()
        }
        _ => ScanPreset::Standard.to_config(),
    };

    // 步骤 4: 服务探测
    InteractiveMenu::print_step(4, 6, "服务探测");
    println!("服务探测可以识别开放端口上运行的服务版本信息，但会增加扫描时间");
    println!();

    let enable_service = InteractiveMenu::read_input("是否启用服务探测? [y/N]: ");
    let mut config = config;
    config.service_detection = enable_service.to_lowercase() == "y";
    if config.service_detection {
        print_success("已启用服务探测");
        let timeout_input = InteractiveMenu::read_input("服务探测超时 (毫秒，默认5000): ");
        if !timeout_input.is_empty() {
            if let Ok(t) = timeout_input.parse::<u64>() {
                config.service_timeout_ms = t;
                print_success(&format!("超时设置为: {}ms", t));
            }
        }
    } else {
        print_info("已跳过服务探测");
    }

    // 步骤 5: Web指纹识别
    InteractiveMenu::print_step(5, 6, "Web指纹识别");
    println!("Web指纹识别可以自动识别开放端口上运行的Web应用");
    println!("(如 WebLogic, 宝塔面板, Tomcat, 泛微OA 等)");
    println!();

    if initial_webfinger {
        config.web_fingerprint = true;
        print_success("已启用Web指纹识别");
    } else {
        let enable_webfinger = InteractiveMenu::read_input("是否启用Web指纹识别? [y/N]: ");
        config.web_fingerprint = enable_webfinger.to_lowercase() == "y";
        if config.web_fingerprint {
            print_success("已启用Web指纹识别");
        } else {
            print_info("已跳过Web指纹识别");
        }
    }

    // 步骤 6: 高级选项
    InteractiveMenu::print_step(6, 6, "高级选项");
    let configure_advanced = InteractiveMenu::read_input("是否配置高级选项? [y/N]: ");
    if configure_advanced.to_lowercase() == "y" {
        configure_advanced_options(&mut config);
    }

    // 确认
    InteractiveMenu::print_step(6, 6, "配置摘要");
    println!("  扫描目标:     {}", targets.join(", "));
    println!("  扫描类型:     {}", format_scan_type(&scan_type));
    println!("  扫描预设:     {}", format_preset(&config));
    println!(
        "  服务探测:     {}",
        if config.service_detection { "启用" } else { "禁用" }
    );
    println!(
        "  Web指纹:     {}",
        if config.web_fingerprint { "启用" } else { "禁用" }
    );
    println!("  主机扫描方式: {}", config.host_scan_method.display_name());
    println!("  端口扫描方式: {}", config.port_scan_method.display_name());
    println!();

    if !InteractiveMenu::confirm("确认开始扫描? [Y/n]: ") {
        print_info("已取消扫描");
        return Ok(());
    }

    println!();
    print_info("开始扫描...");
    println!();

    // 执行扫描
    match scan_type.as_str() {
        "host" => run_host_scan_from_config(targets, config, output),
        "port" => run_port_scan_from_config(targets, config, output_fmt, output),
        "comprehensive" => run_comprehensive_scan_from_config(targets, config, output_fmt, output),
        _ => run_port_scan_from_config(targets, config, output_fmt, output),
    }
}

/// 配置高级选项（向导式）
fn configure_advanced_options(config: &mut ScanConfig) {
    println!();
    println!("  ┌─ 主机扫描方式");
    println!("  │");
    println!("  │  1. TCP SYN    - TCP SYN 扫描（默认，兼容性最好）");
    println!("  │  2. ICMP       - ICMP Ping 扫描（需要 ICMP 权限）");
    println!("  │  3. ARP        - ARP 扫描（仅本地网络，速度快）");
    println!("  │  4. 混合模式   - TCP SYN + ICMP，提高发现率");
    println!();

    let skip = InteractiveMenu::read_input("  按 Enter 跳过 [使用默认: TCP SYN] 或选择 [1-4]: ");
    if !skip.is_empty() {
        if let Ok(method) = skip.parse::<usize>() {
            if (1..=4).contains(&method) {
                config.host_scan_method = match method {
                    1 => HostScanMethod::TcpSyn,
                    2 => HostScanMethod::Icmp,
                    3 => HostScanMethod::Arp,
                    4 => HostScanMethod::Hybrid,
                    _ => HostScanMethod::TcpSyn,
                };
                print_success(&format!(
                    "  已设置: {}",
                    config.host_scan_method.display_name()
                ));
            }
        }
    } else {
        print_info("  使用默认: TCP SYN");
    }
    println!();

    println!("  ┌─ 端口扫描方式");
    println!("  │");
    println!("  │  1. TCP Connect - TCP Connect 扫描（默认，兼容性最好）");
    println!("  │  2. TCP SYN     - TCP SYN 扫描（需要管理员权限）");
    println!("  │  3. UDP         - UDP 扫描（速度较慢）");
    println!();

    let skip =
        InteractiveMenu::read_input("  按 Enter 跳过 [使用默认: TCP Connect] 或选择 [1-3]: ");
    if !skip.is_empty() {
        if let Ok(method) = skip.parse::<usize>() {
            if (1..=3).contains(&method) {
                config.port_scan_method = match method {
                    1 => PortScanMethod::TcpConnect,
                    2 => PortScanMethod::TcpSyn,
                    3 => PortScanMethod::Udp,
                    _ => PortScanMethod::TcpConnect,
                };
                print_success(&format!(
                    "  已设置: {}",
                    config.port_scan_method.display_name()
                ));
            }
        }
    } else {
        print_info("  使用默认: TCP Connect");
    }
    println!();

    println!("  ┌─ 其他选项");
    println!();
    print_info(&format!(
        "  当前服务探测超时: {}ms",
        config.service_timeout_ms
    ));

    let timeout_input = InteractiveMenu::read_input("  按 Enter 跳过或输入新的超时时间 (毫秒): ");
    if !timeout_input.is_empty() {
        if let Ok(t) = timeout_input.parse::<u64>() {
            config.service_timeout_ms = t;
            print_success(&format!("  已设置超时: {}ms", t));
        }
    } else {
        print_info("  保持不变");
    }
    println!();
}

/// 格式化扫描类型
fn format_scan_type(ty: &str) -> String {
    match ty {
        "port" => "端口扫描".to_string(),
        "host" => "主机扫描".to_string(),
        "comprehensive" => "综合扫描".to_string(),
        _ => ty.to_string(),
    }
}

/// 格式化预设
fn format_preset(config: &ScanConfig) -> String {
    // 根据配置判断预设类型
    if config.max_concurrent_ports >= 5000 {
        "Fast (快速)".to_string()
    } else if config.max_concurrent_ports >= 3000 {
        "Standard (标准)".to_string()
    } else if config.service_detection {
        "Deep (深度)".to_string()
    } else {
        "Stealth (隐蔽)".to_string()
    }
}

/// 运行主机存活扫描
fn run_host_scan(
    targets: Vec<String>,
    preset: ScanPreset,
    host_method: Option<HostScanMethod>,
    output: Option<PathBuf>,
) -> Result<()> {
    let mut config = preset_to_config(preset);

    // 应用用户指定的扫描方式
    if let Some(method) = host_method {
        config.host_scan_method = method;
    }

    println!();
    print_info("开始主机存活扫描");
    print_info(&format!("目标: {}", targets.join(", ")));
    print_info(&format!("预设: {:?}", preset));
    print_info(&format!(
        "扫描方式: {}",
        config.host_scan_method.display_name()
    ));
    println!();

    let rt = tokio::runtime::Runtime::new()?;
    let scanner = Scanner::new(config);
    let result = rt.block_on(scanner.host_discovery(targets));

    print_scan_results(&result);

    if let Ok(path) = save_scan_result(&result, OutputFormat::Json, output) {
        println!();
        print_success(&format!("结果已保存到: {}", path.display()));
    }

    Ok(())
}

/// 将预设转换为配置
fn preset_to_config(preset: ScanPreset) -> ScanConfig {
    match preset {
        ScanPreset::Fast => ScanConfig::fast_scan(),
        ScanPreset::Standard => ScanConfig::default(),
        ScanPreset::Deep => ScanConfig::deep_scan(),
        ScanPreset::Stealth => ScanConfig::stealth_scan(),
    }
}

/// 使用配置进行主机存活扫描（交互式模式）
fn run_host_scan_from_config(
    targets: Vec<String>,
    config: ScanConfig,
    output: Option<PathBuf>,
) -> Result<()> {
    println!();
    print_info("开始主机存活扫描");
    print_info(&format!("目标: {}", targets.join(", ")));
    print_info(&format!("预设: {}", format_preset(&config)));
    print_info(&format!(
        "扫描方式: {}",
        config.host_scan_method.display_name()
    ));
    println!();

    let rt = tokio::runtime::Runtime::new()?;
    let scanner = Scanner::new(config);
    let result = rt.block_on(scanner.host_discovery(targets));

    print_scan_results(&result);

    if let Ok(path) = save_scan_result(&result, OutputFormat::Json, output) {
        println!();
        print_success(&format!("结果已保存到: {}", path.display()));
    }

    Ok(())
}

/// 简化的端口扫描（使用默认配置）
fn run_port_scan_simple(
    targets: Vec<String>,
    preset: ScanPreset,
    webfinger: bool,
    output_fmt: OutputFormat,
    output: Option<PathBuf>,
) -> Result<()> {
    let mut config = preset_to_config(preset);
    if webfinger {
        config.web_fingerprint = true;
    }

    println!();
    print_info("开始端口扫描");
    print_info(&format!("目标: {}", targets.join(", ")));
    print_info(&format!("预设: {:?}", preset));
    if webfinger {
        print_success("Web指纹: 启用");
    }
    println!();

    // 创建进度条
    let progress = Arc::new(ScanProgress::new(100, true));
    let progress_clone = progress.clone();

    let rt = tokio::runtime::Runtime::new()?;
    let scanner = Scanner::new(config).with_progress_callback(Arc::new(move |current, total| {
        let percent = (current as f64 / total as f64 * 100.0) as u64;
        progress_clone.set_position(percent as usize);
    }));
    let mut result = rt.block_on(scanner.port_scan(targets));

    if scanner.config.web_fingerprint {
        print_info("正在进行Web指纹探测...");
        rt.block_on(scanner.probe_web_fingerprints(&mut result));
    }

    progress.finish_with_message("扫描完成!");
    println!();

    print_scan_results(&result);

    if let Ok(path) = save_scan_result(&result, output_fmt, output) {
        println!();
        print_success(&format!("结果已保存到: {}", path.display()));
    }

    Ok(())
}

/// 简化的综合扫描（使用默认配置）
fn run_comprehensive_scan_simple(
    targets: Vec<String>,
    preset: ScanPreset,
    webfinger: bool,
    output_fmt: OutputFormat,
    output: Option<PathBuf>,
) -> Result<()> {
    let mut config = preset_to_config(preset);
    if webfinger {
        config.web_fingerprint = true;
    }

    println!();
    print_info("开始综合扫描");
    print_info(&format!("目标: {}", targets.join(", ")));
    print_info(&format!("预设: {:?}", preset));
    if webfinger {
        print_success("Web指纹: 启用");
    }
    println!();

    // 创建进度条
    let progress = Arc::new(ScanProgress::new(100, true));
    let progress_clone = progress.clone();

    let rt = tokio::runtime::Runtime::new()?;
    let scanner = Scanner::new(config).with_progress_callback(Arc::new(move |current, total| {
        let percent = (current as f64 / total as f64 * 100.0) as u64;
        progress_clone.set_position(percent as usize);
    }));
    let mut result = rt.block_on(scanner.comprehensive_scan(targets));

    if scanner.config.web_fingerprint {
        print_info("正在进行Web指纹探测...");
        rt.block_on(scanner.probe_web_fingerprints(&mut result));
    }

    progress.finish_with_message("扫描完成!");
    println!();

    print_scan_results(&result);

    if let Ok(path) = save_scan_result(&result, output_fmt, output) {
        println!();
        print_success(&format!("结果已保存到: {}", path.display()));
    }

    Ok(())
}

/// 使用配置进行端口扫描（交互式模式）
fn run_port_scan_from_config(
    targets: Vec<String>,
    config: ScanConfig,
    output_fmt: OutputFormat,
    output: Option<PathBuf>,
) -> Result<()> {
    println!();
    print_info("开始端口扫描");
    print_info(&format!("目标: {}", targets.join(", ")));
    print_info(&format!("预设: {}", format_preset(&config)));
    print_info(&format!(
        "扫描方式: {}",
        config.port_scan_method.display_name()
    ));
    if config.service_detection {
        print_success("服务探测: 启用");
    }
    if config.web_fingerprint {
        print_success("Web指纹: 启用");
    }
    println!();

    // 创建进度条
    let progress = Arc::new(ScanProgress::new(100, true));
    let progress_clone = progress.clone();

    let rt = tokio::runtime::Runtime::new()?;
    let scanner = Scanner::new(config).with_progress_callback(Arc::new(move |current, total| {
        let percent = (current as f64 / total as f64 * 100.0) as u64;
        progress_clone.set_position(percent as usize);
    }));
    let mut result = rt.block_on(scanner.port_scan(targets));

    // Web指纹探测
    if scanner.config.web_fingerprint {
        print_info("正在进行Web指纹探测...");
        rt.block_on(scanner.probe_web_fingerprints(&mut result));
    }

    progress.finish_with_message("扫描完成!");
    println!();

    print_scan_results(&result);

    if let Ok(path) = save_scan_result(&result, output_fmt, output) {
        println!();
        print_success(&format!("结果已保存到: {}", path.display()));
    }

    Ok(())
}

/// 使用配置进行综合扫描（交互式模式）
fn run_comprehensive_scan_from_config(
    targets: Vec<String>,
    config: ScanConfig,
    output_fmt: OutputFormat,
    output: Option<PathBuf>,
) -> Result<()> {
    println!();
    print_info("开始综合扫描");
    print_info(&format!("目标: {}", targets.join(", ")));
    print_info(&format!("预设: {}", format_preset(&config)));
    print_info(&format!(
        "主机扫描: {}",
        config.host_scan_method.display_name()
    ));
    print_info(&format!(
        "端口扫描: {}",
        config.port_scan_method.display_name()
    ));
    if config.service_detection {
        print_success(&format!(
            "服务探测: 启用 (超时: {}ms)",
            config.service_timeout_ms
        ));
    }
    if config.web_fingerprint {
        print_success("Web指纹: 启用");
    }
    println!();

    // 创建进度条
    let progress = Arc::new(ScanProgress::new(100, true));
    let progress_clone = progress.clone();

    let rt = tokio::runtime::Runtime::new()?;
    let scanner = Scanner::new(config).with_progress_callback(Arc::new(move |current, total| {
        let percent = (current as f64 / total as f64 * 100.0) as u64;
        progress_clone.set_position(percent as usize);
    }));
    let mut result = rt.block_on(scanner.comprehensive_scan(targets));

    // Web指纹探测
    if scanner.config.web_fingerprint {
        print_info("正在进行Web指纹探测...");
        rt.block_on(scanner.probe_web_fingerprints(&mut result));
    }

    progress.finish_with_message("扫描完成!");
    println!();

    print_scan_results(&result);

    if let Ok(path) = save_scan_result(&result, output_fmt, output) {
        println!();
        print_success(&format!("结果已保存到: {}", path.display()));
    }

    Ok(())
}

/// 打印扫描结果
fn print_scan_results(result: &crate::scanner::ScanResult) {
    println!();
    println!("╔════════════════════════════════════════════════════════════════════════════╗");
    println!(
        "║  {}",
        colorize(
            &format!("{} 扫描完成", result.scan_type.name()),
            Color::BrightGreen
        )
    );
    println!("╠════════════════════════════════════════════════════════════════════════════╣");
    println!("║  扫描统计");
    println!("╠────────────────────────────────────────────────────────────────────────────╣");
    println!(
        "║  扫描耗时:     {:<60}║",
        format!("{:.2} 秒", result.duration_secs)
    );
    println!("║  存活主机:     {:<60}║", result.stats.alive_hosts);
    println!("║  开放端口:     {:<60}║", result.stats.total_open_ports);
    if result.stats.web_fingerprints_found > 0 {
        println!("║  Web指纹:     {:<60}║", result.stats.web_fingerprints_found);
    }
    println!("╠════════════════════════════════════════════════════════════════════════════╣");
    println!("║  扫描结果");
    println!("╠────────────────────────────────────────────────────────────────────────────╣");

    if result.hosts.is_empty() {
        println!("║  {:<78}║", "未发现存活主机");
    } else {
        for host in &result.hosts {
            if host.is_alive {
                let latency = host
                    .latency_ms
                    .map_or_else(|| "N/A".to_string(), |l| format!("{}ms", l));
                let ports: Vec<String> = host
                    .open_ports
                    .iter()
                    .map(|p| format!("{}/{}", p.port, p.service.as_deref().unwrap_or("unknown")))
                    .collect();

                println!(
                    "║  {} {:<15} {:<10} {:<48}║",
                    colorize("✓", Color::Green),
                    host.ip,
                    latency,
                    if ports.is_empty() {
                        "无开放端口".to_string()
                    } else {
                        ports.join(", ")
                    }
                );

                // Web指纹信息
                if !host.web_fingerprints.is_empty() {
                    for wf in &host.web_fingerprints {
                        if !wf.web_apps.is_empty() {
                            let apps: Vec<String> = wf.web_apps.iter()
                                .map(|a| format!("{}{}", a.name, a.version.as_deref().map(|v| format!(" {}", v)).unwrap_or_default()))
                                .collect();
                            println!(
                                "║    {} {:<74}║",
                                colorize("W", Color::Cyan),
                                apps.join(", ")
                            );
                        }
                        if !wf.title.is_empty() {
                            println!(
                                "║    {} {:<74}║",
                                colorize("T", Color::Yellow),
                                wf.title
                            );
                        }
                    }
                }
            }
        }
    }

    println!("╚════════════════════════════════════════════════════════════════════════════╝");
    println!();
}
