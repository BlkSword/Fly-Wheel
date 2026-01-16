//! Fly-Wheel - 强大的内网渗透辅助工具

mod collector;
mod core;
mod modules;
mod output;
mod scanner;

use clap::{Parser, Subcommand, ValueEnum};
use collector::InfoCollector;
use core::error::Result;
use output::color::{print_error, print_info, print_success, Color};
use scanner::{ScanConfig, Scanner};
use std::path::PathBuf;

/// 扫描速度预设
#[derive(Clone, ValueEnum, Copy, Debug)]
enum ScanPreset {
    /// 快速扫描 - 高并发，短超时，适合快速发现
    Fast,
    /// 标准扫描 - 平衡速度和准确性
    Standard,
    /// 深度扫描 - 扫描所有端口，低并发
    Deep,
    /// 隐蔽扫描 - 低并发，长延迟，避免检测
    Stealth,
}

/// Fly-Wheel - 内网渗透辅助工具
#[derive(Parser)]
#[command(
    name = "fly-wheel",
    author = "BlkSword",
    version = "0.2.0",
    long_about = None,
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 收集当前系统所有信息
    Collect {
        /// 输出文件路径 (JSON格式)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// 静默模式 (不显示进度条)
        #[arg(short, long)]
        quiet: bool,
    },

    /// 主机存活扫描 (TCP SYN)
    Host {
        /// 扫描目标 (IP/CIDR/范围)
        #[arg(required = true)]
        targets: Vec<String>,

        /// 扫描预设: fast(快)/standard(中)/stealth(隐蔽)
        #[arg(short, long, value_enum, default_value_t = ScanPreset::Standard)]
        preset: ScanPreset,

        /// 输出文件路径 (JSON格式)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// 端口扫描
    Port {
        /// 扫描目标 (IP/CIDR/范围)
        #[arg(required = true)]
        targets: Vec<String>,

        /// 扫描预设: fast(Top100)/standard(Top1000)/deep(全端口)/stealth(隐蔽)
        #[arg(short, long, value_enum, default_value_t = ScanPreset::Standard)]
        preset: ScanPreset,

        /// 输出文件路径 (JSON格式)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// 域环境扫描 (Active Directory)
    Domain {
        /// 输出文件路径 (JSON格式)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// 综合扫描 (主机发现 + 端口扫描)
    Comprehensive {
        /// 扫描目标 (IP/CIDR/范围)
        #[arg(required = true)]
        targets: Vec<String>,

        /// 扫描预设
        #[arg(short, long, value_enum, default_value_t = ScanPreset::Standard)]
        preset: ScanPreset,

        /// 输出文件路径 (JSON格式)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Collect { output, quiet } => run_collect(output, quiet),
        Commands::Host {
            targets,
            preset,
            output,
        } => run_host_scan(targets, preset, output),
        Commands::Port {
            targets,
            preset,
            output,
        } => run_port_scan(targets, preset, output),
        Commands::Domain { output } => run_domain_scan(output),
        Commands::Comprehensive {
            targets,
            preset,
            output,
        } => run_comprehensive_scan(targets, preset, output),
    };

    if let Err(e) = result {
        print_error(&format!("{}", e));
        std::process::exit(1);
    }
}

/// 运行信息收集
fn run_collect(output: Option<PathBuf>, quiet: bool) -> Result<()> {
    print_info("初始化信息收集器...");

    let mut collector = InfoCollector::new();

    print_info("开始收集系统信息...");
    println!();
    let report = collector.collect_all_with_progress(quiet)?;

    println!();
    print_info("正在保存报告...");
    let output_path = collector::save_report(&report, output)?;

    print_collect_results(&report, &output_path);

    Ok(())
}

/// 运行主机存活扫描
fn run_host_scan(targets: Vec<String>, preset: ScanPreset, output: Option<PathBuf>) -> Result<()> {
    let config = preset_to_config(preset);

    println!();
    print_info(&format!("开始主机存活扫描"));
    print_info(&format!("目标: {}", targets.join(", ")));
    print_info(&format!("预设: {:?}", preset));
    println!();

    let rt = tokio::runtime::Runtime::new()?;
    let scanner = Scanner::new(config);
    let result = rt.block_on(scanner.host_discovery(targets));

    print_scan_results(&result);

    if let Ok(path) = scanner.save_result(&result, output) {
        println!();
        print_success(&format!("结果已保存到: {}", path.display()));
    }

    Ok(())
}

/// 运行端口扫描
fn run_port_scan(targets: Vec<String>, preset: ScanPreset, output: Option<PathBuf>) -> Result<()> {
    let config = preset_to_config(preset);

    println!();
    print_info(&format!("开始端口扫描"));
    print_info(&format!("目标: {}", targets.join(", ")));
    print_info(&format!("预设: {:?}", preset));
    println!();

    let rt = tokio::runtime::Runtime::new()?;
    let scanner = Scanner::new(config);
    let result = rt.block_on(scanner.port_scan(targets));

    print_scan_results(&result);

    if let Ok(path) = scanner.save_result(&result, output) {
        println!();
        print_success(&format!("结果已保存到: {}", path.display()));
    }

    Ok(())
}

/// 运行域环境扫描
fn run_domain_scan(output: Option<PathBuf>) -> Result<()> {
    println!();
    print_info("开始域环境扫描...");
    println!();

    let mut scanner = Scanner::default();
    let result = scanner.domain_scan();

    print_domain_scan_results(&result);

    if let Ok(path) = scanner.save_result(&convert_domain_result_to_scan(result), output) {
        println!();
        print_success(&format!("结果已保存到: {}", path.display()));
    }

    Ok(())
}

/// 运行综合扫描
fn run_comprehensive_scan(
    targets: Vec<String>,
    preset: ScanPreset,
    output: Option<PathBuf>,
) -> Result<()> {
    let config = preset_to_config(preset);

    println!();
    print_info(&format!("开始综合扫描"));
    print_info(&format!("目标: {}", targets.join(", ")));
    print_info(&format!("预设: {:?}", preset));
    println!();

    let rt = tokio::runtime::Runtime::new()?;
    let scanner = Scanner::new(config);
    let result = rt.block_on(scanner.comprehensive_scan(targets));

    print_scan_results(&result);

    if let Ok(path) = scanner.save_result(&result, output) {
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

/// 将域扫描结果转换为扫描结果
fn convert_domain_result_to_scan(
    domain_result: scanner::domain::DomainScanResult,
) -> scanner::ScanResult {
    use scanner::models::{HostResult, PortInfo, PortState, ScanResult, ScanStats, ScanType};

    let mut host = HostResult {
        ip: "domain".to_string(),
        hostname: domain_result.domain_name.clone(),
        is_alive: domain_result.is_joined,
        latency_ms: None,
        mac: None,
        open_ports: vec![],
        services: vec![],
    };

    if let Some(ref dc) = domain_result.domain_controller {
        host.open_ports.push(PortInfo {
            port: 0,
            state: PortState::Open,
            service: Some(format!("域控制器: {}", dc)),
            version: None,
            banner: None,
        });
    }

    ScanResult {
        scan_type: ScanType::DomainScan,
        targets: vec![],
        start_time: chrono::Utc::now(),
        end_time: chrono::Utc::now(),
        duration_secs: 0.0,
        hosts: vec![host],
        stats: ScanStats {
            total_targets: 1,
            alive_hosts: if domain_result.is_joined { 1 } else { 0 },
            total_open_ports: 0,
            services_found: 0,
        },
    }
}

/// 彩色化文本
fn colorize(text: &str, color: Color) -> String {
    use std::io::Write;
    use termcolor::{Color as TermColor, ColorSpec, WriteColor};

    let mut buffer = Vec::new();
    let mut writer = termcolor::Ansi::new(&mut buffer);

    let term_color = match color {
        Color::Black => TermColor::Black,
        Color::Red => TermColor::Red,
        Color::Green => TermColor::Green,
        Color::Yellow => TermColor::Yellow,
        Color::Blue => TermColor::Blue,
        Color::Magenta => TermColor::Magenta,
        Color::Cyan => TermColor::Cyan,
        Color::White => TermColor::White,
        Color::BrightBlack => TermColor::Ansi256(8),
        Color::BrightRed => TermColor::Ansi256(9),
        Color::BrightGreen => TermColor::Ansi256(10),
        Color::BrightYellow => TermColor::Ansi256(11),
        Color::BrightBlue => TermColor::Ansi256(12),
        Color::BrightMagenta => TermColor::Ansi256(13),
        Color::BrightCyan => TermColor::Ansi256(14),
        Color::BrightWhite => TermColor::Ansi256(15),
    };

    writer
        .set_color(ColorSpec::new().set_fg(Some(term_color)))
        .ok();
    write!(writer, "{}", text).ok();
    writer.reset().ok();

    String::from_utf8_lossy(&buffer).to_string()
}

/// 打印信息收集结果
fn print_collect_results(report: &collector::SystemReport, output_path: &PathBuf) {
    println!();
    println!("╔════════════════════════════════════════════════════════════════════════════╗");
    println!("║  {}", colorize("信息收集完成", Color::BrightGreen));
    println!("╠════════════════════════════════════════════════════════════════════════════╣");
    println!("║  基础信息");
    println!("╠────────────────────────────────────────────────────────────────────────────╣");
    println!("║  主机名:     {:<60}║", report.metadata.hostname);
    println!(
        "║  操作系统:   {:<60}║",
        format!(
            "{} {}",
            report.metadata.os_type, report.system.os_info.os_version
        )
    );
    println!("║  架构:       {:<60}║", report.metadata.arch);
    println!(
        "║  当前用户:   {:<60}║",
        format!(
            "{} ({:?})",
            report.system.current_user.username, report.system.current_user.privileges
        )
    );
    println!(
        "║  收集耗时:   {:<60}║",
        format!("{:.2} 秒", report.metadata.collection_duration_secs)
    );
    println!("╠════════════════════════════════════════════════════════════════════════════╣");
    println!("║  系统资源");
    println!("╠────────────────────────────────────────────────────────────────────────────╣");
    println!("║  CPU核心数:  {:<60}║", report.system.cpu_info.cpu_count);
    println!(
        "║  总内存:     {:<60}║",
        format!(
            "{:.2} GB",
            report.system.memory_info.total_memory as f64 / 1024.0 / 1024.0 / 1024.0
        )
    );
    println!(
        "║  内存使用:   {:<60}║",
        format!(
            "{:.2} GB ({:.1}%)",
            report.system.memory_info.used_memory as f64 / 1024.0 / 1024.0 / 1024.0,
            report.system.memory_info.usage_percent
        )
    );
    println!("╠════════════════════════════════════════════════════════════════════════════╣");
    println!("║  网络信息");
    println!("╠────────────────────────────────────────────────────────────────────────────╣");
    println!(
        "║  网络接口:   {:<60}║",
        report.network.stats.interface_count
    );
    println!("║  路由条目:   {:<60}║", report.network.stats.route_count);
    println!("║  ARP条目:    {:<60}║", report.network.stats.arp_count);
    println!(
        "║  活动连接:   {:<60}║",
        report.network.stats.connection_count
    );
    println!("╠════════════════════════════════════════════════════════════════════════════╣");
    println!("║  安全信息");
    println!("╠────────────────────────────────────────────────────────────────────────────╣");
    println!("║  进程总数:   {:<60}║", report.processes.total_count);
    println!("║  可疑进程:   {:<60}║", report.processes.suspicious.len());
    println!(
        "║  SSH密钥:    {:<60}║",
        report.credentials.stats.ssh_key_count
    );
    println!(
        "║  API密钥:    {:<60}║",
        report.credentials.stats.api_key_count
    );
    println!("║  敏感文件:   {:<60}║", report.files.stats.sensitive_count);
    println!("╠════════════════════════════════════════════════════════════════════════════╣");
    println!(
        "║  {}",
        colorize(
            &format!("报告已保存到: {}", output_path.display()),
            Color::BrightCyan
        )
    );
    println!("╚════════════════════════════════════════════════════════════════════════════╝");
    println!();
}

/// 打印扫描结果
fn print_scan_results(result: &scanner::ScanResult) {
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
            }
        }
    }

    println!("╚════════════════════════════════════════════════════════════════════════════╝");
    println!();
}

/// 打印域扫描结果
fn print_domain_scan_results(result: &scanner::domain::DomainScanResult) {
    println!();
    println!("╔════════════════════════════════════════════════════════════════════════════╗");
    println!("║  {}", colorize("域环境扫描完成", Color::BrightCyan));
    println!("╠════════════════════════════════════════════════════════════════════════════╣");
    println!("║  域信息");
    println!("╠────────────────────────────────────────────────────────────────────────────╣");

    if result.is_joined {
        println!(
            "║  域名:         {:<60}║",
            result.domain_name.as_deref().unwrap_or("未知")
        );
        println!(
            "║  域控制器:     {:<60}║",
            result.domain_controller.as_deref().unwrap_or("未发现")
        );
        println!(
            "║  当前计算机:   {:<60}║",
            result.current_computer.as_deref().unwrap_or("未知")
        );
        println!(
            "║  当前用户:     {:<60}║",
            result.current_user.as_deref().unwrap_or("未知")
        );
        println!(
            "║  状态:         {:<60}║",
            colorize("已加入域", Color::Green)
        );
    } else {
        println!(
            "║  状态:         {:<60}║",
            colorize("未加入域 / WORKGROUP", Color::Yellow)
        );
    }

    println!("╠════════════════════════════════════════════════════════════════════════════╣");
    println!("║  发现的账户");
    println!("╠────────────────────────────────────────────────────────────────────────────╣");

    if !result.domain_users.is_empty() {
        println!("║  域用户数量:   {:<60}║", result.domain_users.len());
        for (i, user) in result.domain_users.iter().take(10).enumerate() {
            println!("║  {:<2}. {:<74}║", i + 1, user.username);
        }
        if result.domain_users.len() > 10 {
            println!("║  ... 还有 {} 个用户", result.domain_users.len() - 10);
        }
    }

    if !result.admin_accounts.is_empty() {
        println!("║");
        println!("║  域管理员:     {:<60}║", result.admin_accounts.join(", "));
    }

    println!("╠════════════════════════════════════════════════════════════════════════════╣");
    println!("║  SPN账户 (Kerberoasting目标)");
    println!("╠────────────────────────────────────────────────────────────────────────────╣");

    if result.spn_accounts.is_empty() {
        println!("║  {:<78}║", "未发现SPN账户");
    } else {
        println!("║  SPN数量:      {:<60}║", result.spn_accounts.len());
        for (i, spn) in result.spn_accounts.iter().take(10).enumerate() {
            println!(
                "║  {:<2}. {:<30} -> {:<44}║",
                i + 1,
                spn.service_type,
                spn.username
            );
        }
        if result.spn_accounts.len() > 10 {
            println!("║  ... 还有 {} 个SPN账户", result.spn_accounts.len() - 10);
        }
    }

    println!("╚════════════════════════════════════════════════════════════════════════════╝");
    println!();
}
