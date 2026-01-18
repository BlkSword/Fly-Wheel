//! IntraSweep - 内网渗透辅助工具

mod collector;
mod core;
mod cracker;
mod modules;
mod output;
mod scanner;

use clap::{Parser, Subcommand};
use collector::models::{CredentialReport, FileReport, NetworkReport, ProcessReport};
use collector::InfoCollector;
use core::error::{FlyWheelError, Result};
use cracker::service::Cracker;
use cracker::{CrackConfig, CrackService, DictManager};
use modules::collect::{
    CredentialCollector, FileCollector, NetworkCollector, ProcessCollector, SystemCollector,
    SystemInfo,
};
use output::color::{print_error, print_info, print_success, Color};
use output::progress::ScanProgress;
use scanner::{HostScanMethod, PortScanMethod, ScanConfig, ScanPreset, Scanner};
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Arc;

/// 格式化字节数
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

// ============================================================
// 交互式菜单系统
// ============================================================

struct InteractiveMenu;

impl InteractiveMenu {
    /// 读取用户输入
    fn read_input(prompt: &str) -> String {
        print!("{}", prompt);
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        input.trim().to_string()
    }

    /// 读取数字输入
    fn read_number(prompt: &str, min: usize, max: usize) -> usize {
        loop {
            let input = Self::read_input(prompt);
            match input.parse::<usize>() {
                Ok(n) if n >= min && n <= max => return n,
                _ => {
                    print_error(&format!("请输入 {} 到 {} 之间的数字", min, max));
                }
            }
        }
    }
}

/// IntraSweep - 内网渗透辅助工具
#[derive(Parser)]
#[command(
    name = "intrasweep",
    author = "BlkSword",
    version = "0.3.0",
    long_about = None,
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 系统信息收集 (缩写: s)
    System {
        /// 收集项目: all(a), system(sy), network(n), process(p), credential(c), file(f), domain(d)
        #[arg(required = true)]
        item: String,

        /// 输出文件路径 (JSON格式)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// 静默模式 (不显示进度条)
        #[arg(short, long)]
        quiet: bool,
    },

    /// 扫描功能 (缩写: sc)
    Scan {
        /// 扫描目标 (IP/CIDR/范围) - 可选，不填则进入交互式模式
        #[arg(value_name = "TARGETS")]
        targets: Option<Vec<String>>,

        /// 扫描类型: port(端口)/host(主机)/comprehensive(综合) - 可选
        #[arg(value_name = "TYPE")]
        scan_type: Option<String>,

        /// 快速扫描模式 (等同于 --preset fast)
        #[arg(short, long)]
        fast: bool,

        /// 输出文件路径 (JSON格式)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// 爆破功能 (缩写: cr)
    Crack {
        /// 目标主机 (可选，不填则进入交互式模式)
        #[arg(value_name = "TARGET")]
        target: Option<String>,

        /// 端口 (可选，默认为服务默认端口)
        #[arg(short, long)]
        port: Option<u16>,

        /// 服务类型: ssh, rdp, redis, postgres, mongodb, mssql, mysql
        #[arg(short, long)]
        service: Option<String>,

        /// 用户名列表 (逗号分隔，或使用 @文件)
        #[arg(short = 'u', long)]
        usernames: Option<String>,

        /// 密码字典文件
        #[arg(short = 'P', long)]
        password_file: Option<String>,

        /// 用户名字典文件
        #[arg(short = 'U', long)]
        username_file: Option<String>,

        /// 并发数 (默认: 10)
        #[arg(short, long, default_value = "10")]
        concurrency: usize,

        /// 超时时间(秒) (默认: 5)
        #[arg(short, long, default_value = "5")]
        timeout: u64,

        /// 延迟(毫秒) (可选，用于避免触发防护)
        #[arg(short, long)]
        delay: Option<u64>,
    },
}

// ============================================================
// 命令映射常量
// ============================================================

/// system 子命令映射 (完整名称, 缩写)
const SYSTEM_ITEMS: &[(&str, &str)] = &[
    ("all", "a"),
    ("system", "sy"),
    ("network", "n"),
    ("process", "p"),
    ("credential", "c"),
    ("file", "f"),
    ("domain", "d"),
];

/// scan 子命令映射 (完整名称, 缩写)
const SCAN_TYPES: &[(&str, &str)] = &[
    ("host", "h"),
    ("port", "po"),
    ("comprehensive", "c"),
];

// ============================================================
// 命令解析函数
// ============================================================

/// 解析 system 子命令，支持完整名称和缩写
fn parse_system_item(item: &str) -> Option<&'static str> {
    let item_lower = item.to_lowercase();
    for &(full, abbr) in SYSTEM_ITEMS {
        if item_lower == full || item_lower == abbr {
            return Some(full);
        }
    }
    None
}

/// 解析 scan 子命令，支持完整名称和缩写
fn parse_scan_type(scan_type: &str) -> Option<&'static str> {
    let type_lower = scan_type.to_lowercase();
    for &(full, abbr) in SCAN_TYPES {
        if type_lower == full || type_lower == abbr {
            return Some(full);
        }
    }
    None
}

/// 打印所有可用的 system 子命令
fn print_system_items() {
    println!("可用的收集项目:");
    for (full, abbr) in SYSTEM_ITEMS {
        println!("  {} ({})", full, abbr);
    }
}

/// 打印所有可用的 scan 子命令
fn print_scan_types() {
    println!("可用的扫描类型:");
    for (full, abbr) in SCAN_TYPES {
        println!("  {} ({})", full, abbr);
    }
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::System {
            item,
            output,
            quiet,
        } => match parse_system_item(&item) {
            Some("all") => run_system_collect_all(output, quiet),
            Some("system") => run_system_collect_basic(output, quiet),
            Some("network") => run_system_collect_network(output, quiet),
            Some("process") => run_system_collect_process(output, quiet),
            Some("credential") => run_system_collect_credential(output, quiet),
            Some("file") => run_system_collect_file(output, quiet),
            Some("domain") => run_domain_scan(output),
            _ => {
                print_error(&format!("未知的收集项目: {}", item));
                print_system_items();
                std::process::exit(1);
            }
        },

        Commands::Scan {
            targets,
            scan_type,
            fast,
            output,
        } => {
            // 如果没有提供目标或扫描类型，进入交互式模式
            if targets.is_none() || scan_type.is_none() {
                run_interactive_scan(targets, scan_type, fast, output)
            } else {
                // 快速模式：使用默认配置
                let targets = targets.unwrap();
                let scan_type = scan_type.unwrap();
                let preset = if fast {
                    ScanPreset::Fast
                } else {
                    ScanPreset::Standard
                };

                match parse_scan_type(&scan_type) {
                    Some("host") => {
                        if targets.is_empty() {
                            print_error("主机扫描需要指定目标");
                            std::process::exit(1);
                        }
                        run_host_scan(targets, preset, None, output)
                    }
                    Some("port") => {
                        if targets.is_empty() {
                            print_error("端口扫描需要指定目标");
                            std::process::exit(1);
                        }
                        run_port_scan_simple(targets, preset, output)
                    }
                    Some("comprehensive") => {
                        if targets.is_empty() {
                            print_error("综合扫描需要指定目标");
                            std::process::exit(1);
                        }
                        run_comprehensive_scan_simple(targets, preset, output)
                    }
                    _ => {
                        print_error(&format!("未知的扫描类型: {}", scan_type));
                        print_scan_types();
                        std::process::exit(1);
                    }
                }
            }
        }

        Commands::Crack {
            target,
            port,
            service,
            usernames,
            password_file,
            username_file,
            concurrency,
            timeout,
            delay,
        } => {
            // 如果没有提供目标，进入交互式模式
            if target.is_none() {
                run_interactive_crack(
                    port,
                    service,
                    usernames,
                    password_file,
                    username_file,
                    concurrency,
                    timeout,
                    delay,
                )
            } else {
                run_crack(
                    target.unwrap(),
                    port,
                    service,
                    usernames,
                    password_file,
                    username_file,
                    concurrency,
                    timeout,
                    delay,
                )
            }
        }
    };

    if let Err(e) = result {
        print_error(&format!("{}", e));
        std::process::exit(1);
    }
}

/// 运行交互式扫描向导
fn run_interactive_scan(
    initial_targets: Option<Vec<String>>,
    initial_type: Option<String>,
    _fast: bool,
    output: Option<PathBuf>,
) -> Result<()> {
    print_banner();
    println!();
    print_info("IntraSweep 交互式扫描配置向导");
    println!();

    // 步骤 1: 扫描目标
    let targets = if let Some(t) = initial_targets {
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("  [1/5] 扫描目标");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!();
        println!("已指定目标: {}", t.join(", "));
        println!();
        t
    } else {
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("  [1/5] 扫描目标");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!();
        println!("输入格式示例:");
        println!("  单个IP:       192.168.1.1");
        println!("  IP范围:       192.168.1.1-192.168.1.100");
        println!("  CIDR网段:     192.168.1.0/24");
        println!("  多个目标:     192.168.1.1,192.168.1.2,192.168.1.0/24");
        println!();

        loop {
            let input = InteractiveMenu::read_input("请输入扫描目标: ");
            if !input.is_empty() {
                let targets: Vec<String> = input.split(',').map(|s| s.trim().to_string()).collect();
                println!();
                print_success(&format!("已设置: {}", targets.join(", ")));
                println!();
                break targets;
            }
            print_error("目标不能为空，请重新输入");
        }
    };

    // 步骤 2: 扫描类型
    let scan_type = if let Some(st) = initial_type {
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("  [2/5] 扫描类型");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!();
        println!("已指定: {}", format_scan_type(&st));
        println!();
        st
    } else {
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("  [2/5] 扫描类型");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!();
        println!("  1. 端口扫描       - 扫描指定主机的开放端口");
        println!("  2. 主机存活       - 检测网段内的存活主机");
        println!("  3. 综合扫描       - 主机发现 + 端口扫描");
        println!();

        let choice = InteractiveMenu::read_number("请选择扫描类型 [1-3]: ", 1, 3);
        let scan_type = match choice {
            1 => "port".to_string(),
            2 => "host".to_string(),
            3 => "comprehensive".to_string(),
            _ => "port".to_string(),
        };
        println!();
        print_success(&format!("已选择: {}", format_scan_type(&scan_type)));
        println!();
        scan_type
    };

    // 步骤 3: 扫描预设
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  [3/5] 扫描预设");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();
    println!("  1. Fast       - 快速扫描 (高并发，短超时，适合大范围)");
    println!("  2. Standard   - 标准扫描 (平衡速度和准确性)");
    println!("  3. Deep       - 深度扫描 (全端口扫描)");
    println!("  4. Stealth    - 隐蔽扫描 (低并发，有延迟)");
    println!();

    let preset_choice = InteractiveMenu::read_number("请选择扫描预设 [1-4, 默认2]: ", 1, 4);
    let config = match preset_choice {
        1 => {
            println!();
            print_success("已选择: Fast (快速扫描)");
            ScanPreset::Fast.to_config()
        }
        2 => {
            println!();
            print_success("已选择: Standard (标准扫描)");
            ScanPreset::Standard.to_config()
        }
        3 => {
            println!();
            print_success("已选择: Deep (深度扫描)");
            ScanPreset::Deep.to_config()
        }
        4 => {
            println!();
            print_success("已选择: Stealth (隐蔽扫描)");
            ScanPreset::Stealth.to_config()
        }
        _ => ScanPreset::Standard.to_config(),
    };
    println!();

    // 步骤 4: 服务探测
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  [4/5] 服务探测");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();
    println!("服务探测可以识别开放端口上运行的服务版本信息");
    println!("但会增加扫描时间");

    let enable_service = InteractiveMenu::read_input("是否启用服务探测? [y/N]: ");
    let mut config = config;
    config.service_detection = enable_service.to_lowercase() == "y";
    println!();
    if config.service_detection {
        print_success("已启用服务探测");
        println!();
        // 询问服务探测超时
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
    println!();

    // 步骤 5: 高级选项（可选）
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  [5/5] 高级选项");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();

    let configure_advanced = InteractiveMenu::read_input("是否配置高级选项? [y/N]: ");
    if configure_advanced.to_lowercase() == "y" {
        configure_advanced_options(&mut config);
    }
    println!();

    // 显示配置摘要
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  配置确认");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();
    println!("  扫描目标:     {}", targets.join(", "));
    println!("  扫描类型:     {}", format_scan_type(&scan_type));
    println!("  扫描预设:     {}", format_preset(&config));
    println!(
        "  服务探测:     {}",
        if config.service_detection {
            "启用"
        } else {
            "禁用"
        }
    );
    println!("  主机扫描方式: {}", config.host_scan_method.display_name());
    println!("  端口扫描方式: {}", config.port_scan_method.display_name());
    println!();

    let confirm = InteractiveMenu::read_input("确认开始扫描? [Y/n]: ");
    if confirm.to_lowercase() == "n" {
        print_info("已取消扫描");
        return Ok(());
    }

    println!();
    print_info("开始扫描...");
    println!();

    // 执行扫描
    match scan_type.as_str() {
        "host" => run_host_scan(targets, ScanPreset::Standard, None, output),
        "port" => run_port_scan_from_config(targets, config, output),
        "comprehensive" => run_comprehensive_scan_from_config(targets, config, output),
        _ => run_port_scan_from_config(targets, config, output),
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
            if method >= 1 && method <= 4 {
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
            if method >= 1 && method <= 3 {
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

/// 打印 Banner
fn print_banner() {
    println!();
    println!(".___        __                  _________                             ");
    println!("|   | _____/  |_____________   /   _____/_  _  __ ____   ____ ______  ");
    println!("|   |/    \\   __\\_  __ \\__  \\  \\_____  \\\\ \\/ \\/ // __ \\_/ __ \\\\____ \\ ");
    println!("|   |   |  \\  |  |  | \\// __ \\_/        \\\\     /\\  ___/\\  ___/|  |_> >");
    println!("|___|___|  /__|  |__|  (____  /_______  / \\/\\_/  \\___  >\\___  >   __/ ");
    println!("         \\/                 \\/        \\/             \\/     \\/|__|    ");
    println!();
    println!("                       IntraSweep - 内网渗透辅助工具 v0.3.0");
    println!();
}

/// 运行全量系统信息收集
fn run_system_collect_all(output: Option<PathBuf>, quiet: bool) -> Result<()> {
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

/// 运行基础系统信息收集
fn run_system_collect_basic(output: Option<PathBuf>, _quiet: bool) -> Result<()> {
    print_info("开始收集基础系统信息...");
    println!();

    use indicatif::{ProgressBar, ProgressStyle};
    use std::time::Duration;

    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner()
        .template("{spinner:.green} {msg}")
        .expect("创建进度条样式失败"));
    pb.set_message("正在收集系统信息...");
    pb.enable_steady_tick(Duration::from_millis(100));

    let mut collector = SystemCollector::new();
    let system = collector.collect_all();

    pb.finish_with_message("系统信息收集完成");
    println!();

    print_basic_system_info(&system);

    // 保存结果
    let output_path = output.unwrap_or_else(|| {
        let timestamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
        PathBuf::from(format!("intrasweep-system-basic-{}.json", timestamp))
    });

    let json = serde_json::to_string_pretty(&system)?;
    std::fs::write(&output_path, json)?;
    print_success(&format!("结果已保存到: {}", output_path.display()));

    Ok(())
}

/// 运行网络信息收集
fn run_system_collect_network(output: Option<PathBuf>, _quiet: bool) -> Result<()> {
    print_info("开始收集网络信息...");
    println!();

    use indicatif::{ProgressBar, ProgressStyle};
    use std::time::Duration;

    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner()
        .template("{spinner:.green} {msg}")
        .expect("创建进度条样式失败"));
    pb.enable_steady_tick(Duration::from_millis(100));

    let collector = NetworkCollector::new();
    let mut network = NetworkReport::default();

    pb.set_message("正在收集网络接口信息...");
    network.interfaces = collector.collect_interfaces();

    pb.set_message("正在收集路由信息...");
    network.routes = collector.collect_routes();

    pb.set_message("正在收集ARP表...");
    network.arp_table = collector.collect_arp_table();

    pb.set_message("正在收集网络连接...");
    network.connections = collector.collect_connections();

    pb.set_message("正在更新统计信息...");
    network.update_stats();

    pb.finish_with_message("网络信息收集完成");
    println!();

    print_network_info(&network);

    // 保存结果
    let output_path = output.unwrap_or_else(|| {
        let timestamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
        PathBuf::from(format!("intrasweep-system-network-{}.json", timestamp))
    });

    let json = serde_json::to_string_pretty(&network)?;
    std::fs::write(&output_path, json)?;
    print_success(&format!("结果已保存到: {}", output_path.display()));

    Ok(())
}

/// 运行进程信息收集
fn run_system_collect_process(output: Option<PathBuf>, _quiet: bool) -> Result<()> {
    print_info("开始收集进程信息...");
    println!();

    use indicatif::{ProgressBar, ProgressStyle};
    use std::time::Duration;

    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner()
        .template("{spinner:.green} {msg}")
        .expect("创建进度条样式失败"));
    pb.enable_steady_tick(Duration::from_millis(100));

    pb.set_message("正在枚举系统进程...");
    let mut collector = ProcessCollector::new();
    let all_processes = collector.list_processes();

    pb.set_message("正在分析进程详情...");
    let mut process = ProcessReport::default();
    process.total_count = all_processes.len();
    process.processes = all_processes.into_iter().take(100).collect();
    process.update_stats();

    pb.finish();
    println!("✓ 进程信息收集完成 - 共{}个进程", process.total_count);
    println!();

    print_process_info(&process);

    // 保存结果
    let output_path = output.unwrap_or_else(|| {
        let timestamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
        PathBuf::from(format!("intrasweep-system-process-{}.json", timestamp))
    });

    let json = serde_json::to_string_pretty(&process)?;
    std::fs::write(&output_path, json)?;
    print_success(&format!("结果已保存到: {}", output_path.display()));

    Ok(())
}

/// 运行凭据信息收集
fn run_system_collect_credential(output: Option<PathBuf>, _quiet: bool) -> Result<()> {
    print_info("开始收集凭据信息...");
    println!();

    use indicatif::{ProgressBar, ProgressStyle};
    use std::time::Duration;

    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner()
        .template("{spinner:.green} {msg}")
        .expect("创建进度条样式失败"));
    pb.enable_steady_tick(Duration::from_millis(100));

    let collector = CredentialCollector::new();
    let mut credential = CredentialReport::default();

    pb.set_message("正在搜索密码哈希...");
    credential.password_hashes = collector.collect_password_hashes();

    pb.set_message("正在搜索令牌...");
    credential.tokens = collector.collect_tokens();

    pb.set_message("正在搜索SSH密钥...");
    credential.ssh_keys = collector.collect_ssh_keys();

    pb.set_message("正在搜索API密钥...");
    credential.api_keys = collector.collect_api_keys();

    pb.set_message("正在更新统计信息...");
    credential.update_stats();

    pb.finish_with_message("凭据信息收集完成");
    println!();

    print_credential_info(&credential);

    // 保存结果
    let output_path = output.unwrap_or_else(|| {
        let timestamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
        PathBuf::from(format!("intrasweep-system-credential-{}.json", timestamp))
    });

    let json = serde_json::to_string_pretty(&credential)?;
    std::fs::write(&output_path, json)?;
    print_success(&format!("结果已保存到: {}", output_path.display()));

    Ok(())
}

/// 运行文件信息收集
fn run_system_collect_file(output: Option<PathBuf>, _quiet: bool) -> Result<()> {
    print_info("开始收集文件信息...");
    println!();

    use indicatif::{ProgressBar, ProgressStyle};
    use std::time::Duration;

    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner()
        .template("{spinner:.green} {msg}")
        .expect("创建进度条样式失败"));
    pb.enable_steady_tick(Duration::from_millis(100));

    let collector = FileCollector::new();
    let search_paths = get_default_search_paths();

    pb.set_message("正在搜索敏感文件...");
    let mut file = FileReport::default();
    file.sensitive_files = collector.find_sensitive_files(&search_paths);

    pb.set_message("正在搜索配置文件...");
    file.config_files = collector.find_config_files(&search_paths);

    pb.set_message("正在查找最近修改的文件...");
    let recent_paths = get_recent_file_paths();
    let recent_files = collector.find_recent_files(&recent_paths, 7);
    file.recent_files = convert_to_recent_files(recent_files);

    pb.set_message("正在更新统计信息...");
    file.update_stats();

    pb.finish_with_message("文件信息收集完成");
    println!();

    print_file_info(&file);

    // 保存结果
    let output_path = output.unwrap_or_else(|| {
        let timestamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
        PathBuf::from(format!("intrasweep-system-file-{}.json", timestamp))
    });

    let json = serde_json::to_string_pretty(&file)?;
    std::fs::write(&output_path, json)?;
    print_success(&format!("结果已保存到: {}", output_path.display()));

    Ok(())
}

/// 获取默认搜索路径
fn get_default_search_paths() -> Vec<String> {
    let mut paths = Vec::new();

    if cfg!(windows) {
        if let Ok(home) = std::env::var("USERPROFILE") {
            paths.push(format!("{}\\", home));
            paths.push(format!("{}\\.ssh", home));
            paths.push(format!("{}\\.aws", home));
            paths.push("C:\\ProgramData\\".to_string());
        }
    } else {
        paths.push("/home/".to_string());
        paths.push("/root/".to_string());
        paths.push("/etc/".to_string());
        paths.push("/var/".to_string());
        paths.push("/tmp/".to_string());
    }

    paths
}

/// 获取最近文件搜索路径
fn get_recent_file_paths() -> Vec<String> {
    let mut paths = Vec::new();

    if cfg!(windows) {
        if let Ok(home) = std::env::var("USERPROFILE") {
            paths.push(format!("{}\\Desktop", home));
            paths.push(format!("{}\\Documents", home));
            paths.push(format!("{}\\Downloads", home));
        }
        paths.push("C:\\".to_string());
    } else {
        paths.push("/home/".to_string());
        paths.push("/root/".to_string());
        paths.push("/tmp/".to_string());
        paths.push("/var/".to_string());
    }

    paths
}

/// 转换最近文件
fn convert_to_recent_files(paths: Vec<PathBuf>) -> Vec<collector::models::RecentFile> {
    use collector::models::RecentFile;

    paths
        .into_iter()
        .filter_map(|p| {
            let metadata = std::fs::metadata(&p).ok()?;
            let modified = metadata.modified().ok()?;
            let name = p.file_name()?.to_string_lossy().to_string();

            Some(RecentFile {
                path: p.to_string_lossy().to_string(),
                name,
                size: metadata.len(),
                modified: chrono::DateTime::<chrono::Utc>::from(modified).to_rfc3339(),
                is_sensitive: false,
            })
        })
        .collect()
}

/// 打印基础系统信息
fn print_basic_system_info(system: &SystemInfo) {
    println!("╔════════════════════════════════════════════════════════════════════════════╗");
    println!(
        "║  {}",
        colorize("基础系统信息收集完成", Color::BrightGreen)
    );
    println!("╠════════════════════════════════════════════════════════════════════════════╣");
    println!("║  系统信息");
    println!("╠────────────────────────────────────────────────────────────────────────────╣");
    println!(
        "║  操作系统:   {:<60}║",
        format!("{} {}", system.os_info.os_type, system.os_info.os_version)
    );
    println!("║  主机名:     {:<60}║", system.hostname);
    println!("║  架构:       {:<60}║", system.os_info.arch);
    println!("╠════════════════════════════════════════════════════════════════════════════╣");
    println!("║  用户信息");
    println!("╠────────────────────────────────────────────────────────────────────────────╣");
    println!("║  当前用户:   {:<60}║", system.current_user.username);
    println!(
        "║  权限级别:   {:<60}║",
        format!("{:?}", system.current_user.privileges)
    );
    println!("╠════════════════════════════════════════════════════════════════════════════╣");
    println!("║  硬件资源");
    println!("╠────────────────────────────────────────────────────────────────────────────╣");
    println!("║  CPU核心数:  {:<60}║", system.cpu_info.cpu_count);
    println!(
        "║  总内存:     {:<60}║",
        format!(
            "{:.2} GB",
            system.memory_info.total_memory as f64 / 1024.0 / 1024.0 / 1024.0
        )
    );
    println!(
        "║  内存使用:   {:<60}║",
        format!(
            "{:.2} GB ({:.1}%)",
            system.memory_info.used_memory as f64 / 1024.0 / 1024.0 / 1024.0,
            system.memory_info.usage_percent
        )
    );
    println!("╚════════════════════════════════════════════════════════════════════════════╝");
    println!();
}

/// 打印网络信息
fn print_network_info(network: &NetworkReport) {
    println!("╔════════════════════════════════════════════════════════════════════════════╗");
    println!("║  {}", colorize("网络信息收集完成", Color::BrightGreen));
    println!("╠════════════════════════════════════════════════════════════════════════════╣");
    println!("║  网络统计");
    println!("╠────────────────────────────────────────────────────────────────────────────╣");
    println!("║  网络接口:   {:<60}║", network.stats.interface_count);
    println!("║  路由条目:   {:<60}║", network.stats.route_count);
    println!("║  ARP条目:    {:<60}║", network.stats.arp_count);
    println!("║  活动连接:   {:<60}║", network.stats.connection_count);
    println!("╠════════════════════════════════════════════════════════════════════════════╣");
    println!("║  网络接口 (前5个)");
    println!("╠────────────────────────────────────────────────────────────────────────────╣");
    for iface in network.interfaces.iter().take(5) {
        println!("║  {:<60}║", format!("{}: {}", iface.name, iface.ip));
    }
    println!("╚════════════════════════════════════════════════════════════════════════════╝");
    println!();
}

/// 打印进程信息
fn print_process_info(process: &ProcessReport) {
    println!("╔════════════════════════════════════════════════════════════════════════════╗");
    println!("║  {}", colorize("进程信息收集完成", Color::BrightGreen));
    println!("╠════════════════════════════════════════════════════════════════════════════╣");
    println!("║  进程统计");
    println!("╠────────────────────────────────────────────────────────────────────────────╣");
    println!("║  进程总数:   {:<60}║", process.total_count);
    println!("║  可疑进程:   {:<60}║", process.suspicious.len());
    println!("╠════════════════════════════════════════════════════════════════════════════╣");
    println!("║  进程列表 (前10个)");
    println!("╠────────────────────────────────────────────────────────────────────────────╣");
    for proc in process.processes.iter().take(10) {
        println!(
            "║  {:<30} PID:{:<10} CPU:{:>6.1}% MEM:{:<12}║",
            proc.name,
            proc.pid,
            proc.cpu_usage,
            format_bytes(proc.memory_usage)
        );
    }
    println!("╚════════════════════════════════════════════════════════════════════════════╝");
    println!();
}

/// 打印凭据信息
fn print_credential_info(credential: &CredentialReport) {
    println!("╔════════════════════════════════════════════════════════════════════════════╗");
    println!("║  {}", colorize("凭据信息收集完成", Color::BrightGreen));
    println!("╠════════════════════════════════════════════════════════════════════════════╣");
    println!("║  凭据统计");
    println!("╠────────────────────────────────────────────────────────────────────────────╣");
    println!("║  密码哈希:   {:<60}║", credential.stats.hash_count);
    println!("║  SSH密钥:    {:<60}║", credential.stats.ssh_key_count);
    println!("║  API密钥:    {:<60}║", credential.stats.api_key_count);
    println!("║  Token总数:  {:<60}║", credential.stats.token_count);
    println!("╚════════════════════════════════════════════════════════════════════════════╝");
    println!();
}

/// 打印文件信息
fn print_file_info(file: &FileReport) {
    println!("╔════════════════════════════════════════════════════════════════════════════╗");
    println!("║  {}", colorize("文件信息收集完成", Color::BrightGreen));
    println!("╠════════════════════════════════════════════════════════════════════════════╣");
    println!("║  文件统计");
    println!("╠────────────────────────────────────────────────────────────────────────────╣");
    println!("║  敏感文件:   {:<60}║", file.stats.sensitive_count);
    println!("║  配置文件:   {:<60}║", file.stats.config_count);
    println!("║  最近文件:   {:<60}║", file.stats.recent_count);
    println!("╠════════════════════════════════════════════════════════════════════════════╣");
    println!("║  敏感文件 (前5个)");
    println!("╠────────────────────────────────────────────────────────────────────────────╣");
    for file in file.sensitive_files.iter().take(5) {
        println!("║  {:<60}║", file.path);
    }
    println!("╚════════════════════════════════════════════════════════════════════════════╝");
    println!();
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
    print_info(&format!("开始主机存活扫描"));
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

    use indicatif::{ProgressBar, ProgressStyle};
    use std::time::Duration;

    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner()
        .template("{spinner:.green} {msg}")
        .expect("创建进度条样式失败"));
    pb.enable_steady_tick(Duration::from_millis(100));

    pb.set_message("正在检测域环境...");

    let mut scanner = Scanner::default();
    let result = scanner.domain_scan();

    pb.finish_with_message("域环境扫描完成");
    println!();

    print_domain_scan_results(&result);

    if let Ok(path) = scanner.save_result(&convert_domain_result_to_scan(result), output) {
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

/// 简化的端口扫描（使用默认配置）
fn run_port_scan_simple(
    targets: Vec<String>,
    preset: ScanPreset,
    output: Option<PathBuf>,
) -> Result<()> {
    let config = preset_to_config(preset);

    println!();
    print_info(&format!("开始端口扫描"));
    print_info(&format!("目标: {}", targets.join(", ")));
    print_info(&format!("预设: {:?}", preset));
    println!();

    // 创建进度条
    let progress = Arc::new(ScanProgress::new(100, true));
    let progress_clone = progress.clone();

    let rt = tokio::runtime::Runtime::new()?;
    let scanner = Scanner::new(config).with_progress_callback(Arc::new(move |current, total| {
        let percent = (current as f64 / total as f64 * 100.0) as u64;
        progress_clone.set_position(percent as usize);
    }));
    let result = rt.block_on(scanner.port_scan(targets));

    progress.finish_with_message("扫描完成!");
    println!();

    print_scan_results(&result);

    if let Ok(path) = scanner.save_result(&result, output) {
        println!();
        print_success(&format!("结果已保存到: {}", path.display()));
    }

    Ok(())
}

/// 简化的综合扫描（使用默认配置）
fn run_comprehensive_scan_simple(
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

    // 创建进度条
    let progress = Arc::new(ScanProgress::new(100, true));
    let progress_clone = progress.clone();

    let rt = tokio::runtime::Runtime::new()?;
    let scanner = Scanner::new(config).with_progress_callback(Arc::new(move |current, total| {
        let percent = (current as f64 / total as f64 * 100.0) as u64;
        progress_clone.set_position(percent as usize);
    }));
    let result = rt.block_on(scanner.comprehensive_scan(targets));

    progress.finish_with_message("扫描完成!");
    println!();

    print_scan_results(&result);

    if let Ok(path) = scanner.save_result(&result, output) {
        println!();
        print_success(&format!("结果已保存到: {}", path.display()));
    }

    Ok(())
}

/// 使用配置进行端口扫描（交互式模式）
fn run_port_scan_from_config(
    targets: Vec<String>,
    config: ScanConfig,
    output: Option<PathBuf>,
) -> Result<()> {
    println!();
    print_info(&format!("开始端口扫描"));
    print_info(&format!("目标: {}", targets.join(", ")));
    print_info(&format!("预设: {}", format_preset(&config)));
    print_info(&format!(
        "扫描方式: {}",
        config.port_scan_method.display_name()
    ));
    if config.service_detection {
        print_success("服务探测: 启用");
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
    let result = rt.block_on(scanner.port_scan(targets));

    progress.finish_with_message("扫描完成!");
    println!();

    print_scan_results(&result);

    if let Ok(path) = scanner.save_result(&result, output) {
        println!();
        print_success(&format!("结果已保存到: {}", path.display()));
    }

    Ok(())
}

/// 使用配置进行综合扫描（交互式模式）
fn run_comprehensive_scan_from_config(
    targets: Vec<String>,
    config: ScanConfig,
    output: Option<PathBuf>,
) -> Result<()> {
    println!();
    print_info(&format!("开始综合扫描"));
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
    println!();

    // 创建进度条
    let progress = Arc::new(ScanProgress::new(100, true));
    let progress_clone = progress.clone();

    let rt = tokio::runtime::Runtime::new()?;
    let scanner = Scanner::new(config).with_progress_callback(Arc::new(move |current, total| {
        let percent = (current as f64 / total as f64 * 100.0) as u64;
        progress_clone.set_position(percent as usize);
    }));
    let result = rt.block_on(scanner.comprehensive_scan(targets));

    progress.finish_with_message("扫描完成!");
    println!();

    print_scan_results(&result);

    if let Ok(path) = scanner.save_result(&result, output) {
        println!();
        print_success(&format!("结果已保存到: {}", path.display()));
    }

    Ok(())
}

/// 运行交互式爆破向导
fn run_interactive_crack(
    initial_port: Option<u16>,
    initial_service: Option<String>,
    _initial_usernames: Option<String>,
    initial_password_file: Option<String>,
    _initial_username_file: Option<String>,
    initial_concurrency: usize,
    initial_timeout: u64,
    initial_delay: Option<u64>,
) -> Result<()> {
    print_banner();
    println!();
    print_info("IntraSweep 交互式爆破配置向导");
    println!();

    // 步骤 1: 目标主机
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  [1/7] 目标主机");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();
    println!("输入格式示例:");
    println!("  IP地址:       192.168.1.1");
    println!("  域名:         example.com");
    println!();

    let target = loop {
        let input = InteractiveMenu::read_input("请输入目标主机: ");
        if !input.is_empty() {
            break input;
        }
        print_error("目标不能为空，请重新输入");
    };
    println!();
    print_success(&format!("已设置目标: {}", target));
    println!();

    // 步骤 2: 服务类型
    let service = if let Some(s) = &initial_service {
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("  [2/7] 服务类型");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!();
        println!("已指定: {}", s);
        println!();
        s.clone()
    } else {
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("  [2/7] 服务类型");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!();
        println!("  1. SSH       - SSH 爆破 (默认端口: 22)");
        println!("  2. RDP       - RDP 爆破 (默认端口: 3389)");
        println!("  3. Redis     - Redis 爆破 (默认端口: 6379)");
        println!("  4. Postgres  - PostgreSQL 爆破 (默认端口: 5432)");
        println!("  5. MongoDB   - MongoDB 爆破 (默认端口: 27017)");
        println!("  6. MSSQL     - MSSQL 爆破 (默认端口: 1433)");
        println!("  7. MySQL     - MySQL 爆破 (默认端口: 3306)");
        println!("  8. WinRM     - WinRM 爆破 (默认端口: 5985)");
        println!();

        let choice = InteractiveMenu::read_number("请选择服务类型 [1-8]: ", 1, 8);
        let service = match choice {
            1 => "ssh".to_string(),
            2 => "rdp".to_string(),
            3 => "redis".to_string(),
            4 => "postgres".to_string(),
            5 => "mongodb".to_string(),
            6 => "mssql".to_string(),
            7 => "mysql".to_string(),
            8 => "winrm".to_string(),
            _ => "ssh".to_string(),
        };
        println!();
        print_success(&format!("已选择: {}", service.to_uppercase()));
        println!();
        service
    };

    // 解析服务类型
    let service_type = match service.to_lowercase().as_str() {
        "ssh" => CrackService::Ssh,
        "rdp" => CrackService::Rdp,
        "redis" => CrackService::Redis,
        "postgres" | "postgresql" => CrackService::Postgres,
        "mongodb" | "mongo" => CrackService::Mongodb,
        "mssql" => CrackService::Mssql,
        "mysql" => CrackService::Mysql,
        "winrm" => CrackService::Winrm,
        _ => CrackService::Ssh,
    };

    // 步骤 3: 端口
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  [3/7] 端口");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();

    let default_port = service_type.default_port();
    println!("默认端口: {}", default_port);
    println!();

    let port = if let Some(p) = initial_port {
        println!("已指定端口: {}", p);
        println!();
        p
    } else {
        let port_input =
            InteractiveMenu::read_input(&format!("按 Enter 使用默认端口或输入自定义端口: "));
        println!();
        if port_input.is_empty() {
            print_success(&format!("使用默认端口: {}", default_port));
            println!();
            default_port
        } else {
            let p = port_input.parse::<u16>().unwrap_or(default_port);
            print_success(&format!("已设置端口: {}", p));
            println!();
            p
        }
    };

    // 步骤 4: 用户名配置
    let usernames = if service_type.requires_username() {
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("  [4/7] 用户名配置");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!();
        println!("  1. 手动输入用户名 (逗号分隔)");
        println!("  2. 从文件加载用户名字典");
        println!("  3. 使用默认用户名列表");
        println!();

        let choice = InteractiveMenu::read_number("请选择 [1-3]: ", 1, 3);
        println!();

        match choice {
            1 => {
                let input = InteractiveMenu::read_input("请输入用户名 (多个用逗号分隔): ");
                println!();
                print_success("已设置用户名");
                println!();
                Some(input)
            }
            2 => {
                loop {
                    let file = InteractiveMenu::read_input("请输入用户名字典文件路径: ");
                    println!();

                    // 验证字典文件
                    match DictManager::validate_dict_file(&file) {
                        Ok(count) => {
                            print_success(&format!("✓ 字典文件验证通过 (包含 {} 个用户名)", count));
                            println!();
                            break Some(format!("@{}", file));
                        }
                        Err(e) => {
                            print_error(&format!("✗ 字典文件验证失败: {}", e));
                            println!();
                            let retry = InteractiveMenu::read_input("是否重新输入? [Y/n]: ");
                            if retry.to_lowercase() == "n" {
                                println!();
                                print_info("将使用默认用户名列表");
                                println!();
                                break None;
                            }
                            println!();
                        }
                    }
                }
            }
            3 => {
                println!();
                print_info("将使用默认用户名列表");
                println!();
                None
            }
            _ => None,
        }
    } else {
        None
    };

    // 步骤 5: 密码字典
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  [5/7] 密码字典");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();

    let password_file = if initial_password_file.is_some() {
        println!("已指定密码字典文件");
        println!();
        initial_password_file
    } else {
        println!("  1. 从文件加载密码字典");
        println!("  2. 使用默认密码字典");
        println!();

        let choice = InteractiveMenu::read_number("请选择 [1-2]: ", 1, 2);
        println!();

        match choice {
            1 => {
                loop {
                    let file = InteractiveMenu::read_input("请输入密码字典文件路径: ");
                    println!();

                    // 验证字典文件
                    match DictManager::validate_dict_file(&file) {
                        Ok(count) => {
                            print_success(&format!("✓ 字典文件验证通过 (包含 {} 个密码)", count));
                            println!();
                            break Some(file);
                        }
                        Err(e) => {
                            print_error(&format!("✗ 字典文件验证失败: {}", e));
                            println!();
                            let retry = InteractiveMenu::read_input("是否重新输入? [Y/n]: ");
                            if retry.to_lowercase() == "n" {
                                println!();
                                print_info("将使用默认密码字典");
                                println!();
                                break None;
                            }
                            println!();
                        }
                    }
                }
            }
            2 => {
                println!();
                print_info("将使用默认密码字典");
                println!();
                None
            }
            _ => None,
        }
    };

    // 步骤 6: 性能配置
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  [6/7] 性能配置");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();

    let concurrency = if initial_concurrency == 10 {
        let input = InteractiveMenu::read_input(&format!("并发数 (默认: 10): "));
        println!();
        if input.is_empty() {
            10
        } else {
            let c = input.parse::<usize>().unwrap_or(10);
            print_success(&format!("已设置并发数: {}", c));
            println!();
            c
        }
    } else {
        println!("已指定并发数: {}", initial_concurrency);
        println!();
        initial_concurrency
    };

    let timeout = if initial_timeout == 5 {
        let input = InteractiveMenu::read_input(&format!("超时时间/秒 (默认: 5): "));
        println!();
        if input.is_empty() {
            5
        } else {
            let t = input.parse::<u64>().unwrap_or(5);
            print_success(&format!("已设置超时: {} 秒", t));
            println!();
            t
        }
    } else {
        println!("已指定超时: {} 秒", initial_timeout);
        println!();
        initial_timeout
    };

    // 步骤 7: 高级选项
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  [7/7] 高级选项");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();

    let delay = if initial_delay.is_some() {
        println!("已指定延迟");
        println!();
        initial_delay
    } else {
        let input = InteractiveMenu::read_input("设置延迟/毫秒，可选 (按 Enter 跳过): ");
        println!();
        if input.is_empty() {
            print_info("未设置延迟");
            println!();
            None
        } else {
            let d = input.parse::<u64>().ok();
            if let Some(delay_val) = d {
                print_success(&format!("已设置延迟: {} 毫秒", delay_val));
            } else {
                print_info("输入无效，未设置延迟");
            }
            println!();
            d
        }
    };

    // 调用 run_crack 执行爆破
    run_crack(
        target,
        Some(port),
        Some(service),
        usernames,
        password_file,
        None, // username_file 从 usernames 参数解析
        concurrency,
        timeout,
        delay,
    )
}

/// 运行爆破
fn run_crack(
    target: String,
    port: Option<u16>,
    service: Option<String>,
    usernames: Option<String>,
    password_file: Option<String>,
    username_file: Option<String>,
    concurrency: usize,
    timeout: u64,
    delay: Option<u64>,
) -> Result<()> {
    use std::time::Duration;

    // 显示 Banner
    print_banner();
    println!();

    // 解析服务类型
    let service_type = if let Some(s) = service {
        match s.to_lowercase().as_str() {
            "ssh" => CrackService::Ssh,
            "rdp" => CrackService::Rdp,
            "redis" => CrackService::Redis,
            "postgres" | "postgresql" => CrackService::Postgres,
            "mongodb" | "mongo" => CrackService::Mongodb,
            "mssql" => CrackService::Mssql,
            "mysql" => CrackService::Mysql,
            "winrm" => CrackService::Winrm,
            _ => {
                print_error(&format!("不支持的服务类型: {}", s));
                println!("支持的服务: ssh, rdp, redis, postgres, mongodb, mssql, mysql, winrm");
                return Ok(());
            }
        }
    } else {
        // 如果没有指定服务，交互式选择
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("  选择服务类型");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!();
        println!("  1. SSH       - SSH 爆破 (22)");
        println!("  2. RDP       - RDP 爆破 (3389)");
        println!("  3. Redis     - Redis 爆破 (6379)");
        println!("  4. Postgres  - PostgreSQL 爆破 (5432)");
        println!("  5. MongoDB   - MongoDB 爆破 (27017)");
        println!("  6. MSSQL     - MSSQL 爆破 (1433)");
        println!("  7. MySQL     - MySQL 爆破 (3306)");
        println!("  8. WinRM     - WinRM 爆破 (5985)");
        println!();

        let choice = InteractiveMenu::read_number("请选择服务类型 [1-8]: ", 1, 8);
        match choice {
            1 => CrackService::Ssh,
            2 => CrackService::Rdp,
            3 => CrackService::Redis,
            4 => CrackService::Postgres,
            5 => CrackService::Mongodb,
            6 => CrackService::Mssql,
            7 => CrackService::Mysql,
            8 => CrackService::Winrm,
            _ => CrackService::Ssh,
        }
    };

    // 创建配置
    let mut config = CrackConfig::new(target.clone(), service_type);

    // 设置端口
    if let Some(p) = port {
        config = config.with_port(p);
    }

    // 初始化字典管理器
    let mut dict_manager = DictManager::new();

    // 加载用户名
    if service_type.requires_username() {
        if let Some(username_file) = username_file {
            match dict_manager.load_usernames_from_file(&username_file) {
                Ok(count) => {
                    println!();
                    print_success(&format!("已加载 {} 个用户名", count));
                }
                Err(e) => {
                    print_error(&format!("加载用户名字典失败: {}", e));
                    return Err(FlyWheelError::Other {
                        message: "加载用户名字典失败".to_string(),
                    });
                }
            }
        } else if let Some(usernames_str) = usernames {
            let username_list: Vec<String> = usernames_str
                .split(',')
                .map(|s| s.trim().to_string())
                .collect();
            dict_manager.set_usernames(username_list);
            println!();
            print_success(&format!(
                "已设置 {} 个用户名",
                dict_manager.username_count()
            ));
        }
    }

    // 加载密码
    if let Some(pwd_file) = password_file {
        match dict_manager.load_passwords_from_file(&pwd_file) {
            Ok(count) => {
                print_success(&format!("已加载 {} 个密码", count));
            }
            Err(e) => {
                print_error(&format!("加载密码字典失败: {}", e));
                return Err(FlyWheelError::Other {
                    message: "加载密码字典失败".to_string(),
                });
            }
        }
    } else {
        println!();
        print_info(&format!(
            "使用默认密码字典 ({} 个密码)",
            dict_manager.password_count()
        ));
    }

    // 设置用户名和密码
    config = config.with_usernames(dict_manager.usernames().to_vec());
    config = config.with_passwords(dict_manager.passwords().to_vec());
    config = config.with_concurrency(concurrency);
    config = config.with_timeout(Duration::from_secs(timeout));
    if let Some(d) = delay {
        config = config.with_delay(d);
    }

    // 显示配置摘要
    println!();
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  配置摘要");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();
    println!("  目标:         {}:{}", config.target, config.port);
    println!("  服务:         {}", service_type.name());
    if service_type.requires_username() {
        println!("  用户名数:     {}", config.usernames.len());
    }
    println!("  密码数:       {}", config.passwords.len());
    if service_type.requires_username() {
        println!(
            "  总尝试次数:   {}",
            config.usernames.len() * config.passwords.len()
        );
    } else {
        println!("  总尝试次数:   {}", config.passwords.len());
    }
    println!("  并发数:       {}", config.concurrency);
    println!("  超时:         {} 秒", timeout);
    if let Some(d) = config.delay_ms {
        println!("  延迟:         {} 毫秒", d);
    }
    println!();

    // 确认
    let confirm = InteractiveMenu::read_input("确认开始爆破? [Y/n]: ");
    if confirm.to_lowercase() == "n" {
        print_info("已取消爆破");
        return Ok(());
    }

    println!();

    // 执行爆破
    let rt = tokio::runtime::Runtime::new()?;

    // 创建进度条
    use indicatif::{ProgressBar, ProgressStyle};
    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner()
        .template("{spinner:.green} {msg}")
        .expect("创建进度条样式失败"));
    pb.set_message("正在爆破...");
    pb.enable_steady_tick(std::time::Duration::from_millis(100));

    // 根据服务类型选择爆破器
    let result = rt.block_on(async {
        match service_type {
            CrackService::Ssh => {
                let cracker = cracker::ssh::SshCracker::new();
                cracker.crack(&config).await
            }
            CrackService::Rdp => {
                let cracker = cracker::rdp::RdpCracker::new();
                cracker.crack(&config).await
            }
            CrackService::Redis => {
                let cracker = cracker::redis_crack::RedisCracker::new();
                cracker.crack(&config).await
            }
            CrackService::Postgres => {
                let cracker = cracker::postgres::PostgresCracker::new();
                cracker.crack(&config).await
            }
            CrackService::Mysql => {
                let cracker = cracker::mysql::MysqlCracker::new();
                cracker.crack(&config).await
            }
            CrackService::Mssql => {
                let cracker = cracker::mssql::MssqlCracker::new();
                cracker.crack(&config).await
            }
            CrackService::Mongodb => {
                let cracker = cracker::mongodb_crack::MongodbCracker::new();
                cracker.crack(&config).await
            }
            CrackService::Winrm => {
                let cracker = cracker::winrm::WinrmCracker::new();
                cracker.crack(&config).await
            }
        }
    });

    pb.finish_with_message("爆破完成");
    println!();

    // 显示结果
    if result.is_success() {
        println!("╔════════════════════════════════════════════════════════════════════════════╗");
        println!("║  {}", colorize("爆破成功!", Color::BrightGreen));
        println!("╠════════════════════════════════════════════════════════════════════════════╣");
        println!("║  目标:        {}:{}", result.target, result.port);
        println!("║  服务:        {}", result.service);
        if let Some(username) = &result.username {
            println!("║  用户名:      {}", username);
        }
        if let Some(password) = &result.password {
            println!("║  密码:        {}", password);
        }
        println!("║  耗时:        {} ms", result.elapsed_ms);
        println!("╚════════════════════════════════════════════════════════════════════════════╝");
    } else {
        println!("╔════════════════════════════════════════════════════════════════════════════╗");
        println!("║  {}", colorize("爆破失败", Color::BrightRed));
        println!("╠════════════════════════════════════════════════════════════════════════════╣");
        println!("║  目标:        {}:{}", result.target, result.port);
        println!("║  服务:        {}", result.service);
        println!("║  消息:        {}", result.message);
        println!("╚════════════════════════════════════════════════════════════════════════════╝");
    }
    println!();

    Ok(())
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
