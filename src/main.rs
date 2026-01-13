//! Fly-Wheel - 内网渗透辅助工具
//!
//! 用于授权渗透测试和可控靶场环境的网络扫描工具

mod core;
mod modules;
mod output;

use clap::{Parser, Subcommand};
use core::config::{ConfigWizard, ScanConfig};
use core::error::Result;
use modules::host;
use modules::identify::FingerprintMatcher;
use modules::info;
use modules::persist;
use modules::scan;
use modules::collect;
use output::color::{print_error, print_info, print_success, print_warning};
use output::table::{PortRow, ResultTable};
use std::process;

/// Fly-Wheel 内网渗透辅助工具
#[derive(Parser)]
#[command(
    name = "fly-wheel",
    author = "BlkSword",
    version = "0.2.0",
    about = "高性能内网扫描工具",
    long_about = "Fly-Wheel 是一个基于 Rust 开发的内网渗透辅助工具，专注于提供高速的网络扫描功能。"
)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// 是否使用彩色输出
    #[arg(short, long, global = true, action = clap::ArgAction::SetTrue)]
    color: bool,

    /// 详细输出模式
    #[arg(short, long, global = true, action = clap::ArgAction::SetTrue)]
    verbose: bool,

    /// 配置文件路径
    #[arg(short, long, global = true)]
    config: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// 主机存活检测
    Host {
        /// 目标网络 (例如: 192.168.1.0/24)
        #[arg(short, long)]
        target: String,
        /// 扫描类型 (icmp, tcp)
        #[arg(short = 's', long = "scan-type", default_value = "icmp")]
        scan_type: String,
    },

    /// 端口扫描
    Scan {
        /// 目标主机 (例如: 192.168.1.1)
        #[arg(short, long)]
        target: String,
        /// 端口范围 (例如: 1-1000, 22,80,443)
        #[arg(short, long)]
        ports: Option<String>,
        /// 启用服务识别
        #[arg(long, action = clap::ArgAction::SetTrue)]
        identify: bool,
    },

    /// 信息收集
    Info {
        /// 目标主机或域名
        #[arg(short, long)]
        target: String,
    },

    /// 持久化设置
    Persist {
        /// 目标主机
        #[arg(short, long)]
        target: String,
    },

    /// 配置管理
    Config {
        #[command(subcommand)]
        config_cmd: ConfigCommands,
    },

    /// 主机信息收集
    Collect {
        #[command(subcommand)]
        collect_cmd: CollectCommands,
    },

    /// 网络发现（已弃用，使用 host 命令）
    Discover {
        /// 目标网络
        #[arg(short, long)]
        target: String,
    },
}

#[derive(Subcommand)]
enum ConfigCommands {
    /// 运行配置向导
    Wizard,
    /// 显示当前配置
    Show,
    /// 重置为默认配置
    Reset,
}

#[derive(Subcommand)]
enum CollectCommands {
    /// 收集所有系统信息
    All,
    /// 收集系统信息（OS、主机、用户等）
    System,
    /// 收集网络配置（接口、路由、ARP等）
    Network,
    /// 收集进程信息
    Process {
        /// 可选：按名称过滤进程
        #[arg(short, long)]
        name: Option<String>,
    },
    /// 收集凭据（密码哈希、令牌、密钥）
    Credential,
    /// 搜索敏感文件
    File {
        /// 搜索路径（多个路径用逗号分隔）
        #[arg(short, long, default_value = ".")]
        paths: String,
        /// 搜索类型：sensitive, config, keyword, recent
        #[arg(short, long, default_value = "sensitive")]
        search_type: String,
        /// 关键词（仅用于 keyword 搜索类型）
        #[arg(short, long)]
        keywords: Option<String>,
        /// 最近天数（仅用于 recent 搜索类型）
        #[arg(short, long, default_value = "7")]
        days: u64,
    },
}

fn main() {
    // 解析命令行参数
    let cli = Cli::parse();

    // 初始化日志系统
    init_logging(cli.verbose);

    // 加载配置
    let config = load_or_create_config();

    // 执行命令
    if let Err(e) = run(&cli, &config) {
        print_error(&format!("{}", e));
        process::exit(1);
    }
}

/// 初始化日志系统
fn init_logging(verbose: bool) {
    if verbose {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .init();
    }
}

/// 加载或创建配置
fn load_or_create_config() -> ScanConfig {
    match ScanConfig::load() {
        Ok(config) => config,
        Err(_) => {
            print_warning("无法加载配置文件，使用默认配置");
            ScanConfig::default()
        }
    }
}

/// 运行命令
fn run(cli: &Cli, config: &ScanConfig) -> Result<()> {
    match &cli.command {
        Commands::Host { target, scan_type } => {
            run_host_discovery(target, scan_type, config)?;
        }

        Commands::Scan {
            target,
            ports,
            identify,
        } => {
            run_port_scan(target, ports.as_deref(), *identify, config)?;
        }

        Commands::Info { target } => {
            run_info_gathering(target, config)?;
        }

        Commands::Persist { target } => {
            run_persistence(target, config)?;
        }

        Commands::Config { config_cmd } => {
            run_config_command(config_cmd)?;
        }

        Commands::Collect { collect_cmd } => {
            run_collect_command(collect_cmd)?;
        }

        Commands::Discover { target } => {
            print_warning("discover 命令已弃用，请使用 host 命令");
            run_host_discovery(target, "icmp", config)?;
        }
    }

    Ok(())
}

/// 主机发现
fn run_host_discovery(target: &str, scan_type: &str, config: &ScanConfig) -> Result<()> {
    print_info(&format!("正在进行主机发现: {} (使用 {} 扫描)", target, scan_type));

    let result = host::discover_hosts(target, scan_type);
    println!("{}", result);

    Ok(())
}

/// 端口扫描
fn run_port_scan(
    target: &str,
    ports: Option<&str>,
    identify: bool,
    config: &ScanConfig,
) -> Result<()> {
    print_info(&format!("正在进行端口扫描: {}", target));

    if identify {
        print_info("已启用服务识别");
    }

    let result = scan::run(target, ports);
    println!("{}", result);

    // 如果启用了服务识别，识别开放端口的服务
    if identify {
        identify_services(target, ports, config)?;
    }

    Ok(())
}

/// 服务识别
fn identify_services(target: &str, ports: Option<&str>, config: &ScanConfig) -> Result<()> {
    print_info("正在识别服务...");

    // 解析端口列表
    let ports_to_scan = if let Some(port_str) = ports {
        parse_ports(port_str)?
    } else {
        // 默认扫描常见端口
        (1..=1000).collect()
    };

    let mut matcher = FingerprintMatcher::new();
    let mut table = ResultTable::new(config.output.use_colors);

    print_info("正在抓取 Banner...");

    for port in ports_to_scan {
        let addr = format!("{}:{}", target, port).parse::<std::net::SocketAddr>();

        if let Ok(addr) = addr {
            use modules::identify::BannerGrabber;
            use std::time::Duration;

            let grabber = BannerGrabber::new(Duration::from_secs(2), 2048);
            let banner_future = grabber.grab(addr);

            // 使用 tokio 运行时执行异步操作
            if let Ok(banner_result) = tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(banner_future)
            {
                if let Some(service_info) = matcher.get_service_info(
                    port,
                    banner_result.banner.as_deref(),
                ) {
                    table.add_port_row(PortRow {
                        port,
                        status: "open".to_string(),
                        service: service_info.service,
                        version: service_info.version,
                        banner: service_info.banner,
                    });
                }
            }
        }
    }

    table.print_summary("服务识别结果");
    table.print();

    Ok(())
}

/// 解析端口参数
fn parse_ports(port_str: &str) -> Result<Vec<u16>> {
    // 复用 scan 模块的端口解析逻辑
    // 这里简化处理
    if port_str.contains('-') {
        let parts: Vec<&str> = port_str.split('-').collect();
        if parts.len() == 2 {
            let start: u16 = parts[0].parse().map_err(|_| {
                core::error::FlyWheelError::InvalidPortRange {
                    range: port_str.to_string(),
                }
            })?;
            let end: u16 = parts[1].parse().map_err(|_| {
                core::error::FlyWheelError::InvalidPortRange {
                    range: port_str.to_string(),
                }
            })?;
            Ok((start..=end).collect())
        } else {
            Err(core::error::FlyWheelError::InvalidPortRange {
                range: port_str.to_string(),
            })
        }
    } else if port_str.contains(',') {
        port_str
            .split(',')
            .map(|p| {
                p.trim().parse::<u16>().map_err(|_| {
                    core::error::FlyWheelError::InvalidPortRange {
                        range: port_str.to_string(),
                    }
                })
            })
            .collect()
    } else {
        Ok(vec![port_str.parse::<u16>().map_err(|_| {
            core::error::FlyWheelError::InvalidPortRange {
                range: port_str.to_string(),
            }
        })?])
    }
}

/// 信息收集
fn run_info_gathering(target: &str, config: &ScanConfig) -> Result<()> {
    print_info(&format!("正在进行信息收集: {}", target));
    let result = info::run(target);
    println!("{}", result);
    Ok(())
}

/// 持久化设置
fn run_persistence(target: &str, config: &ScanConfig) -> Result<()> {
    print_warning(&format!("持久化操作需要明确授权，目标: {}", target));
    let result = persist::run(target);
    println!("{}", result);
    Ok(())
}

/// 配置管理命令
fn run_config_command(cmd: &ConfigCommands) -> Result<()> {
    match cmd {
        ConfigCommands::Wizard => {
            print_info("启动配置向导...");
            let config = ConfigWizard::run()?;
            ConfigWizard::show_config(&config);
            print_success("配置已保存");
        }

        ConfigCommands::Show => {
            let config = ScanConfig::load()?;
            ConfigWizard::show_config(&config);
        }

        ConfigCommands::Reset => {
            print_info("重置为默认配置...");
            let config = ScanConfig::default();
            config.save()?;
            print_success("配置已重置");
        }
    }

    Ok(())
}

/// 主机信息收集命令
fn run_collect_command(cmd: &CollectCommands) -> Result<()> {
    match cmd {
        CollectCommands::All => {
            print_info("正在收集所有系统信息...");
            let mut sys_collector = collect::SystemCollector::new();
            let sys_info = sys_collector.collect_all();

            println!("\n========== 系统信息 ==========");
            println!("操作系统: {} {}", sys_info.os_info.os_type, sys_info.os_info.os_version);
            println!("架构: {}", sys_info.os_info.arch);
            println!("主机名: {}", sys_info.hostname);
            if let Some(domain) = &sys_info.domain {
                println!("域名: {}", domain);
            }
            println!("当前用户: {} (权限: {:?})", sys_info.current_user.username, sys_info.current_user.privileges);
            println!("运行时间: {} 秒", sys_info.uptime);
            println!("CPU数量: {}", sys_info.cpu_info.cpu_count);
            println!("内存: {} / {} MB ({:.1}%)",
                sys_info.memory_info.used_memory / 1024 / 1024,
                sys_info.memory_info.total_memory / 1024 / 1024,
                sys_info.memory_info.usage_percent
            );

            println!("\n========== 网络接口 ==========");
            let net_collector = collect::NetworkCollector::new();
            let interfaces = net_collector.collect_interfaces();
            for iface in interfaces {
                println!("{}: {} ({})", iface.name, iface.ip, if iface.is_up { "UP" } else { "DOWN" });
            }

            println!("\n========== 进程信息 ==========");
            let mut proc_collector = collect::ProcessCollector::new();
            let processes = proc_collector.list_processes();
            println!("运行中进程数: {}", processes.len());

            println!("\n========== 凭据信息 ==========");
            let cred_collector = collect::CredentialCollector::new();
            let hashes = cred_collector.collect_password_hashes();
            let tokens = cred_collector.collect_tokens();
            let ssh_keys = cred_collector.collect_ssh_keys();
            let api_keys = cred_collector.collect_api_keys();

            println!("密码哈希: {} 条", hashes.len());
            println!("令牌: {} 条", tokens.len());
            println!("SSH密钥: {} 条", ssh_keys.len());
            println!("API密钥: {} 条", api_keys.len());

            print_success("信息收集完成");
        }

        CollectCommands::System => {
            print_info("正在收集系统信息...");
            let mut sys_collector = collect::SystemCollector::new();
            let sys_info = sys_collector.collect_all();

            println!("\n========== 操作系统 ==========");
            println!("类型: {}", sys_info.os_info.os_type);
            println!("版本: {}", sys_info.os_info.os_version);
            println!("架构: {}", sys_info.os_info.arch);

            println!("\n========== 主机信息 ==========");
            println!("主机名: {}", sys_info.hostname);
            if let Some(domain) = &sys_info.domain {
                println!("域名: {}", domain);
            }

            println!("\n========== 用户信息 ==========");
            println!("当前用户: {}", sys_info.current_user.username);
            println!("权限级别: {:?}", sys_info.current_user.privileges);
            println!("用户组: {:?}", sys_info.current_user.groups);
            println!("所有用户: {:?}", sys_info.users);

            println!("\n========== 硬件信息 ==========");
            println!("CPU数量: {}", sys_info.cpu_info.cpu_count);
            if let Some(brand) = &sys_info.cpu_info.cpu_brand {
                println!("CPU型号: {}", brand);
            }
            if let Some(freq) = sys_info.cpu_info.cpu_freq {
                println!("CPU频率: {} MHz", freq);
            }

            println!("\n========== 内存信息 ==========");
            println!("总内存: {} MB", sys_info.memory_info.total_memory / 1024 / 1024);
            println!("已用内存: {} MB", sys_info.memory_info.used_memory / 1024 / 1024);
            println!("可用内存: {} MB", sys_info.memory_info.available_memory / 1024 / 1024);
            println!("使用率: {:.1}%", sys_info.memory_info.usage_percent);

            println!("\n========== 磁盘信息 ==========");
            for disk in &sys_info.disk_info {
                println!("{}: {} 总空间: {} GB 可用: {} GB",
                    disk.name,
                    disk.mount_point,
                    disk.total_space / 1024 / 1024 / 1024,
                    disk.available_space / 1024 / 1024 / 1024
                );
            }

            println!("\n========== 系统运行时间 ==========");
            println!("运行时间: {} 秒 (约 {} 小时)",
                sys_info.uptime,
                sys_info.uptime / 3600
            );

            print_success("系统信息收集完成");
        }

        CollectCommands::Network => {
            print_info("正在收集网络配置信息...");
            let net_collector = collect::NetworkCollector::new();

            println!("\n========== 网络接口 ==========");
            let interfaces = net_collector.collect_interfaces();
            for iface in &interfaces {
                println!("名称: {}", iface.name);
                println!("  IP地址: {}", iface.ip);
                println!("  子网掩码: {}", iface.netmask);
                println!("  状态: {}", if iface.is_up { "UP" } else { "DOWN" });
            }

            println!("\n========== 路由表 ==========");
            let routes = net_collector.collect_routes();
            for route in &routes {
                println!("{} via {} metric={} dev={}",
                    route.destination, route.gateway, route.metric, route.interface
                );
            }

            println!("\n========== ARP 表 ==========");
            let arp = net_collector.collect_arp_table();
            println!("ARP 条目数: {}", arp.len());

            println!("\n========== 网络连接 ==========");
            let conns = net_collector.collect_connections();
            println!("活动连接数: {}", conns.len());

            print_success("网络配置信息收集完成");
        }

        CollectCommands::Process { name } => {
            print_info("正在收集进程信息...");
            let mut proc_collector = collect::ProcessCollector::new();

            if let Some(filter_name) = name {
                println!("\n========== 搜索进程: {} ==========", filter_name);
                let processes = proc_collector.find_by_name(filter_name);
                for proc in processes {
                    println!("PID: {} 名称: {}", proc.pid, proc.name);
                    println!("  可执行文件: {}", proc.exe);
                    println!("  命令行: {}", proc.cmd);
                    println!("  CPU使用率: {:.1}%", proc.cpu_usage);
                    println!("  内存使用: {} MB", proc.memory_usage / 1024 / 1024);
                }
            } else {
                println!("\n========== 所有进程 ==========");
                let processes = proc_collector.list_processes();
                println!("进程总数: {}", processes.len());
                for proc in processes.iter().take(20) {
                    println!("PID: {:<8} 名称: {:<20} CPU: {:>5.1}% 内存: {:>8} MB",
                        proc.pid,
                        proc.name,
                        proc.cpu_usage,
                        proc.memory_usage / 1024 / 1024
                    );
                }
                if processes.len() > 20 {
                    println!("... (还有 {} 个进程)", processes.len() - 20);
                }
            }

            print_success("进程信息收集完成");
        }

        CollectCommands::Credential => {
            print_warning("凭据收集需要适当授权");
            print_info("正在收集凭据信息...");
            let cred_collector = collect::CredentialCollector::new();

            println!("\n========== 密码哈希 ==========");
            let hashes = cred_collector.collect_password_hashes();
            for hash in &hashes {
                println!("类型: {} 位置: {}", hash.hash_type, hash.location);
                println!("  用户: {}", hash.username);
                println!("  哈希: {}", hash.hash);
            }

            println!("\n========== 令牌 ==========");
            let tokens = cred_collector.collect_tokens();
            for token in &tokens {
                println!("类型: {} 位置: {}", token.token_type, token.location);
                println!("  内容: {}", token.content);
            }

            println!("\n========== SSH 密钥 ==========");
            let ssh_keys = cred_collector.collect_ssh_keys();
            for key in &ssh_keys {
                println!("类型: {} 路径: {}", key.key_type, key.path);
                if let Some(fingerprint) = &key.fingerprint {
                    println!("  指纹: {}", fingerprint);
                }
            }

            println!("\n========== API 密钥 ==========");
            let api_keys = cred_collector.collect_api_keys();
            for key in &api_keys {
                println!("服务: {} 位置: {}", key.service, key.location);
            }

            print_success("凭据收集完成");
        }

        CollectCommands::File { paths, search_type, keywords, days } => {
            print_info(&format!("正在搜索文件: {} (类型: {})", paths, search_type));
            let file_collector = collect::FileCollector::new();
            let search_paths: Vec<String> = paths.split(',').map(|s| s.trim().to_string()).collect();

            match search_type.as_str() {
                "sensitive" => {
                    let files = file_collector.find_sensitive_files(&search_paths);
                    println!("\n========== 敏感文件 ({} 条) ==========", files.len());
                    for file in files.iter().take(50) {
                        println!("[{}] {} ({} 字节)",
                            file.category, file.path, file.size
                        );
                    }
                    if files.len() > 50 {
                        println!("... (还有 {} 个文件)", files.len() - 50);
                    }
                }

                "config" => {
                    let files = file_collector.find_config_files(&search_paths);
                    println!("\n========== 配置文件 ({} 条) ==========", files.len());
                    for file in files.iter().take(50) {
                        println!("[{}] {} ({} 字节)",
                            file.config_type, file.path, file.size
                        );
                    }
                    if files.len() > 50 {
                        println!("... (还有 {} 个文件)", files.len() - 50);
                    }
                }

                "keyword" => {
                    let kw_list: Vec<String> = if let Some(kw) = keywords {
                        kw.split(',').map(|s| s.trim().to_string()).collect()
                    } else {
                        print_error("keyword 搜索类型需要 --keywords 参数");
                        return Ok(());
                    };
                    let matches = file_collector.search_keywords(&search_paths, &kw_list);
                    println!("\n========== 关键词匹配 ({} 条) ==========", matches.len());
                    for m in matches.iter().take(20) {
                        println!("文件: {} ({} 次匹配)", m.file_name, m.total_matches);
                        for (line_num, line) in m.lines.iter().take(3) {
                            println!("  行 {}: {}", line_num, line.trim());
                        }
                    }
                }

                "recent" => {
                    let files = file_collector.find_recent_files(&search_paths, *days);
                    println!("\n========== 最近 {} 天修改的文件 ({} 条) ==========", days, files.len());
                    for file in files.iter().take(50) {
                        println!("{}", file.display());
                    }
                    if files.len() > 50 {
                        println!("... (还有 {} 个文件)", files.len() - 50);
                    }
                }

                _ => {
                    print_error(&format!("未知的搜索类型: {}", search_type));
                }
            }

            print_success("文件搜索完成");
        }
    }

    Ok(())
}
