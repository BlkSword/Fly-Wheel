//! IntraSweep - 内网渗透辅助工具

mod collector;
mod core;
mod modules;
mod output;
mod scanner;

use clap::{Parser, Subcommand, ValueEnum};
use collector::InfoCollector;
use collector::models::{NetworkReport, ProcessReport, CredentialReport, FileReport};
use core::error::Result;
use modules::collect::{SystemCollector, NetworkCollector, ProcessCollector, CredentialCollector, FileCollector, SystemInfo};
use output::color::{print_error, print_info, print_success, Color};
use scanner::{ScanConfig, Scanner, HostScanMethod, PortScanMethod};
use std::path::PathBuf;

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

/// IntraSweep - 内网渗透辅助工具
#[derive(Parser)]
#[command(
    name = "intrasweep",
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
        /// 扫描类型: host(h), port(po), domain(d), comprehensive(c)
        #[arg(required = true)]
        scan_type: String,

        /// 扫描目标 (IP/CIDR/范围)
        #[arg(value_name = "TARGETS")]
        targets: Vec<String>,

        /// 扫描预设: fast(快)/standard(中)/deep(深)/stealth(隐蔽)
        #[arg(short, long, value_enum, default_value_t = ScanPreset::Standard)]
        preset: ScanPreset,

        /// 主机扫描方式: tcp-syn/icmp/arp/hybrid
        #[arg(long, value_enum)]
        host_method: Option<HostScanMethod>,

        /// 端口扫描方式: tcp-connect/tcp-syn/udp/sctp
        #[arg(long, value_enum)]
        port_method: Option<PortScanMethod>,

        /// 输出文件路径 (JSON格式)
        #[arg(short, long)]
        output: Option<PathBuf>,
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
    ("domain", "d"),
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
        Commands::System { item, output, quiet } => {
            match parse_system_item(&item) {
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
            }
        }

        Commands::Scan { scan_type, targets, preset, host_method, port_method, output } => {
            match parse_scan_type(&scan_type) {
                Some("host") => {
                    if targets.is_empty() {
                        print_error("主机扫描需要指定目标");
                        std::process::exit(1);
                    }
                    run_host_scan(targets, preset, host_method, output)
                }
                Some("port") => {
                    if targets.is_empty() {
                        print_error("端口扫描需要指定目标");
                        std::process::exit(1);
                    }
                    run_port_scan(targets, preset, port_method, output)
                }
                Some("domain") => run_domain_scan(output),
                Some("comprehensive") => {
                    if targets.is_empty() {
                        print_error("综合扫描需要指定目标");
                        std::process::exit(1);
                    }
                    run_comprehensive_scan(targets, preset, host_method, port_method, output)
                }
                _ => {
                    print_error(&format!("未知的扫描类型: {}", scan_type));
                    print_scan_types();
                    std::process::exit(1);
                }
            }
        }
    };

    if let Err(e) = result {
        print_error(&format!("{}", e));
        std::process::exit(1);
    }
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

    let mut collector = SystemCollector::new();
    let system = collector.collect_all();

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

    let collector = NetworkCollector::new();
    let mut network = NetworkReport::default();

    network.interfaces = collector.collect_interfaces();
    network.routes = collector.collect_routes();
    network.arp_table = collector.collect_arp_table();
    network.connections = collector.collect_connections();
    network.update_stats();

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

    let mut collector = ProcessCollector::new();
    let all_processes = collector.list_processes();

    let mut process = ProcessReport::default();
    process.total_count = all_processes.len();
    process.processes = all_processes.into_iter().take(100).collect();
    process.update_stats();

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

    let collector = CredentialCollector::new();
    let mut credential = CredentialReport::default();

    credential.password_hashes = collector.collect_password_hashes();
    credential.tokens = collector.collect_tokens();
    credential.ssh_keys = collector.collect_ssh_keys();
    credential.api_keys = collector.collect_api_keys();
    credential.update_stats();

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

    let collector = FileCollector::new();
    let search_paths = get_default_search_paths();

    let mut file = FileReport::default();
    file.sensitive_files = collector.find_sensitive_files(&search_paths);
    file.config_files = collector.find_config_files(&search_paths);

    let recent_paths = get_recent_file_paths();
    let recent_files = collector.find_recent_files(&recent_paths, 7);
    file.recent_files = convert_to_recent_files(recent_files);
    file.update_stats();

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
                modified: chrono::DateTime::<chrono::Utc>::from(modified)
                    .to_rfc3339(),
                is_sensitive: false,
            })
        })
        .collect()
}

/// 打印基础系统信息
fn print_basic_system_info(system: &SystemInfo) {
    println!("╔════════════════════════════════════════════════════════════════════════════╗");
    println!("║  {}", colorize("基础系统信息收集完成", Color::BrightGreen));
    println!("╠════════════════════════════════════════════════════════════════════════════╣");
    println!("║  系统信息");
    println!("╠────────────────────────────────────────────────────────────────────────────╣");
    println!("║  操作系统:   {:<60}║", format!("{} {}", system.os_info.os_type, system.os_info.os_version));
    println!("║  主机名:     {:<60}║", system.hostname);
    println!("║  架构:       {:<60}║", system.os_info.arch);
    println!("╠════════════════════════════════════════════════════════════════════════════╣");
    println!("║  用户信息");
    println!("╠────────────────────────────────────────────────────────────────────────────╣");
    println!("║  当前用户:   {:<60}║", system.current_user.username);
    println!("║  权限级别:   {:<60}║", format!("{:?}", system.current_user.privileges));
    println!("╠════════════════════════════════════════════════════════════════════════════╣");
    println!("║  硬件资源");
    println!("╠────────────────────────────────────────────────────────────────────────────╣");
    println!("║  CPU核心数:  {:<60}║", system.cpu_info.cpu_count);
    println!("║  总内存:     {:<60}║", format!("{:.2} GB", system.memory_info.total_memory as f64 / 1024.0 / 1024.0 / 1024.0));
    println!("║  内存使用:   {:<60}║", format!("{:.2} GB ({:.1}%)",
        system.memory_info.used_memory as f64 / 1024.0 / 1024.0 / 1024.0,
        system.memory_info.usage_percent));
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
        println!("║  {:<30} PID:{:<10} CPU:{:>6.1}% MEM:{:<12}║",
            proc.name, proc.pid, proc.cpu_usage, format_bytes(proc.memory_usage));
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
fn run_host_scan(targets: Vec<String>, preset: ScanPreset, host_method: Option<HostScanMethod>, output: Option<PathBuf>) -> Result<()> {
    let mut config = preset_to_config(preset);

    // 应用用户指定的扫描方式
    if let Some(method) = host_method {
        config.host_scan_method = method;
    }

    println!();
    print_info(&format!("开始主机存活扫描"));
    print_info(&format!("目标: {}", targets.join(", ")));
    print_info(&format!("预设: {:?}", preset));
    print_info(&format!("扫描方式: {}", config.host_scan_method.display_name()));
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
fn run_port_scan(targets: Vec<String>, preset: ScanPreset, port_method: Option<PortScanMethod>, output: Option<PathBuf>) -> Result<()> {
    let mut config = preset_to_config(preset);

    // 应用用户指定的扫描方式
    if let Some(method) = port_method {
        config.port_scan_method = method;
    }

    println!();
    print_info(&format!("开始端口扫描"));
    print_info(&format!("目标: {}", targets.join(", ")));
    print_info(&format!("预设: {:?}", preset));
    print_info(&format!("扫描方式: {}", config.port_scan_method.display_name()));
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
    host_method: Option<HostScanMethod>,
    port_method: Option<PortScanMethod>,
    output: Option<PathBuf>,
) -> Result<()> {
    let mut config = preset_to_config(preset);

    // 应用用户指定的扫描方式
    if let Some(method) = host_method {
        config.host_scan_method = method;
    }
    if let Some(method) = port_method {
        config.port_scan_method = method;
    }

    println!();
    print_info(&format!("开始综合扫描"));
    print_info(&format!("目标: {}", targets.join(", ")));
    print_info(&format!("预设: {:?}", preset));
    print_info(&format!("主机扫描: {}", config.host_scan_method.display_name()));
    print_info(&format!("端口扫描: {}", config.port_scan_method.display_name()));
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
