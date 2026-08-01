//! 系统信息收集 CLI
//!
//! 处理 system 子命令的各类信息收集功能

use crate::cli::{colorize, format_bytes, parse_system_item, print_banner, print_system_items, save_scan_result, InteractiveMenu};
use crate::collector::models::*;
use crate::collector::InfoCollector;
use crate::core::Result;
use crate::modules::collect::*;
use crate::output::color::*;

use crate::output::format::OutputFormat;
use crate::scanner::Scanner;
use std::path::{Path, PathBuf};

/// 系统信息收集命令入口
pub fn run_system(item: &Option<String>, output: Option<PathBuf>, quiet: bool) -> Result<()> {
    // 无参数时进入交互式
    let item_str = match item {
        Some(i) => i.clone(),
        None => {
            print_banner();
            print_info("IntraSweep 交互式系统信息收集");
            println!();
            print_system_items();
            let choice = InteractiveMenu::read_number_opt("请选择收集项目 [1-7, 默认 1(all)]: ", 1, 7, 1);
            let items: [&str; 7] = ["all", "system", "network", "process", "credential", "file", "domain"];
            items[choice - 1].to_string()
        }
    };

    match parse_system_item(&item_str) {
        Some("all") => run_system_collect_all(output, quiet),
        Some("system") => run_system_collect_basic(output, quiet),
        Some("network") => run_system_collect_network(output, quiet),
        Some("process") => run_system_collect_process(output, quiet),
        Some("credential") => run_system_collect_credential(output, quiet),
        Some("file") => run_system_collect_file(output, quiet),
        Some("domain") => run_domain_scan(output),
        _ => {
            print_error(&format!("未知的收集项目: {}", item_str));
            print_system_items();
            std::process::exit(1);
        }
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
    let output_path = crate::collector::save_report(&report, output)?;

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
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .expect("创建进度条样式失败"),
    );
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
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .expect("创建进度条样式失败"),
    );
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
#[allow(clippy::field_reassign_with_default)]
fn run_system_collect_process(output: Option<PathBuf>, _quiet: bool) -> Result<()> {
    print_info("开始收集进程信息...");
    println!();

    use indicatif::{ProgressBar, ProgressStyle};
    use std::time::Duration;

    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .expect("创建进度条样式失败"),
    );
    pb.enable_steady_tick(Duration::from_millis(100));

    pb.set_message("正在枚举系统进程...");
    let mut collector = ProcessCollector::new();
    let all_processes = collector.list_processes();

    pb.set_message("正在分析进程详情...");
    #[allow(clippy::field_reassign_with_default)]
    let mut process = ProcessReport::default();
    process.total_count = all_processes.len();
    process.processes = all_processes.into_iter().take(100).collect();
    process.update_stats();

    pb.finish();
    println!("进程信息收集完成 - 共{}个进程", process.total_count);
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
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .expect("创建进度条样式失败"),
    );
    pb.enable_steady_tick(Duration::from_millis(100));

    let collector = CredentialCollector::new();
    let mut credential = CredentialReport::default();

    pb.set_message("正在搜索密码哈希...");
    credential.password_hashes = collector.collect_password_hashes();

    pb.set_message("正在搜索令牌...");
    credential.tokens = collector.collect_tokens();
    credential.tokens.extend(collector.collect_env_secrets());

    pb.set_message("正在搜索SSH密钥...");
    credential.ssh_keys = collector.collect_ssh_keys();

    pb.set_message("正在搜索API密钥...");
    credential.api_keys = collector.collect_api_keys();

    pb.set_message("正在搜索远程连接历史...");
    credential.known_hosts = collector.collect_known_hosts();
    let mut remote_sessions = collector.collect_putty_sessions();
    remote_sessions.extend(collector.collect_rdp_history());
    credential.remote_sessions = remote_sessions;

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
#[allow(clippy::field_reassign_with_default)]
fn run_system_collect_file(output: Option<PathBuf>, _quiet: bool) -> Result<()> {
    print_info("开始收集文件信息...");
    println!();

    use indicatif::{ProgressBar, ProgressStyle};
    use std::time::Duration;

    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .expect("创建进度条样式失败"),
    );
    pb.enable_steady_tick(Duration::from_millis(100));

    let collector = FileCollector::new();
    let search_paths = get_default_search_paths();

    pb.set_message("正在搜索敏感文件...");
    #[allow(clippy::field_reassign_with_default)]
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
fn convert_to_recent_files(paths: Vec<PathBuf>) -> Vec<crate::collector::models::RecentFile> {
    use crate::collector::models::RecentFile;

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
    println!("║  已连主机:   {:<60}║", credential.stats.known_host_count);
    println!("║  远程会话:   {:<60}║", credential.stats.remote_session_count);
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

/// 打印信息收集结果
fn print_collect_results(report: &crate::collector::SystemReport, output_path: &Path) {
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

/// 运行域环境扫描
fn run_domain_scan(output: Option<PathBuf>) -> Result<()> {
    println!();
    print_info("开始域环境扫描...");
    println!();

    use indicatif::{ProgressBar, ProgressStyle};
    use std::time::Duration;

    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .expect("创建进度条样式失败"),
    );
    pb.enable_steady_tick(Duration::from_millis(100));

    pb.set_message("正在检测域环境...");

    let mut scanner = Scanner::default();
    let result = scanner.domain_scan();

    pb.finish_with_message("域环境扫描完成");
    println!();

    print_domain_scan_results(&result);

    if let Ok(path) = save_scan_result(&convert_domain_result_to_scan(result), OutputFormat::Json, output) {
        println!();
        print_success(&format!("结果已保存到: {}", path.display()));
    }

    Ok(())
}

/// 将域扫描结果转换为通用扫描结果
fn convert_domain_result_to_scan(
    domain_result: crate::scanner::domain::DomainScanResult,
) -> crate::scanner::ScanResult {
    use crate::scanner::models::{HostResult, PortInfo, PortState, ScanResult, ScanStats, ScanType};

    let mut host = HostResult {
        ip: "domain".to_string(),
        hostname: domain_result.domain_name.clone(),
        is_alive: domain_result.is_joined,
        latency_ms: None,
        mac: None,
        open_ports: vec![],
        services: vec![],
        web_fingerprints: vec![],
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
            web_fingerprints_found: 0,
        },
    }
}

/// 打印域扫描结果
fn print_domain_scan_results(result: &crate::scanner::domain::DomainScanResult) {
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
