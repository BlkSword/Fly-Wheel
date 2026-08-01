//! CLI 模块化基础设施
//!
//! 定义 Cli/Commands 结构、交互式菜单、共享工具函数

// CLI 命令处理函数需要较多参数传递用户配置
#![allow(clippy::too_many_arguments)]

pub mod ad;
pub mod crack;
pub mod cred;
pub mod privesc;
pub mod recon;
pub mod report;
pub mod scan;
pub mod system;
pub mod tunnel;
pub mod vuln;

use crate::core::Result;
use crate::output::color::print_error;
use clap::{Parser, Subcommand};
use std::io::{self, Write};
use std::path::PathBuf;

// ============================================================
// 交互式菜单系统
// ============================================================

pub(crate) struct InteractiveMenu;

impl InteractiveMenu {
    /// 读取用户输入
    pub fn read_input(prompt: &str) -> String {
        print!("{}", prompt);
        let _ = io::stdout().flush();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            return String::new();
        }
        input.trim().to_string()
    }

    /// 读取用户输入，空输入时重试
    pub fn read_input_required(prompt: &str, error_msg: &str) -> String {
        loop {
            let input = Self::read_input(prompt);
            if !input.is_empty() {
                return input;
            }
            print_error(error_msg);
        }
    }

    /// 读取数字输入（必选，无默认值）
    pub fn read_number(prompt: &str, min: usize, max: usize) -> usize {
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

    /// 读取数字输入（可选，支持按回车取默认值）
    pub fn read_number_opt(prompt: &str, min: usize, max: usize, default: usize) -> usize {
        loop {
            let input = Self::read_input(prompt);
            if input.is_empty() {
                return default;
            }
            match input.parse::<usize>() {
                Ok(n) if n >= min && n <= max => return n,
                _ => {
                    print_error(&format!(
                        "请输入 {} 到 {} 之间的数字，或按回车使用默认值 {}",
                        min, max, default
                    ));
                }
            }
        }
    }

    /// 读取端口号（支持按回车取默认端口）
    pub fn read_port(prompt: &str, default: u16) -> u16 {
        let input = Self::read_input(prompt);
        if input.is_empty() {
            return default;
        }
        match input.parse::<u16>() {
            Ok(p) => p,
            Err(_) => {
                print_error(&format!("无效端口号，使用默认端口: {}", default));
                default
            }
        }
    }

    /// 打印步骤标题
    pub fn print_step(step: usize, total: usize, title: &str) {
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("  [{}/{}] {}", step, total, title);
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!();
    }

    /// 确认操作（默认 Y）
    pub fn confirm(prompt: &str) -> bool {
        let input = Self::read_input(prompt);
        !input.eq_ignore_ascii_case("n")
    }
}

// ============================================================
// CLI 定义
// ============================================================

/// IntraSweep — 高性能内网渗透侦察与打击工具
#[derive(Parser)]
#[command(
    name = "intrasweep",
    author = "BlkSword",
    version = "0.4.0",
    long_about = None,
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// 详细输出 (DEBUG级别日志)
    #[arg(short = 'v', long, global = true)]
    pub verbose: bool,

    /// 安静模式 (仅错误)
    #[arg(short = 'q', long, global = true)]
    pub quiet: bool,

    /// 日志文件路径
    #[arg(long, global = true)]
    pub log_file: Option<PathBuf>,

    /// 配置文件路径 (YAML)
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// 系统信息收集 — OS/网络/进程/凭据/文件/域环境一键收集 (缩写: s)
    System {
        /// 收集项目: all(a), system(sy), network(n), process(p), credential(c), file(f), domain(d)（留空进入交互式）
        #[arg(value_name = "ITEM")]
        item: Option<String>,

        /// 输出文件路径 (JSON格式)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// 静默模式 (不显示进度条)
        #[arg(short, long)]
        quiet: bool,
    },

    /// 网络扫描 — 主机发现/端口扫描/服务探测/Web指纹识别 (缩写: sc)
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

        /// 启用Web指纹识别
        #[arg(long)]
        webfinger: bool,

        /// 输出格式: json, csv (默认: json)
        #[arg(long, default_value = "json")]
        format: String,

        /// 输出文件路径 (JSON格式)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// 密码爆破/喷洒 — 8种服务(SSH/RDP/Redis/MySQL/MSSQL等)+域密码喷洒 (缩写: cr)
    Crack {
        /// 目标主机 (可选，不填则进入交互式模式)
        #[arg(value_name = "TARGET")]
        target: Option<String>,

        /// 端口 (可选，默认为服务默认端口)
        #[arg(short, long)]
        port: Option<u16>,

        /// 服务类型: ssh, rdp, redis, postgres, mongodb, mssql, mysql, winrm
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

        /// 密码喷洒模式（域环境，防账户锁定）
        #[arg(long)]
        spray: bool,
    },

    /// 内网穿透 — 正向/反向/SOCKS5/链式/HTTP/DNS隧道 (缩写: tu)
    Tunnel {
        /// 隧道类型: forward, reverse, socks5, chain, http, dns
        #[arg(value_name = "TYPE")]
        tunnel_type: Option<String>,

        /// 目标地址 (host:port)
        #[arg(short, long)]
        target: Option<String>,

        /// 本地监听端口
        #[arg(short = 'L', long)]
        local_port: Option<u16>,

        /// 远程监听端口
        #[arg(short = 'R', long)]
        remote_port: Option<u16>,

        /// 跳板主机 (host:port，可多次指定)
        #[arg(short = 'H', long)]
        hop: Option<Vec<String>>,

        /// SOCKS5 认证用户名
        #[arg(long)]
        socks5_username: Option<String>,

        /// SOCKS5 认证密码
        #[arg(long)]
        socks5_password: Option<String>,

        /// 加密密钥（启用 XChaCha20-Poly1305 AEAD 加密）
        #[arg(long)]
        encryption_key: Option<String>,

        /// 最大并发连接
        #[arg(short, long, default_value = "100")]
        max_connections: usize,

        /// 超时时间(秒)
        #[arg(short, long, default_value = "30")]
        timeout: u64,
    },

    /// 漏洞扫描 — 31条内置PoC + 外部YAML/JSON/脚本 + Web主动探测(SQLi/XSS/RCE) (缩写: v)
    Vuln {
        /// 扫描目标 (IP/CIDR/host:port) - 可选，不填则进入交互式模式
        #[arg(value_name = "TARGETS")]
        targets: Option<Vec<String>>,

        /// 外部 PoC 文件或目录
        #[arg(long)]
        poc_file: Option<PathBuf>,

        /// 按严重性过滤: critical, high, medium, low, info
        #[arg(long)]
        severity: Option<String>,

        /// 按类别过滤
        #[arg(long)]
        category: Option<String>,

        /// 启用 Web 主动探测（SQLi/XSS/命令注入/路径穿越）
        #[arg(long)]
        web_probe: bool,

        /// 输出格式: json, csv (默认: json)
        #[arg(long, default_value = "json")]
        format: String,

        /// 输出文件路径
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// 并发数 (默认: 20)
        #[arg(short, long, default_value = "20")]
        concurrency: usize,

        /// 超时时间(秒) (默认: 10)
        #[arg(short, long, default_value = "10")]
        timeout: u64,
    },

    /// 本地凭据收集 — 浏览器/WiFi/应用/SAM/LSASS/GPP 一键提取 (缩写: crd)
    Cred {
        /// 域控 IP 地址（GPP 解密需要）
        #[arg(short, long)]
        dc: Option<String>,

        /// 域名 (例: corp.local)（GPP 解密需要）
        #[arg(short, long)]
        domain: Option<String>,

        /// 输出格式: json, csv (默认: json)
        #[arg(long, default_value = "json")]
        format: String,

        /// 输出文件路径
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// AD域枚举 — LDAP查询/Kerberoasting/AS-REP/GoldenTicket/DCSync/BloodHound/ADCS (缩写: ad)
    Ad {
        /// 域控 IP 地址 - 可选，不填则进入交互式模式
        #[arg(short, long)]
        dc: Option<String>,

        /// 域名 (例: corp.local) - 可选
        #[arg(short, long)]
        domain: Option<String>,

        /// 用户名
        #[arg(short, long)]
        username: Option<String>,

        /// 密码
        #[arg(short, long)]
        password: Option<String>,

        /// 使用 LDAPS (端口 636)
        #[arg(long)]
        ssl: bool,

        /// 执行模式: all, kerberoast, asrep-roast, bloodhound, adcs, gpp, dcsync
        #[arg(short, long, default_value = "all")]
        mode: String,

        /// BloodHound 输出目录 (mode=bloodhound 时使用)
        #[arg(long)]
        bloodhound_dir: Option<PathBuf>,

        /// Golden Ticket 模式（需同时指定 --krbtgt-hash）
        #[arg(long)]
        golden_ticket: bool,

        /// krbtgt NTLM 哈希（用于 Golden Ticket）
        #[arg(long)]
        krbtgt_hash: Option<String>,

        /// 输出格式: json, csv (默认: json)
        #[arg(long, default_value = "json")]
        format: String,

        /// 输出文件路径
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// 信息侦察 — EDR检测/情境感知/共享搜索/防火墙/VLAN发现 (缩写: rc)
    Recon {
        /// 域控 IP 地址（用户会话猎杀需要）
        #[arg(short, long)]
        dc: Option<String>,

        /// 域名 (例: corp.local)（用户会话猎杀需要）
        #[arg(short, long)]
        domain: Option<String>,

        /// 侦察模式: full, edr, situational, host, shares, firewall, vlan
        #[arg(short, long, default_value = "full")]
        mode: String,

        /// 输出格式: json, csv (默认: json)
        #[arg(long, default_value = "json")]
        format: String,

        /// 输出文件路径
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// 提权检测 — Windows 7类/Linux 8类自动化提权向量检查 (缩写: p)
    Privesc {
        /// 检查类别（留空运行全部）: service, credentials, registry, tokens, files, patches, dll, suid, capabilities, cron, writable, docker, sudo, ssh, kernel
        #[arg(short, long)]
        check: Option<String>,

        /// 输出格式: json, csv (默认: json)
        #[arg(long, default_value = "json")]
        format: String,

        /// 输出文件路径
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// 渗透报告生成 — 执行摘要/完整Markdown/HTML + MITRE ATT&CK映射 + 自定义JSON输入 (缩写: rp)
    Report {
        /// 报告格式: executive, full, html
        #[arg(long, default_value = "full")]
        format: String,

        /// 输入数据文件（JSON格式，含AD/扫描/凭据结果）
        #[arg(long)]
        input: Option<PathBuf>,

        /// 包含 MITRE ATT&CK 映射
        #[arg(long)]
        mitre: bool,

        /// 输出文件路径
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

// ============================================================
// 命令映射常量
// ============================================================

/// system 子命令映射 (完整名称, 缩写)
pub(crate) const SYSTEM_ITEMS: &[(&str, &str)] = &[
    ("all", "a"),
    ("system", "sy"),
    ("network", "n"),
    ("process", "p"),
    ("credential", "c"),
    ("file", "f"),
    ("domain", "d"),
];

/// scan 子命令映射 (完整名称, 缩写)
pub(crate) const SCAN_TYPES: &[(&str, &str)] =
    &[("host", "h"), ("port", "po"), ("comprehensive", "c")];

/// tunnel 子命令映射 (完整名称, 缩写)
/// 注: http/dns 隧道尚未接线，暂不列入
pub(crate) const TUNNEL_TYPES: &[(&str, &str)] = &[
    ("forward", "fo"),
    ("reverse", "re"),
    ("socks5", "so"),
    ("chain", "ch"),
];

// ============================================================
// 共享工具函数
// ============================================================

/// 解析 system 子命令，支持完整名称和缩写
pub(crate) fn parse_system_item(item: &str) -> Option<&'static str> {
    let item_lower = item.to_lowercase();
    for &(full, abbr) in SYSTEM_ITEMS {
        if item_lower == full || item_lower == abbr {
            return Some(full);
        }
    }
    None
}

/// 解析 scan 子命令，支持完整名称和缩写
pub(crate) fn parse_scan_type(scan_type: &str) -> Option<&'static str> {
    let type_lower = scan_type.to_lowercase();
    for &(full, abbr) in SCAN_TYPES {
        if type_lower == full || type_lower == abbr {
            return Some(full);
        }
    }
    None
}

/// 打印所有可用的 system 子命令
pub(crate) fn print_system_items() {
    println!("可用的收集项目:");
    for (full, abbr) in SYSTEM_ITEMS {
        println!("  {} ({})", full, abbr);
    }
}

/// 打印所有可用的 scan 子命令
pub(crate) fn print_scan_types() {
    println!("可用的扫描类型:");
    for (full, abbr) in SCAN_TYPES {
        println!("  {} ({})", full, abbr);
    }
}

/// 保存扫描结果（支持 JSON/CSV 格式）
pub(crate) fn save_scan_result(
    result: &crate::scanner::ScanResult,
    output_fmt: crate::output::format::OutputFormat,
    output: Option<PathBuf>,
) -> Result<PathBuf> {
    let path = output.unwrap_or_else(|| {
        let hostname = if !result.hosts.is_empty() {
            result.hosts[0].ip.clone()
        } else {
            "scan".to_string()
        };
        PathBuf::from(crate::output::format::generate_output_filename(
            &hostname, output_fmt,
        ))
    });
    crate::output::format::export_result(result, &path, output_fmt)?;
    Ok(path)
}

/// 格式化字节数
pub(crate) fn format_bytes(bytes: u64) -> String {
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

/// 彩色化文本
pub(crate) fn colorize(text: &str, color: crate::output::color::Color) -> String {
    use termcolor::{Color as TermColor, ColorSpec, WriteColor};

    let mut buffer = Vec::new();
    let mut writer = termcolor::Ansi::new(&mut buffer);

    let term_color = match color {
        crate::output::color::Color::Black => TermColor::Black,
        crate::output::color::Color::Red => TermColor::Red,
        crate::output::color::Color::Green => TermColor::Green,
        crate::output::color::Color::Yellow => TermColor::Yellow,
        crate::output::color::Color::Blue => TermColor::Blue,
        crate::output::color::Color::Magenta => TermColor::Magenta,
        crate::output::color::Color::Cyan => TermColor::Cyan,
        crate::output::color::Color::White => TermColor::White,
        crate::output::color::Color::BrightBlack => TermColor::Ansi256(8),
        crate::output::color::Color::BrightRed => TermColor::Ansi256(9),
        crate::output::color::Color::BrightGreen => TermColor::Ansi256(10),
        crate::output::color::Color::BrightYellow => TermColor::Ansi256(11),
        crate::output::color::Color::BrightBlue => TermColor::Ansi256(12),
        crate::output::color::Color::BrightMagenta => TermColor::Ansi256(13),
        crate::output::color::Color::BrightCyan => TermColor::Ansi256(14),
        crate::output::color::Color::BrightWhite => TermColor::Ansi256(15),
    };

    writer
        .set_color(ColorSpec::new().set_fg(Some(term_color)))
        .ok();
    write!(writer, "{}", text).ok();
    writer.reset().ok();

    String::from_utf8_lossy(&buffer).to_string()
}

/// 打印 Banner
pub(crate) fn print_banner() {
    println!();
    println!(".___        __                  _________                             ");
    println!("|   | _____/  |_____________   /   _____/_  _  __ ____   ____ ______  ");
    println!("|   |/    \\   __\\_  __ \\__  \\  \\_____  \\\\ \\/ \\/ // __ \\_/ __ \\\\____ \\ ");
    println!("|   |   |  \\  |  |  | \\// __ \\_/        \\\\     /\\  ___/\\  ___/|  |_> >");
    println!("|___|___|  /__|  |__|  (____  /_______  / \\/\\_/  \\___  >\\___  >   __/ ");
    println!("         \\/                 \\/        \\/             \\/     \\/|__|    ");
    println!();
    println!(
        "                       {}",
        crate::core::obfstr::sensitive::banner_label()
    );
    println!();
}
