//! IntraSweep - 内网渗透辅助工具

// 二进制入口有独立的模块树，与 lib.rs 的 API 层分开编译
#![allow(clippy::too_many_arguments)]

mod ad;
mod cli;
mod collector;
mod core;
mod cracker;
mod cred;
mod modules;
mod output;
mod privesc;
mod recon;
mod scanner;
mod tunnel;
mod vuln;

use cli::Commands;
use clap::Parser;
use output::color::{print_error, print_info};

fn main() {
    let cli = cli::Cli::parse();

    core::log::init_logging(&core::log::LogConfig {
        verbose: cli.verbose,
        quiet: cli.quiet,
        log_file: cli.log_file.clone(),
    });

    // 加载配置文件（失败时报错退出，不再静默丢弃）
    let cfg = match cli.config.as_ref() {
        Some(path) => match core::config::load_config(path) {
            Ok(cfg) => {
                tracing::info!("已加载配置文件: {}", path.display());
                Some(cfg)
            }
            Err(e) => {
                print_error(&format!("加载配置文件失败: {}", e));
                std::process::exit(1);
            }
        },
        None => None,
    };

    tracing::debug!("启动 IntraSweep");

    let result = match cli.command {
        Commands::System { item, output, quiet } => {
            cli::system::run_system(&item, output, quiet)
        }

        Commands::Scan { targets, scan_type, fast, webfinger, format, output } => {
            // 配置文件回填：CLI 未指定时使用 config 中的预设
            let (targets, scan_type, fast, webfinger) = if let Some(ref c) = cfg {
                let sp = c.scan.as_ref();
                (
                    targets.or_else(|| sp.and_then(|s| s.targets.clone())),
                    scan_type.or_else(|| sp.and_then(|s| s.scan_type.clone())),
                    fast || sp.and_then(|s| s.fast).unwrap_or(false),
                    webfinger || sp.and_then(|s| s.webfinger).unwrap_or(false),
                )
            } else {
                (targets, scan_type, fast, webfinger)
            };
            let format = apply_default_format(&cfg, &format);
            cli::scan::run_scan(targets, scan_type, fast, webfinger, &format, output)
        }

        Commands::Crack { target, port, service, usernames, password_file,
                          username_file, concurrency, timeout, delay, spray } => {
            // 配置文件回填
            let (password_file, username_file, concurrency, timeout) = if let Some(ref c) = cfg {
                let cp = c.crack.as_ref();
                (
                    password_file.or_else(|| cp.and_then(|p| p.password_file.clone())),
                    username_file.or_else(|| cp.and_then(|p| p.username_file.clone())),
                    if concurrency != 10 { concurrency } else {
                        cp.and_then(|p| p.concurrency).or(c.defaults.concurrency).unwrap_or(10)
                    },
                    if timeout != 5 { timeout } else {
                        cp.and_then(|p| p.timeout).or(c.defaults.timeout).unwrap_or(5)
                    },
                )
            } else {
                (password_file, username_file, concurrency, timeout)
            };
            cli::crack::run_crack_cmd(target, port, service, usernames,
                                      password_file, username_file,
                                      concurrency, timeout, delay, spray)
        }

        Commands::Tunnel { tunnel_type, target, local_port, remote_port,
                           hop, socks5_username, socks5_password,
                           max_connections, timeout, encryption_key } => {
            // 加密隧道尚未正确接线，显式报错而非静默跑明文
            if encryption_key.is_some() {
                print_error("--encryption-key 加密隧道尚未实现（当前版本加密管道未正确接线，使用会导致明文传输）。请等待后续版本。");
                std::process::exit(1);
            }
            // 配置文件回填
            let (max_connections, timeout) = if let Some(ref c) = cfg {
                let tp = c.tunnel.as_ref();
                (
                    if max_connections != 100 { max_connections } else {
                        tp.and_then(|t| t.max_connections).or(c.defaults.concurrency).unwrap_or(100)
                    },
                    if timeout != 30 { timeout } else {
                        tp.and_then(|t| t.timeout).or(c.defaults.timeout).unwrap_or(30)
                    },
                )
            } else {
                (max_connections, timeout)
            };
            cli::tunnel::run_tunnel_cmd(tunnel_type, target, local_port,
                                       remote_port, hop, socks5_username,
                                       socks5_password, max_connections, timeout,
                                       encryption_key)
        }

        Commands::Vuln { targets, poc_file, severity, category,
                         format, output, concurrency, timeout, web_probe } => {
            if web_probe {
                print_error("--web-probe Web 主动探测尚未实现（仅有 payload 生成器，无执行逻辑）。请等待后续版本。");
                std::process::exit(1);
            }
            let (concurrency, timeout) = if let Some(ref c) = cfg {
                (
                    if concurrency != 20 { concurrency } else {
                        c.defaults.concurrency.unwrap_or(20)
                    },
                    if timeout != 10 { timeout } else {
                        c.defaults.timeout.unwrap_or(10)
                    },
                )
            } else {
                (concurrency, timeout)
            };
            let format = apply_default_format(&cfg, &format);
            cli::vuln::run_vuln_cmd(targets, poc_file, severity, category,
                                    &format, output, concurrency, timeout, web_probe)
        }

        Commands::Cred { dc, domain, username, password, format, output } => {
            let format = apply_default_format(&cfg, &format);
            cli::cred::run_cred_cmd(dc, domain, username, password, &format, output)
        }

        Commands::Ad { dc, domain, username, password, ssl, mode,
                       bloodhound_dir, format, output,
                       golden_ticket, krbtgt_hash } => {
            if golden_ticket || krbtgt_hash.is_some() {
                print_error("--golden-ticket / --krbtgt-hash 尚未实现真实的 Kerberos 票据伪造（当前仅写 kirbi 文件）。请使用 mimikatz 替代。");
                std::process::exit(1);
            }
            match mode.as_str() {
                "dcsync" => {
                    print_error("AD --mode dcsync 尚未实现真实的 DRSUAPI 协议。请使用 mimikatz 或 impacket secretsdump.py 替代。");
                    std::process::exit(1);
                }
                "gpp" => {
                    print_info("AD --mode gpp 将搜索 SYSVOL 中的 GPP 密码文件并解密。");
                }
                "adcs" => {
                    print_info("AD --mode adcs 枚举 ADCS 证书服务（当前仅匿名绑定，ESC 检测有限）。");
                }
                _ => {}
            }
            let format = apply_default_format(&cfg, &format);
            cli::ad::run_ad_cmd(dc, domain, username, password, ssl,
                               mode, bloodhound_dir, &format, output,
                               golden_ticket, krbtgt_hash)
        }

        Commands::Recon { dc, domain, mode, format, output } => {
            let format = apply_default_format(&cfg, &format);
            cli::recon::run_recon_cmd(dc, domain, mode, &format, output)
        }

        Commands::Privesc { check, format, output } => {
            let format = apply_default_format(&cfg, &format);
            cli::privesc::run_privesc_cmd(check, &format, output)
        }

        Commands::Report { format, input, mitre, output } => {
            cli::report::run_report_cmd(format, mitre, output, input)
        }
    };

    if let Err(e) = result {
        print_error(&format!("{}", e));
        std::process::exit(1);
    }
}

/// 配置文件中的 defaults.format 作为 --format 的后备值
fn apply_default_format(cfg: &Option<core::config::AppConfig>, cli_format: &str) -> String {
    if cli_format != "json" {
        return cli_format.to_string();
    }
    cfg.as_ref()
        .and_then(|c| c.defaults.format.clone())
        .unwrap_or_else(|| cli_format.to_string())
}
