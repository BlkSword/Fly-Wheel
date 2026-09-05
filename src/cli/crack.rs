//! 爆破 CLI
//!
//! 处理密码爆破子命令的交互式配置向导和直接模式

use crate::cli::{colorize, print_banner, InteractiveMenu};
use crate::core::error::IntraSweepError;
use crate::core::Result;
use crate::cracker::service::Cracker;
use crate::cracker::{CrackConfig, CrackService, DictManager};
use crate::output::color::{print_error, print_info, print_success, Color};

/// 爆破命令入口
pub fn run_crack_cmd(
    target: Option<String>,
    port: Option<u16>,
    service: Option<String>,
    usernames: Option<String>,
    password_file: Option<String>,
    username_file: Option<String>,
    concurrency: usize,
    timeout: u64,
    delay: Option<u64>,
    spray: bool,
) -> Result<()> {
    // 密码喷射模式：对支持快速认证测试的服务走 SprayEngine（少量密码 × 大量用户）
    if spray {
        let supported = service
            .as_deref()
            .map(|s| matches!(s.to_lowercase().as_str(), "ssh" | "winrm"))
            .unwrap_or(false);
        if supported {
            return run_spray(
                target,
                port,
                service.unwrap(),
                usernames,
                username_file,
                password_file,
            );
        }
        print_info("密码喷射当前仅支持 SSH/WinRM，其余服务回退到普通爆破模式");
    }

    match target {
        Some(target) => run_crack(
            target,
            port,
            service,
            usernames,
            password_file,
            username_file,
            concurrency,
            timeout,
            delay,
        ),
        None => run_interactive_crack(
            port,
            service,
            usernames,
            password_file,
            username_file,
            concurrency,
            timeout,
            delay,
        ),
    }
}

/// 运行密码喷射（SSH/WinRM）
///
/// 使用少量高价值密码对大量用户名轮次尝试，轮次间冷却以防账户锁定。
fn run_spray(
    target: Option<String>,
    port: Option<u16>,
    service: String,
    usernames: Option<String>,
    username_file: Option<String>,
    _password_file: Option<String>,
) -> Result<()> {
    use crate::cracker::spray::{SprayConfig, SprayEngine};

    let target = match target {
        Some(t) => t,
        None => {
            print_error("密码喷射需要指定目标主机");
            return Ok(());
        }
    };

    let service_type = match service.to_lowercase().as_str() {
        "ssh" => CrackService::Ssh,
        "winrm" => CrackService::Winrm,
        other => {
            print_error(&format!("密码喷射不支持服务: {}", other));
            return Ok(());
        }
    };

    // 解析用户名列表
    let mut dict = DictManager::new();
    if let Some(uf) = username_file {
        if let Err(e) = dict.load_usernames_from_file(&uf) {
            print_error(&format!("加载用户名字典失败: {}", e));
            return Err(IntraSweepError::Other {
                message: "加载用户名字典失败".to_string(),
            });
        }
    } else if let Some(u) = usernames {
        let list: Vec<String> = u
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        dict.set_usernames(list);
    }

    let user_list = dict.usernames().to_vec();
    if user_list.is_empty() {
        print_error("密码喷射需要用户名列表（--usernames 或 --username-file）");
        return Ok(());
    }

    // 喷射密码：少量高价值密码（满足常见复杂度策略）
    let spray_passwords = vec![
        "P@ssw0rd".to_string(),
        "Password123!".to_string(),
        "Welcome2024!".to_string(),
        "Admin@123".to_string(),
        "1qaz@WSX".to_string(),
    ];

    let mut config = SprayConfig::new(&target, service_type);
    if let Some(p) = port {
        config = config.with_port(p);
    }
    config = config
        .with_usernames(user_list.clone())
        .with_passwords(spray_passwords.clone())
        .with_cooldown(30)
        .with_lock_threshold(5);

    println!();
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  密码喷射 (Password Spray)");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  目标:     {}:{}", config.target, config.port);
    println!("  服务:     {}", service_type.name());
    println!("  用户数:   {}", user_list.len());
    println!(
        "  密码数:   {} (每轮1个，轮间冷却 {}s)",
        spray_passwords.len(),
        config.cooldown_secs
    );
    println!("  锁阈值:   {} (接近时冷却翻倍)", config.lock_threshold);
    println!();

    let engine = SprayEngine::new(config);
    let rt = tokio::runtime::Runtime::new()?;
    let result = rt.block_on(engine.round_spray())?;

    println!();
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  喷射结果");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  成功:     {} 个凭据", result.success_count);
    println!("  总尝试:   {}", result.total_attempts);
    println!("  失败:     {}", result.failure_count);
    println!("  预估锁定: {}", result.estimated_lockouts);
    println!("  耗时:     {} ms", result.elapsed_ms);

    if !result.credentials.is_empty() {
        println!();
        print_success(&format!("命中 {} 组凭据:", result.credentials.len()));
        for (user, pass) in &result.credentials {
            println!("    {} : {}", user, pass);
        }
    }
    println!();

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
    print_info(&format!(
        "IntraSweep 交互式{}配置向导",
        crate::core::obfstr::sensitive::crack_label()
    ));
    println!();

    // 步骤 1: 目标主机
    InteractiveMenu::print_step(1, 8, "目标主机");
    println!("输入格式示例:");
    println!("  IP地址:       192.168.1.1");
    println!("  域名:         example.com");
    println!();

    let target =
        InteractiveMenu::read_input_required("请输入目标主机: ", "目标不能为空，请重新输入");
    print_success(&format!("已设置目标: {}", target));

    // 步骤 2: 服务类型
    let service = if let Some(s) = &initial_service {
        InteractiveMenu::print_step(2, 8, "服务类型");
        println!("已指定: {}", s);
        println!();
        s.clone()
    } else {
        InteractiveMenu::print_step(2, 8, "服务类型");
        println!("  1. SSH       - SSH 爆破 (默认端口: 22)");
        println!("  2. RDP       - RDP 爆破 (默认端口: 3389)");
        println!("  3. Redis     - Redis 爆破 (默认端口: 6379)");
        println!("  4. Postgres  - PostgreSQL 爆破 (默认端口: 5432)");
        println!("  5. MongoDB   - MongoDB 爆破 (默认端口: 27017)");
        println!("  6. MSSQL     - MSSQL 爆破 (默认端口: 1433)");
        println!("  7. MySQL     - MySQL 爆破 (默认端口: 3306)");
        println!("  8. WinRM     - WinRM 爆破 (默认端口: 5985)");
        println!();

        let choice = InteractiveMenu::read_number_opt("请选择服务类型 [1-8, 默认 1]: ", 1, 8, 1);
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
        print_success(&format!("已选择: {}", service.to_uppercase()));
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
    InteractiveMenu::print_step(3, 8, "端口");
    let default_port = service_type.default_port();

    let port = if let Some(p) = initial_port {
        println!("已指定端口: {}", p);
        println!();
        p
    } else {
        let p = InteractiveMenu::read_port(
            &format!("请输入端口 (默认: {}): ", default_port),
            default_port,
        );
        print_success(&format!("已设置端口: {}", p));
        p
    };

    // 步骤 4: 用户名配置
    let (usernames, username_file) = if service_type.requires_username() {
        InteractiveMenu::print_step(4, 8, "用户名配置");
        println!("  1. 手动输入用户名 (逗号分隔)");
        println!("  2. 从文件加载用户名字典");
        println!("  3. 使用默认用户名列表");
        println!();

        let choice = InteractiveMenu::read_number_opt("请选择 [1-3, 默认 3]: ", 1, 3, 3);

        match choice {
            1 => {
                let input = InteractiveMenu::read_input("请输入用户名 (多个用逗号分隔): ");
                print_success("已设置用户名");
                (Some(input), None)
            }
            2 => {
                let file = loop {
                    let file = InteractiveMenu::read_input("请输入用户名字典文件路径: ");
                    match DictManager::validate_dict_file(&file) {
                        Ok(count) => {
                            print_success(&format!("字典文件验证通过 (包含 {} 个用户名)", count));
                            break Some(file);
                        }
                        Err(e) => {
                            print_error(&format!("字典文件验证失败: {}", e));
                            let retry = InteractiveMenu::read_input("是否重新输入? [Y/n]: ");
                            if retry.to_lowercase() == "n" {
                                print_info("将使用默认用户名列表");
                                break None;
                            }
                        }
                    }
                };
                (None, file)
            }
            3 => {
                print_info("将使用默认用户名列表");
                (None, None)
            }
            _ => (None, None),
        }
    } else {
        (None, None)
    };

    // 步骤 5: 密码字典
    InteractiveMenu::print_step(5, 8, "密码字典");

    let password_file = if initial_password_file.is_some() {
        println!("已指定密码字典文件");
        println!();
        initial_password_file
    } else {
        println!("  1. 从文件加载密码字典");
        println!("  2. 使用默认密码字典");
        println!();

        let choice = InteractiveMenu::read_number_opt("请选择 [1-2, 默认 2]: ", 1, 2, 2);

        match choice {
            1 => {
                loop {
                    let file = InteractiveMenu::read_input("请输入密码字典文件路径: ");
                    println!();

                    // 验证字典文件
                    match DictManager::validate_dict_file(&file) {
                        Ok(count) => {
                            print_success(&format!("字典文件验证通过 (包含 {} 个密码)", count));
                            println!();
                            break Some(file);
                        }
                        Err(e) => {
                            print_error(&format!("字典文件验证失败: {}", e));
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
    InteractiveMenu::print_step(6, 8, "性能配置");

    let concurrency = if initial_concurrency == 10 {
        let input = InteractiveMenu::read_input("并发数 (默认: 10): ");
        let c = if input.is_empty() {
            10
        } else {
            input.parse::<usize>().unwrap_or(10)
        };
        print_success(&format!("已设置并发数: {}", c));
        c
    } else {
        println!("已指定并发数: {}", initial_concurrency);
        initial_concurrency
    };

    let timeout = if initial_timeout == 5 {
        let input = InteractiveMenu::read_input("超时时间/秒 (默认: 5): ");
        let t = if input.is_empty() {
            5
        } else {
            input.parse::<u64>().unwrap_or(5)
        };
        print_success(&format!("已设置超时: {} 秒", t));
        t
    } else {
        println!("已指定超时: {} 秒", initial_timeout);
        initial_timeout
    };

    // 步骤 7: 高级选项
    InteractiveMenu::print_step(7, 8, "高级选项");

    let delay = if initial_delay.is_some() {
        println!("已指定延迟");
        initial_delay
    } else {
        let input = InteractiveMenu::read_input("设置延迟/毫秒，可选 (按 Enter 跳过): ");
        if input.is_empty() {
            print_info("未设置延迟");
            None
        } else {
            match input.parse::<u64>() {
                Ok(d) => {
                    print_success(&format!("已设置延迟: {} 毫秒", d));
                    Some(d)
                }
                Err(_) => {
                    print_error("输入无效，未设置延迟");
                    None
                }
            }
        }
    };

    // 步骤 8: 确认配置
    InteractiveMenu::print_step(8, 8, "确认配置");
    println!("  目标主机:     {}", target);
    println!(
        "  服务类型:     {} (端口: {})",
        service.to_uppercase(),
        port
    );
    println!("  并发数:       {}", concurrency);
    println!("  超时:         {} 秒", timeout);
    if let Some(ref d) = delay {
        println!("  延迟:         {} 毫秒", d);
    }
    println!();

    if !InteractiveMenu::confirm("确认开始爆破? [Y/n]: ") {
        print_info("已取消爆破");
        return Ok(());
    }

    // 密码喷洒模式（仅 SSH：少量密码 × 大量用户，轮间冷却防账户锁定）
    if service.to_lowercase() == "ssh" {
        let spray = InteractiveMenu::read_input("使用密码喷洒模式?（SSH，防账户锁定）[y/N]: ");
        if spray.to_lowercase() == "y" {
            return run_spray(
                Some(target),
                Some(port),
                service,
                usernames,
                username_file,
                password_file,
            );
        }
    }

    // 调用 run_crack 执行爆破
    run_crack(
        target,
        Some(port),
        Some(service),
        usernames,
        password_file,
        username_file,
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

    // 显示摘要
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
                    return Err(IntraSweepError::Other {
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
                return Err(IntraSweepError::Other {
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

    // 执行爆破
    let rt = tokio::runtime::Runtime::new()?;

    // 创建进度条
    use indicatif::{ProgressBar, ProgressStyle};
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .expect("创建进度条样式失败"),
    );
    pb.set_message("正在爆破...");
    pb.enable_steady_tick(std::time::Duration::from_millis(100));

    // 根据服务类型选择爆破器
    let result = rt.block_on(async {
        match service_type {
            CrackService::Ssh => {
                let cracker = crate::cracker::ssh::SshCracker::new();
                cracker.crack(&config).await
            }
            CrackService::Rdp => {
                let cracker = crate::cracker::rdp::RdpCracker::new();
                cracker.crack(&config).await
            }
            CrackService::Redis => {
                let cracker = crate::cracker::redis_crack::RedisCracker::new();
                cracker.crack(&config).await
            }
            CrackService::Postgres => {
                let cracker = crate::cracker::postgres::PostgresCracker::new();
                cracker.crack(&config).await
            }
            CrackService::Mysql => {
                let cracker = crate::cracker::mysql::MysqlCracker::new();
                cracker.crack(&config).await
            }
            CrackService::Mssql => {
                let cracker = crate::cracker::mssql::MssqlCracker::new();
                cracker.crack(&config).await
            }
            CrackService::Mongodb => {
                let cracker = crate::cracker::mongodb_crack::MongodbCracker::new();
                cracker.crack(&config).await
            }
            CrackService::Winrm => {
                let cracker = crate::cracker::winrm::WinrmCracker::new();
                cracker.crack(&config).await
            }
        }
    });

    pb.finish_with_message("爆破完成");
    println!();

    // 显示结果
    if result.is_success() {
        println!("╔════════════════════════════════════════════════════════════════════════════╗");
        println!(
            "║  {}",
            colorize(
                &format!("{}!", crate::core::obfstr::sensitive::crack_success_label()),
                Color::BrightGreen
            )
        );
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
        println!(
            "║  {}",
            colorize(
                &crate::core::obfstr::sensitive::crack_failed_label(),
                Color::BrightRed
            )
        );
        println!("╠════════════════════════════════════════════════════════════════════════════╣");
        println!("║  目标:        {}:{}", result.target, result.port);
        println!("║  服务:        {}", result.service);
        println!("║  消息:        {}", result.message);
        println!("╚════════════════════════════════════════════════════════════════════════════╝");
    }
    println!();

    Ok(())
}
