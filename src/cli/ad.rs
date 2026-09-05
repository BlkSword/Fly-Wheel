//! AD 域深度枚举 CLI

use crate::cli::{print_banner, InteractiveMenu};
use crate::core::error::IntraSweepError;
use crate::core::Result;
use crate::output::color::{print_info, print_success};
use crate::output::format::OutputFormat;
use std::path::PathBuf;

/// 交互式向导返回参数：dc, domain, username, password, ssl, mode, bloodhound_dir
type AdWizardArgs = (
    String,
    String,
    Option<String>,
    Option<String>,
    bool,
    String,
    Option<PathBuf>,
);

pub fn run_ad_cmd(
    dc: Option<String>,
    domain: Option<String>,
    username: Option<String>,
    password: Option<String>,
    ssl: bool,
    mode: String,
    bloodhound_dir: Option<PathBuf>,
    format: &str,
    output: Option<PathBuf>,
    _golden_ticket: bool,
    _krbtgt_hash: Option<String>,
) -> Result<()> {
    let output_fmt = OutputFormat::parse(format).unwrap_or(OutputFormat::Json);

    // 无参数时进入交互式模式
    let (dc, domain, username, password, ssl, mode, bloodhound_dir) = match (dc, domain) {
        (Some(dc), Some(domain)) => (dc, domain, username, password, ssl, mode, bloodhound_dir),
        (dc_opt, domain_opt) => run_interactive_ad(
            dc_opt,
            domain_opt,
            username,
            password,
            ssl,
            mode,
            bloodhound_dir,
        )?,
    };

    let ad_label = "AD域枚举";
    print_info(&format!("开始{}...", ad_label));

    let mut config = crate::ad::ldap::LdapConfig::new(&dc, &domain).use_ssl(ssl);
    if let (Some(user), Some(pass)) = (&username, &password) {
        config = config.with_credentials(user, pass);
    }

    let rt = tokio::runtime::Runtime::new()?;
    let ad_err = |e: String| -> IntraSweepError { IntraSweepError::Other { message: e } };

    let result = match mode.as_str() {
        "kerberoast" => {
            let enumerator = crate::ad::ldap::AdEnumerator::new(config);
            let targets = rt.block_on(enumerator.kerberoast()).map_err(ad_err)?;
            print_kerberoast_results(&targets);
            save_ad_result(&output_fmt, &output, &serde_json::to_value(&targets)?)?;
            return Ok(());
        }
        "asrep-roast" => {
            let enumerator = crate::ad::ldap::AdEnumerator::new(config);
            let targets = rt.block_on(enumerator.asrep_roast()).map_err(ad_err)?;
            print_asrep_results(&targets);
            save_ad_result(&output_fmt, &output, &serde_json::to_value(&targets)?)?;
            return Ok(());
        }
        "bloodhound" => {
            let enumerator = crate::ad::ldap::AdEnumerator::new(config);
            let result = rt.block_on(enumerator.enumerate_all()).map_err(ad_err)?;
            let bh_dir =
                bloodhound_dir.unwrap_or_else(|| std::path::PathBuf::from("bloodhound_output"));
            crate::ad::bloodhound::export_bloodhound(&result, &bh_dir)?;
            print_success(&format!("BloodHound 数据已导出到: {}", bh_dir.display()));
            return Ok(());
        }
        "adcs" => {
            let result = crate::recon::adcs::enumerate_adcs(&dc, &domain).map_err(ad_err)?;
            print_adcs_results(&result);
            save_ad_result(&output_fmt, &output, &serde_json::to_value(&result)?)?;
            return Ok(());
        }
        "gpp" => {
            let creds = crate::cred::gpp::find_and_decrypt_gpp(&dc, &domain).map_err(ad_err)?;
            print_gpp_results(&creds);
            save_ad_result(&output_fmt, &output, &serde_json::to_value(&creds)?)?;
            return Ok(());
        }
        _ => {
            let enumerator = crate::ad::ldap::AdEnumerator::new(config);
            let result = rt.block_on(enumerator.enumerate_all()).map_err(ad_err)?;
            print_ad_enum_results(&result);
            result
        }
    };

    save_ad_result(&output_fmt, &output, &serde_json::to_value(&result)?)?;
    Ok(())
}

fn run_interactive_ad(
    initial_dc: Option<String>,
    initial_domain: Option<String>,
    initial_username: Option<String>,
    initial_password: Option<String>,
    initial_ssl: bool,
    initial_mode: String,
    initial_bloodhound_dir: Option<PathBuf>,
) -> Result<AdWizardArgs> {
    print_banner();
    println!();
    print_info("IntraSweep 交互式 AD 域枚举向导");
    println!();

    // 步骤 1: 域控 IP
    InteractiveMenu::print_step(1, 6, "域控制器");
    let dc = if let Some(d) = initial_dc {
        println!("已指定域控: {}", d);
        println!();
        d
    } else {
        InteractiveMenu::read_input_required("请输入域控 IP 地址: ", "域控 IP 不能为空")
    };
    print_success(&format!("域控: {}", dc));

    // 步骤 2: 域名
    InteractiveMenu::print_step(2, 6, "域名");
    let domain = if let Some(d) = initial_domain {
        println!("已指定域名: {}", d);
        println!();
        d
    } else {
        InteractiveMenu::read_input_required("请输入域名 (例: corp.local): ", "域名不能为空")
    };
    print_success(&format!("域名: {}", domain));

    // 步骤 3: 认证凭据
    InteractiveMenu::print_step(3, 6, "认证凭据 (可选)");
    println!("留空则使用匿名绑定");
    println!();
    let username = if initial_username.is_some() {
        println!("已指定用户名");
        initial_username
    } else {
        let u = InteractiveMenu::read_input("用户名 (留空=匿名): ");
        if u.is_empty() {
            None
        } else {
            Some(u)
        }
    };
    let password = if username.is_some() && initial_password.is_none() {
        let p = InteractiveMenu::read_input("密码: ");
        if p.is_empty() {
            None
        } else {
            Some(p)
        }
    } else {
        initial_password
    };
    if username.is_some() && password.is_some() {
        print_success("已设置认证凭据");
    } else {
        print_info("将使用匿名绑定");
    }

    // 步骤 4: 连接选项
    InteractiveMenu::print_step(4, 6, "连接选项");
    println!("LDAPS (端口 636) 可加密 LDAP 流量");
    println!();
    let ssl = if initial_ssl {
        print_info("已启用 LDAPS");
        true
    } else {
        let use_ssl = InteractiveMenu::read_input("是否使用 LDAPS? [y/N]: ");
        let ssl_enabled = use_ssl.to_lowercase() == "y";
        if ssl_enabled {
            print_success("已启用 LDAPS (端口 636)");
        } else {
            print_info("使用标准 LDAP (端口 389)");
        }
        ssl_enabled
    };

    // 步骤 5: 执行模式
    InteractiveMenu::print_step(5, 6, "执行模式");
    println!("  1. 完整枚举     - 用户、组、计算机、信任、GPO、Kerberoast、AS-REP");
    println!("  2. Kerberoast   - 仅提取 SPN 账户");
    println!("  3. AS-REP Roast - 仅查找预认证禁用用户");
    println!("  4. BloodHound   - 枚举并导出 BloodHound JSON");
    println!("  5. ADCS         - 枚举证书服务与可利用模板");
    println!("  6. GPP          - 搜索并解密 SYSVOL 中的 GPP 密码");
    println!();

    let default_mode = match initial_mode.as_str() {
        "kerberoast" => 2,
        "asrep-roast" => 3,
        "bloodhound" => 4,
        "adcs" => 5,
        "gpp" => 6,
        _ => 1,
    };
    let mode = if initial_mode != "all" {
        println!("已指定模式: {}", initial_mode);
        initial_mode
    } else {
        let choice = InteractiveMenu::read_number_opt("请选择 [1-6, 默认 1]: ", 1, 6, default_mode);
        let m = match choice {
            1 => "all".to_string(),
            2 => "kerberoast".to_string(),
            3 => "asrep-roast".to_string(),
            4 => "bloodhound".to_string(),
            5 => "adcs".to_string(),
            6 => "gpp".to_string(),
            _ => "all".to_string(),
        };
        print_success(&format!("已选择模式: {}", m));
        m
    };

    // 步骤 6: 确认
    let bloodhound_dir = if mode == "bloodhound" && initial_bloodhound_dir.is_none() {
        InteractiveMenu::print_step(6, 6, "BloodHound 输出目录");
        let dir = InteractiveMenu::read_input("输出目录 (默认: bloodhound_output): ");
        if dir.is_empty() {
            None
        } else {
            Some(PathBuf::from(dir))
        }
    } else {
        initial_bloodhound_dir
    };

    InteractiveMenu::print_step(6, 6, "配置确认");
    println!("  域控:         {}", dc);
    println!("  域名:         {}", domain);
    println!(
        "  认证:         {}",
        if username.is_some() {
            "已设置凭据"
        } else {
            "匿名绑定"
        }
    );
    println!(
        "  连接:         {}",
        if ssl { "LDAPS (636)" } else { "LDAP (389)" }
    );
    println!("  模式:         {}", mode);
    if let Some(ref bh) = bloodhound_dir {
        println!("  BloodHound:   {}", bh.display());
    }
    println!();

    if !InteractiveMenu::confirm("确认开始 AD 枚举? [Y/n]: ") {
        print_info("已取消");
        return Err(IntraSweepError::Other {
            message: "用户取消".to_string(),
        });
    }

    Ok((dc, domain, username, password, ssl, mode, bloodhound_dir))
}

fn save_ad_result(
    fmt: &OutputFormat,
    output: &Option<PathBuf>,
    data: &serde_json::Value,
) -> Result<()> {
    if let Some(path) = output {
        match fmt {
            OutputFormat::Json => {
                let content = serde_json::to_string_pretty(data)?;
                std::fs::write(&path, content)?;
            }
            OutputFormat::Csv => export_value_csv(&path, data)?,
        }
        print_success(&format!("结果已保存到: {}", path.display()));
    }
    Ok(())
}

/// 将 AD 结果转换为可用的 CSV；数组展开为多行，对象输出一行摘要
fn export_value_csv(path: &std::path::Path, data: &serde_json::Value) -> Result<()> {
    let mut wtr = csv::Writer::from_path(path)?;

    match data {
        serde_json::Value::Array(items) => {
            if items.is_empty() {
                wtr.write_record(["value"])?;
                wtr.write_record([""])?;
                wtr.flush()?;
                return Ok(());
            }

            let keys = collect_object_keys(items);
            if keys.is_empty() {
                wtr.write_record(["value"])?;
                for item in items {
                    wtr.write_record([scalar_value_to_string(item)])?;
                }
                wtr.flush()?;
                return Ok(());
            }

            wtr.write_record(&keys)?;
            for item in items {
                let values: Vec<String> = keys
                    .iter()
                    .map(|k| item.get(k).map(scalar_value_to_string).unwrap_or_default())
                    .collect();
                wtr.write_record(&values)?;
            }
        }
        serde_json::Value::Object(obj) => {
            let keys: Vec<String> = obj.keys().cloned().collect();
            wtr.write_record(&keys)?;
            let values: Vec<String> = keys
                .iter()
                .map(|k| obj.get(k).map(scalar_value_to_string).unwrap_or_default())
                .collect();
            wtr.write_record(&values)?;
        }
        other => {
            wtr.write_record(["value"])?;
            wtr.write_record([scalar_value_to_string(other)])?;
        }
    }

    wtr.flush()?;
    Ok(())
}

fn collect_object_keys(items: &[serde_json::Value]) -> Vec<String> {
    let mut keys = Vec::new();
    for item in items {
        if let Some(obj) = item.as_object() {
            for key in obj.keys() {
                if !keys.iter().any(|k| k == key) {
                    keys.push(key.clone());
                }
            }
        }
    }
    keys
}

fn scalar_value_to_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => String::new(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => s.clone(),
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

fn print_adcs_results(result: &crate::recon::adcs::AdcsEnumResult) {
    println!();
    println!("{}", "=".repeat(70));
    println!("║  ADCS 枚举结果");
    println!("║  CA 服务器: {}", result.ca_servers.len());
    println!("║  证书模板: {}", result.certificate_templates.len());
    println!("║  可利用配置: {}", result.exploitable_issues.len());
    println!("╠{}", "=".repeat(69));

    for issue in &result.exploitable_issues {
        println!(
            "║  [{}] {} - {}",
            issue.esc_type, issue.description, issue.severity
        );
    }

    println!("╚{}", "=".repeat(69));
}

fn print_gpp_results(creds: &[crate::cred::Credential]) {
    println!();
    println!("{}", "=".repeat(70));
    println!("║  GPP 解密结果 (共 {} 条)", creds.len());
    println!("╠{}", "=".repeat(69));
    for cred in creds {
        let username = cred.username.as_deref().unwrap_or("(未知用户)");
        println!("║  {} : *** | {}", username, cred.source);
    }
    println!("╚{}", "=".repeat(69));
}

fn print_ad_enum_results(result: &crate::ad::AdEnumResult) {
    println!("\n{}", "═".repeat(70));
    println!("║  AD 域枚举结果");
    println!("║  域名: {:<58}║", result.domain_name);
    if let Some(ref dc) = result.domain_controller {
        println!("║  域控: {:<58}║", dc);
    }
    println!("║  耗时: {:.2}s{:<51}║", result.duration_secs, "");
    println!("╠{}", "═".repeat(69));

    println!(
        "║  用户: {}  组: {}  计算机: {}",
        result.users.len(),
        result.groups.len(),
        result.computers.len()
    );
    println!(
        "║  Kerberoast目标: {}  AS-REP目标: {}",
        result.kerberoast_targets.len(),
        result.asrep_targets.len()
    );
    println!(
        "║  信任关系: {}  GPO: {}",
        result.trusts.len(),
        result.gpos.len()
    );

    let admin_count = result.users.iter().filter(|u| u.admin_count).count();
    let da_count = result
        .users
        .iter()
        .filter(|u| u.member_of.iter().any(|m| m.contains("Domain Admins")))
        .count();
    println!(
        "║  管理员账户: {}  Domain Admins: {}",
        admin_count, da_count
    );

    println!("╠{}", "═".repeat(69));

    if !result.kerberoast_targets.is_empty() {
        println!("║  Kerberoast 目标:");
        for t in result.kerberoast_targets.iter().take(10) {
            let status = if t.enabled { "启用" } else { "禁用" };
            println!(
                "║    {} ({}) SPN: {} [{}]",
                t.username, status, t.spn, t.service_type
            );
        }
        if result.kerberoast_targets.len() > 10 {
            println!(
                "║    ... 还有 {} 个目标",
                result.kerberoast_targets.len() - 10
            );
        }
    }

    if !result.asrep_targets.is_empty() {
        println!("║  AS-REP Roast 目标:");
        for t in &result.asrep_targets {
            let status = if t.enabled { "启用" } else { "禁用" };
            println!("║    {} ({})", t.username, status);
        }
    }

    println!("╚{}\n", "═".repeat(69));
}

fn print_kerberoast_results(targets: &[crate::ad::KerberoastTarget]) {
    println!("\n{}", "═".repeat(70));
    println!("║  Kerberoast 目标 (共 {} 个)", targets.len());
    println!("╠{}", "═".repeat(69));
    for t in targets.iter().take(20) {
        let status = if t.enabled { "启用" } else { "禁用" };
        let admin = if t.admin_count { " [管理员]" } else { "" };
        println!(
            "║  {} | {} | {} ({}){}",
            t.username, t.spn, t.service_type, status, admin
        );
    }
    if targets.len() > 20 {
        println!("║  ... 还有 {} 个目标", targets.len() - 20);
    }
    println!("╚{}\n", "═".repeat(69));
}

fn print_asrep_results(targets: &[crate::ad::AsrepTarget]) {
    println!("\n{}", "═".repeat(70));
    println!("║  AS-REP Roast 目标 (共 {} 个)", targets.len());
    println!("╠{}", "═".repeat(69));
    for t in targets {
        let status = if t.enabled { "启用" } else { "禁用" };
        println!("║  {} ({})", t.username, status);
    }
    println!("╚{}\n", "═".repeat(69));
}
