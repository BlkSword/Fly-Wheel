//! Windows 提权检查
//!
//! 检测 Windows 系统上的常见提权向量

use super::{PrivescFinding, PrivescResult, PrivescSeverity, PrivescStats};
use std::process::Command;

/// 运行所有 Windows 提权检查
pub fn run_checks() -> PrivescResult {
    let hostname = whoami::fallible::hostname().unwrap_or_else(|_| "unknown".to_string());
    let os = System::os_version();
    let current_user = whoami::username();
    let is_admin = check_admin();

    let mut findings = Vec::new();

    // 服务相关
    findings.extend(check_unquoted_service_paths());
    findings.extend(check_weak_service_permissions());
    findings.extend(check_always_install_elevated());
    findings.extend(check_writable_service_binaries());

    // 凭据相关
    findings.extend(check_stored_credentials());
    findings.extend(check_auto_logon());
    findings.extend(check_sam_access());

    // 令牌特权
    findings.extend(check_token_privileges());

    // 敏感文件
    findings.extend(check_sensitive_files());

    // 补丁
    findings.extend(check_patches());

    // DLL 劫持
    findings.extend(check_dll_hijacking());

    let stats = compute_stats(&findings);

    PrivescResult {
        hostname,
        os,
        current_user,
        is_admin,
        findings,
        stats,
    }
}

/// 运行指定类别检查
pub fn run_category(category: &str) -> Vec<PrivescFinding> {
    match category {
        "service" => {
            let mut f = Vec::new();
            f.extend(check_unquoted_service_paths());
            f.extend(check_weak_service_permissions());
            f.extend(check_writable_service_binaries());
            f
        }
        "credentials" => {
            let mut f = Vec::new();
            f.extend(check_stored_credentials());
            f.extend(check_auto_logon());
            f.extend(check_sam_access());
            f
        }
        "registry" => {
            check_always_install_elevated()
        }
        "tokens" => check_token_privileges(),
        "files" => check_sensitive_files(),
        "patches" => check_patches(),
        "dll" => check_dll_hijacking(),
        _ => Vec::new(),
    }
}

struct System;

impl System {
    fn os_version() -> String {
        let output = Command::new("cmd")
            .args(["/C", "ver"])
            .output();
        match output {
            Ok(o) => String::from_utf8_lossy(&o.stdout).trim().to_string(),
            Err(_) => "Windows".to_string(),
        }
    }
}

fn check_admin() -> bool {
    Command::new("net")
        .args(["session"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn run_cmd(cmd: &str, args: &[&str]) -> Option<String> {
    Command::new(cmd).args(args).output().ok().map(|o| {
        String::from_utf8_lossy(&o.stdout).to_string()
    })
}

/// 通过 PowerShell 执行命令（替代已弃用的 wmic）
fn run_powershell(command: &str) -> Option<String> {
    run_cmd("powershell", &["-NoProfile", "-NonInteractive", "-Command", command])
}

/// 解析 CSV 行（处理引号内的逗号和转义引号）
fn parse_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '"' if in_quotes => {
                if chars.peek() == Some(&'"') {
                    current.push('"');
                    chars.next();
                } else {
                    in_quotes = false;
                }
            }
            '"' => in_quotes = true,
            ',' if !in_quotes => {
                fields.push(std::mem::take(&mut current));
            }
            _ => current.push(c),
        }
    }
    fields.push(current);
    fields
}

// ============================================================
// 服务相关检查
// ============================================================

fn check_unquoted_service_paths() -> Vec<PrivescFinding> {
    let mut findings = Vec::new();
    let Some(output) = run_powershell(
        "Get-CimInstance Win32_Service | Select-Object Name,PathName,StartMode | ConvertTo-Csv -NoTypeInformation",
    ) else {
        return findings;
    };

    for line in output.lines().skip(1) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let fields = parse_csv_line(line);
        if fields.len() < 2 {
            continue;
        }

        let service_name = fields[0].trim().to_string();
        let path = fields[1].trim().to_string();
        if path.is_empty() || !path.contains(' ') || !path.contains(':') {
            continue;
        }

        // 检查是否未加引号且路径含空格
        if !path.starts_with('"') && path.contains(' ') {
            findings.push(PrivescFinding {
                category: "服务".to_string(),
                severity: PrivescSeverity::High,
                title: "未引用的服务路径".to_string(),
                description: format!("服务 '{}' 的可执行路径包含空格且未用引号包裹", service_name),
                detail: format!("路径: {}", path),
                remediation: "在注册表中为服务路径添加引号，或将可执行文件移动到无空格路径".to_string(),
            });
        }
    }

    findings
}

fn check_weak_service_permissions() -> Vec<PrivescFinding> {
    let mut findings = Vec::new();

    // 使用 sc query 枚举服务，然后检查关键服务
    let Some(output) = run_cmd("sc", &["query"]) else {
        return findings;
    };
    let mut service_names = Vec::new();

    for line in output.lines() {
        if line.contains("SERVICE_NAME:") {
            let name = line.split(':').nth(1).map(|s| s.trim().to_string());
            if let Some(name) = name {
                service_names.push(name);
            }
        }
    }

    // 检查是否可以修改关键服务
    for name in service_names.iter().take(20) {
        // 尝试查询服务配置
        if let Some(qc_output) = run_cmd("sc", &["qc", name]) {
            // 检查服务二进制路径
            if qc_output.contains("BINARY_PATH_NAME") {
                let bin_path = qc_output
                    .lines()
                    .find(|l| l.contains("BINARY_PATH_NAME"))
                    .and_then(|l| l.split(':').nth(1))
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default();

                // 检查是否在用户可写目录
                let user_writable = bin_path.contains("\\Users\\")
                    || bin_path.contains("\\Temp\\")
                    || bin_path.contains("\\AppData\\");

                if user_writable {
                    findings.push(PrivescFinding {
                        category: "服务".to_string(),
                        severity: PrivescSeverity::Critical,
                        title: "服务二进制路径可写".to_string(),
                        description: format!("服务 '{}' 的二进制文件位于可能可写的路径", name),
                        detail: format!("路径: {}", bin_path),
                        remediation: "将服务二进制文件移动到受保护的系统目录".to_string(),
                    });
                }
            }
        }
    }

    findings
}

fn check_writable_service_binaries() -> Vec<PrivescFinding> {
    let mut findings = Vec::new();
    let Some(output) = run_powershell(
        "Get-CimInstance Win32_Service | Select-Object Name,PathName | ConvertTo-Csv -NoTypeInformation",
    ) else {
        return findings;
    };

    for line in output.lines().skip(1) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let fields = parse_csv_line(trimmed);
        if fields.len() < 2 {
            continue;
        }

        let raw_path = fields[1].trim().to_string();
        if raw_path.is_empty() || !raw_path.contains(':') {
            continue;
        }

        // 提取可执行文件路径（去除可能的参数和引号）
        let path = if raw_path.starts_with('"') {
            raw_path.split('"').nth(1).unwrap_or("").to_string()
        } else {
            raw_path.split_whitespace().next().unwrap_or("").to_string()
        };

        if path.is_empty() || !path.contains(':') {
            continue;
        }

        // 检查文件是否可写
        if let Ok(metadata) = std::fs::metadata(&path) {
            if !metadata.permissions().readonly() {
                // 进一步检查是否在系统目录
                if !path.to_lowercase().starts_with("c:\\windows\\") {
                    findings.push(PrivescFinding {
                        category: "服务".to_string(),
                        severity: PrivescSeverity::High,
                        title: "非系统目录的服务二进制".to_string(),
                        description: "服务二进制文件不在系统目录中，可能存在写入权限".to_string(),
                        detail: format!("路径: {}", path),
                        remediation: "检查文件权限，确保只有管理员可写".to_string(),
                    });
                }
            }
        }
    }

    findings
}

fn check_always_install_elevated() -> Vec<PrivescFinding> {
    let mut findings = Vec::new();

    // 检查 HKLM 和 HKCU 的 AlwaysInstallElevated
    let hklm = run_cmd("reg", &["query", r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer", "/v", "AlwaysInstallElevated"]);
    let hkcu = run_cmd("reg", &["query", r"HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer", "/v", "AlwaysInstallElevated"]);

    let hklm_enabled = hklm.map(|o| o.contains("0x1")).unwrap_or(false);
    let hkcu_enabled = hkcu.map(|o| o.contains("0x1")).unwrap_or(false);

    if hklm_enabled && hkcu_enabled {
        findings.push(PrivescFinding {
            category: "注册表".to_string(),
            severity: PrivescSeverity::Critical,
            title: "AlwaysInstallElevated 已启用".to_string(),
            description: "MSI 安装包以 SYSTEM 权限运行，任何用户安装的 MSI 都能获得最高权限".to_string(),
            detail: "HKLM 和 HKCU 的 AlwaysInstallElevated 均设置为 1".to_string(),
            remediation: "禁用 AlwaysInstallElevated 策略".to_string(),
        });
    }

    findings
}

// ============================================================
// 凭据相关检查
// ============================================================

fn check_stored_credentials() -> Vec<PrivescFinding> {
    let mut findings = Vec::new();

    // 检查 cmdkey 存储的凭据
    if let Some(output) = run_cmd("cmdkey", &["/list"]) {
        let cred_count = output.lines().filter(|l| l.contains("Target:")).count();
        if cred_count > 0 {
            findings.push(PrivescFinding {
                category: "凭据".to_string(),
                severity: PrivescSeverity::High,
                title: "存储的 Windows 凭据".to_string(),
                description: format!("系统存储了 {} 条凭据，可能包含明文密码", cred_count),
                detail: output.chars().take(500).collect(),
                remediation: "使用 'cmdkey /delete' 删除不需要的存储凭据".to_string(),
            });
        }
    }

    findings
}

fn check_auto_logon() -> Vec<PrivescFinding> {
    let mut findings = Vec::new();

    if let Some(output) = run_cmd("reg", &["query", r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "/v", "DefaultPassword"]) {
        if output.contains("DefaultPassword") && !output.contains("未找到") {
            findings.push(PrivescFinding {
                category: "凭据".to_string(),
                severity: PrivescSeverity::Critical,
                title: "自动登录密码泄露".to_string(),
                description: "注册表中存储了自动登录的明文密码".to_string(),
                detail: "注册表路径: HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\DefaultPassword".to_string(),
                remediation: "删除 DefaultPassword 注册表值，禁用自动登录".to_string(),
            });
        }
    }

    findings
}

fn check_sam_access() -> Vec<PrivescFinding> {
    let mut findings = Vec::new();

    let sam_paths = [
        r"C:\Windows\repair\SAM",
        r"C:\Windows\repair\SYSTEM",
        r"C:\Windows\System32\config\RegBack\SAM",
        r"C:\Windows\System32\config\RegBack\SYSTEM",
    ];

    for path in sam_paths {
        if std::fs::metadata(path).is_ok() {
            findings.push(PrivescFinding {
                category: "凭据".to_string(),
                severity: PrivescSeverity::Critical,
                title: "SAM/SYSTEM 文件可访问".to_string(),
                description: "SAM 或 SYSTEM 注册表配置文件可被读取，可导出密码哈希".to_string(),
                detail: format!("文件路径: {}", path),
                remediation: "限制文件访问权限，确保只有 SYSTEM 账户可读取".to_string(),
            });
        }
    }

    findings
}

// ============================================================
// 令牌特权检查
// ============================================================

fn check_token_privileges() -> Vec<PrivescFinding> {
    let mut findings = Vec::new();

    if let Some(output) = run_cmd("whoami", &["/priv"]) {
        let high_priv = [
            ("SeDebugPrivilege", "调试程序", "可注入任意进程，包括 SYSTEM 进程"),
            ("SeImpersonatePrivilege", "模拟客户端", "可模拟高权限令牌（土豆系列提权）"),
            ("SeAssignPrimaryTokenPrivilege", "分配主令牌", "可分配新进程令牌"),
            ("SeLoadDriverPrivilege", "加载驱动", "可加载未签名内核驱动"),
            ("SeTakeOwnershipPrivilege", "取得所有权", "可取得任意文件/注册表所有权"),
            ("SeBackupPrivilege", "备份文件", "可读取任意文件，包括 SAM/SYSTEM"),
            ("SeRestorePrivilege", "恢复文件", "可写入任意文件，包括系统文件"),
            ("SeCreateTokenPrivilege", "创建令牌", "可创建任意权限的令牌"),
        ];

        for (priv_name, display_name, impact) in &high_priv {
            if output.contains(priv_name) {
                findings.push(PrivescFinding {
                    category: "令牌特权".to_string(),
                    severity: PrivescSeverity::High,
                    title: format!("高特权令牌: {}", display_name),
                    description: format!("当前用户持有 {} 特权，{}", display_name, impact),
                    detail: format!("特权: {}", priv_name),
                    remediation: "从用户账户中移除不必要的高特权".to_string(),
                });
            }
        }
    }

    findings
}

// ============================================================
// 敏感文件检查
// ============================================================

fn check_sensitive_files() -> Vec<PrivescFinding> {
    let mut findings = Vec::new();

    let sensitive_paths = [
        (r"C:\Windows\Panther\Unattend.xml", "Windows 无人值守安装文件", PrivescSeverity::Critical),
        (r"C:\Windows\Panther\Unattend.xml.bak", "Windows 无人值守安装备份", PrivescSeverity::Critical),
        (r"C:\Windows\System32\sysprep\unattend.xml", "Sysprep 配置文件", PrivescSeverity::Critical),
        (r"C:\Windows\System32\sysprep\Panther\unattend.xml", "Sysprep Panther 配置", PrivescSeverity::High),
        (r"C:\Users\*\AppData\Local\Microsoft\Credentials", "Windows 凭据目录", PrivescSeverity::High),
        (r"C:\Users\*\AppData\Roaming\Microsoft\Credentials", "Windows 凭据目录", PrivescSeverity::High),
    ];

    for (path, desc, severity) in &sensitive_paths {
        // 处理通配符
        if path.contains('*') {
            if let Some(parent) = path.split('*').next() {
                if let Ok(entries) = std::fs::read_dir(parent) {
                    for entry in entries.flatten() {
                        let suffix = path.split('*').nth(1).unwrap_or("");
                        let full_path = format!("{}{}{}", entry.path().display(), if suffix.starts_with('\\') { "" } else { "\\" }, suffix.trim_start_matches('\\'));
                        if std::fs::metadata(&full_path).is_ok() {
                            findings.push(PrivescFinding {
                                category: "敏感文件".to_string(),
                                severity: *severity,
                                title: desc.to_string(),
                                description: format!("发现{}，可能包含明文密码或凭据", desc),
                                detail: format!("路径: {}", full_path),
                                remediation: "删除文件或限制访问权限".to_string(),
                            });
                        }
                    }
                }
            }
        } else if std::fs::metadata(path).is_ok() {
            findings.push(PrivescFinding {
                category: "敏感文件".to_string(),
                severity: *severity,
                title: desc.to_string(),
                description: format!("发现{}，可能包含明文密码或凭据", desc),
                detail: format!("路径: {}", path),
                remediation: "删除文件或限制访问权限".to_string(),
            });
        }
    }

    findings
}

// ============================================================
// 补丁检查
// ============================================================

fn check_patches() -> Vec<PrivescFinding> {
    let mut findings = Vec::new();

    if let Some(output) = run_powershell(
        "Get-CimInstance Win32_QuickFixEngineering | Select-Object HotFixID,InstalledOn | ConvertTo-Csv -NoTypeInformation",
    ) {
        // 检查已知高危漏洞对应的补丁
        let critical_patches = [
            ("KB4534271", "CVE-2020-0796 (SMBv3压缩RCE)"),
            ("KB4522010", "CVE-2019-1405 / CVE-2019-1322"),
            ("KB4486161", "CVE-2019-0604 (SharePoint RCE)"),
            ("KB4517245", "CVE-2019-1215"),
        ];

        for (kb, vuln) in &critical_patches {
            if !output.contains(kb) {
                findings.push(PrivescFinding {
                    category: "补丁".to_string(),
                    severity: PrivescSeverity::High,
                    title: format!("缺少安全补丁: {}", kb),
                    description: format!("系统未安装 {}，影响漏洞: {}", kb, vuln),
                    detail: format!("建议安装 {} 以修复安全漏洞", kb),
                    remediation: format!("安装 Windows Update 补丁 {}", kb),
                });
            }
        }
    }

    findings
}

// ============================================================
// DLL 劫持检查
// ============================================================

/// 检查目录是否可写（通过尝试创建临时文件）
fn is_dir_writable(dir: &str) -> bool {
    let test_file = std::path::Path::new(dir).join(format!(".intrasweep_probe_{}", std::process::id()));
    if std::fs::write(&test_file, b"probe").is_ok() {
        let _ = std::fs::remove_file(&test_file);
        true
    } else {
        false
    }
}

/// 获取所有服务的 (Name, PathName) 列表
fn get_service_paths() -> Vec<(String, String)> {
    let Some(output) = run_powershell(
        "Get-CimInstance Win32_Service | Select-Object Name,PathName | ConvertTo-Csv -NoTypeInformation",
    ) else {
        return Vec::new();
    };

    let mut services = Vec::new();
    for line in output.lines().skip(1) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let fields = parse_csv_line(line);
        if fields.len() >= 2 {
            let name = fields[0].trim().to_string();
            let path = fields[1].trim().to_string();
            if !name.is_empty() && !path.is_empty() {
                services.push((name, path));
            }
        }
    }
    services
}

/// 从服务 PathName 中提取可执行文件路径
fn extract_exe_path(raw_path: &str) -> String {
    let p = raw_path.trim();
    if p.starts_with('"') {
        p.split('"').nth(1).unwrap_or("").to_string()
    } else {
        // 无引号时取第一个空格前的部分（可能是 exe 路径）
        // 但如果路径含空格且无引号，取到 .exe 为止
        if let Some(idx) = p.to_lowercase().find(".exe") {
            p[..idx + 4].to_string()
        } else {
            p.split_whitespace().next().unwrap_or("").to_string()
        }
    }
}

/// DLL 劫持综合检查
fn check_dll_hijacking() -> Vec<PrivescFinding> {
    let mut findings = Vec::new();
    findings.extend(check_dll_unquoted_service_paths());
    findings.extend(check_writable_path_dirs());
    findings.extend(check_missing_service_dlls());
    findings
}

/// 检查服务未引用路径（DLL 劫持视角）
fn check_dll_unquoted_service_paths() -> Vec<PrivescFinding> {
    let mut findings = Vec::new();

    for (name, raw_path) in get_service_paths() {
        let path = extract_exe_path(&raw_path);
        if path.is_empty() || !path.contains(':') {
            continue;
        }

        // 未加引号且路径含空格 → DLL 搜索路径可能被劫持
        if !raw_path.starts_with('"') && path.contains(' ') {
            // 检查路径中的目录是否存在且可写
            if let Some(parent) = std::path::Path::new(&path).parent() {
                if let Some(dir_str) = parent.to_str() {
                    if is_dir_writable(dir_str) {
                        findings.push(PrivescFinding {
                            category: "DLL 劫持".to_string(),
                            severity: PrivescSeverity::High,
                            title: "服务未引用路径可被 DLL 劫持".to_string(),
                            description: format!(
                                "服务 '{}' 的路径含空格且未加引号，其目录可写，攻击者可放置恶意 DLL",
                                name
                            ),
                            detail: format!("路径: {}\n目录: {}", raw_path, dir_str),
                            remediation: "为服务路径添加引号，并限制目录写入权限".to_string(),
                        });
                    }
                }
            }
        }
    }

    findings
}

/// 检查 %PATH% 中可写的目录
fn check_writable_path_dirs() -> Vec<PrivescFinding> {
    let mut findings = Vec::new();

    let Ok(path_var) = std::env::var("PATH") else {
        return findings;
    };

    for dir in path_var.split(';') {
        let dir = dir.trim();
        if dir.is_empty() {
            continue;
        }

        let Ok(metadata) = std::fs::metadata(dir) else {
            continue;
        };
        if !metadata.is_dir() {
            continue;
        }

        // 跳过系统保护目录
        let lower = dir.to_lowercase();
        if lower.starts_with("c:\\windows\\")
            || lower.starts_with("c:\\program files\\")
            || lower.starts_with("c:\\program files (x86)\\")
        {
            continue;
        }

        if is_dir_writable(dir) {
            findings.push(PrivescFinding {
                category: "DLL 劫持".to_string(),
                severity: PrivescSeverity::High,
                title: "PATH 中存在可写目录".to_string(),
                description: format!(
                    "目录 '{}' 在系统 PATH 中且当前用户可写，攻击者可放置恶意 DLL 被其他程序加载",
                    dir
                ),
                detail: format!("可写 PATH 目录: {}", dir),
                remediation: "移除 PATH 中不必要的目录，或限制目录写入权限".to_string(),
            });
        }
    }

    findings
}

/// 检查服务目录中缺失或可写的 DLL
fn check_missing_service_dlls() -> Vec<PrivescFinding> {
    let mut findings = Vec::new();

    // 常见可被劫持的 DLL 名称
    let common_dlls = [
        "version.dll", "winmm.dll", "dwmapi.dll", "wbemcomn.dll",
        "profapi.dll", "cryptbase.dll", "amsi.dll", "uxtheme.dll",
        "dxva2.dll", "msftedit.dll", "propsys.dll", "secur32.dll",
    ];

    for (name, raw_path) in get_service_paths() {
        let exe_path = extract_exe_path(&raw_path);
        if exe_path.is_empty() || !exe_path.contains(':') {
            continue;
        }

        let Some(parent) = std::path::Path::new(&exe_path).parent() else {
            continue;
        };
        let Some(dir_str) = parent.to_str() else {
            continue;
        };

        // 跳过系统目录（系统 DLL 受 SFP 保护）
        let lower_dir = dir_str.to_lowercase();
        if lower_dir.starts_with("c:\\windows\\system32")
            || lower_dir.starts_with("c:\\windows\\syswow64")
        {
            continue;
        }

        for dll_name in &common_dlls {
            let dll_path = parent.join(dll_name);
            if dll_path.exists() {
                // DLL 存在 — 检查是否可写
                if let Ok(metadata) = std::fs::metadata(&dll_path) {
                    if !metadata.permissions().readonly() {
                        findings.push(PrivescFinding {
                            category: "DLL 劫持".to_string(),
                            severity: PrivescSeverity::High,
                            title: "服务目录中 DLL 可写".to_string(),
                            description: format!(
                                "服务 '{}' 目录中的 {} 文件可写，可被替换为恶意 DLL",
                                name, dll_name
                            ),
                            detail: format!("DLL 路径: {}", dll_path.display()),
                            remediation: "限制 DLL 文件权限，确保只有管理员可写".to_string(),
                        });
                    }
                }
            } else {
                // DLL 不存在 — 如果目录可写，攻击者可放置恶意 DLL
                if is_dir_writable(dir_str) {
                    findings.push(PrivescFinding {
                        category: "DLL 劫持".to_string(),
                        severity: PrivescSeverity::Medium,
                        title: "服务目录缺少常见 DLL".to_string(),
                        description: format!(
                            "服务 '{}' 目录中不存在 {}，若服务加载该 DLL 则可被劫持",
                            name, dll_name
                        ),
                        detail: format!("目录: {}\n缺失 DLL: {}", dir_str, dll_name),
                        remediation: "确认服务是否加载该 DLL，限制目录写入权限".to_string(),
                    });
                }
            }
        }
    }

    findings
}

fn compute_stats(findings: &[PrivescFinding]) -> PrivescStats {
    PrivescStats {
        total_checks: findings.len(),
        critical_count: findings.iter().filter(|f| f.severity == PrivescSeverity::Critical).count(),
        high_count: findings.iter().filter(|f| f.severity == PrivescSeverity::High).count(),
        medium_count: findings.iter().filter(|f| f.severity == PrivescSeverity::Medium).count(),
        low_count: findings.iter().filter(|f| f.severity == PrivescSeverity::Low).count(),
        info_count: findings.iter().filter(|f| f.severity == PrivescSeverity::Info).count(),
    }
}
