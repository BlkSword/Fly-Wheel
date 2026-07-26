//! Linux 提权检查
//!
//! 检测 Linux 系统上的常见提权向量

use super::{PrivescFinding, PrivescResult, PrivescSeverity, PrivescStats};
use std::process::Command;

/// 运行所有 Linux 提权检查
pub fn run_checks() -> PrivescResult {
    // is_root check
    fn is_root() -> bool {
        std::process::Command::new("id")
            .arg("-u")
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
            .unwrap_or(false)
    }

    let hostname = whoami::fallible::hostname().unwrap_or_else(|_| "unknown".to_string());
    let os = run_cmd_str("uname", &["-a"]);
    let current_user = whoami::username();
    let is_admin = is_root();

    let mut findings = Vec::new();

    findings.extend(check_suid_binaries());
    findings.extend(check_capabilities());
    findings.extend(check_cron_jobs());
    findings.extend(check_writable_etc());
    findings.extend(check_docker_group());
    findings.extend(check_sudo_rules());
    findings.extend(check_ssh_keys());
    findings.extend(check_kernel_exploits());

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
        "suid" => check_suid_binaries(),
        "capabilities" => check_capabilities(),
        "cron" => check_cron_jobs(),
        "writable" => check_writable_etc(),
        "docker" => check_docker_group(),
        "sudo" => check_sudo_rules(),
        "ssh" => check_ssh_keys(),
        "kernel" => check_kernel_exploits(),
        _ => Vec::new(),
    }
}

fn run_cmd_str(cmd: &str, args: &[&str]) -> String {
    Command::new(cmd)
        .args(args)
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

// ============================================================
// SUID/SGID 检查
// ============================================================

fn check_suid_binaries() -> Vec<PrivescFinding> {
    let mut findings = Vec::new();

    let output = run_cmd_str("find", &["/", "-perm", "-4000", "-type", "f", "-executable", "2>/dev/null"]);
    if output.is_empty() {
        return findings;
    }

    // 已知可利用的 SUID 二进制（GTFOBins）
    let exploitable = [
        ("/usr/bin/find", "find"),
        ("/usr/bin/vim", "vim"),
        ("/usr/bin/vi", "vi"),
        ("/usr/bin/nano", "nano"),
        ("/usr/bin/less", "less"),
        ("/usr/bin/more", "more"),
        ("/usr/bin/bash", "bash"),
        ("/usr/bin/sh", "sh"),
        ("/usr/bin/dash", "dash"),
        ("/usr/bin/python", "python"),
        ("/usr/bin/python3", "python3"),
        ("/usr/bin/perl", "perl"),
        ("/usr/bin/ruby", "ruby"),
        ("/usr/bin/lua", "lua"),
        ("/usr/bin/awk", "awk"),
        ("/usr/bin/tar", "tar"),
        ("/usr/bin/cp", "cp"),
        ("/usr/bin/mv", "mv"),
        ("/usr/bin/ntfs-3g", "ntfs-3g"),
        ("/usr/bin/strace", "strace"),
        ("/usr/bin/ltrace", "ltrace"),
        ("/usr/bin/env", "env"),
        ("/usr/bin/nohup", "nohup"),
        ("/usr/bin/time", "time"),
        ("/usr/bin/tee", "tee"),
        ("/usr/bin/base64", "base64"),
        ("/usr/bin/xxd", "xxd"),
    ];

    let mut found_exploitable = Vec::new();
    for line in output.lines() {
        let path = line.trim();
        if exploitable.iter().any(|(p, _)| *p == path) {
            found_exploitable.push(path.to_string());
        }
    }

    if !found_exploitable.is_empty() {
        findings.push(PrivescFinding {
            category: "SUID".to_string(),
            severity: PrivescSeverity::High,
            title: "可利用的 SUID 二进制".to_string(),
            description: format!("发现 {} 个已知可利用的 SUID 二进制文件", found_exploitable.len()),
            detail: found_exploitable.join("\n"),
            remediation: "移除不必要的 SUID 权限: chmod u-s <path>".to_string(),
        });
    }

    // 报告非标准 SUID
    let standard_suids = [
        "/usr/bin/passwd", "/usr/bin/sudo", "/usr/bin/su",
        "/usr/bin/chsh", "/usr/bin/chfn", "/usr/bin/newgrp",
        "/usr/bin/gpasswd", "/usr/bin/mount", "/usr/bin/umount",
        "/usr/bin/pkexec",
    ];

    let non_standard: Vec<&str> = output.lines()
        .map(|l| l.trim())
        .filter(|p| !exploitable.iter().any(|(ep, _)| *ep == *p))
        .filter(|p| !standard_suids.contains(&(*p).to_string().as_str()))
        .filter(|p| !p.is_empty())
        .collect();

    if !non_standard.is_empty() {
        findings.push(PrivescFinding {
            category: "SUID".to_string(),
            severity: PrivescSeverity::Medium,
            title: "非标准 SUID 二进制".to_string(),
            description: format!("发现 {} 个非标准 SUID 文件", non_standard.len()),
            detail: non_standard.iter().map(|s| s.to_string()).collect::<Vec<_>>().join("\n"),
            remediation: "审查这些文件的来源和必要性".to_string(),
        });
    }

    findings
}

// ============================================================
// Capabilities 检查
// ============================================================

fn check_capabilities() -> Vec<PrivescFinding> {
    let mut findings = Vec::new();

    let output = run_cmd_str("getcap", &["-r", "/", "2>/dev/null"]);
    if output.is_empty() {
        return findings;
    }

    let dangerous_caps = [
        ("cap_setuid", "可设置用户ID，直接提权"),
        ("cap_setgid", "可设置组ID，提升组权限"),
        ("cap_sys_admin", "系统管理员能力，接近 root"),
        ("cap_sys_ptrace", "可调试进程，注入代码"),
        ("cap_dac_override", "绕过文件权限检查"),
        ("cap_dac_read_search", "绕过文件读取权限"),
        ("cap_net_raw", "原始网络访问，可嗅探流量"),
        ("cap_net_admin", "网络管理能力"),
    ];

    let mut found_dangerous = Vec::new();
    for line in output.lines() {
        for (cap, desc) in &dangerous_caps {
            if line.contains(cap) {
                found_dangerous.push(format!("{} ({})", line.trim(), desc));
            }
        }
    }

    if !found_dangerous.is_empty() {
        findings.push(PrivescFinding {
            category: "Capabilities".to_string(),
            severity: PrivescSeverity::High,
            title: "危险的文件 Capabilities".to_string(),
            description: format!("发现 {} 个具有危险 capabilities 的文件", found_dangerous.len()),
            detail: found_dangerous.join("\n"),
            remediation: "使用 setcap -r <path> 移除不必要的 capabilities".to_string(),
        });
    }

    findings
}

// ============================================================
// Cron 检查
// ============================================================

fn check_cron_jobs() -> Vec<PrivescFinding> {
    let mut findings = Vec::new();

    let cron_paths = [
        "/etc/crontab",
        "/etc/cron.d/",
        "/var/spool/cron/",
    ];

    for path in &cron_paths {
        let meta = if path.ends_with('/') {
            std::fs::read_dir(path).ok().map(|_| true)
        } else {
            std::fs::metadata(path).ok().map(|_| true)
        };

        if meta.is_some() {
            // 检查是否可写 — 尝试以追加方式打开
            let test_path = format!("{}.intrasweep_test", path);
            let writable = std::fs::OpenOptions::new()
                
                .append(true)
                .open(&test_path)
                .is_ok();
            if writable {
                let _ = std::fs::remove_file(&test_path);
                findings.push(PrivescFinding {
                    category: "Cron".to_string(),
                    severity: PrivescSeverity::Critical,
                    title: "可写的 Cron 配置".to_string(),
                    description: "Cron 配置文件或目录可被当前用户写入".to_string(),
                    detail: format!("路径: {}", path),
                    remediation: "限制 cron 配置文件权限为 600 或 644".to_string(),
                });
            }
        }
    }

    // 检查当前用户的 crontab
    let user_cron = run_cmd_str("crontab", &["-l"]);
    if !user_cron.is_empty() && !user_cron.contains("no crontab") {
        findings.push(PrivescFinding {
            category: "Cron".to_string(),
            severity: PrivescSeverity::Info,
            title: "用户 Crontab 条目".to_string(),
            description: "当前用户有 crontab 条目".to_string(),
            detail: user_cron.chars().take(500).collect(),
            remediation: "检查 crontab 条目是否引用了可写的脚本".to_string(),
        });
    }

    findings
}

// ============================================================
// 可写 /etc 检查
// ============================================================

fn check_writable_etc() -> Vec<PrivescFinding> {
    let mut findings = Vec::new();

    let etc_files = [
        ("/etc/passwd", "用户数据库", PrivescSeverity::Critical),
        ("/etc/shadow", "密码哈希", PrivescSeverity::Critical),
        ("/etc/sudoers", "Sudo 配置", PrivescSeverity::Critical),
        ("/etc/hosts", "DNS 解析", PrivescSeverity::Medium),
        ("/etc/resolv.conf", "DNS 配置", PrivescSeverity::Low),
    ];

    for (path, desc, severity) in &etc_files {
        if std::fs::metadata(path).is_ok() {
            // 尝试写入检测
            let test_path = format!("{}.intrasweep_test", path);
            let writable = std::fs::OpenOptions::new()
                
                .append(true)
                .open(&test_path)
                .is_ok();
            if writable {
                let _ = std::fs::remove_file(&test_path);
                findings.push(PrivescFinding {
                    category: "可写文件".to_string(),
                    severity: *severity,
                    title: format!("可写的 {} ({})", desc, path),
                    description: format!("{} 文件可被当前用户写入", desc),
                    detail: format!("路径: {}", path),
                    remediation: format!("chmod o-w {}", path),
                });
            }
        }
    }

    findings
}

// ============================================================
// Docker 组检查
// ============================================================

fn check_docker_group() -> Vec<PrivescFinding> {
    let mut findings = Vec::new();

    let groups = run_cmd_str("id", &["-nG"]);
    if groups.split_whitespace().any(|g| g == "docker") {
        findings.push(PrivescFinding {
            category: "Docker".to_string(),
            severity: PrivescSeverity::Critical,
            title: "Docker 组成员".to_string(),
            description: "当前用户在 docker 组中，可通过挂载根文件系统获取 root 权限".to_string(),
            detail: "docker run -v /:/host -it alpine chroot /host".to_string(),
            remediation: "将用户从 docker 组移除，或使用 rootless docker".to_string(),
        });
    }

    findings
}

// ============================================================
// Sudo 规则检查
// ============================================================

fn check_sudo_rules() -> Vec<PrivescFinding> {
    let mut findings = Vec::new();

    let output = run_cmd_str("sudo", &["-l"]);
    if output.is_empty() || output.contains("a password") && !output.contains("NOPASSWD") {
        // 需要密码且没有 NOPASSWD，不一定是漏洞
        return findings;
    }

    // 检查危险 sudo 规则
    let dangerous_commands = [
        ("(ALL) NOPASSWD: ALL", "无密码全权限 sudo", PrivescSeverity::Critical),
        ("NOPASSWD: /bin/bash", "无密码 root shell", PrivescSeverity::Critical),
        ("NOPASSWD: /bin/sh", "无密码 root shell", PrivescSeverity::Critical),
        ("NOPASSWD: /usr/bin/find", "可通过 find 提权", PrivescSeverity::High),
        ("NOPASSWD: /usr/bin/vim", "可通过 vim 提权", PrivescSeverity::High),
        ("NOPASSWD: /usr/bin/python", "可通过 python 提权", PrivescSeverity::High),
        ("NOPASSWD: /usr/bin/perl", "可通过 perl 提权", PrivescSeverity::High),
        ("NOPASSWD: /usr/bin/less", "可通过 less 提权", PrivescSeverity::High),
        ("NOPASSWD: /usr/bin/tar", "可通过 tar 提权", PrivescSeverity::High),
        ("NOPASSWD: /usr/bin/apt", "可通过 apt 提权", PrivescSeverity::High),
        ("NOPASSWD: /usr/bin/yum", "可通过 yum 提权", PrivescSeverity::High),
        ("NOPASSWD: /usr/bin/systemctl", "可通过 systemctl 提权", PrivescSeverity::High),
    ];

    for (pattern, desc, severity) in &dangerous_commands {
        if output.contains(pattern) {
            findings.push(PrivescFinding {
                category: "Sudo".to_string(),
                severity: *severity,
                title: format!("危险 sudo 规则: {}", desc),
                description: format!("sudo 配置允许: {}", pattern),
                detail: output.chars().take(500).collect(),
                remediation: "限制 sudo 规则到最小必要命令集".to_string(),
            });
        }
    }

    findings
}

// ============================================================
// SSH 密钥检查
// ============================================================

fn check_ssh_keys() -> Vec<PrivescFinding> {
    let mut findings = Vec::new();

    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    let ssh_dir = format!("{}/.ssh", home);

    let key_files = [
        ("id_rsa", "RSA 私钥"),
        ("id_ed25519", "Ed25519 私钥"),
        ("id_ecdsa", "ECDSA 私钥"),
        ("id_dsa", "DSA 私钥"),
    ];

    for (file, desc) in &key_files {
        let path = format!("{}/{}", ssh_dir, file);
        if std::fs::metadata(&path).is_ok() {
            findings.push(PrivescFinding {
                category: "SSH".to_string(),
                severity: PrivescSeverity::High,
                title: format!("发现 {}", desc),
                description: format!("在 {} 目录发现 {} 文件", ssh_dir, desc),
                detail: format!("路径: {}", path),
                remediation: "确保私钥文件权限为 600，考虑使用密码保护私钥".to_string(),
            });
        }
    }

    // 检查 authorized_keys
    let auth_keys = format!("{}/authorized_keys", ssh_dir);
    if std::fs::metadata(&auth_keys).is_ok() {
        if let Ok(content) = std::fs::read_to_string(&auth_keys) {
            let key_count = content.lines().filter(|l| !l.is_empty() && !l.starts_with('#')).count();
            if key_count > 0 {
                findings.push(PrivescFinding {
                    category: "SSH".to_string(),
                    severity: PrivescSeverity::Info,
                    title: "SSH 授权密钥".to_string(),
                    description: format!("authorized_keys 中有 {} 条授权密钥", key_count),
                    detail: format!("路径: {}", auth_keys),
                    remediation: "审查授权密钥列表，移除不必要的密钥".to_string(),
                });
            }
        }
    }

    // 检查其他用户的 SSH 密钥
    if std::fs::metadata("/home").is_ok() {
        if let Ok(entries) = std::fs::read_dir("/home") {
            for entry in entries.flatten() {
                let user_ssh = format!("{}/.ssh/id_rsa", entry.path().display());
                if std::fs::metadata(&user_ssh).is_ok() {
                    findings.push(PrivescFinding {
                        category: "SSH".to_string(),
                        severity: PrivescSeverity::Medium,
                        title: "其他用户的 SSH 私钥".to_string(),
                        description: "发现其他用户目录下的 SSH 私钥文件".to_string(),
                        detail: format!("路径: {}", user_ssh),
                        remediation: "确保私钥文件权限正确（600）且不可被其他用户读取".to_string(),
                    });
                }
            }
        }
    }

    findings
}

// ============================================================
// 内核漏洞检查
// ============================================================

fn check_kernel_exploits() -> Vec<PrivescFinding> {
    let mut findings = Vec::new();

    let kernel_version = run_cmd_str("uname", &["-r"]);
    if kernel_version.is_empty() {
        return findings;
    }

    // 已知内核漏洞
    let kernel_exploits = [
        ("3.10.0", "3.10.999", "CVE-2021-4034 (PwnKit)", PrivescSeverity::Critical),
        ("4.4.0", "4.4.999", "CVE-2022-0847 (Dirty Pipe)", PrivescSeverity::Critical),
        ("4.1.0", "5.8.13", "CVE-2021-3156 (Baron Samedit)", PrivescSeverity::Critical),
        ("2.6.22", "4.8.2", "CVE-2016-5195 (Dirty Cow)", PrivescSeverity::Critical),
        ("4.10.0", "5.1.16", "CVE-2019-18634 (sudo pwfeedback)", PrivescSeverity::High),
    ];

    for (min_ver, max_ver, cve, severity) in &kernel_exploits {
        if is_kernel_in_range(&kernel_version, min_ver, max_ver) {
            findings.push(PrivescFinding {
                category: "内核".to_string(),
                severity: *severity,
                title: format!("潜在内核漏洞: {}", cve),
                description: format!("当前内核 {} 可能受 {} 影响", kernel_version, cve),
                detail: format!("内核版本: {}", kernel_version),
                remediation: "更新内核到最新安全版本".to_string(),
            });
        }
    }

    findings
}

fn is_kernel_in_range(version: &str, min: &str, max: &str) -> bool {
    let ver = parse_kernel_version(version);
    let min_v = parse_kernel_version(min);
    let max_v = parse_kernel_version(max);

    if ver.is_empty() || min_v.is_empty() || max_v.is_empty() {
        return false;
    }

    ver >= min_v && ver <= max_v
}

fn parse_kernel_version(version: &str) -> Vec<u32> {
    version
        .split(['.', '-'])
        .filter_map(|s| s.parse().ok())
        .collect()
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
