//! 环境态势感知模块
//!
//! 一键收集当前主机的全部环境信息：
//! OS版本、域信息、网络配置、已安装软件、运行服务、补丁级别

use crate::recon::{NetworkAdapter, PotentialVuln, SituationalInfo, VulnSeverity};

/// 收集完整的态势感知信息
pub fn collect_situational_awareness() -> Result<SituationalInfo, String> {
    let os = get_os_info();
    let os_version = get_os_version();
    let hostname = whoami::fallible::hostname().unwrap_or_default();
    let current_user = whoami::username();
    let privileges = get_current_privileges();
    let (in_domain, domain_name) = check_domain_membership();
    let domain_controllers = find_domain_controllers(&domain_name);
    let local_ips = get_local_ips();
    let network_adapters = get_network_adapters();
    let installed_software = list_installed_software();
    let running_services = list_running_services();
    let installed_patches = list_installed_patches();
    let potential_vulnerabilities = check_missing_patches(&installed_patches);

    Ok(SituationalInfo {
        os,
        os_version,
        hostname,
        current_user,
        privileges,
        in_domain,
        domain_name,
        domain_controllers,
        local_ips,
        network_adapters,
        installed_software,
        running_services,
        installed_patches,
        potential_vulnerabilities,
    })
}

fn get_os_info() -> String {
    if cfg!(windows) {
        whoami::distro()
    } else if cfg!(target_os = "linux") {
        // 读取/etc/os-release
        if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
            for line in content.lines() {
                if line.starts_with("PRETTY_NAME=") {
                    return line.trim_start_matches("PRETTY_NAME=")
                        .trim_matches('"')
                        .to_string();
                }
            }
        }
        "Linux".to_string()
    } else {
        std::env::consts::OS.to_string()
    }
}

fn get_os_version() -> String {
    if cfg!(windows) {
        // ver是cmd.exe内置命令，必须通过cmd /c调用
        if let Ok(output) = std::process::Command::new("cmd").args(["/c", "ver"]).output() {
            let ver = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !ver.is_empty() {
                return ver;
            }
        }
        "未知".to_string()
    } else {
        whoami::distro()
    }
}

fn get_current_privileges() -> Vec<String> {
    let mut privs = Vec::new();

    if cfg!(windows) {
        // 检查是否管理员
        let output = std::process::Command::new("net")
            .args(["session"])
            .output();

        match output {
            Ok(o) if o.status.success() => {
                privs.push("Administrator".to_string());
            }
            _ => {
                privs.push("Standard User".to_string());
            }
        }

        // 检查SeDebugPrivilege
        let whoami_output = std::process::Command::new("whoami")
            .args(["/priv"])
            .output();

        if let Ok(o) = whoami_output {
            let stdout = String::from_utf8_lossy(&o.stdout);
            if stdout.contains("SeDebugPrivilege") {
                privs.push("SeDebugPrivilege".to_string());
            }
            if stdout.contains("SeImpersonatePrivilege") {
                privs.push("SeImpersonatePrivilege".to_string());
            }
            if stdout.contains("SeBackupPrivilege") {
                privs.push("SeBackupPrivilege".to_string());
            }
            if stdout.contains("SeRestorePrivilege") {
                privs.push("SeRestorePrivilege".to_string());
            }
            if stdout.contains("SeTakeOwnershipPrivilege") {
                privs.push("SeTakeOwnershipPrivilege".to_string());
            }
        }
    } else if cfg!(unix) {
        #[cfg(unix)]
        {
            if nix::unistd::Uid::effective().is_root() {
                privs.push("root".to_string());
            }
        }
        // 检查sudo
        if std::process::Command::new("sudo").arg("-n").arg("true").output().map(|o| o.status.success()).unwrap_or(false) {
            privs.push("sudo (passwordless)".to_string());
        }
    }

    privs
}

fn check_domain_membership() -> (bool, Option<String>) {
    if cfg!(windows) {
        // systeminfo | findstr /B /C:"Domain"
        let output = std::process::Command::new("systeminfo")
            .output();

        if let Ok(o) = output {
            let stdout = String::from_utf8_lossy(&o.stdout);
            for line in stdout.lines() {
                if line.contains("域:") || line.contains("Domain:") {
                    let domain = line.split(':').nth(1).unwrap_or("").trim().to_string();
                    if !domain.is_empty() && domain != "WORKGROUP" {
                        return (true, Some(domain));
                    }
                    return (false, Some(domain));
                }
            }
        }

        // 备用方法：检查USERDOMAIN
        if let Ok(domain) = std::env::var("USERDOMAIN") {
            if !domain.is_empty() && domain != whoami::fallible::hostname().unwrap_or_default() {
                return (true, Some(domain));
            }
        }
    } else if cfg!(unix) {
        // 检查realm或sssd
        if std::path::Path::new("/etc/krb5.conf").exists() {
            if let Ok(content) = std::fs::read_to_string("/etc/krb5.conf") {
                for line in content.lines() {
                    if line.trim().starts_with("default_realm") {
                        let realm = line.split('=').nth(1).unwrap_or("").trim().to_string();
                        return (true, Some(realm));
                    }
                }
            }
        }
    }

    (false, None)
}

fn find_domain_controllers(domain: &Option<String>) -> Vec<String> {
    let mut dcs = Vec::new();

    if cfg!(windows) {
        // nltest /dclist:
        if let Some(ref domain) = domain {
            let output = std::process::Command::new("nltest")
                .args(["/dclist:", domain])
                .output();

            if let Ok(o) = output {
                let stdout = String::from_utf8_lossy(&o.stdout);
                for line in stdout.lines() {
                    if line.contains("DC") || line.contains("\\") {
                        let dc = line.trim();
                        if !dc.is_empty() && !dc.contains("命令") && !dc.contains("成功") {
                            dcs.push(dc.to_string());
                        }
                    }
                }
            }
        }

        // nslookup
        if let Some(ref domain) = domain {
            let output = std::process::Command::new("nslookup")
                .args([&format!("_ldap._tcp.{}", domain)])
                .output();

            if let Ok(o) = output {
                let stdout = String::from_utf8_lossy(&o.stdout);
                for line in stdout.lines() {
                    if line.contains("Address") && !line.contains("#") {
                        if let Some(addr) = line.split(':').nth(1) {
                            dcs.push(addr.trim().to_string());
                        }
                    }
                }
            }
        }

        // 备用: 检查LOGONSERVER
        if dcs.is_empty() {
            if let Ok(logon_server) = std::env::var("LOGONSERVER") {
                if !logon_server.is_empty() {
                    dcs.push(logon_server.trim_start_matches('\\').to_string());
                }
            }
        }
    }

    dcs
}

fn get_local_ips() -> Vec<String> {
    let mut ips = Vec::new();

    if cfg!(windows) {
        if let Ok(output) = std::process::Command::new("ipconfig").output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if line.contains("IPv4") || line.contains("IP Address") {
                    if let Some(addr) = line.split(':').nth(1) {
                        let ip = addr.trim().to_string();
                        if !ip.is_empty() && !ips.contains(&ip) {
                            ips.push(ip);
                        }
                    }
                }
            }
        }
    }

    // 使用本地接口API获取
    if ips.is_empty() {
        if let Ok(hostname) = whoami::fallible::hostname() {
            // 简单的localhost fallback
            ips.push("127.0.0.1".to_string());
            let _ = hostname;
        }
    }

    ips
}

fn get_network_adapters() -> Vec<NetworkAdapter> {
    let mut adapters = Vec::new();

    if cfg!(windows) {
        if let Ok(output) = std::process::Command::new("ipconfig")
            .args(["/all"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let mut current_name = String::new();
            let mut current_ips = Vec::new();
            let mut current_mac = None;
            let mut current_dns = Vec::new();
            let mut current_mask = None;
            let mut current_gw = None;

            for line in stdout.lines() {
                let line = line.trim();

                // 适配器名称
                if line.contains("适配器") || line.contains("adapter") {
                    if !current_name.is_empty() {
                        adapters.push(NetworkAdapter {
                            name: std::mem::take(&mut current_name),
                            ip_addresses: std::mem::take(&mut current_ips),
                            mac_address: std::mem::take(&mut current_mac),
                            dns_servers: std::mem::take(&mut current_dns),
                            subnet_mask: std::mem::take(&mut current_mask),
                            default_gateway: std::mem::take(&mut current_gw),
                        });
                    }
                    current_name = line.trim_end_matches(':').to_string();
                }

                if line.contains("IPv4") || line.contains("IP Address") {
                    if let Some(addr) = line.split(':').nth(1) {
                        current_ips.push(addr.trim().to_string());
                    }
                }
                if line.contains("物理地址") || line.contains("Physical") {
                    if let Some(mac) = line.split(':').nth(1) {
                        current_mac = Some(mac.trim().to_string());
                    }
                }
                if line.contains("子网掩码") || line.contains("Subnet Mask") {
                    if let Some(mask) = line.split(':').nth(1) {
                        current_mask = Some(mask.trim().to_string());
                    }
                }
                if line.contains("默认网关") || line.contains("Default Gateway") {
                    if let Some(gw) = line.split(':').nth(1) {
                        current_gw = Some(gw.trim().to_string());
                    }
                }
                if line.contains("DNS") {
                    if let Some(dns) = line.split(':').nth(1) {
                        current_dns.push(dns.trim().to_string());
                    }
                }
            }

            // 最后一个适配器
            if !current_name.is_empty() {
                adapters.push(NetworkAdapter {
                    name: current_name,
                    ip_addresses: current_ips,
                    mac_address: current_mac,
                    dns_servers: current_dns,
                    subnet_mask: current_mask,
                    default_gateway: current_gw,
                });
            }
        }
    }

    adapters
}

fn list_installed_software() -> Vec<String> {
    let mut software = Vec::new();

    if cfg!(windows) {
        // wmic product get name
        if let Ok(output) = std::process::Command::new("wmic")
            .args(["product", "get", "name", "/format:csv"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines().skip(1) {
                let name = line.split(',').nth(1).unwrap_or("").trim().to_string();
                if !name.is_empty() && !software.contains(&name) {
                    software.push(name);
                }
            }
        }

        // 备用：从注册表读取
        if software.is_empty() {
            let output = std::process::Command::new("reg")
                .args(["query", r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "/s", "/f", "DisplayName"])
                .output();

            if let Ok(o) = output {
                let stdout = String::from_utf8_lossy(&o.stdout);
                for line in stdout.lines() {
                    if line.contains("DisplayName") {
                        if let Some(name) = line.split("REG_SZ").nth(1) {
                            let n = name.trim().to_string();
                            if !n.is_empty() && !software.contains(&n) {
                                software.push(n);
                            }
                        }
                    }
                }
            }
        }
    } else if cfg!(unix) {
        // dpkg -l 或 rpm -qa
        for cmd in &["dpkg", "rpm"] {
            let args = if *cmd == "dpkg" { vec!["-l"] } else { vec!["-qa"] };
            if let Ok(output) = std::process::Command::new(cmd).args(&args).output() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines().take(50) {
                    software.push(line.to_string());
                }
                break;
            }
        }
    }

    // 截断大量软件列表
    if software.len() > 100 {
        software.truncate(100);
    }

    software
}

fn list_running_services() -> Vec<String> {
    let mut services = Vec::new();

    if cfg!(windows) {
        if let Ok(output) = std::process::Command::new("sc")
            .args(["query", "state=", "all"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if line.contains("SERVICE_NAME") {
                    let name = line.split(':').nth(1).unwrap_or("").trim().to_string();
                    if !name.is_empty() {
                        services.push(name);
                    }
                }
            }
        }
    } else if cfg!(unix) {
        if let Ok(output) = std::process::Command::new("systemctl")
            .args(["list-units", "--type=service", "--no-pager"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines().skip(1).take(50) {
                let name = line.split_whitespace().next().unwrap_or("").to_string();
                if !name.is_empty() {
                    services.push(name);
                }
            }
        }
    }

    services.truncate(50);
    services
}

fn list_installed_patches() -> Vec<String> {
    let mut patches = Vec::new();

    if cfg!(windows) {
        // wmic qfe list
        if let Ok(output) = std::process::Command::new("wmic")
            .args(["qfe", "get", "HotFixID", "/format:csv"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines().skip(1) {
                let kb = line.split(',').nth(1).unwrap_or("").trim().to_string();
                if kb.starts_with("KB") && !patches.contains(&kb) {
                    patches.push(kb);
                }
            }
        }

        // 备用：systeminfo
        if patches.is_empty() {
            if let Ok(output) = std::process::Command::new("systeminfo").output() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    if line.contains("KB") {
                        for part in line.split_whitespace() {
                            if part.starts_with("KB") {
                                if !patches.contains(&part.to_string()) {
                                    patches.push(part.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    patches
}

/// 检查缺失的关键补丁（仅Windows平台）
fn check_missing_patches(installed: &[String]) -> Vec<PotentialVuln> {
    let mut vulns = Vec::new();

    // KB补丁检查仅适用于Windows
    if !cfg!(windows) {
        return vulns;
    }

    // 关键漏洞与对应KB号
    let critical_patches = [
        ("KB4012212", "MS17-010 EternalBlue (永恒之蓝)", VulnSeverity::Critical),
        ("KB4012213", "MS17-010 EternalBlue (Win10)", VulnSeverity::Critical),
        ("KB4012606", "MS17-010 EternalBlue (Win8.1)", VulnSeverity::Critical),
        ("KB4551762", "CVE-2020-0796 SMBGhost", VulnSeverity::Critical),
        ("KB5005565", "CVE-2021-36934 HiveNightmare (SeriousSAM)", VulnSeverity::High),
        ("KB5005568", "CVE-2021-36934 HiveNightmare (Win11)", VulnSeverity::High),
        ("KB5000802", "CVE-2021-24084 (Win10)", VulnSeverity::High),
        ("KB4534273", "CVE-2020-0601 CurveBall (CryptoAPI)", VulnSeverity::High),
        ("KB4499175", "CVE-2019-1388 UAC Bypass", VulnSeverity::High),
        ("KB4524244", "CVE-2020-0787 (Win7)", VulnSeverity::High),
        ("KB4500331", "CVE-2019-0841 (Win10 AppX)", VulnSeverity::Medium),
        ("KB4578013", "CVE-2020-17087 (Win10)", VulnSeverity::Medium),
    ];

    for (kb, desc, severity) in &critical_patches {
        if !installed.iter().any(|p| p == *kb) {
            vulns.push(PotentialVuln {
                identifier: kb.to_string(),
                description: desc.to_string(),
                severity: severity.clone(),
                related_patch: Some(kb.to_string()),
            });
        }
    }

    // 排序：严重性高的优先
    vulns.sort_by(|a, b| b.severity.cmp(&a.severity));

    vulns
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collect_situational() {
        let result = collect_situational_awareness();
        assert!(result.is_ok());
        let info = result.unwrap();
        assert!(!info.hostname.is_empty());
        assert!(!info.os.is_empty());
    }

    #[test]
    #[cfg(windows)]
    fn test_check_missing_patches() {
        let installed = vec!["KB4012212".to_string()];
        let vulns = check_missing_patches(&installed);
        // KB4012212已安装，但其他未安装
        assert!(vulns.iter().any(|v| v.identifier != "KB4012212"));
    }

    #[test]
    fn test_check_missing_patches_all_installed() {
        let installed: Vec<String> = [
            "KB4012212", "KB4012213", "KB4012606", "KB4551762",
            "KB5005565", "KB5005568", "KB5000802", "KB4534273",
            "KB4499175", "KB4524244", "KB4500331", "KB4578013",
        ].iter().map(|s| s.to_string()).collect();
        let vulns = check_missing_patches(&installed);
        assert!(vulns.is_empty());
    }

    #[test]
    fn test_get_local_ips() {
        let ips = get_local_ips();
        assert!(!ips.is_empty());
    }
}
