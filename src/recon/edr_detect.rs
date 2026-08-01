//! EDR/AV安全软件检测模块
//!
//! 帮助攻击者选择合适的免杀技术和规避策略。
//!
//! 检测方法：
//! 1. 进程名匹配
//! 2. 服务名匹配
//! 3. 注册表键检测
//! 4. 文件系统检测
//! 5. WMI查询

use serde::{Deserialize, Serialize};

/// 安全产品信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityProduct {
    /// 产品名称
    pub name: String,
    /// 厂商
    pub vendor: String,
    /// 产品类型（AV/EDR/XDR/Firewall/DLP等）
    pub product_type: SecurityProductType,
    /// 检测方法
    pub detection_method: String,
    /// 是否运行中
    pub is_running: bool,
    /// 进程名
    pub process_name: Option<String>,
    /// 可执行文件路径
    pub executable_path: Option<String>,
    /// 版本
    pub version: Option<String>,
}

/// 安全产品类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SecurityProductType {
    /// 防病毒
    Antivirus,
    /// 终端检测与响应
    EDR,
    /// 扩展检测与响应
    XDR,
    /// 主机入侵防御
    HIPS,
    /// 防火墙
    Firewall,
    /// 数据防泄漏
    DLP,
    /// 应用白名单
    ApplicationControl,
    /// 未知
    Unknown,
}

impl std::fmt::Display for SecurityProductType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecurityProductType::Antivirus => write!(f, "AV"),
            SecurityProductType::EDR => write!(f, "EDR"),
            SecurityProductType::XDR => write!(f, "XDR"),
            SecurityProductType::HIPS => write!(f, "HIPS"),
            SecurityProductType::Firewall => write!(f, "防火墙"),
            SecurityProductType::DLP => write!(f, "DLP"),
            SecurityProductType::ApplicationControl => write!(f, "应用白名单"),
            SecurityProductType::Unknown => write!(f, "未知"),
        }
    }
}

/// EDR/AV签名数据库
struct SecuritySignature {
    name: &'static str,
    vendor: &'static str,
    product_type: SecurityProductType,
    process_names: &'static [&'static str],
    service_names: &'static [&'static str],
    registry_keys: &'static [&'static str],
    file_paths: &'static [&'static str],
}

/// 已知安全产品签名
const KNOWN_SECURITY_PRODUCTS: &[SecuritySignature] = &[
    // Microsoft Defender
    SecuritySignature {
        name: "Microsoft Defender Antivirus",
        vendor: "Microsoft",
        product_type: SecurityProductType::Antivirus,
        process_names: &["MsMpEng.exe", "NisSrv.exe", "SecurityHealthService.exe", "MsSense.exe"],
        service_names: &["WinDefend", "WdNisSvc", "Sense"],
        registry_keys: &[r"SOFTWARE\Microsoft\Windows Defender"],
        file_paths: &[r"C:\ProgramData\Microsoft\Windows Defender"],
    },
    // Microsoft Defender for Endpoint (EDR)
    SecuritySignature {
        name: "Microsoft Defender for Endpoint",
        vendor: "Microsoft",
        product_type: SecurityProductType::EDR,
        process_names: &["MsSense.exe", "SenseCncProxy.exe", "SenseIR.exe"],
        service_names: &["Sense"],
        registry_keys: &[r"SOFTWARE\Microsoft\Windows Advanced Threat Protection"],
        file_paths: &[r"C:\Program Files\Windows Defender Advanced Threat Protection"],
    },
    // CrowdStrike Falcon
    SecuritySignature {
        name: "CrowdStrike Falcon",
        vendor: "CrowdStrike",
        product_type: SecurityProductType::EDR,
        process_names: &["CSFalconService.exe", "CSFalconContainer.exe"],
        service_names: &["CSFalconService", "CSAgent"],
        registry_keys: &[r"SYSTEM\CrowdStrike"],
        file_paths: &[r"C:\Windows\System32\drivers\CrowdStrike"],
    },
    // Carbon Black
    SecuritySignature {
        name: "Carbon Black",
        vendor: "VMware",
        product_type: SecurityProductType::EDR,
        process_names: &["CbDefense.exe", "CbSensor.exe", "RepMgr.exe", "RepUtils.exe"],
        service_names: &["CarbonBlack", "CbDefense", "CbSensor"],
        registry_keys: &[r"SOFTWARE\CarbonBlack"],
        file_paths: &[r"C:\Program Files\Confer"],
    },
    // SentinelOne
    SecuritySignature {
        name: "SentinelOne",
        vendor: "SentinelOne",
        product_type: SecurityProductType::EDR,
        process_names: &["SentinelAgent.exe", "SentinelAgentWorker.exe", "SentinelStaticEngine.exe"],
        service_names: &["SentinelAgent"],
        registry_keys: &[r"SOFTWARE\SentinelOne"],
        file_paths: &[r"C:\Program Files\SentinelOne"],
    },
    // Trend Micro
    SecuritySignature {
        name: "Trend Micro Apex One",
        vendor: "Trend Micro",
        product_type: SecurityProductType::Antivirus,
        process_names: &["PccNTMon.exe", "ntrtscan.exe", "TMBMSRV.exe", "TmListen.exe"],
        service_names: &["TMBMServer", "TmFilter", "tmwfp", "ntrtscan"],
        registry_keys: &[r"SOFTWARE\TrendMicro"],
        file_paths: &[r"C:\Program Files\Trend Micro"],
    },
    // Symantec Endpoint Protection
    SecuritySignature {
        name: "Symantec Endpoint Protection",
        vendor: "Broadcom",
        product_type: SecurityProductType::Antivirus,
        process_names: &["ccSvcHst.exe", "Smc.exe", "Rtvscan.exe", "SymCorpUI.exe"],
        service_names: &["Symantec Endpoint Protection", "sep", "SmcService"],
        registry_keys: &[r"SOFTWARE\Symantec\Symantec Endpoint Protection"],
        file_paths: &[r"C:\Program Files\Symantec\Symantec Endpoint Protection"],
    },
    // McAfee
    SecuritySignature {
        name: "McAfee Endpoint Security",
        vendor: "McAfee",
        product_type: SecurityProductType::Antivirus,
        process_names: &["Mcshield.exe", "mfemms.exe", "mfeann.exe", "mfefire.exe"],
        service_names: &["McShield", "mfemms", "mfevtp", "mfeapfk"],
        registry_keys: &[r"SOFTWARE\McAfee"],
        file_paths: &[r"C:\Program Files\McAfee"],
    },
    // Sophos
    SecuritySignature {
        name: "Sophos Endpoint",
        vendor: "Sophos",
        product_type: SecurityProductType::Antivirus,
        process_names: &["SophosFS.exe", "SavService.exe", "SophosUI.exe", "SEDService.exe"],
        service_names: &["Sophos Endpoint Defense", "SAVService"],
        registry_keys: &[r"SOFTWARE\Sophos"],
        file_paths: &[r"C:\Program Files\Sophos"],
    },
    // Kaspersky
    SecuritySignature {
        name: "Kaspersky Endpoint Security",
        vendor: "Kaspersky",
        product_type: SecurityProductType::Antivirus,
        process_names: &["avp.exe", "avpui.exe", "klnagent.exe"],
        service_names: &["AVP", "klnagent"],
        registry_keys: &[r"SOFTWARE\KasperskyLab"],
        file_paths: &[r"C:\Program Files\Kaspersky Lab"],
    },
    // ESET
    SecuritySignature {
        name: "ESET Endpoint Security",
        vendor: "ESET",
        product_type: SecurityProductType::Antivirus,
        process_names: &["ekrn.exe", "egui.exe"],
        service_names: &["ekrn", "ekrnEpfw"],
        registry_keys: &[r"SOFTWARE\ESET"],
        file_paths: &[r"C:\Program Files\ESET"],
    },
    // Palo Alto Cortex XDR
    SecuritySignature {
        name: "Cortex XDR",
        vendor: "Palo Alto Networks",
        product_type: SecurityProductType::XDR,
        process_names: &["CyveraConsole.exe", "Traps.exe", "cyserver.exe"],
        service_names: &["CyveraService", "Traps"],
        registry_keys: &[r"SOFTWARE\Cyvera"],
        file_paths: &[r"C:\Program Files\Palo Alto Networks\Traps"],
    },
    // 360安全卫士
    SecuritySignature {
        name: "360安全卫士",
        vendor: "奇虎360",
        product_type: SecurityProductType::Antivirus,
        process_names: &["360sd.exe", "360rp.exe", "360tray.exe", "ZhuDongFangYu.exe"],
        service_names: &["360EntClientSvc", "ZhuDongFangYu"],
        registry_keys: &[r"SOFTWARE\360Safe"],
        file_paths: &[r"C:\Program Files\360"],
    },
    // 火绒
    SecuritySignature {
        name: "火绒安全",
        vendor: "火绒",
        product_type: SecurityProductType::Antivirus,
        process_names: &["HipsDaemon.exe", "HipsTray.exe", "HipsMain.exe", "wsctrl.exe"],
        service_names: &["HipsDaemon", "Huorong"],
        registry_keys: &[r"SOFTWARE\Huorong"],
        file_paths: &[r"C:\Program Files\Huorong"],
    },
    // Elastic EDR
    SecuritySignature {
        name: "Elastic Security",
        vendor: "Elastic",
        product_type: SecurityProductType::EDR,
        process_names: &["elastic-endpoint.exe", "elastic-agent.exe"],
        service_names: &["ElasticEndpoint", "elastic-agent"],
        registry_keys: &[r"SOFTWARE\Elastic"],
        file_paths: &[r"C:\Program Files\Elastic\Endpoint"],
    },
];

/// 检测所有安全产品
pub fn detect_security_products() -> Result<Vec<SecurityProduct>, String> {
    let mut products = Vec::new();

    // 获取运行中的进程列表
    let running_processes = get_running_processes()?;

    // 获取运行中的服务列表
    let running_services = get_running_services()?;

    for sig in KNOWN_SECURITY_PRODUCTS {
        let mut detected = false;
        let mut method = String::new();
        let mut proc_name = None;
        let mut exe_path = None;

        // 检查进程
        for pname in sig.process_names {
            if running_processes.iter().any(|p| p.to_lowercase().contains(&pname.to_lowercase())) {
                detected = true;
                proc_name = Some(pname.to_string());
                method = format!("进程检测: {}", pname);
                break;
            }
        }

        // 如果没通过进程检测到，检查服务
        if !detected {
            for sname in sig.service_names {
                if running_services.iter().any(|s| s.to_lowercase().contains(&sname.to_lowercase())) {
                    detected = true;
                    method = format!("服务检测: {}", sname);
                    break;
                }
            }
        }

        // 检查注册表键
        if !detected {
            for key in sig.registry_keys {
                let full_key = if key.starts_with("SOFTWARE") || key.starts_with("SYSTEM") {
                    format!("HKLM\\{}", key)
                } else {
                    key.to_string()
                };

                if check_registry_key_exists(&full_key) {
                    detected = true;
                    method = format!("注册表检测: {}", key);
                    break;
                }
            }
        }

        // 检查文件路径
        if !detected {
            for path in sig.file_paths {
                if std::path::Path::new(path).exists() {
                    detected = true;
                    method = format!("文件系统检测: {}", path);
                    exe_path = Some(path.to_string());
                    break;
                }
            }
        }

        if detected {
            products.push(SecurityProduct {
                name: sig.name.to_string(),
                vendor: sig.vendor.to_string(),
                product_type: sig.product_type.clone(),
                detection_method: method,
                is_running: proc_name.is_some(),
                process_name: proc_name,
                executable_path: exe_path,
                version: None,
            });
        }
    }

    Ok(products)
}

/// 获取运行中的进程列表
fn get_running_processes() -> Result<Vec<String>, String> {
    let mut processes = Vec::new();

    if cfg!(windows) {
        let output = std::process::Command::new("tasklist")
            .args(["/FO", "CSV", "/NH"])
            .output()
            .map_err(|e| format!("tasklist失败: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let parts: Vec<&str> = line.trim_matches('"').split("\",\"").collect();
            if !parts.is_empty() {
                processes.push(parts[0].to_string());
            }
        }
    } else if cfg!(unix) {
        let output = std::process::Command::new("ps")
            .args(["-eo", "comm"])
            .output()
            .map_err(|e| format!("ps失败: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines().skip(1) {
            processes.push(line.trim().to_string());
        }
    }

    Ok(processes)
}

/// 获取运行中的服务列表
fn get_running_services() -> Result<Vec<String>, String> {
    let mut services = Vec::new();

    if cfg!(windows) {
        let output = std::process::Command::new("sc")
            .args(["query", "state=", "all"])
            .output()
            .map_err(|e| format!("sc失败: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.contains("SERVICE_NAME") {
                if let Some(name) = line.split(':').nth(1) {
                    services.push(name.trim().to_string());
                }
            }
        }
    }

    Ok(services)
}

/// 检查注册表键是否存在
fn check_registry_key_exists(key: &str) -> bool {
    if cfg!(windows) {
        let output = std::process::Command::new("reg")
            .args(["query", key, "/ve"])
            .output();

        matches!(output, Ok(o) if o.status.success())
    } else {
        false
    }
}

/// 检测Windows Defender状态
pub fn check_defender_status() -> Option<String> {
    if cfg!(windows) {
        let output = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "Get-MpComputerStatus | Select-Object AMRunningMode, AntivirusEnabled, RealTimeProtectionEnabled | ConvertTo-Json",
            ])
            .output();

        if let Ok(o) = output {
            if o.status.success() {
                return Some(String::from_utf8_lossy(&o.stdout).to_string());
            }
        }
    }
    None
}

/// 检测AMSI是否启用
pub fn check_amsi_enabled() -> bool {
    if cfg!(windows) {
        // 检查AMSI相关注册表键
        let key = r"HKLM\SOFTWARE\Microsoft\AMSI\Providers";
        check_registry_key_exists(key)
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_security_products() {
        let result = detect_security_products();
        assert!(result.is_ok());
    }

    #[test]
    fn test_security_product_type_display() {
        assert_eq!(SecurityProductType::EDR.to_string(), "EDR");
        assert_eq!(SecurityProductType::Antivirus.to_string(), "AV");
    }

    #[test]
    fn test_get_running_processes() {
        let result = get_running_processes();
        assert!(result.is_ok());
    }

    #[test]
    fn test_known_products_count() {
        assert!(KNOWN_SECURITY_PRODUCTS.len() >= 10);
    }

    #[test]
    fn test_all_products_have_process_or_service() {
        for sig in KNOWN_SECURITY_PRODUCTS {
            assert!(
                !sig.process_names.is_empty() || !sig.service_names.is_empty(),
                "{} 需要至少一个进程名或服务名",
                sig.name
            );
        }
    }
}
