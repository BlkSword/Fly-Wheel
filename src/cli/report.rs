//! 报告生成 CLI 命令处理与交互式向导

use crate::cli::{print_banner, InteractiveMenu};
use crate::core::Result;
use crate::output::color::{print_error, print_info, print_success};
use crate::output::color::print_warning;
use std::path::PathBuf;

pub fn run_report_cmd(
    format: String,
    mitre: bool,
    output: Option<PathBuf>,
    input: Option<PathBuf>,
) -> Result<()> {
    print_banner();

    // 有输入数据文件则直接生成
    if let Some(ref inp) = input {
        return run_report_from_data(inp, &format, mitre, output);
    }

    // 如果输出路径未指定，进入交互式
    if output.is_none() {
        return run_report_interactive(&format, mitre);
    }

    run_report_direct(&format, mitre, output.unwrap())
}

/// 从数据文件生成报告
fn run_report_from_data(
    input_file: &PathBuf,
    format: &str,
    mitre: bool,
    output: Option<PathBuf>,
) -> Result<()> {
    print_info(&format!("从数据文件生成报告: {}", input_file.display()));

    let content = std::fs::read_to_string(input_file)
        .map_err(|e| format!("读取数据文件失败: {}", e))?;

    // 尝试反序列化为 AttackChainReport
    let report = match serde_json::from_str::<crate::output::report::AttackChainReport>(&content) {
        Ok(r) => {
            print_info(&format!("加载了 {} 个攻击步骤, {} 个发现", r.steps.len(), r.findings.len()));
            r
        }
        Err(_) => {
            // 尝试作为 AD 枚举结果 + 额外元数据解析
            print_info("尝试作为综合数据解析...");
            build_report_from_json_data(&content)?
        }
    };

    let report_content = match format {
        "executive" => crate::output::report::ReportGenerator::generate_executive_summary(&report),
        "html" => crate::output::report::ReportGenerator::generate_html_report(&report),
        _ => {
            let mut md = crate::output::report::ReportGenerator::generate_full_report(&report);
            if mitre {
                md.push_str("\n\n---\n*MITRE ATT&CK 映射已包含在报告中*\n");
            }
            md
        }
    };

    let out_path = output.unwrap_or_else(|| {
        let ext = match format {
            "executive" | "full" => "md",
            _ => "html",
        };
        PathBuf::from(format!("pentest_report_{}.{}", chrono::Utc::now().format("%Y%m%d_%H%M%S"), ext))
    });

    std::fs::write(&out_path, &report_content)?;
    print_success(&format!("报告已保存: {}", out_path.display()));

    Ok(())
}

/// 从 JSON 数据构建报告（支持 AD 结果 + scan 结果混合输入）
fn build_report_from_json_data(content: &str) -> crate::core::Result<crate::output::report::AttackChainReport> {
    let mut report = crate::output::report::AttackChainReport {
        title: "内网渗透测试报告".to_string(),
        target_organization: "（从数据中提取）".to_string(),
        report_date: chrono::Utc::now().format("%Y-%m-%d").to_string(),
        entry_point: "（待补充）".to_string(),
        final_objective: "（待补充）".to_string(),
        steps: Vec::new(),
        findings: Vec::new(),
        timeline: Vec::new(),
        compromised_hosts: Vec::new(),
        stolen_credentials: 0,
        risk_score: 0,
    };

    // 尝试解析为通用 JSON 对象
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(content) {
        if let Some(obj) = json.as_object() {
            // 提取目标组织
            if let Some(name) = obj.get("domain_name").or_else(|| obj.get("target_organization")) {
                report.target_organization = name.as_str().unwrap_or("未知").to_string();
            }

            // 从 AD 枚举结果构建发现
            if let Some(users) = obj.get("users").and_then(|v| v.as_array()) {
                let admin_count = users.iter().filter(|u| u.get("admin_count").and_then(|a| a.as_bool()).unwrap_or(false)).count();
                if admin_count > 0 {
                    report.findings.push(crate::output::report::ReportFinding {
                        id: "F-AD-001".to_string(),
                        title: "发现高权限域用户".to_string(),
                        description: format!("AD 枚举发现 {} 个高权限用户", admin_count),
                        severity: crate::output::report::FindingSeverity::Medium,
                        affected_hosts: vec!["域控制器".to_string()],
                        recommendation: "审计所有高权限账户，移除不必要的管理员权限".to_string(),
                        cvss_score: None,
                    });
                }
            }

            // Kerberoast 目标
            if let Some(kerb) = obj.get("kerberoast_targets").and_then(|v| v.as_array()) {
                if !kerb.is_empty() {
                    report.findings.push(crate::output::report::ReportFinding {
                        id: "F-KERB-001".to_string(),
                        title: "发现 Kerberoasting 目标".to_string(),
                        description: format!("发现 {} 个注册了 SPN 的用户账户，可进行 Kerberoasting 攻击", kerb.len()),
                        severity: crate::output::report::FindingSeverity::High,
                        affected_hosts: kerb.iter().filter_map(|k| k.get("spn").and_then(|s| s.as_str()).map(|s| s.to_string())).collect(),
                        recommendation: "为服务账户设置强密码（>=25字符随机密码），定期轮换".to_string(),
                        cvss_score: Some(7.5),
                    });
                }
            }

            // AS-REP 目标
            if let Some(asrep) = obj.get("asrep_targets").and_then(|v| v.as_array()) {
                if !asrep.is_empty() {
                    report.findings.push(crate::output::report::ReportFinding {
                        id: "F-ASREP-001".to_string(),
                        title: "发现 AS-REP Roasting 目标".to_string(),
                        description: format!("发现 {} 个未启用 Kerberos 预认证的用户", asrep.len()),
                        severity: crate::output::report::FindingSeverity::High,
                        affected_hosts: asrep.iter().filter_map(|a| a.get("username").and_then(|u| u.as_str()).map(|s| s.to_string())).collect(),
                        recommendation: "为这些用户账户启用 Kerberos 预认证".to_string(),
                        cvss_score: Some(7.0),
                    });
                }
            }

            // GPO
            if let Some(gpos) = obj.get("gpos").and_then(|v| v.as_array()) {
                if !gpos.is_empty() {
                    report.timeline.push(crate::output::report::TimelineEntry {
                        timestamp: chrono::Utc::now().format("%H:%M").to_string(),
                        event: format!("发现 {} 个组策略对象", gpos.len()),
                        phase: "AD 枚举".to_string(),
                        host: Some("域控制器".to_string()),
                    });
                }
            }

            // 信任关系
            if let Some(trusts) = obj.get("trusts").and_then(|v| v.as_array()) {
                for trust in trusts {
                    if let (Some(domain), Some(dir), Some(typ)) = (
                        trust.get("domain").and_then(|d| d.as_str()),
                        trust.get("trust_direction").and_then(|d| d.as_str()),
                        trust.get("trust_type").and_then(|t| t.as_str()),
                    ) {
                        report.findings.push(crate::output::report::ReportFinding {
                            id: format!("F-TRUST-{}", domain),
                            title: format!("发现域信任关系: {}", domain),
                            description: format!("信任方向: {}, 信任类型: {}", dir, typ),
                            severity: crate::output::report::FindingSeverity::Low,
                            affected_hosts: vec![domain.to_string()],
                            recommendation: "审查跨域访问策略，限制不必要的跨域权限".to_string(),
                            cvss_score: Some(3.0),
                        });
                    }
                }
            }

            // 凭据统计
            if let Some(creds) = obj.get("credentials").or_else(|| obj.get("stolen_credentials")) {
                report.stolen_credentials = creds.as_u64().unwrap_or(0) as usize;
            }
            if let Some(stats) = obj.get("stats") {
                if let Some(total) = stats.get("total") {
                    report.stolen_credentials = total.as_u64().unwrap_or(0) as usize;
                }
                if let Some(high) = stats.get("high_value") {
                    if high.as_u64().unwrap_or(0) > 0 {
                        report.risk_score += 20;
                    }
                }
            }

            // ==================== 扫描结果聚合 ====================
            if let Some(hosts) = obj.get("hosts").and_then(|v| v.as_array()) {
                let alive: Vec<_> = hosts.iter()
                    .filter(|h| h.get("is_alive").and_then(|a| a.as_bool()).unwrap_or(false))
                    .collect();

                if !alive.is_empty() {
                    report.timeline.push(crate::output::report::TimelineEntry {
                        timestamp: chrono::Utc::now().format("%H:%M").to_string(),
                        event: format!("主机发现: {} 台存活（共 {} 台目标）", alive.len(), hosts.len()),
                        phase: "侦察".to_string(),
                        host: None,
                    });
                }

                // 提取开放端口和服务
                for host in &alive {
                    let ip = host.get("ip").and_then(|i| i.as_str()).unwrap_or("unknown");
                    if let Some(ports) = host.get("open_ports").and_then(|p| p.as_array()) {
                        for port_info in ports {
                            let port = port_info.get("port").and_then(|p| p.as_u64()).unwrap_or(0);
                            let service = port_info.get("service").and_then(|s| s.as_str()).unwrap_or("");
                            if !service.is_empty() {
                                report.timeline.push(crate::output::report::TimelineEntry {
                                    timestamp: chrono::Utc::now().format("%H:%M").to_string(),
                                    event: format!("发现服务 {}:{}/{}", ip, port, service),
                                    phase: "服务探测".to_string(),
                                    host: Some(ip.to_string()),
                                });
                            }
                        }
                    }
                }

                // 扫描统计
                if let Some(scan_stats) = obj.get("stats") {
                    if let Some(total_targets) = scan_stats.get("total_targets").and_then(|t| t.as_u64()) {
                        report.steps.push(crate::output::report::ReportStep {
                            step_number: report.steps.len() + 1,
                            phase: "侦察".to_string(),
                            title: "网络扫描".to_string(),
                            description: format!("扫描 {} 个目标，发现 {} 台存活主机", total_targets, alive.len()),
                            source_host: "攻击机".to_string(),
                            target_host: None,
                            technique: "T1046 - Network Service Discovery".to_string(),
                            mitre_id: Some("T1046".to_string()),
                            success: !alive.is_empty(),
                            evidence: Some(format!("{} 台存活主机", alive.len())),
                        });
                    }
                }
            }

            // ==================== 爆破结果聚合 ====================
            if let Some(crack_success) = obj.get("is_success").and_then(|s| s.as_bool()) {
                if crack_success {
                    let target = obj.get("target").and_then(|t| t.as_str()).unwrap_or("unknown");
                    let port = obj.get("port").and_then(|p| p.as_u64()).unwrap_or(0);
                    let service = obj.get("service").and_then(|s| s.as_str()).unwrap_or("");
                    let username = obj.get("username").and_then(|u| u.as_str()).unwrap_or("");

                    report.findings.push(crate::output::report::ReportFinding {
                        id: format!("F-CRACK-{}", target),
                        title: format!("弱口令: {}:{} ({})", target, port, service),
                        description: format!("服务 {}:{} 存在弱口令，用户名: {}", target, port, username),
                        severity: crate::output::report::FindingSeverity::Critical,
                        affected_hosts: vec![target.to_string()],
                        recommendation: "立即修改弱口令，启用账户锁定策略，限制远程访问".to_string(),
                        cvss_score: Some(9.8),
                    });
                    report.stolen_credentials += 1;
                    report.risk_score += 25;
                }
            }

            // 多组爆破结果（数组格式）
            if let Some(results) = obj.get("crack_results").and_then(|v| v.as_array()) {
                for res in results {
                    if res.get("is_success").and_then(|s| s.as_bool()).unwrap_or(false) {
                        let target = res.get("target").and_then(|t| t.as_str()).unwrap_or("unknown");
                        report.stolen_credentials += 1;
                        report.findings.push(crate::output::report::ReportFinding {
                            id: format!("F-CRACK-{}", target),
                            title: format!("弱口令: {}", target),
                            description: "发现有效凭据".to_string(),
                            severity: crate::output::report::FindingSeverity::Critical,
                            affected_hosts: vec![target.to_string()],
                            recommendation: "修改密码并审查账户活动".to_string(),
                            cvss_score: Some(9.8),
                        });
                    }
                }
            }

            // ==================== 提权检测结果聚合 ====================
            if let Some(findings) = obj.get("findings").and_then(|v| v.as_array()) {
                for finding in findings {
                    let title = finding.get("title").and_then(|t| t.as_str()).unwrap_or("未知提权风险");
                    let category = finding.get("category").and_then(|c| c.as_str()).unwrap_or("");
                    let severity_str = finding.get("severity").and_then(|s| s.as_str()).unwrap_or("medium");
                    let description = finding.get("description").and_then(|d| d.as_str()).unwrap_or("");
                    let remediation = finding.get("remediation").and_then(|r| r.as_str()).unwrap_or("");

                    let severity = match severity_str {
                        "critical" => crate::output::report::FindingSeverity::Critical,
                        "high" => crate::output::report::FindingSeverity::High,
                        "medium" => crate::output::report::FindingSeverity::Medium,
                        "low" => crate::output::report::FindingSeverity::Low,
                        _ => crate::output::report::FindingSeverity::Info,
                    };

                    report.findings.push(crate::output::report::ReportFinding {
                        id: format!("F-PRIVESC-{}", category),
                        title: format!("[提权] {}", title),
                        description: description.to_string(),
                        severity,
                        affected_hosts: vec![obj.get("hostname").and_then(|h| h.as_str()).unwrap_or("localhost").to_string()],
                        recommendation: remediation.to_string(),
                        cvss_score: None,
                    });
                }
            }

            // ==================== 漏洞扫描结果聚合 ====================
            if let Some(vuln_findings) = obj.get("vuln_findings").or_else(|| obj.get("vulnerabilities")).and_then(|v| v.as_array()) {
                for vf in vuln_findings {
                    let vuln_id = vf.get("vuln_id").and_then(|v| v.as_str()).unwrap_or("unknown");
                    let vuln_name = vf.get("vuln_name").and_then(|v| v.as_str()).unwrap_or("未知漏洞");
                    let target = vf.get("target").and_then(|t| t.as_str()).unwrap_or("unknown");
                    let sev = vf.get("severity").and_then(|s| s.as_str()).unwrap_or("medium");

                    let severity = match sev {
                        "critical" => crate::output::report::FindingSeverity::Critical,
                        "high" => crate::output::report::FindingSeverity::High,
                        "medium" => crate::output::report::FindingSeverity::Medium,
                        "low" => crate::output::report::FindingSeverity::Low,
                        _ => crate::output::report::FindingSeverity::Info,
                    };

                    report.findings.push(crate::output::report::ReportFinding {
                        id: format!("F-VULN-{}", vuln_id),
                        title: format!("[漏洞] {}", vuln_name),
                        description: vf.get("description").and_then(|d| d.as_str()).unwrap_or("").to_string(),
                        severity,
                        affected_hosts: vec![target.to_string()],
                        recommendation: vf.get("remediation").and_then(|r| r.as_str()).unwrap_or("修复漏洞").to_string(),
                        cvss_score: None,
                    });
                }
            }

            // 计算风险评分
            let critical: usize = report.findings.iter().filter(|f| f.severity == crate::output::report::FindingSeverity::Critical).count();
            let high: usize = report.findings.iter().filter(|f| f.severity == crate::output::report::FindingSeverity::High).count();
            report.risk_score = std::cmp::min(100u32, 10 + (critical * 25) as u32 + (high * 15) as u32 + report.stolen_credentials as u32);
        }
    }

    Ok(report)
}

fn run_report_direct(
    format: &str,
    _mitre: bool,
    output: PathBuf,
) -> Result<()> {
    print_info("生成渗透测试报告...");
    print_warning("未提供输入数据，生成空报告模板。使用 --input <JSON文件> 加载实际数据。");

    let report = crate::output::report::AttackChainReport {
        title: "内网渗透测试报告".to_string(),
        target_organization: "（请使用 --input 提供数据或通过交互式模式填写）".to_string(),
        report_date: chrono::Utc::now().format("%Y-%m-%d").to_string(),
        entry_point: "（待补充）".to_string(),
        final_objective: "（待补充）".to_string(),
        steps: Vec::new(),
        findings: Vec::new(),
        timeline: Vec::new(),
        compromised_hosts: Vec::new(),
        stolen_credentials: 0,
        risk_score: 0,
    };

    let content = match format {
        "executive" => crate::output::report::ReportGenerator::generate_executive_summary(&report),
        "html" => crate::output::report::ReportGenerator::generate_html_report(&report),
        _ => crate::output::report::ReportGenerator::generate_full_report(&report),
    };

    std::fs::write(&output, &content)?;
    print_success(&format!("报告已保存: {}", output.display()));

    Ok(())
}

fn run_report_interactive(format: &str, _mitre: bool) -> Result<()> {
    print_info("IntraSweep 交互式报告生成向导");
    println!();

    InteractiveMenu::print_step(1, 4, "数据来源");
    let data_file = InteractiveMenu::read_input("JSON 数据文件路径（AD/扫描/凭据结果，可选）: ");
    let has_data = !data_file.is_empty();

    InteractiveMenu::print_step(2, 4, "报告信息");
    let org = InteractiveMenu::read_input("目标组织名称 [默认: 目标组织]: ");
    let org = if org.is_empty() { "目标组织".to_string() } else { org };

    let entry = InteractiveMenu::read_input("攻击入口描述（可选）: ");
    let objective = InteractiveMenu::read_input("最终目标描述（可选）: ");

    InteractiveMenu::print_step(3, 4, "报告格式");
    println!("1. 完整报告 (Markdown)");
    println!("2. 执行摘要 (面向管理层)");
    println!("3. HTML 报告 (自包含，可浏览器查看)");
    let fmt_choice = InteractiveMenu::read_number_opt("请选择 [1-3, 默认 1]: ", 1, 3, 1);
    let fmt = match fmt_choice {
        2 => "executive",
        3 => "html",
        _ => format,
    };

    InteractiveMenu::print_step(4, 4, "输出路径");
    let ext = match fmt {
        "executive" | "full" => "md",
        _ => "html",
    };
    let default_path = format!("pentest_report.{}", ext);
    let output_path = InteractiveMenu::read_input(&format!("输出路径 [默认: {}]: ", default_path));
    let output = PathBuf::from(if output_path.is_empty() { default_path } else { output_path });

    if !InteractiveMenu::confirm("确认生成报告? [Y/n]: ") {
        print_info("已取消");
        return Ok(());
    }

    if has_data {
        let input_file = PathBuf::from(&data_file);
        if !input_file.exists() {
            print_warning(&format!("数据文件不存在: {}，生成空模板报告", data_file));
            return run_report_direct(fmt, false, output);
        } else {
            return run_report_from_data(&input_file, fmt, false, Some(output));
        }
    } else {
        // 手动填写基本信息的报告
        let report = crate::output::report::AttackChainReport {
            title: format!("{} 渗透测试报告", org),
            target_organization: org,
            report_date: chrono::Utc::now().format("%Y-%m-%d").to_string(),
            entry_point: if entry.is_empty() { "（待补充）".to_string() } else { entry },
            final_objective: if objective.is_empty() { "（待补充）".to_string() } else { objective },
            steps: Vec::new(),
            findings: Vec::new(),
            timeline: Vec::new(),
            compromised_hosts: Vec::new(),
            stolen_credentials: 0,
            risk_score: 0,
        };

        let content = match fmt {
            "executive" => crate::output::report::ReportGenerator::generate_executive_summary(&report),
            "html" => crate::output::report::ReportGenerator::generate_html_report(&report),
            _ => crate::output::report::ReportGenerator::generate_full_report(&report),
        };

        std::fs::write(&output, &content)?;
        print_success(&format!("报告已保存: {}", output.display()));
    }

    Ok(())
}
