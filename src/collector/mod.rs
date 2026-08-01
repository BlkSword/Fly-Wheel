//! 统一信息收集模块
//!
//! 提供一键收集所有系统信息的功能

pub mod models;
pub use models::SystemReport;

use crate::core::Result;
use crate::modules::collect::{
    CredentialCollector, FileCollector, NetworkCollector, ProcessCollector, SystemCollector,
};
use crate::output::progress::LayeredProgress;
use models::*;
use std::path::PathBuf;
use std::time::Instant;

/// 统一信息收集器
pub struct InfoCollector {
    system: SystemCollector,
    network: NetworkCollector,
    process: ProcessCollector,
    credential: CredentialCollector,
    file: FileCollector,
}

impl InfoCollector {
    /// 创建新的信息收集器
    pub fn new() -> Self {
        Self {
            system: SystemCollector::new(),
            network: NetworkCollector::new(),
            process: ProcessCollector::new(),
            credential: CredentialCollector::new(),
            file: FileCollector::new(),
        }
    }

    /// 收集所有信息（带进度显示）
    #[allow(clippy::field_reassign_with_default)]
    pub fn collect_all_with_progress(&mut self, quiet: bool) -> Result<SystemReport> {
        let start = Instant::now();

        // 创建分层进度条（8个步骤）
        let progress = if quiet {
            LayeredProgress::hidden()
        } else {
            LayeredProgress::new()
        };

        progress.start_overall("开始收集系统信息...", 8);

        // 1. 收集系统基础信息
        progress.start_task("收集系统基础信息");
        progress.update_current("检测操作系统类型和版本");
        let system = self.system.collect_all();
        progress.complete_task(&format!("系统信息收集完成 - {}", system.os_info.os_type));

        // 2. 收集网络接口信息
        progress.start_task("收集网络接口信息");
        progress.update_current("扫描网络接口");
        #[allow(clippy::field_reassign_with_default)]
        let mut network_report = NetworkReport::default();
        network_report.interfaces = self.network.collect_interfaces();
        progress.complete_task(&format!(
            "网络接口收集完成 - 发现{}个接口",
            network_report.interfaces.len()
        ));

        // 3. 收集网络配置信息
        progress.start_task("收集网络配置信息");
        progress.update_current("获取路由表");
        network_report.routes = self.network.collect_routes();
        progress.update_current("获取ARP表");
        network_report.arp_table = self.network.collect_arp_table();
        progress.update_current("获取网络连接");
        network_report.connections = self.network.collect_connections();
        network_report.update_stats();
        progress.complete_task(&format!(
            "网络配置收集完成 - {}个路由, {}个ARP条目, {}个活动连接",
            network_report.stats.route_count,
            network_report.stats.arp_count,
            network_report.stats.connection_count
        ));

        // 4. 收集进程信息
        progress.start_task("收集进程信息");
        progress.update_current("枚举系统进程");
        #[allow(clippy::field_reassign_with_default)]
        let mut process_report = ProcessReport::default();
        let all_processes = self.process.list_processes();
        process_report.total_count = all_processes.len();
        progress.update_current("分析进程详情");
        process_report.processes = all_processes.into_iter().take(100).collect();
        process_report.update_stats();
        progress.complete_task(&format!(
            "进程信息收集完成 - 共{}个进程",
            process_report.total_count
        ));

        // 5. 收集密码哈希
        progress.start_task("收集密码哈希信息");
        progress.update_current("搜索系统密码文件");
        let mut credential_report = CredentialReport::default();
        credential_report.password_hashes = self.credential.collect_password_hashes();
        progress.complete_task(&format!(
            "密码哈希收集完成 - 发现{}个条目",
            credential_report.password_hashes.len()
        ));

        // 6. 收集密钥和令牌
        progress.start_task("收集SSH密钥和API令牌");
        progress.update_current("搜索AWS凭证");
        credential_report.tokens = self.credential.collect_tokens();
        credential_report
            .tokens
            .extend(self.credential.collect_env_secrets());
        progress.update_current("搜索SSH密钥");
        credential_report.ssh_keys = self.credential.collect_ssh_keys();
        progress.update_current("搜索API密钥");
        credential_report.api_keys = self.credential.collect_api_keys();
        progress.update_current("搜索远程连接历史");
        credential_report.known_hosts = self.credential.collect_known_hosts();
        let mut remote_sessions = self.credential.collect_putty_sessions();
        remote_sessions.extend(self.credential.collect_rdp_history());
        credential_report.remote_sessions = remote_sessions;
        credential_report.update_stats();
        progress.complete_task(&format!(
            "密钥收集完成 - {}个SSH密钥, {}个API密钥",
            credential_report.stats.ssh_key_count, credential_report.stats.api_key_count
        ));

        // 7. 收集敏感文件
        progress.start_task("搜索敏感文件");
        let mut file_report = FileReport::default();
        progress.update_current("扫描用户目录");
        let search_paths = self.get_default_search_paths();
        file_report.sensitive_files = self.file.find_sensitive_files(&search_paths);
        progress.update_current("扫描配置文件");
        file_report.config_files = self.file.find_config_files(&search_paths);
        progress.update_current("查找最近修改的文件");
        let recent_paths = self.get_recent_file_paths();
        let recent_files = self.file.find_recent_files(&recent_paths, 7);
        file_report.recent_files = self.convert_to_recent_files(recent_files);
        file_report.update_stats();
        progress.complete_task(&format!(
            "文件搜索完成 - {}个敏感文件, {}个最近文件",
            file_report.stats.sensitive_count, file_report.stats.recent_count
        ));

        // 8. 生成最终报告
        progress.start_task("生成最终报告");
        progress.update_current("汇总所有收集的信息");
        let duration = start.elapsed().as_secs_f64();
        let metadata = ReportMetadata {
            hostname: system.hostname.clone(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            collection_duration_secs: duration,
            collector_version: env!("CARGO_PKG_VERSION").to_string(),
            os_type: system.os_info.os_type.clone(),
            arch: system.os_info.arch.clone(),
        };
        progress.complete_task(&format!("报告生成完成 - 耗时{:.2}秒", duration));

        progress.finish();

        Ok(SystemReport {
            metadata,
            system,
            network: network_report,
            processes: process_report,
            credentials: credential_report,
            files: file_report,
        })
    }

    /// 获取默认搜索路径
    fn get_default_search_paths(&self) -> Vec<String> {
        let mut paths = Vec::new();

        if cfg!(windows) {
            // Windows 搜索路径
            if let Ok(home) = std::env::var("USERPROFILE") {
                paths.push(format!("{}\\", home));
                paths.push(format!("{}\\.ssh", home));
                paths.push(format!("{}\\.aws", home));
                paths.push("C:\\ProgramData\\".to_string());
            }
        } else {
            // Unix 搜索路径
            paths.push("/home/".to_string());
            paths.push("/root/".to_string());
            paths.push("/etc/".to_string());
            paths.push("/var/".to_string());
            paths.push("/tmp/".to_string());
        }

        paths
    }

    /// 获取最近文件搜索路径
    fn get_recent_file_paths(&self) -> Vec<String> {
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
    fn convert_to_recent_files(&self, paths: Vec<PathBuf>) -> Vec<RecentFile> {
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
                    is_sensitive: false, // 可以添加逻辑判断
                })
            })
            .collect()
    }

    /// 收集所有信息（无进度显示）
    pub fn collect_all(&mut self) -> Result<SystemReport> {
        self.collect_all_with_progress(true)
    }
}

impl Default for InfoCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// 生成输出文件名
pub fn generate_output_filename(hostname: &str) -> String {
    let timestamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
    format!("intrasweep-{}-{}.json", hostname, timestamp)
}

/// 保存报告到文件
pub fn save_report(report: &SystemReport, output_path: Option<PathBuf>) -> Result<PathBuf> {
    let path = output_path.unwrap_or_else(|| {
        let filename = generate_output_filename(&report.metadata.hostname);
        PathBuf::from(filename)
    });

    let json = serde_json::to_string_pretty(report)?;

    std::fs::write(&path, json)?;

    Ok(path)
}

#[cfg(test)]
mod tests {
    // 测试构造数据多为字段赋值模式，与进度条/默认值构建风格一致
    #![allow(clippy::field_reassign_with_default)]
    use super::*;
    use crate::modules::collect::*;

    // === 辅助函数 ===

    fn make_process(name: &str, cpu: f32, memory: u64) -> ProcessInfo {
        ProcessInfo {
            pid: 1,
            name: name.to_string(),
            exe: format!("/usr/bin/{}", name),
            cmd: format!("{} --daemon", name),
            cpu_usage: cpu,
            memory_usage: memory,
            parent: Some(1),
            start_time: 1000,
            environ: vec!["PATH=/usr/bin".to_string()],
        }
    }

    fn make_interface(name: &str, ip: &str) -> NetworkInterface {
        NetworkInterface {
            name: name.to_string(),
            ip: ip.to_string(),
            netmask: "255.255.255.0".to_string(),
            mac: Some("00:11:22:33:44:55".to_string()),
            ipv6: None,
            is_up: true,
            gateway: Some("192.168.1.1".to_string()),
            dns_servers: vec!["8.8.8.8".to_string()],
        }
    }

    fn make_route(dest: &str) -> RouteEntry {
        RouteEntry {
            destination: dest.to_string(),
            gateway: "192.168.1.1".to_string(),
            netmask: "255.255.255.0".to_string(),
            metric: 100,
            interface: "eth0".to_string(),
        }
    }

    fn make_hash_entry(username: &str, hash: &str) -> HashEntry {
        HashEntry {
            hash_type: "SHA-256".to_string(),
            location: "/etc/shadow".to_string(),
            username: username.to_string(),
            hash: hash.to_string(),
        }
    }

    fn make_sensitive_file(path: &str, size: u64) -> SensitiveFile {
        SensitiveFile {
            path: path.to_string(),
            file_name: path.rsplit('/').next().unwrap_or(path).to_string(),
            category: "测试".to_string(),
            size,
            modified: None,
        }
    }

    // === 现有测试 ===

    #[test]
    fn test_collector_creation() {
        let _collector = InfoCollector::new();
    }

    #[test]
    fn test_generate_output_filename() {
        let filename = generate_output_filename("test-host");
        assert!(filename.starts_with("intrasweep-test-host-"));
        assert!(filename.ends_with(".json"));
    }

    #[test]
    fn test_generate_output_filename_empty() {
        let filename = generate_output_filename("");
        assert!(filename.starts_with("intrasweep--"));
        assert!(filename.ends_with(".json"));
    }

    #[test]
    fn test_generate_output_filename_special_chars() {
        let filename = generate_output_filename("host.name");
        assert!(filename.contains("host.name"));
    }

    // === NetworkReport::update_stats ===

    #[test]
    fn test_network_report_update_stats() {
        let mut report = NetworkReport::default();
        report.interfaces = vec![
            make_interface("eth0", "10.0.0.1"),
            make_interface("eth1", "192.168.1.1"),
        ];
        report.routes = vec![
            make_route("0.0.0.0"),
            make_route("10.0.0.0"),
            make_route("192.168.1.0"),
        ];
        report.arp_table = vec![ArpEntry {
            ip: "192.168.1.5".to_string(),
            mac: "aa:bb:cc:dd:ee:ff".to_string(),
            interface: "eth0".to_string(),
            interface_ip: Some("10.0.0.1".to_string()),
            state: "动态".to_string(),
        }];
        report.connections = vec![NetworkConnection {
            protocol: "TCP".to_string(),
            local_addr: "10.0.0.1".to_string(),
            local_port: 22,
            remote_addr: "10.0.0.100".to_string(),
            remote_port: 54321,
            state: "ESTABLISHED".to_string(),
            pid: Some(1234),
        }];

        report.update_stats();

        assert_eq!(report.stats.interface_count, 2);
        assert_eq!(report.stats.route_count, 3);
        assert_eq!(report.stats.arp_count, 1);
        assert_eq!(report.stats.connection_count, 1);
    }

    #[test]
    fn test_network_report_update_stats_empty() {
        let mut report = NetworkReport::default();
        report.update_stats();
        assert_eq!(report.stats.interface_count, 0);
        assert_eq!(report.stats.route_count, 0);
        assert_eq!(report.stats.arp_count, 0);
        assert_eq!(report.stats.connection_count, 0);
    }

    // === ProcessReport::update_stats ===

    #[test]
    fn test_process_report_update_stats_suspicious() {
        let mut report = ProcessReport::default();
        report.processes = vec![
            make_process("nc", 5.0, 10_000_000),
            make_process("nginx", 10.0, 100_000_000),
            make_process("meterpreter", 20.0, 50_000_000),
        ];
        report.update_stats();

        assert_eq!(report.suspicious.len(), 2);
        assert!(report.suspicious.iter().any(|p| p.name == "nc"));
        assert!(report.suspicious.iter().any(|p| p.name == "meterpreter"));
        assert!(!report.suspicious.iter().any(|p| p.name == "nginx"));
    }

    #[test]
    fn test_process_report_update_stats_high_cpu() {
        let mut report = ProcessReport::default();
        report.processes = vec![
            make_process("idle", 5.0, 10_000_000),
            make_process("busy1", 55.0, 500_000_000),
            make_process("busy2", 90.0, 100_000_000),
        ];
        report.update_stats();

        assert_eq!(report.high_cpu.len(), 2);
        assert!(report.high_cpu.iter().any(|p| p.name == "busy1"));
        assert!(report.high_cpu.iter().any(|p| p.name == "busy2"));
        assert!(!report.high_cpu.iter().any(|p| p.name == "idle"));
    }

    #[test]
    fn test_process_report_update_stats_high_memory() {
        let mut report = ProcessReport::default();
        report.processes = vec![
            make_process("small", 1.0, 500_000_000),
            make_process("medium", 5.0, 1024 * 1024 * 1024), // 刚好等于阈值
            make_process("big", 10.0, 2 * 1024 * 1024 * 1024),
        ];
        report.update_stats();

        // high_memory 检查 > 1024^3，不包含刚好等于阈值的
        assert_eq!(report.high_memory.len(), 1);
        assert!(report.high_memory.iter().any(|p| p.name == "big"));
    }

    #[test]
    fn test_process_report_update_stats_empty() {
        let mut report = ProcessReport::default();
        report.update_stats();
        assert_eq!(report.suspicious.len(), 0);
        assert_eq!(report.high_cpu.len(), 0);
        assert_eq!(report.high_memory.len(), 0);
    }

    #[test]
    fn test_process_report_case_insensitive_suspicious() {
        let mut report = ProcessReport::default();
        report.processes = vec![
            make_process("PowerShell", 5.0, 10_000_000), // 混合大小写
            make_process("PWSH", 5.0, 10_000_000),       // 大写
        ];
        report.update_stats();
        assert_eq!(report.suspicious.len(), 2);
    }

    // === CredentialReport::update_stats ===

    #[test]
    fn test_credential_report_update_stats() {
        let mut report = CredentialReport::default();
        report.password_hashes = vec![
            make_hash_entry("root", "abc123"),
            make_hash_entry("admin", "def456"),
        ];
        report.tokens = vec![Token {
            token_type: "Bearer".to_string(),
            location: "/home/user/.config".to_string(),
            content: "tok_xxx".to_string(),
        }];
        report.ssh_keys = vec![
            SshKey {
                key_type: "RSA".to_string(),
                path: "/root/.ssh/id_rsa".to_string(),
                fingerprint: Some("SHA256:aaa".to_string()),
            },
            SshKey {
                key_type: "ED25519".to_string(),
                path: "/root/.ssh/id_ed25519".to_string(),
                fingerprint: None,
            },
        ];
        report.api_keys = vec![
            ApiKey {
                service: "AWS".to_string(),
                location: "~/.aws/credentials".to_string(),
                redacted: true,
                key_value: None,
            },
            ApiKey {
                service: "GitHub".to_string(),
                location: "~/.gitconfig".to_string(),
                redacted: false,
                key_value: Some("ghp_xxx".to_string()),
            },
            ApiKey {
                service: "Docker".to_string(),
                location: "~/.docker/config.json".to_string(),
                redacted: true,
                key_value: None,
            },
        ];

        report.update_stats();

        assert_eq!(report.stats.hash_count, 2);
        assert_eq!(report.stats.token_count, 1);
        assert_eq!(report.stats.ssh_key_count, 2);
        assert_eq!(report.stats.api_key_count, 3);
    }

    #[test]
    fn test_credential_report_update_stats_empty() {
        let mut report = CredentialReport::default();
        report.update_stats();
        assert_eq!(report.stats.hash_count, 0);
        assert_eq!(report.stats.token_count, 0);
        assert_eq!(report.stats.ssh_key_count, 0);
        assert_eq!(report.stats.api_key_count, 0);
    }

    // === FileReport::update_stats ===

    #[test]
    fn test_file_report_update_stats() {
        let mut report = FileReport::default();
        report.sensitive_files = vec![
            make_sensitive_file("/etc/shadow", 1024),
            make_sensitive_file("/etc/sudoers", 2048),
        ];
        report.config_files = vec![ConfigFile {
            path: "/etc/nginx/nginx.conf".to_string(),
            file_name: "nginx.conf".to_string(),
            config_type: "nginx".to_string(),
            size: 512,
        }];

        report.update_stats();

        assert_eq!(report.stats.sensitive_count, 2);
        assert_eq!(report.stats.config_count, 1);
        assert_eq!(report.stats.recent_count, 0);
        assert_eq!(report.stats.sensitive_total_size, 3072);
    }

    #[test]
    fn test_file_report_update_stats_empty() {
        let mut report = FileReport::default();
        report.update_stats();
        assert_eq!(report.stats.sensitive_count, 0);
        assert_eq!(report.stats.config_count, 0);
        assert_eq!(report.stats.recent_count, 0);
        assert_eq!(report.stats.sensitive_total_size, 0);
    }

    // === ReportMetadata ===

    #[test]
    fn test_report_metadata_construction() {
        let meta = ReportMetadata {
            hostname: "test-server".to_string(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            collection_duration_secs: 12.5,
            collector_version: "0.3.0".to_string(),
            os_type: "Linux".to_string(),
            arch: "x86_64".to_string(),
        };
        assert_eq!(meta.hostname, "test-server");
        assert_eq!(meta.os_type, "Linux");
        assert_eq!(meta.collection_duration_secs, 12.5);
    }

    // === JSON 序列化 ===

    #[test]
    fn test_network_report_json_roundtrip() {
        let mut report = NetworkReport::default();
        report.interfaces = vec![make_interface("eth0", "10.0.0.1")];
        report.update_stats();

        let json = serde_json::to_string(&report).expect("序列化应成功");
        let deserialized: NetworkReport = serde_json::from_str(&json).expect("反序列化应成功");

        assert_eq!(deserialized.interfaces.len(), 1);
        assert_eq!(deserialized.interfaces[0].name, "eth0");
        assert_eq!(deserialized.stats.interface_count, 1);
    }

    #[test]
    fn test_process_report_json_roundtrip() {
        let mut report = ProcessReport::default();
        report.processes = vec![make_process("ssh", 0.1, 5_000_000)];
        report.update_stats();

        let json = serde_json::to_string(&report).expect("序列化应成功");
        let deserialized: ProcessReport = serde_json::from_str(&json).expect("反序列化应成功");

        assert_eq!(deserialized.processes.len(), 1);
        assert_eq!(deserialized.processes[0].name, "ssh");
    }

    #[test]
    fn test_recent_file_construction() {
        let file = RecentFile {
            path: "/tmp/test.log".to_string(),
            name: "test.log".to_string(),
            size: 4096,
            modified: "2024-01-01 00:00:00".to_string(),
            is_sensitive: true,
        };
        assert_eq!(file.path, "/tmp/test.log");
        assert_eq!(file.name, "test.log");
        assert_eq!(file.size, 4096);
        assert!(file.is_sensitive);
    }
}
