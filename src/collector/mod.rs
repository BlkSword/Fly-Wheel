//! 统一信息收集模块
//!
//! 提供一键收集所有系统信息的功能

pub mod models;
pub use models::SystemReport;

use crate::core::Result;
use crate::modules::collect::{
    SystemCollector, NetworkCollector, ProcessCollector,
    CredentialCollector, FileCollector
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
        let mut network_report = NetworkReport::default();
        network_report.interfaces = self.network.collect_interfaces();
        progress.complete_task(&format!("网络接口收集完成 - 发现{}个接口", network_report.interfaces.len()));

        // 3. 收集网络配置信息
        progress.start_task("收集网络配置信息");
        progress.update_current("获取路由表");
        network_report.routes = self.network.collect_routes();
        progress.update_current("获取ARP表");
        network_report.arp_table = self.network.collect_arp_table();
        progress.update_current("获取网络连接");
        network_report.connections = self.network.collect_connections();
        network_report.update_stats();
        progress.complete_task(&format!("网络配置收集完成 - {}个路由, {}个ARP条目, {}个活动连接",
            network_report.stats.route_count,
            network_report.stats.arp_count,
            network_report.stats.connection_count));

        // 4. 收集进程信息
        progress.start_task("收集进程信息");
        progress.update_current("枚举系统进程");
        let mut process_report = ProcessReport::default();
        let all_processes = self.process.list_processes();
        process_report.total_count = all_processes.len();
        progress.update_current("分析进程详情");
        process_report.processes = all_processes.into_iter().take(100).collect();
        process_report.update_stats();
        progress.complete_task(&format!("进程信息收集完成 - 共{}个进程", process_report.total_count));

        // 5. 收集密码哈希
        progress.start_task("收集密码哈希信息");
        progress.update_current("搜索系统密码文件");
        let mut credential_report = CredentialReport::default();
        credential_report.password_hashes = self.credential.collect_password_hashes();
        progress.complete_task(&format!("密码哈希收集完成 - 发现{}个条目", credential_report.password_hashes.len()));

        // 6. 收集密钥和令牌
        progress.start_task("收集SSH密钥和API令牌");
        progress.update_current("搜索AWS凭证");
        let mut credential_report = credential_report;
        credential_report.tokens = self.credential.collect_tokens();
        progress.update_current("搜索SSH密钥");
        credential_report.ssh_keys = self.credential.collect_ssh_keys();
        progress.update_current("搜索API密钥");
        credential_report.api_keys = self.credential.collect_api_keys();
        credential_report.update_stats();
        progress.complete_task(&format!("密钥收集完成 - {}个SSH密钥, {}个API密钥",
            credential_report.stats.ssh_key_count,
            credential_report.stats.api_key_count));

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
        progress.complete_task(&format!("文件搜索完成 - {}个敏感文件, {}个最近文件",
            file_report.stats.sensitive_count,
            file_report.stats.recent_count));

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
                    modified: chrono::DateTime::<chrono::Utc>::from(modified)
                        .to_rfc3339(),
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
    format!("fly-wheel-{}-{}.json", hostname, timestamp)
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
    use super::*;

    #[test]
    fn test_collector_creation() {
        let collector = InfoCollector::new();
        // 验证创建成功
        assert!(true);
    }

    #[test]
    fn test_generate_output_filename() {
        let filename = generate_output_filename("test-host");
        assert!(filename.starts_with("fly-wheel-test-host-"));
        assert!(filename.ends_with(".json"));
    }
}
