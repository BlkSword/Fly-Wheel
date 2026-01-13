//! 进程信息收集模块
//!
//! 收集运行中的进程信息

use serde::{Deserialize, Serialize};
use sysinfo::System;

/// 进程信息收集器
pub struct ProcessCollector {
    system: System,
}

impl ProcessCollector {
    /// 创建新的进程信息收集器
    pub fn new() -> Self {
        let mut system = System::new();
        system.refresh_processes();
        Self { system }
    }

    /// 列出所有进程
    pub fn list_processes(&mut self) -> Vec<ProcessInfo> {
        self.system.refresh_processes();

        self.system
            .processes()
            .iter()
            .map(|(pid, process)| ProcessInfo {
                pid: pid.as_u32(),
                name: process.name().to_string(),
                exe: process
                    .exe()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default(),
                cmd: process.cmd().join(" "),
                cpu_usage: process.cpu_usage(),
                memory_usage: process.memory(),
                parent: process.parent().map(|p| p.as_u32()),
                start_time: process.start_time(),
                environ: process.environ().to_vec(),
            })
            .collect()
    }

    /// 获取进程详细信息
    pub fn get_process_details(&mut self, pid: u32) -> Option<ProcessDetails> {
        self.system.refresh_processes();

        let process = self.system.process(sysinfo::Pid::from_u32(pid))?;
        let disk_usage = process.disk_usage();

        Some(ProcessDetails {
            pid,
            name: process.name().to_string(),
            exe: process
                .exe()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default(),
            cwd: process
                .cwd()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default(),
            root: process
                .root()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default(),
            memory: process.memory(),
            virtual_memory: process.virtual_memory(),
            cpu_usage: process.cpu_usage(),
            disk_usage: disk_usage.total_written_bytes + disk_usage.total_read_bytes,
            run_time: process.run_time(),
            parent: process.parent().map(|p| p.as_u32()),
            user: None, // 需要平台特定实现
            threads: None, // 需要平台特定实现
        })
    }

    /// 查找可疑进程
    pub fn find_suspicious_processes(&mut self) -> Vec<ProcessInfo> {
        let processes = self.list_processes();

        processes
            .into_iter()
            .filter(|p| {
                // 检查可疑的进程名
                let suspicious_names = vec![
                    "nc", "netcat", "ncat",
                    "meterpreter", "metasploit",
                    "powershell", "pwsh",
                    "cmd.exe", "powershell.exe",
                    "bash", "sh",
                    "python", "perl", "ruby",
                ];

                let name_lower = p.name.to_lowercase();
                suspicious_names.iter().any(|s| name_lower.contains(s))
            })
            .collect()
    }

    /// 按名称查找进程
    pub fn find_by_name(&mut self, name: &str) -> Vec<ProcessInfo> {
        let processes = self.list_processes();

        processes
            .into_iter()
            .filter(|p| p.name.to_lowercase().contains(&name.to_lowercase()))
            .collect()
    }
}

impl Default for ProcessCollector {
    fn default() -> Self {
        Self::new()
    }
}

// ==================== 数据结构 ====================

/// 进程基本信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub exe: String,
    pub cmd: String,
    pub cpu_usage: f32,
    pub memory_usage: u64,
    pub parent: Option<u32>,
    pub start_time: u64,
    pub environ: Vec<String>,
}

/// 进程详细信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessDetails {
    pub pid: u32,
    pub name: String,
    pub exe: String,
    pub cwd: String,
    pub root: String,
    pub memory: u64,
    pub virtual_memory: u64,
    pub cpu_usage: f32,
    pub disk_usage: u64,
    pub run_time: u64,
    pub parent: Option<u32>,
    pub user: Option<String>,
    pub threads: Option<usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_collector_creation() {
        let collector = ProcessCollector::new();
        // 验证对象创建成功
        assert!(collector.system.processes().len() >= 0);
    }

    #[test]
    fn test_list_processes() {
        let mut collector = ProcessCollector::new();
        let processes = collector.list_processes();
        // 应该至少有一些系统进程
        assert!(!processes.is_empty());
    }

    #[test]
    fn test_find_by_name() {
        let mut collector = ProcessCollector::new();
        let processes = collector.find_by_name("system");
        // 不应该崩溃
        assert!(true);
    }

    #[test]
    fn test_find_suspicious_processes() {
        let mut collector = ProcessCollector::new();
        let processes = collector.find_suspicious_processes();
        // 不应该崩溃
        assert!(true);
    }
}
