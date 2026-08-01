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

        // 获取进程用户
        let user = self.get_process_user(pid);

        // 获取线程数
        let threads = self.get_process_threads(pid);

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
            user,
            threads,
        })
    }

    /// 获取进程所属用户
    fn get_process_user(&self, pid: u32) -> Option<String> {
        #[cfg(windows)]
        {
            // Windows: 使用 tasklist /FI /V 获取进程所有者
            use std::process::Command;
            if let Ok(output) = Command::new("tasklist")
                .args(["/FI", &format!("PID eq {}", pid), "/FO", "CSV", "/V"])
                .output()
            {
                let content = String::from_utf8_lossy(&output.stdout);
                for line in content.lines().skip(1) {
                    let fields: Vec<&str> = line.split("\",\"").collect();
                    if fields.len() >= 7 {
                        // CSV 格式: "映像名称","PID","会话名","会话#","内存使用","状态","用户名"
                        let user = fields[6].trim_matches('"').to_string();
                        if !user.is_empty() && user != "N/A" {
                            return Some(user);
                        }
                    }
                }
            }
            None
        }

        #[cfg(target_os = "linux")]
        {
            // Linux: 从 /proc/[pid]/status 读取
            let status_path = format!("/proc/{}/status", pid);
            if let Ok(content) = std::fs::read_to_string(&status_path) {
                for line in content.lines() {
                    if line.starts_with("Uid:") {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 2 {
                            if let Ok(uid) = parts[1].parse::<u32>() {
                                // 尝试解析用户名
                                return Some(get_username_by_uid(uid));
                            }
                        }
                    }
                }
            }
            None
        }

        #[cfg(not(any(windows, target_os = "linux")))]
        {
            let _ = pid;
            None
        }
    }

    /// 获取进程线程数
    fn get_process_threads(&self, pid: u32) -> Option<usize> {
        #[cfg(windows)]
        {
            // Windows: 使用 wmic 获取线程数
            use std::process::Command;
            if let Ok(output) = Command::new("wmic")
                .args([
                    "process",
                    "where",
                    &format!("ProcessId={}", pid),
                    "get",
                    "ThreadCount",
                    "/value",
                ])
                .output()
            {
                let content = String::from_utf8_lossy(&output.stdout);
                for line in content.lines() {
                    if line.starts_with("ThreadCount=") {
                        if let Some(count_str) = line.split('=').nth(1) {
                            if let Ok(count) = count_str.trim().parse::<usize>() {
                                return Some(count);
                            }
                        }
                    }
                }
            }
            None
        }

        #[cfg(target_os = "linux")]
        {
            // Linux: 从 /proc/[pid]/status 读取 Threads 行
            let status_path = format!("/proc/{}/status", pid);
            if let Ok(content) = std::fs::read_to_string(&status_path) {
                for line in content.lines() {
                    if line.starts_with("Threads:") {
                        if let Some(count_str) = line.split(':').nth(1) {
                            if let Ok(count) = count_str.trim().parse::<usize>() {
                                return Some(count);
                            }
                        }
                    }
                }
            }
            None
        }

        #[cfg(not(any(windows, target_os = "linux")))]
        {
            let _ = pid;
            None
        }
    }

    /// 查找可疑进程
    pub fn find_suspicious_processes(&mut self) -> Vec<ProcessInfo> {
        let processes = self.list_processes();

        processes
            .into_iter()
            .filter(|p| {
                // 检查可疑的进程名
                let suspicious_names = vec![
                    "nc",
                    "netcat",
                    "ncat",
                    "meterpreter",
                    "metasploit",
                    "powershell",
                    "pwsh",
                    "cmd.exe",
                    "powershell.exe",
                    "bash",
                    "sh",
                    "python",
                    "perl",
                    "ruby",
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

/// Linux: 通过 UID 获取用户名
#[cfg(target_os = "linux")]
fn get_username_by_uid(uid: u32) -> String {
    if let Ok(content) = std::fs::read_to_string("/etc/passwd") {
        for line in content.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 3 {
                if let Ok(puid) = parts[2].parse::<u32>() {
                    if puid == uid {
                        return parts[0].to_string();
                    }
                }
            }
        }
    }
    format!("uid_{}", uid)
}

#[cfg(test)]
mod tests {
    // 测试构造数据多为字段赋值模式，与进度条/默认值构建风格一致
    #![allow(clippy::field_reassign_with_default)]
    use super::*;

    #[test]
    fn test_process_collector_creation() {
        let _collector = ProcessCollector::new();
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
        let _processes = collector.find_by_name("system");
    }

    #[test]
    fn test_find_suspicious_processes() {
        let mut collector = ProcessCollector::new();
        let _processes = collector.find_suspicious_processes();
    }
}
