//! 隧道数据模型
//!
//! 定义连接信息、隧道状态等数据结构

use std::net::SocketAddr;
use std::time::Duration;

/// 连接信息
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ConnectionInfo {
    /// 连接唯一标识
    pub id: String,
    /// 本地地址
    pub local_addr: SocketAddr,
    /// 远程地址
    pub remote_addr: SocketAddr,
    /// 发送字节数
    pub bytes_sent: u64,
    /// 接收字节数
    pub bytes_received: u64,
    /// 连接建立时间
    pub connected_at: chrono::DateTime<chrono::Utc>,
    /// 连接持续时间
    pub duration: Duration,
    /// 是否活跃
    pub is_active: bool,
}

impl ConnectionInfo {
    /// 创建新的连接信息
    pub fn new(id: String, local_addr: SocketAddr, remote_addr: SocketAddr) -> Self {
        Self {
            id,
            local_addr,
            remote_addr,
            bytes_sent: 0,
            bytes_received: 0,
            connected_at: chrono::Utc::now(),
            duration: Duration::default(),
            is_active: true,
        }
    }

    /// 更新流量统计
    pub fn update_stats(&mut self, sent: u64, received: u64) {
        self.bytes_sent += sent;
        self.bytes_received += received;
        if self.is_active {
            self.duration = chrono::Utc::now().signed_duration_since(self.connected_at)
                .to_std()
                .unwrap_or_default();
        }
    }

    /// 关闭连接
    pub fn close(&mut self) {
        self.is_active = false;
        self.duration = chrono::Utc::now().signed_duration_since(self.connected_at)
            .to_std()
            .unwrap_or_default();
    }

    /// 格式化流量大小
    pub fn format_bytes(bytes: u64) -> String {
        const KB: u64 = 1024;
        const MB: u64 = KB * 1024;
        const GB: u64 = MB * 1024;

        if bytes >= GB {
            format!("{:.2} GB", bytes as f64 / GB as f64)
        } else if bytes >= MB {
            format!("{:.2} MB", bytes as f64 / MB as f64)
        } else if bytes >= KB {
            format!("{:.2} KB", bytes as f64 / KB as f64)
        } else {
            format!("{} B", bytes)
        }
    }
}

/// 隧道状态
#[derive(Debug, Clone)]
pub struct TunnelStatus {
    /// 是否运行中
    pub is_running: bool,
    /// 活跃连接数
    pub active_connections: usize,
    /// 总连接数
    pub total_connections: usize,
    /// 连接列表
    pub connections: Vec<ConnectionInfo>,
    /// 启动时间
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    /// 总发送字节数
    pub total_bytes_sent: u64,
    /// 总接收字节数
    pub total_bytes_received: u64,
}

impl TunnelStatus {
    /// 创建新的隧道状态
    pub fn new() -> Self {
        Self {
            is_running: false,
            active_connections: 0,
            total_connections: 0,
            connections: Vec::new(),
            started_at: None,
            total_bytes_sent: 0,
            total_bytes_received: 0,
        }
    }

    /// 启动隧道
    pub fn start(&mut self) {
        self.is_running = true;
        self.started_at = Some(chrono::Utc::now());
    }

    /// 停止隧道
    #[allow(dead_code)]
    pub fn stop(&mut self) {
        self.is_running = false;
        self.active_connections = 0;
        // 关闭所有活跃连接
        for conn in &mut self.connections {
            if conn.is_active {
                conn.close();
            }
        }
    }

    /// 添加连接
    pub fn add_connection(&mut self, conn: ConnectionInfo) {
        self.total_connections += 1;
        self.active_connections += 1;
        self.connections.push(conn);
    }

    /// 移除连接
    pub fn remove_connection(&mut self, id: &str) {
        if let Some(pos) = self.connections.iter().position(|c| c.id == id) {
            if self.connections[pos].is_active {
                self.active_connections -= 1;
                self.connections[pos].close();
            }
            // 更新统计
            self.total_bytes_sent += self.connections[pos].bytes_sent;
            self.total_bytes_received += self.connections[pos].bytes_received;
        }
    }

    /// 更新连接统计
    pub fn update_connection(&mut self, id: &str, sent: u64, received: u64) {
        if let Some(conn) = self.connections.iter_mut().find(|c| c.id == id) {
            conn.update_stats(sent, received);
        }
    }

    /// 获取运行时间
    #[allow(dead_code)]
    pub fn uptime(&self) -> Option<Duration> {
        if let Some(started) = self.started_at {
            Some(
                chrono::Utc::now()
                    .signed_duration_since(started)
                    .to_std()
                    .unwrap_or_default(),
            )
        } else {
            None
        }
    }

    /// 格式化运行时间
    #[allow(dead_code)]
    pub fn format_uptime(&self) -> String {
        if let Some(uptime) = self.uptime() {
            let secs = uptime.as_secs();
            let hours = secs / 3600;
            let minutes = (secs % 3600) / 60;
            let seconds = secs % 60;

            if hours > 0 {
                format!("{}小时{}分{}秒", hours, minutes, seconds)
            } else if minutes > 0 {
                format!("{}分{}秒", minutes, seconds)
            } else {
                format!("{}秒", seconds)
            }
        } else {
            "未启动".to_string()
        }
    }
}

impl Default for TunnelStatus {
    fn default() -> Self {
        Self::new()
    }
}

/// 隧道事件
#[derive(Debug, Clone)]
pub enum TunnelEvent {
    /// 连接建立
    Connected {
        #[allow(dead_code)]
        id: String,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    },
    /// 连接断开
    Disconnected { id: String },
    /// 数据传输
    DataTransferred {
        id: String,
        sent: u64,
        received: u64,
    },
    /// 错误
    Error { message: String },
    /// 隧道启动
    Started,
    /// 隧道停止
    #[allow(dead_code)]
    Stopped,
}

/// 隧道事件处理器
pub trait TunnelEventHandler: Send + Sync {
    /// 处理隧道事件
    fn on_event(&self, event: TunnelEvent);
}

/// 默认的日志事件处理器
pub struct LogEventHandler {
    enable_log: bool,
}

impl LogEventHandler {
    pub fn new(enable_log: bool) -> Self {
        Self { enable_log }
    }
}

impl TunnelEventHandler for LogEventHandler {
    fn on_event(&self, event: TunnelEvent) {
        if !self.enable_log {
            return;
        }

        match event {
            TunnelEvent::Connected {
                id: _,
                local_addr,
                remote_addr,
            } => {
                println!("[连接] {} <- {}", local_addr, remote_addr);
            }
            TunnelEvent::Disconnected { id } => {
                println!("[断开] 连接 {} 已关闭", id);
            }
            TunnelEvent::DataTransferred { id, sent, received } => {
                if sent > 0 || received > 0 {
                    println!(
                        "[传输] {} -> {} bytes, <- {} bytes",
                        id,
                        ConnectionInfo::format_bytes(sent),
                        ConnectionInfo::format_bytes(received)
                    );
                }
            }
            TunnelEvent::Error { message } => {
                eprintln!("[错误] {}", message);
            }
            TunnelEvent::Started => {
                println!("[隧道] 已启动");
            }
            TunnelEvent::Stopped => {
                println!("[隧道] 已停止");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_info() {
        let local: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let remote: SocketAddr = "192.168.1.100:80".parse().unwrap();

        let mut conn = ConnectionInfo::new("test-id".to_string(), local, remote);
        assert_eq!(conn.is_active, true);
        assert_eq!(conn.bytes_sent, 0);
        assert_eq!(conn.bytes_received, 0);

        conn.update_stats(1024, 2048);
        assert_eq!(conn.bytes_sent, 1024);
        assert_eq!(conn.bytes_received, 2048);

        conn.close();
        assert_eq!(conn.is_active, false);
    }

    #[test]
    fn test_tunnel_status() {
        let mut status = TunnelStatus::new();
        assert_eq!(status.is_running, false);
        assert_eq!(status.active_connections, 0);

        status.start();
        assert_eq!(status.is_running, true);
        assert!(status.started_at.is_some());

        let local: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let remote: SocketAddr = "192.168.1.100:80".parse().unwrap();
        let conn = ConnectionInfo::new("conn-1".to_string(), local, remote);

        status.add_connection(conn);
        assert_eq!(status.active_connections, 1);
        assert_eq!(status.total_connections, 1);

        status.remove_connection("conn-1");
        assert_eq!(status.active_connections, 0);
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(ConnectionInfo::format_bytes(500), "500 B");
        assert_eq!(ConnectionInfo::format_bytes(2048), "2.00 KB");
        assert_eq!(ConnectionInfo::format_bytes(2_000_000), "1.91 MB");
    }
}
