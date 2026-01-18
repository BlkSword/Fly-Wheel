//! 服务定义和通用接口

#![allow(dead_code)]

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// 支持的爆破服务类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CrackService {
    /// SSH (22)
    Ssh,
    /// RDP (3389)
    Rdp,
    /// Redis (6379)
    Redis,
    /// PostgreSQL (5432)
    Postgres,
    /// MongoDB (27017)
    Mongodb,
    /// MSSQL (1433)
    Mssql,
    /// MySQL (3306)
    Mysql,
    /// WinRM (5985/5986)
    Winrm,
}

impl CrackService {
    /// 获取服务的默认端口
    pub fn default_port(&self) -> u16 {
        match self {
            CrackService::Ssh => 22,
            CrackService::Rdp => 3389,
            CrackService::Redis => 6379,
            CrackService::Postgres => 5432,
            CrackService::Mongodb => 27017,
            CrackService::Mssql => 1433,
            CrackService::Mysql => 3306,
            CrackService::Winrm => 5985,
        }
    }

    /// 获取服务名称
    pub fn name(&self) -> &str {
        match self {
            CrackService::Ssh => "SSH",
            CrackService::Rdp => "RDP",
            CrackService::Redis => "Redis",
            CrackService::Postgres => "PostgreSQL",
            CrackService::Mongodb => "MongoDB",
            CrackService::Mssql => "MSSQL",
            CrackService::Mysql => "MySQL",
            CrackService::Winrm => "WinRM",
        }
    }

    /// 是否需要用户名
    pub fn requires_username(&self) -> bool {
        match self {
            CrackService::Redis | CrackService::Mongodb => false,
            _ => true,
        }
    }
}

/// 爆破配置
#[derive(Debug, Clone)]
pub struct CrackConfig {
    /// 目标主机
    pub target: String,
    /// 目标端口
    pub port: u16,
    /// 服务类型
    pub service: CrackService,
    /// 用户名列表（对于不需要用户名的服务可为空）
    pub usernames: Vec<String>,
    /// 密码列表
    pub passwords: Vec<String>,
    /// 并发数
    pub concurrency: usize,
    /// 超时时间（每个连接）
    pub timeout: Duration,
    /// 延迟（毫秒，用于避免触发防护）
    pub delay_ms: Option<u64>,
}

impl Default for CrackConfig {
    fn default() -> Self {
        Self {
            target: String::new(),
            port: 0,
            service: CrackService::Ssh,
            usernames: vec!["root".to_string(), "admin".to_string()],
            passwords: vec![
                "password".to_string(),
                "123456".to_string(),
                "admin".to_string(),
            ],
            concurrency: 10,
            timeout: Duration::from_secs(5),
            delay_ms: None,
        }
    }
}

impl CrackConfig {
    /// 创建新的配置
    pub fn new(target: String, service: CrackService) -> Self {
        Self {
            target,
            port: service.default_port(),
            service,
            ..Default::default()
        }
    }

    /// 设置端口
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// 设置用户名列表
    pub fn with_usernames(mut self, usernames: Vec<String>) -> Self {
        self.usernames = usernames;
        self
    }

    /// 设置密码列表
    pub fn with_passwords(mut self, passwords: Vec<String>) -> Self {
        self.passwords = passwords;
        self
    }

    /// 设置并发数
    pub fn with_concurrency(mut self, concurrency: usize) -> Self {
        self.concurrency = concurrency;
        self
    }

    /// 设置超时
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// 设置延迟
    pub fn with_delay(mut self, delay_ms: u64) -> Self {
        self.delay_ms = Some(delay_ms);
        self
    }
}

/// 爆破结果状态
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CrackStatus {
    /// 成功
    Success,
    /// 失败
    Failed,
    /// 超时
    Timeout,
    /// 连接错误
    ConnectionError,
    /// 认证失败
    AuthFailed,
}

/// 爆破结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrackResult {
    /// 目标主机
    pub target: String,
    /// 目标端口
    pub port: u16,
    /// 服务类型
    pub service: String,
    /// 用户名（如果适用）
    pub username: Option<String>,
    /// 密码（如果成功）
    pub password: Option<String>,
    /// 状态
    pub status: CrackStatus,
    /// 消息
    pub message: String,
    /// 耗时（毫秒）
    pub elapsed_ms: u64,
}

impl CrackResult {
    /// 创建成功结果
    pub fn success(
        target: String,
        port: u16,
        service: CrackService,
        username: Option<String>,
        password: String,
        elapsed_ms: u64,
    ) -> Self {
        Self {
            target,
            port,
            service: service.name().to_string(),
            username,
            password: Some(password),
            status: CrackStatus::Success,
            message: "爆破成功".to_string(),
            elapsed_ms,
        }
    }

    /// 创建失败结果
    pub fn failed(
        target: String,
        port: u16,
        service: CrackService,
        username: Option<String>,
        message: String,
    ) -> Self {
        Self {
            target,
            port,
            service: service.name().to_string(),
            username,
            password: None,
            status: CrackStatus::Failed,
            message,
            elapsed_ms: 0,
        }
    }

    /// 判断是否成功
    pub fn is_success(&self) -> bool {
        self.status == CrackStatus::Success
    }
}

/// 爆破器trait
#[async_trait]
pub trait Cracker: Send + Sync {
    /// 执行爆破
    async fn crack(&self, config: &CrackConfig) -> CrackResult;

    /// 验证单个凭据
    async fn verify(&self, target: &str, port: u16, username: Option<&str>, password: &str) -> bool;
}
