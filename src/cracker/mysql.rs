//! MySQL 爆破模块

use async_trait::async_trait;
use mysql_async::Pool;
use std::time::Duration;

use crate::cracker::service::{CrackConfig, CrackResult, CrackService, Cracker};
use tokio::sync::Semaphore;
use std::sync::Arc;

/// MySQL 爆破器
pub struct MysqlCracker;

impl MysqlCracker {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MysqlCracker {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Cracker for MysqlCracker {
    async fn crack(&self, config: &CrackConfig) -> CrackResult {
        let start = std::time::Instant::now();
        let semaphore = Arc::new(Semaphore::new(config.concurrency));
        let mut tasks = Vec::new();

        println!();
        println!("开始 MySQL 爆破...");
        println!("目标: {}:{}", config.target, config.port);
        println!("用户名数: {}", config.usernames.len());
        println!("密码数: {}", config.passwords.len());
        println!("总尝试次数: {}", config.usernames.len() * config.passwords.len());
        println!();

        for username in &config.usernames {
            for password in &config.passwords {
                let semaphore = semaphore.clone();
                let target = config.target.clone();
                let port = config.port;
                let username = username.clone();
                let password = password.clone();
                let timeout = config.timeout;
                let delay = config.delay_ms;

                let task = tokio::spawn(async move {
                    let _permit = semaphore.acquire().await.unwrap();
                    let result = Self::try_connect(&target, port, &username, &password, timeout).await;

                    // 延迟
                    if let Some(delay_ms) = delay {
                        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    }

                    (username, password, result)
                });

                tasks.push(task);
            }
        }

        // 等待所有任务完成
        for task in tasks {
            if let Ok((username, password, success)) = task.await {
                if success {
                    let elapsed = start.elapsed().as_millis() as u64;
                    return CrackResult::success(
                        config.target.clone(),
                        config.port,
                        CrackService::Mysql,
                        Some(username),
                        password,
                        elapsed,
                    );
                }
            }
        }

        CrackResult::failed(
            config.target.clone(),
            config.port,
            CrackService::Mysql,
            None,
            "所有凭据尝试失败".to_string(),
        )
    }

    async fn verify(&self, target: &str, port: u16, username: Option<&str>, password: &str) -> bool {
        let username = username.unwrap_or("root");
        Self::try_connect(target, port, username, password, Duration::from_secs(5)).await
    }
}

impl MysqlCracker {
    /// 尝试连接
    async fn try_connect(target: &str, port: u16, username: &str, password: &str, timeout: Duration) -> bool {
        let url = format!(
            "mysql://{}:{}@{}:{}/mysql",
            username, password, target, port
        );

        // from_url 返回 Result，需要在异步上下文中使用
        let pool = match Pool::from_url(&url) {
            Ok(p) => p,
            Err(_) => return false,
        };

        // 尝试获取连接来验证凭据
        match tokio::time::timeout(timeout, pool.get_conn()).await {
            Ok(Ok(_)) => true,
            _ => false,
        }
    }
}
