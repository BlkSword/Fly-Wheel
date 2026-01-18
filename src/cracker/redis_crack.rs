//! Redis 爆破模块

use async_trait::async_trait;
use std::time::Duration;

use crate::cracker::service::{CrackConfig, CrackResult, CrackService, Cracker};
use tokio::sync::Semaphore;
use std::sync::Arc;

/// Redis 爆破器
pub struct RedisCracker;

impl RedisCracker {
    pub fn new() -> Self {
        Self
    }
}

impl Default for RedisCracker {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Cracker for RedisCracker {
    async fn crack(&self, config: &CrackConfig) -> CrackResult {
        let start = std::time::Instant::now();
        let semaphore = Arc::new(Semaphore::new(config.concurrency));
        let mut tasks = Vec::new();

        println!();
        println!("开始 Redis 爆破...");
        println!("目标: {}:{}", config.target, config.port);
        println!("密码数: {}", config.passwords.len());
        println!("总尝试次数: {}", config.passwords.len());
        println!();

        for password in &config.passwords {
            let semaphore = semaphore.clone();
            let target = config.target.clone();
            let port = config.port;
            let password = password.clone();
            let timeout = config.timeout;
            let delay = config.delay_ms;

            let task = tokio::spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();
                let result = Self::try_connect(&target, port, &password, timeout).await;

                // 延迟
                if let Some(delay_ms) = delay {
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                }

                (password, result)
            });

            tasks.push(task);
        }

        // 等待所有任务完成
        for task in tasks {
            if let Ok((password, success)) = task.await {
                if success {
                    let elapsed = start.elapsed().as_millis() as u64;
                    return CrackResult::success(
                        config.target.clone(),
                        config.port,
                        CrackService::Redis,
                        None,
                        password,
                        elapsed,
                    );
                }
            }
        }

        CrackResult::failed(
            config.target.clone(),
            config.port,
            CrackService::Redis,
            None,
            "所有密码尝试失败".to_string(),
        )
    }

    async fn verify(&self, target: &str, port: u16, _username: Option<&str>, password: &str) -> bool {
        Self::try_connect(target, port, password, Duration::from_secs(5)).await
    }
}

impl RedisCracker {
    /// 尝试连接
    async fn try_connect(target: &str, port: u16, password: &str, timeout: Duration) -> bool {
        // 构建连接字符串
        let connection_string = if password.is_empty() || password == "nil" {
            format!("redis://{}:{}", target, port)
        } else {
            format!("redis://:{}@{}:{}", password, target, port)
        };

        // 尝试连接
        match tokio::time::timeout(
            timeout,
            tokio::task::spawn_blocking(move || {
                let client = redis::Client::open(connection_string);
                if let Ok(client) = client {
                    if let Ok(_conn) = client.get_connection() {
                        return true;
                    }
                }
                false
            })
        ).await {
            Ok(Ok(true)) => true,
            _ => false,
        }
    }
}
