//! MSSQL 爆破模块

use async_trait::async_trait;
use tiberius::{AuthMethod, Config};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_util::compat::TokioAsyncWriteCompatExt;

use crate::cracker::service::{CrackConfig, CrackResult, CrackService, Cracker};
use tokio::sync::Semaphore;
use std::sync::Arc;

/// MSSQL 爆破器
pub struct MssqlCracker;

impl MssqlCracker {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MssqlCracker {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Cracker for MssqlCracker {
    async fn crack(&self, config: &CrackConfig) -> CrackResult {
        let start = std::time::Instant::now();
        let semaphore = Arc::new(Semaphore::new(config.concurrency));
        let mut tasks = Vec::new();

        println!();
        println!("开始 MSSQL 爆破...");
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
                        CrackService::Mssql,
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
            CrackService::Mssql,
            None,
            "所有凭据尝试失败".to_string(),
        )
    }

    async fn verify(&self, target: &str, port: u16, username: Option<&str>, password: &str) -> bool {
        let username = username.unwrap_or("sa");
        Self::try_connect(target, port, username, password, Duration::from_secs(5)).await
    }
}

impl MssqlCracker {
    /// 尝试连接
    async fn try_connect(target: &str, port: u16, username: &str, password: &str, timeout: Duration) -> bool {
        // 先建立 TCP 连接
        let tcp_connect = match tokio::time::timeout(
            Duration::from_secs(3),
            TcpStream::connect((target, port))
        ).await {
            Ok(Ok(stream)) => stream,
            _ => return false,
        };

        // 配置连接
        let mut config = Config::new();
        config.host(&target);
        config.port(port);
        config.authentication(AuthMethod::sql_server(username, password));
        config.trust_cert();

        // 使用 compat_write() 转换为 futures 兼容的流
        match tokio::time::timeout(timeout, tiberius::Client::connect(config, tcp_connect.compat_write())).await {
            Ok(Ok(_conn)) => true,
            _ => false,
        }
    }
}
