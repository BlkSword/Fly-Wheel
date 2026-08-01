//! PostgreSQL 爆破模块

use async_trait::async_trait;
use std::time::Duration;
use tokio_postgres::NoTls;

use crate::cracker::base;
use crate::cracker::service::{CrackConfig, CrackResult, CrackService, Cracker};

/// PostgreSQL 爆破器
pub struct PostgresCracker;

impl PostgresCracker {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PostgresCracker {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Cracker for PostgresCracker {
    async fn crack(&self, config: &CrackConfig) -> CrackResult {
        let target = config.target.clone();
        let port = config.port;

        base::run_crack(
            config,
            CrackService::Postgres,
            "PostgreSQL",
            move |username, password, _, _, _timeout| {
                let username = username.unwrap_or_else(|| "postgres".to_string());
                let conn_str = format!(
                    "host={} port={} user={} password={} dbname=postgres",
                    target, port, username, password
                );

                // 使用 tokio runtime 来执行异步连接
                let rt = match tokio::runtime::Runtime::new() {
                    Ok(rt) => rt,
                    Err(_) => return false,
                };

                rt.block_on(tokio_postgres::connect(&conn_str, NoTls))
                    .is_ok()
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
        let username = username.unwrap_or("postgres");
        let conn_str = format!(
            "host={} port={} user={} password={} dbname=postgres",
            target, port, username, password
        );

        matches!(
            tokio::time::timeout(
                Duration::from_secs(5),
                tokio_postgres::connect(&conn_str, NoTls)
            )
            .await,
            Ok(Ok(_conn))
        )
    }
}
