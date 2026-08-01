//! MSSQL 爆破模块

use async_trait::async_trait;
use tiberius::{AuthMethod, Config};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_util::compat::TokioAsyncWriteCompatExt;

use crate::cracker::base;
use crate::cracker::service::{CrackConfig, CrackResult, CrackService, Cracker};

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
        let target = config.target.clone();
        let port = config.port;

        base::run_crack(config, CrackService::Mssql, "MSSQL", move |username, password, _, _, timeout| {
            let username = username.unwrap_or_else(|| "sa".to_string());

            // 使用 tokio runtime 执行异步连接
            let rt = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(_) => return false,
            };

            rt.block_on(async {
                let tcp_connect = match tokio::time::timeout(
                    Duration::from_secs(3),
                    TcpStream::connect((&target as &str, port))
                ).await {
                    Ok(Ok(stream)) => stream,
                    _ => return false,
                };

                let mut config = Config::new();
                config.host(&target);
                config.port(port);
                config.authentication(AuthMethod::sql_server(&username, &password));
                config.trust_cert();

                matches!(tokio::time::timeout(timeout, tiberius::Client::connect(config, tcp_connect.compat_write())).await, Ok(Ok(_conn)))
            })
        }).await
    }

    async fn verify(&self, target: &str, port: u16, username: Option<&str>, password: &str) -> bool {
        let username = username.unwrap_or("sa");
        Self::try_connect_async(target, port, username, password, Duration::from_secs(5)).await
    }
}

impl MssqlCracker {
    async fn try_connect_async(target: &str, port: u16, username: &str, password: &str, timeout: Duration) -> bool {
        let tcp_connect = match tokio::time::timeout(
            Duration::from_secs(3),
            TcpStream::connect((target, port))
        ).await {
            Ok(Ok(stream)) => stream,
            _ => return false,
        };

        let mut config = Config::new();
        config.host(target);
        config.port(port);
        config.authentication(AuthMethod::sql_server(username, password));
        config.trust_cert();

        matches!(tokio::time::timeout(timeout, tiberius::Client::connect(config, tcp_connect.compat_write())).await, Ok(Ok(_conn)))
    }
}
