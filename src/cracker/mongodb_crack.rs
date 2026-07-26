//! MongoDB 爆破模块

use async_trait::async_trait;
use mongodb::{Client, options::ClientOptions};
use std::time::Duration;

use crate::cracker::base;
use crate::cracker::service::{CrackConfig, CrackResult, CrackService, Cracker};

/// MongoDB 爆破器
pub struct MongodbCracker;

impl MongodbCracker {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MongodbCracker {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Cracker for MongodbCracker {
    async fn crack(&self, config: &CrackConfig) -> CrackResult {
        let target = config.target.clone();
        let port = config.port;

        base::run_crack(config, CrackService::Mongodb, "MongoDB", move |_username, password, _, _, timeout| {
            let target = target.clone();
            let rt = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(_) => return false,
            };

            rt.block_on(async {
                Self::try_connect_async(&target, port, &password, timeout).await
            })
        }).await
    }

    async fn verify(&self, target: &str, port: u16, _username: Option<&str>, password: &str) -> bool {
        Self::try_connect_async(target, port, password, Duration::from_secs(5)).await
    }
}

impl MongodbCracker {
    /// 真正验证 MongoDB 连接：Client::with_options 是惰性的，必须执行 ping 才能确认认证结果
    async fn try_connect_async(target: &str, port: u16, password: &str, timeout: Duration) -> bool {
        let connection_string = format!(
            "mongodb://:{}@{}:{}/admin?serverSelectionTimeoutMS={}&connectTimeoutMS={}",
            password,
            target,
            port,
            timeout.as_millis(),
            timeout.as_millis()
        );

        match tokio::time::timeout(timeout + Duration::from_secs(2), async {
            match ClientOptions::parse(&connection_string).await {
                Ok(opts) => {
                    match Client::with_options(opts) {
                        Ok(client) => {
                            // 必须执行 ping 才能真正验证连接和认证
                            use mongodb::bson::doc;
                            client
                                .database("admin")
                                .run_command(doc! { "ping": 1 })
                                .await
                                .is_ok()
                        }
                        Err(_) => false,
                    }
                }
                Err(_) => false,
            }
        }).await
        {
            Ok(success) => success,
            Err(_) => false,
        }
    }
}
