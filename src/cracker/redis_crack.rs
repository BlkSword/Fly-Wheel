//! Redis 爆破模块

use async_trait::async_trait;
use std::time::Duration;

use crate::cracker::base;
use crate::cracker::service::{CrackConfig, CrackResult, CrackService, Cracker};

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
        base::run_crack(
            config,
            CrackService::Redis,
            "Redis",
            |_username, password, target, port, timeout| {
                Self::try_connect_sync(&target, port, &password, timeout)
            },
        )
        .await
    }

    async fn verify(
        &self,
        target: &str,
        port: u16,
        _username: Option<&str>,
        password: &str,
    ) -> bool {
        Self::try_connect_sync(target, port, password, Duration::from_secs(5))
    }
}

impl RedisCracker {
    fn try_connect_sync(target: &str, port: u16, password: &str, _timeout: Duration) -> bool {
        let connection_string = if password.is_empty() || password == "nil" {
            format!("redis://{}:{}", target, port)
        } else {
            format!("redis://:{}@{}:{}", password, target, port)
        };

        let client = redis::Client::open(connection_string);
        if let Ok(client) = client {
            if let Ok(_conn) = client.get_connection() {
                return true;
            }
        }
        false
    }
}
