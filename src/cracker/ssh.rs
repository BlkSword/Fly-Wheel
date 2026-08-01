//! SSH 爆破模块

use async_trait::async_trait;
use ssh2::Session;
use std::net::TcpStream;
use std::time::Duration;

use crate::cracker::base;
use crate::cracker::service::{CrackConfig, CrackResult, CrackService, Cracker};

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
        base::run_crack(
            config,
            CrackService::Ssh,
            "SSH",
            |username, password, target, port, timeout| {
                let user = username.as_deref().unwrap_or("root");
                Self::try_connect_sync(&target, port, user, &password, timeout)
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
        Self::try_connect_sync(target, port, username, password, Duration::from_secs(5))
    }
}

impl SshCracker {
    fn try_connect_sync(
        target: &str,
        port: u16,
        username: &str,
        password: &str,
        timeout: Duration,
    ) -> bool {
        let addr = format!("{}:{}", target, port);

        let stream = match TcpStream::connect(&addr) {
            Ok(s) => s,
            Err(_) => return false,
        };

        if stream.set_read_timeout(Some(timeout)).is_err() {
            return false;
        }
        if stream.set_write_timeout(Some(timeout)).is_err() {
            return false;
        }

        let mut sess = match Session::new() {
            Ok(s) => s,
            Err(_) => return false,
        };

        sess.set_tcp_stream(stream);

        if sess.handshake().is_err() {
            return false;
        }

        sess.userauth_password(username, password).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ssh_cracker_creation() {
        let cracker = SshCracker::new();
        assert!(
            !cracker
                .verify("127.0.0.1", 22, Some("root"), "wrongpassword")
                .await
        );
    }
}
