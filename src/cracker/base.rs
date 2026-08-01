//! 爆破模块公共引擎
//!
//! 提供统一的并发控制、提前终止和结果收集逻辑，
//! 消除各 cracker 实现中的重复代码。

use crate::cracker::service::{CrackConfig, CrackResult, CrackService};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

/// 爆破任务的单次尝试凭据
#[derive(Debug)]
pub struct Attempt {
    pub username: Option<String>,
    pub password: String,
}

/// 单次尝试结果
pub struct AttemptResult {
    pub attempt: Attempt,
    pub success: bool,
}

/// 带提前终止的并发爆破引擎
///
/// - 使用 Semaphore 控制并发数
/// - 使用 AtomicBool 在首次成功后立即停止派发新任务
/// - 所有 .unwrap() 已消除，使用安全的错误处理
pub async fn run_crack(
    config: &CrackConfig,
    service: CrackService,
    print_info: &str,
    try_connect: impl Fn(Option<String>, String, String, u16, Duration) -> bool + Send + Sync + 'static,
) -> CrackResult {
    let start = std::time::Instant::now();
    let semaphore = Arc::new(Semaphore::new(config.concurrency));
    let found = Arc::new(AtomicBool::new(false));

    // 构建尝试列表
    let attempts = build_attempts(config);

    let total = attempts.len();

    // 打印信息
    println!();
    println!(
        "开始 {} {}...",
        print_info,
        crate::core::obfstr::sensitive::crack_label()
    );
    println!("目标: {}:{}", config.target, config.port);
    if config.usernames.is_empty() || !service.requires_username() {
        println!("密码数: {}", config.passwords.len());
    } else {
        println!("用户名数: {}", config.usernames.len());
        println!("密码数: {}", config.passwords.len());
    }
    println!("总尝试次数: {}", total);
    println!();

    let mut tasks = Vec::with_capacity(total.min(config.concurrency * 2));

    // 将闭包包装一次，所有任务共享
    type TryConnectFn =
        Arc<dyn Fn(Option<String>, String, String, u16, Duration) -> bool + Send + Sync>;
    let try_connect_arc: TryConnectFn = Arc::new(try_connect);

    for attempt in attempts {
        // 如果已经找到，不再派发新任务
        if found.load(Ordering::Relaxed) {
            break;
        }

        let semaphore = semaphore.clone();
        let found = found.clone();
        let target = config.target.clone();
        let port = config.port;
        let timeout = config.timeout;
        let delay = config.delay_ms;
        let try_connect_owned = try_connect_arc.clone();

        let task = tokio::spawn(async move {
            // 如果已经找到，直接跳过
            if found.load(Ordering::Relaxed) {
                return None;
            }

            // 安全获取信号量
            let _permit = match semaphore.acquire().await {
                Ok(p) => p,
                Err(_) => return None,
            };

            // 再次检查，因为等待信号量期间可能已找到
            if found.load(Ordering::Relaxed) {
                return None;
            }

            let username = attempt.username.clone();
            let password = attempt.password.clone();
            let target_clone = target.clone();
            let try_connect_blocking = try_connect_owned.clone();
            let username_for_log = username.clone();
            let result = tokio::task::spawn_blocking(move || {
                try_connect_blocking(username, password, target_clone, port, timeout)
            })
            .await
            .unwrap_or(false);

            // 延迟
            if let Some(delay_ms) = delay {
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }

            if result {
                tracing::info!(
                    "找到有效凭据 - {}: {}@{}:{}",
                    service.name(),
                    username_for_log.as_deref().unwrap_or("-"),
                    target,
                    port
                );
                found.store(true, Ordering::Relaxed);
                Some(AttemptResult {
                    attempt,
                    success: true,
                })
            } else {
                None
            }
        });

        tasks.push(task);
    }

    // 等待所有任务完成
    for task in tasks {
        if let Ok(Some(result)) = task.await {
            if result.success {
                let elapsed = start.elapsed().as_millis() as u64;
                return CrackResult::success(
                    config.target.clone(),
                    config.port,
                    service,
                    result.attempt.username,
                    result.attempt.password,
                    elapsed,
                );
            }
        }
    }

    CrackResult::failed(
        config.target.clone(),
        config.port,
        service,
        None,
        "所有凭据尝试失败".to_string(),
    )
}

/// 根据服务类型构建尝试列表
fn build_attempts(config: &CrackConfig) -> Vec<Attempt> {
    if config.usernames.is_empty() || !config.service.requires_username() {
        // 无需用户名的服务 (Redis, MongoDB)
        config
            .passwords
            .iter()
            .map(|p| Attempt {
                username: None,
                password: p.clone(),
            })
            .collect()
    } else {
        // 需要用户名的服务
        let mut attempts = Vec::with_capacity(config.usernames.len() * config.passwords.len());
        for username in &config.usernames {
            for password in &config.passwords {
                attempts.push(Attempt {
                    username: Some(username.clone()),
                    password: password.clone(),
                });
            }
        }
        attempts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cracker::service::CrackService;
    use std::time::Duration;

    fn make_config(service: CrackService) -> CrackConfig {
        CrackConfig::new("127.0.0.1".to_string(), service)
            .with_usernames(vec!["root".to_string()])
            .with_passwords(vec!["123456".to_string(), "password".to_string()])
            .with_concurrency(2)
            .with_timeout(Duration::from_secs(2))
    }

    #[tokio::test]
    async fn test_run_crack_all_fail() {
        let config = make_config(CrackService::Ssh);
        let result = run_crack(&config, CrackService::Ssh, "SSH测试", |_, _, _, _, _| {
            false
        })
        .await;
        assert!(!result.is_success());
    }

    #[tokio::test]
    async fn test_run_crack_immediate_success() {
        let config = make_config(CrackService::Ssh);
        let result = run_crack(&config, CrackService::Ssh, "SSH测试", |_, _, _, _, _| {
            true
        })
        .await;
        assert!(result.is_success());
        assert_eq!(result.username, Some("root".to_string()));
    }

    #[test]
    fn test_build_attempts_with_usernames() {
        let config = CrackConfig::new("127.0.0.1".to_string(), CrackService::Ssh)
            .with_usernames(vec!["root".to_string(), "admin".to_string()])
            .with_passwords(vec!["123456".to_string()]);
        let attempts = build_attempts(&config);
        assert_eq!(attempts.len(), 2);
        assert_eq!(attempts[0].username, Some("root".to_string()));
        assert_eq!(attempts[1].username, Some("admin".to_string()));
    }

    #[test]
    fn test_build_attempts_no_usernames() {
        let config = CrackConfig::new("127.0.0.1".to_string(), CrackService::Redis)
            .with_passwords(vec!["123456".to_string(), "password".to_string()]);
        let attempts = build_attempts(&config);
        assert_eq!(attempts.len(), 2);
        assert!(attempts[0].username.is_none());
    }
}
