//! DCSync 攻击模块
//!
//! 模拟一个域控制器向另一个域控制器请求同步密码数据。
//! 需要拥有 DS-Replication-Get-Changes 和 DS-Replication-Get-Changes-All 权限
//! （域管理员默认拥有此权限）。
//!
//! 使用DCSync可以：
//! 1. 提取任意域用户的NTLM哈希
//! 2. 提取krbtgt账户的哈希（用于Golden Ticket）
//! 3. 提取所有域用户的密码历史
//!
//! 关键信息：
//! - 目录复制权限（Domain Admins, Enterprise Admins, Administrators默认拥有）
//! - 域控制器地址
//! - 目标用户（可选，默认提取所有用户的哈希）

use serde::{Deserialize, Serialize};

/// DCSync 结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DcsyncResult {
    /// 用户名
    pub username: String,
    /// NTLM哈希
    pub ntlm_hash: String,
    /// LM哈希
    pub lm_hash: Option<String>,
    /// 用户RID
    pub rid: u32,
    /// 是否启用
    pub enabled: bool,
    /// 上次密码修改时间
    pub pwd_last_set: Option<String>,
    /// 密码过期时间
    pub pwd_expires: Option<String>,
    /// 用户账户控制标记
    pub user_account_control: u32,
    /// 凭据类型(明文/NTLM/Kerberos密钥等)
    pub credential_type: Option<String>,
}

/// 执行 DCSync 攻击
///
/// # Arguments
/// * `dc` - 域控制器地址
/// * `domain` - 域名
/// * `username` - 具有复制权限的账户
/// * `password` - 密码（可选）
/// * `nthash` - NTLM哈希（可选，用于PtH认证）
/// * `target_user` - 要提取哈希的目标用户（可选，默认所有用户）
pub async fn dcsync(
    dc: &str,
    domain: &str,
    username: &str,
    password: Option<&str>,
    nthash: Option<&str>,
    target_user: Option<&str>,
) -> Result<Vec<DcsyncResult>, String> {
    tracing::info!(
        "[DCSync] 从 {} 同步凭据 (域: {}, 用户: {})",
        dc,
        domain,
        target_user.unwrap_or("所有用户")
    );

    // 通过DRSUAPI协议执行DCSync
    // 使用IDL_DRSGetNCChanges请求复制数据

    // 建立与DC的SMB连接（用于认证）
    // 1. 通过SMB连接到IPC$共享
    // 2. 绑定到DRSUAPI RPC接口
    // 3. 调用IDL_DRSGetNCChanges请求用户凭据数据

    let results = match (password, nthash) {
        (Some(pwd), _) => {
            dcsync_with_password(dc, domain, username, pwd, target_user).await
        }
        (_, Some(hash)) => {
            dcsync_with_hash(dc, domain, username, hash, target_user).await
        }
        _ => {
            return Err("需要提供密码或NTLM哈希进行认证".to_string());
        }
    }?;

    if results.is_empty() {
        tracing::warn!("[DCSync] 未获取到凭据数据");
    } else {
        tracing::info!("[DCSync] 成功获取 {} 个用户的凭据", results.len());
    }

    Ok(results)
}

/// 使用密码认证执行DCSync
async fn dcsync_with_password(
    _dc: &str,
    _domain: &str,
    _username: &str,
    _password: &str,
    _target_user: Option<&str>,
) -> Result<Vec<DcsyncResult>, String> {
    Err("DCSync (DRSUAPI) 尚未实现。当前版本无法执行真实的目录复制请求。请使用 mimikatz 或 impacket 的 secretsdump.py 替代。".to_string())
}

/// 使用NTLM哈希认证执行DCSync (Pass-the-Hash)
async fn dcsync_with_hash(
    _dc: &str,
    _domain: &str,
    _username: &str,
    _nthash: &str,
    _target_user: Option<&str>,
) -> Result<Vec<DcsyncResult>, String> {
    Err("DCSync (DRSUAPI) 尚未实现。当前版本无法执行真实的目录复制请求。请使用 mimikatz 或 impacket 的 secretsdump.py 替代。".to_string())
}

/// 导出DCSync结果为hashcat破解格式
pub fn export_to_hashcat(results: &[DcsyncResult]) -> String {
    results
        .iter()
        .map(|r| {
            format!(
                "{}:{}:{}:{}:::",
                r.username,
                r.rid,
                r.lm_hash.as_deref().unwrap_or("aad3b435b51404eeaad3b435b51404ee"),
                r.ntlm_hash,
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// 导出DCSync结果为pwdump格式
pub fn export_to_pwdump(results: &[DcsyncResult]) -> String {
    results
        .iter()
        .map(|r| {
            format!(
                "{}:{}:{}:{}:{}:::",
                r.username,
                r.rid,
                r.lm_hash.as_deref().unwrap_or("aad3b435b51404eeaad3b435b51404ee"),
                r.ntlm_hash,
                r.pwd_last_set.as_deref().unwrap_or(""),
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dcsync_result_creation() {
        let result = DcsyncResult {
            username: "Administrator".to_string(),
            ntlm_hash: "31d6cfe0d16ae931b73c59d7e0c089c0".to_string(),
            lm_hash: Some("aad3b435b51404eeaad3b435b51404ee".to_string()),
            rid: 500,
            enabled: true,
            pwd_last_set: Some("2024-01-01T00:00:00".to_string()),
            pwd_expires: None,
            user_account_control: 0x10200,
            credential_type: Some("NTLM哈希".to_string()),
        };

        assert_eq!(result.username, "Administrator");
        assert_eq!(result.rid, 500);
        assert!(result.enabled);
    }

    #[test]
    fn test_export_to_hashcat() {
        let results = vec![
            DcsyncResult {
                username: "admin".to_string(),
                ntlm_hash: "aaa".to_string(),
                lm_hash: None,
                rid: 500,
                enabled: true,
                pwd_last_set: None,
                pwd_expires: None,
                user_account_control: 512,
                credential_type: None,
            },
        ];
        let output = export_to_hashcat(&results);
        assert!(output.contains("admin"));
        assert!(output.contains("aaa"));
    }

    #[test]
    fn test_export_to_pwdump() {
        let results = vec![
            DcsyncResult {
                username: "testuser".to_string(),
                ntlm_hash: "bbb".to_string(),
                lm_hash: Some("ccc".to_string()),
                rid: 1000,
                enabled: true,
                pwd_last_set: Some("2024-01-01".to_string()),
                pwd_expires: None,
                user_account_control: 512,
                credential_type: None,
            },
        ];
        let output = export_to_pwdump(&results);
        assert!(output.contains("testuser"));
        assert!(output.contains("bbb"));
        assert!(output.contains("ccc"));
    }
}
