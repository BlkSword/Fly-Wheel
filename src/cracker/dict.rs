//! 字典管理模块

#![allow(dead_code)]

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;

/// 字典条目
#[derive(Debug, Clone)]
pub struct DictEntry {
    /// 内容
    pub content: String,
    /// 行号
    pub line_number: usize,
}

/// 字典管理器
pub struct DictManager {
    /// 用户名字典
    usernames: Vec<String>,
    /// 密码字典
    passwords: Vec<String>,
}

impl Default for DictManager {
    fn default() -> Self {
        Self::new()
    }
}

impl DictManager {
    /// 创建新的字典管理器
    pub fn new() -> Self {
        Self {
            usernames: Self::default_usernames(),
            passwords: Self::default_passwords(),
        }
    }

    /// 获取默认用户名列表
    fn default_usernames() -> Vec<String> {
        vec![
            "root".to_string(),
            "admin".to_string(),
            "administrator".to_string(),
            "test".to_string(),
            "user".to_string(),
            "guest".to_string(),
            "oracle".to_string(),
            "postgres".to_string(),
            "mysql".to_string(),
            "mongodb".to_string(),
            "redis".to_string(),
            "sa".to_string(),
        ]
    }

    /// 获取默认密码列表
    fn default_passwords() -> Vec<String> {
        vec![
            "".to_string(),           // 空密码
            "password".to_string(),
            "123456".to_string(),
            "12345678".to_string(),
            "admin".to_string(),
            "root".to_string(),
            "test".to_string(),
            "guest".to_string(),
            "password123".to_string(),
            "qwerty".to_string(),
            "1q2w3e".to_string(),
            "123123".to_string(),
        ]
    }

    /// 验证字典文件是否存在并返回条目数量
    pub fn validate_dict_file<P: AsRef<Path>>(path: P) -> Result<usize> {
        let path_ref = path.as_ref();

        // 检查文件是否存在
        if !path_ref.exists() {
            return Err(anyhow::anyhow!("文件不存在: {}", path_ref.display()));
        }

        // 检查是否为文件
        if !path_ref.is_file() {
            return Err(anyhow::anyhow!("不是有效的文件: {}", path_ref.display()));
        }

        // 尝试打开文件并计数条目
        let file = File::open(&path_ref).context("无法打开字典文件")?;
        let reader = BufReader::new(file);
        let count = reader
            .lines()
            .filter_map(|line| line.ok())
            .map(|line| line.trim().to_string())
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .count();

        if count == 0 {
            return Err(anyhow::anyhow!("字典文件为空或没有有效条目: {}", path_ref.display()));
        }

        Ok(count)
    }

    /// 从文件加载用户名（带进度条）
    pub fn load_usernames_from_file<P: AsRef<Path>>(&mut self, path: P) -> Result<usize> {
        let file = File::open(&path).context("无法打开用户名字典文件")?;
        let reader = BufReader::new(file);

        // 创建进度条
        let pb = ProgressBar::new_spinner();
        pb.set_style(ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .expect("创建进度条样式失败"));
        pb.set_message("正在加载用户名字典...");
        pb.enable_steady_tick(Duration::from_millis(100));

        let usernames: Vec<String> = reader
            .lines()
            .filter_map(|line| line.ok())
            .map(|line| line.trim().to_string())
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect();

        self.usernames = usernames;

        let count = self.usernames.len();
        pb.finish();
        println!("✓ 已加载 {} 个用户名", count);

        Ok(self.usernames.len())
    }

    /// 从文件加载密码（带进度条）
    pub fn load_passwords_from_file<P: AsRef<Path>>(&mut self, path: P) -> Result<usize> {
        let file = File::open(&path).context("无法打开密码字典文件")?;
        let reader = BufReader::new(file);

        // 创建进度条
        let pb = ProgressBar::new_spinner();
        pb.set_style(ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .expect("创建进度条样式失败"));
        pb.set_message("正在加载密码字典...");
        pb.enable_steady_tick(Duration::from_millis(100));

        let passwords: Vec<String> = reader
            .lines()
            .filter_map(|line| line.ok())
            .map(|line| line.trim().to_string())
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect();

        self.passwords = passwords;

        let count = self.passwords.len();
        pb.finish();
        println!("✓ 已加载 {} 个密码", count);

        Ok(self.passwords.len())
    }

    /// 添加单个用户名
    pub fn add_username(&mut self, username: String) {
        if !self.usernames.contains(&username) {
            self.usernames.push(username);
        }
    }

    /// 添加单个密码
    pub fn add_password(&mut self, password: String) {
        if !self.passwords.contains(&password) {
            self.passwords.push(password);
        }
    }

    /// 设置用户名列表
    pub fn set_usernames(&mut self, usernames: Vec<String>) {
        self.usernames = usernames;
    }

    /// 设置密码列表
    pub fn set_passwords(&mut self, passwords: Vec<String>) {
        self.passwords = passwords;
    }

    /// 获取用户名列表
    pub fn usernames(&self) -> &[String] {
        &self.usernames
    }

    /// 获取密码列表
    pub fn passwords(&self) -> &[String] {
        &self.passwords
    }

    /// 获取用户名数量
    pub fn username_count(&self) -> usize {
        self.usernames.len()
    }

    /// 获取密码数量
    pub fn password_count(&self) -> usize {
        self.passwords.len()
    }

    /// 获取总尝试次数
    pub fn total_attempts(&self) -> usize {
        self.usernames.len() * self.passwords.len()
    }

    /// 生成用户名密码组合
    pub fn generate_combinations(&self) -> Vec<(String, String)> {
        let mut combinations = Vec::new();
        for username in &self.usernames {
            for password in &self.passwords {
                combinations.push((username.clone(), password.clone()));
            }
        }
        combinations
    }

    /// 创建迭代器
    pub fn iter(&self) -> DictIterator<'_> {
        DictIterator {
            usernames: &self.usernames,
            passwords: &self.passwords,
            username_idx: 0,
            password_idx: 0,
        }
    }
}

/// 字典迭代器
pub struct DictIterator<'a> {
    usernames: &'a [String],
    passwords: &'a [String],
    username_idx: usize,
    password_idx: usize,
}

impl<'a> Iterator for DictIterator<'a> {
    type Item = (Option<&'a str>, &'a str);

    fn next(&mut self) -> Option<Self::Item> {
        if self.username_idx >= self.usernames.len() {
            return None;
        }

        let username = if self.usernames.is_empty() {
            None
        } else {
            Some(self.usernames[self.username_idx].as_str())
        };

        let password = &self.passwords[self.password_idx];

        self.password_idx += 1;
        if self.password_idx >= self.passwords.len() {
            self.password_idx = 0;
            self.username_idx += 1;
        }

        Some((username, password))
    }
}

/// 从字符串创建用户名列表
pub fn parse_usernames(input: &str) -> Vec<String> {
    input
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// 从字符串创建密码列表
pub fn parse_passwords(input: &str) -> Vec<String> {
    input
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_dict() {
        let dict = DictManager::new();
        assert!(!dict.usernames().is_empty());
        assert!(!dict.passwords().is_empty());
    }

    #[test]
    fn test_parse_usernames() {
        let usernames = parse_usernames("root,admin,test");
        assert_eq!(usernames, vec!["root", "admin", "test"]);
    }

    #[test]
    fn test_parse_passwords() {
        let passwords = parse_passwords("123456,password,admin");
        assert_eq!(passwords, vec!["123456", "password", "admin"]);
    }

    #[test]
    fn test_dict_iterator() {
        let dict = DictManager::new();
        let mut iter = dict.iter();
        let (username, password) = iter.next().unwrap();
        assert!(username.is_some());
        assert!(!password.is_empty());
    }
}
