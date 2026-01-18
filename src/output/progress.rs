//! 进度条模块
//!
//! 提供扫描进度显示功能

#![allow(dead_code)]

use comfy_table::presets::UTF8_FULL;
use comfy_table::Table;
use indicatif::{ProgressBar, ProgressStyle};
use std::io::{self, Write};
use std::time::Duration;

/// 扫描进度条
pub struct ScanProgress {
    bar: ProgressBar,
    total: usize,
    current: usize,
    show_eta: bool,
}

impl ScanProgress {
    /// 创建新的进度条
    pub fn new(total: usize, show_eta: bool) -> Self {
        let bar = ProgressBar::new(total as u64);

        let style = ProgressStyle::default_bar()
            .template(
                "{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} ({eta})",
            )
            .expect("创建进度条样式失败")
            .progress_chars("=>-");

        bar.set_style(style);
        bar.enable_steady_tick(Duration::from_millis(100));

        Self {
            bar,
            total,
            current: 0,
            show_eta,
        }
    }

    /// 使用默认配置创建
    pub fn with_default(total: usize) -> Self {
        Self::new(total, true)
    }

    /// 隐藏进度条（静默模式）
    pub fn hidden() -> Self {
        let bar = ProgressBar::hidden();
        Self {
            bar,
            total: 0,
            current: 0,
            show_eta: false,
        }
    }

    /// 增加进度
    pub fn inc(&self, n: u64) {
        self.bar.inc(n);
    }

    /// 设置当前进度
    pub fn set_position(&self, pos: usize) {
        self.bar.set_position(pos as u64);
    }

    /// 设置消息
    pub fn set_message(&self, msg: &str) {
        self.bar.set_message(msg.to_string());
    }

    /// 完成进度条并显示消息
    pub fn finish_with_message(&self, msg: &str) {
        self.bar.finish_with_message(msg.to_string());
    }

    /// 完成进度条
    pub fn finish(&self) {
        self.bar.finish();
    }

    /// 放弃进度条（显示警告信息）
    pub fn abandon(&self) {
        self.bar.abandon();
    }

    /// 放弃进度条并显示消息
    pub fn abandon_with_message(&self, msg: &str) {
        self.bar.abandon_with_message(msg.to_string());
    }

    /// 获取当前进度
    pub fn current(&self) -> usize {
        self.current
    }

    /// 获取总进度
    pub fn total(&self) -> usize {
        self.total
    }

    /// 获取进度百分比
    pub fn percentage(&self) -> f64 {
        if self.total == 0 {
            100.0
        } else {
            (self.current as f64 / self.total as f64) * 100.0
        }
    }

    /// 检查是否完成
    pub fn is_finished(&self) -> bool {
        self.current >= self.total
    }
}

impl Drop for ScanProgress {
    fn drop(&mut self) {
        if !self.is_finished() {
            self.bar.finish();
        }
    }
}

/// 简单文本进度条（无需外部依赖）
pub struct SimpleProgress {
    current: usize,
    total: usize,
    width: usize,
    last_print_len: usize,
}

impl SimpleProgress {
    /// 创建新的简单进度条
    pub fn new(total: usize) -> Self {
        Self {
            current: 0,
            total,
            width: 50,
            last_print_len: 0,
        }
    }

    /// 设置进度条宽度
    pub fn set_width(&mut self, width: usize) {
        self.width = width;
    }

    /// 更新进度
    pub fn update(&mut self, current: usize) {
        self.current = current;
        self.print();
    }

    /// 增加进度
    pub fn inc(&mut self, n: usize) {
        self.current += n;
        self.print();
    }

    /// 打印进度条
    fn print(&mut self) {
        let progress = if self.total > 0 {
            (self.current as f64 / self.total as f64) * 100.0
        } else {
            100.0
        };

        let filled = (progress as usize) * self.width / 100;
        let bar: String = std::iter::repeat('=')
            .take(filled)
            .chain(std::iter::repeat(' '))
            .take(self.width)
            .collect();

        let msg = format!("\r[{}] {:.1}% ({}/{})", bar, progress, self.current, self.total);

        // 计算需要清除的字符数
        let clear_len = if msg.len() < self.last_print_len {
            self.last_print_len - msg.len()
        } else {
            0
        };

        let clear_spaces: String = " ".repeat(clear_len);
        let full_msg = format!("{}{}", msg, clear_spaces);

        print!("{}", full_msg);
        io::stdout().flush().unwrap();

        self.last_print_len = msg.len();
    }

    /// 完成进度条
    pub fn finish(&mut self, msg: Option<&str>) {
        self.current = self.total;
        self.print();

        if let Some(message) = msg {
            println!("\r{}", message);
        } else {
            println!();
        }
    }
}

impl Drop for SimpleProgress {
    fn drop(&mut self) {
        if self.current < self.total {
            self.finish(None);
        }
    }
}

/// 多任务进度跟踪器
pub struct MultiProgress {
    tasks: Vec<TaskProgress>,
    total_tasks: usize,
}

/// 单个任务进度
#[derive(Debug, Clone)]
pub struct TaskProgress {
    pub name: String,
    pub current: usize,
    pub total: usize,
    pub status: TaskStatus,
}

/// 任务状态
#[derive(Debug, Clone, PartialEq)]
pub enum TaskStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
}

impl MultiProgress {
    /// 创建新的多任务进度跟踪器
    pub fn new(total_tasks: usize) -> Self {
        Self {
            tasks: Vec::with_capacity(total_tasks),
            total_tasks,
        }
    }

    /// 添加任务
    pub fn add_task(&mut self, name: String, total: usize) {
        self.tasks.push(TaskProgress {
            name,
            current: 0,
            total,
            status: TaskStatus::Pending,
        });
    }

    /// 更新任务进度
    pub fn update_task(&mut self, index: usize, current: usize) {
        if let Some(task) = self.tasks.get_mut(index) {
            task.current = current;
            task.status = TaskStatus::InProgress;
        }
    }

    /// 完成任务
    pub fn complete_task(&mut self, index: usize) {
        if let Some(task) = self.tasks.get_mut(index) {
            task.current = task.total;
            task.status = TaskStatus::Completed;
        }
    }

    /// 标记任务失败
    pub fn fail_task(&mut self, index: usize) {
        if let Some(task) = self.tasks.get_mut(index) {
            task.status = TaskStatus::Failed;
        }
    }

    /// 打印所有任务状态
    pub fn print(&self) {
        let mut table = Table::new();
        table.load_preset(UTF8_FULL);
        table.set_header(vec!["任务", "进度", "状态"]);

        for task in &self.tasks {
            let progress = format!("{}/{}", task.current, task.total);
            let status = match task.status {
                TaskStatus::Pending => "待处理".to_string(),
                TaskStatus::InProgress => "进行中".to_string(),
                TaskStatus::Completed => "已完成".to_string(),
                TaskStatus::Failed => "失败".to_string(),
            };

            table.add_row(vec![&task.name, &progress, &status]);
        }

        println!();
        println!("{}", table);
        println!();
    }

    /// 获取总体进度
    pub fn overall_progress(&self) -> f64 {
        if self.tasks.is_empty() {
            return 100.0;
        }

        let total_progress: f64 = self
            .tasks
            .iter()
            .map(|t| {
                if t.total > 0 {
                    (t.current as f64 / t.total as f64) * 100.0
                } else {
                    0.0
                }
            })
            .sum();

        total_progress / self.tasks.len() as f64
    }
}

/// 分层进度条
///
/// 显示总体进度条和当前任务详细信息
pub struct LayeredProgress {
    overall: ProgressBar,
    task_detail: ProgressBar,
    hidden: bool,
}

impl LayeredProgress {
    /// 创建新的分层进度条
    pub fn new() -> Self {
        let overall_style = ProgressStyle::default_bar()
            .template(
                "{spinner:.green} [{elapsed_precise}] {msg}\n  {wide_bar:.cyan/blue} {pos}/{len} ({percent}%)\n{spinner:.blue} 当前: {prefix}",
            )
            .expect("创建进度条样式失败")
            .progress_chars("=>-");

        let overall = ProgressBar::new(8);
        overall.set_style(overall_style);
        overall.enable_steady_tick(Duration::from_millis(120));
        overall.set_prefix("准备中...");

        let task_style = ProgressStyle::default_bar()
            .template("    详细: {msg}")
            .expect("创建进度条样式失败");

        let task_detail = ProgressBar::hidden();
        task_detail.set_style(task_style);

        Self {
            overall,
            task_detail,
            hidden: false,
        }
    }

    /// 创建隐藏的进度条（静默模式）
    pub fn hidden() -> Self {
        let overall = ProgressBar::hidden();
        let task_detail = ProgressBar::hidden();

        Self {
            overall,
            task_detail,
            hidden: true,
        }
    }

    /// 开始总体进度
    pub fn start_overall(&self, message: &str, total: u64) {
        if self.hidden {
            return;
        }
        self.overall.set_length(total);
        self.overall.set_message(message.to_string());
    }

    /// 开始新任务
    pub fn start_task(&self, task_name: &str) {
        if self.hidden {
            return;
        }
        self.overall.set_prefix(task_name.to_string());
        self.overall.set_message("正在收集系统信息...");
        self.task_detail.set_message("初始化中...");
    }

    /// 完成当前任务
    pub fn complete_task(&self, message: &str) {
        if self.hidden {
            return;
        }
        self.task_detail.set_message(format!("✓ {}", message));
        self.task_detail.tick();
        std::thread::sleep(Duration::from_millis(100));
        self.overall.inc(1);
    }

    /// 更新当前任务详情
    pub fn update_current(&self, message: &str) {
        if self.hidden {
            return;
        }
        self.overall.set_prefix(message.to_string());
    }

    /// 完成所有进度
    pub fn finish(&self) {
        if self.hidden {
            return;
        }
        self.task_detail.finish();
        self.overall.finish();
    }
}

impl Drop for LayeredProgress {
    fn drop(&mut self) {
        self.task_detail.finish();
        self.overall.finish();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_progress_creation() {
        let progress = ScanProgress::new(100, true);
        assert_eq!(progress.total(), 100);
        assert_eq!(progress.current(), 0);
        assert!(!progress.is_finished());
    }

    #[test]
    fn test_scan_progress_inc() {
        let progress = ScanProgress::new(100, true);
        progress.inc(10);
        assert_eq!(progress.current(), 10);
        assert!(!progress.is_finished());
    }

    #[test]
    fn test_scan_progress_finish() {
        let progress = ScanProgress::new(100, true);
        progress.set_position(100);
        assert!(progress.is_finished());
        assert_eq!(progress.percentage(), 100.0);
    }

    #[test]
    fn test_simple_progress() {
        let mut progress = SimpleProgress::new(100);
        assert_eq!(progress.total, 100);
        assert_eq!(progress.current, 0);

        progress.update(50);
        assert_eq!(progress.current, 50);

        progress.inc(25);
        assert_eq!(progress.current, 75);
    }

    #[test]
    fn test_multi_progress() {
        let mut multi = MultiProgress::new(2);
        multi.add_task("任务1".to_string(), 100);
        multi.add_task("任务2".to_string(), 200);

        assert_eq!(multi.tasks.len(), 2);

        multi.update_task(0, 50);
        assert_eq!(multi.tasks[0].current, 50);
        assert_eq!(multi.tasks[0].status, TaskStatus::InProgress);

        multi.complete_task(0);
        assert_eq!(multi.tasks[0].status, TaskStatus::Completed);
    }

    #[test]
    fn test_overall_progress() {
        let mut multi = MultiProgress::new(2);
        multi.add_task("任务1".to_string(), 100);
        multi.add_task("任务2".to_string(), 100);

        multi.update_task(0, 100);
        multi.update_task(1, 50);

        // 任务1完成(100%)，任务2完成50%，总体应该是75%
        let progress = multi.overall_progress();
        assert!((progress - 75.0).abs() < 0.01);
    }

    #[test]
    fn test_layered_progress_creation() {
        let progress = LayeredProgress::new();
        // 验证创建成功
        assert!(!progress.hidden);
    }

    #[test]
    fn test_layered_progress_hidden() {
        let progress = LayeredProgress::hidden();
        assert!(progress.hidden);
    }
}
