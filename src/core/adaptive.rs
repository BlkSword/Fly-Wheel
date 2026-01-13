//! 自适应批处理模块
//!
//! 根据扫描结果动态调整批处理大小以优化性能

use std::time::{Duration, Instant};

/// 自适应批处理器
///
/// 根据扫描的成功率和响应时间动态调整批处理大小
#[derive(Debug, Clone)]
pub struct AdaptiveBatcher {
    /// 当前批处理大小
    current_batch: usize,
    /// 最小批处理大小
    min_batch: usize,
    /// 最大批处理大小
    max_batch: usize,
    /// 当前批次开放端口数
    open_ports_in_batch: usize,
    /// 当前批次总扫描数
    total_in_batch: usize,
    /// 批次开始时间
    batch_start: Option<Instant>,
    /// 历史成功率（用于平滑调整）
    success_rate_history: Vec<f64>,
    /// 历史记录最大长度
    history_size: usize,
}

impl AdaptiveBatcher {
    /// 创建新的自适应批处理器
    pub fn new(initial_batch: usize, min_batch: usize, max_batch: usize) -> Self {
        Self {
            current_batch: initial_batch.clamp(min_batch, max_batch),
            min_batch,
            max_batch,
            open_ports_in_batch: 0,
            total_in_batch: 0,
            batch_start: None,
            success_rate_history: Vec::new(),
            history_size: 5,
        }
    }

    /// 使用默认配置创建
    pub fn with_defaults() -> Self {
        Self::new(3000, 500, 10000)
    }

    /// 获取当前批处理大小
    pub fn current_batch(&self) -> usize {
        self.current_batch
    }

    /// 开始新批次
    pub fn start_batch(&mut self) {
        self.open_ports_in_batch = 0;
        self.total_in_batch = 0;
        self.batch_start = Some(Instant::now());
    }

    /// 记录一次扫描结果
    pub fn record_result(&mut self, is_open: bool) {
        self.total_in_batch += 1;
        if is_open {
            self.open_ports_in_batch += 1;
        }
    }

    /// 检查批次是否完成
    pub fn is_batch_complete(&self) -> bool {
        self.total_in_batch >= self.current_batch
    }

    /// 调整批处理大小
    ///
    /// 基于以下因素：
    /// - 开放端口比率（比率低时增大批处理）
    /// - 扫描速度（速度快时可以增大批处理）
    /// - 历史趋势（平滑调整避免剧烈波动）
    pub fn adjust_batch(&mut self) {
        if self.total_in_batch == 0 {
            return;
        }

        // 计算当前批次成功率
        let current_rate = self.open_ports_in_batch as f64 / self.total_in_batch as f64;

        // 计算批次耗时
        let batch_duration = self
            .batch_start
            .map(|start| start.elapsed())
            .unwrap_or(Duration::ZERO);

        // 保存到历史记录
        self.success_rate_history.push(current_rate);
        if self.success_rate_history.len() > self.history_size {
            self.success_rate_history.remove(0);
        }

        // 计算平均成功率
        let avg_rate = if self.success_rate_history.is_empty() {
            current_rate
        } else {
            self.success_rate_history.iter().sum::<f64>() / self.success_rate_history.len() as f64
        };

        // 根据成功率和速度调整批处理大小
        let mut new_batch = self.current_batch;

        // 成功率极低（< 1%）时大幅增加批处理
        if avg_rate < 0.01 {
            new_batch = (self.current_batch as f64 * 1.5) as usize;
        }
        // 成功率较低（< 5%）时适度增加
        else if avg_rate < 0.05 {
            new_batch = (self.current_batch as f64 * 1.2) as usize;
        }
        // 成功率较高（> 20%）时减少批处理
        else if avg_rate > 0.2 {
            new_batch = (self.current_batch as f64 * 0.7) as usize;
        }
        // 成功率很高（> 50%）时大幅减少
        else if avg_rate > 0.5 {
            new_batch = (self.current_batch as f64 * 0.5) as usize;
        }

        // 根据速度微调
        if batch_duration < Duration::from_secs(1) {
            // 速度很快，可以增加
            new_batch = (new_batch as f64 * 1.1) as usize;
        } else if batch_duration > Duration::from_secs(10) {
            // 速度较慢，适当减少
            new_batch = (new_batch as f64 * 0.9) as usize;
        }

        // 限制在范围内
        self.current_batch = new_batch.clamp(self.min_batch, self.max_batch);

        // 重置批次统计
        self.start_batch();
    }

    /// 强制设置批处理大小
    pub fn set_batch(&mut self, batch: usize) {
        self.current_batch = batch.clamp(self.min_batch, self.max_batch);
    }

    /// 获取统计信息
    pub fn stats(&self) -> AdaptiveStats {
        let avg_rate = if self.success_rate_history.is_empty() {
            0.0
        } else {
            self.success_rate_history.iter().sum::<f64>()
                / self.success_rate_history.len() as f64
        };

        AdaptiveStats {
            current_batch: self.current_batch,
            avg_success_rate: avg_rate,
            open_ports_in_batch: self.open_ports_in_batch,
            total_in_batch: self.total_in_batch,
        }
    }
}

/// 自适应批处理统计信息
#[derive(Debug, Clone)]
pub struct AdaptiveStats {
    pub current_batch: usize,
    pub avg_success_rate: f64,
    pub open_ports_in_batch: usize,
    pub total_in_batch: usize,
}

/// 根据系统限制获取最优批处理大小
pub fn get_optimal_batch_size() -> usize {
    const DEFAULT_BATCH_SIZE: usize = 3000;

    cfg_if::cfg_if! {
        if #[cfg(unix)] {
            // Unix 系统：检查文件描述符限制
            if let Some(limit) = get_fd_limit() {
                // 保留一些文件描述符给系统使用
                let safe_limit = (limit as usize).saturating_sub(100);
                DEFAULT_BATCH_SIZE.min(safe_limit)
            } else {
                DEFAULT_BATCH_SIZE
            }
        } else {
            // 其他系统使用默认值
            DEFAULT_BATCH_SIZE
        }
    }
}

/// 获取文件描述符限制（仅 Unix）
#[cfg(unix)]
fn get_fd_limit() -> Option<u64> {
    unsafe {
        let mut rl = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };

        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) == 0 {
            Some(rl.rlim_cur)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adaptive_batcher_creation() {
        let batcher = AdaptiveBatcher::with_defaults();
        assert_eq!(batcher.current_batch(), 3000);
    }

    #[test]
    fn test_start_batch() {
        let mut batcher = AdaptiveBatcher::with_defaults();
        batcher.start_batch();
        assert_eq!(batcher.open_ports_in_batch, 0);
        assert_eq!(batcher.total_in_batch, 0);
    }

    #[test]
    fn test_record_result() {
        let mut batcher = AdaptiveBatcher::with_defaults();
        batcher.start_batch();

        batcher.record_result(true);
        batcher.record_result(false);
        batcher.record_result(true);

        assert_eq!(batcher.open_ports_in_batch, 2);
        assert_eq!(batcher.total_in_batch, 3);
    }

    #[test]
    fn test_is_batch_complete() {
        let mut batcher = AdaptiveBatcher::new(10, 5, 100);
        batcher.start_batch();

        for _ in 0..9 {
            batcher.record_result(false);
        }
        assert!(!batcher.is_batch_complete());

        batcher.record_result(false);
        assert!(batcher.is_batch_complete());
    }

    #[test]
    fn test_adjust_batch_increase() {
        let mut batcher = AdaptiveBatcher::new(1000, 100, 10000);
        batcher.start_batch();

        // 模拟低成功率（应该增大批处理）
        for _ in 0..1000 {
            batcher.record_result(false);
        }

        let old_batch = batcher.current_batch();
        batcher.adjust_batch();
        assert!(batcher.current_batch() >= old_batch);
    }

    #[test]
    fn test_adjust_batch_decrease() {
        let mut batcher = AdaptiveBatcher::new(1000, 100, 10000);
        batcher.start_batch();

        // 模拟高成功率（应该减小批处理）
        for _ in 0..500 {
            batcher.record_result(true);
        }
        for _ in 0..500 {
            batcher.record_result(false);
        }

        let old_batch = batcher.current_batch();
        batcher.adjust_batch();
        assert!(batcher.current_batch() <= old_batch);
    }

    #[test]
    fn test_set_batch() {
        let mut batcher = AdaptiveBatcher::new(3000, 500, 10000);
        batcher.set_batch(5000);
        assert_eq!(batcher.current_batch(), 5000);

        // 测试下限
        batcher.set_batch(100);
        assert_eq!(batcher.current_batch(), 500);

        // 测试上限
        batcher.set_batch(20000);
        assert_eq!(batcher.current_batch(), 10000);
    }

    #[test]
    fn test_stats() {
        let mut batcher = AdaptiveBatcher::with_defaults();
        batcher.start_batch();

        batcher.record_result(true);
        batcher.record_result(false);
        batcher.record_result(true);

        let stats = batcher.stats();
        assert_eq!(stats.open_ports_in_batch, 2);
        assert_eq!(stats.total_in_batch, 3);
    }
}
