//! 配置管理模块
//!
//! 提供交互式配置向导和配置文件管理功能

use crate::core::error::{FlyWheelError, Result};
use crate::core::FlyWheelError::Config;
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Select};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// 扫描配置结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    /// 通用配置
    pub general: GeneralConfig,
    /// 性能配置
    pub performance: PerformanceConfig,
    /// 隐蔽性配置
    pub stealth: StealthConfig,
    /// 输出配置
    pub output: OutputConfig,
}

/// 通用配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    /// 默认超时时间（毫秒）
    pub default_timeout_ms: u64,
    /// 最大重试次数
    pub max_retries: u32,
    /// 目标验证
    pub target_validation: bool,
}

/// 性能配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// 批处理大小
    pub batch_size: usize,
    /// 最大并发数
    pub max_concurrent: usize,
    /// 自适应批处理
    pub adaptive_batching: bool,
}

/// 隐蔽性配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StealthConfig {
    /// 随机化扫描顺序
    pub randomize_order: bool,
    /// 扫描间延迟（毫秒）
    pub delay_between_scans_ms: u64,
    /// Decoy 主机列表
    pub decoy_hosts: Vec<String>,
}

/// 输出配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    /// 使用彩色输出
    pub use_colors: bool,
    /// 显示进度条
    pub show_progress: bool,
    /// 自动保存结果
    pub save_results: bool,
    /// 结果保存目录
    pub results_dir: Option<String>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            general: GeneralConfig {
                default_timeout_ms: 1000,
                max_retries: 2,
                target_validation: true,
            },
            performance: PerformanceConfig {
                batch_size: 3000,
                max_concurrent: 6000,
                adaptive_batching: true,
            },
            stealth: StealthConfig {
                randomize_order: false,
                delay_between_scans_ms: 0,
                decoy_hosts: vec![],
            },
            output: OutputConfig {
                use_colors: true,
                show_progress: true,
                save_results: false,
                results_dir: None,
            },
        }
    }
}

impl ScanConfig {
    /// 快速模式配置
    pub fn fast() -> Self {
        let mut config = Self::default();
        config.performance.batch_size = 5000;
        config.performance.max_concurrent = 10000;
        config.performance.adaptive_batching = true;
        config
    }

    /// 平衡模式配置
    pub fn balanced() -> Self {
        Self::default()
    }

    /// 隐蔽模式配置
    pub fn stealth() -> Self {
        let mut config = Self::default();
        config.performance.batch_size = 500;
        config.performance.max_concurrent = 1000;
        config.performance.adaptive_batching = false;
        config.stealth.randomize_order = true;
        config.stealth.delay_between_scans_ms = 100;
        config
    }

    /// 获取配置文件路径
    pub fn config_path() -> Result<PathBuf> {
        let config_dir = dirs::home_dir()
            .ok_or_else(|| Config {
                reason: "无法获取用户主目录".to_string(),
            })?
            .join(".fly-wheel");

        // 确保配置目录存在
        if !config_dir.exists() {
            fs::create_dir_all(&config_dir).map_err(|e| Config {
                reason: format!("创建配置目录失败: {}", e),
            })?;
        }

        Ok(config_dir.join("config.toml"))
    }

    /// 加载配置文件
    pub fn load() -> Result<Self> {
        let path = Self::config_path()?;

        if !path.exists() {
            return Ok(Self::default());
        }

        let content = fs::read_to_string(&path).map_err(|e| Config {
            reason: format!("读取配置文件失败: {}", e),
        })?;

        toml::from_str(&content).map_err(|e| Config {
            reason: format!("解析配置文件失败: {}", e),
        })
    }

    /// 保存配置文件
    pub fn save(&self) -> Result<()> {
        let path = Self::config_path()?;

        let content = toml::to_string_pretty(self).map_err(|e| Config {
            reason: format!("序列化配置失败: {}", e),
        })?;

        fs::write(&path, content).map_err(|e| Config {
            reason: format!("写入配置文件失败: {}", e),
        })?;

        Ok(())
    }
}

/// 交互式配置向导
pub struct ConfigWizard;

impl ConfigWizard {
    /// 运行配置向导
    pub fn run() -> Result<ScanConfig> {
        println!("\n=== Fly-Wheel 配置向导 ===\n");

        let theme = ColorfulTheme::default();

        // 选择性能模式
        let performance_mode = Select::with_theme(&theme)
            .with_prompt("选择性能模式")
            .items(&["快速 (适合本地网络)", "平衡 (推荐)", "隐蔽 (较慢但更难检测)"])
            .default(1)
            .interact()
            .map_err(|e| Config {
                reason: format!("用户取消选择: {}", e),
            })?;

        let config = match performance_mode {
            0 => ScanConfig::fast(),
            1 => ScanConfig::balanced(),
            2 => ScanConfig::stealth(),
            _ => ScanConfig::default(),
        };

        // 是否使用彩色输出
        let use_colors = Confirm::with_theme(&theme)
            .with_prompt("使用彩色输出?")
            .default(true)
            .interact()
            .map_err(|e| Config {
                reason: format!("用户取消选择: {}", e),
            })?;

        // 是否自动保存结果
        let save_results = Confirm::with_theme(&theme)
            .with_prompt("自动保存扫描结果?")
            .default(false)
            .interact()
            .map_err(|e| Config {
                reason: format!("用户取消选择: {}", e),
            })?;

        // 自定义超时时间
        let custom_timeout = Confirm::with_theme(&theme)
            .with_prompt("自定义超时时间?")
            .default(false)
            .interact()
            .map_err(|e| Config {
                reason: format!("用户取消选择: {}", e),
            })?;

        let mut final_config = config;
        final_config.output.use_colors = use_colors;
        final_config.output.save_results = save_results;

        if custom_timeout {
            let timeout: String = Input::with_theme(&theme)
                .with_prompt("输入默认超时时间（毫秒）")
                .default("1000".to_string())
                .interact()
                .map_err(|e| Config {
                    reason: format!("用户取消输入: {}", e),
                })?;

            final_config.general.default_timeout_ms =
                timeout.parse().unwrap_or(1000);
        }

        // 保存配置
        let save_config = Confirm::with_theme(&theme)
            .with_prompt("保存配置以供后续使用?")
            .default(true)
            .interact()
            .map_err(|e| Config {
                reason: format!("用户取消选择: {}", e),
            })?;

        if save_config {
            final_config.save()?;
            println!("\n配置已保存到: {:?}", ScanConfig::config_path()?);
        }

        Ok(final_config)
    }

    /// 显示当前配置
    pub fn show_config(config: &ScanConfig) {
        println!("\n=== 当前配置 ===");
        println!("\n[通用配置]");
        println!("  超时时间: {} ms", config.general.default_timeout_ms);
        println!("  最大重试: {}", config.general.max_retries);

        println!("\n[性能配置]");
        println!("  批处理大小: {}", config.performance.batch_size);
        println!("  最大并发: {}", config.performance.max_concurrent);
        println!(
            "  自适应批处理: {}",
            config.performance.adaptive_batching
        );

        println!("\n[隐蔽性配置]");
        println!(
            "  随机化顺序: {}",
            config.stealth.randomize_order
        );
        println!(
            "  扫描延迟: {} ms",
            config.stealth.delay_between_scans_ms
        );

        println!("\n[输出配置]");
        println!("  彩色输出: {}", config.output.use_colors);
        println!("  显示进度: {}", config.output.show_progress);
        println!("  自动保存: {}", config.output.save_results);
        println!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ScanConfig::default();
        assert_eq!(config.general.default_timeout_ms, 1000);
        assert_eq!(config.performance.batch_size, 3000);
    }

    #[test]
    fn test_fast_config() {
        let config = ScanConfig::fast();
        assert_eq!(config.performance.batch_size, 5000);
        assert!(config.performance.adaptive_batching);
    }

    #[test]
    fn test_stealth_config() {
        let config = ScanConfig::stealth();
        assert_eq!(config.performance.batch_size, 500);
        assert!(config.stealth.randomize_order);
        assert!(config.stealth.delay_between_scans_ms > 0);
    }

    #[test]
    fn test_config_serialization() {
        let config = ScanConfig::default();
        let serialized = toml::to_string(&config).unwrap();
        let deserialized: ScanConfig = toml::from_str(&serialized).unwrap();
        assert_eq!(
            deserialized.general.default_timeout_ms,
            config.general.default_timeout_ms
        );
    }
}
