//! 颜色管理模块
//!
//! 提供终端颜色输出功能

use std::fmt::{self, Display};

/// 终端颜色枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Color {
    /// 黑色
    Black,
    /// 红色
    Red,
    /// 绿色
    Green,
    /// 黄色
    Yellow,
    /// 蓝色
    Blue,
    /// 品红色
    Magenta,
    /// 青色
    Cyan,
    /// 白色
    White,
    /// 亮黑色（灰色）
    BrightBlack,
    /// 亮红色
    BrightRed,
    /// 亮绿色
    BrightGreen,
    /// 亮黄色
    BrightYellow,
    /// 亮蓝色
    BrightBlue,
    /// 亮品红色
    BrightMagenta,
    /// 亮青色
    BrightCyan,
    /// 亮白色
    BrightWhite,
}

impl Color {
    /// 获取 ANSI 颜色代码
    pub fn ansi_color_code(self) -> u8 {
        match self {
            Color::Black => 30,
            Color::Red => 31,
            Color::Green => 32,
            Color::Yellow => 33,
            Color::Blue => 34,
            Color::Magenta => 35,
            Color::Cyan => 36,
            Color::White => 37,
            Color::BrightBlack => 90,
            Color::BrightRed => 91,
            Color::BrightGreen => 92,
            Color::BrightYellow => 93,
            Color::BrightBlue => 94,
            Color::BrightMagenta => 95,
            Color::BrightCyan => 96,
            Color::BrightWhite => 97,
        }
    }

    /// 获取 ANSI 背景颜色代码
    pub fn ansi_bg_color_code(self) -> u8 {
        self.ansi_color_code() + 10
    }
}

/// 彩色文本结构
#[derive(Debug, Clone)]
pub struct ColoredText {
    text: String,
    color: Color,
    bold: bool,
}

impl ColoredText {
    /// 创建新的彩色文本
    pub fn new(text: impl Into<String>, color: Color) -> Self {
        Self {
            text: text.into(),
            color,
            bold: false,
        }
    }

    /// 设置粗体
    pub fn bold(mut self) -> Self {
        self.bold = true;
        self
    }

    /// 渲染为 ANSI 字符串
    pub fn to_ansi(&self) -> String {
        let color_code = self.color.ansi_color_code();
        let mut result = format!("\x1b[{}m", color_code);

        if self.bold {
            result.push_str("\x1b[1m");
        }

        result.push_str(&self.text);
        result.push_str("\x1b[0m");

        result
    }
}

impl Display for ColoredText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_ansi())
    }
}

/// 颜色样式
pub trait Colorize {
    /// 设置颜色
    fn color(self, color: Color) -> ColoredText;
    /// 红色
    fn red(self) -> ColoredText;
    /// 绿色
    fn green(self) -> ColoredText;
    /// 黄色
    fn yellow(self) -> ColoredText;
    /// 蓝色
    fn blue(self) -> ColoredText;
    /// 品红色
    fn magenta(self) -> ColoredText;
    /// 青色
    fn cyan(self) -> ColoredText;
    /// 白色
    fn white(self) -> ColoredText;
}

impl<T: Into<String>> Colorize for T {
    fn color(self, color: Color) -> ColoredText {
        ColoredText::new(self.into(), color)
    }

    fn red(self) -> ColoredText {
        self.color(Color::Red)
    }

    fn green(self) -> ColoredText {
        self.color(Color::Green)
    }

    fn yellow(self) -> ColoredText {
        self.color(Color::Yellow)
    }

    fn blue(self) -> ColoredText {
        self.color(Color::Blue)
    }

    fn magenta(self) -> ColoredText {
        self.color(Color::Magenta)
    }

    fn cyan(self) -> ColoredText {
        self.color(Color::Cyan)
    }

    fn white(self) -> ColoredText {
        self.color(Color::White)
    }
}

/// 状态颜色映射
pub struct StatusColors;

impl StatusColors {
    /// 开放端口颜色
    pub fn open() -> Color {
        Color::Green
    }

    /// 过滤端口颜色
    pub fn filtered() -> Color {
        Color::Yellow
    }

    /// 关闭端口颜色
    pub fn closed() -> Color {
        Color::Red
    }

    /// 错误颜色
    pub fn error() -> Color {
        Color::Red
    }

    /// 警告颜色
    pub fn warning() -> Color {
        Color::Yellow
    }

    /// 信息颜色
    pub fn info() -> Color {
        Color::Cyan
    }

    /// 成功颜色
    pub fn success() -> Color {
        Color::Green
    }

    /// IP 地址颜色
    pub fn ip_address() -> Color {
        Color::Cyan
    }

    /// 端口颜色
    pub fn port() -> Color {
        Color::Blue
    }

    /// 服务名称颜色
    pub fn service() -> Color {
        Color::White
    }

    /// 版本信息颜色
    pub fn version() -> Color {
        Color::BrightBlack
    }

    /// 根据状态字符串获取颜色
    pub fn from_status(status: &str) -> Color {
        match status.to_lowercase().as_str() {
            "open" => Self::open(),
            "filtered" => Self::filtered(),
            "closed" => Self::closed(),
            _ => Color::White,
        }
    }
}

/// 打印彩色消息
pub fn print_color(color: Color, text: &str) {
    println!("{}", ColoredText::new(text, color));
}

/// 打印彩色消息并换行
pub fn println_color(color: Color, text: &str) {
    println!("{}", ColoredText::new(text, color));
}

/// 打印成功消息
pub fn print_success(text: &str) {
    println_color(StatusColors::success(), text);
}

/// 打印错误消息
pub fn print_error(text: &str) {
    eprintln!("{} {}", ColoredText::new("错误:", Color::Red).bold(), text);
}

/// 打印警告消息
pub fn print_warning(text: &str) {
    println!(
        "{} {}",
        ColoredText::new("警告:", Color::Yellow).bold(),
        text
    );
}

/// 打印横幅
pub fn print_banner() {
    println!();
    println!("╔════════════════════════════════════════════════════════════════════════════╗");
    println!("║  {}", ColoredText::new("Fly-Wheel 内网渗透辅助工具", Color::Cyan).bold());
    println!("║  {}", ColoredText::new("版本: 0.2.0  作者: BlkSword", Color::BrightBlack).bold());
    println!("╚════════════════════════════════════════════════════════════════════════════╝");
}

/// 打印信息消息
pub fn print_info(text: &str) {
    println!(
        "{} {}",
        ColoredText::new("信息:", Color::Cyan).bold(),
        text
    );
}

/// 打印主机信息（彩色）
pub fn print_host_info(ip: &str, ports: &[u16]) {
    println!(
        "{}: {} 开放端口: {}",
        ColoredText::new("主机", Color::Cyan).bold(),
        ColoredText::new(ip, Color::Green).bold(),
        ColoredText::new(
            ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", "),
            Color::Yellow
        ),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_color_codes() {
        assert_eq!(Color::Red.ansi_color_code(), 31);
        assert_eq!(Color::Green.ansi_color_code(), 32);
        assert_eq!(Color::Blue.ansi_color_code(), 34);
        assert_eq!(Color::BrightRed.ansi_color_code(), 91);
    }

    #[test]
    fn test_colored_text() {
        let text = ColoredText::new("test", Color::Red);
        assert_eq!(text.text, "test");
        assert_eq!(text.color, Color::Red);
        assert!(!text.bold);
    }

    #[test]
    fn test_colored_text_bold() {
        let text = ColoredText::new("test", Color::Red).bold();
        assert!(text.bold);
    }

    #[test]
    fn test_colored_text_to_ansi() {
        let text = ColoredText::new("test", Color::Red);
        let ansi = text.to_ansi();
        assert!(ansi.contains("\x1b[31m"));
        assert!(ansi.contains("test"));
        assert!(ansi.contains("\x1b[0m"));
    }

    #[test]
    fn test_colorize_trait() {
        let text = "Hello".red();
        assert_eq!(text.text, "Hello");
        assert_eq!(text.color, Color::Red);
    }

    #[test]
    fn test_status_colors() {
        assert_eq!(StatusColors::from_status("open"), Color::Green);
        assert_eq!(StatusColors::from_status("filtered"), Color::Yellow);
        assert_eq!(StatusColors::from_status("closed"), Color::Red);
    }

    #[test]
    fn test_bold_colored_text_to_ansi() {
        let text = ColoredText::new("test", Color::Red).bold();
        let ansi = text.to_ansi();
        assert!(ansi.contains("\x1b[31m"));
        assert!(ansi.contains("\x1b[1m"));
    }
}
