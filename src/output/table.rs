//! 表格输出模块
//!
//! 提供美化的表格输出功能

use comfy_table::{presets::UTF8_FULL, Attribute, Cell, Color, Table};
use std::fmt;

/// 端口扫描结果行
#[derive(Debug, Clone)]
pub struct PortRow {
    pub port: u16,
    pub status: String,
    pub service: String,
    pub version: Option<String>,
    pub banner: Option<String>,
}

impl fmt::Display for PortRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.port)
    }
}

/// 结果表格
pub struct ResultTable {
    table: Table,
    use_colors: bool,
    row_count: usize,
}

impl ResultTable {
    /// 创建新的结果表格
    pub fn new(use_colors: bool) -> Self {
        let mut table = Table::new();
        table.load_preset(UTF8_FULL);
        table.set_header(vec!["端口", "状态", "服务", "版本", "Banner"]);

        Self {
            table,
            use_colors,
            row_count: 0,
        }
    }

    /// 使用默认配置创建
    pub fn default() -> Self {
        Self::new(true)
    }

    /// 添加端口扫描结果行
    pub fn add_port_row(&mut self, row: PortRow) {
        let status_color = match row.status.as_str() {
            "open" => Color::Green,
            "filtered" => Color::Yellow,
            "closed" => Color::Red,
            _ => Color::White,
        };

        let mut cell = Cell::new(&row.status).add_attribute(Attribute::Bold);
        if self.use_colors {
            cell = cell.fg(status_color);
        }

        let port_cell = if self.use_colors {
            Cell::new(row.port).fg(Color::Cyan)
        } else {
            Cell::new(row.port)
        };

        self.table.add_row(vec![
            port_cell,
            cell,
            Cell::new(&row.service),
            Cell::new(row.version.as_deref().unwrap_or("-")),
            Cell::new(row.banner.as_deref().unwrap_or("-")),
        ]);

        self.row_count += 1;
    }

    /// 添加一行主机信息
    pub fn add_host_row(&mut self, ip: &str, hostname: Option<&str>, os: Option<&str>) {
        let ip_cell = if self.use_colors {
            Cell::new(ip).fg(Color::Cyan).add_attribute(Attribute::Bold)
        } else {
            Cell::new(ip).add_attribute(Attribute::Bold)
        };

        self.table.add_row(vec![
            ip_cell,
            Cell::new(hostname.unwrap_or("-")),
            Cell::new(os.unwrap_or("-")),
            Cell::new(""),
            Cell::new(""),
        ]);

        self.row_count += 1;
    }

    /// 添加自定义行
    pub fn add_row(&mut self, cells: Vec<String>) {
        let table_cells: Vec<Cell> = cells.iter().map(|s| Cell::new(s.as_str())).collect();
        self.table.add_row(table_cells);
        self.row_count += 1;
    }

    /// 打印表格
    pub fn print(&self) {
        if self.row_count > 0 {
            println!();
            println!("{}", self.table);
            println!();
        }
    }

    /// 获取行数
    pub fn len(&self) -> usize {
        self.row_count
    }

    /// 检查是否为空
    pub fn is_empty(&self) -> bool {
        self.row_count == 0
    }

    /// 打印汇总信息
    pub fn print_summary(&self, title: &str) {
        if self.is_empty() {
            println!("\n{}: 无结果\n", title);
        } else {
            println!("\n{}: 发现 {} 项结果\n", title, self.row_count);
        }
    }
}

/// 简单的主机结果表格
pub struct HostResultTable {
    table: Table,
    use_colors: bool,
    row_count: usize,
}

impl HostResultTable {
    /// 创建新的主机结果表格
    pub fn new(use_colors: bool) -> Self {
        let mut table = Table::new();
        table.load_preset(UTF8_FULL);
        table.set_header(vec!["IP 地址", "主机名", "操作系统", "开放端口数"]);

        Self {
            table,
            use_colors,
            row_count: 0,
        }
    }

    /// 添加主机行
    pub fn add_host(
        &mut self,
        ip: &str,
        hostname: Option<&str>,
        os: Option<&str>,
        port_count: usize,
    ) {
        let ip_cell = if self.use_colors {
            Cell::new(ip)
                .fg(Color::Green)
                .add_attribute(Attribute::Bold)
        } else {
            Cell::new(ip).add_attribute(Attribute::Bold)
        };

        self.table.add_row(vec![
            ip_cell,
            Cell::new(hostname.unwrap_or("未知")),
            Cell::new(os.unwrap_or("未知")),
            Cell::new(port_count.to_string()),
        ]);

        self.row_count += 1;
    }

    /// 打印表格
    pub fn print(&self) {
        if self.row_count > 0 {
            println!();
            println!("{}", self.table);
            println!();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_result_table_creation() {
        let table = ResultTable::new(true);
        assert_eq!(table.len(), 0);
        assert!(table.is_empty());
    }

    #[test]
    fn test_add_port_row() {
        let mut table = ResultTable::new(false);
        table.add_port_row(PortRow {
            port: 80,
            status: "open".to_string(),
            service: "http".to_string(),
            version: Some("nginx/1.18".to_string()),
            banner: Some("Server: nginx".to_string()),
        });

        assert_eq!(table.len(), 1);
        assert!(!table.is_empty());
    }

    #[test]
    fn test_add_host_row() {
        let mut table = ResultTable::new(false);
        table.add_host_row("192.168.1.1", Some("target.local"), Some("Linux"));

        assert_eq!(table.len(), 1);
    }

    #[test]
    fn test_host_result_table() {
        let mut table = HostResultTable::new(false);
        table.add_host("192.168.1.1", Some("target.local"), Some("Linux"), 5);

        assert_eq!(table.row_count, 1);
    }

    #[test]
    fn test_port_row_display() {
        let row = PortRow {
            port: 80,
            status: "open".to_string(),
            service: "http".to_string(),
            version: None,
            banner: None,
        };
        assert_eq!(format!("{}", row), "80");
    }
}
