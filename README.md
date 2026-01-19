# IntraSweep - 内网渗透辅助工具

IntraSweep 是一个基于 Rust 开发的高性能内网渗透辅助工具，提供扫描、信息收集、密码爆破和内网穿透功能。

## 特性

- **高性能扫描** - 异步 I/O 高并发架构
- **交互式向导** - 无需记忆复杂参数
- **实时进度** - 可视化进度反馈
- **密码爆破** - 支持多种服务
- **内网穿透** - 正向/反向隧道、SOCKS5 代理、链式跳板

## 安装

```bash
# 安装 Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 克隆并构建
git clone https://github.com/BlkSword/IntraSweep.git
cd IntraSweep
cargo build --release
```

可执行文件位于 `target/release/intrasweep.exe`

## 快速开始

### 扫描功能

```bash
# 交互式向导（推荐）
intrasweep scan

# 快速命令
intrasweep scan 192.168.1.1              # 交互式配置
intrasweep scan 192.168.1.0/24 port      # 端口扫描
intrasweep scan 192.168.1.0/24 host      # 主机发现
intrasweep scan 192.168.1.0/24 comprehensive  # 综合扫描
```

### 系统信息收集

```bash
intrasweep system all        # 全量收集
intrasweep system network    # 网络信息
intrasweep system domain     # 域环境信息
intrasweep system credential  # 凭据信息
```

### 密码爆破

```bash
intrasweep crack              # 交互式向导
intrasweep crack 192.168.1.1 --service ssh -u root -P passwords.txt
```

### 内网穿透

```bash
# 交互式向导（推荐）
intrasweep tunnel

# 正向隧道 - 本地端口转发到远程目标
intrasweep tunnel forward -t 192.168.1.100:3389 -L 8080

# 反向隧道 - 从内网建立连接回外网
intrasweep tunnel reverse -t 10.0.0.1:8888 -L 8080

# SOCKS5 代理 - 动态端口转发
intrasweep tunnel socks5 -L 1080

# 链式隧道 - 多级跳板连接
intrasweep tunnel chain -H 10.0.0.1:2222 -H 10.0.0.2:3333 -t 192.168.2.100:80
```

## 命令参考

### System 命令

| 命令 | 缩写 | 功能 |
|-----|------|-----|
| all | a | 全量收集 |
| system | sy | 系统信息 |
| network | n | 网络信息 |
| process | p | 进程信息 |
| credential | c | 凭据信息 |
| file | f | 文件信息 |
| domain | d | 域信息 |

### Scan 命令

| 类型 | 功能 |
|-----|------|
| port | 端口扫描 |
| host | 主机发现 |
| comprehensive | 综合扫描 |

### Crack 命令

支持服务：`ssh`, `rdp`, `redis`, `postgres`, `mysql`, `mssql`, `mongodb`, `winrm`

| 参数 | 说明 |
|-----|------|
| `-s, --service` | 服务类型 |
| `-p, --port` | 端口 |
| `-u, --usernames` | 用户名（逗号分隔） |
| `-U, --username-file` | 用户名字典文件 |
| `-P, --password-file` | 密码字典文件 |
| `-c, --concurrency` | 并发数（默认: 10） |
| `-t, --timeout` | 超时秒数（默认: 5） |

### Tunnel 命令

| 类型 | 缩写 | 功能 |
|-----|------|------|
| forward | fo | 正向 TCP 端口转发 |
| reverse | re | 反向 TCP 端口转发 |
| socks5 | so | SOCKS5 代理服务器 |
| chain | ch | 链式隧道（多级跳板）|

| 参数 | 说明 |
|-----|------|
| `-t, --target` | 目标地址 (host:port) |
| `-L, --local-port` | 本地监听端口 |
| `-R, --remote-port` | 远程监听端口 |
| `-H, --hop` | 跳板主机 (可多次指定) |
| `--socks5-username` | SOCKS5 认证用户名 |
| `--socks5-password` | SOCKS5 认证密码 |
| `-c, --max-connections` | 最大并发连接（默认: 100）|
| `--timeout` | 超时时间（秒，默认: 30）|

## 扫描预设

| 预设 | 说明 |
|-----|------|
| `--fast` | 快速扫描 |
| `--type <type>` | 扫描类型 |
| `-o <file>` | 输出文件 |

## 版本

v0.3.0

## License

MIT
