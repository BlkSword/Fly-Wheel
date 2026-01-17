# IntraSweep - 内网渗透辅助工具

IntraSweep 是一个基于 Rust 开发的内网渗透辅助工具。

## 当前功能

### 高速端口扫描

单核服务器上 3 秒全端口扫描

### 存活主机快速检测

两种方式：TCP、ICMP

254 个 IP — TCP 2s，ICMP 15s

### 系统信息收集

支持细分的系统信息收集模块

## 安装

确保你已经安装了 Rust 开发环境，然后克隆此仓库并构建项目：

```Shell
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Clone the repository and build
git clone https://github.com/BlkSword/Fly-Wheel.git
cd Fly-Wheel
cargo build --release
```

## 使用方法

### 系统信息收集

```Shell
# 全量收集所有信息
intrasweep system all

# 收集网络信息
intrasweep system network

# 收集进程信息
intrasweep system process

# 使用缩写形式
intrasweep s n    # system network
intrasweep s p    # system process
```

### 扫描功能

```Shell
# 主机存活扫描（默认 TCP SYN）
intrasweep scan host 192.168.1.0/24

# 使用 ICMP 扫描
intrasweep scan host 192.168.1.0/24 --host-method icmp

# 端口扫描（默认 TCP Connect）
intrasweep scan port 192.168.1.1 --preset fast

# 使用 TCP SYN 端口扫描（需要管理员权限）
intrasweep scan port 192.168.1.1 --port-method tcp-syn

# 综合扫描（主机发现 + 端口扫描）
intrasweep scan comprehensive 192.168.1.0/24 --host-method hybrid --port-method tcp-connect

# 使用缩写形式
intrasweep sc h 192.168.1.0/24
```

### 可用命令

**system 子命令：**
| 命令 | 缩写 | 功能 |
|-----|------|-----|
| all | a | 全量收集 |
| system | sy | 基础系统信息 |
| network | n | 网络信息 |
| process | p | 进程信息 |
| credential | c | 凭据信息 |
| file | f | 文件信息 |
| domain | d | 域信息 |

**scan 子命令：**
| 命令 | 缩写 | 功能 |
|-----|------|-----|
| host | h | 主机存活扫描 |
| port | po | 端口扫描 |
| domain | d | 域环境扫描 |
| comprehensive | c | 综合扫描 |

### 扫描预设

- `fast`: 快速扫描 - 高并发，短超时
- `standard`: 标准扫描 - 平衡速度和准确性（默认）
- `deep`: 深度扫描 - 扫描所有端口，低并发
- `stealth`: 隐蔽扫描 - 低并发，长延迟，避免检测

### 扫描方式

**主机扫描方式 (`--host-method`):**
| 方式 | 说明 | 适用场景 |
|-----|------|---------|
| tcp-syn | TCP SYN 扫描（默认） | 兼容性最好，适用于所有网络 |
| icmp | ICMP Ping 扫描 | 需要 ICMP 权限，速度较慢但准确 |
| arp | ARP 扫描 | 仅适用于本地网络，速度快 |
| hybrid | 混合模式 | TCP SYN + ICMP，提高发现率 |

**端口扫描方式 (`--port-method`):**
| 方式 | 说明 | 适用场景 |
|-----|------|---------|
| tcp-connect | TCP Connect 扫描（默认） | 兼容性最好，无需特殊权限 |
| tcp-syn | TCP SYN 扫描 | 需要管理员权限，隐蔽性更好 |
| udp | UDP 扫描 | 扫描 UDP 端口，速度较慢 |
| sctp | SCTP 扫描 | 扫描 SCTP 端口 |
