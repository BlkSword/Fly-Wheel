# FlyWheel - 内网渗透辅助工具

FlyWheel是一个基于Rust开发的内网渗透辅助工具(暂时为当前功能)

## 当前功能

### 高速端口扫描

单核服务器上3s全端口

### 存活主机快速检测

两种方式：TCP,ICMP

254个IP————TCP 2s，ICMP 15s

## 安装

确保你已经安装了Rust开发环境，然后克隆此仓库并构建项目：

```Shell
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Clone the repository and build
git clone https://github.com/BlkSword/Fly-Wheel.git
cargo build
```


## 使用方法

```Shell
# 主机发现
./fly-wheel host -t 192.168.1.0/24

# 端口扫描
./fly-wheel scan -t 192.168.1.1

```



