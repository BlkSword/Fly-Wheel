# FlyWheel - 内网渗透测试工具

FlyWheel是一个基于Rust开发的功能完整的内网渗透测试工具，具有以下核心功能：

## 当前功能

实现了高速端口扫描(单核服务器上3s全端口)

## 安装

确保你已经安装了Rust开发环境，然后克隆此仓库并构建项目：

```Shell
cargo build --release
```


## 使用方法

```Shell
# 网络发现
./fly-wheel discover -t 192.168.1.0/24

# 端口扫描
./fly-wheel scan -t 192.168.1.1

# 漏洞扫描
./fly-wheel vuln -t 192.168.1.1

# 横向移动
./fly-wheel move -t 192.168.1.1

# 信息收集
./fly-wheel info -t 192.168.1.1

# 建立持久化
./fly-wheel persist -t 192.168.1.1
```




