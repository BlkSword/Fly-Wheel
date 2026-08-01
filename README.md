# IntraSweep

[![Rust](https://img.shields.io/badge/rust-1.85+-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey.svg)]()
[![Release](https://img.shields.io/badge/release-v0.4.0-green.svg)]()

**一个二进制，打完全链路。**

IntraSweep 是一个 Rust 编写的内网渗透工具箱。不是 Nmap，不是 Hydra，不是 mimikatz——是把它们的**常用功能**装进一个 7MB 静态二进制里，无依赖、跨平台、丢上去就能跑。

```
传统工具链：                          IntraSweep：
nmap + hydra + chisel + rubeus       intrasweep
+ impacket + mimikatz + bloodhound   一个文件，7MB
+ winpeas + nuclei + lazagne         无 Python / .NET / JRE
+ Python 运行时 + .NET 运行时         无 EDR 敏感进程名
= 20 个文件，5 种语言，3 个运行时      = 1 个文件，0 个依赖
```

> **免责声明**：本工具仅供授权渗透测试和安全研究使用。未经授权对他人系统进行测试属于违法行为。

---

## 目录

- [为什么需要 IntraSweep](#为什么需要-intrasweep)
- [功能与状态](#功能与状态)
- [安装与构建](#安装与构建)
- [快速开始](#快速开始)
- [命令参考](#命令参考)
- [配置文件](#配置文件)
- [项目结构](#项目结构)
- [技术栈](#技术栈)
- [路线图](#路线图)
- [License](#license)

---

## 为什么需要 IntraSweep

一次内网渗透，你通常要：

```
扫描 → 发现服务 → 爆破/利用 → 拿凭据 → 横向移动 → 提权 → 提取 → 隧道 → 报告
```

每一步一个工具，每个工具一种语言，每种语言一个运行时。你往目标机上丢 20 个文件，EDR 看到 `python3`、`powershell -enc`、`mimikatz.exe` 直接告警。

**IntraSweep 的思路**：不追求在任何单项上超越专用工具，而是用**一个二进制**覆盖每一步的**常用功能**，达到"够用"的档次。

| 对比维度 | 传统工具链 | IntraSweep |
|----------|-----------|------------|
| 文件数 | 15-20 个 | **1 个** |
| 总体积 | 200MB+（含运行时） | **~7MB** |
| 运行时依赖 | Python / .NET / JRE | **无** |
| 跨平台 | 多数仅 Windows 或仅 Linux | **Windows + Linux** |
| EDR 特征 | 解释器进程 + 已知工具签名 | **单一未知二进制** |
| 上手成本 | 每个工具单独学 | **统一 CLI + 交互式向导** |
| 单项深度 | 各工具是其领域最佳 | 覆盖常用功能，不追求极致 |

---

## 功能与状态

> ✅ 可用 ｜ ⚠️ 有限（核心流程可走通，边界场景不足）｜ ❌ 未实现（CLI 显式报错）

### 侦察与扫描

| 功能 | 状态 | 对标工具 | 说明 |
|------|:----:|----------|------|
| 端口扫描 | ✅ | Nmap `-sT` | TCP Connect，自适应超时，4 种预设 |
| 主机发现 | ✅ | Nmap `-sn` | TCP 多端口并行探测 + ARP（Windows） |
| 服务识别 | ✅ | Nmap `-sV` | SSH/FTP/HTTP/Redis/MySQL/MSSQL/RDP 等 Banner 抓取 |
| Web 指纹 | ✅ | WhatWeb / EHole | 34 条规则，覆盖主流中间件/OA/面板 |
| 域信息扫描 | ✅ | nltest / setspn | 域控发现、域用户枚举、SPN 查询 |

### 爆破与凭据

| 功能 | 状态 | 对标工具 | 说明 |
|------|:----:|----------|------|
| SSH 爆破 | ✅ | Hydra `-t ssh` | 并发引擎 + 命中即停 |
| Redis 爆破 | ✅ | Hydra `-t redis` | 同上 |
| WinRM 爆破 | ✅ | NetExec `--winrm` | Basic 认证 |
| PostgreSQL 爆破 | ✅ | Hydra `-t postgres` | 异步直连 |
| MySQL 爆破 | ✅ | Hydra `-t mysql` | 异步直连 |
| MSSQL 爆破 | ✅ | Hydra `-t mssql` | tiberius 异步 |
| MongoDB 爆破 | ✅ | — | 强制 ping 验证 |
| RDP 爆破 | ⚠️ | Hydra `-t rdp` | CredSSP 实现有限 |
| 密码喷洒 | ✅ | NetExec `--spray` | SSH，轮间冷却防锁定 |
| GPP 解密 | ✅ | gpp-decrypt | 正确微软密钥 + SYSVOL 搜索（`cred`） |
| DPAPI 解密 | ✅ | mimikatz `dpapi` | CryptUnprotectData FFI（`cred`） |
| 浏览器密码 | ✅ | LaZagne / SharpChrome | Chrome/Edge v10/v11/v20（`cred`） |
| WiFi 密码 | ✅ | LaZagne | netsh wlan / NetworkManager（`cred`） |
| 应用凭据 | ✅ | LaZagne | Git/SSH/FileZilla/OpenVPN/Navicat（`cred`） |
| SAM/LSASS 导出 | ⚠️ | mimikatz | 导出动作可用，解析为启发式（`cred`） |

### AD 域攻击

| 功能 | 状态 | 对标工具 | 说明 |
|------|:----:|----------|------|
| LDAP 枚举 | ✅ | ldapsearch / ADRecon | 用户/组/计算机/SPN/信任/GPO，Paged Results |
| Kerberoasting | ⚠️ | Rubeus / GetUserSPNs | TCP 前缀已修正，缺完整 AP-REQ |
| AS-REP Roast | ⚠️ | Rubeus / GetNPUsers | TCP 前缀已修正 |
| BloodHound 导出 | ✅ | SharpHound | 真实 objectSid |
| ADCS 枚举 | ⚠️ | Certify / Certipy | ESC1 + ESC3 |
| DCSync | ❌ | mimikatz / secretsdump | 未实现，显式报错 |
| Golden Ticket | ❌ | mimikatz / Rubeus | 未实现，显式报错 |

### 隧道与代理

| 功能 | 状态 | 对标工具 | 说明 |
|------|:----:|----------|------|
| SOCKS5 代理 | ✅ | ssh -D / Neo-reGeorg | RFC 1928/1929，认证，重试 |
| 正向隧道 | ✅ | ssh -L / Chisel | TCP 转发，半关闭 |
| 反向隧道 | ✅ | ssh -R / Chisel | 自动重连 |
| 链式隧道 | ✅ | 多级 ssh -L | 多跳板 |
| 加密传输 | ❌ | Chisel / Ligolo | 加密层已实现，管道未接线 |

### 漏洞与提权

| 功能 | 状态 | 对标工具 | 说明 |
|------|:----:|----------|------|
| PoC 漏洞扫描 | ✅ | Nuclei（轻量版） | 33 条内置 + YAML/JSON/脚本外部加载 |
| Windows 提权检测 | ✅ | WinPEAS / PowerUp | 7 类检查，PowerShell/CIM |
| Linux 提权检测 | ✅ | LinPEAS / LinEnum | 8 类检查 |
| EDR/AV 检测 | ✅ | SharpEDRChecker | 18 厂商签名 |

### 信息收集与报告

| 功能 | 状态 | 对标工具 | 说明 |
|------|:----:|----------|------|
| 系统信息收集 | ✅ | Seatbelt / sysinfo | 7 类一键收集 |
| 本地凭据提取 | ✅ | LaZagne | 浏览器/WiFi/应用/SAM/LSASS/GPP 一键（`cred`） |
| 信息侦察 | ✅ | Seatbelt / WinPEAS | EDR检测/情境感知/共享搜索/防火墙/VLAN（`recon`） |
| 渗透报告 | ✅ | Pwndoc（轻量版） | 聚合 5 类数据源，Markdown/HTML |
| YAML 配置 | ✅ | — | CLI > 配置文件 > 默认值 |

---

## 安装与构建

### 从源码构建

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
git clone https://github.com/BlkSword/IntraSweep.git
cd IntraSweep
cargo build --release
```

### 系统依赖

| 平台 | 依赖 |
|------|------|
| Linux | `pkg-config` `libssl-dev` `build-essential` `libsqlite3-dev` |
| Windows | MSVC Build Tools |

### Release 配置

```toml
[profile.release]
opt-level = "z"       # 最小体积
lto = true            # 链接时优化
strip = true          # 去除符号表
codegen-units = 1
panic = "abort"
```

---

## 快速开始

```bash
# 所有命令不带参数时进入交互式向导
intrasweep scan
intrasweep crack
intrasweep tunnel

# 扫描
intrasweep scan 192.168.1.0/24 port --fast
intrasweep scan 192.168.1.0/24 comprehensive --webfinger -o result.json

# 爆破
intrasweep crack 192.168.1.1 -s ssh -u root -P passwords.txt
intrasweep crack 192.168.1.1 -s ssh -U users.txt --spray

# 隧道
intrasweep tunnel socks5 -L 1080
intrasweep tunnel forward -t 192.168.1.100:3389 -L 8080

# 本地凭据提取（浏览器/WiFi/应用/SAM/LSASS/GPP）
intrasweep cred -o creds.json

# 信息侦察（EDR检测/情境感知/共享/防火墙/VLAN）
intrasweep recon --mode full -o recon.json
intrasweep recon --mode edr

# AD 域枚举
intrasweep ad --dc 10.0.0.1 -d corp.local -u admin -p password

# 漏洞扫描
intrasweep vuln 192.168.1.0/24 --severity critical

# 提权检测
intrasweep privesc

# 信息收集
intrasweep system all -o report.json

# 报告（聚合所有结果）
intrasweep report --input ad_result.json --format full -o report.md
```

### 全局选项

```
-v, --verbose          DEBUG 日志
-q, --quiet            仅错误
    --log-file <PATH>  日志文件
    --config <PATH>    YAML 配置文件
```

---

## 命令参考

### scan — 网络扫描

```bash
intrasweep scan [TARGETS] [port|host|comprehensive] [--fast] [--webfinger] [--format json|csv] [-o FILE]
```

预设：Fast / Standard / Deep / Stealth。主机发现：TCP Connect（默认）/ ARP（Windows）/ 混合。

### system — 信息收集

```bash
intrasweep system [all|system|network|process|credential|file|domain] [-o FILE] [-q]
```

### crack — 密码爆破

```bash
intrasweep crack [TARGET] -s <SERVICE> [-u USERS] [-U USER_FILE] [-P PASS_FILE]
                 [-c CONCURRENCY] [-t TIMEOUT] [--delay MS] [--spray]
```

| 服务 | 端口 | 状态 | | 服务 | 端口 | 状态 |
|------|:----:|:----:|-|------|:----:|:----:|
| ssh | 22 | ✅ | | postgres | 5432 | ✅ |
| redis | 6379 | ✅ | | mysql | 3306 | ✅ |
| winrm | 5985 | ✅ | | mssql | 1433 | ✅ |
| mongodb | 27017 | ✅ | | rdp | 3389 | ⚠️ |

### tunnel — 内网穿透

```bash
intrasweep tunnel [forward|reverse|socks5|chain] [-t TARGET] [-L PORT] [-H HOP]
                  [--socks5-username USER] [--socks5-password PASS]
```

### vuln — 漏洞扫描

```bash
intrasweep vuln [TARGETS] [--poc-file PATH] [--severity LEVEL] [--category CAT]
                [--format json|csv] [-c CONCURRENCY] [-t TIMEOUT]
```

33 条内置 PoC（反序列化/未授权/OA/RCE/信息泄露/配置检测），支持 YAML/JSON/脚本外部加载。

### ad — AD 域枚举

```bash
intrasweep ad --dc <IP> -d <DOMAIN> [-u USER] [-p PASS] [--ssl]
              [-m all|kerberoast|asrep-roast|bloodhound|adcs|gpp] [--bloodhound-dir DIR]
```

LDAP Paged Results（大域不截断）、objectSid 解析、trustAttributes 位掩码、密码策略查询。

### privesc — 提权检测

```bash
intrasweep privesc [-c CATEGORY] [--format json|csv] [-o FILE]
```

Windows 7 类（PowerShell/CIM，兼容 Win11）+ Linux 8 类。

### cred — 本地凭据提取

```bash
intrasweep cred [--dc IP] [--domain DOMAIN] [-u USER] [-p PASS]
                [--format json|csv] [-o FILE]
```

浏览器（Chrome/Edge/Firefox）、WiFi、应用（Git/SSH/FileZilla/OpenVPN/Navicat）、SAM/LSASS、GPP 一键提取。无参数进入交互式向导；非 Windows 平台自动跳过需 SYSTEM 权限的提取项。

### recon — 信息侦察

```bash
intrasweep recon [--dc IP] [--domain DOMAIN] [--mode full|edr|situational|host|shares|firewall|vlan]
                 [--format json|csv] [-o FILE]
```

EDR/AV 检测、环境态势感知、文件共享搜索、防火墙规则、VLAN/拓扑发现；`--domain` 时附加域管会话猎杀。

### report — 报告生成

```bash
intrasweep report [--format full|executive|html] [--input DATA.json] [--mitre] [-o FILE]
```

自动聚合 AD/扫描/爆破/提权/漏洞 5 类数据源。

---

## 配置文件

```yaml
# intrasweep.yaml — CLI 参数 > 配置文件 > 默认值
defaults:
  concurrency: 50
  timeout: 10
  format: json

scan:
  targets: [192.168.1.0/24]
  type: comprehensive
  webfinger: true

crack:
  username_file: ./dict/users.txt
  password_file: ./dict/passwords.txt

tunnel:
  max_connections: 200
```

---

## 项目结构

```
src/
├── main.rs              入口（命令路由、配置回填、未实现功能拦截）
├── lib.rs               库入口
├── cli/                 10 个命令 + 交互式向导
├── scanner/             主机发现 / 端口扫描 / 服务探测 / Web 指纹 / ARP
├── cracker/             8 种服务爆破 + 并发引擎 + NTLMv2 + 密码喷洒
├── tunnel/              正向 / 反向 / SOCKS5 / 链式 + relay + 加密层
├── vuln/                PoC 引擎 / 33 条规则 / 外部加载 / 匹配器
├── ad/                  LDAP 枚举 / BloodHound / SID 解析 / 分页查询
├── cred/                浏览器 / WiFi / 应用 / SAM / LSASS / GPP 凭据提取
├── recon/               EDR 检测 / 用户猎杀 / 共享搜索 / 防火墙 / ADCS / VLAN
├── privesc/             Windows 7 类 + Linux 8 类
├── collector/           7 类系统信息收集
├── core/                错误处理 / 配置 / 日志 / 混淆 / 凭据库
└── output/              彩色终端 / JSON / CSV / 进度条 / 报告
```

---

## 技术栈

| 类别 | 技术 |
|------|------|
| 语言 | Rust 2021，静态链接，无运行时依赖 |
| 异步 | tokio |
| CLI | clap 4 |
| 加密 | XChaCha20-Poly1305 / AES-256-GCM / AES-256-CBC / NTLMv2 / MD4 |
| LDAP | ldap3（Paged Results） |
| 数据库 | rusqlite / tiberius / tokio-postgres / mysql_async / redis / mongodb |
| Windows | winreg / windows crate / crypt32 FFI |
| Linux | nix / /proc |
| CI | GitHub Actions（Windows + Linux + macOS，fmt + clippy 门禁） |

---

## 路线图

详见 [docs/ROADMAP.md](docs/ROADMAP.md)。

**v0.5.0 目标**：用成熟的 Rust 协议库替换手写实现，达到各工具常用功能的"够用"档次。

**v1.0 目标**：自动化攻击链编排——扫描 → 爆破 → 横向 → 提权 → 提取 → 报告，一条命令走完。

---

## License

Copyright 2024-2026 BlkSword. Apache License 2.0.
