# IntraSweep

[![Rust](https://img.shields.io/badge/rust-1.85+-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey.svg)]()
[![Release](https://img.shields.io/badge/release-v0.4.0-green.svg)]()

**IntraSweep** 是一个基于 Rust 的内网渗透测试工具，聚焦内网侦察与打击的核心环节：网络扫描、系统信息收集、弱口令爆破、内网穿透隧道、凭据提取与 AD 域攻击。专为红队单兵作业设计，提供从初始侦察到报告生成的一站式能力。

> **免责声明**：本工具仅供授权渗透测试和安全研究使用。未经授权对他人系统进行测试属于违法行为。使用者需自行承担法律责任。

---

## 目录

- [功能概览](#功能概览)
- [安装与构建](#安装与构建)
- [快速开始](#快速开始)
- [命令参考](#命令参考)
  - [网络扫描 (scan)](#网络扫描-scan)
  - [系统信息收集 (system)](#系统信息收集-system)
  - [密码爆破 (crack)](#密码爆破-crack)
  - [内网穿透 (tunnel)](#内网穿透-tunnel)
  - [漏洞扫描 (vuln)](#漏洞扫描-vuln)
  - [AD 域枚举 (ad)](#ad-域枚举-ad)
  - [提权检测 (privesc)](#提权检测-privesc)
  - [报告生成 (report)](#报告生成-report)
- [配置文件](#配置文件)
- [项目结构](#项目结构)
- [技术栈](#技术栈)
- [版本](#版本)
- [License](#license)

---

## 功能概览

| 模块 | 状态 | 说明 |
|------|:----:|------|
| 端口扫描 / 主机发现 | ✅ | TCP Connect，自适应批处理与超时，FuturesUnordered 正确回收全部结果 |
| 服务探测 / Banner 抓取 | ✅ | SSH/FTP/SMTP/HTTP/Redis/MySQL/MSSQL/RDP 等多协议识别 |
| Web 指纹识别 | ✅ | 34 条规则，覆盖中间件/OA/管理面板/开发工具/基础设施 |
| SSH / Redis / WinRM 爆破 | ✅ | 并发引擎 + Semaphore 限流 + 命中即停 |
| PostgreSQL / MySQL / MSSQL 爆破 | ✅ | spawn_blocking 异步直连 |
| MongoDB 爆破 | ✅ | 强制 `ping` 验证，消除惰性连接误报 |
| RDP 爆破 | ⚠️ | CredSSP/NLA 协议实现有限，成功判定不够可靠 |
| 密码喷洒 (SSH) | ✅ | 少量密码 × 大量用户，轮间冷却防账户锁定 |
| SOCKS5 代理 | ✅ | RFC 1928/1929 合规，用户名密码认证，目标连接重试 |
| 正向 / 反向 / 链式隧道 | ✅ | TCP 双向转发，半关闭支持，优雅关闭 |
| 加密隧道 | ❌ | XChaCha20-Poly1305 加密层已实现但管道未接线，CLI 显式报错 |
| HTTP / DNS 隧道 | ❌ | 未接线，CLI 已移除入口 |
| NTLM 认证核心 | ✅ | NTLMv2 完整实现，自研 MD4（含标准测试向量），安全缓冲 u32 偏移 |
| GPP 密码解密 | ✅ | 正确微软公开 AES-256 密钥 + 全零 IV，SYSVOL 自动搜索 |
| DPAPI 解密 | ✅ | `CryptUnprotectData` FFI 实现（Windows），浏览器密码链路打通 |
| 浏览器密码提取 | ✅ | Chrome/Edge (v10/v11/v20) AES-256-GCM 解密 |
| WiFi / 应用凭据提取 | ✅ | netsh wlan、Git/SSH/FileZilla/OpenVPN/Navicat 等 |
| Kerberoasting | ⚠️ | TCP 长度前缀已修正，TGS-REQ 缺完整 AP-REQ padata |
| AS-REP Roasting | ⚠️ | TCP 长度前缀已修正，enc-part 解析已修正 |
| DCSync | ❌ | 未实现 DRSUAPI 协议，CLI 显式报错并推荐 mimikatz/impacket |
| Golden Ticket | ❌ | 未实现真实票据伪造，CLI 显式报错 |
| AD LDAP 枚举 | ✅ | 用户/组/计算机/SPN/信任/GPO，Paged Results 支持大域 |
| BloodHound 导出 | ✅ | 真实 objectSid，Users/Groups/Computers JSON |
| ADCS 证书枚举 | ⚠️ | CA/模板枚举，ESC1 + ESC3 启发式检测 |
| 漏洞扫描 (PoC 引擎) | ✅ | 33 条内置 PoC，YAML/JSON/脚本外部加载，多步骤变量传递 |
| Web 主动探测 | ❌ | 仅有 payload 生成器，无执行引擎，CLI 显式报错 |
| 系统信息收集 | ✅ | OS/网络/进程/凭据/文件/域环境 7 类一键收集 |
| EDR/AV 检测 | ✅ | 18 个厂商签名，进程/服务/注册表/文件路径多维检测 |
| 提权检测 (Windows) | ✅ | 服务/注册表/凭据/令牌/文件/补丁/DLL 劫持 7 类，PowerShell/CIM |
| 提权检测 (Linux) | ✅ | SUID/Capabilities/Cron/可写文件/Docker/Sudo/SSH/内核 8 类 |
| 报告生成 | ✅ | 聚合 AD/扫描/爆破/提权/漏洞结果，Markdown/HTML 输出 |
| YAML 配置文件 | ✅ | CLI 参数 > 配置文件 > 默认值，6 个子命令支持回填 |
| 插件系统 | ❌ | 无动态加载实现 |

> ✅ 可用 ｜ ⚠️ 有限实现 ｜ ❌ 未实现（CLI 显式报错）

---

## 安装与构建

### 从源码构建

```bash
# 安装 Rust 工具链 (1.85+)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 克隆仓库
git clone https://github.com/BlkSword/IntraSweep.git
cd IntraSweep

# Release 构建（推荐）
cargo build --release
```

可执行文件位于 `target/release/intrasweep`（Linux）或 `target/release/intrasweep.exe`（Windows）。

### 系统依赖

| 平台 | 依赖 |
|------|------|
| Linux | `pkg-config` `libssl-dev` `build-essential` `libsqlite3-dev` |
| Windows | MSVC Build Tools（`windows` crate 需要） |

### 构建配置

Release 构建使用最小体积优化：

```toml
[profile.release]
opt-level = "z"       # 最小体积
lto = true            # 链接时优化
strip = true          # 去除符号表
codegen-units = 1     # 单代码生成单元
panic = "abort"       # panic 时直接终止
```

---

## 快速开始

```bash
# 交互式向导（所有命令不带参数时自动进入）
intrasweep scan
intrasweep crack
intrasweep tunnel

# 直接扫描
intrasweep scan 192.168.1.0/24 port --fast
intrasweep scan 192.168.1.0/24 comprehensive --webfinger -o result.json

# 爆破
intrasweep crack 192.168.1.1 -s ssh -u root -P passwords.txt
intrasweep crack 192.168.1.1 -s ssh -U users.txt --spray   # 密码喷洒

# SOCKS5 代理
intrasweep tunnel socks5 -L 1080
intrasweep tunnel socks5 -L 1080 --socks5-username user --socks5-password pass

# 正向隧道
intrasweep tunnel forward -t 192.168.1.100:3389 -L 8080

# AD 域枚举
intrasweep ad --dc 10.0.0.1 -d corp.local -u admin -p password

# 漏洞扫描
intrasweep vuln 192.168.1.0/24 --severity critical

# 提权检测
intrasweep privesc

# 全量信息收集
intrasweep system all -o report.json
```

### 全局选项

```
-v, --verbose          详细输出 (DEBUG 级别日志)
-q, --quiet            安静模式 (仅错误)
    --log-file <PATH>  日志写入文件
    --config <PATH>    YAML 配置文件（预设参数）
```

---

## 命令参考

### 网络扫描 (scan)

```bash
intrasweep scan [TARGETS] [TYPE] [OPTIONS]
```

| 参数 | 说明 |
|------|------|
| `TARGETS` | 扫描目标（IP/CIDR/范围），可选，不填进入交互式 |
| `TYPE` | `port`（端口）/ `host`（主机）/ `comprehensive`（综合） |
| `-f, --fast` | 快速扫描预设（高并发、短超时） |
| `--webfinger` | 启用 Web 指纹识别（34 条规则） |
| `--format` | 输出格式：`json`（默认）/ `csv` |
| `-o` | 输出文件路径 |

**扫描预设**：Fast（高并发短超时）、Standard（平衡）、Deep（全端口）、Stealth（低并发有延迟）

**主机发现方法**：TCP Connect（默认，跨平台）、ARP（仅 Windows 本地网段）、混合模式

### 系统信息收集 (system)

```bash
intrasweep system [ITEM] [OPTIONS]
```

| 项目 | 缩写 | 说明 |
|------|------|------|
| `all` | `a` | 全量收集 |
| `system` | `sy` | OS、主机名、架构、CPU、内存 |
| `network` | `n` | 接口、路由、ARP、连接 |
| `process` | `p` | 进程列表、可疑进程、资源占用 |
| `credential` | `c` | 密码哈希、SSH 密钥、API Key |
| `file` | `f` | 敏感文件、配置文件、最近文件 |
| `domain` | `d` | 域加入状态、域控、域用户、SPN |

### 密码爆破 (crack)

```bash
intrasweep crack [TARGET] [OPTIONS]
```

| 参数 | 说明 |
|------|------|
| `-s, --service` | 服务类型（见下表） |
| `-p, --port` | 端口（默认使用服务默认端口） |
| `-u, --usernames` | 用户名（逗号分隔） |
| `-U, --username-file` | 用户名字典文件 |
| `-P, --password-file` | 密码字典文件 |
| `-c, --concurrency` | 并发数（默认 10） |
| `-t, --timeout` | 超时秒数（默认 5） |
| `--delay` | 延迟毫秒数（避免触发防护） |
| `--spray` | 密码喷洒模式（当前支持 SSH） |

| 服务 | 默认端口 | 认证方式 | 状态 |
|------|:--------:|----------|:----:|
| `ssh` | 22 | 密码/密钥 | ✅ |
| `redis` | 6379 | 密码 | ✅ |
| `winrm` | 5985 | Basic | ✅ |
| `postgres` | 5432 | 密码 | ✅ |
| `mysql` | 3306 | 密码 | ✅ |
| `mssql` | 1433 | SQL Server 认证 | ✅ |
| `mongodb` | 27017 | 密码（ping 验证） | ✅ |
| `rdp` | 3389 | CredSSP/NLA + NTLMv2 | ⚠️ |

### 内网穿透 (tunnel)

```bash
intrasweep tunnel [TYPE] [OPTIONS]
```

| 类型 | 说明 | 状态 |
|------|------|:----:|
| `forward` | 本地端口转发到远程目标 | ✅ |
| `reverse` | 从内网建立连接回控制端 | ✅ |
| `socks5` | RFC 1928 SOCKS5 代理（支持 RFC 1929 认证） | ✅ |
| `chain` | 多级跳板链式隧道 | ✅ |

| 参数 | 说明 |
|------|------|
| `-t, --target` | 目标地址 (host:port) |
| `-L, --local-port` | 本地监听端口 |
| `-H, --hop` | 跳板主机（可多次指定） |
| `--socks5-username` | SOCKS5 认证用户名 |
| `--socks5-password` | SOCKS5 认证密码 |
| `-c, --max-connections` | 最大并发连接（默认 100） |
| `-t, --timeout` | 超时秒数（默认 30） |

> `--encryption-key` 加密隧道尚未接线，使用时会显式报错退出。

### 漏洞扫描 (vuln)

```bash
intrasweep vuln [TARGETS] [OPTIONS]
```

| 参数 | 说明 |
|------|------|
| `--poc-file` | 外部 PoC 文件或目录（YAML/JSON/脚本） |
| `--severity` | 按严重性过滤：`critical` `high` `medium` `low` `info` |
| `--category` | 按类别过滤 |
| `--format` | 输出格式：`json`（默认）/ `csv` |
| `-c, --concurrency` | 并发数（默认 20） |
| `-t, --timeout` | 超时秒数（默认 10） |

**内置 PoC（33 条）**：

| 类别 | 数量 | 示例 |
|------|:----:|------|
| 反序列化 | 3 | Shiro-550, Fastjson, Log4Shell (CVE-2021-44228) |
| 未授权访问 | 15 | Nacos, Jenkins, Elasticsearch, Redis, MongoDB, Docker API 等 |
| OA 系统 | 4 | 泛微OA, 致远OA, 通达OA, 蓝凌OA |
| RCE | 2 | WebLogic CVE-2020-14882, ThinkPHP 5.x |
| 信息泄露 | 4 | .git 目录, .env 文件, Druid 监控, Spring Boot Actuator |
| 配置/检测 | 5 | SMB 签名, RDP 检测, WinRM 检测, Memcached, ZooKeeper |

**外部 PoC 格式**：支持 HTTP 声明式（YAML/JSON）、TCP 协议、多步骤变量传递、Python/PowerShell/Bash 脚本。

### AD 域枚举 (ad)

```bash
intrasweep ad --dc <IP> -d <DOMAIN> [OPTIONS]
```

| 参数 | 说明 |
|------|------|
| `--dc` | 域控 IP 地址 |
| `-d, --domain` | 域名（例 `corp.local`） |
| `-u, --username` | 认证用户名（留空匿名绑定） |
| `-p, --password` | 认证密码 |
| `--ssl` | 使用 LDAPS（端口 636） |
| `-m, --mode` | 执行模式（见下表） |
| `--bloodhound-dir` | BloodHound 输出目录 |

| 模式 | 说明 | 状态 |
|------|------|:----:|
| `all`（默认） | 完整枚举：用户/组/计算机/SPN/信任/GPO/Kerberoast/AS-REP | ✅ |
| `kerberoast` | 提取 SPN 账户 | ⚠️ |
| `asrep-roast` | 查找预认证禁用用户 | ⚠️ |
| `bloodhound` | 导出 BloodHound JSON（真实 objectSid） | ✅ |
| `adcs` | ADCS 证书服务枚举 | ⚠️ |
| `gpp` | GPP 密码搜索与解密 | ✅ |
| `dcsync` | DCSync 攻击 | ❌ 显式报错 |

> `--golden-ticket` / `--krbtgt-hash` 尚未实现，使用时显式报错。

**LDAP 特性**：Paged Results 分页查询（大域 >1000 条不截断）、objectSid 二进制解析、trustAttributes 位掩码、密码策略查询。

### 提权检测 (privesc)

```bash
intrasweep privesc [OPTIONS]
```

| 参数 | 说明 |
|------|------|
| `-c, --check` | 检查类别（留空运行全部） |
| `--format` | 输出格式：`json`（默认）/ `csv` |
| `-o` | 输出文件路径 |

**Windows 检查项**（PowerShell/CIM，兼容 Win11）：

| 类别 | 说明 |
|------|------|
| `service` | 未引用服务路径、弱服务权限、可写服务二进制 |
| `credentials` | cmdkey 存储凭据、自动登录密码、SAM 文件访问 |
| `registry` | AlwaysInstallElevated |
| `tokens` | SeDebugPrivilege、SeImpersonatePrivilege 等危险令牌 |
| `files` | unattend.xml、sysprep 配置、凭据目录 |
| `patches` | 缺失安全更新（MS17-010/SMBGhost/HiveNightmare 等） |
| `dll` | DLL 劫持（未引用路径 + 可写 PATH + 缺失 DLL） |

**Linux 检查项**：

| 类别 | 说明 |
|------|------|
| `suid` | 已知可利用 SUID 二进制 |
| `capabilities` | 危险 capabilities（cap_setuid、cap_sys_admin 等） |
| `cron` | 可写 cron 配置、用户 crontab |
| `writable` | /etc/passwd、/etc/shadow、/etc/sudoers 可写 |
| `docker` | Docker 组成员 |
| `sudo` | 危险 NOPASSWD 规则 |
| `ssh` | 私钥文件、其他用户密钥 |
| `kernel` | 已知内核漏洞匹配（Dirty Cow/Pipe/PwnKit/Baron Samedit） |

### 报告生成 (report)

```bash
intrasweep report [OPTIONS]
```

| 参数 | 说明 |
|------|------|
| `--format` | 报告格式：`full`（默认）/ `executive` / `html` |
| `--input` | 输入数据文件（JSON，支持 AD/扫描/爆破/提权/漏洞结果） |
| `--mitre` | 包含 MITRE ATT&CK 映射 |
| `-o` | 输出文件路径 |

报告引擎自动聚合以下数据源：AD 枚举（用户/信任/Kerberoast/AS-REP）、网络扫描（存活主机/开放端口/服务）、爆破结果（弱口令）、提权检测（发现列表）、漏洞扫描（漏洞发现）。

---

## 配置文件

支持 YAML 格式配置文件，CLI 显式参数优先级高于配置文件：

```yaml
# intrasweep.yaml
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
  timeout: 60
```

```bash
intrasweep --config intrasweep.yaml scan
```

---

## 项目结构

```
src/
├── main.rs              入口（命令路由、配置加载、未实现功能拦截）
├── lib.rs               库入口（供集成测试使用）
├── cli/                 CLI 层（8 个命令 + 交互式向导）
├── scanner/             扫描引擎（主机发现/端口扫描/服务探测/Web指纹/ARP）
├── cracker/             密码爆破（8 种服务 + 并发引擎 + NTLMv2 + 密码喷洒）
├── tunnel/              网络穿透（正向/反向/SOCKS5/链式 + 加密层 + relay）
├── vuln/                漏洞扫描（PoC 引擎/33 条内置规则/外部加载/匹配器）
├── ad/                  AD 域枚举（LDAP/BloodHound/分页查询/SID 解析）
├── cred/                凭据攻击（GPP/DPAPI/浏览器/WiFi/应用/Kerberoast/AS-REP）
├── recon/               信息侦察（EDR检测/用户猎杀/共享搜索/防火墙/ADCS）
├── privesc/             提权检测（Windows 7类 + Linux 8类）
├── collector/           信息收集编排（7 类系统信息）
├── modules/collect/     信息收集底层实现
├── core/                核心库（错误处理/配置/日志/字符串混淆/加密凭据库）
└── output/              输出层（彩色终端/JSON/CSV/进度条/报告生成）
```

---

## 技术栈

| 类别 | 技术 |
|------|------|
| 语言 | Rust 2021 Edition |
| 异步运行时 | tokio (full) |
| CLI | clap 4 (derive) |
| 序列化 | serde + serde_json + serde_yaml |
| 加密 | XChaCha20-Poly1305, AES-256-GCM, AES-256-CBC, NTLMv2 (HMAC-MD5), MD4 |
| LDAP | ldap3 (Paged Results) |
| 网络 | tokio TCP, reqwest HTTP, native-tls |
| 数据库 | rusqlite (浏览器), tiberius (MSSQL), tokio-postgres, mysql_async, redis, mongodb |
| 日志 | tracing + tracing-subscriber |
| 终端 | indicatif (进度条), termcolor (颜色), comfy-table |
| Windows API | winreg, windows crate, crypt32.dll FFI (DPAPI) |
| Linux | nix, /proc 文件系统 |
| CI | GitHub Actions (Windows/Linux/macOS + fmt + clippy) |

---

## 版本

**v0.4.0** — 基于代码审查的系统性修复与功能补全

- 修复 7 个 P0 致命 bug（主机发现丢结果、SOCKS5 缓冲区覆写、MongoDB 恒成功、嵌套 runtime panic、NTLM 布局错误、GPP 密钥错误、DCSync 伪造数据）
- AD LDAP 分页查询 + objectSid 解析 + trustAttributes 位掩码
- DPAPI `CryptUnprotectData` 实现，浏览器密码链路打通
- Kerberoast/AS-REP TCP 长度前缀修正
- 33 条 PoC 规则误报收紧，匹配器修正
- 提权检测 wmic → PowerShell/CIM，DLL 劫持检查实现
- 报告聚合 5 类数据源
- YAML 配置管道接通
- 字节级协议测试（NTLM/GPP/主机发现）
- CI 3 平台矩阵 + fmt + clippy 门禁

---

## License

Copyright 2024-2026 BlkSword

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
