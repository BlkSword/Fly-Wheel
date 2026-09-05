# IntraSweep 路线图

> 目标：一个 7MB 静态二进制，覆盖内网渗透常用功能的 80%，达到各专用工具"够用"的档次。
> 原则：**不造轮子，装轮子。** 协议实现用成熟 crate，精力放在编排和 OPSEC 上。

---

## 当前状态 (v0.4.0)

- 65 个源文件，~38,500 行 Rust
- 470 个测试，cargo check 0 error
- 7 个 P0 致命 bug 已修复
- 核心链路（扫描/爆破/隧道/信息收集/提权/报告）可用
- 协议实现（NTLM/Kerberos/RDP）为手写，存在完整性缺陷

---

## v0.5.0 — 协议正确性（用成熟库替换手写实现）

**目标**：所有协议交互达到"对真实目标可用"的档次，不再因协议错误导致功能失效。

### 替换清单

| 当前实现 | 问题 | 替换为 | 对标档次 |
|----------|------|--------|----------|
| 手写 NTLM Type1/2/3 | offset/flags 曾出错 | `ntlmclient` 或 `pava::ntlm` | Hydra NTLM 爆破 |
| 手写 Kerberos ASN.1 | 缺 AP-REQ，tag 曾写错 | `kerberos-asn1` + `kerberos-crypto` | impacket GetUserSPNs |
| 手写 RDP CredSSP | 协议阶段错误 | 砍掉或降级为端口探测，标注 ⚠️ | — |
| DCSync 编造数据 | 完全不可用 | `pava`（含 DRSUAPI）或保持 ❌ 报错 | impacket secretsdump |
| 手写 SMB（无） | 不存在 | `pava::smb` | smbclient 基础操作 |

### 具体任务

- [ ] 引入 `pava` crate（SMB + DRSUAPI + SAMR，impacket 的 Rust 移植）
- [ ] 引入 `kerberos-asn1` + `kerberos-crypto`，重写 Kerberoast/AS-REP
- [ ] 用 `pava::ntlm` 替换 `cracker/ntlm.rs` 手写实现
- [ ] RDP 爆破降级为"RDP 端口开放 + NLA 检测"，移除不可靠的成功判定
- [ ] 如 `pava` DRSUAPI 可用，实现真实 DCSync；否则保持显式报错
- [ ] 为每个替换后的协议补字节级集成测试（对真实服务或 mock）
- [ ] Kerberoast 输出验证：hashcat -m 13100 可破解
- [ ] AS-REP 输出验证：hashcat -m 18200 可破解

### 验收标准

```
在真实 AD 环境（Windows Server 2019+ 域控）中：
✅ Kerberoast 拿到 TGS，hashcat 可破解
✅ AS-REP Roast 拿到加密 TGT
✅ BloodHound JSON 可导入 BloodHound CE
✅ GPP 解密出真实密码
✅ LDAP 枚举 >1000 条不截断
✅ DCSync 拿到 NTLM 哈希（或显式报错推荐 mimikatz）
```

---

## v0.6.0 — 功能补齐（达到各工具常用功能档次）

**目标**：每个模块覆盖对标工具最常用的 3-5 个功能，不追求全覆盖。

### 扫描模块

| 功能 | 对标 | 优先级 |
|------|------|:------:|
| UDP 端口扫描（Top 100） | Nmap `-sU --top-ports 100` | P1 |
| 扫描结果去重与合并 | Nmap `-oA` | P2 |
| 域名目标 DNS 解析 | Nmap 自动解析 | P1（已部分实现） |

### 爆破模块

| 功能 | 对标 | 优先级 |
|------|------|:------:|
| RDP 爆破（正确实现或移除） | Hydra `-t rdp` | P1 |
| SMB 爆破 | NetExec `smb` | P1 |
| FTP / Telnet / VNC 爆破 | Hydra 常用协议 | P2 |
| 爆破结果自动写入凭据库 | NetExec `--loot` | P1 |
| 密码喷洒扩展到 SMB/WinRM | NetExec `--spray` | P1 |
  - **已部分完成**：SSH/WinRM 已支持，SMB 未实现 |

### 隧道模块

| 功能 | 对标 | 优先级 |
|------|------|:------:|
| 加密隧道接线 | Chisel `--key` | P0 |
| HTTP 隧道（CONNECT 代理穿透） | Neo-reGeorg | P1 |
  - **已完成 CLI 接线**：`intrasweep tunnel http -H proxy -t target` |
| 隧道流量统计与状态面板 | Chisel UI | P2 |

### 凭据模块

| 功能 | 对标 | 优先级 |
|------|------|:------:|
| Firefox 密码提取（key4.db + logins.json） | LaZagne | P1 |
| Windows 凭据管理器完整提取 | LaZagne / mimikatz | P1 |
| LSASS dump 解析（minidump → 明文凭据） | mimikatz / pypykatz | P2 |
| NTDS.dit 离线解析 | impacket secretsdump | P2 |

### AD 模块

| 功能 | 对标 | 优先级 |
|------|------|:------:|
| ADCS ESC1-ESC8 完整检测 | Certify / Certipy | P1 |
| BloodHound ACL 收集 | SharpHound | P2 |
| 域信任跨域枚举 | BloodHound | P2 |
| SPN 服务类型完整映射 | Rubeus | P1 |

### 提权模块

| 功能 | 对标 | 优先级 |
|------|------|:------:|
| Windows 服务 DLL 劫持完整检测 | PowerUp | P1（已部分实现） |
| Linux 内核 CVE 数据库更新机制 | LinPEAS | P2 |
| 容器逃逸检测（Docker/K8s） | CDK / Deepce | P2 |

### 漏洞扫描

| 功能 | 对标 | 优先级 |
|------|------|:------:|
| PoC 规则扩充到 100+ | Nuclei 常用模板 | P1 |
| Web 主动探测引擎接线 | Nuclei / sqlmap | P2 |
  - **已部分完成**：`vuln --web-probe` 已接入基础 GET/POST 探测 |
| 子域名/目录枚举 | dirsearch / subfinder | P2 |

---

## v0.7.0 — 编排层（自动化攻击链）

**目标**：一条命令走完"扫描 → 爆破 → 横向 → 提权 → 提取 → 报告"。

### 核心设计

```rust
// 自动攻击链编排
intrasweep auto 192.168.1.0/24 --cred user:pass --depth 3

// 执行流程：
// 1. 扫描网段，发现存活主机和开放服务
// 2. 对每个服务自动选择攻击策略：
//    - SMB 无签名 → 尝试空会话枚举 → 爆破
//    - Kerberos → Kerberoast → 离线破解
//    - WinRM/SSH → 用已有凭据尝试登录
//    - MSSQL/MySQL → 爆破 → 尝试 xp_cmdshell
// 3. 拿到新凭据后自动横向（BFS，depth 控制跳数）
// 4. 每台拿下的机器自动跑提权检测 + 凭据提取
// 5. 自动生成攻击路径图 + 渗透报告
```

### 具体任务

- [ ] 攻击链状态机（Scan → Exploit → Loot → Pivot → Escalate → Report）
- [ ] 凭据库：所有模块共享，爆破/提取的凭据自动入库，后续模块自动取用
- [ ] 横向移动策略引擎（根据服务类型 + 已有凭据自动选择）
- [ ] 攻击路径可视化（ASCII 图 + JSON 导出）
- [ ] 一键报告：自动聚合所有发现，生成完整渗透报告

---

## v1.0 — 生产就绪

### 质量门禁

- [ ] 所有协议交互有字节级集成测试
- [ ] 在真实 AD 环境（Server 2019/2022）全流程验证
- [ ] 在 Kali / Ubuntu 22.04 / Win10 / Win11 编译通过
- [ ] clippy 0 warning，fmt 100% 合规
- [ ] 无生产路径 unwrap/expect
- [ ] 凭据内存 zeroize
- [ ] 敏感操作审计日志

### OPSEC 加固

- [ ] 字符串编译期混淆（proc-macro 替代运行时 XOR）
- [ ] 可选 UPX 压缩 / 图标伪装
- [ ] 进程名/窗口标题伪装
- [ ] 网络流量特征随机化（UA/JA3）
- [ ] 操作完成后自清理（删除日志/临时文件）

### 文档

- [ ] 每个模块的使用文档 + 原理说明
- [ ] 攻击链操作手册（从 0 到域管的完整流程）
- [ ] 与 NetExec/Impacket 的功能对照表
- [ ] 贡献指南

---

## 不做的事

| 不做 | 理由 |
|------|------|
| C2 框架 | Sliver/CobaltStrike 是另一个维度的产品 |
| Web 漏洞扫描器 | Nuclei 9000+ 模板，追不上 |
| 全端口 SYN 扫描 | Masscan 的 kernel-level 性能，Rust 用户态做不到 |
| 密码离线破解 | hashcat 的 GPU 加速，不是一个量级 |
| GUI | 保持 CLI 单二进制优势 |
| 插件动态加载 | 增加攻击面，违背 OPSEC 原则 |

---

## 时间线估算

| 版本 | 核心工作 | 前置条件 |
|------|---------|---------|
| v0.5.0 | 协议库替换 + 真实 AD 验证 | 需要 AD 测试环境 |
| v0.6.0 | 功能补齐到"够用" | v0.5.0 协议正确 |
| v0.7.0 | 编排层 + 自动攻击链 | v0.6.0 各模块可用 |
| v1.0 | 质量门禁 + OPSEC + 文档 | v0.7.0 编排可用 |

**关键依赖**：v0.5.0 的协议替换需要真实 AD 环境验证。没有域控测试环境，协议正确性无法保证。
