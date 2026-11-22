# Mirage

**Mirage** 是一个基于 Rust 的 **OpenSSH 前置反向代理与预认证 CVE 防护盾**。

Mirage 部署在真实 OpenSSH `sshd` 前端（例如 Mirage 监听 `0.0.0.0:22`，真实 `sshd` 监听 `127.0.0.1:22022`）：正常管理员连接完全透明直通真实 `sshd`（原生密钥、密码、PAM、SFTP 体验完全一致，零露馅风险）；所有针对 OpenSSH 预认证阶段的畸形包、CVE 利用载荷、慢速连接攻击和自动化扫描器都会在**接触真实 `sshd` 之前**被拦截。

---

## 快速开始

### 一键安装并自动配置 OpenSSH

```bash
curl -fsSLO https://raw.githubusercontent.com/ProjectRalyn/Mirage/main/mirage.sh
chmod +x mirage.sh
sudo ./mirage.sh deploy
```

`mirage.sh deploy` 会交互式完成以下全部操作：
1. 下载安装 `mirage-daemon` 并生成 `/etc/mirage/config.toml`。
2. 按需配置**爆破突发**、**预认证 CVE / sigil 异常**、**扫描器 Banner** 的独立处置策略（`fail2ban` / `ssh_honeypot` / `endlessh_tarpit` / `drop`）。
3. 按需自动将本机 OpenSSH `sshd` 迁移至 `127.0.0.1:22022`（自动处理 `ssh.socket` 与 SELinux，重启后实时校验 Banner，**异常自动回滚防失联**），由 Mirage 接管 `22` 端口并启动 `mirage.service`。

> 建议保留当前 SSH 会话，另开新终端确认登录正常后再关闭。  
> 常用维护命令：`sudo ./mirage.sh status`、`sudo ./mirage.sh logs`、`sudo ./mirage.sh sshd-restore`、`sudo ./mirage.sh uninstall`。

### 从源码编译（可选）

```bash
cargo build --release --workspace
sudo install -m 0755 target/release/mirage-daemon /usr/local/bin/mirage-daemon
sudo ./mirage.sh deploy
```

---

## 核心防护机制

1. **RFC 4253 Banner 校验与预认证超时门禁**
   - 在连接后端 `sshd` 之前，严格校验客户端 Banner（`SSH-2.0-` / `SSH-1.99-` 前缀、长度上限 `255` 字节、仅允许可打印 ASCII）。
   - 对 Banner + 密钥交换完成（`SSH_MSG_NEWKEYS`）全程施加 `preauth_timeout_secs` 超时限制，缓解 `LoginGraceTime` 慢速预认证竞争/耗尽攻击（如 CVE-2024-6387 regreSSHion）。

2. **Pre-`NEWKEYS` 二进制包校验 + `sigil-filter` 字段启发式检查**
   - 逐包解析未加密的 pre-`NEWKEYS` 阶段 SSH 二进制帧（`packet_length` 上限、`padding_length`、8 字节对齐、合法 pre-KEX 状态机 opcode），阻断 pre-KEX `SSH_MSG_USERAUTH_SUCCESS`（CVE-2018-10933）、`SSH2_MSG_PING`（CVE-2025-26466）及 Strict-KEX 违规包（Terrapin CVE-2023-48795）。
   - 对 `SSH_MSG_KEXINIT` 的 10 个算法列表字段及 `SSH_MSG_DEBUG` 字符串逐一进行长度/字符集校验和 [`sigil-filter`](https://crates.io/crates/sigil-filter) 检测，捕获不当构造的缓冲区溢出、命令注入或控制字符载荷。
   - 校验通过的客户端会原封不动转发原始字节到 `upstream_sshd_addr`，保证真实 `sshd` 的主机密钥与 `exchange_hash_H` 100% 一致；双方完成 `SSH_MSG_NEWKEYS` 后直接切换为零拷贝双向加密透传。

3. **按威胁类型独立可配置的防御动作（`bruteforce_action` / `cve_exploit_action` / `scanner_action`）**
   - 可针对**爆破突发**、**预认证 CVE / sigil 异常**、**自动化扫描器**分别独立配置为 `fail2ban`、`ssh_honeypot`、`endlessh_tarpit` 或 `drop`：
   - `fail2ban`：在 O(1) 固定容量内存表内封禁来源 IP `quarantine_secs` 秒（重连 0 CPU 秒断），并输出 `MIRAGE_BAN` 日志（可配置 `ban_log_file` 对接宿主机 Fail2Ban / nftables）。
   - `ssh_honeypot`：使用与真实后端一致的缓存 Banner、稳定 Ed25519 主机密钥、Strict-KEX、`aes128-ctr`/`aes256-ctr`、`hmac-sha2-256`/`hmac-sha2-512` 与 `EXT_INFO` 无感引入纯 Rust SSH-2 蜜罐，并受全局/单 IP 并发封顶保护抗 CC。
   - `endlessh_tarpit`：拖入 Endlessh 慢速 pre-banner 焦油坑。
   - `drop`：仅立即断开当前异常连接。
