# Mirage

**Mirage** 是一个基于 Rust 的 **OpenSSH 前置反向代理与预认证 CVE 防护盾**。

Mirage 部署在真实 OpenSSH `sshd` 前端（例如 Mirage 监听 `0.0.0.0:22`，真实 `sshd` 监听 `127.0.0.1:22022`）：正常管理员连接完全透明直通真实 `sshd`（原生密钥、密码、PAM、SFTP 体验完全一致，零露馅风险）；所有针对 OpenSSH 预认证阶段的畸形包、CVE 利用载荷、慢速连接攻击和自动化扫描器都会在**接触真实 `sshd` 之前**被拦截。

> HTTP 蜜罐模块已独立拆分为 **evilpot** 项目；Redis 与 PostgreSQL 蜜罐模块已弃用移除。

---

## 核心防护机制

1. **RFC 4253 Banner 校验与预认证超时门禁**
   - 在连接后端 `sshd` 之前，严格校验客户端 Banner（`SSH-2.0-` / `SSH-1.99-` 前缀、长度上限 `255` 字节、仅允许可打印 ASCII）。
   - 对 Banner + 密钥交换完成（`SSH_MSG_NEWKEYS`）全程施加 `preauth_timeout_secs` 超时限制，缓解 `LoginGraceTime` 慢速预认证竞争/耗尽攻击（如 CVE-2024-6387 regreSSHion）。

2. **Pre-`NEWKEYS` 二进制包校验 + `sigil-filter` 字段启发式检查**
   - 逐包解析未加密的 pre-`NEWKEYS` 阶段 SSH 二进制帧（`packet_length` 上限、`padding_length`、8 字节对齐、合法 pre-KEX 状态机 opcode），阻断如 pre-KEX `SSH_MSG_USERAUTH_SUCCESS`（CVE-2018-10933）或越权 `CHANNEL_OPEN` 等异常状态跳转。
   - 对 `SSH_MSG_KEXINIT` 的 10 个算法列表字段及 `SSH_MSG_DEBUG` 字符串逐一进行长度/字符集校验和 [`sigil-filter`](https://crates.io/crates/sigil-filter) 检测，捕获不当构造的缓冲区溢出、命令注入或控制字符载荷。
   - 校验通过的客户端会原封不动转发原始字节到 `upstream_sshd_addr`，保证真实 `sshd` 的主机密钥与 `exchange_hash_H` 100% 一致；双方完成 `SSH_MSG_NEWKEYS` 后直接切换为零拷贝双向加密透传。

3. **按威胁类型独立可配置的防御动作（`bruteforce_action` / `cve_exploit_action` / `scanner_action`）**
   - 可针对**爆破突发**、**预认证 CVE / sigil 异常**、**自动化扫描器**分别独立配置为 `fail2ban`、`ssh_honeypot`、`endlessh_tarpit` 或 `drop`：
   - `fail2ban`：在 O(1) 固定容量内存表内封禁来源 IP `quarantine_secs` 秒（重连 0 CPU 秒断），并输出 `MIRAGE_BAN` 日志（可配置 `ban_log_file` 对接宿主机 Fail2Ban / nftables）。
   - `ssh_honeypot`：使用与真实后端一致的缓存 Banner、稳定 Ed25519 主机密钥、Strict-KEX、`aes128-ctr`/`aes256-ctr`、`hmac-sha2-256`/`hmac-sha2-512` 与 `EXT_INFO` 无感引入纯 Rust SSH-2 蜜罐，并受全局/单 IP 并发封顶保护抗 CC。
   - `endlessh_tarpit`：拖入 Endlessh 慢速 pre-banner 焦油坑。
   - `drop`：仅立即断开当前异常连接。

---

## 快速部署

### 1. 将真实 OpenSSH `sshd` 迁移至本地回环端口

```sshconfig
# /etc/ssh/sshd_config.d/99-mirage-upstream.conf
ListenAddress 127.0.0.1:22022
```

```bash
sudo sshd -t && sudo systemctl reload ssh
```

### 2. 编译并启动 Mirage 前置防护代理

```bash
cargo build --release --workspace
sudo ./target/release/mirage-daemon --bind 0.0.0.0:22 --upstream-sshd 127.0.0.1:22022
```

或使用一键部署脚本：

```bash
sudo ./mirage.sh deploy
```
