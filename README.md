# MiragePot (`mirage-pot`)

一个专为**不对称防御（Asymmetric Deception & Tarpit）**设计的极低开销 Rust 蜜罐组件。既可以作为 `tower::Layer` 零侵入嵌入现有 Rust Web 服务（Axum / Hyper / Tower），也可以作为独立的 **HTTP (WordPress/API) + SSH + Redis + PostgreSQL** 多协议蜜罐守护进程（`mirage-daemon`）或原生 OpenSSH 受限诱饵终端（`mirage-fake-shell`）运行。

---

## 核心增强特性

1. **绝不暴露固定后台 URL（动态随机长路径 + 自定义路由 + Token 鉴权）**：
   - 状态面板与手动轮换接口**不再使用任何固定路径**。默认配置 `path_prefix = "auto"` 会在每次启动时自动生成 36 位高熵随机路径（如 `/_m_9f4b2c8e1a7d3065b8e2f1c4a9d0731e/status`），也可在 `config.toml` 中自定义为任意超长随机路径，并支持 `X-Mirage-Token` Header 鉴权（未授权探测直接返回伪装 404）。
   - 所有 HTTP 诱饵触发路径（WordPress、配置泄露、API 调试、慢速滴灌归档后缀）均可在 `config.toml` 中自由增删改。

2. **跨协议凭证自洽联动（HTTP 泄露 $\rightarrow$ Redis / PostgreSQL / SSH 真实可用）**：
   - 同一轮换周期（Epoch）内，同一攻击者网段在 `/.env` 或 `/wp-config.php.bak` 中偷到的 `DB_PASSWORD` 和 `WP_REDIS_PASSWORD`，拿去连蜜罐的 **PostgreSQL 端口**、**Redis 端口**或 **SSH 端口**时，**会直接认证成功（第 1 次即放行）**并触发高优告警 `StolenCredentialUsed`！
   - 定时轮换触发后，所有预生成快照原子切换，旧密码跨全协议同时失效。

3. **深度逼真的 WordPress / Redis / PostgreSQL 协议级伪装**：
   - **WordPress 全套仿真**：
     - 完整响应头（`X-Pingback`、`Link: <.../wp-json/>; rel="https://api.w.org/"`、`Set-Cookie: wordpress_test_cookie=...`）。
     - 覆盖 `/wp-login.php`（GET 登录框 + POST 爆破延迟及标准 WP 用户名存在错误提示）、`/wp-json/`（REST 根发现文档）、`/wp-json/wp/v2/users`、`/wp-json/wp/v2/posts`（内含运维迁移笔记诱饵）、`/xmlrpc.php`、`/wp-config.php.bak`（及 `.wp-config.php.swp`）、`/wp-content/debug.log`（PHP 死锁与 Redis/S3 报错日志）、`/wp-admin/admin-ajax.php`、`/readme.html`。
   - **Redis (RESP2/RESP3) 协议蜜罐 (`db_traps.rs`)**：
     - 支持 `redis-cli` 与自动化脚本直接连接，支持 `AUTH`（第 $N$ 次爆破放行或偷来的密码直接放行）、`PING`、`INFO`（零拷贝返回逼真的 Redis 7.0.11 主从状态）、`KEYS *`、`GET`、`SET`、`DBSIZE`、`ROLE`。
     - **Redis 写公钥 / 写计划任务 / 主从复制 RCE 陷阱**：完美伪装 `CONFIG SET dir /root/.ssh`、`CONFIG SET dbfilename authorized_keys`、`SAVE`/`BGSAVE` 以及 `SLAVEOF`/`REPLICAOF` 恶意主从加载，捕获攻击者写入的公钥与 Rogue Master 地址。
   - **PostgreSQL (PGWire v3.0) 协议蜜罐 (`db_traps.rs`)**：
     - 实现完整 PostgreSQL v3 二进制握手（自动处理 `SSLRequest`、`StartupMessage`、明文密码认证、`ParameterStatus`、`ReadyForQuery`），支持真实 `psql` / Navicat / DBeaver / Metasploit 直接连接。
     - 支持查询 `SELECT version()`、`pg_tables`、`SELECT * FROM users`、`SELECT * FROM vault_secrets`。
     - **CVE-2019-9193 (`COPY ... FROM PROGRAM '...'`) 超管 RCE 陷阱**：自动提取 `FROM PROGRAM` 中的 Shell 命令送入纯内存伪终端执行，将逼真的命令输出封装为 PostgreSQL `DataRow` 返回给攻击者！

4. **与真实 Ubuntu 22.04 服务器一模一样的极低开销 SSH 终端 (`shell.rs` & `transport.rs`)**：
   - **零进程、`<2 KB` 内存/会话**：基于共享预生成模板 + 有界 Copy-on-Write (CoW) 内存覆盖层（最多 16 个文件 / 8 KB）。
   - **交互式终端体验**：支持 **Tab 键命令与文件名补全**、**上下方向键 (`\x1b[A`/`\x1b[B`) 历史命令回溯**、`Ctrl-C`、`Ctrl-D`、`Ctrl-L` 清屏、`Ctrl-U`。
   - **支持管道 (`|`)、重定向 (`>` / `>>`) 与环境变量 (`export` / `$VAR` / `$?`)**：
     - 攻击者可执行 `cat /etc/passwd | grep bash | wc -l`、`ps aux | grep python`、`cat ~/.env | base64`。
     - 攻击者执行 `echo "ssh-ed25519 AAAA..." >> ~/.ssh/authorized_keys` 后再 `cat ~/.ssh/authorized_keys`，能看到自己刚写入的公钥，同时蜜罐在后台静默捕获写入内容。
   - **60+ 逼真 Linux 命令模板**：
     - 系统与硬件：`uname`、`hostnamectl`、`lsb_release`、`lscpu`（96 核 AMD EPYC 9654）、`lspci`、`lsblk`、`free -h`（504GiB 内存）、`df -h`、`mount`、`dmesg`、`uptime`、`date`、`nvidia-smi`（8x NVIDIA H100 80GB 显卡）、`top`、`ps aux`。
     - 权限与服务：`id`、`whoami`、`groups`、`w`、`who`、`last`、`sudo -l`（暴露 `(root) NOPASSWD: /usr/bin/python3 /opt/deploy/sync_vault.py` 诱饵并支持执行）、`crontab -l`、`systemctl status`、`service`、`journalctl`。
     - 网络与容器/数据库客户端：`ip a`、`ip route`、`ifconfig`、`ss -tulnp`、`netstat`、`arp`、`iptables -L`、`ping`、`dig`、`docker ps`、`docker images`、`kubectl get pods`、`kubectl get secrets`、`aws s3 ls`、`redis-cli`、`psql`、`git`。
     - 木马捕获器：`wget`、`curl`、`scp`、`tftp`、`nc`、`socat`。

---

## 支持的接入与部署模式

### HTTP 接入模式（4 种）

| 模式 | 拓扑位置 | 适用场景与特点 | 启动 / 接入方式 |
| :--- | :--- | :--- | :--- |
| **1. 前线反代 (`frontline_proxy`)** | 站在真实业务服务最前线 | 攻击探针直接由 MiragePot 拦截进入诱饵/滴灌；正常业务请求通过内置 `hyper` HTTP/1.1 反向代理透明转发至上游 `upstream_http_url`。 | `mirage-daemon --http-mode frontline-proxy --upstream-http http://127.0.0.1:3000` |
| **2. 后置引流池 (`behind_proxy_sink`)** | 挂在 Nginx / Caddy / WAF / Cloudflare 之后 | 前置网关过滤识别疑似攻击后引流进来；信任 `X-Real-IP` / `CF-Connecting-IP`，可选校验 `required_ingress_header`（防绕过 WAF 直扫）；未命中具体路径规则的任意探测自动兜底返回 `sink_fallback_trap`（100% 捕获不放过）。 | `mirage-daemon --http-mode behind-proxy-sink`（可用 `--print-nginx-config` / `--print-caddy-config` 一键导出反代配置） |
| **3. 嵌入式库 (`MirageHttpLayer`)** | 进程内 `tower::Layer` 中间件 | 零额外网络跳数，一行 `.layer(MirageHttpLayer::new(engine))` 直接挂在现有 Axum / Hyper / Tower Rust 服务上。 | 见 `crates/mirage-http/examples/axum_embed.rs` |
| **4. 独立蜜罐 (`standalone`)** | 独立监听端口 | 作为纯诱饵节点部署。 | `mirage-daemon --http-mode standalone` |

### SSH 接入模式（3 种）

| 模式 | 拓扑位置 | 适用场景与特点 | 启动 / 接入方式 |
| :--- | :--- | :--- | :--- |
| **1. 原生 OpenSSH PAM `.so` + `ForceCommand`** | 作为动态链接库 `libpam_mirage.so` 直接挂在宿主机 OpenSSH 上 | **不改动 22 端口，零风险**：真实管理员账号在 `pam_sm_authenticate` 中直接返回 `PAM_IGNORE` 走原系统认证；诱饵账号第 $N$ 次爆破（或使用从 `.env`/`wp-config` 偷来的密码）放行进入 `mirage-fake-shell`。 | `cargo build --release --workspace` 生成 `target/release/libpam_mirage.so` + `mirage-fake-shell`；运行 `mirage-daemon --print-sshd-config` 获取完整 `/etc/pam.d/sshd` 与 `sshd_config` 配置 |
| **2. 前线反代分流 (`frontline_proxy`)** | 站在真实 `sshd`（如 `127.0.0.1:22022`）最前线 | 支持按 `trusted_client_ips` 白名单或 `upstream_bypass_banner_substr` 隐蔽 Banner 暗号将管理员透明拼接 (`copy_bidirectional`) 至真实 `sshd`；扫描器进 Endlessh Tarpit，其余攻击者进轮换 CVE Banner 的 SSH-2 蜜罐。 | `mirage-daemon --ssh-mode frontline-proxy --ssh-addr 0.0.0.0:22 --upstream-sshd 127.0.0.1:22022` |
| **3. 独立 SSH-2 蜜罐 (`standalone`)** | 独立端口 | 纯 Rust 完整 SSH-2 加密传输层 + 轮换 CVE Banner + CVE-2018-10933 陷阱 + 纯内存假 Shell。 | `mirage-daemon --ssh-mode standalone --ssh-addr 0.0.0.0:2222` |

