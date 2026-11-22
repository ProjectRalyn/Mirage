# Mirage

**极低开销、支持可嵌入与独立运行的不对称防御与时间消耗蜜罐（Deception & Tarpit）Rust 组件。**

[English](README.md) | [简体中文](README.zh-CN.md)

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](#许可证)
[![Rust](https://img.shields.io/badge/Rust-1.70%2B-orange.svg)](#快速开始)

**Mirage** 旨在以接近零开销的代价消耗攻击者的自动化扫描器、字典爆破与人工红队精力。不同于启动笨重容器或每次请求动态渲染模板的传统蜜罐，Mirage 在后台定时预先烘焙全套自洽的服务器画像（`bytes::Bytes` 零拷贝内存快照），并在热路径上无锁提供响应与慢速滴灌（Tarpit）。

---

## 快速开始

### 一键部署与管理脚本（Linux `x86_64` / `aarch64`）

自动从 GitHub Releases 拉取最新预编译的 `mirage-daemon`、`mirage-fake-shell` 与 `libpam_mirage.so`，配置 `systemd` 服务与 `/etc/mirage/config.toml`，并支持交互式配置、编辑以及一键挂载原生 OpenSSH PAM（`libpam_mirage.so` + `ForceCommand`）：

```bash
curl -fsSL https://raw.githubusercontent.com/ProjectRalyn/Mirage/main/mirage.sh -o mirage.sh
chmod +x mirage.sh
sudo ./mirage.sh
```

也支持直接通过子命令调用：`sudo ./mirage.sh deploy`、`sudo ./mirage.sh install`、`sudo ./mirage.sh pam-setup`、`sudo ./mirage.sh edit`、`sudo ./mirage.sh status`、`sudo ./mirage.sh logs`、`sudo ./mirage.sh uninstall`。

### 源码编译与测试

```bash
git clone git@github.com:ProjectRalyn/Mirage.git
cd Mirage

# 运行全工作区 14 项单元与集成测试
cargo test --workspace

# 编译 Release 二进制与 libpam_mirage.so
cargo build --release --workspace
```

### 运行示例

```bash
# 1. 启动四合一独立蜜罐（HTTP / SSH / Redis / PostgreSQL）
cargo run --release --bin mirage-daemon -- \
  --http-addr 0.0.0.0:8080 \
  --ssh-addr 0.0.0.0:2222 \
  --redis-addr 0.0.0.0:16379 \
  --pg-addr 0.0.0.0:15432 \
  --rotation-secs 300

# 2. 作为 HTTP 前线反代运行在真实服务 (:3000) 之前
cargo run --release --bin mirage-daemon -- \
  --http-mode frontline-proxy \
  --http-addr 0.0.0.0:8080 \
  --upstream-http http://127.0.0.1:3000

# 3. 一键生成 Nginx / Caddy / OpenSSH PAM .so / TOML 配置模板
cargo run --bin mirage-daemon -- --print-nginx-config
cargo run --bin mirage-daemon -- --print-caddy-config
cargo run --bin mirage-daemon -- --print-sshd-config
cargo run --bin mirage-daemon -- --print-default-config > config.toml
```

### 嵌入 Axum 服务

参考 [`crates/mirage-http/examples/axum_embed.rs`](crates/mirage-http/examples/axum_embed.rs)：

```rust
use axum::{routing::get, Router};
use mirage_core::{MirageConfig, MirageEngine};
use mirage_http::MirageHttpLayer;

let engine = MirageEngine::new(MirageConfig::default());
engine.spawn_rotation_task();

let app = Router::new()
    .route("/api/health", get(|| async { "OK" }))
    .layer(MirageHttpLayer::new(engine));
```

---

## 核心特性

### 1. 零拷贝预生成与定时轮换
- **基于 Epoch 的快照轮换（`mirage-core`）**：后台 Tokio 定时任务在锁外预先生成 `N` 套完整服务器画像并原子切换。所有 HTTP 响应、Redis `INFO` 块及 SSH 虚拟文件系统均从不可变 `Arc<PrebakedPersona>` 快照读取。
- **确定性子网分片**：同一 `/24`（IPv4）或 `/64`（IPv6）网段的攻击者在当前周期内始终映射到同一画像——主机名、数据库表名、假 AWS Key、WordPress Nonce 与 SSH Banner 完全自洽；定时轮换触发后，旧周期泄露的密钥与密码全部同时失效。
- **跨协议凭证自洽联动**：攻击者在 HTTP（`/.env`、`/wp-config.php.bak`、`/actuator/env`）中窃取的密码，在同一周期内去登录 Mirage 的 **PostgreSQL**、**Redis** 或 **SSH** 端口时**第 1 次即可直接登录成功**，并立即触发 `StolenCredentialLoginAccepted` / `StolenCredentialUsed` 高危告警。
- **并发水位熔断（`TarpitPermit`）**：全局限制最大慢速滴灌与延迟连接数（`max_tarpit_connections`），防止反向 DoS。

### 2. 集成 [`sigil-filter`](https://crates.io/crates/sigil-filter) 零分配启发式攻击识别
- 结合高特异性路径规则与 `sigil-filter`（零外部依赖、正常请求 ~85 ns 热路径短接、多层解混淆、覆盖 12 类攻击载荷）。
- 同时检测 HTTP **Path**、**Query**、**关键请求头**（`User-Agent`、`Referer`、`Cookie`、`X-Api-Version`、`X-Forwarded-Host`、`Authorization`）以及 `FrontlineProxy` 模式下的 **SSH 客户端 Banner**。
- 12 类 `ViolationCategory` 均映射到专属的预生成轮换诱饵：
  - **`SqlInjection`**：MySQL/PostgreSQL 语法报错、布尔盲注、时间盲注（`SLEEP()`），以及 **SQLMap 逐字符二分盲注提取**（`ORD(MID((SELECT ...), pos, 1)) > N`）。
  - **`PathTraversal`**：返回当前画像的假 `/etc/passwd`、`/proc/self/environ` 或 `.env`。
  - **`CommandInjection`**：提取注入命令并在纯内存 `FakeShellSession` 中安全执行并返回逼真回显。
  - **`Ssrf`**：返回自动轮换的假 AWS EC2 IMDSv1 临时凭证 JSON（`169.254.169.254`）。
  - **`SstiAndCodeInjection`**：渲染 `49` 及伪造的 Flask/Jinja2 `config` 字典。
  - **`DeserializationAndPrototypePollution`**：模拟 Log4Shell / JNDI `JndiLookup` Java 堆栈报错。
  - **`NoSqlInjection` / `XxeAndXmlInjection` / `LdapInjection` / `Xss` / `CrlfAndHeaderInjection` / `BufferOverflow`**：分别返回假 MongoDB 文档、SOAP XML 实体回显、LDIF 目录导出、非 `HttpOnly` 诱饵 Cookie、代理调试头或慢速滴灌 Tarpit。

### 3. 多协议深度仿真
- **WordPress / CMS 全套仿真**：完整 WP 响应头（`X-Pingback`、`Link`、`Set-Cookie: wordpress_test_cookie`）、`/wp-login.php`（POST 爆破延迟与标准用户名错误提示）、`/wp-json/`、`/wp-json/wp/v2/users`、`/wp-json/wp/v2/posts`、`/xmlrpc.php`、`/wp-config.php.bak`、`/wp-content/debug.log`、`/wp-admin/admin-ajax.php`、`/readme.html`。
- **大文件慢速滴灌（Tarpit）**：针对 `/actuator/heapdump`、`/backup.sql.gz` 等请求，返回 `200 OK`、`Content-Length: 256 MiB` 及合法 GZIP / HPROF 文件头，以每秒数百字节从 4 KiB 环形缓冲区持续滴灌。
- **Redis (`RESP2/RESP3`) 蜜罐**：支持 `AUTH`、`PING`、`INFO`、`KEYS *`、`GET`、`SET`、`DBSIZE`、`ROLE`，以及 **写公钥/计划任务/主从复制 RCE 陷阱**（`CONFIG SET dir`、`CONFIG SET dbfilename`、`SAVE`/`BGSAVE`、`SLAVEOF`/`REPLICAOF`）。
- **PostgreSQL (`PGWire v3.0`) 蜜罐**：完整二进制握手（`SSLRequest`、`StartupMessage`、密码认证、`ParameterStatus`、`ReadyForQuery`），可查询 `users`、`vault_secrets` 表，并内置 **CVE-2019-9193（`COPY ... FROM PROGRAM '...'`）** 超管 RCE 陷阱。
- **SSH-2 与纯内存 Linux 终端（`<2 KB` 内存/会话）**：
  - 纯 Rust 加密 SSH-2 传输层（`curve25519-sha256`、`ssh-ed25519`、`aes128-ctr`、`hmac-sha2-256`），支持轮换高危 CVE Banner、**CVE-2018-10933** 认证绕过陷阱、第 $N$ 次弱密码爆破放行。
  - 完整交互式 Ubuntu 22.04 LTS 仿真：支持 **Tab 补全**、**上下方向键历史回溯**、`Ctrl-C`/`Ctrl-D`/`Ctrl-L`/`Ctrl-U`、**管道 (`|`)**、**有界 Copy-on-Write 文件重定向 (`>` / `>>`)**、环境变量、60+ 常用命令（8 卡 H100 `nvidia-smi`、`hostnamectl`、`lscpu`、`docker ps`、`kubectl get secrets`、`sudo -l`、`redis-cli`、`psql`、`ss`、`ip`）及木马 URL 捕获（`wget`/`curl` 下载后报 `GLIBC_2.38 not found`）。

### 4. 隐藏式随机后台面板
- 状态监控与手动轮换接口**绝不暴露在固定可预测 URL**。
- 默认 `path_prefix = "auto"` 每次启动自动生成 36 位高熵随机路径（如 `/_m_9f4b2c8e1a7d3065b8e2f1c4a9d0731e/status`），也可在 TOML 中配置任意长随机路径及 `X-Mirage-Token` 鉴权头。

---

## 支持的接入与部署模式

### HTTP 接入模式（4 种）

| 模式 | 拓扑位置 | 说明 |
| :--- | :--- | :--- |
| **`frontline_proxy`** | 站在真实业务服务最前线 | Mirage 率先用 `sigil-filter` + 规则检测流量，攻击请求直接进入诱饵，正常请求通过 `hyper` 透明反代至 `upstream_http_url`。 |
| **`behind_proxy_sink`** | 挂在 Nginx / Caddy / Envoy / WAF 之后 | 专门接收前置网关识别并引流过来的疑似攻击请求；支持 `X-Real-IP` / `CF-Connecting-IP` 还原攻击者 IP、可选校验 `required_ingress_header` 防绕过直扫，并对任意未匹配路径使用 `sink_fallback_trap` 兜底全量捕获。 |
| **`MirageHttpLayer`** | 进程内 `tower::Layer` 中间件 | 一行 `.layer(MirageHttpLayer::new(engine))` 直接嵌入现有 Axum / Hyper / Tower 服务。 |
| **`standalone`** | 独立蜜罐监听 | 作为纯诱饵节点独立运行。 |

### SSH 接入模式（3 种）

| 模式 | 拓扑位置 | 说明 |
| :--- | :--- | :--- |
| **原生 OpenSSH PAM `.so` + `ForceCommand`** | `libpam_mirage.so` 挂载于 `/etc/pam.d/sshd` | **不改动 22 端口**：真实管理员账号在 `pam_sm_authenticate` 中立即返回 `PAM_IGNORE (25)` 走原系统认证；诱饵账号第 $N$ 次爆破（或使用窃取到的轮换密码）放行，并由 `sshd_config` 的 `ForceCommand` 送入 `mirage-fake-shell`。 |
| **`frontline_proxy`** | 站在真实 `sshd` 前面的反代分流器 | 监听 22 端口，按 `trusted_client_ips` 或 `upstream_bypass_banner_substr` 将可信流量透明拼接 (`copy_bidirectional`) 至 `upstream_sshd_addr`（如 `127.0.0.1:22022`），扫描器进入 Endlessh Tarpit 或 SSH-2 蜜罐。 |
| **`standalone`** | 独立 SSH-2 蜜罐 | 纯 Rust 加密 SSH-2 欺骗服务。 |

---

## 项目结构

```text
crates/
├── mirage-core   # 配置、Epoch 画像烘焙、MirageEngine、sigil-filter 检测器、FakeShellSession、Redis/PG 蜜罐
├── mirage-http   # Tower Layer/Service、FrontlineProxy、BehindProxySink、TarpitDripBody、Nginx/Caddy 配置生成器
├── mirage-ssh    # 加密 SSH-2 传输层、Endlessh Pre-Banner Tarpit、FrontlineProxy 分流器、ForceCommand 终端
├── mirage-pam    # 原生 OpenSSH 接入用 Linux PAM 动态链接库 (libpam_mirage.so)
└── mirage-bin    # `mirage-daemon`（多协议守护进程）与 `mirage-fake-shell`（OpenSSH ForceCommand 二进制）
```

---

## 许可证

采用 [MIT](https://opensource.org/licenses/MIT) 或 [Apache-2.0](https://opensource.org/licenses/Apache-2.0) 双重许可。
