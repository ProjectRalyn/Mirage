# Mirage

**Low-overhead asymmetric deception & tarpit honeypot component for Rust.**

[English](README.md) | [简体中文](README.zh-CN.md)

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![Rust](https://img.shields.io/badge/Rust-1.70%2B-orange.svg)](#quick-start)

**Mirage** is a high-performance, embeddable or standalone deception engine designed to waste attackers' time, compute, and wordlist budget at near-zero cost to the defender. Instead of spinning up heavy containers or dynamically rendering templates on every probe, Mirage pre-bakes coherent, zero-copy server personas (`bytes::Bytes`) in the background and automatically rotates them on a configurable schedule.

---

## Key Capabilities

### 1. Zero-Copy Pre-Generation & Scheduled Rotation
- **Epoch-Based Snapshot Rotation (`mirage-core`)**: A background Tokio task periodically pre-bakes `N` complete server personas off-lock and atomically swaps them in. All HTTP responses, Redis `INFO` payloads, and SSH virtual filesystems are served from immutable `Arc<PrebakedPersona>` snapshots.
- **Deterministic Subnet Sharding**: Attackers from the same `/24` (IPv4) or `/64` (IPv6) subnet are deterministically mapped to the same persona within an epoch—so hostnames, database table names, AWS keys, WordPress nonces, and SSH banners remain 100% consistent across requests. Once the epoch rotates, all previously leaked tokens and passwords expire simultaneously.
- **Cross-Protocol Credential Coherence**: Credentials leaked via HTTP (`/.env`, `/wp-config.php.bak`, `/actuator/env`) are **actually accepted on the first attempt** if the attacker tries them against Mirage's **PostgreSQL**, **Redis**, or **SSH** listeners during the same epoch, immediately raising a `StolenCredentialLoginAccepted` / `StolenCredentialUsed` alert.
- **Bounded Tarpit Watermarking (`TarpitPermit`)**: Global concurrent slow-drip and sleep-tarpit slots are strictly capped (`max_tarpit_connections`) to prevent self-DoS.

### 2. Heuristic Attack Recognition via [`sigil-filter`](https://crates.io/crates/sigil-filter)
- Powered by `sigil-filter` (zero-dependency, ~85 ns benign fast-path, multi-pass anti-obfuscation across 12 attack categories) alongside high-specificity traps.
- Inspects HTTP **paths**, **query strings**, **selected headers** (`User-Agent`, `Referer`, `Cookie`, `X-Api-Version`, `X-Forwarded-Host`, `Authorization`), and **SSH client banners** in `FrontlineProxy` mode.
- Every `ViolationCategory` maps to a tailored, pre-baked rotating deception payload:
  - **`SqlInjection`**: Error-based (MySQL/PostgreSQL), Boolean-based blind, Time-based blind (`SLEEP()`), and **SQLMap character-by-character binary-search extraction** (`ORD(MID((SELECT ...), pos, 1)) > N`).
  - **`PathTraversal`**: Serves the persona's fake `/etc/passwd`, `/proc/self/environ`, or `.env`.
  - **`CommandInjection`**: Extracts the injected command and executes it safely inside the in-memory `FakeShellSession`.
  - **`Ssrf`**: Serves a rotating fake AWS EC2 IMDSv1 temporary credentials JSON (`169.254.169.254`).
  - **`SstiAndCodeInjection`**: Renders evaluated `49` alongside a fake Flask/Jinja2 `config` dump.
  - **`DeserializationAndPrototypePollution`**: Simulates Log4Shell / JNDI `JndiLookup` Java stack traces.
  - **`NoSqlInjection` / `XxeAndXmlInjection` / `LdapInjection` / `Xss` / `CrlfAndHeaderInjection` / `BufferOverflow`**: Serves fake MongoDB admin documents, SOAP XML entity leaks, LDIF dumps, bait non-`HttpOnly` cookies, internal proxy debug headers, or slow-drip tarpits.

### 3. Deep Protocol Deception
- **WordPress / CMS Suite**: Full headers (`X-Pingback`, `Link`, `Set-Cookie: wordpress_test_cookie`), `/wp-login.php` (with realistic POST login-error feedback to bait WPScan), `/wp-json/`, `/wp-json/wp/v2/users`, `/wp-json/wp/v2/posts`, `/xmlrpc.php`, `/wp-config.php.bak`, `/wp-content/debug.log`, `/wp-admin/admin-ajax.php`, and `/readme.html`.
- **Archive Slow-Drip Tarpit**: Requests for `/actuator/heapdump`, `/backup.sql.gz`, etc. receive `200 OK` with `Content-Length: 256 MiB` and valid GZIP / Java HPROF headers, dripped from a 4 KiB ring buffer at a few hundred bytes per second.
- **Redis (`RESP2/RESP3`) Honeypot**: Supports `AUTH`, `PING`, `INFO`, `KEYS *`, `GET`, `SET`, `DBSIZE`, `ROLE`, plus **RCE traps** (`CONFIG SET dir`, `CONFIG SET dbfilename`, `SAVE`/`BGSAVE`, `SLAVEOF`/`REPLICAOF`).
- **PostgreSQL (`PGWire v3.0`) Honeypot**: Full binary handshake (`SSLRequest`, `StartupMessage`, cleartext password auth, `ParameterStatus`, `ReadyForQuery`), queryable `users` and `vault_secrets` tables, and a **CVE-2019-9193 (`COPY ... FROM PROGRAM '...'`)** RCE trap backed by `FakeShellSession`.
- **SSH-2 & In-Memory Linux Shell (`<2 KB` RAM/session)**:
  - Pure-Rust encrypted SSH-2 transport (`curve25519-sha256`, `ssh-ed25519`, `aes128-ctr`, `hmac-sha2-256`) with rotating CVE banners (`OpenSSH_8.9p1`, `OpenSSH_9.2p1 Debian-2+deb12u2`, `libssh_0.8.1`), **CVE-2018-10933** auth-bypass trap, and Nth-attempt weak password acceptance.
  - Interactive Ubuntu 22.04 LTS shell simulation supporting **Tab completion**, **Up/Down arrow history**, `Ctrl-C`/`Ctrl-D`/`Ctrl-L`/`Ctrl-U`, **pipes (`|`)**, **bounded Copy-on-Write redirection (`>` / `>>`)**, environment variables, 60+ realistic commands (`nvidia-smi` showing 8x H100 GPUs, `hostnamectl`, `lscpu`, `docker ps`, `kubectl get secrets`, `sudo -l`, `redis-cli`, `psql`, `ss`, `ip`), and a malware URL catcher (`wget`/`curl` reporting `GLIBC_2.38 not found` after download).

### 4. Hidden, Randomized Admin Panel
- Status and manual rotation endpoints are **never exposed at fixed predictable paths**.
- By default (`path_prefix = "auto"`), Mirage generates a 36-character high-entropy URL prefix at startup (e.g. `/_m_9f4b2c8e1a7d3065b8e2f1c4a9d0731e/status`), or uses any custom path and `X-Mirage-Token` header configured in TOML.

---

## Deployment & Integration Modes

### HTTP Integration Modes (4 Topologies)

| Mode | Topology | Use Case |
| :--- | :--- | :--- |
| **`frontline_proxy`** | In front of your real HTTP backend | Mirage inspects all traffic first (`sigil-filter` + path traps), intercepts attacks, and proxies benign requests via `hyper` to `upstream_http_url`. |
| **`behind_proxy_sink`** | Behind Nginx / Caddy / Envoy / Cloudflare WAF | Receives only suspicious/diverted requests from your edge proxy; restores attacker IP from `X-Real-IP` / `CF-Connecting-IP`, validates optional `required_ingress_header`, and traps 100% of unmatched probes with `sink_fallback_trap`. |
| **`MirageHttpLayer`** | Embedded `tower::Layer` in-process | One-line `.layer(MirageHttpLayer::new(engine))` inside any Axum, Hyper, or Tower service. |
| **`standalone`** | Standalone HTTP honeypot | Pure decoy listener. |

### SSH Integration Modes (3 Topologies)

| Mode | Topology | Use Case |
| :--- | :--- | :--- |
| **Native OpenSSH PAM `.so` + `ForceCommand`** | `libpam_mirage.so` loaded in `/etc/pam.d/sshd` | **Zero port-22 changes**: Real users get `PAM_IGNORE (25)` and authenticate normally; decoy accounts delay `1..N-1` attempts, accept on the Nth attempt (or stolen credential), and drop attackers into `mirage-fake-shell` via `sshd_config` `ForceCommand`. |
| **`frontline_proxy`** | Multiplexer in front of real `sshd` | Listens on port 22 and splices `trusted_client_ips` or `upstream_bypass_banner_substr` clients transparently to `upstream_sshd_addr` (`127.0.0.1:22022`), while routing scanners to Endlessh tarpit or the SSH-2 honeypot. |
| **`standalone`** | Standalone SSH-2 honeypot | Pure-Rust encrypted SSH-2 deception server. |

---

## Architecture

```text
crates/
├── mirage-core   # Config, Epoch persona baker, MirageEngine, sigil-filter detector, FakeShellSession, Redis & PG traps
├── mirage-http   # Tower Layer/Service, FrontlineProxy, BehindProxySink, TarpitDripBody, Nginx/Caddy config generators
├── mirage-ssh    # Encrypted SSH-2 transport, Endlessh pre-banner tarpit, FrontlineProxy multiplexer, ForceCommand stdio shell
├── mirage-pam    # Linux PAM shared library (libpam_mirage.so) for native OpenSSH integration
└── mirage-bin    # `mirage-daemon` (multi-protocol server) & `mirage-fake-shell` (OpenSSH ForceCommand binary)
```

---

## Quick Start

### Build & Test

```bash
git clone git@github.com:ProjectRalyn/Mirage.git
cd Mirage

# Run all 14 unit and integration tests
cargo test --workspace

# Build release binaries and libpam_mirage.so
cargo build --release --workspace
```

### Run Standalone / Frontline / Behind-Proxy Daemon

```bash
# 1. Standalone multi-protocol honeypot (HTTP, SSH, Redis, PostgreSQL)
cargo run --release --bin mirage-daemon -- \
  --http-addr 0.0.0.0:8080 \
  --ssh-addr 0.0.0.0:2222 \
  --redis-addr 0.0.0.0:16379 \
  --pg-addr 0.0.0.0:15432 \
  --rotation-secs 300

# 2. HTTP Frontline Reverse Proxy in front of your real app on :3000
cargo run --release --bin mirage-daemon -- \
  --http-mode frontline-proxy \
  --http-addr 0.0.0.0:8080 \
  --upstream-http http://127.0.0.1:3000

# 3. Generate integration configs for Nginx, Caddy, or OpenSSH PAM .so
cargo run --bin mirage-daemon -- --print-nginx-config
cargo run --bin mirage-daemon -- --print-caddy-config
cargo run --bin mirage-daemon -- --print-sshd-config
cargo run --bin mirage-daemon -- --print-default-config > config.toml
```

### Embed in an Axum Service

See [`crates/mirage-http/examples/axum_embed.rs`](crates/mirage-http/examples/axum_embed.rs):

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

## License

Dual-licensed under [MIT](https://opensource.org/licenses/MIT) or [Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0).
