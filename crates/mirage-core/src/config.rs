use rand::Rng;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::Path;

/// Root configuration for the MiragePot deception & tarpit component.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MirageConfig {
    /// Rotation interval in seconds for pre-generated deception snapshots.
    pub rotation_interval_secs: u64,
    /// Number of distinct pre-baked server personas per rotation epoch.
    pub persona_slots: usize,
    /// Master secret seed used for deterministic generation across rotations.
    pub master_seed: u64,
    /// Maximum concurrent slow/tarpit connections allowed across the process.
    pub max_tarpit_connections: usize,
    /// Bytes per second dripped to tarpitted HTTP/SSH/DB streams.
    pub tarpit_drip_bytes_per_sec: usize,
    /// Canary token / webhook base URL embedded into fake `.env`, Git configs, Redis keys, and PG rows.
    pub canary_webhook_url: String,
    /// Management & telemetry panel configuration (customizable / randomized secret URL).
    pub admin: AdminPanelConfig,
    /// `sigil-filter` zero-allocation heuristic attack recognition engine configuration.
    pub sigil: SigilFilterConfig,
    /// HTTP deception & reverse-proxy / WAF-sink configuration.
    pub http: HttpHoneypotConfig,
    /// SSH deception, frontline proxy, and OpenSSH integration configuration.
    pub ssh: SshHoneypotConfig,
    /// Redis (RESP2/RESP3) deception & RCE trap configuration.
    pub redis: RedisHoneypotConfig,
    /// PostgreSQL (PGWire v3) deception & COPY-FROM-PROGRAM trap configuration.
    pub postgres: PostgresHoneypotConfig,
}

impl Default for MirageConfig {
    fn default() -> Self {
        Self {
            rotation_interval_secs: 300,
            persona_slots: 16,
            master_seed: 0x4D49_5241_4745_504F,
            max_tarpit_connections: 1024,
            tarpit_drip_bytes_per_sec: 256,
            canary_webhook_url: "https://canary.internal.example.com/t".to_string(),
            admin: AdminPanelConfig::default(),
            sigil: SigilFilterConfig::default(),
            http: HttpHoneypotConfig::default(),
            ssh: SshHoneypotConfig::default(),
            redis: RedisHoneypotConfig::default(),
            postgres: PostgresHoneypotConfig::default(),
        }
    }
}

/// Configuration for the embedded `sigil-filter` heuristic attack recognizer
/// (zero-dependency, ~85ns benign short-circuit across all 12 attack categories).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SigilFilterConfig {
    /// Enable `sigil-filter` heuristic attack detection across HTTP paths, queries, headers, and SSH banners.
    pub enabled: bool,
    /// Minimum Noisy-OR confidence score `[0.0, 1.0]` required to classify a request as malicious.
    pub min_confidence: f32,
    /// Byte length warning threshold for `BufferOverflow` detection.
    pub overflow_warn_len: usize,
    /// Byte length critical threshold for `BufferOverflow` detection.
    pub overflow_crit_len: usize,
    /// Inspect HTTP headers (`User-Agent`, `Referer`, `Cookie`, `X-Api-Version`, `X-Forwarded-Host`, etc.)
    /// with `sigil-filter` to catch header-borne attacks such as Log4Shell (`${jndi:...}`) and CRLF injection.
    pub inspect_headers: bool,
    /// Inspect SSH client identification banners with `sigil-filter` in `FrontlineProxy` mode.
    pub inspect_ssh_banners: bool,
}

impl Default for SigilFilterConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_confidence: 0.55,
            overflow_warn_len: 2048,
            overflow_crit_len: 8192,
            inspect_headers: true,
            inspect_ssh_banners: true,
        }
    }
}

impl MirageConfig {
    pub fn from_toml_file(path: impl AsRef<Path>) -> Result<Self, String> {
        let content = std::fs::read_to_string(path.as_ref())
            .map_err(|e| format!("failed to read config file {}: {e}", path.as_ref().display()))?;
        toml::from_str(&content).map_err(|e| format!("failed to parse TOML config: {e}"))
    }

    pub fn from_toml_str(content: &str) -> Result<Self, String> {
        toml::from_str(content).map_err(|e| format!("failed to parse TOML config: {e}"))
    }
}

/// Configuration for the internal telemetry/rotation endpoints so they are never exposed at fixed URLs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AdminPanelConfig {
    pub enabled: bool,
    /// Set to `"auto"` to generate a 36-char high-entropy random prefix at startup,
    /// or specify any custom long random prefix in TOML.
    pub path_prefix: String,
    /// Optional secret token required in the `X-Mirage-Token` header.
    pub secret_token: Option<String>,
}

impl Default for AdminPanelConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            path_prefix: "auto".to_string(),
            secret_token: None,
        }
    }
}

impl AdminPanelConfig {
    pub fn resolved_prefix(&self) -> String {
        let trimmed = self.path_prefix.trim();
        if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("auto") {
            let mut rng = rand::thread_rng();
            let rand_hex: String = (0..32)
                .map(|_| {
                    const HEX: &[u8] = b"0123456789abcdef";
                    HEX[rng.gen_range(0..16)] as char
                })
                .collect();
            format!("/_m_{rand_hex}")
        } else if trimmed.starts_with('/') {
            trimmed.trim_end_matches('/').to_string()
        } else {
            format!("/{}", trimmed.trim_end_matches('/'))
        }
    }
}

/// Deployment topology mode for the HTTP honeypot component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpDeployMode {
    /// Standalone honeypot server (benign requests hit a minimal default gateway page).
    Standalone,
    /// Frontline reverse proxy sitting in front of `upstream_http_url`:
    /// attack probes are intercepted and trapped; benign traffic is transparently proxied upstream.
    FrontlineProxy,
    /// Sink honeypot sitting BEHIND an existing reverse proxy / WAF (Nginx / Caddy / Envoy / Cloudflare):
    /// all requests routed here are already considered suspicious; unmatched paths automatically fall
    /// back to `sink_fallback_trap` instead of returning 404 or passing through!
    BehindProxySink,
}

impl Default for HttpDeployMode {
    fn default() -> Self {
        Self::Standalone
    }
}

/// Fallback trap returned in `BehindProxySink` mode when a WAF-diverted request does not match
/// a specific path rule (e.g. arbitrary `/admin-v2` or `/struts2` probes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SinkFallbackTrap {
    ApiDebug,
    WordPressLogin,
    SqlError,
    DotEnv,
    TarpitStream,
}

impl Default for SinkFallbackTrap {
    fn default() -> Self {
        Self::ApiDebug
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HttpHoneypotConfig {
    /// Deployment mode: `standalone`, `frontline_proxy`, or `behind_proxy_sink`.
    pub mode: HttpDeployMode,
    /// Bind address when running standalone / frontline_proxy / behind_proxy_sink.
    pub bind_addr: SocketAddr,
    /// Real upstream HTTP backend (e.g. `http://127.0.0.1:3000`) used in `frontline_proxy` mode.
    pub upstream_http_url: Option<String>,
    /// Fallback deception trap used in `behind_proxy_sink` mode when no specific path trap matches.
    pub sink_fallback_trap: SinkFallbackTrap,
    /// Preferred header to extract the real attacker IP when running behind Nginx/Caddy/Cloudflare
    /// (e.g. `"x-real-ip"`, `"cf-connecting-ip"`, or `"x-forwarded-for"`).
    pub real_ip_header: Option<String>,
    /// Optional ingress validation header in `behind_proxy_sink` mode (`"Header-Name: Expected-Value"`).
    /// When set, requests missing this header are ignored with 404 so direct scans bypassing your WAF
    /// cannot probe the sink directly.
    pub required_ingress_header: Option<String>,
    pub enable_wordpress_trap: bool,
    pub enable_secret_leak_trap: bool,
    pub enable_sqli_trap: bool,
    pub enable_api_trap: bool,
    pub enable_tarpit_archives: bool,
    pub fake_archive_size_bytes: u64,
    pub sqli_time_delay_ms: u64,
    pub custom_wordpress_paths: Vec<String>,
    pub custom_secret_paths: Vec<String>,
    pub custom_api_debug_paths: Vec<String>,
    pub custom_tarpit_suffixes: Vec<String>,
    pub scanner_user_agents: Vec<String>,
}

impl Default for HttpHoneypotConfig {
    fn default() -> Self {
        Self {
            mode: HttpDeployMode::Standalone,
            bind_addr: "0.0.0.0:8080".parse().unwrap(),
            upstream_http_url: None,
            sink_fallback_trap: SinkFallbackTrap::ApiDebug,
            real_ip_header: Some("x-real-ip".to_string()),
            required_ingress_header: None,
            enable_wordpress_trap: true,
            enable_secret_leak_trap: true,
            enable_sqli_trap: true,
            enable_api_trap: true,
            enable_tarpit_archives: true,
            fake_archive_size_bytes: 256 * 1024 * 1024,
            sqli_time_delay_ms: 2500,
            custom_wordpress_paths: vec![
                "/wp-login.php".to_string(),
                "/wp-admin".to_string(),
                "/wp-json".to_string(),
                "/xmlrpc.php".to_string(),
                "/wp-content/debug.log".to_string(),
                "/wp-config.php.bak".to_string(),
                "/wp-config.php~".to_string(),
                "/.wp-config.php.swp".to_string(),
                "/wp-includes/wlwmanifest.xml".to_string(),
                "/readme.html".to_string(),
            ],
            custom_secret_paths: vec![
                "/.env".to_string(),
                "/.git/config".to_string(),
                "/.git/HEAD".to_string(),
                "/actuator/env".to_string(),
                "/phpinfo.php".to_string(),
            ],
            custom_api_debug_paths: vec![
                "/api/v1/debug".to_string(),
                "/api/debug".to_string(),
                "/admin/debug".to_string(),
                "/_debug".to_string(),
            ],
            custom_tarpit_suffixes: vec![
                "/heapdump".to_string(),
                ".sql.gz".to_string(),
                ".sql".to_string(),
                "/backup.zip".to_string(),
                "/backup.tar.gz".to_string(),
                "/www.zip".to_string(),
                "/db_backup.gz".to_string(),
            ],
            scanner_user_agents: vec![
                "sqlmap".to_string(),
                "nuclei".to_string(),
                "nikto".to_string(),
                "dirsearch".to_string(),
                "gobuster".to_string(),
                "feroxbuster".to_string(),
                "ffuf".to_string(),
                "masscan".to_string(),
                "zgrab".to_string(),
                "acunetix".to_string(),
                "nessus".to_string(),
                "wpscan".to_string(),
            ],
        }
    }
}

/// Deployment topology mode for the SSH honeypot component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SshDeployMode {
    /// Standalone SSH-2 honeypot (all incoming connections enter deception / tarpit).
    Standalone,
    /// Frontline SSH reverse proxy / multiplexer sitting in front of real `upstream_sshd_addr`:
    /// trusted IPs or secret-banner admin clients are transparently spliced to real `sshd`,
    /// while scanners and untrusted attackers enter the MiragePot SSH-2 honeypot / Endlessh tarpit.
    FrontlineProxy,
}

impl Default for SshDeployMode {
    fn default() -> Self {
        Self::Standalone
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SshHoneypotConfig {
    /// Deployment mode: `standalone` or `frontline_proxy`.
    /// (For native OpenSSH `.so` integration, load `libpam_mirage.so` in `/etc/pam.d/sshd` + `mirage-fake-shell`.)
    pub mode: SshDeployMode,
    /// Bind address for the standalone SSH honeypot / frontline multiplexer.
    pub bind_addr: SocketAddr,
    /// Real OpenSSH daemon address (e.g. `127.0.0.1:22022`) used in `frontline_proxy` mode.
    pub upstream_sshd_addr: Option<SocketAddr>,
    /// Client IP addresses transparently forwarded to `upstream_sshd_addr` in `frontline_proxy` mode.
    pub trusted_client_ips: Vec<String>,
    /// Optional secret substring in the client SSH identification banner that routes the connection
    /// directly to `upstream_sshd_addr` (e.g. a bastion/admin custom banner comment).
    pub upstream_bypass_banner_substr: Option<String>,
    /// When true in `frontline_proxy` mode, connections whose client banner is NOT in `scanner_ssh_banners`
    /// are proxied to real `sshd` (only known scanner banners go to the honeypot).
    /// When false (default, safer), only `trusted_client_ips` or `upstream_bypass_banner_substr` reach real `sshd`.
    pub proxy_non_scanners_to_upstream: bool,
    /// Client SSH identification string substrings immediately classified as automated scanners.
    pub scanner_ssh_banners: Vec<String>,
    /// When true, known scanner banners are placed into an Endlessh-style pre-banner tarpit.
    pub endlessh_tarpit_for_scanners: bool,
    /// Interval in milliseconds between pre-banner tarpit drip lines.
    pub endlessh_drip_interval_ms: u64,
    /// Accept any password on the N-th authentication attempt from the same IP/session.
    pub accept_password_on_attempt: u32,
    /// Artificial delay in milliseconds before rejecting a password attempt.
    pub auth_fail_delay_ms: u64,
    /// Simulate CVE-2018-10933 / CVE-2023-38408 / CVE-2024-6387 banners.
    pub simulate_cve_banners: bool,
}

impl Default for SshHoneypotConfig {
    fn default() -> Self {
        Self {
            mode: SshDeployMode::Standalone,
            bind_addr: "0.0.0.0:2222".parse().unwrap(),
            upstream_sshd_addr: None,
            trusted_client_ips: Vec::new(),
            upstream_bypass_banner_substr: None,
            proxy_non_scanners_to_upstream: false,
            scanner_ssh_banners: vec![
                "masscan".to_string(),
                "zgrab".to_string(),
                "libssh2".to_string(),
                "paramiko".to_string(),
                "go-ssh".to_string(),
                "SSH-2.0-Go".to_string(),
                "asyncssh".to_string(),
                "JSCH".to_string(),
            ],
            endlessh_tarpit_for_scanners: false,
            endlessh_drip_interval_ms: 4000,
            accept_password_on_attempt: 3,
            auth_fail_delay_ms: 1200,
            simulate_cve_banners: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RedisHoneypotConfig {
    pub enabled: bool,
    pub bind_addr: SocketAddr,
    pub accept_auth_on_attempt: u32,
    pub auth_fail_delay_ms: u64,
}

impl Default for RedisHoneypotConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bind_addr: "0.0.0.0:16379".parse().unwrap(),
            accept_auth_on_attempt: 2,
            auth_fail_delay_ms: 800,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PostgresHoneypotConfig {
    pub enabled: bool,
    pub bind_addr: SocketAddr,
    pub accept_auth_on_attempt: u32,
    pub auth_fail_delay_ms: u64,
}

impl Default for PostgresHoneypotConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bind_addr: "0.0.0.0:15432".parse().unwrap(),
            accept_auth_on_attempt: 2,
            auth_fail_delay_ms: 900,
        }
    }
}
