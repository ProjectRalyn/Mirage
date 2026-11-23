use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::Path;

/// Root configuration for the Mirage OpenSSH Frontline Reverse Proxy & Pre-Auth CVE Shield.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MirageConfig {
    /// Rotation interval in seconds for pre-generated honeypot VFS personas.
    pub rotation_interval_secs: u64,
    /// Number of distinct pre-baked server personas per rotation epoch.
    pub persona_slots: usize,
    /// Master secret seed used for deterministic generation & stable honeypot host key derivation.
    pub master_seed: u64,
    /// Maximum concurrent tarpit connections allowed across the process.
    pub max_tarpit_connections: usize,
    /// Canary webhook base URL embedded into fake shell secrets inside the honeypot.
    pub canary_webhook_url: String,
    /// `sigil-filter` zero-allocation heuristic inspection configuration for SSH banners & KEX packets.
    pub sigil: SigilFilterConfig,
    /// Frontline SSH reverse proxy, pre-auth OpenSSH CVE shield, anti-CC/DoS, and response policy configuration.
    pub ssh: SshProxyConfig,
}

impl Default for MirageConfig {
    fn default() -> Self {
        Self {
            rotation_interval_secs: 300,
            persona_slots: 16,
            master_seed: 0x4D49_5241_4745_504F,
            max_tarpit_connections: 1024,
            canary_webhook_url: "https://canary.internal.example.com/t".to_string(),
            sigil: SigilFilterConfig::default(),
            ssh: SshProxyConfig::default(),
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

/// Configuration for the embedded `sigil-filter` heuristic attack recognizer
/// inspecting SSH client identification banners and pre-auth KEX packet fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SigilFilterConfig {
    /// Enable `sigil-filter` inspection on pre-auth SSH banners and KEX fields.
    pub enabled: bool,
    /// Minimum Noisy-OR confidence score `[0.0, 1.0]` required to flag a constructed field as malicious.
    pub min_confidence: f32,
    /// Byte length warning threshold for `BufferOverflow` detection.
    pub overflow_warn_len: usize,
    /// Byte length critical threshold for `BufferOverflow` detection.
    pub overflow_crit_len: usize,
    /// Inspect SSH client identification banners (`SSH-2.0-...`) with `sigil-filter`.
    pub inspect_ssh_banners: bool,
    /// Inspect unencrypted `SSH_MSG_KEXINIT` algorithm name-lists and `SSH_MSG_DEBUG` strings with `sigil-filter`.
    pub inspect_kex_packets: bool,
}

impl Default for SigilFilterConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_confidence: 0.55,
            overflow_warn_len: 2048,
            overflow_crit_len: 8192,
            inspect_ssh_banners: true,
            inspect_kex_packets: true,
        }
    }
}

/// Configurable defense action for each threat category (`bruteforce_action`, `cve_exploit_action`, `scanner_action`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseAction {
    /// Immediately close the offending connection without banning subsequent connections.
    Drop,
    /// Built-in Fail2Ban: ban the IP in memory for `quarantine_secs` (0-CPU immediate drop on reconnect)
    /// and emit a `MIRAGE_BAN` event (plus optional `ban_log_file` for host Fail2Ban/nftables sync).
    #[serde(alias = "ban")]
    Fail2ban,
    /// Trap the offending connection in an Endlessh-style slow pre-banner drip tarpit.
    EndlesshTarpit,
    /// Seamlessly divert the offending connection into Mirage's pure-Rust SSH-2 honeypot
    /// (automatically degrades to `Drop` if anti-CC honeypot caps are reached).
    SshHoneypot,
}

impl Default for ResponseAction {
    fn default() -> Self {
        Self::SshHoneypot
    }
}

/// Frontline SSH Reverse Proxy, Pre-Auth OpenSSH CVE Shield & Anti-CC Honeypot configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SshProxyConfig {
    /// Public bind address for the Mirage SSH frontline proxy (e.g. `0.0.0.0:22`).
    pub bind_addr: SocketAddr,
    /// Real upstream OpenSSH daemon address (e.g. `127.0.0.1:22022`).
    pub upstream_sshd_addr: SocketAddr,
    /// Trusted client IPs spliced directly to `upstream_sshd_addr` without pre-auth inspection or rate limits.
    pub trusted_client_ips: Vec<String>,
    /// Client SSH identification string substrings immediately classified as automated scanners/exploits.
    pub scanner_ssh_banners: Vec<String>,

    // ---- Per-Category Configurable Response Policies ----
    /// Action for brute-force / high-rate short-session bursts (`fail2ban` | `ssh_honeypot` | `endlessh_tarpit` | `drop`).
    pub bruteforce_action: ResponseAction,
    /// Action for pre-auth CVE probes, Strict-KEX violations, malformed packets & `sigil-filter` hits
    /// (`ssh_honeypot` | `fail2ban` | `endlessh_tarpit` | `drop`).
    pub cve_exploit_action: ResponseAction,
    /// Action for automated scanner banners (`endlessh_tarpit` | `ssh_honeypot` | `fail2ban` | `drop`).
    pub scanner_action: ResponseAction,
    /// Optional path to append `MIRAGE_BAN` lines for external Fail2Ban / nftables / iptables integration.
    pub ban_log_file: Option<String>,
    /// Optional path to append structured JSONL attacker session recordings & behavioral fingerprints.
    pub honeypot_log_file: Option<String>,

    // ---- Pre-Auth OpenSSH CVE Shield ----
    /// Maximum seconds allowed for banner + KEX (`SSH_MSG_NEWKEYS`) completion (mitigates CVE-2024-6387 regreSSHion).
    pub preauth_timeout_secs: u64,
    /// Maximum RFC 4253 SSH identification banner length in bytes (standard is 255).
    pub max_banner_bytes: usize,
    /// Maximum unencrypted pre-`NEWKEYS` SSH packet length in bytes (RFC 4253 §6.1 = 35000).
    pub max_preauth_packet_bytes: usize,
    /// Maximum number of client packets allowed before `SSH_MSG_NEWKEYS` completes (blocks CVE-2025-26466 floods).
    pub max_preauth_packets: usize,
    /// Maximum byte length allowed for any single `SSH_MSG_KEXINIT` algorithm name-list.
    pub max_kex_namelist_bytes: usize,
    /// Enforce Strict-KEX pre-auth sequencing: first packet must be `KEXINIT`, and blocks `SSH2_MSG_PING` (192),
    /// `IGNORE` (2), `DEBUG` (4), `UNIMPLEMENTED` (3) before `NEWKEYS` (blocks Terrapin CVE-2023-48795 & CVE-2025-26466).
    pub strict_kex_enforcement: bool,

    // ---- Anti-CC / DoS & Brute-Force Anomaly Detection ----
    /// Global maximum concurrent TCP connections accepted by Mirage (excess dropped at 0 CPU).
    pub max_total_connections: usize,
    /// Global maximum concurrent pre-auth handshakes (like OpenSSH `MaxStartups`).
    pub max_preauth_connections: usize,
    /// Maximum concurrent TCP connections allowed per source IP.
    pub max_connections_per_ip: u16,
    /// Global maximum concurrent SSH-2 honeypot sessions (protects KEX CPU under CC flood).
    pub max_honeypot_sessions: usize,
    /// Maximum concurrent SSH-2 honeypot sessions per source IP.
    pub max_honeypot_per_ip: u16,
    /// Sliding window duration in seconds for brute-force & connection-burst detection.
    pub rate_window_secs: u64,
    /// Maximum new connections per IP within `rate_window_secs` before triggering `bruteforce_action`.
    pub max_conns_per_ip_window: u16,
    /// Upstream session duration below this threshold (seconds) counts as a short/failed-auth probe.
    pub bruteforce_short_session_secs: u64,
    /// Number of short sessions within `rate_window_secs` before triggering `bruteforce_action`.
    pub bruteforce_short_sessions_threshold: u16,
    /// Ban / quarantine duration in seconds for flagged brute-force, scanner, or CVE attacker IPs.
    pub quarantine_secs: u64,

    // ---- Honeypot / Tarpit Tuning ----
    /// Interval in milliseconds between Endlessh pre-banner tarpit drip lines.
    pub endlessh_drip_interval_ms: u64,
    /// Inside the SSH-2 honeypot, accept password on the N-th attempt (0 = never accept, disconnect at MaxAuthTries).
    pub accept_password_on_attempt: u32,
    /// Artificial delay in milliseconds before rejecting a password attempt inside the honeypot.
    pub auth_fail_delay_ms: u64,
    /// Idle read timeout in seconds inside an active honeypot session (prevents slowloris slot exhaustion).
    pub honeypot_idle_timeout_secs: u64,
    /// Hard maximum lifetime in seconds for a single honeypot session.
    pub honeypot_max_duration_secs: u64,
}

impl Default for SshProxyConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:2222".parse().unwrap(),
            upstream_sshd_addr: "127.0.0.1:22022".parse().unwrap(),
            trusted_client_ips: Vec::new(),
            scanner_ssh_banners: vec![
                "masscan".to_string(),
                "zgrab".to_string(),
                "libssh2".to_string(),
                "paramiko".to_string(),
                "go-ssh".to_string(),
                "SSH-2.0-Go".to_string(),
                "asyncssh".to_string(),
                "JSCH".to_string(),
                "PuTTY_Release_0.64".to_string(),
            ],
            bruteforce_action: ResponseAction::Fail2ban,
            cve_exploit_action: ResponseAction::SshHoneypot,
            scanner_action: ResponseAction::EndlesshTarpit,
            ban_log_file: None,
            honeypot_log_file: None,
            preauth_timeout_secs: 15,
            max_banner_bytes: 255,
            max_preauth_packet_bytes: 35000,
            max_preauth_packets: 8,
            max_kex_namelist_bytes: 4096,
            strict_kex_enforcement: true,
            max_total_connections: 4096,
            max_preauth_connections: 256,
            max_connections_per_ip: 16,
            max_honeypot_sessions: 256,
            max_honeypot_per_ip: 4,
            rate_window_secs: 60,
            max_conns_per_ip_window: 12,
            bruteforce_short_session_secs: 8,
            bruteforce_short_sessions_threshold: 5,
            quarantine_secs: 600,
            endlessh_drip_interval_ms: 4000,
            accept_password_on_attempt: 3,
            auth_fail_delay_ms: 1200,
            honeypot_idle_timeout_secs: 60,
            honeypot_max_duration_secs: 300,
        }
    }
}
