use crate::config::{MirageConfig, ResponseAction};
use crate::guard::{GuardVerdict, IpGuardTable, ThreatCategory};
use crate::persona::{PersonaSnapshot, PrebakedPersona};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::fs::OpenOptions;
use std::hash::{Hash, Hasher};
use std::io::Write;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::task::JoinHandle;
use tracing::{info, warn};

/// Structured threat telemetry event recorded whenever Mirage intercepts a suspicious SSH packet,
/// brute-force burst, Fail2Ban ban, or honeypot interaction.
#[derive(Debug, Clone, Serialize)]
pub struct ThreatEvent {
    pub timestamp_unix: u64,
    pub epoch_id: u64,
    pub persona_hostname: String,
    pub client_ip: String,
    pub protocol: &'static str,
    pub trap_kind: String,
    pub detail: String,
}

/// Live atomic metrics for the Mirage SSH frontline proxy, pre-auth CVE shield & anti-CC guard.
#[derive(Debug, Default)]
pub struct MirageMetrics {
    pub current_epoch: AtomicU64,
    pub rotations_completed: AtomicU64,
    pub sigil_detections: AtomicU64,
    pub tarpit_bytes_dripped: AtomicU64,
    pub active_tarpit_connections: AtomicUsize,
    pub ssh_connections_total: AtomicU64,
    pub ssh_proxied_to_upstream: AtomicU64,
    pub ssh_blocked_preauth: AtomicU64,
    pub ssh_dropped_cc_dos: AtomicU64,
    pub ssh_banned_fail2ban: AtomicU64,
    pub ssh_diverted_honeypot: AtomicU64,
    pub ssh_bruteforce_quarantined: AtomicU64,
    pub ssh_auth_attempts: AtomicU64,
    pub ssh_fake_shell_logins: AtomicU64,
    pub ssh_commands_executed: AtomicU64,
    pub malware_indicators_captured: AtomicU64,
}

#[derive(Debug, Clone, Serialize)]
pub struct MirageMetricsSnapshot {
    pub current_epoch: u64,
    pub rotations_completed: u64,
    pub sigil_detections: u64,
    pub tarpit_bytes_dripped: u64,
    pub active_tarpit_connections: usize,
    pub active_total_connections: usize,
    pub active_preauth_connections: usize,
    pub active_honeypot_sessions: usize,
    pub ssh_connections_total: u64,
    pub ssh_proxied_to_upstream: u64,
    pub ssh_blocked_preauth: u64,
    pub ssh_dropped_cc_dos: u64,
    pub ssh_banned_fail2ban: u64,
    pub ssh_diverted_honeypot: u64,
    pub ssh_bruteforce_quarantined: u64,
    pub ssh_auth_attempts: u64,
    pub ssh_fake_shell_logins: u64,
    pub ssh_commands_executed: u64,
    pub malware_indicators_captured: u64,
}

/// RAII permit guarding a concurrent tarpit / slow-drip connection.
pub struct TarpitPermit {
    engine: Arc<MirageEngine>,
}

impl Drop for TarpitPermit {
    fn drop(&mut self) {
        self.engine
            .metrics
            .active_tarpit_connections
            .fetch_sub(1, Ordering::Relaxed);
    }
}

/// RAII permit guarding global & per-IP active TCP connection watermarks.
pub struct ConnPermit {
    engine: Arc<MirageEngine>,
    ip: IpAddr,
}

impl Drop for ConnPermit {
    fn drop(&mut self) {
        self.engine.guard.on_disconnect(self.ip);
    }
}

/// RAII permit guarding concurrent pre-auth handshake slots (`max_preauth_connections`).
pub struct PreAuthPermit {
    engine: Arc<MirageEngine>,
}

impl Drop for PreAuthPermit {
    fn drop(&mut self) {
        self.engine.guard.release_preauth();
    }
}

/// RAII permit guarding global & per-IP active SSH-2 honeypot slots (KEX CPU protection).
pub struct HoneypotPermit {
    engine: Arc<MirageEngine>,
    ip: IpAddr,
}

impl Drop for HoneypotPermit {
    fn drop(&mut self) {
        self.engine.guard.release_honeypot(self.ip);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshAuthDecision {
    RejectAfterDelay { attempt: u32, delay_ms: u64 },
    AcceptIntoFakeShell { attempt: u32 },
}

/// Core thread-safe engine managing `sigil-filter` inspection, fixed-cap anti-CC/brute-force guard,
/// per-category response policies (Fail2Ban / SSH Honeypot / Endlessh / Drop), upstream banner cache,
/// stable honeypot host key, pre-baked personas, and telemetry.
pub struct MirageEngine {
    config: MirageConfig,
    sigil: sigil_filter::Sigil,
    guard: IpGuardTable,
    upstream_banner_cache: RwLock<Option<String>>,
    honeypot_host_key_seed: [u8; 32],
    snapshot: RwLock<Arc<PersonaSnapshot>>,
    epoch_counter: AtomicU64,
    pub metrics: MirageMetrics,
    ssh_attempts_by_ip: Mutex<HashMap<IpAddr, u32>>,
    recent_events: Mutex<VecDeque<ThreatEvent>>,
}

impl MirageEngine {
    pub fn new(config: MirageConfig) -> Arc<Self> {
        let initial_epoch = 1;
        let sigil = sigil_filter::Sigil::new()
            .with_min_confidence(config.sigil.min_confidence)
            .with_buffer_limits(config.sigil.overflow_warn_len, config.sigil.overflow_crit_len);
        let snapshot = PersonaSnapshot::bake(
            config.master_seed,
            initial_epoch,
            config.persona_slots,
            &config.canary_webhook_url,
        );

        let mut key_hasher = Sha256::new();
        key_hasher.update(b"mirage-stable-ssh-ed25519-hostkey-v1:");
        key_hasher.update(config.master_seed.to_le_bytes());
        let honeypot_host_key_seed: [u8; 32] = key_hasher.finalize().into();

        let metrics = MirageMetrics::default();
        metrics.current_epoch.store(initial_epoch, Ordering::Relaxed);

        Arc::new(Self {
            config,
            sigil,
            guard: IpGuardTable::new(),
            upstream_banner_cache: RwLock::new(None),
            honeypot_host_key_seed,
            snapshot: RwLock::new(Arc::new(snapshot)),
            epoch_counter: AtomicU64::new(initial_epoch),
            metrics,
            ssh_attempts_by_ip: Mutex::new(HashMap::new()),
            recent_events: Mutex::new(VecDeque::with_capacity(256)),
        })
    }

    pub fn config(&self) -> &MirageConfig {
        &self.config
    }

    pub fn sigil(&self) -> &sigil_filter::Sigil {
        &self.sigil
    }

    pub fn honeypot_host_key_seed(&self) -> [u8; 32] {
        self.honeypot_host_key_seed
    }

    /// Resolve the configured `ResponseAction` for a given `ThreatCategory`.
    pub fn action_for(&self, category: ThreatCategory) -> ResponseAction {
        match category {
            ThreatCategory::BruteForce => self.config.ssh.bruteforce_action,
            ThreatCategory::CveExploit => self.config.ssh.cve_exploit_action,
            ThreatCategory::Scanner => self.config.ssh.scanner_action,
        }
    }

    pub fn cached_upstream_banner(&self) -> Option<String> {
        self.upstream_banner_cache
            .read()
            .ok()
            .and_then(|g| g.clone())
    }

    pub fn set_upstream_banner(&self, banner: String) {
        if banner.starts_with("SSH-2.0-") || banner.starts_with("SSH-1.99-") {
            if let Ok(mut guard) = self.upstream_banner_cache.write() {
                if guard.as_deref() != Some(banner.as_str()) {
                    *guard = Some(banner);
                }
            }
        }
    }

    pub fn evaluate_incoming_connection(
        self: &Arc<Self>,
        ip: IpAddr,
    ) -> (GuardVerdict, Option<ConnPermit>) {
        let verdict = self.guard.on_connect(ip, &self.config.ssh);
        match verdict {
            GuardVerdict::TrustedDirect | GuardVerdict::DropOverloaded(_) => (verdict, None),
            GuardVerdict::Quarantined { .. } | GuardVerdict::InspectAndProxy => (
                verdict,
                Some(ConnPermit {
                    engine: self.clone(),
                    ip,
                }),
            ),
        }
    }

    pub fn try_acquire_preauth(self: &Arc<Self>) -> Option<PreAuthPermit> {
        if self
            .guard
            .try_acquire_preauth(self.config.ssh.max_preauth_connections)
        {
            Some(PreAuthPermit {
                engine: self.clone(),
            })
        } else {
            None
        }
    }

    pub fn try_acquire_honeypot(self: &Arc<Self>, ip: IpAddr) -> Option<HoneypotPermit> {
        if self.guard.try_acquire_honeypot(ip, &self.config.ssh) {
            Some(HoneypotPermit {
                engine: self.clone(),
                ip,
            })
        } else {
            None
        }
    }

    /// Quarantine an offending IP according to its `ThreatCategory` (skipped for pure `Drop`).
    /// Emits a Fail2Ban-compatible `MIRAGE_BAN` record when the category's policy is `Fail2ban`.
    pub fn flag_hostile_ip(&self, ip: IpAddr, category: ThreatCategory, reason: &str) {
        let action = self.action_for(category);
        if action != ResponseAction::Drop {
            self.guard
                .flag_hostile(ip, category, self.config.ssh.quarantine_secs);
        }
        if action == ResponseAction::Fail2ban {
            self.emit_fail2ban_record(ip, category, reason);
        }
    }

    pub fn record_short_upstream_session(&self, ip: IpAddr) -> bool {
        let newly = self.guard.record_short_session(ip, &self.config.ssh);
        if newly {
            self.metrics
                .ssh_bruteforce_quarantined
                .fetch_add(1, Ordering::Relaxed);
            if self.config.ssh.bruteforce_action == ResponseAction::Fail2ban {
                self.emit_fail2ban_record(
                    ip,
                    ThreatCategory::BruteForce,
                    "short_session_bruteforce_burst",
                );
            }
        }
        newly
    }

    /// Emit a Fail2Ban-parseable `MIRAGE_BAN` line to tracing and optional `ban_log_file`.
    pub fn emit_fail2ban_record(&self, ip: IpAddr, category: ThreatCategory, reason: &str) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let ban_secs = self.config.ssh.quarantine_secs;
        let line = format!(
            "ts={ts} MIRAGE_BAN client_ip={ip} category={} ban_secs={ban_secs} reason={reason}",
            category.as_str()
        );
        warn!("{line}");
        if let Some(ref path) = self.config.ssh.ban_log_file {
            if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
                let _ = writeln!(f, "{line}");
            }
        }
    }

    pub fn current_snapshot(&self) -> Arc<PersonaSnapshot> {
        self.snapshot
            .read()
            .expect("MirageEngine snapshot lock poisoned")
            .clone()
    }

    pub fn select_persona(&self, client_ip: IpAddr) -> Arc<PrebakedPersona> {
        let snap = self.current_snapshot();
        let subnet_key = normalize_ip_subnet(client_ip);
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        snap.epoch_id.hash(&mut hasher);
        subnet_key.hash(&mut hasher);
        let idx = (hasher.finish() as usize) % snap.personas.len();
        snap.personas[idx].clone()
    }

    pub fn rotate_now(&self) -> Arc<PersonaSnapshot> {
        let next_epoch = self.epoch_counter.fetch_add(1, Ordering::SeqCst) + 1;

        let new_snapshot = Arc::new(PersonaSnapshot::bake(
            self.config.master_seed,
            next_epoch,
            self.config.persona_slots,
            &self.config.canary_webhook_url,
        ));

        {
            let mut guard = self
                .snapshot
                .write()
                .expect("MirageEngine snapshot write lock poisoned");
            *guard = new_snapshot.clone();
        }

        if let Ok(mut map) = self.ssh_attempts_by_ip.lock() {
            map.clear();
        }

        self.metrics.current_epoch.store(next_epoch, Ordering::Relaxed);
        self.metrics
            .rotations_completed
            .fetch_add(1, Ordering::Relaxed);

        info!(
            epoch = next_epoch,
            slots = new_snapshot.personas.len(),
            "Rotated Mirage pre-generated SSH honeypot persona snapshot"
        );

        new_snapshot
    }

    pub fn spawn_rotation_task(self: &Arc<Self>) -> JoinHandle<()> {
        let engine = self.clone();
        let interval_secs = engine.config.rotation_interval_secs.max(1);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
            ticker.tick().await;
            loop {
                ticker.tick().await;
                engine.rotate_now();
            }
        })
    }

    pub fn try_acquire_tarpit(self: &Arc<Self>) -> Option<TarpitPermit> {
        let max = self.config.max_tarpit_connections;
        let mut current = self
            .metrics
            .active_tarpit_connections
            .load(Ordering::Relaxed);
        loop {
            if current >= max {
                return None;
            }
            match self.metrics.active_tarpit_connections.compare_exchange_weak(
                current,
                current + 1,
                Ordering::SeqCst,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    return Some(TarpitPermit {
                        engine: self.clone(),
                    });
                }
                Err(actual) => current = actual,
            }
        }
    }

    pub fn evaluate_ssh_password_attempt(
        &self,
        client_ip: IpAddr,
        username: &str,
        password: &str,
    ) -> SshAuthDecision {
        self.metrics
            .ssh_auth_attempts
            .fetch_add(1, Ordering::Relaxed);
        let persona = self.select_persona(client_ip);

        let attempt = {
            let mut guard = self.ssh_attempts_by_ip.lock().unwrap();
            if guard.len() >= 4096 && !guard.contains_key(&client_ip) {
                guard.clear();
            }
            let entry = guard.entry(client_ip).or_insert(0);
            *entry = entry.saturating_add(1);
            *entry
        };

        let matches_leaked_secret = password == persona.postgres_data.db_password
            || password == persona.redis_data.require_pass;
        let threshold = self.config.ssh.accept_password_on_attempt;

        if matches_leaked_secret || (threshold > 0 && attempt >= threshold) {
            if let Ok(mut guard) = self.ssh_attempts_by_ip.lock() {
                guard.remove(&client_ip);
            }
            self.metrics
                .ssh_fake_shell_logins
                .fetch_add(1, Ordering::Relaxed);
            self.record_event(
                client_ip,
                &persona,
                "SSH-HONEYPOT",
                if matches_leaked_secret {
                    "StolenCredentialLoginAccepted"
                } else {
                    "WeakPasswordBaitAccepted"
                },
                format!(
                    "Accepted credentials user='{}' pass='{}' on attempt #{} into fake shell",
                    username, password, attempt
                ),
            );
            SshAuthDecision::AcceptIntoFakeShell { attempt }
        } else {
            self.record_event(
                client_ip,
                &persona,
                "SSH-HONEYPOT",
                "PasswordBruteForceTarpit",
                format!(
                    "Rejected credentials user='{}' pass='{}' (attempt #{}/{})",
                    username, password, attempt, threshold
                ),
            );
            SshAuthDecision::RejectAfterDelay {
                attempt,
                delay_ms: self.config.ssh.auth_fail_delay_ms,
            }
        }
    }

    pub fn record_event(
        &self,
        client_ip: IpAddr,
        persona: &PrebakedPersona,
        protocol: &'static str,
        trap_kind: impl Into<String>,
        detail: impl Into<String>,
    ) {
        let trap_kind = trap_kind.into();
        let detail = detail.into();
        let timestamp_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        warn!(
            protocol,
            epoch = persona.epoch_id,
            persona = %persona.hostname,
            client_ip = %client_ip,
            trap = %trap_kind,
            detail = %detail,
            "Mirage SSH guard event"
        );

        let event = ThreatEvent {
            timestamp_unix,
            epoch_id: persona.epoch_id,
            persona_hostname: persona.hostname.clone(),
            client_ip: client_ip.to_string(),
            protocol,
            trap_kind,
            detail,
        };

        if let Ok(mut queue) = self.recent_events.lock() {
            if queue.len() >= 256 {
                queue.pop_front();
            }
            queue.push_back(event);
        }
    }

    pub fn recent_events(&self) -> Vec<ThreatEvent> {
        self.recent_events
            .lock()
            .map(|q| q.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn metrics_snapshot(&self) -> MirageMetricsSnapshot {
        MirageMetricsSnapshot {
            current_epoch: self.metrics.current_epoch.load(Ordering::Relaxed),
            rotations_completed: self.metrics.rotations_completed.load(Ordering::Relaxed),
            sigil_detections: self.metrics.sigil_detections.load(Ordering::Relaxed),
            tarpit_bytes_dripped: self.metrics.tarpit_bytes_dripped.load(Ordering::Relaxed),
            active_tarpit_connections: self
                .metrics
                .active_tarpit_connections
                .load(Ordering::Relaxed),
            active_total_connections: self.guard.active_total_connections(),
            active_preauth_connections: self.guard.active_preauth_connections(),
            active_honeypot_sessions: self.guard.active_honeypot_sessions(),
            ssh_connections_total: self.metrics.ssh_connections_total.load(Ordering::Relaxed),
            ssh_proxied_to_upstream: self
                .metrics
                .ssh_proxied_to_upstream
                .load(Ordering::Relaxed),
            ssh_blocked_preauth: self.metrics.ssh_blocked_preauth.load(Ordering::Relaxed),
            ssh_dropped_cc_dos: self.metrics.ssh_dropped_cc_dos.load(Ordering::Relaxed),
            ssh_banned_fail2ban: self.metrics.ssh_banned_fail2ban.load(Ordering::Relaxed),
            ssh_diverted_honeypot: self.metrics.ssh_diverted_honeypot.load(Ordering::Relaxed),
            ssh_bruteforce_quarantined: self
                .metrics
                .ssh_bruteforce_quarantined
                .load(Ordering::Relaxed),
            ssh_auth_attempts: self.metrics.ssh_auth_attempts.load(Ordering::Relaxed),
            ssh_fake_shell_logins: self.metrics.ssh_fake_shell_logins.load(Ordering::Relaxed),
            ssh_commands_executed: self.metrics.ssh_commands_executed.load(Ordering::Relaxed),
            malware_indicators_captured: self
                .metrics
                .malware_indicators_captured
                .load(Ordering::Relaxed),
        }
    }
}

fn normalize_ip_subnet(ip: IpAddr) -> [u8; 8] {
    match ip {
        IpAddr::V4(v4) => {
            let oct = v4.octets();
            [oct[0], oct[1], oct[2], 0, 0, 0, 0, 4]
        }
        IpAddr::V6(v6) => {
            let oct = v6.octets();
            [oct[0], oct[1], oct[2], oct[3], oct[4], oct[5], oct[6], oct[7]]
        }
    }
}
