use crate::config::MirageConfig;
use crate::persona::{PersonaSnapshot, PrebakedPersona};
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::task::JoinHandle;
use tracing::{info, warn};

/// Structured threat telemetry event recorded whenever a trap is triggered.
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

/// Live atomic metrics for the MiragePot engine.
#[derive(Debug, Default)]
pub struct MirageMetrics {
    pub current_epoch: AtomicU64,
    pub rotations_completed: AtomicU64,
    pub http_requests_inspected: AtomicU64,
    pub http_traps_triggered: AtomicU64,
    pub sigil_detections: AtomicU64,
    pub tarpit_bytes_dripped: AtomicU64,
    pub active_tarpit_connections: AtomicUsize,
    pub ssh_connections_total: AtomicU64,
    pub ssh_auth_attempts: AtomicU64,
    pub ssh_fake_shell_logins: AtomicU64,
    pub ssh_commands_executed: AtomicU64,
    pub malware_indicators_captured: AtomicU64,
}

#[derive(Debug, Clone, Serialize)]
pub struct MirageMetricsSnapshot {
    pub current_epoch: u64,
    pub rotations_completed: u64,
    pub http_requests_inspected: u64,
    pub http_traps_triggered: u64,
    pub sigil_detections: u64,
    pub tarpit_bytes_dripped: u64,
    pub active_tarpit_connections: usize,
    pub ssh_connections_total: u64,
    pub ssh_auth_attempts: u64,
    pub ssh_fake_shell_logins: u64,
    pub ssh_commands_executed: u64,
    pub malware_indicators_captured: u64,
}

/// RAII permit guarding a concurrent tarpit / slow-drip connection.
/// Automatically decrements `active_tarpit_connections` when dropped.
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshAuthDecision {
    /// Reject this password attempt after `delay_ms` to waste brute-forcer time.
    RejectAfterDelay { attempt: u32, delay_ms: u64 },
    /// Pretend the attacker guessed the password on the N-th attempt and drop them into the Fake Shell.
    AcceptIntoFakeShell { attempt: u32 },
}

/// Core thread-safe engine managing pre-baked persona snapshots, rotation, tarpit watermarks,
/// and threat telemetry. Can be shared across HTTP middleware and SSH/DB servers via `Arc<MirageEngine>`.
pub struct MirageEngine {
    config: MirageConfig,
    resolved_admin_prefix: String,
    sigil: sigil_filter::Sigil,
    snapshot: RwLock<Arc<PersonaSnapshot>>,
    epoch_counter: AtomicU64,
    pub metrics: MirageMetrics,
    ssh_attempts_by_ip: Mutex<HashMap<IpAddr, u32>>,
    recent_events: Mutex<VecDeque<ThreatEvent>>,
}

impl MirageEngine {
    /// Initialize the engine and synchronously pre-bake Epoch 1.
    pub fn new(config: MirageConfig) -> Arc<Self> {
        let initial_epoch = 1;
        let resolved_admin_prefix = config.admin.resolved_prefix();
        let sigil = sigil_filter::Sigil::new()
            .with_min_confidence(config.sigil.min_confidence)
            .with_buffer_limits(config.sigil.overflow_warn_len, config.sigil.overflow_crit_len);
        let snapshot = PersonaSnapshot::bake(
            config.master_seed,
            initial_epoch,
            config.persona_slots,
            &config.canary_webhook_url,
        );
        let metrics = MirageMetrics::default();
        metrics.current_epoch.store(initial_epoch, Ordering::Relaxed);

        Arc::new(Self {
            config,
            resolved_admin_prefix,
            sigil,
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

    /// Access the pre-configured zero-allocation `sigil-filter` heuristic attack recognizer.
    pub fn sigil(&self) -> &sigil_filter::Sigil {
        &self.sigil
    }

    /// Return the resolved secret URL prefix for the admin status & rotation panel
    /// (e.g. `/_m_9f4b2c8e1a7d3065b8e2f1c4a9d0731e` or the custom path from `config.toml`).
    pub fn admin_path_prefix(&self) -> &str {
        &self.resolved_admin_prefix
    }

    /// Obtain the currently active `PersonaSnapshot` in O(1) time.
    pub fn current_snapshot(&self) -> Arc<PersonaSnapshot> {
        self.snapshot
            .read()
            .expect("MirageEngine snapshot lock poisoned")
            .clone()
    }

    /// Deterministically select a pre-baked `PrebakedPersona` for `client_ip` in the current rotation epoch.
    pub fn select_persona(&self, client_ip: IpAddr) -> Arc<PrebakedPersona> {
        let snap = self.current_snapshot();
        let subnet_key = normalize_ip_subnet(client_ip);
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        snap.epoch_id.hash(&mut hasher);
        subnet_key.hash(&mut hasher);
        let idx = (hasher.finish() as usize) % snap.personas.len();
        snap.personas[idx].clone()
    }

    /// Pre-bake the next epoch's `PersonaSnapshot` off-lock and atomically swap it in.
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
            sample_host = %new_snapshot.personas[0].hostname,
            sample_ssh_banner = %new_snapshot.personas[0].ssh_banner,
            "Rotated MiragePot pre-generated persona snapshot"
        );

        new_snapshot
    }

    /// Spawn a background Tokio task that automatically rotates pre-generated payloads on schedule.
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

    /// Attempt to acquire a bounded tarpit connection slot.
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

    /// Evaluate an SSH password authentication attempt and decide whether to delay+reject
    /// or let the attacker into the zero-overhead Fake Shell on the N-th attempt
    /// (or immediately if they used the persona's leaked DB/Redis password!).
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
            if guard.len() >= 8192 && !guard.contains_key(&client_ip) {
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
            self.metrics
                .ssh_fake_shell_logins
                .fetch_add(1, Ordering::Relaxed);
            self.record_event(
                client_ip,
                &persona,
                "SSH",
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
                "SSH",
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

    /// Record a structured threat telemetry event and keep the latest 256 events in memory.
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
            "MiragePot deception trap triggered"
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
            http_requests_inspected: self.metrics.http_requests_inspected.load(Ordering::Relaxed),
            http_traps_triggered: self.metrics.http_traps_triggered.load(Ordering::Relaxed),
            sigil_detections: self.metrics.sigil_detections.load(Ordering::Relaxed),
            tarpit_bytes_dripped: self.metrics.tarpit_bytes_dripped.load(Ordering::Relaxed),
            active_tarpit_connections: self
                .metrics
                .active_tarpit_connections
                .load(Ordering::Relaxed),
            ssh_connections_total: self.metrics.ssh_connections_total.load(Ordering::Relaxed),
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
