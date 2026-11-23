use crate::config::SshProxyConfig;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const IP_SHARDS: usize = 16;
const IP_SLOTS_PER_SHARD: usize = 1024; // 16,384 fixed slots total (~1.2 MB constant RAM, OOM-proof)

const SUBNET_SHARDS: usize = 8;
const SUBNET_SLOTS_PER_SHARD: usize = 512; // 4,096 fixed /24 or /64 subnet slots

/// Threat category attached to a quarantined IP/subnet so Mirage applies the matching configured `ResponseAction`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatCategory {
    BruteForce,
    CveExploit,
    Scanner,
}

impl ThreatCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::BruteForce => "bruteforce",
            Self::CveExploit => "cve_exploit",
            Self::Scanner => "scanner",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardVerdict {
    /// Immediate transparent splice to upstream sshd without inspection.
    TrustedDirect,
    /// Global or per-IP CC/DoS concurrency watermark exceeded -> drop immediately at 0 CPU.
    DropOverloaded(&'static str),
    /// IP or subnet is quarantined -> execute the configured `ResponseAction` for `category`.
    Quarantined {
        category: ThreatCategory,
        reason: &'static str,
    },
    /// Normal traffic -> run zero-touch pre-auth CVE inspection and relay to upstream sshd.
    InspectAndProxy,
}

#[derive(Debug, Clone, Copy)]
struct IpSlot {
    occupied: bool,
    ip: IpAddr,
    window_start_sec: u64,
    conn_count: u16,
    short_session_count: u16,
    active_conns: u16,
    active_honeypot: u16,
    quarantine_until_sec: u64,
    quarantine_category: ThreatCategory,
    last_seen_sec: u64,
}

impl Default for IpSlot {
    fn default() -> Self {
        Self {
            occupied: false,
            ip: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            window_start_sec: 0,
            conn_count: 0,
            short_session_count: 0,
            active_conns: 0,
            active_honeypot: 0,
            quarantine_until_sec: 0,
            quarantine_category: ThreatCategory::BruteForce,
            last_seen_sec: 0,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct SubnetSlot {
    occupied: bool,
    subnet_key: [u8; 8],
    window_start_sec: u64,
    conn_count: u16,
    short_session_count: u16,
    quarantine_until_sec: u64,
    quarantine_category: ThreatCategory,
    last_seen_sec: u64,
}

impl Default for SubnetSlot {
    fn default() -> Self {
        Self {
            occupied: false,
            subnet_key: [0u8; 8],
            window_start_sec: 0,
            conn_count: 0,
            short_session_count: 0,
            quarantine_until_sec: 0,
            quarantine_category: ThreatCategory::BruteForce,
            last_seen_sec: 0,
        }
    }
}

/// Fixed-capacity, zero-allocation-per-connection sharded IP & subnet anomaly / CC-DoS guard.
/// Uses direct-mapped bounded slots so even a 100k-IP spoofed DDoS flood cannot grow heap memory.
pub struct IpGuardTable {
    ip_shards: Vec<Mutex<Vec<IpSlot>>>,
    subnet_shards: Vec<Mutex<Vec<SubnetSlot>>>,
    active_total: AtomicUsize,
    active_preauth: AtomicUsize,
    active_honeypot: AtomicUsize,
}

impl IpGuardTable {
    pub fn new() -> Self {
        let mut ip_shards = Vec::with_capacity(IP_SHARDS);
        for _ in 0..IP_SHARDS {
            ip_shards.push(Mutex::new(vec![IpSlot::default(); IP_SLOTS_PER_SHARD]));
        }
        let mut subnet_shards = Vec::with_capacity(SUBNET_SHARDS);
        for _ in 0..SUBNET_SHARDS {
            subnet_shards.push(Mutex::new(vec![SubnetSlot::default(); SUBNET_SLOTS_PER_SHARD]));
        }
        Self {
            ip_shards,
            subnet_shards,
            active_total: AtomicUsize::new(0),
            active_preauth: AtomicUsize::new(0),
            active_honeypot: AtomicUsize::new(0),
        }
    }

    pub fn active_total_connections(&self) -> usize {
        self.active_total.load(Ordering::Relaxed)
    }

    pub fn active_preauth_connections(&self) -> usize {
        self.active_preauth.load(Ordering::Relaxed)
    }

    pub fn active_honeypot_sessions(&self) -> usize {
        self.active_honeypot.load(Ordering::Relaxed)
    }

    /// Evaluate incoming connection at TCP accept time (O(1), zero heap allocation).
    pub fn on_connect(&self, ip: IpAddr, cfg: &SshProxyConfig) -> GuardVerdict {
        let ip_str = ip.to_string();
        if cfg.trusted_client_ips.iter().any(|t| t == &ip_str) {
            return GuardVerdict::TrustedDirect;
        }

        if !try_inc_bounded(&self.active_total, cfg.max_total_connections.max(1)) {
            return GuardVerdict::DropOverloaded("global_max_total_connections");
        }

        let now = now_unix_secs();
        let window = cfg.rate_window_secs.max(5);

        let subnet_quarantined = self.touch_subnet(ip, now, window, cfg);

        let (shard_idx, slot_idx) = ip_indices(ip);
        let mut shard = self.ip_shards[shard_idx].lock().unwrap();
        let slot = &mut shard[slot_idx];

        if !slot.occupied || slot.ip != ip {
            *slot = IpSlot {
                occupied: true,
                ip,
                window_start_sec: now,
                conn_count: 0,
                short_session_count: 0,
                active_conns: 0,
                active_honeypot: 0,
                quarantine_until_sec: 0,
                quarantine_category: ThreatCategory::BruteForce,
                last_seen_sec: now,
            };
        }

        if now.saturating_sub(slot.window_start_sec) >= window {
            slot.window_start_sec = now;
            slot.conn_count = 0;
            slot.short_session_count = 0;
        }
        slot.last_seen_sec = now;

        if slot.active_conns >= cfg.max_connections_per_ip.max(1) {
            self.active_total.fetch_sub(1, Ordering::Relaxed);
            return GuardVerdict::DropOverloaded("per_ip_max_connections");
        }

        slot.active_conns = slot.active_conns.saturating_add(1);
        slot.conn_count = slot.conn_count.saturating_add(1);

        if cfg.max_conns_per_ip_window > 0 && slot.conn_count > cfg.max_conns_per_ip_window {
            let until = now.saturating_add(cfg.quarantine_secs);
            if now >= slot.quarantine_until_sec {
                slot.quarantine_until_sec = until;
                slot.quarantine_category = ThreatCategory::BruteForce;
            } else if until > slot.quarantine_until_sec {
                slot.quarantine_until_sec = until;
            }
        }

        if now < slot.quarantine_until_sec {
            return GuardVerdict::Quarantined {
                category: slot.quarantine_category,
                reason: "ip_quarantined",
            };
        }
        if let Some(sub_cat) = subnet_quarantined {
            return GuardVerdict::Quarantined {
                category: sub_cat,
                reason: "subnet_quarantined",
            };
        }

        GuardVerdict::InspectAndProxy
    }

    pub fn on_disconnect(&self, ip: IpAddr) {
        self.active_total.fetch_sub(1, Ordering::Relaxed);
        let (shard_idx, slot_idx) = ip_indices(ip);
        let mut shard = self.ip_shards[shard_idx].lock().unwrap();
        let slot = &mut shard[slot_idx];
        if slot.occupied && slot.ip == ip {
            slot.active_conns = slot.active_conns.saturating_sub(1);
        }
    }

    pub fn try_acquire_preauth(&self, max_preauth: usize) -> bool {
        try_inc_bounded(&self.active_preauth, max_preauth.max(1))
    }

    pub fn release_preauth(&self) {
        self.active_preauth.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn try_acquire_honeypot(&self, ip: IpAddr, cfg: &SshProxyConfig) -> bool {
        if !try_inc_bounded(&self.active_honeypot, cfg.max_honeypot_sessions.max(1)) {
            return false;
        }
        let (shard_idx, slot_idx) = ip_indices(ip);
        let mut shard = self.ip_shards[shard_idx].lock().unwrap();
        let slot = &mut shard[slot_idx];
        if slot.occupied && slot.ip == ip {
            if slot.active_honeypot >= cfg.max_honeypot_per_ip.max(1) {
                self.active_honeypot.fetch_sub(1, Ordering::Relaxed);
                return false;
            }
            slot.active_honeypot = slot.active_honeypot.saturating_add(1);
        }
        true
    }

    pub fn release_honeypot(&self, ip: IpAddr) {
        self.active_honeypot.fetch_sub(1, Ordering::Relaxed);
        let (shard_idx, slot_idx) = ip_indices(ip);
        let mut shard = self.ip_shards[shard_idx].lock().unwrap();
        let slot = &mut shard[slot_idx];
        if slot.occupied && slot.ip == ip {
            slot.active_honeypot = slot.active_honeypot.saturating_sub(1);
        }
    }

    /// Quarantine an IP under `category` for `quarantine_secs`.
    pub fn flag_hostile(&self, ip: IpAddr, category: ThreatCategory, quarantine_secs: u64) {
        let now = now_unix_secs();
        let until = now.saturating_add(quarantine_secs.max(30));
        let (shard_idx, slot_idx) = ip_indices(ip);
        let mut shard = self.ip_shards[shard_idx].lock().unwrap();
        let slot = &mut shard[slot_idx];
        if !slot.occupied || slot.ip != ip {
            *slot = IpSlot {
                occupied: true,
                ip,
                window_start_sec: now,
                conn_count: 1,
                short_session_count: 0,
                active_conns: 0,
                active_honeypot: 0,
                quarantine_until_sec: until,
                quarantine_category: category,
                last_seen_sec: now,
            };
        } else {
            slot.quarantine_until_sec = slot.quarantine_until_sec.max(until);
            slot.quarantine_category = category;
            slot.last_seen_sec = now;
        }
    }

    /// Record a short-lived upstream session (typical signature of password brute-force or race retries).
    /// Returns `true` if this event newly pushed the IP (or its subnet) into `BruteForce` quarantine.
    pub fn record_short_session(&self, ip: IpAddr, cfg: &SshProxyConfig) -> bool {
        let now = now_unix_secs();
        let window = cfg.rate_window_secs.max(5);
        let threshold = cfg.bruteforce_short_sessions_threshold;
        if threshold == 0 {
            return false;
        }

        let mut newly_quarantined = false;
        {
            let (shard_idx, slot_idx) = ip_indices(ip);
            let mut shard = self.ip_shards[shard_idx].lock().unwrap();
            let slot = &mut shard[slot_idx];
            if slot.occupied && slot.ip == ip {
                if now.saturating_sub(slot.window_start_sec) >= window {
                    slot.window_start_sec = now;
                    slot.conn_count = 0;
                    slot.short_session_count = 0;
                }
                slot.short_session_count = slot.short_session_count.saturating_add(1);
                if slot.short_session_count >= threshold {
                    let was_q = now < slot.quarantine_until_sec;
                    slot.quarantine_until_sec =
                        slot.quarantine_until_sec.max(now.saturating_add(cfg.quarantine_secs));
                    slot.quarantine_category = ThreatCategory::BruteForce;
                    if !was_q {
                        newly_quarantined = true;
                    }
                }
            }
        }

        let subnet_key = normalize_subnet_key(ip);
        let (s_shard, s_slot) = subnet_indices(subnet_key);
        let mut sub_guard = self.subnet_shards[s_shard].lock().unwrap();
        let sub = &mut sub_guard[s_slot];
        if sub.occupied && sub.subnet_key == subnet_key {
            if now.saturating_sub(sub.window_start_sec) >= window {
                sub.window_start_sec = now;
                sub.conn_count = 0;
                sub.short_session_count = 0;
            }
            sub.short_session_count = sub.short_session_count.saturating_add(1);
            let sub_thresh = threshold.saturating_mul(3);
            if sub.short_session_count >= sub_thresh {
                let was_q = now < sub.quarantine_until_sec;
                sub.quarantine_until_sec =
                    sub.quarantine_until_sec.max(now.saturating_add(cfg.quarantine_secs));
                sub.quarantine_category = ThreatCategory::BruteForce;
                if !was_q {
                    newly_quarantined = true;
                }
            }
        }

        newly_quarantined
    }

    fn touch_subnet(
        &self,
        ip: IpAddr,
        now: u64,
        window: u64,
        cfg: &SshProxyConfig,
    ) -> Option<ThreatCategory> {
        let subnet_key = normalize_subnet_key(ip);
        let (s_shard, s_slot) = subnet_indices(subnet_key);
        let mut sub_guard = self.subnet_shards[s_shard].lock().unwrap();
        let sub = &mut sub_guard[s_slot];

        if !sub.occupied || sub.subnet_key != subnet_key {
            *sub = SubnetSlot {
                occupied: true,
                subnet_key,
                window_start_sec: now,
                conn_count: 1,
                short_session_count: 0,
                quarantine_until_sec: 0,
                quarantine_category: ThreatCategory::BruteForce,
                last_seen_sec: now,
            };
            return None;
        }

        if now.saturating_sub(sub.window_start_sec) >= window {
            sub.window_start_sec = now;
            sub.conn_count = 0;
            sub.short_session_count = 0;
        }
        sub.last_seen_sec = now;
        sub.conn_count = sub.conn_count.saturating_add(1);

        let sub_conn_cap = cfg.max_conns_per_ip_window.saturating_mul(4);
        if sub_conn_cap > 0 && sub.conn_count > sub_conn_cap {
            sub.quarantine_until_sec =
                sub.quarantine_until_sec.max(now.saturating_add(cfg.quarantine_secs));
            sub.quarantine_category = ThreatCategory::BruteForce;
        }

        if now < sub.quarantine_until_sec {
            Some(sub.quarantine_category)
        } else {
            None
        }
    }
}

impl Default for IpGuardTable {
    fn default() -> Self {
        Self::new()
    }
}

fn try_inc_bounded(counter: &AtomicUsize, max: usize) -> bool {
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        if current >= max {
            return false;
        }
        match counter.compare_exchange_weak(
            current,
            current + 1,
            Ordering::SeqCst,
            Ordering::Relaxed,
        ) {
            Ok(_) => return true,
            Err(actual) => current = actual,
        }
    }
}

fn ip_indices(ip: IpAddr) -> (usize, usize) {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    ip.hash(&mut hasher);
    let h = hasher.finish() as usize;
    let shard = h % IP_SHARDS;
    let slot = (h / IP_SHARDS) % IP_SLOTS_PER_SHARD;
    (shard, slot)
}

fn subnet_indices(subnet_key: [u8; 8]) -> (usize, usize) {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    subnet_key.hash(&mut hasher);
    let h = hasher.finish() as usize;
    let shard = h % SUBNET_SHARDS;
    let slot = (h / SUBNET_SHARDS) % SUBNET_SLOTS_PER_SHARD;
    (shard, slot)
}

fn normalize_subnet_key(ip: IpAddr) -> [u8; 8] {
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

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
