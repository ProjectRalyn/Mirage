pub mod transport;

use mirage_core::{FakeShellSession, MirageEngine, PrebakedPersona, SshDeployMode};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn};

/// Run the standalone SSH honeypot or frontline OpenSSH multiplexer on `engine.config().ssh.bind_addr`.
pub async fn run_standalone_ssh_server(engine: Arc<MirageEngine>) -> io::Result<()> {
    let bind_addr = engine.config().ssh.bind_addr;
    let mode = engine.config().ssh.mode;
    let listener = TcpListener::bind(bind_addr).await?;
    info!(
        %bind_addr,
        ?mode,
        upstream = ?engine.config().ssh.upstream_sshd_addr,
        "MiragePot SSH engine listening"
    );
    serve_ssh_listener(listener, engine).await
}

/// Serve an existing `TcpListener` with the MiragePot SSH engine.
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
/// - In `FrontlineProxy` mode:
///   1. Trusted client IPs are transparently spliced directly to `upstream_sshd_addr`.
///   2. Clients matching `upstream_bypass_banner_substr` (or non-scanners when
///      `proxy_non_scanners_to_upstream = true`) have their client banner replayed and spliced
///      to `upstream_sshd_addr`.
/// - Otherwise:
///   3. Scanner banners optionally enter Endlessh pre-banner tarpit mode.
///   4. All other untrusted connections enter the full encrypted SSH-2 deception engine.
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
    let is_frontline_proxy = cfg.mode == SshDeployMode::FrontlineProxy;

    // 1. Immediate IP-based transparent proxy to real upstream sshd
    if let Some(upstream_addr) = cfg.upstream_sshd_addr {
        let ip_str = client_ip.to_string();
        if cfg.trusted_client_ips.iter().any(|t| t == &ip_str) {
            info!(%client_ip, %upstream_addr, "Frontline SSH proxy: forwarding trusted IP to real sshd");
            return splice_to_upstream_sshd(stream, upstream_addr, None).await;
        }
    }

    let persona = engine.select_persona(client_ip);

    // 2. Peek/read client banner first with a short timeout
    let mut initial_client_banner = None;
    if let Ok(Ok(line)) =
        tokio::time::timeout(Duration::from_millis(250), read_ssh_line(&mut stream)).await
    {
        if !line.is_empty() {
            initial_client_banner = Some(line);
        }
    }

    // 3. Banner-based routing in FrontlineProxy mode + `sigil-filter` & Scanner classification
    if let Some(ref c_banner) = initial_client_banner {
        let c_lower = c_banner.to_ascii_lowercase();
        let mut is_scanner = cfg
            .scanner_ssh_banners
            .iter()
            .any(|sig| c_lower.contains(&sig.to_ascii_lowercase()));

        // Run zero-allocation `sigil-filter` heuristic check on the client SSH banner
        if engine.config().sigil.enabled && engine.config().sigil.inspect_ssh_banners {
            let sigil_res = engine.sigil().detect(c_banner.as_str());
            if let Some(violation) = sigil_res.violation {
                is_scanner = true;
                engine
                    .metrics
                    .sigil_detections
                    .fetch_add(1, Ordering::Relaxed);
                engine.record_event(
                    client_ip,
                    &persona,
                    "SSH",
                    format!("SigilBannerTrap({violation:?})"),
                    format!(
                        "sigil-filter flagged SSH banner '{}' (confidence={:.2})",
                        c_banner, sigil_res.confidence
                    ),
                );
            }
        }

        if is_frontline_proxy && !is_scanner {
            if let Some(upstream_addr) = cfg.upstream_sshd_addr {
                let matches_secret_banner = cfg
                    .upstream_bypass_banner_substr
                    .as_deref()
                    .map(|sub| !sub.is_empty() && c_banner.contains(sub))
                    .unwrap_or(false);

                if matches_secret_banner || cfg.proxy_non_scanners_to_upstream {
                    info!(
                        %client_ip,
                        %upstream_addr,
                        client_banner = %c_banner,
                        "Frontline SSH proxy: forwarding authenticated/non-scanner banner to real sshd"
                    );
                    let replay = format!("{c_banner}\r\n");
                    return splice_to_upstream_sshd(stream, upstream_addr, Some(replay.as_bytes()))
                        .await;
                }
            }
        }

        if is_scanner && cfg.endlessh_tarpit_for_scanners {
            return run_endlessh_tarpit(stream, &engine, &persona, client_ip, c_banner).await;
        }
    }

    // 4. Send the persona's rotating vulnerable SSH Server Banner
    let server_banner = persona.ssh_banner.clone();
    stream
        .write_all(format!("{server_banner}\r\n").as_bytes())
        .await?;
    stream.flush().await?;

    // 5. Read client banner if the client waited for server banner first
    let client_banner = match initial_client_banner {
        Some(b) => b,
        None => {
            tokio::time::timeout(Duration::from_secs(10), read_ssh_line(&mut stream))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SSH banner read timeout"))??
        }
    };

    engine.record_event(
        client_ip,
        &persona,
        "SSH",
        "BannerHandshake",
        format!(
            "client_banner='{}' -> served rotating server_banner='{}' ({})",
            client_banner, server_banner, persona.ssh_cve_profile
        ),
    );

    // 6. Run full encrypted SSH-2 key exchange, auth deception, and fake shell
    transport::run_ssh2_deception_session(
        stream,
        engine,
        persona,
        client_ip,
        &client_banner,
        &server_banner,
    )
    .await
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
            "Trapped scanner banner '{}' in slow pre-banner drip loop",
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

async fn read_ssh_line(stream: &mut TcpStream) -> io::Result<String> {
    let mut buf = Vec::with_capacity(128);
    let mut byte = [0u8; 1];
    while buf.len() < 255 {
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

/// Run the Fake Shell over standard input/output for native OpenSSH `ForceCommand` integration.
pub async fn run_stdio_fake_shell(
    engine: Arc<MirageEngine>,
    login_user: Option<String>,
) -> io::Result<()> {
    let client_ip = std::env::var("SSH_CONNECTION")
        .or_else(|_| std::env::var("SSH_CLIENT"))
        .ok()
        .and_then(|val| val.split_whitespace().next()?.parse::<IpAddr>().ok())
        .unwrap_or(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));

    let user = login_user.or_else(|| std::env::var("USER").ok());
    let persona = engine.select_persona(client_ip);
    let mut session = FakeShellSession::new(persona.clone(), user.as_deref());

    let mut stdout = tokio::io::stdout();

    if let Ok(orig_cmd) = std::env::var("SSH_ORIGINAL_COMMAND") {
        if !orig_cmd.trim().is_empty() {
            engine.record_event(
                client_ip,
                &persona,
                "OPENSSH-FORCECMD",
                "ExecCommand",
                format!("cmd: {orig_cmd}"),
            );
            let res = session.execute_line(&orig_cmd);
            if res.delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(res.delay_ms)).await;
            }
            if !res.output.is_empty() {
                stdout.write_all(res.output.as_bytes()).await?;
                stdout.flush().await?;
            }
            return Ok(());
        }
    }

    stdout
        .write_all(session.welcome_banner().as_bytes())
        .await?;
    stdout.write_all(session.prompt().as_bytes()).await?;
    stdout.flush().await?;

    let stdin = BufReader::new(tokio::io::stdin());
    let mut lines = stdin.lines();

    while let Some(line) = lines.next_line().await? {
        let res = session.execute_line(&line);
        for indicator in &res.captured_indicators {
            warn!(%client_ip, %indicator, "Captured malware payload indicator in OpenSSH ForceCommand shell");
        }
        if res.delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(res.delay_ms)).await;
        }
        if !res.output.is_empty() {
            stdout.write_all(res.output.as_bytes()).await?;
        }
        if res.should_exit {
            break;
        }
        stdout.write_all(session.prompt().as_bytes()).await?;
        stdout.flush().await?;
    }

    Ok(())
}

/// Generate complete integration snippets for BOTH:
/// 1. Native OpenSSH PAM `.so` (`libpam_mirage.so`) + `ForceCommand` (`mirage-fake-shell`)
/// 2. Frontline SSH Reverse Proxy (`mirage-daemon --ssh-mode frontline_proxy`)
pub fn generate_openssh_config_snippet(fake_shell_bin_path: &str, pam_so_path: &str) -> String {
    format!(
        r#"# ============================================================================
# Mode A: Native OpenSSH PAM Shared Library (.so) + ForceCommand Integration
# ============================================================================
# Keep real OpenSSH listening directly on port 22!
# Real admin users are completely unaffected (libpam_mirage.so returns PAM_IGNORE).
# Only decoy accounts trigger N-th password acceptance + mirage-fake-shell!
#
# 1. Build and install the PAM .so module and Fake Shell binary:
#    cargo build --release --workspace
#    sudo install -m 0755 target/release/libpam_mirage.so {pam_so_path}
#    sudo install -m 0755 target/release/mirage-fake-shell {fake_shell_bin_path}
#
# 2. Create powerless decoy system users (no home directory, nologin/fake-shell):
#    for u in svc_deploy admin test ubnt postgres; do
#        sudo useradd -M -s {fake_shell_bin_path} "$u" 2>/dev/null || true
#    done
#
# 3. Add this single line at the TOP of /etc/pam.d/sshd (before @include common-auth / pam_unix.so):
#    auth sufficient {pam_so_path} decoy_users=svc_deploy,admin,test,ubnt,postgres accept_on=3 fail_delay_ms=1200 log_file=/var/log/mirage-pam.jsonl
#
# 4. Drop this file into /etc/ssh/sshd_config.d/99-mirage.conf and reload sshd:
UsePAM yes
KbdInteractiveAuthentication yes

Match User svc_deploy,admin,test,ubnt,postgres
    PasswordAuthentication yes
    PermitEmptyPasswords no
    ForceCommand {fake_shell_bin_path}
    AllowTcpForwarding no
    X11Forwarding no
    PermitTunnel no
    AllowAgentForwarding no

# ============================================================================
# Mode B: Frontline SSH Reverse Proxy / Multiplexer Mode
# ============================================================================
# Move real OpenSSH `sshd` to `ListenAddress 127.0.0.1:22022` and run:
#   mirage-daemon --ssh-mode frontline_proxy --ssh-addr 0.0.0.0:22 --upstream-sshd 127.0.0.1:22022
#
# Configure trusted admin IPs or secret banner bypass in config.toml:
#   [ssh]
#   mode = "frontline_proxy"
#   upstream_sshd_addr = "127.0.0.1:22022"
#   trusted_client_ips = ["203.0.113.10"]
#   upstream_bypass_banner_substr = "CorpBastion-9f4b"
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use mirage_core::MirageConfig;

    #[tokio::test]
    async fn test_ssh_banner_rotation_and_kexinit_handshake() {
        let mut cfg = MirageConfig::default();
        cfg.ssh.auth_fail_delay_ms = 10;
        let engine = MirageEngine::new(cfg);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let eng_server = engine.clone();
        tokio::spawn(async move {
            let _ = serve_ssh_listener(listener, eng_server).await;
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(b"SSH-2.0-OpenSSH_9.0_TestClient\r\n")
            .await
            .unwrap();

        let server_banner = read_ssh_line(&mut client).await.unwrap();
        assert!(server_banner.starts_with("SSH-2.0-"));

        let mut len_buf = [0u8; 4];
        client.read_exact(&mut len_buf).await.unwrap();
        let pkt_len = u32::from_be_bytes(len_buf) as usize;
        assert!(pkt_len > 32 && pkt_len < 4096);
        let mut body = vec![0u8; pkt_len];
        client.read_exact(&mut body).await.unwrap();
        assert_eq!(body[1], 20); // SSH_MSG_KEXINIT
    }

    #[tokio::test]
    async fn test_endlessh_tarpit_for_scanners() {
        let mut cfg = MirageConfig::default();
        cfg.ssh.endlessh_tarpit_for_scanners = true;
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

        let line1 = read_ssh_line(&mut scanner).await.unwrap();
        assert!(line1.starts_with("OpenSSH-PreAuth-Node-"));
        assert!(!line1.starts_with("SSH-2.0-"));
    }

    #[tokio::test]
    async fn test_ssh_frontline_proxy_forwards_secret_banner_to_real_sshd() {
        // 1. Mock real upstream OpenSSH daemon
        let mock_sshd = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mock_sshd_addr = mock_sshd.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = mock_sshd.accept().await {
                let received_client_banner = read_ssh_line(&mut s).await.unwrap();
                let reply = format!("SSH-2.0-REAL_UPSTREAM_OPENSSH_GOT_{received_client_banner}\r\n");
                let _ = s.write_all(reply.as_bytes()).await;
            }
        });

        // 2. Start MiragePot SSH in FrontlineProxy mode with a secret admin banner token
        let mut cfg = MirageConfig::default();
        cfg.ssh.mode = SshDeployMode::FrontlineProxy;
        cfg.ssh.upstream_sshd_addr = Some(mock_sshd_addr);
        cfg.ssh.upstream_bypass_banner_substr = Some("AdminBastion-XYZ".to_string());
        let engine = MirageEngine::new(cfg);

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = serve_ssh_listener(proxy_listener, engine).await;
        });

        // 3. Connect with admin banner -> transparently spliced to mock_sshd with banner replayed!
        let mut admin_client = TcpStream::connect(proxy_addr).await.unwrap();
        admin_client
            .write_all(b"SSH-2.0-OpenSSH_9.6_AdminBastion-XYZ\r\n")
            .await
            .unwrap();
        let upstream_banner = read_ssh_line(&mut admin_client).await.unwrap();
        assert_eq!(
            upstream_banner,
            "SSH-2.0-REAL_UPSTREAM_OPENSSH_GOT_SSH-2.0-OpenSSH_9.6_AdminBastion-XYZ"
        );
    }
}
