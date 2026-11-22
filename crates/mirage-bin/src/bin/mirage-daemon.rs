use clap::{Parser, ValueEnum};
use mirage_deception::{MirageConfig, MirageEngine, ResponseAction};
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing::info;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliResponseAction {
    Drop,
    Fail2ban,
    EndlesshTarpit,
    SshHoneypot,
}

impl From<CliResponseAction> for ResponseAction {
    fn from(v: CliResponseAction) -> Self {
        match v {
            CliResponseAction::Drop => ResponseAction::Drop,
            CliResponseAction::Fail2ban => ResponseAction::Fail2ban,
            CliResponseAction::EndlesshTarpit => ResponseAction::EndlesshTarpit,
            CliResponseAction::SshHoneypot => ResponseAction::SshHoneypot,
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "mirage-daemon",
    about = "Mirage OpenSSH Frontline Reverse Proxy & Pre-Auth CVE Shield powered by sigil-filter"
)]
struct Cli {
    /// Optional path to a TOML configuration file.
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Bind address for the Mirage SSH frontline proxy (e.g. 0.0.0.0:22).
    #[arg(long)]
    bind: Option<SocketAddr>,

    /// Real upstream OpenSSH daemon address (e.g. 127.0.0.1:22022).
    #[arg(long)]
    upstream_sshd: Option<SocketAddr>,

    /// Response action for brute-force / high-rate bursts (`fail2ban`, `ssh-honeypot`, `endlessh-tarpit`, `drop`).
    #[arg(long, value_enum)]
    bruteforce_action: Option<CliResponseAction>,

    /// Response action for pre-auth CVE / Strict-KEX / sigil-filter violations.
    #[arg(long, value_enum)]
    cve_action: Option<CliResponseAction>,

    /// Response action for automated scanner banners (`masscan`, `zgrab`, `libssh2`, etc.).
    #[arg(long, value_enum)]
    scanner_action: Option<CliResponseAction>,

    /// Optional log file path to emit `MIRAGE_BAN` lines for external Fail2Ban/nftables integration.
    #[arg(long)]
    ban_log_file: Option<String>,

    /// Override the automatic persona rotation interval in seconds.
    #[arg(long)]
    rotation_secs: Option<u64>,

    /// Print the default TOML configuration and exit.
    #[arg(long)]
    print_default_config: bool,

    /// Print the upstream OpenSSH `sshd` & Fail2Ban integration guide and exit.
    #[arg(long)]
    print_sshd_config: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    if cli.print_default_config {
        let default_cfg = MirageConfig::default();
        println!("{}", toml::to_string_pretty(&default_cfg)?);
        return Ok(());
    }

    let mut config = match cli.config {
        Some(path) => MirageConfig::from_toml_file(path)?,
        None => MirageConfig::default(),
    };

    if let Some(bind) = cli.bind {
        config.ssh.bind_addr = bind;
    }
    if let Some(upstream) = cli.upstream_sshd {
        config.ssh.upstream_sshd_addr = upstream;
    }
    if let Some(action) = cli.bruteforce_action {
        config.ssh.bruteforce_action = action.into();
    }
    if let Some(action) = cli.cve_action {
        config.ssh.cve_exploit_action = action.into();
    }
    if let Some(action) = cli.scanner_action {
        config.ssh.scanner_action = action.into();
    }
    if let Some(log_path) = cli.ban_log_file {
        config.ssh.ban_log_file = Some(log_path);
    }
    if let Some(rot) = cli.rotation_secs {
        config.rotation_interval_secs = rot;
    }

    if cli.print_sshd_config {
        println!(
            "{}",
            mirage_ssh::generate_openssh_proxy_guide(
                config.ssh.bind_addr,
                config.ssh.upstream_sshd_addr
            )
        );
        return Ok(());
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let engine = MirageEngine::new(config.clone());
    let snap = engine.current_snapshot();

    info!(
        epoch = snap.epoch_id,
        bind_addr = %config.ssh.bind_addr,
        upstream_sshd = %config.ssh.upstream_sshd_addr,
        bruteforce_action = ?config.ssh.bruteforce_action,
        cve_exploit_action = ?config.ssh.cve_exploit_action,
        scanner_action = ?config.ssh.scanner_action,
        sigil_banners = config.sigil.inspect_ssh_banners,
        sigil_kex = config.sigil.inspect_kex_packets,
        "Mirage Frontline SSH CVE Shield initialized"
    );

    let _rotator_handle = engine.spawn_rotation_task();
    mirage_ssh::run_standalone_ssh_server(engine).await?;

    Ok(())
}
