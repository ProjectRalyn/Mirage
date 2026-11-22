use clap::{Parser, ValueEnum};
use mirage_core::{
    run_standalone_postgres_server, run_standalone_redis_server, HttpDeployMode, MirageConfig,
    MirageEngine, SshDeployMode,
};
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing::info;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliHttpMode {
    Standalone,
    FrontlineProxy,
    BehindProxySink,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliSshMode {
    Standalone,
    FrontlineProxy,
}

#[derive(Debug, Parser)]
#[command(
    name = "mirage-daemon",
    about = "Low-overhead asymmetric HTTP, SSH, Redis & PostgreSQL deception honeypot supporting Frontline Proxy, Behind-Proxy Sink, Embedded Layer, and OpenSSH PAM .so modes"
)]
struct Cli {
    /// Optional path to a TOML configuration file.
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// HTTP deployment mode (`standalone`, `frontline-proxy`, or `behind-proxy-sink`).
    #[arg(long, value_enum)]
    http_mode: Option<CliHttpMode>,

    /// Override the HTTP honeypot bind address (e.g. 0.0.0.0:8080).
    #[arg(long)]
    http_addr: Option<SocketAddr>,

    /// Real upstream HTTP backend URL for `frontline-proxy` mode (e.g. http://127.0.0.1:3000).
    #[arg(long)]
    upstream_http: Option<String>,

    /// SSH deployment mode (`standalone` or `frontline-proxy`).
    #[arg(long, value_enum)]
    ssh_mode: Option<CliSshMode>,

    /// Override the SSH honeypot bind address (e.g. 0.0.0.0:2222).
    #[arg(long)]
    ssh_addr: Option<SocketAddr>,

    /// Real upstream OpenSSH daemon address for `frontline-proxy` mode (e.g. 127.0.0.1:22022).
    #[arg(long)]
    upstream_sshd: Option<SocketAddr>,

    /// Override the Redis (RESP) honeypot bind address (e.g. 0.0.0.0:16379).
    #[arg(long)]
    redis_addr: Option<SocketAddr>,

    /// Override the PostgreSQL (PGWire v3) honeypot bind address (e.g. 0.0.0.0:15432).
    #[arg(long)]
    pg_addr: Option<SocketAddr>,

    /// Override the secret admin panel URL prefix (default: "auto" generates a 36-char random path).
    #[arg(long)]
    admin_path: Option<String>,

    /// Override the automatic payload rotation interval in seconds.
    #[arg(long)]
    rotation_secs: Option<u64>,

    /// Print the default TOML configuration and exit.
    #[arg(long)]
    print_default_config: bool,

    /// Print the native OpenSSH PAM `.so` + `ForceCommand` & Frontline SSH Proxy integration guide.
    #[arg(long)]
    print_sshd_config: bool,

    /// Print an Nginx `behind_proxy_sink` configuration template and exit.
    #[arg(long)]
    print_nginx_config: bool,

    /// Print a Caddy `behind_proxy_sink` configuration template and exit.
    #[arg(long)]
    print_caddy_config: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    if cli.print_default_config {
        let default_cfg = MirageConfig::default();
        println!("{}", toml::to_string_pretty(&default_cfg)?);
        return Ok(());
    }

    if cli.print_sshd_config {
        println!(
            "{}",
            mirage_ssh::generate_openssh_config_snippet(
                "/usr/local/bin/mirage-fake-shell",
                "/usr/local/lib/security/libpam_mirage.so"
            )
        );
        return Ok(());
    }

    if cli.print_nginx_config {
        println!(
            "{}",
            mirage_http::generate_nginx_sink_config("127.0.0.1:8080", "127.0.0.1:3000")
        );
        return Ok(());
    }

    if cli.print_caddy_config {
        println!(
            "{}",
            mirage_http::generate_caddy_sink_config("127.0.0.1:8080", "127.0.0.1:3000")
        );
        return Ok(());
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let mut config = match cli.config {
        Some(path) => MirageConfig::from_toml_file(path)?,
        None => MirageConfig::default(),
    };

    if let Some(m) = cli.http_mode {
        config.http.mode = match m {
            CliHttpMode::Standalone => HttpDeployMode::Standalone,
            CliHttpMode::FrontlineProxy => HttpDeployMode::FrontlineProxy,
            CliHttpMode::BehindProxySink => HttpDeployMode::BehindProxySink,
        };
    }
    if let Some(http_addr) = cli.http_addr {
        config.http.bind_addr = http_addr;
    }
    if let Some(upstream_http) = cli.upstream_http {
        config.http.upstream_http_url = Some(upstream_http);
        if cli.http_mode.is_none() {
            config.http.mode = HttpDeployMode::FrontlineProxy;
        }
    }
    if let Some(m) = cli.ssh_mode {
        config.ssh.mode = match m {
            CliSshMode::Standalone => SshDeployMode::Standalone,
            CliSshMode::FrontlineProxy => SshDeployMode::FrontlineProxy,
        };
    }
    if let Some(ssh_addr) = cli.ssh_addr {
        config.ssh.bind_addr = ssh_addr;
    }
    if let Some(upstream_sshd) = cli.upstream_sshd {
        config.ssh.upstream_sshd_addr = Some(upstream_sshd);
        if cli.ssh_mode.is_none() {
            config.ssh.mode = SshDeployMode::FrontlineProxy;
        }
    }
    if let Some(redis_addr) = cli.redis_addr {
        config.redis.bind_addr = redis_addr;
    }
    if let Some(pg_addr) = cli.pg_addr {
        config.postgres.bind_addr = pg_addr;
    }
    if let Some(admin_path) = cli.admin_path {
        config.admin.path_prefix = admin_path;
    }
    if let Some(rot) = cli.rotation_secs {
        config.rotation_interval_secs = rot;
    }

    let engine = MirageEngine::new(config.clone());
    let snap = engine.current_snapshot();

    info!(
        epoch = snap.epoch_id,
        persona_slots = snap.personas.len(),
        rotation_interval_secs = config.rotation_interval_secs,
        admin_prefix = %engine.admin_path_prefix(),
        http_mode = ?config.http.mode,
        http_bind = %config.http.bind_addr,
        ssh_mode = ?config.ssh.mode,
        ssh_bind = %config.ssh.bind_addr,
        redis_bind = %config.redis.bind_addr,
        postgres_bind = %config.postgres.bind_addr,
        "Mirage initialized pre-baked deception pool"
    );

    let _rotator_handle = engine.spawn_rotation_task();

    tokio::try_join!(
        mirage_http::run_standalone_http_server(engine.clone()),
        mirage_ssh::run_standalone_ssh_server(engine.clone()),
        run_standalone_redis_server(engine.clone()),
        run_standalone_postgres_server(engine),
    )?;

    Ok(())
}
