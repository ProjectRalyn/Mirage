use clap::Parser;
use mirage_deception::{MirageConfig, MirageEngine};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Parser)]
#[command(
    name = "mirage-fake-shell",
    about = "Zero-overhead in-memory Fake Shell for native OpenSSH ForceCommand integration"
)]
struct Cli {
    /// Optional path to a TOML configuration file.
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Override the simulated login username.
    #[arg(short, long)]
    user: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let mut config = match cli.config {
        Some(path) => MirageConfig::from_toml_file(path)?,
        None => MirageConfig::default(),
    };

    // Derive current time-based epoch so separate `ForceCommand` invocations automatically
    // rotate their pre-baked VFS and credentials every `rotation_interval_secs`!
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let interval = config.rotation_interval_secs.max(1);
    let time_epoch = (now_secs / interval) + 1;
    config.master_seed = config.master_seed.wrapping_add(time_epoch);

    let engine = MirageEngine::new(config);
    mirage_ssh::run_stdio_fake_shell(engine, cli.user).await?;

    Ok(())
}
