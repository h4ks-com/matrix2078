use std::{net::SocketAddr, path::PathBuf, process::ExitCode, sync::Arc};

use clap::Parser;
use tracing_subscriber::EnvFilter;

mod bridge;
mod config;
mod format;
mod ircd;
mod matrix;
mod media;
mod state;

use config::Config;

#[derive(Parser, Debug)]
#[command(
    name = "matrix2078",
    version,
    about = "IRC server (IRCd) backed by Matrix — connect an IRC client, chat on Matrix"
)]
struct Args {
    /// Path to the TOML config file
    #[arg(short, long, default_value = "matrix2078.toml")]
    config: PathBuf,

    /// Override the listen address
    #[arg(long)]
    listen: Option<SocketAddr>,

    /// Override the local media server listen address
    #[arg(long)]
    media_listen: Option<SocketAddr>,
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cfg = match load_config(&args) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("error: {e:#}");
            return ExitCode::FAILURE;
        }
    };
    tracing::info!(
        listen = %cfg.listen,
        server = %cfg.server_name,
        state_dir = %cfg.state_dir.display(),
        "matrix2078 starting"
    );

    match ircd::server::run(Arc::new(cfg)).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn load_config(args: &Args) -> anyhow::Result<Config> {
    let mut cfg = Config::load_or_default(&args.config)?;
    if let Some(listen) = args.listen {
        cfg.listen = listen;
    }
    if let Some(media_listen) = args.media_listen {
        cfg.media_listen = media_listen;
    }
    Ok(cfg)
}
