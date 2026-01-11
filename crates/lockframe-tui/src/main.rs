//! Lockframe TUI entry point.

use clap::Parser;
use lockframe_app::Runtime;
use lockframe_core::env::Environment;
use lockframe_server::SystemEnv;
use lockframe_tui::TerminalDriver;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Lockframe terminal UI client
#[derive(Parser, Debug)]
#[command(name = "lockframe-tui")]
#[command(about = "Terminal UI for the Lockframe messaging protocol")]
#[command(version)]
struct Args {
    /// Server address to connect to
    #[arg(short, long, default_value = "localhost:4433")]
    server: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            "lockframe_tui=debug,tower_http=debug,axum::rejection=trace".into()
        }))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let args = Args::parse();
    let env = SystemEnv::new();
    let sender_id = Environment::random_u64(&env);
    let driver = TerminalDriver::new(args.server.clone())?;
    let runtime = Runtime::new(driver, env, sender_id, args.server);

    Ok(runtime.run().await?)
}
