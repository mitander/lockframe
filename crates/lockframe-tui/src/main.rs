//! Lockframe TUI entry point.

use clap::Parser;
use lockframe_tui::runtime::Runtime;

/// Lockframe terminal UI client
#[derive(Parser, Debug)]
#[command(name = "lockframe-tui")]
#[command(about = "Terminal UI for the Lockframe messaging protocol")]
#[command(version)]
struct Args {
    /// Server address to connect to (enables QUIC mode)
    ///
    /// If not provided, runs in simulation mode with an in-process server.
    #[arg(short, long)]
    server: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let runtime = match args.server {
        Some(addr) => Runtime::with_quic_server(addr)?,
        None => Runtime::new()?,
    };

    Ok(runtime.run().await?)
}
