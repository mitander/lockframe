//! Lockframe TUI entry point.

use lockframe_tui::runtime::Runtime;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = Runtime::new()?;
    Ok(runtime.run()?)
}
