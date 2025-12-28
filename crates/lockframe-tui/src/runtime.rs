//! Async runtime
//!
//! Event loop that drives terminal I/O and coordinates between the App
//! state machine and the protocol client. This is the only impure code
//! in the TUI crate.

use std::io::{self, stdout};

use crossterm::{
    ExecutableCommand,
    event::{self, Event, KeyEventKind},
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};
use thiserror::Error;

use crate::{
    App,
    app::{AppAction, AppEvent},
    ui,
};

/// Runtime errors.
#[derive(Debug, Error)]
pub enum RuntimeError {
    /// I/O error from terminal operations.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

/// Async runtime for the TUI.
///
/// Manages terminal setup/teardown and the main event loop.
pub struct Runtime {
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
    app: App,
}

impl Runtime {
    /// Create a new runtime with default server address.
    pub fn new() -> Result<Self, RuntimeError> {
        Self::with_server("localhost:8080".to_string())
    }

    /// Create a new runtime with specified server address.
    pub fn with_server(server_addr: String) -> Result<Self, RuntimeError> {
        enable_raw_mode()?;
        stdout().execute(EnterAlternateScreen)?;

        let backend = CrosstermBackend::new(stdout());
        let terminal = Terminal::new(backend)?;
        let app = App::new(server_addr);

        Ok(Self { terminal, app })
    }

    /// Run the main event loop.
    pub fn run(mut self) -> Result<(), RuntimeError> {
        // Initial render
        self.render()?;

        loop {
            // Poll for events with 100ms timeout (for tick events)
            if event::poll(std::time::Duration::from_millis(100))? {
                let app_event = match event::read()? {
                    Event::Key(key) if key.kind == KeyEventKind::Press => AppEvent::Key(key.code),
                    Event::Resize(cols, rows) => AppEvent::Resize(cols, rows),
                    _ => continue,
                };

                let actions = self.app.handle(app_event);

                if self.process_actions(actions)? {
                    break;
                }
            } else {
                // Tick event on timeout
                let actions = self.app.handle(AppEvent::Tick);
                if self.process_actions(actions)? {
                    break;
                }
            }
        }

        Ok(())
    }

    /// Process actions returned by the app. Returns true if should quit.
    fn process_actions(&mut self, actions: Vec<AppAction>) -> Result<bool, RuntimeError> {
        for action in actions {
            match action {
                AppAction::Render => self.render()?,
                AppAction::Quit => return Ok(true),
                // Client operations (not yet implemented)
                AppAction::Connect { .. }
                | AppAction::CreateRoom { .. }
                | AppAction::JoinRoom { .. }
                | AppAction::LeaveRoom { .. }
                | AppAction::SendMessage { .. } => {},
            }
        }
        Ok(false)
    }

    /// Render the UI.
    fn render(&mut self) -> Result<(), RuntimeError> {
        self.terminal.draw(|frame| {
            ui::render(frame, &self.app);
        })?;
        Ok(())
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        // Restore terminal state
        let _ = disable_raw_mode();
        let _ = stdout().execute(LeaveAlternateScreen);
    }
}
