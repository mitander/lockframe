//! Terminal driver for the TUI.
//!
//! Implements the [`Driver`] trait for terminal I/O using crossterm for
//! keyboard events and ratatui for rendering. Network uses quinn for QUIC.

use std::{
    io::{self, Stdout, stdout},
    time::Instant,
};

use crossterm::{
    ExecutableCommand,
    event::{Event, EventStream, KeyCode, KeyEventKind},
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use futures::StreamExt;
use lockframe_app::{App, AppAction, AppEvent, Driver};
use lockframe_client::transport::{self, ConnectedClient, TransportError};
use lockframe_proto::Frame;
use ratatui::{Terminal, backend::CrosstermBackend};
use thiserror::Error;

use crate::{InputState, KeyInput, ui};

/// Terminal driver errors.
#[derive(Debug, Error)]
pub enum TerminalError {
    /// I/O error from terminal operations.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// Transport error.
    #[error("transport error: {0}")]
    Transport(#[from] TransportError),

    /// Channel send error.
    #[error("channel send error")]
    ChannelSend,
}

/// Terminal driver implementing the [`Driver`] trait.
///
/// Handles terminal I/O (crossterm), rendering (ratatui), and network
/// communication (quinn QUIC). Owns the input state for text editing.
pub struct TerminalDriver {
    terminal: Terminal<CrosstermBackend<Stdout>>,
    event_stream: EventStream,
    connection: Option<ConnectedClient>,
    server_addr: String,
    input_state: InputState,
}

impl TerminalDriver {
    /// Create a new terminal driver.
    pub fn new(server_addr: String) -> Result<Self, TerminalError> {
        enable_raw_mode()?;
        stdout().execute(EnterAlternateScreen)?;

        let backend = CrosstermBackend::new(stdout());
        let terminal = Terminal::new(backend)?;
        let event_stream = EventStream::new();

        Ok(Self {
            terminal,
            event_stream,
            connection: None,
            server_addr,
            input_state: InputState::new(),
        })
    }

    /// Convert crossterm `KeyCode` to `KeyInput`.
    fn convert_key(code: KeyCode) -> Option<KeyInput> {
        match code {
            KeyCode::Char(c) => Some(KeyInput::Char(c)),
            KeyCode::Enter => Some(KeyInput::Enter),
            KeyCode::Backspace => Some(KeyInput::Backspace),
            KeyCode::Delete => Some(KeyInput::Delete),
            KeyCode::Tab => Some(KeyInput::Tab),
            KeyCode::Esc => Some(KeyInput::Esc),
            KeyCode::Left => Some(KeyInput::Left),
            KeyCode::Right => Some(KeyInput::Right),
            KeyCode::Up => Some(KeyInput::Up),
            KeyCode::Down => Some(KeyInput::Down),
            KeyCode::Home => Some(KeyInput::Home),
            KeyCode::End => Some(KeyInput::End),
            _ => None,
        }
    }
}

impl Driver for TerminalDriver {
    type Error = TerminalError;
    type Instant = Instant;

    async fn poll_event(&mut self, app: &mut App) -> Result<Vec<AppAction>, Self::Error> {
        let timeout = tokio::time::Duration::from_millis(100);

        tokio::select! {
            biased;

            // Terminal events
            maybe_event = self.event_stream.next() => {
                match maybe_event {
                    Some(Ok(Event::Key(key_event))) if key_event.kind == KeyEventKind::Press => {
                        match Self::convert_key(key_event.code) {
                            Some(key_input) => Ok(self.input_state.handle_key(key_input, app)),
                            None => Ok(vec![]),
                        }
                    },
                    Some(Ok(Event::Resize(cols, rows))) => {
                        Ok(app.handle(AppEvent::Resize(cols, rows)))
                    },
                    Some(Err(e)) => Err(TerminalError::Io(e)),
                    _ => Ok(vec![]),
                }
            }

            // Tick timeout
            () = tokio::time::sleep(timeout) => {
                Ok(app.handle(AppEvent::Tick))
            }
        }
    }

    async fn send_frame(&mut self, frame: Frame) -> Result<(), Self::Error> {
        if let Some(conn) = &self.connection {
            conn.to_server.send(frame).await.map_err(|_| TerminalError::ChannelSend)?;
        }
        Ok(())
    }

    async fn recv_frame(&mut self) -> Option<Frame> {
        self.connection.as_mut().and_then(|conn| conn.from_server.try_recv().ok())
    }

    async fn connect(&mut self, _addr: &str) -> Result<(), Self::Error> {
        let client = transport::connect(&self.server_addr).await?;
        self.connection = Some(client);
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connection.is_some()
    }

    fn now(&self) -> Self::Instant {
        Instant::now()
    }

    fn render(&mut self, app: &App) -> Result<(), Self::Error> {
        self.terminal.draw(|frame| {
            ui::render(frame, app, &self.input_state);
        })?;
        Ok(())
    }

    fn stop(&mut self) {
        if let Some(ref conn) = self.connection {
            conn.stop();
        }
    }
}

impl Drop for TerminalDriver {
    fn drop(&mut self) {
        self.stop();
        let _ = disable_raw_mode();
        let _ = stdout().execute(LeaveAlternateScreen);
    }
}
