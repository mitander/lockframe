//! Async runtime
//!
//! Event loop that drives terminal I/O and coordinates between the App
//! state machine, Bridge, and Client. Uses tokio::select! to handle terminal
//! events and server frames concurrently.
//!
//! Supports two modes:
//! - Simulation mode: In-process server for single-client testing
//! - QUIC mode: Real QUIC connection for multi-client testing

use std::io::{self, stdout};

use crossterm::{
    ExecutableCommand,
    event::{Event, EventStream, KeyEventKind},
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use futures::StreamExt;
use lockframe_client::transport::{self, ConnectedClient, TransportError};
use lockframe_core::env::Environment;
use lockframe_proto::{
    Frame, FrameHeader, Opcode, Payload, errors::ProtocolError, payloads::session::Hello,
};
use lockframe_server::SystemEnv;
use ratatui::{Terminal, backend::CrosstermBackend};
use thiserror::Error;
use tokio::sync::mpsc;

use crate::{
    App,
    app::{AppAction, AppEvent},
    bridge::Bridge,
    server::{self, ServerHandle},
    ui,
};

/// Runtime errors.
#[derive(Debug, Error)]
pub enum RuntimeError {
    /// I/O error from terminal operations.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// Transport error.
    #[error("transport error: {0}")]
    Transport(#[from] TransportError),

    /// Protocol error.
    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),

    /// Frame sending error.
    #[error("failed to send frames: {0}")]
    FrameSend(#[from] Box<dyn std::error::Error + Send + Sync>),
}

/// Connection to a server (either in-process or QUIC).
enum Connection {
    /// In-process simulated server.
    InProcess(ServerHandle),
    /// QUIC connection to remote server.
    Quic(ConnectedClient),
}

impl Connection {
    fn to_server(&self) -> &mpsc::Sender<Frame> {
        match self {
            Connection::InProcess(h) => &h.to_server,
            Connection::Quic(h) => &h.to_server,
        }
    }

    fn from_server(&mut self) -> &mut mpsc::Receiver<Frame> {
        match self {
            Connection::InProcess(h) => &mut h.from_server,
            Connection::Quic(h) => &mut h.from_server,
        }
    }

    fn stop(&self) {
        match self {
            Connection::InProcess(h) => h.stop(),
            Connection::Quic(h) => h.stop(),
        }
    }
}

/// Connection mode for the runtime.
#[derive(Clone)]
enum ConnectionMode {
    /// Simulation mode - spawn in-process server on /connect.
    Simulation,
    /// QUIC mode - connect to this server address.
    Quic(String),
}

/// Async runtime for the TUI.
///
/// Manages terminal setup/teardown, the main event loop, and coordinates
/// between App (UI) and Bridge (protocol) state machines.
pub struct Runtime {
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
    app: App,
    bridge: Bridge<SystemEnv>,
    connection: Option<Connection>,
    mode: ConnectionMode,
}

impl Runtime {
    /// Create a new runtime in simulation mode.
    pub fn new() -> Result<Self, RuntimeError> {
        Self::create("localhost:4433".to_string(), ConnectionMode::Simulation)
    }

    /// Create a new runtime that connects to a QUIC server.
    pub fn with_quic_server(server_addr: String) -> Result<Self, RuntimeError> {
        Self::create(server_addr.clone(), ConnectionMode::Quic(server_addr))
    }

    fn create(display_addr: String, mode: ConnectionMode) -> Result<Self, RuntimeError> {
        enable_raw_mode()?;
        stdout().execute(EnterAlternateScreen)?;

        let backend = CrosstermBackend::new(stdout());
        let terminal = Terminal::new(backend)?;
        let app = App::new(display_addr);

        let env = SystemEnv::new();
        let sender_id = Environment::random_u64(&env);
        let bridge = Bridge::new(env, sender_id);

        Ok(Self { terminal, app, bridge, connection: None, mode })
    }

    /// Run the main event loop.
    pub async fn run(mut self) -> Result<(), RuntimeError> {
        self.render()?;
        self.connect().await?;

        let mut event_stream = EventStream::new();
        let mut tick_interval = tokio::time::interval(std::time::Duration::from_millis(100));

        loop {
            // Server connection active
            let should_quit = if let Some(ref mut conn) = self.connection {
                tokio::select! {
                    // Terminal events
                    maybe_event = event_stream.next() => {
                        match maybe_event {
                            Some(Ok(event)) => self.handle_terminal_event(event).await?,
                            Some(Err(e)) => return Err(RuntimeError::Io(e)),
                            None => true,
                        }
                    }

                    // Frames from server
                    Some(frame) = conn.from_server().recv() => {
                        if let Some(Opcode::HelloReply) = frame.header.opcode_enum() {
                            // Extract session_id and skip frame processing
                            self.handle_hello_reply(frame).await?;
                            continue;
                        }

                        let events = self.bridge.handle_frame(frame);
                        self.send_outgoing_frames().await.unwrap_or_else(|e| {
                            tracing::warn!("Failed to send outgoing frames after handling server frame: {:?}", e);
                        });
                        self.process_bridge_events(events).await?
                    }

                    // Periodic tick
                    _ = tick_interval.tick() => {
                        let now = std::time::Instant::now();
                        let events = self.bridge.handle_tick(now);
                        self.process_bridge_events(events).await?;

                        let actions = self.app.handle(AppEvent::Tick);
                        self.process_actions(actions).await?
                    }
                }
            } else {
                tokio::select! {
                    // No server connection active (terminal events only)
                    maybe_event = event_stream.next() => {
                        match maybe_event {
                            Some(Ok(event)) => self.handle_terminal_event(event).await?,
                            Some(Err(e)) => return Err(RuntimeError::Io(e)),
                            None => true,
                        }
                    }

                    // Periodic tick
                    _ = tick_interval.tick() => {
                        let actions = self.app.handle(AppEvent::Tick);
                        self.process_actions(actions).await?
                    }
                }
            };

            if should_quit {
                break;
            }
        }

        Ok(())
    }

    /// Handle a terminal event and return whether to quit.
    async fn handle_terminal_event(&mut self, event: Event) -> Result<bool, RuntimeError> {
        let app_event = match event {
            Event::Key(key) if key.kind == KeyEventKind::Press => AppEvent::Key(key.code),
            Event::Resize(cols, rows) => AppEvent::Resize(cols, rows),
            _ => return Ok(false),
        };

        let actions = self.app.handle(app_event);
        self.process_actions(actions).await
    }

    /// Process actions returned by the app. Returns true if should quit.
    ///
    /// Uses iterative processing to avoid async recursion between actions and
    /// events.
    async fn process_actions(
        &mut self,
        initial_actions: Vec<AppAction>,
    ) -> Result<bool, RuntimeError> {
        let mut pending_actions = initial_actions;

        while !pending_actions.is_empty() {
            let actions = std::mem::take(&mut pending_actions);

            for action in actions {
                match action {
                    AppAction::Render => self.render()?,
                    AppAction::Quit => return Ok(true),
                    AppAction::Connect { server_addr: _ } => {
                        self.connect().await?;
                    },

                    // Protocol operations go through the bridge
                    AppAction::CreateRoom { room_id: _ }
                    | AppAction::JoinRoom { room_id: _ }
                    | AppAction::LeaveRoom { room_id: _ }
                    | AppAction::SendMessage { room_id: _, content: _ }
                    | AppAction::PublishKeyPackage
                    | AppAction::AddMember { room_id: _, user_id: _ } => {
                        let events = self.bridge.process_app_action(action);
                        for event in events {
                            let new_actions = self.app.handle(event);
                            pending_actions.extend(new_actions);
                        }
                        self.send_outgoing_frames().await.unwrap_or_else(|e| {
                            tracing::warn!("Failed to send outgoing frames: {:?}", e);
                        });
                    },
                }
            }
        }
        Ok(false)
    }

    /// Handle HelloReply frame to extract session_id and trigger connection
    /// flow.
    async fn handle_hello_reply(&mut self, frame: Frame) -> Result<(), RuntimeError> {
        let payload = Payload::from_frame(frame)?;

        let hello_reply = match payload {
            Payload::HelloReply(reply) => reply,
            other => {
                tracing::warn!("Unexpected payload type for HelloReply opcode: {:?}", other);
                return Err(RuntimeError::Protocol(
                    lockframe_proto::errors::ProtocolError::CborDecode(format!(
                        "Expected HelloReply, got {:?}",
                        other
                    )),
                ));
            },
        };

        let events = self.bridge.process_app_action(AppAction::PublishKeyPackage);
        for event in events {
            let actions = self.app.handle(event);
            self.process_actions_blocking(actions).unwrap_or_else(|e| {
                // These are app errors not protocol errors, don't fail connection
                tracing::warn!("Failed to process actions from app event: {:?}", e);
            });
        }

        let session_id = hello_reply.session_id;
        let sender_id = self.bridge.sender_id();
        let actions = self.app.handle(AppEvent::Connected { session_id, sender_id });
        self.process_actions_blocking(actions).unwrap_or_else(|e| {
            tracing::warn!("Failed to process actions from Connected event: {:?}", e);
        });

        self.send_outgoing_frames().await?;

        Ok(())
    }

    /// Process actions synchronously (use in sync contexts).
    fn process_actions_blocking(&mut self, actions: Vec<AppAction>) -> Result<(), RuntimeError> {
        for action in actions {
            match action {
                AppAction::Render => self.render()?,
                AppAction::Quit => return Ok(()),

                // Protocol actions shouldn't happen in sync contexts
                AppAction::Connect { server_addr: _ }
                | AppAction::CreateRoom { room_id: _ }
                | AppAction::JoinRoom { room_id: _ }
                | AppAction::LeaveRoom { room_id: _ }
                | AppAction::SendMessage { room_id: _, content: _ }
                | AppAction::PublishKeyPackage
                | AppAction::AddMember { room_id: _, user_id: _ } => {
                    tracing::warn!("Unexpected protocol action in sync context: {:?}", action);
                },
            }
        }
        Ok(())
    }
    /// Process events from the bridge back to the app.
    async fn process_bridge_events(&mut self, events: Vec<AppEvent>) -> Result<bool, RuntimeError> {
        for event in events {
            let actions = self.app.handle(event);
            if self.process_actions(actions).await? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Connect to the server based on the mode.
    async fn connect(&mut self) -> Result<(), RuntimeError> {
        let session_id = self.bridge.sender_id();

        let connection = match &self.mode {
            ConnectionMode::Simulation => {
                let handle = server::spawn_server(session_id);
                Connection::InProcess(handle)
            },
            ConnectionMode::Quic(addr) => {
                let client = transport::connect(addr).await?;
                Connection::Quic(client)
            },
        };

        self.connection = Some(connection);
        self.send_hello().await?;

        self.app.handle(AppEvent::Connecting).into_iter().for_each(|action| match action {
            AppAction::Render => {
                self.render().unwrap_or_else(|e| {
                    tracing::warn!("Failed to render during Connecting: {:?}", e);
                });
            },

            // Protocol actions shouldn't happen when connecting
            AppAction::Quit
            | AppAction::Connect { server_addr: _ }
            | AppAction::CreateRoom { room_id: _ }
            | AppAction::JoinRoom { room_id: _ }
            | AppAction::LeaveRoom { room_id: _ }
            | AppAction::SendMessage { room_id: _, content: _ }
            | AppAction::PublishKeyPackage
            | AppAction::AddMember { room_id: _, user_id: _ } => {
                tracing::warn!("Unexpected action during Connecting: {:?}", action);
            },
        });

        Ok(())
    }

    /// Send Hello frame to authenticate with the server.
    async fn send_hello(&mut self) -> Result<(), RuntimeError> {
        let sender_id = self.bridge.sender_id();
        let hello = Hello {
            version: 1,
            capabilities: Vec::new(),
            sender_id: Some(sender_id),
            auth_token: None,
        };

        let frame = match Payload::Hello(hello).into_frame(FrameHeader::new(Opcode::Hello)) {
            Ok(frame) => frame,
            Err(e) => {
                tracing::error!("Failed to create Hello frame: {:?}", e);
                return Err(RuntimeError::Protocol(
                    lockframe_proto::errors::ProtocolError::CborDecode(format!(
                        "Failed to create Hello frame: {:?}",
                        e
                    )),
                ));
            },
        };

        if let Some(conn) = &self.connection {
            conn.to_server().send(frame).await.map_err(|e| {
                tracing::error!("Failed to send Hello frame: {:?}", e);
                RuntimeError::Transport(TransportError::Stream(format!(
                    "Channel send failed: {:?}",
                    e
                )))
            })?;
            return Ok(());
        } else {
            tracing::error!("No connection available for Hello frame");
            return Err(RuntimeError::Io(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "No connection available",
            )));
        }
    }

    /// Send all pending outgoing frames to the server.
    async fn send_outgoing_frames(
        &mut self,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let frames = self.bridge.take_outgoing();
        if frames.is_empty() {
            return Ok(());
        }

        let conn = self.connection.as_mut().ok_or("No connection available")?;

        for frame in frames {
            conn.to_server().send(frame).await?;
        }
        Ok(())
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
        if let Some(ref conn) = self.connection {
            conn.stop();
        }

        let _ = disable_raw_mode();
        let _ = stdout().execute(LeaveAlternateScreen);
    }
}
