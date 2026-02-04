//! Generic runtime for application orchestration.
//!
//! The Runtime drives the application event loop, coordinating between:
//! - [`App`]: UI state machine
//! - [`Bridge`]: Protocol bridge to Client
//! - [`Driver`]: Platform-specific I/O

use std::{ops::Sub, time::Duration};

use lockframe_core::env::Environment;
use lockframe_proto::{Frame, FrameHeader, Opcode, Payload, payloads::session::Hello};

use crate::{App, AppAction, AppEvent, Bridge, Driver};

/// Generic runtime that orchestrates App, Bridge, and Driver.
///
/// # Type Parameters
///
/// - `D`: Platform-specific I/O driver
/// - `E`: Environment for cryptographic operations
pub struct Runtime<D, E>
where
    D: Driver,
    E: Environment,
{
    driver: D,
    app: App,
    bridge: Bridge<E>,
    server_addr: String,
}

impl<D, E> Runtime<D, E>
where
    D: Driver<Instant = E::Instant>,
    E: Environment,
    D::Instant: Sub<Output = Duration>,
{
    /// Create a new runtime with the given driver and environment.
    pub fn new(driver: D, env: E, sender_id: u64, server_addr: String) -> Self {
        let app = App::new(server_addr.clone());
        let bridge = Bridge::new(env, sender_id);
        Self { driver, app, bridge, server_addr }
    }

    /// Run the main event loop.
    ///
    /// This is the core orchestration loop that:
    /// 1. Polls for input events from the driver
    /// 2. Receives frames from the server
    /// 3. Processes actions and events between App and Bridge
    /// 4. Sends outgoing frames through the driver
    ///
    /// # Errors
    ///
    /// Returns an error if the driver encounters an I/O error.
    pub async fn run(mut self) -> Result<(), D::Error> {
        self.driver.render(&self.app)?;
        self.connect().await?;

        loop {
            let should_quit = self.process_cycle().await?;
            if should_quit {
                break;
            }
        }

        self.driver.stop();
        Ok(())
    }

    /// Process one cycle of the event loop.
    ///
    /// Returns `true` if the application should quit.
    async fn process_cycle(&mut self) -> Result<bool, D::Error> {
        let actions = self.driver.poll_event(&mut self.app).await?;
        if !actions.is_empty() && self.process_actions(actions).await? {
            return Ok(true);
        }

        if self.driver.is_connected()
            && let Some(frame) = self.driver.recv_frame().await
        {
            if let Some(Opcode::HelloReply) = frame.header.opcode_enum() {
                self.handle_hello_reply(frame).await?;
            } else {
                let events = self.bridge.handle_frame(frame);
                self.send_outgoing_frames().await?;
                if self.process_bridge_events(events).await? {
                    return Ok(true);
                }
            }
        }

        let now = self.driver.now();
        let events = self.bridge.handle_tick(now);
        if self.process_bridge_events(events).await? {
            return Ok(true);
        }

        Ok(false)
    }

    /// Process actions returned by the App.
    ///
    /// Returns `true` if should quit.
    async fn process_actions(&mut self, initial_actions: Vec<AppAction>) -> Result<bool, D::Error> {
        let mut pending_actions = initial_actions;

        while !pending_actions.is_empty() {
            let actions = std::mem::take(&mut pending_actions);

            for action in actions {
                match action {
                    AppAction::Render => self.driver.render(&self.app)?,
                    AppAction::Quit => return Ok(true),
                    AppAction::Connect { server_addr: _ } => {
                        self.connect().await?;
                    },

                    // Protocol operations go through the bridge
                    AppAction::CreateRoom { .. }
                    | AppAction::JoinRoom { .. }
                    | AppAction::LeaveRoom { .. }
                    | AppAction::SendMessage { .. }
                    | AppAction::PublishKeyPackage
                    | AppAction::AddMember { .. } => {
                        let events = self.bridge.process_app_action(action);
                        for event in events {
                            let new_actions = self.app.handle(event);
                            pending_actions.extend(new_actions);
                        }
                        self.send_outgoing_frames().await?;
                    },
                }
            }
        }
        Ok(false)
    }

    /// Handle `HelloReply` frame to complete connection handshake.
    async fn handle_hello_reply(&mut self, frame: Frame) -> Result<(), D::Error> {
        let payload = match Payload::from_frame(&frame) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("Failed to parse HelloReply: {:?}", e);
                return Ok(());
            },
        };

        let hello_reply = match payload {
            Payload::HelloReply(reply) => reply,
            other => {
                tracing::warn!("Unexpected payload type for HelloReply: {:?}", other);
                return Ok(());
            },
        };

        let events = self.bridge.process_app_action(AppAction::PublishKeyPackage);
        for event in events {
            let actions = self.app.handle(event);
            self.process_actions_sync(actions);
        }

        let session_id = hello_reply.session_id;
        let sender_id = self.bridge.sender_id();
        let actions = self.app.handle(AppEvent::Connected { session_id, sender_id });
        self.process_actions_sync(actions);

        self.send_outgoing_frames().await?;
        Ok(())
    }

    /// Process actions synchronously (for use in sync contexts).
    fn process_actions_sync(&mut self, actions: Vec<AppAction>) {
        for action in actions {
            match action {
                AppAction::Render => {
                    if let Err(e) = self.driver.render(&self.app) {
                        tracing::warn!("Failed to render: {:?}", e);
                    }
                },
                AppAction::Quit => {},

                // Protocol actions shouldn't happen in sync contexts
                AppAction::Connect { .. }
                | AppAction::CreateRoom { .. }
                | AppAction::JoinRoom { .. }
                | AppAction::LeaveRoom { .. }
                | AppAction::SendMessage { .. }
                | AppAction::PublishKeyPackage
                | AppAction::AddMember { .. } => {
                    tracing::warn!("Unexpected protocol action in sync context: {:?}", action);
                },
            }
        }
    }

    /// Process events from Bridge back to App.
    async fn process_bridge_events(&mut self, events: Vec<AppEvent>) -> Result<bool, D::Error> {
        for event in events {
            let actions = self.app.handle(event);
            if self.process_actions(actions).await? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Connect to the server and send Hello.
    async fn connect(&mut self) -> Result<(), D::Error> {
        self.driver.connect(&self.server_addr).await?;

        let actions = self.app.handle(AppEvent::Connecting);
        self.process_actions_sync(actions);
        self.send_hello().await?;

        Ok(())
    }

    /// Send Hello frame to authenticate with the server.
    async fn send_hello(&mut self) -> Result<(), D::Error> {
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
                return Ok(());
            },
        };

        self.driver.send_frame(frame).await
    }

    /// Send all pending outgoing frames to the server.
    async fn send_outgoing_frames(&mut self) -> Result<(), D::Error> {
        let frames = self.bridge.take_outgoing();
        for frame in frames {
            self.driver.send_frame(frame).await?;
        }
        Ok(())
    }

    /// Get a reference to the App
    pub fn app(&self) -> &App {
        &self.app
    }

    /// Get a mutable reference to the App
    pub fn app_mut(&mut self) -> &mut App {
        &mut self.app
    }
}
