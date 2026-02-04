//! Actor wrappers for scenario execution.
//!
//! Actors wrap Connection state machines and provide high-level action methods
//! that automatically execute `ConnectionActions` (send frames, close
//! connections).

use std::time::Instant;

use lockframe_core::connection::{Connection, ConnectionAction, ConnectionState};
use lockframe_proto::Frame;

/// Client actor builder for scenario execution.
pub struct ClientActor {
    name: String,
    connection: Connection,
    now: Instant,
}

impl ClientActor {
    /// Create a new client actor.
    pub fn new(name: String, connection: Connection, now: Instant) -> Self {
        Self { name, connection, now }
    }

    /// Send Hello frame and transition to Pending state.
    ///
    /// Returns the Hello frame that should be sent over the network.
    pub fn send_hello(&mut self) -> Result<Frame, String> {
        let actions = self
            .connection
            .send_hello(self.now)
            .map_err(|e| format!("Client {} failed to send_hello: {}", self.name, e))?;

        // Extract the SendFrame action
        if actions.len() != 1 {
            return Err(format!("Expected 1 action from send_hello, got {}", actions.len()));
        }

        match &actions[0] {
            ConnectionAction::SendFrame(frame) => Ok(frame.clone()),
            ConnectionAction::Close { reason } => Err(reason.clone()),
        }
    }

    /// Handle incoming `HelloReply` frame.
    pub fn handle_hello_reply(&mut self, frame: &Frame) -> Result<(), String> {
        let actions = self
            .connection
            .handle_frame(frame, self.now)
            .map_err(|e| format!("Client {} failed to handle HelloReply: {}", self.name, e))?;

        if !actions.is_empty() {
            return Err(format!("Unexpected actions from HelloReply: {} actions", actions.len()));
        }

        Ok(())
    }

    /// Expect that the client is now authenticated.
    pub fn expect_authenticated(&self) -> Result<(), String> {
        if self.connection.state() == ConnectionState::Authenticated {
            Ok(())
        } else {
            Err(format!(
                "Client {} expected Authenticated, got {:?}",
                self.name,
                self.connection.state()
            ))
        }
    }

    /// Underlying connection state (for oracle assertions).
    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    /// Actor name used in error messages.
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Server actor builder for scenario execution.
pub struct ServerActor {
    name: String,
    connection: Connection,
    now: Instant,
}

impl ServerActor {
    /// Create a new server actor.
    pub fn new(name: String, connection: Connection, now: Instant) -> Self {
        Self { name, connection, now }
    }

    /// Handle incoming Hello frame and return `HelloReply` frame.
    pub fn handle_hello(&mut self, frame: &Frame) -> Result<Frame, String> {
        let actions = self
            .connection
            .handle_frame(frame, self.now)
            .map_err(|e| format!("Server {} failed to handle Hello: {}", self.name, e))?;

        // Should return SendFrame(HelloReply)
        if actions.len() != 1 {
            return Err(format!("Expected 1 action from handle_hello, got {}", actions.len()));
        }

        match &actions[0] {
            ConnectionAction::SendFrame(frame) => Ok(frame.clone()),
            ConnectionAction::Close { reason } => Err(reason.clone()),
        }
    }

    /// Expect that the server is now authenticated.
    pub fn expect_authenticated(&self) -> Result<(), String> {
        if self.connection.state() == ConnectionState::Authenticated {
            Ok(())
        } else {
            Err(format!(
                "Server {} expected Authenticated, got {:?}",
                self.name,
                self.connection.state()
            ))
        }
    }

    /// Underlying connection state (for oracle assertions).
    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    /// Actor name used in error messages.
    pub fn name(&self) -> &str {
        &self.name
    }
}
