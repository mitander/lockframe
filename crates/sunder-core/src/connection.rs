//! Connection state machine for Sunder protocol.
//!
//! This module implements the session layer - managing connection lifecycle,
//! heartbeats, timeouts, and graceful shutdown.
//!
//! # Architecture: Action-Based State Machine
//!
//! This state machine follows the action pattern:
//! - Methods accept time as parameter (no stored Environment)
//! - Methods return `Result<Vec<ConnectionAction>, ConnectionError>`
//! - Driver code executes actions (send frames, close connection, etc.)
//!
//! This enables:
//! - Pure state machine logic (no I/O)
//! - Easy testing (no mocking time/RNG)
//! - Composability (multiple connections can share one Environment)
//!
//! # State Machine
//!
//! ```text
//! ┌──────┐  Hello   ┌──────────┐  Authenticated  ┌───────────────┐
//! │ Init │─────────>│ Pending  │────────────────>│ Authenticated │
//! └──────┘          └──────────┘                 └───────────────┘
//!                        │                               │
//!                        │ Timeout/Error                 │ Goodbye/Timeout
//!                        ↓                               ↓
//!                   ┌────────┐                      ┌────────┐
//!                   │ Closed │<─────────────────────│ Closed │
//!                   └────────┘                      └────────┘
//! ```
//!
//! # Lifecycle
//!
//! 1. **Init**: Connection created, no handshake yet
//! 2. **Pending**: Hello sent, waiting for HelloReply
//! 3. **Authenticated**: HelloReply received, ready for messages
//! 4. **Closed**: Connection terminated (graceful or error)
//!
//! # Timeouts
//!
//! - **Handshake timeout**: 30 seconds to complete Hello/HelloReply
//! - **Idle timeout**: 60 seconds without any activity
//! - **Heartbeat interval**: 20 seconds (sends Ping to keep alive)

use std::time::{Duration, Instant};

use sunder_proto::{
    Frame, FrameHeader, Opcode, Payload,
    payloads::session::{Goodbye, Hello, HelloReply},
};

use crate::error::ConnectionError;

/// Actions returned by the connection state machine.
///
/// The driver (test harness or production server) executes these actions:
/// - `SendFrame`: Serialize and send the frame over the transport
/// - `Close`: Close the connection with the given reason
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionAction {
    /// Send this frame to the peer
    SendFrame(Frame),

    /// Close the connection with this reason
    Close {
        /// Reason for closing the connection
        reason: String,
    },
}

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Initial state - no handshake started
    Init,
    /// Hello sent, waiting for HelloReply
    Pending,
    /// HelloReply received, connection authenticated
    Authenticated,
    /// Connection closed (graceful or error)
    Closed,
}

/// Connection configuration
#[derive(Debug, Clone)]
pub struct ConnectionConfig {
    /// Timeout for completing handshake
    pub handshake_timeout: Duration,
    /// Idle timeout before disconnecting
    pub idle_timeout: Duration,
    /// Heartbeat interval (should be < idle_timeout / 2)
    pub heartbeat_interval: Duration,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            handshake_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(60),
            heartbeat_interval: Duration::from_secs(20),
        }
    }
}

/// Connection state machine
///
/// Manages lifecycle, timeouts, and heartbeats for a single connection.
///
/// This is a pure state machine - no I/O, no Environment storage.
/// Time is passed as parameters to methods that need it.
#[derive(Debug, Clone)]
pub struct Connection {
    /// Current state
    state: ConnectionState,
    /// Configuration
    config: ConnectionConfig,
    /// Last activity timestamp
    last_activity: Instant,
    /// Last heartbeat sent timestamp
    last_heartbeat: Option<Instant>,
    /// Session ID (assigned by server)
    session_id: Option<u64>,
}

impl Connection {
    /// Create a new connection in [`ConnectionState::Init`] state
    pub fn new(now: Instant, config: ConnectionConfig) -> Self {
        Self {
            state: ConnectionState::Init,
            config,
            last_activity: now,
            last_heartbeat: None,
            session_id: None,
        }
    }

    /// Get current state
    #[must_use]
    pub fn state(&self) -> ConnectionState {
        self.state
    }

    /// Get session ID (if authenticated)
    #[must_use]
    pub fn session_id(&self) -> Option<u64> {
        self.session_id
    }

    /// Set session ID (server use: before handling Hello)
    ///
    /// The server should generate a random session ID and set it before
    /// handling an incoming Hello frame. The state machine will use this
    /// ID when constructing the HelloReply.
    pub fn set_session_id(&mut self, session_id: u64) {
        self.session_id = Some(session_id);
    }

    /// Client: initiate handshake
    ///
    /// Transitions to Pending state and returns SendFrame(Hello) action.
    ///
    /// # Errors
    ///
    /// Returns `InvalidState` if not in Init state
    pub fn send_hello(&mut self, now: Instant) -> Result<Vec<ConnectionAction>, ConnectionError> {
        if self.state != ConnectionState::Init {
            return Err(ConnectionError::InvalidState {
                state: self.state,
                operation: "send_hello".to_string(),
            });
        }

        self.state = ConnectionState::Pending;
        self.last_activity = now;

        let hello = Payload::Hello(Hello { version: 1, capabilities: vec![], auth_token: None });
        let frame = hello.into_frame(FrameHeader::new(Opcode::Hello))?;

        Ok(vec![ConnectionAction::SendFrame(frame)])
    }

    /// Transition to Closed state
    pub fn close(&mut self) {
        self.state = ConnectionState::Closed;
    }

    /// Update last activity timestamp
    ///
    /// Call this when receiving any frame from peer.
    pub fn update_activity(&mut self, now: Instant) {
        self.last_activity = now;
    }

    /// Check if connection has timed out
    ///
    /// Returns `Some(elapsed)` if timed out, `None` otherwise
    #[must_use]
    pub fn check_timeout(&self, now: Instant) -> Option<Duration> {
        let elapsed = now.duration_since(self.last_activity);

        let timeout = match self.state {
            ConnectionState::Pending => self.config.handshake_timeout,
            ConnectionState::Authenticated => self.config.idle_timeout,
            _ => return None,
        };

        if elapsed > timeout { Some(elapsed) } else { None }
    }

    /// Tick the state machine - check for timeouts and heartbeats
    ///
    /// Call this periodically to handle:
    /// - Timeout detection
    /// - Heartbeat sending
    ///
    /// Returns actions to execute
    pub fn tick(&mut self, now: Instant) -> Vec<ConnectionAction> {
        let mut actions = Vec::new();

        // Check for timeout
        if let Some(elapsed) = self.check_timeout(now) {
            let reason = match self.state {
                ConnectionState::Pending => format!("handshake timeout after {:?}", elapsed),
                ConnectionState::Authenticated => format!("idle timeout after {:?}", elapsed),
                _ => "timeout".to_string(),
            };

            self.close();
            actions.push(ConnectionAction::Close { reason });
            return actions;
        }

        // Check if we should send heartbeat
        if self.state == ConnectionState::Authenticated {
            let should_send = match self.last_heartbeat {
                None => true, // Never sent heartbeat
                Some(last) => {
                    let elapsed = now.duration_since(last);
                    elapsed >= self.config.heartbeat_interval
                },
            };

            if should_send {
                let ping_header = FrameHeader::new(sunder_proto::Opcode::Ping);
                let ping_frame = Frame::new(ping_header, Vec::new());

                actions.push(ConnectionAction::SendFrame(ping_frame));
                self.last_heartbeat = Some(now);
                self.last_activity = now;
            }
        }

        actions
    }

    /// Process a frame received from the peer and return actions.
    ///
    /// # Errors
    ///
    /// Returns error if frame is unexpected for current state or malformed
    pub fn handle_frame(
        &mut self,
        frame: &Frame,
        now: Instant,
    ) -> Result<Vec<ConnectionAction>, ConnectionError> {
        self.last_activity = now;

        let Some(opcode) = frame.header.opcode_enum() else {
            return Err(ConnectionError::UnexpectedFrame {
                state: self.state,
                opcode: frame.header.opcode(),
            });
        };

        match (self.state, opcode) {
            // Server: receive Hello in Init state
            (ConnectionState::Init, Opcode::Hello) => {
                let payload = Payload::from_frame(frame.clone())?;

                match payload {
                    Payload::Hello(hello) => {
                        if hello.version != 1 {
                            return Err(ConnectionError::UnsupportedVersion(hello.version));
                        }

                        // Server must have session_id set before handling Hello
                        let Some(session_id) = self.session_id else {
                            return Err(ConnectionError::Protocol(
                                "server must set session_id before handling Hello".to_string(),
                            ));
                        };

                        self.state = ConnectionState::Authenticated;

                        let reply = Payload::HelloReply(HelloReply {
                            session_id,
                            capabilities: vec![],
                            challenge: None,
                        });

                        let frame = reply.into_frame(FrameHeader::new(Opcode::HelloReply))?;

                        Ok(vec![ConnectionAction::SendFrame(frame)])
                    },
                    _ => Err(ConnectionError::InvalidPayload {
                        expected: "Hello",
                        opcode: Opcode::Hello.to_u16(),
                    }),
                }
            },

            // Client: receive HelloReply in Pending state
            (ConnectionState::Pending, Opcode::HelloReply) => {
                let payload = Payload::from_frame(frame.clone())?;

                match payload {
                    Payload::HelloReply(reply) => {
                        self.state = ConnectionState::Authenticated;
                        self.session_id = Some(reply.session_id);

                        Ok(vec![]) // No response needed
                    },
                    _ => Err(ConnectionError::InvalidPayload {
                        expected: "HelloReply",
                        opcode: Opcode::HelloReply.to_u16(),
                    }),
                }
            },

            // Both: Ping when Authenticated
            (ConnectionState::Authenticated, Opcode::Ping) => {
                let pong_header = FrameHeader::new(Opcode::Pong);
                let pong_frame = Frame::new(pong_header, Vec::new());
                Ok(vec![ConnectionAction::SendFrame(pong_frame)])
            },

            // Both: Pong when Authenticated
            (ConnectionState::Authenticated, Opcode::Pong) => {
                // Activity already updated
                Ok(vec![])
            },

            // Both: Goodbye (any state except Closed)
            (state, Opcode::Goodbye) if state != ConnectionState::Closed => {
                let payload = Payload::from_frame(frame.clone())?;

                let reason = match payload {
                    Payload::Goodbye(goodbye) => goodbye.reason,
                    _ => {
                        return Err(ConnectionError::InvalidPayload {
                            expected: "Goodbye",
                            opcode: Opcode::Goodbye.to_u16(),
                        });
                    },
                };

                self.state = ConnectionState::Closed;

                let reply = Payload::Goodbye(Goodbye { reason: "ack".to_string() });
                let frame = reply.into_frame(FrameHeader::new(Opcode::Goodbye))?;

                Ok(vec![ConnectionAction::SendFrame(frame), ConnectionAction::Close {
                    reason: format!("peer goodbye: {}", reason),
                }])
            },

            // Both: Error frame
            (_, Opcode::Error) => {
                self.state = ConnectionState::Closed;

                Ok(vec![ConnectionAction::Close { reason: "peer error".to_string() }])
            },

            // Default: unexpected frame for current state
            (state, opcode) => {
                Err(ConnectionError::UnexpectedFrame { state, opcode: opcode.to_u16() })
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_lifecycle() {
        let t0 = Instant::now();
        let mut conn = Connection::new(t0, ConnectionConfig::default());

        // Initial state
        assert_eq!(conn.state(), ConnectionState::Init);
        assert_eq!(conn.session_id(), None);

        // Send Hello
        let actions = conn.send_hello(t0).unwrap();
        assert_eq!(conn.state(), ConnectionState::Pending);
        assert_eq!(actions.len(), 1); // Returns SendFrame(Hello) action
        assert!(matches!(actions[0], ConnectionAction::SendFrame(_)));

        // Receive HelloReply
        let reply = Payload::HelloReply(HelloReply {
            session_id: 12345,
            capabilities: vec![],
            challenge: None,
        });
        let reply_frame = reply.into_frame(FrameHeader::new(Opcode::HelloReply)).unwrap();
        let actions = conn.handle_frame(&reply_frame, t0).unwrap();
        assert_eq!(conn.state(), ConnectionState::Authenticated);
        assert_eq!(conn.session_id(), Some(12345));
        assert!(actions.is_empty());

        // Close
        conn.close();
        assert_eq!(conn.state(), ConnectionState::Closed);
    }

    #[test]
    fn heartbeat_timing() {
        let t0 = Instant::now();
        let config =
            ConnectionConfig { heartbeat_interval: Duration::from_secs(20), ..Default::default() };
        let mut conn = Connection::new(t0, config);

        // Move to authenticated
        conn.send_hello(t0).unwrap();
        let reply = Payload::HelloReply(HelloReply {
            session_id: 12345,
            capabilities: vec![],
            challenge: None,
        });
        let reply_frame = reply.into_frame(FrameHeader::new(Opcode::HelloReply)).unwrap();
        conn.handle_frame(&reply_frame, t0).unwrap();

        // Tick immediately - should send first heartbeat
        let t1 = t0;
        let actions = conn.tick(t1);
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], ConnectionAction::SendFrame(_)));

        // Tick again immediately - should NOT send (too soon)
        let t2 = t1 + Duration::from_secs(1);
        let actions = conn.tick(t2);
        assert!(actions.is_empty());

        // Advance time past heartbeat interval
        let t3 = t1 + Duration::from_secs(21);
        let actions = conn.tick(t3);
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], ConnectionAction::SendFrame(_)));
    }

    #[test]
    fn handshake_timeout() {
        let t0 = Instant::now();
        let config =
            ConnectionConfig { handshake_timeout: Duration::from_secs(30), ..Default::default() };
        let mut conn = Connection::new(t0, config);

        conn.send_hello(t0).unwrap();

        // Check timeout immediately - should be fine
        assert!(conn.check_timeout(t0).is_none());

        // Advance time past handshake timeout
        let t1 = t0 + Duration::from_secs(31);
        let elapsed = conn.check_timeout(t1);
        assert!(elapsed.is_some());
        assert!(elapsed.unwrap() > Duration::from_secs(30));

        // Tick should close connection
        let actions = conn.tick(t1);
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], ConnectionAction::Close { .. }));
        assert_eq!(conn.state(), ConnectionState::Closed);
    }

    #[test]
    fn idle_timeout() {
        let t0 = Instant::now();
        let config =
            ConnectionConfig { idle_timeout: Duration::from_secs(60), ..Default::default() };
        let mut conn = Connection::new(t0, config);

        // Move to authenticated
        conn.send_hello(t0).unwrap();
        let reply = Payload::HelloReply(HelloReply {
            session_id: 12345,
            capabilities: vec![],
            challenge: None,
        });
        let reply_frame = reply.into_frame(FrameHeader::new(Opcode::HelloReply)).unwrap();
        conn.handle_frame(&reply_frame, t0).unwrap();

        // Check timeout immediately - should be fine
        assert!(conn.check_timeout(t0).is_none());

        // Advance time past idle timeout
        let t1 = t0 + Duration::from_secs(61);
        let elapsed = conn.check_timeout(t1);
        assert!(elapsed.is_some());

        // Tick should close connection
        let actions = conn.tick(t1);
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], ConnectionAction::Close { .. }));
        assert_eq!(conn.state(), ConnectionState::Closed);
    }

    #[test]
    fn invalid_state_transitions() {
        let t0 = Instant::now();
        let mut conn = Connection::new(t0, ConnectionConfig::default());

        // Can't receive HelloReply from Init
        let reply = Payload::HelloReply(HelloReply {
            session_id: 12345,
            capabilities: vec![],
            challenge: None,
        });
        let reply_frame = reply.into_frame(FrameHeader::new(Opcode::HelloReply)).unwrap();
        let result = conn.handle_frame(&reply_frame, t0);
        assert!(matches!(result, Err(ConnectionError::UnexpectedFrame { .. })));

        // Can't send Hello twice
        conn.send_hello(t0).unwrap();
        let result = conn.send_hello(t0);
        assert!(matches!(result, Err(ConnectionError::InvalidState { .. })));
    }

    #[test]
    fn handle_ping_responds_with_pong() {
        let t0 = Instant::now();
        let mut conn = Connection::new(t0, ConnectionConfig::default());

        // Move to authenticated
        conn.send_hello(t0).unwrap();
        let reply = Payload::HelloReply(HelloReply {
            session_id: 12345,
            capabilities: vec![],
            challenge: None,
        });
        let reply_frame = reply.into_frame(FrameHeader::new(Opcode::HelloReply)).unwrap();
        conn.handle_frame(&reply_frame, t0).unwrap();

        // Create a Ping frame
        let ping_header = FrameHeader::new(sunder_proto::Opcode::Ping);
        let ping_frame = Frame::new(ping_header, Vec::new());

        // Handle Ping - should return Pong action
        let actions = conn.handle_frame(&ping_frame, t0).unwrap();
        assert_eq!(actions.len(), 1);

        match &actions[0] {
            ConnectionAction::SendFrame(frame) => {
                assert_eq!(frame.header.opcode_enum(), Some(sunder_proto::Opcode::Pong));
                assert_eq!(frame.payload.len(), 0);
            },
            _ => panic!("Expected SendFrame action with Pong"),
        }
    }

    #[test]
    fn handle_pong_updates_activity() {
        let t0 = Instant::now();
        let mut conn = Connection::new(t0, ConnectionConfig::default());

        // Move to authenticated
        conn.send_hello(t0).unwrap();
        let reply = Payload::HelloReply(HelloReply {
            session_id: 12345,
            capabilities: vec![],
            challenge: None,
        });
        let reply_frame = reply.into_frame(FrameHeader::new(Opcode::HelloReply)).unwrap();
        conn.handle_frame(&reply_frame, t0).unwrap();

        // Create a Pong frame
        let pong_header = FrameHeader::new(sunder_proto::Opcode::Pong);
        let pong_frame = Frame::new(pong_header, Vec::new());

        // Handle Pong
        let t1 = t0 + Duration::from_secs(30);
        let actions = conn.handle_frame(&pong_frame, t1).unwrap();
        assert!(actions.is_empty());

        // Activity should be updated (not timed out)
        let t2 = t1 + Duration::from_secs(40); // 40s after Pong, but only 10s from last activity
        assert!(conn.check_timeout(t2).is_none());
    }

    #[test]
    fn handle_ping_before_authenticated() {
        let t0 = Instant::now();
        let mut conn = Connection::new(t0, ConnectionConfig::default());

        // Create a Ping frame
        let ping_header = FrameHeader::new(sunder_proto::Opcode::Ping);
        let ping_frame = Frame::new(ping_header, Vec::new());

        // Should fail - not authenticated yet
        let result = conn.handle_frame(&ping_frame, t0);
        assert!(matches!(result, Err(ConnectionError::UnexpectedFrame { .. })));
    }

    #[test]
    fn server_handle_hello() {
        let t0 = Instant::now();
        let mut conn = Connection::new(t0, ConnectionConfig::default());

        // Server sets session ID
        conn.set_session_id(0x1234_5678_9ABC_DEF0);

        // Create Hello frame
        let hello = Payload::Hello(Hello { version: 1, capabilities: vec![], auth_token: None });
        let hello_frame = hello.into_frame(FrameHeader::new(Opcode::Hello)).unwrap();

        // Handle Hello - should return HelloReply action
        let actions = conn.handle_frame(&hello_frame, t0).unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(conn.state(), ConnectionState::Authenticated);
        assert_eq!(conn.session_id(), Some(0x1234_5678_9ABC_DEF0));

        match &actions[0] {
            ConnectionAction::SendFrame(frame) => {
                assert_eq!(frame.header.opcode_enum(), Some(Opcode::HelloReply));

                // Verify HelloReply contains correct session_id
                let payload = Payload::from_frame(frame.clone()).unwrap();
                match payload {
                    Payload::HelloReply(reply) => {
                        assert_eq!(reply.session_id, 0x1234_5678_9ABC_DEF0);
                    },
                    _ => panic!("Expected HelloReply payload"),
                }
            },
            _ => panic!("Expected SendFrame action"),
        }
    }

    #[test]
    fn server_hello_without_session_id() {
        let t0 = Instant::now();
        let mut conn = Connection::new(t0, ConnectionConfig::default());

        // Don't set session ID - should fail

        let hello = Payload::Hello(Hello { version: 1, capabilities: vec![], auth_token: None });
        let hello_frame = hello.into_frame(FrameHeader::new(Opcode::Hello)).unwrap();

        let result = conn.handle_frame(&hello_frame, t0);
        assert!(matches!(result, Err(ConnectionError::Protocol(_))));
    }

    #[test]
    fn server_hello_unsupported_version() {
        let t0 = Instant::now();
        let mut conn = Connection::new(t0, ConnectionConfig::default());
        conn.set_session_id(12345);

        let hello = Payload::Hello(Hello {
            version: 99, // Unsupported version
            capabilities: vec![],
            auth_token: None,
        });
        let hello_frame = hello.into_frame(FrameHeader::new(Opcode::Hello)).unwrap();

        let result = conn.handle_frame(&hello_frame, t0);
        assert!(matches!(result, Err(ConnectionError::UnsupportedVersion(99))));
    }

    #[test]
    fn handle_goodbye_authenticated() {
        let t0 = Instant::now();
        let mut conn = Connection::new(t0, ConnectionConfig::default());

        // Move to authenticated
        conn.send_hello(t0).unwrap();
        let reply = Payload::HelloReply(HelloReply {
            session_id: 12345,
            capabilities: vec![],
            challenge: None,
        });
        let reply_frame = reply.into_frame(FrameHeader::new(Opcode::HelloReply)).unwrap();
        conn.handle_frame(&reply_frame, t0).unwrap();

        // Send Goodbye
        let goodbye = Payload::Goodbye(Goodbye { reason: "client shutdown".to_string() });
        let goodbye_frame = goodbye.into_frame(FrameHeader::new(Opcode::Goodbye)).unwrap();

        let actions = conn.handle_frame(&goodbye_frame, t0).unwrap();
        assert_eq!(conn.state(), ConnectionState::Closed);
        assert_eq!(actions.len(), 2);

        // Should send Goodbye ack and Close
        assert!(matches!(actions[0], ConnectionAction::SendFrame(_)));
        assert!(matches!(actions[1], ConnectionAction::Close { .. }));
    }

    #[test]
    fn handle_goodbye_pending() {
        let t0 = Instant::now();
        let mut conn = Connection::new(t0, ConnectionConfig::default());

        // Move to pending
        conn.send_hello(t0).unwrap();

        // Send Goodbye while still pending
        let goodbye = Payload::Goodbye(Goodbye { reason: "timeout".to_string() });
        let goodbye_frame = goodbye.into_frame(FrameHeader::new(Opcode::Goodbye)).unwrap();

        let actions = conn.handle_frame(&goodbye_frame, t0).unwrap();
        assert_eq!(conn.state(), ConnectionState::Closed);
        assert_eq!(actions.len(), 2);
    }

    #[test]
    fn handle_error_frame() {
        let t0 = Instant::now();
        let mut conn = Connection::new(t0, ConnectionConfig::default());

        // Move to authenticated
        conn.send_hello(t0).unwrap();
        let reply = Payload::HelloReply(HelloReply {
            session_id: 12345,
            capabilities: vec![],
            challenge: None,
        });
        let reply_frame = reply.into_frame(FrameHeader::new(Opcode::HelloReply)).unwrap();
        conn.handle_frame(&reply_frame, t0).unwrap();

        // Receive Error frame
        let error_header = FrameHeader::new(Opcode::Error);
        let error_frame = Frame::new(error_header, Vec::new());

        let actions = conn.handle_frame(&error_frame, t0).unwrap();
        assert_eq!(conn.state(), ConnectionState::Closed);
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], ConnectionAction::Close { .. }));
    }
}
