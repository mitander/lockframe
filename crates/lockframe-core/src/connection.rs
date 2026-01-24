//! Session layer state machine.
//!
//! Manages connection lifecycle, heartbeats, timeouts, and graceful shutdown.
//! Uses the action pattern: methods take time as input and return actions for
//! the driver to execute. This keeps the state machine pure (no I/O) and makes
//! testing straightforward.
//!
//! # State Machine
//!
//! ```text
//! ┌──────┐  Hello   ┌──────────┐   HelloReply    ┌───────────────┐
//! │ Init │─────────>│ Pending  │────────────────>│ Authenticated │
//! └──────┘          └──────────┘                 └───────────────┘
//!                        │                               │
//!                        │ Timeout/Error                 │ Goodbye/Timeout
//!                        ↓                               ↓
//!                   ┌────────┐                      ┌────────┐
//!                   │ Closed │<─────────────────────│ Closed │
//!                   └────────┘                      └────────┘
//! ```

use std::{
    ops::Sub,
    time::{Duration, Instant},
};

use lockframe_proto::{
    Frame, FrameHeader, Opcode, Payload,
    payloads::session::{Goodbye, Hello, HelloReply},
};

use crate::error::ConnectionError;

/// Time allowed to complete the Hello/HelloReply handshake.
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum time allowed without any activity before the connection is closed.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Interval at which the connection sends Ping frames while authenticated.
pub const DEFAULT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(20);

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
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            heartbeat_interval: DEFAULT_HEARTBEAT_INTERVAL,
        }
    }
}

/// Connection state machine
///
/// Manages lifecycle, timeouts, and heartbeats for a single connection.
///
/// This is a pure state machine - no I/O, no Environment storage.
/// Time is passed as parameters to methods that need it.
///
/// Generic over `Instant` to support both real time and virtual time for
/// deterministic testing.
#[derive(Debug, Clone)]
pub struct Connection<I = Instant>
where
    I: Copy + Ord + Send + Sync + Sub<Output = Duration>,
{
    /// Current state
    state: ConnectionState,
    /// Configuration
    config: ConnectionConfig,
    /// Last activity timestamp
    last_activity: I,
    /// Last heartbeat sent timestamp
    last_heartbeat: Option<I>,
    /// Session ID (assigned by server)
    session_id: Option<u64>,
    /// Client's sender ID (from Hello frame, used for KeyPackage registry)
    client_sender_id: Option<u64>,
}

impl<I> Connection<I>
where
    I: Copy + Ord + Send + Sync + Sub<Output = Duration>,
{
    /// Create a new connection in [`ConnectionState::Init`] state
    pub fn new(now: I, config: ConnectionConfig) -> Self {
        Self {
            state: ConnectionState::Init,
            config,
            last_activity: now,
            last_heartbeat: None,
            session_id: None,
            client_sender_id: None,
        }
    }

    /// Current connection state
    #[must_use]
    pub fn state(&self) -> ConnectionState {
        self.state
    }

    /// Session ID assigned by server. `None` if not authenticated.
    #[must_use]
    pub fn session_id(&self) -> Option<u64> {
        self.session_id
    }

    /// Client's sender ID from Hello frame. `None` if not provided.
    ///
    /// Used for KeyPackage registry lookup. Falls back to session_id if not
    /// set.
    #[must_use]
    pub fn client_sender_id(&self) -> Option<u64> {
        self.client_sender_id
    }

    /// Maximum time allowed for handshake completion.
    #[must_use]
    pub fn handshake_timeout(&self) -> Duration {
        self.config.handshake_timeout
    }

    /// Assign session ID (server use only, before handling Hello).
    ///
    /// The server should generate a random session ID and set it before
    /// handling an incoming Hello frame. The state machine will use this
    /// ID when constructing the HelloReply.
    pub fn set_session_id(&mut self, session_id: u64) {
        self.session_id = Some(session_id);
    }

    /// Initiate handshake (client use).
    ///
    /// Transitions to Pending state and returns SendFrame(Hello) action.
    ///
    /// # Errors
    ///
    /// - `ConnectionError::InvalidState` if not in Init state
    pub fn send_hello(&mut self, now: I) -> Result<Vec<ConnectionAction>, ConnectionError> {
        if self.state != ConnectionState::Init {
            return Err(ConnectionError::InvalidState {
                state: self.state,
                operation: "send_hello".to_string(),
            });
        }

        self.state = ConnectionState::Pending;
        self.last_activity = now;

        let hello = Payload::Hello(Hello {
            version: 1,
            capabilities: vec![],
            sender_id: None,
            auth_token: None,
        });
        let frame = hello.into_frame(FrameHeader::new(Opcode::Hello))?;

        Ok(vec![ConnectionAction::SendFrame(frame)])
    }

    /// Process incoming Hello and generate session ID (server use).
    ///
    /// Transitions to Authenticated and returns SendFrame(HelloReply).
    ///
    /// # Errors
    ///
    /// - `ConnectionError::InvalidState` if not in Init state
    /// - `ConnectionError::UnsupportedVersion` if version ≠ 1
    pub fn handle_hello<E: crate::env::Environment>(
        &mut self,
        hello: &Hello,
        env: &E,
        now: I,
    ) -> Result<Vec<ConnectionAction>, ConnectionError> {
        if self.state != ConnectionState::Init {
            return Err(ConnectionError::InvalidState {
                state: self.state,
                operation: "handle_hello".to_string(),
            });
        }

        if hello.version != 1 {
            return Err(ConnectionError::UnsupportedVersion(hello.version));
        }

        let session_id = env.random_u64();
        debug_assert_ne!(session_id, 0);

        self.session_id = Some(session_id);
        self.state = ConnectionState::Authenticated;
        self.last_activity = now;

        let reply =
            Payload::HelloReply(HelloReply { session_id, capabilities: vec![], challenge: None });

        let frame = reply.into_frame(FrameHeader::new(Opcode::HelloReply))?;

        Ok(vec![ConnectionAction::SendFrame(frame)])
    }

    /// Mark connection as closed.
    pub fn close(&mut self) {
        self.state = ConnectionState::Closed;
    }

    /// Mark connection as active (call when receiving frames).
    pub fn update_activity(&mut self, now: I) {
        self.last_activity = now;
    }

    /// Elapsed time since last activity, if timeout exceeded. `None` otherwise.
    #[must_use]
    pub fn check_timeout(&self, now: I) -> Option<Duration> {
        let elapsed = now - self.last_activity;

        let timeout = match self.state {
            ConnectionState::Pending => self.config.handshake_timeout,
            ConnectionState::Authenticated => self.config.idle_timeout,
            _ => return None,
        };

        if elapsed > timeout { Some(elapsed) } else { None }
    }

    /// Process periodic maintenance (timeouts and heartbeats).
    ///
    /// Call this periodically to trigger timeout detection and heartbeat
    /// sending.
    pub fn tick(&mut self, now: I) -> Vec<ConnectionAction> {
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

        if self.state == ConnectionState::Authenticated {
            let should_send = match self.last_heartbeat {
                None => true, // Never sent heartbeat
                Some(last) => {
                    let elapsed = now - last;
                    elapsed >= self.config.heartbeat_interval
                },
            };

            if should_send {
                let ping_header = FrameHeader::new(lockframe_proto::Opcode::Ping);
                let ping_frame = Frame::new(ping_header, Vec::new());

                actions.push(ConnectionAction::SendFrame(ping_frame));
                self.last_heartbeat = Some(now);
                self.last_activity = now;
            }
        }

        actions
    }

    /// Process incoming frame and update state.
    ///
    /// # Errors
    ///
    /// - `ConnectionError::UnexpectedFrame` if opcode invalid for current state
    /// - `ConnectionError::InvalidPayload` if CBOR deserialization fails
    /// - `ConnectionError::UnsupportedVersion` if Hello version ≠ 1
    /// - `ConnectionError::Protocol` if server session_id not set
    pub fn handle_frame(
        &mut self,
        frame: &Frame,
        now: I,
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

                        let Some(session_id) = self.session_id else {
                            return Err(ConnectionError::Protocol(
                                "server must set session_id before handling Hello".to_string(),
                            ));
                        };

                        debug_assert_ne!(session_id, 0);

                        self.client_sender_id = hello.sender_id;
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
    use crate::env::Environment;

    #[derive(Clone)]
    struct TestEnv;

    impl crate::env::Environment for TestEnv {
        type Instant = Instant;
        fn now(&self) -> Instant {
            Instant::now()
        }

        fn sleep(&self, _duration: Duration) -> impl std::future::Future<Output = ()> + Send {
            async {}
        }

        fn random_bytes(&self, buffer: &mut [u8]) {
            // Deterministic for tests
            for (i, byte) in buffer.iter_mut().enumerate() {
                *byte = i as u8;
            }
        }
    }

    #[test]
    fn connection_lifecycle() {
        let env = TestEnv;
        let t0 = env.now();
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
    fn handle_ping_responds_with_pong() {
        let env = TestEnv;
        let t0 = env.now();
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
        let ping_header = FrameHeader::new(lockframe_proto::Opcode::Ping);
        let ping_frame = Frame::new(ping_header, Vec::new());

        // Handle Ping - should return Pong action
        let actions = conn.handle_frame(&ping_frame, t0).unwrap();
        assert_eq!(actions.len(), 1);

        match &actions[0] {
            ConnectionAction::SendFrame(frame) => {
                assert_eq!(frame.header.opcode_enum(), Some(lockframe_proto::Opcode::Pong));
                assert_eq!(frame.payload.len(), 0);
            },
            _ => panic!("Expected SendFrame action with Pong"),
        }
    }

    #[test]
    fn handle_pong_updates_activity() {
        let env = TestEnv;
        let t0 = env.now();
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
        let pong_header = FrameHeader::new(lockframe_proto::Opcode::Pong);
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
        let env = TestEnv;
        let t0 = env.now();
        let mut conn = Connection::new(t0, ConnectionConfig::default());

        // Create a Ping frame
        let ping_header = FrameHeader::new(lockframe_proto::Opcode::Ping);
        let ping_frame = Frame::new(ping_header, Vec::new());

        // Should fail - not authenticated yet
        let result = conn.handle_frame(&ping_frame, t0);
        assert!(matches!(result, Err(ConnectionError::UnexpectedFrame { .. })));
    }

    #[test]
    fn server_handle_hello() {
        let env = TestEnv;
        let t0 = env.now();
        let mut conn = Connection::new(t0, ConnectionConfig::default());

        // Server sets session ID
        conn.set_session_id(0x1234_5678_9ABC_DEF0);

        // Create Hello frame
        let hello = Payload::Hello(Hello {
            version: 1,
            capabilities: vec![],
            sender_id: None,
            auth_token: None,
        });
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
        let env = TestEnv;
        let t0 = env.now();
        let mut conn = Connection::new(t0, ConnectionConfig::default());

        // Don't set session ID - should fail

        let hello = Payload::Hello(Hello {
            version: 1,
            capabilities: vec![],
            sender_id: None,
            auth_token: None,
        });
        let hello_frame = hello.into_frame(FrameHeader::new(Opcode::Hello)).unwrap();

        let result = conn.handle_frame(&hello_frame, t0);
        assert!(matches!(result, Err(ConnectionError::Protocol(_))));
    }

    #[test]
    fn server_hello_unsupported_version() {
        let env = TestEnv;
        let t0 = env.now();
        let mut conn = Connection::new(t0, ConnectionConfig::default());
        conn.set_session_id(12345);

        let hello = Payload::Hello(Hello {
            version: 99, // Unsupported version
            capabilities: vec![],
            sender_id: None,
            auth_token: None,
        });
        let hello_frame = hello.into_frame(FrameHeader::new(Opcode::Hello)).unwrap();

        let result = conn.handle_frame(&hello_frame, t0);
        assert!(matches!(result, Err(ConnectionError::UnsupportedVersion(99))));
    }

    #[test]
    fn server_generates_session_id_from_environment() {
        let env = TestEnv;
        let t0 = env.now();
        let mut conn = Connection::new(t0, ConnectionConfig::default());

        // Create Hello message
        let hello = Hello { version: 1, capabilities: vec![], sender_id: None, auth_token: None };

        // Call handle_hello() with Hello struct directly
        let actions = conn.handle_hello(&hello, &env, t0).unwrap();

        // Assert actions contain SendFrame with HelloReply
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            ConnectionAction::SendFrame(frame) => {
                assert_eq!(frame.header.opcode_enum(), Some(Opcode::HelloReply));

                // Verify HelloReply contains session_id
                let payload = Payload::from_frame(frame.clone()).unwrap();
                match payload {
                    Payload::HelloReply(reply) => {
                        assert_ne!(reply.session_id, 0);
                    },
                    _ => panic!("Expected HelloReply payload"),
                }
            },
            _ => panic!("Expected SendFrame action"),
        }

        // Assert session_id is Some()
        assert!(conn.session_id().is_some());
    }

    #[test]
    fn handle_hello_rejects_unsupported_version() {
        let env = TestEnv;
        let t0 = env.now();
        let mut conn = Connection::new(t0, ConnectionConfig::default());

        let hello = Hello { version: 99, capabilities: vec![], sender_id: None, auth_token: None };

        let result = conn.handle_hello(&hello, &env, t0);
        assert!(matches!(result, Err(ConnectionError::UnsupportedVersion(99))));
    }

    #[test]
    fn handle_hello_rejects_if_not_init_state() {
        let env = TestEnv;
        let t0 = env.now();
        let mut conn = Connection::new(t0, ConnectionConfig::default());

        // Move to Authenticated state by sending hello and receiving reply
        conn.send_hello(t0).unwrap();
        let reply = Payload::HelloReply(HelloReply {
            session_id: 12345,
            capabilities: vec![],
            challenge: None,
        });
        let reply_frame = reply.into_frame(FrameHeader::new(Opcode::HelloReply)).unwrap();
        conn.handle_frame(&reply_frame, t0).unwrap();
        assert_eq!(conn.state(), ConnectionState::Authenticated);

        // Now try to handle Hello in Authenticated state - should fail
        let hello = Hello { version: 1, capabilities: vec![], sender_id: None, auth_token: None };

        let result = conn.handle_hello(&hello, &env, t0);
        assert!(matches!(result, Err(ConnectionError::InvalidState { .. })));
    }

    #[test]
    fn handle_goodbye_authenticated() {
        let env = TestEnv;
        let t0 = env.now();
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
        let env = TestEnv;
        let t0 = env.now();
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
        let env = TestEnv;
        let t0 = env.now();
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
