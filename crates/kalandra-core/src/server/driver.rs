//! Server driver - Sans-IO orchestrator for the server.
//!
//! The ServerDriver ties together the core components:
//! - Connection state machines (session layer)
//! - RoomManager (group layer with MLS validation)
//! - ConnectionRegistry (session↔room mapping)
//! - Storage (persistence)
//!
//! # Architecture
//!
//! ```text
//! ServerDriver
//!   ├─ connections: HashMap<u64, Connection>
//!   ├─ registry: ConnectionRegistry
//!   ├─ room_manager: RoomManager
//!   └─ storage: S (impl Storage)
//! ```
//!
//! # Event Flow
//!
//! 1. External runtime produces `ServerEvent`s (connection accepted, frame
//!    received)
//! 2. ServerDriver processes events and produces `ServerAction`s
//! 3. ActionExecutor (runtime-specific) executes actions

use std::{collections::HashMap, ops::Sub, time::Duration};

use kalandra_proto::{Frame, FrameHeader, Opcode, Payload, payloads::session::SyncResponse};

use super::{
    error::ServerError,
    registry::{ConnectionRegistry, SessionInfo},
};
use crate::{
    connection::{Connection, ConnectionAction, ConnectionConfig},
    env::Environment,
    mls::MlsGroupState,
    room_manager::{RoomAction, RoomManager},
    storage::Storage,
};

/// Server configuration
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Connection configuration (timeouts, heartbeat interval)
    pub connection: ConnectionConfig,
    /// Maximum concurrent connections
    pub max_connections: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self { connection: ConnectionConfig::default(), max_connections: 10_000 }
    }
}

/// Events that the server driver processes.
///
/// These are produced by the external runtime (simulation or production).
#[derive(Debug, Clone)]
pub enum ServerEvent {
    /// A new connection was accepted
    ConnectionAccepted {
        /// Unique connection ID assigned by the runtime
        conn_id: u64,
    },

    /// A frame was received from a connection
    FrameReceived {
        /// Connection that sent the frame
        conn_id: u64,
        /// The received frame
        frame: Frame,
    },

    /// A connection was closed (by peer or error)
    ConnectionClosed {
        /// Connection that was closed
        conn_id: u64,
        /// Reason for closure
        reason: String,
    },

    /// Periodic tick for timeout checking
    Tick,
}

/// Actions that the server driver produces.
///
/// These are executed by the ActionExecutor (runtime-specific).
#[derive(Debug, Clone)]
pub enum ServerAction<I> {
    /// Send a frame to a specific session
    SendToSession {
        /// Target session ID
        session_id: u64,
        /// Frame to send
        frame: Frame,
    },

    /// Broadcast frame to all sessions in a room
    BroadcastToRoom {
        /// Target room ID
        room_id: u128,
        /// Frame to broadcast
        frame: Frame,
        /// Optional session to exclude from broadcast
        exclude_session: Option<u64>,
    },

    /// Close a connection
    CloseConnection {
        /// Session to close
        session_id: u64,
        /// Reason for closure
        reason: String,
    },

    /// Persist a frame to storage
    PersistFrame {
        /// Room the frame belongs to
        room_id: u128,
        /// Log index for this frame
        log_index: u64,
        /// Frame to persist
        frame: Frame,
    },

    /// Persist updated MLS state
    PersistMlsState {
        /// Room the state belongs to
        room_id: u128,
        /// Updated MLS state
        state: MlsGroupState,
    },

    /// Log a message (for debugging/monitoring)
    Log {
        /// Log level
        level: LogLevel,
        /// Message to log
        message: String,
        /// When the event occurred
        timestamp: I,
    },
}

/// Log levels for server actions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    /// Debug information
    Debug,
    /// Informational message
    Info,
    /// Warning
    Warn,
    /// Error
    Error,
}

/// Sans-IO server driver.
///
/// Orchestrates connection management, room operations, and frame routing.
/// All methods return actions rather than performing I/O directly.
///
/// # Type Parameters
///
/// - `E`: Environment implementation (provides time, RNG)
/// - `S`: Storage implementation
pub struct ServerDriver<E, S>
where
    E: Environment,
    S: Storage,
{
    /// Connection state machines (conn_id → Connection)
    connections: HashMap<u64, Connection<E::Instant>>,
    /// Session/room registry
    registry: ConnectionRegistry,
    /// Room manager (MLS validation + sequencing)
    room_manager: RoomManager<E>,
    /// Storage backend
    storage: S,
    /// Environment (time, RNG)
    env: E,
    /// Server configuration
    config: ServerConfig,
}

impl<E, S> ServerDriver<E, S>
where
    E: Environment,
    S: Storage,
    E::Instant: Sub<Output = Duration>,
{
    /// Create a new server driver.
    pub fn new(env: E, storage: S, config: ServerConfig) -> Self {
        Self {
            connections: HashMap::new(),
            registry: ConnectionRegistry::new(),
            room_manager: RoomManager::new(),
            storage,
            env,
            config,
        }
    }

    /// Process a server event and return actions to execute.
    ///
    /// This is the main entry point for the server driver.
    pub fn process_event(
        &mut self,
        event: ServerEvent,
    ) -> Result<Vec<ServerAction<E::Instant>>, ServerError> {
        match event {
            ServerEvent::ConnectionAccepted { conn_id } => self.handle_connection_accepted(conn_id),
            ServerEvent::FrameReceived { conn_id, frame } => {
                self.handle_frame_received(conn_id, frame)
            },
            ServerEvent::ConnectionClosed { conn_id, reason } => {
                self.handle_connection_closed(conn_id, &reason)
            },
            ServerEvent::Tick => self.handle_tick(),
        }
    }

    /// Handle a new connection being accepted.
    fn handle_connection_accepted(
        &mut self,
        conn_id: u64,
    ) -> Result<Vec<ServerAction<E::Instant>>, ServerError> {
        let now = self.env.now();

        if self.connections.len() >= self.config.max_connections {
            return Ok(vec![ServerAction::CloseConnection {
                session_id: conn_id,
                reason: "max connections exceeded".to_string(),
            }]);
        }

        let mut conn = Connection::new(&self.env, now, self.config.connection.clone());

        let session_id = self.env.random_u64();
        conn.set_session_id(session_id);

        self.connections.insert(conn_id, conn);
        self.registry.register_session(conn_id, SessionInfo::new());

        Ok(vec![ServerAction::Log {
            level: LogLevel::Debug,
            message: format!("connection {} accepted, session_id={}", conn_id, session_id),
            timestamp: now,
        }])
    }

    /// Handle a frame received from a connection.
    fn handle_frame_received(
        &mut self,
        conn_id: u64,
        frame: Frame,
    ) -> Result<Vec<ServerAction<E::Instant>>, ServerError> {
        let now = self.env.now();
        let mut actions = Vec::new();

        let conn =
            self.connections.get_mut(&conn_id).ok_or(ServerError::SessionNotFound(conn_id))?;
        let opcode = frame.header.opcode_enum();

        match opcode {
            Some(Opcode::Hello)
            | Some(Opcode::Ping)
            | Some(Opcode::Pong)
            | Some(Opcode::Goodbye) => {
                // Session-layer frames
                let conn_actions = conn.handle_frame(&frame, now).map_err(|e| {
                    ServerError::ConnectionFailed { session_id: conn_id, reason: e.to_string() }
                })?;

                for action in conn_actions {
                    match action {
                        ConnectionAction::SendFrame(f) => {
                            actions.push(ServerAction::SendToSession {
                                session_id: conn_id,
                                frame: f,
                            });
                        },
                        ConnectionAction::Close { reason } => {
                            actions.push(ServerAction::CloseConnection {
                                session_id: conn_id,
                                reason,
                            });
                        },
                    }
                }

                if opcode == Some(Opcode::Hello) {
                    if let Some(info) = self.registry.sessions_mut(conn_id) {
                        info.authenticated = true;
                        info.user_id = conn.session_id();
                    }
                }
            },

            Some(Opcode::SyncRequest) => {
                let sync_actions = self.handle_sync_request(conn_id, &frame)?;
                actions.extend(sync_actions);
            },

            _ => {
                // Room-level frames
                conn.update_activity(now);
                let room_actions =
                    self.room_manager.process_frame(frame, &self.env, &self.storage)?;

                for room_action in room_actions {
                    actions.extend(self.convert_room_action(room_action, conn_id));
                }
            },
        }

        Ok(actions)
    }

    /// Handle a sync request from a client.
    fn handle_sync_request(
        &mut self,
        conn_id: u64,
        frame: &Frame,
    ) -> Result<Vec<ServerAction<E::Instant>>, ServerError> {
        let room_id = frame.header.room_id();

        let payload = Payload::from_frame(frame.clone())?;
        let (from_log_index, limit) = match payload {
            Payload::SyncRequest(req) => (req.from_log_index, req.limit as usize),
            _ => {
                return Err(ServerError::Protocol("expected SyncRequest payload".to_string()));
            },
        };

        let room_action = self.room_manager.handle_sync_request(
            room_id,
            conn_id,
            from_log_index,
            limit,
            &self.env,
            &self.storage,
        )?;

        Ok(self.convert_room_action(room_action, conn_id))
    }

    /// Handle a connection being closed.
    fn handle_connection_closed(
        &mut self,
        conn_id: u64,
        reason: &str,
    ) -> Result<Vec<ServerAction<E::Instant>>, ServerError> {
        let now = self.env.now();
        let mut actions = Vec::new();

        if let Some(mut conn) = self.connections.remove(&conn_id) {
            conn.close();
        }

        if let Some((_info, rooms)) = self.registry.unregister_session(conn_id) {
            actions.push(ServerAction::Log {
                level: LogLevel::Info,
                message: format!(
                    "connection {} closed: {}, was in {} rooms",
                    conn_id,
                    reason,
                    rooms.len()
                ),
                timestamp: now,
            });
        }

        Ok(actions)
    }

    /// Handle periodic tick for timeout checking.
    fn handle_tick(&mut self) -> Result<Vec<ServerAction<E::Instant>>, ServerError> {
        let now = self.env.now();
        let mut actions = Vec::new();

        let conn_ids: Vec<u64> = self.connections.keys().copied().collect();

        for conn_id in conn_ids {
            if let Some(conn) = self.connections.get_mut(&conn_id) {
                let conn_actions = conn.tick(now);

                for action in conn_actions {
                    match action {
                        ConnectionAction::SendFrame(f) => {
                            actions.push(ServerAction::SendToSession {
                                session_id: conn_id,
                                frame: f,
                            });
                        },
                        ConnectionAction::Close { reason } => {
                            actions.push(ServerAction::CloseConnection {
                                session_id: conn_id,
                                reason,
                            });
                        },
                    }
                }
            }
        }

        Ok(actions)
    }

    /// Convert a RoomAction to ServerActions.
    fn convert_room_action(
        &self,
        room_action: RoomAction<E::Instant>,
        sender_conn_id: u64,
    ) -> Vec<ServerAction<E::Instant>> {
        match room_action {
            RoomAction::Broadcast { room_id, frame, exclude_sender, .. } => {
                let is_sender = if exclude_sender { Some(sender_conn_id) } else { None };
                vec![ServerAction::BroadcastToRoom { room_id, frame, exclude_session: is_sender }]
            },

            RoomAction::PersistFrame { room_id, log_index, frame, .. } => {
                vec![ServerAction::PersistFrame { room_id, log_index, frame }]
            },

            RoomAction::PersistMlsState { room_id, state, .. } => {
                vec![ServerAction::PersistMlsState { room_id, state }]
            },

            RoomAction::Reject { sender_id, reason, processed_at } => {
                vec![ServerAction::Log {
                    level: LogLevel::Warn,
                    message: format!("rejected frame from {}: {}", sender_id, reason),
                    timestamp: processed_at,
                }]
            },

            RoomAction::SendSyncResponse {
                sender_id,
                room_id,
                frames,
                has_more,
                server_epoch,
                ..
            } => {
                let response =
                    Payload::SyncResponse(SyncResponse { frames, has_more, server_epoch });

                match response.into_frame(FrameHeader::new(Opcode::SyncResponse)) {
                    Ok(mut frame) => {
                        frame.header.set_room_id(room_id);
                        vec![ServerAction::SendToSession { session_id: sender_id, frame }]
                    },
                    Err(e) => {
                        vec![ServerAction::Log {
                            level: LogLevel::Error,
                            message: format!("failed to encode SyncResponse: {}", e),
                            timestamp: self.env.now(),
                        }]
                    },
                }
            },
        }
    }

    /// Create a new room.
    ///
    /// The creator is automatically subscribed to the room.
    pub fn create_room(
        &mut self,
        room_id: u128,
        creator_conn_id: u64,
    ) -> Result<Vec<ServerAction<E::Instant>>, ServerError> {
        let now = self.env.now();

        let info = self
            .registry
            .sessions(creator_conn_id)
            .ok_or(ServerError::SessionNotFound(creator_conn_id))?;

        let user_id = info.user_id.unwrap_or(creator_conn_id);

        self.room_manager.create_room(room_id, user_id, &self.env)?;
        self.registry.subscribe(creator_conn_id, room_id);

        Ok(vec![ServerAction::Log {
            level: LogLevel::Info,
            message: format!("room {:032x} created by session {}", room_id, creator_conn_id),
            timestamp: now,
        }])
    }

    /// Subscribe a session to a room.
    pub fn subscribe_to_room(&mut self, session_id: u64, room_id: u128) -> bool {
        self.registry.subscribe(session_id, room_id)
    }

    /// Unsubscribe a session from a room.
    pub fn unsubscribe_from_room(&mut self, session_id: u64, room_id: u128) -> bool {
        self.registry.unsubscribe(session_id, room_id)
    }

    /// Get all sessions subscribed to a room.
    pub fn sessions_in_room(&self, room_id: u128) -> impl Iterator<Item = u64> + '_ {
        self.registry.sessions_in_room(room_id)
    }

    /// Get the number of active connections.
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    /// Check if a room exists.
    pub fn has_room(&self, room_id: u128) -> bool {
        self.room_manager.has_room(room_id)
    }

    /// Get the current epoch for a room.
    pub fn room_epoch(&self, room_id: u128) -> Option<u64> {
        self.room_manager.epoch(room_id)
    }
}

impl<E, S> std::fmt::Debug for ServerDriver<E, S>
where
    E: Environment,
    S: Storage,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerDriver")
            .field("connection_count", &self.connections.len())
            .field("session_count", &self.registry.session_count())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStorage;

    #[derive(Clone)]
    struct TestEnv {}

    impl Environment for TestEnv {
        type Instant = std::time::Instant;

        fn now(&self) -> Self::Instant {
            // Using real Instant for simplicity in unit tests
            std::time::Instant::now()
        }

        fn sleep(&self, _duration: Duration) -> impl std::future::Future<Output = ()> + Send {
            async {}
        }

        fn random_bytes(&self, buffer: &mut [u8]) {
            use rand::RngCore;
            rand::thread_rng().fill_bytes(buffer);
        }
    }

    #[test]
    fn server_accepts_connection() {
        let env = TestEnv {};
        let storage = MemoryStorage::new();
        let mut server = ServerDriver::new(env, storage, ServerConfig::default());

        let actions = server.process_event(ServerEvent::ConnectionAccepted { conn_id: 1 }).unwrap();

        assert_eq!(server.connection_count(), 1);
        assert!(matches!(actions[0], ServerAction::Log { level: LogLevel::Debug, .. }));
    }

    #[test]
    fn server_rejects_when_max_connections_exceeded() {
        let env = TestEnv {};
        let storage = MemoryStorage::new();
        let config = ServerConfig { max_connections: 2, ..Default::default() };
        let mut server = ServerDriver::new(env, storage, config);

        // Accept two connections
        server.process_event(ServerEvent::ConnectionAccepted { conn_id: 1 }).unwrap();
        server.process_event(ServerEvent::ConnectionAccepted { conn_id: 2 }).unwrap();

        // Third should be rejected
        let actions = server.process_event(ServerEvent::ConnectionAccepted { conn_id: 3 }).unwrap();

        assert_eq!(server.connection_count(), 2);
        assert!(matches!(actions[0], ServerAction::CloseConnection { .. }));
    }

    #[test]
    fn server_handles_connection_closed() {
        let env = TestEnv {};
        let storage = MemoryStorage::new();
        let mut server = ServerDriver::new(env, storage, ServerConfig::default());

        server.process_event(ServerEvent::ConnectionAccepted { conn_id: 1 }).unwrap();
        assert_eq!(server.connection_count(), 1);

        server
            .process_event(ServerEvent::ConnectionClosed {
                conn_id: 1,
                reason: "client disconnect".to_string(),
            })
            .unwrap();

        assert_eq!(server.connection_count(), 0);
    }

    #[test]
    fn server_creates_room() {
        let env = TestEnv {};
        let storage = MemoryStorage::new();
        let mut server = ServerDriver::new(env, storage, ServerConfig::default());

        // Accept connection first
        server.process_event(ServerEvent::ConnectionAccepted { conn_id: 1 }).unwrap();

        // Create room
        let room_id = 0x1234_5678_90ab_cdef_1234_5678_90ab_cdef;
        let actions = server.create_room(room_id, 1).unwrap();

        assert!(server.has_room(room_id));
        assert!(matches!(actions[0], ServerAction::Log { level: LogLevel::Info, .. }));

        // Creator should be subscribed
        let sessions: Vec<_> = server.sessions_in_room(room_id).collect();
        assert_eq!(sessions, vec![1]);
    }

    #[test]
    fn server_create_room_fails_for_unknown_session() {
        let env = TestEnv {};
        let storage = MemoryStorage::new();
        let mut server = ServerDriver::new(env, storage, ServerConfig::default());

        let room_id = 0x1234_5678_90ab_cdef_1234_5678_90ab_cdef;
        let result = server.create_room(room_id, 999);

        assert!(matches!(result, Err(ServerError::SessionNotFound(999))));
    }

    #[test]
    fn server_subscribe_and_unsubscribe() {
        let env = TestEnv {};
        let storage = MemoryStorage::new();
        let mut server = ServerDriver::new(env, storage, ServerConfig::default());

        let room_id = 0x1234_5678_90ab_cdef_1234_5678_90ab_cdef;

        // Accept connections
        server.process_event(ServerEvent::ConnectionAccepted { conn_id: 1 }).unwrap();
        server.process_event(ServerEvent::ConnectionAccepted { conn_id: 2 }).unwrap();

        // Create room (subscribes conn 1)
        server.create_room(room_id, 1).unwrap();

        // Subscribe conn 2
        assert!(server.subscribe_to_room(2, room_id));

        let sessions: Vec<_> = server.sessions_in_room(room_id).collect();
        assert_eq!(sessions.len(), 2);

        // Unsubscribe conn 2
        assert!(server.unsubscribe_from_room(2, room_id));

        let sessions: Vec<_> = server.sessions_in_room(room_id).collect();
        assert_eq!(sessions.len(), 1);
    }
}
