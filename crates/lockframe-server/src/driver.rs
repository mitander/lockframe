//! Server driver.
//!
//! Ties together connection state machines, RoomManager (MLS validation +
//! sequencing), ConnectionRegistry (session-to-room mapping), and storage.

use std::{collections::HashMap, time::Instant};

use lockframe_core::{
    connection::{Connection, ConnectionAction, ConnectionConfig},
    env::Environment,
    mls::MlsGroupState,
};
use lockframe_proto::{
    Frame, FrameHeader, Opcode, Payload,
    payloads::{ErrorPayload, mls::KeyPackageFetchPayload, session::SyncResponse},
};

use crate::{
    key_package_registry::{KeyPackageEntry, KeyPackageRegistry, StoreResult},
    registry::{ConnectionRegistry, SessionInfo},
    room_manager::{RoomAction, RoomManager},
    server_error::ServerError,
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
        session_id: u64,
    },

    /// A frame was received from a connection
    FrameReceived {
        /// Connection that sent the frame
        session_id: u64,
        /// The received frame
        frame: Frame,
    },

    /// A connection was closed (by peer or error)
    ConnectionClosed {
        /// Connection that was closed
        session_id: u64,
        /// Reason for closure
        reason: String,
    },

    /// Periodic tick for timeout checking
    Tick,
}

/// Actions that the server driver produces.
///
/// These are executed by runtime-specific code (production or simulation).
#[derive(Debug, Clone)]
pub enum ServerAction {
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
        timestamp: Instant,
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

/// Action-based server driver.
///
/// Orchestrates connection management, room operations, and frame routing.
pub struct ServerDriver<E, S>
where
    E: Environment,
    S: Storage,
{
    /// Connection state machines (session_id → Connection)
    connections: HashMap<u64, Connection>,
    /// Session/room registry
    pub(crate) registry: ConnectionRegistry,
    /// Room manager (MLS validation + sequencing)
    room_manager: RoomManager<E>,
    /// KeyPackage registry for publish/fetch operations
    key_package_registry: KeyPackageRegistry,
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
{
    /// Create a new server driver.
    pub fn new(env: E, storage: S, config: ServerConfig) -> Self {
        Self {
            connections: HashMap::new(),
            registry: ConnectionRegistry::new(),
            room_manager: RoomManager::new(),
            key_package_registry: KeyPackageRegistry::new(),
            storage,
            env,
            config,
        }
    }

    /// Process a server event and return actions to execute.
    ///
    /// This is the main entry point for the server driver.
    pub fn process_event(&mut self, event: ServerEvent) -> Result<Vec<ServerAction>, ServerError> {
        match event {
            ServerEvent::ConnectionAccepted { session_id } => {
                self.handle_connection_accepted(session_id)
            },
            ServerEvent::FrameReceived { session_id, frame } => {
                self.handle_frame_received(session_id, frame)
            },
            ServerEvent::ConnectionClosed { session_id, reason } => {
                self.handle_connection_closed(session_id, &reason)
            },
            ServerEvent::Tick => self.handle_tick(),
        }
    }

    /// Handle a new connection being accepted.
    fn handle_connection_accepted(
        &mut self,
        session_id: u64,
    ) -> Result<Vec<ServerAction>, ServerError> {
        let now = self.env.now();

        if self.connections.len() >= self.config.max_connections {
            return Ok(vec![ServerAction::CloseConnection {
                session_id,
                reason: "max connections exceeded".to_string(),
            }]);
        }

        let mut conn = Connection::new(now, self.config.connection.clone());
        conn.set_session_id(session_id);

        self.connections.insert(session_id, conn);
        self.registry.register_session(session_id, SessionInfo::new());

        Ok(vec![ServerAction::Log {
            level: LogLevel::Debug,
            message: format!("connection {} accepted, session_id={}", session_id, session_id),
            timestamp: now,
        }])
    }

    /// Handle a frame received from a connection.
    fn handle_frame_received(
        &mut self,
        session_id: u64,
        frame: Frame,
    ) -> Result<Vec<ServerAction>, ServerError> {
        let now = self.env.now();
        let mut actions = Vec::new();

        let conn = self
            .connections
            .get_mut(&session_id)
            .ok_or(ServerError::SessionNotFound(session_id))?;
        let opcode = frame.header.opcode_enum();

        match opcode {
            Some(Opcode::Hello)
            | Some(Opcode::Ping)
            | Some(Opcode::Pong)
            | Some(Opcode::Goodbye) => {
                // Session-layer frames
                let conn_actions = conn.handle_frame(&frame, now).map_err(|e| {
                    ServerError::ConnectionFailed { session_id, reason: e.to_string() }
                })?;

                for action in conn_actions {
                    match action {
                        ConnectionAction::SendFrame(f) => {
                            actions.push(ServerAction::SendToSession { session_id, frame: f });
                        },
                        ConnectionAction::Close { reason } => {
                            actions.push(ServerAction::CloseConnection { session_id, reason });
                        },
                    }
                }

                if opcode == Some(Opcode::Hello) {
                    if let Some(_) = self.registry.sessions(session_id) {
                        // TODO: Extract actual user_id from auth_token when authentication is
                        // implemented For now, use session_id as temporary user_id.
                        let user_id = session_id;

                        let new_info = SessionInfo::authenticated(user_id);
                        self.registry.update_session_info(session_id, new_info);
                    }
                }
            },

            Some(Opcode::SyncRequest) => {
                let sync_actions = self.handle_sync_request(session_id, &frame);
                actions.extend(sync_actions);
            },

            Some(Opcode::KeyPackagePublish) => {
                conn.update_activity(now);
                let publish_actions = self.handle_key_package_publish(session_id, &frame);
                actions.extend(publish_actions);
            },

            Some(Opcode::KeyPackageFetch) => {
                conn.update_activity(now);
                let fetch_actions = self.handle_key_package_fetch(session_id, &frame);
                actions.extend(fetch_actions);
            },

            Some(Opcode::Welcome) => {
                let room_id = frame.header.room_id();
                let recipient_id = frame.header.recipient_id();
                conn.update_activity(now);

                let room_actions =
                    self.room_manager.process_frame(frame, &self.env, &self.storage)?;

                if let Some(recipient_session_id) = self.registry.session_id_for_user(recipient_id)
                {
                    self.registry.subscribe(recipient_session_id, room_id);

                    actions.push(ServerAction::Log {
                        level: LogLevel::Debug,
                        message: format!(
                            "session {} (user {}) subscribed to room {:032x} via Welcome",
                            recipient_session_id, recipient_id, room_id
                        ),
                        timestamp: now,
                    });
                } else {
                    actions.push(ServerAction::Log {
                        level: LogLevel::Warn,
                        message: format!(
                            "Welcome recipient {} not connected, cannot subscribe to room {:032x}",
                            recipient_id, room_id
                        ),
                        timestamp: now,
                    });
                }

                for room_action in room_actions {
                    actions.extend(self.convert_room_action(room_action, session_id));
                }
            },

            _ => {
                // Room-level frames (Commit, Proposal, AppMessage, etc.)
                conn.update_activity(now);
                let room_actions =
                    self.room_manager.process_frame(frame, &self.env, &self.storage)?;

                for room_action in room_actions {
                    actions.extend(self.convert_room_action(room_action, session_id));
                }
            },
        }

        Ok(actions)
    }

    /// Handle a sync request from a client.
    fn handle_sync_request(&mut self, session_id: u64, frame: &Frame) -> Vec<ServerAction> {
        let room_id = frame.header.room_id();

        let result = (|| -> Result<Vec<ServerAction>, ServerError> {
            let payload = Payload::from_frame(frame.clone())?;
            let (from_log_index, limit) = match payload {
                Payload::SyncRequest(req) => (req.from_log_index, req.limit as usize),
                _ => {
                    return Err(ServerError::Protocol("expected SyncRequest payload".to_string()));
                },
            };

            let room_action = self.room_manager.handle_sync_request(
                room_id,
                session_id,
                from_log_index,
                limit,
                &self.env,
                &self.storage,
            )?;

            Ok(self.convert_room_action(room_action, session_id))
        })();

        match result {
            Ok(actions) => actions,
            Err(e) => self.make_error_response(session_id, room_id, &e),
        }
    }

    fn make_error_response(
        &self,
        session_id: u64,
        room_id: u128,
        error: &ServerError,
    ) -> Vec<ServerAction> {
        let error_payload = match error {
            ServerError::Room(room_err) => match room_err {
                crate::room_manager::RoomError::RoomNotFound(_) => {
                    ErrorPayload::room_not_found(room_id)
                },
                crate::room_manager::RoomError::Storage(e) => {
                    ErrorPayload::storage_error(e.to_string())
                },
                crate::room_manager::RoomError::MlsValidation(e) => {
                    ErrorPayload::mls_error(e.to_string())
                },
                crate::room_manager::RoomError::Sequencing(e) => {
                    ErrorPayload::sequencer_error(e.to_string())
                },
                _ => ErrorPayload::frame_rejected(error.to_string()),
            },
            ServerError::Protocol(msg) => ErrorPayload::invalid_payload(msg),
            _ => ErrorPayload::frame_rejected(error.to_string()),
        };

        let error_msg = error_payload.message.clone();
        let error = Payload::Error(error_payload);
        match error.into_frame(FrameHeader::new(Opcode::Error)) {
            Ok(mut frame) => {
                frame.header.set_room_id(room_id);
                vec![ServerAction::SendToSession { session_id, frame }, ServerAction::Log {
                    level: LogLevel::Warn,
                    message: format!("sync request failed for {}: {}", session_id, error_msg),
                    timestamp: self.env.now(),
                }]
            },
            Err(e) => vec![ServerAction::Log {
                level: LogLevel::Error,
                message: format!("failed to encode error response: {}", e),
                timestamp: self.env.now(),
            }],
        }
    }

    /// Handle KeyPackage publish request.
    fn handle_key_package_publish(&mut self, session_id: u64, frame: &Frame) -> Vec<ServerAction> {
        let now = self.env.now();

        let user_id = match self.registry.sessions(session_id) {
            Some(info) => match info.user_id {
                Some(id) => id,
                None => {
                    let error =
                        Payload::Error(ErrorPayload::frame_rejected("Session not authenticated"));
                    return match error.into_frame(FrameHeader::new(Opcode::Error)) {
                        Ok(frame) => vec![
                            ServerAction::SendToSession { session_id, frame },
                            ServerAction::Log {
                                level: LogLevel::Warn,
                                message: format!(
                                    "KeyPackagePublish from unauthenticated session {}",
                                    session_id
                                ),
                                timestamp: now,
                            },
                        ],
                        Err(e) => vec![ServerAction::Log {
                            level: LogLevel::Error,
                            message: format!("failed to encode error response: {}", e),
                            timestamp: now,
                        }],
                    };
                },
            },
            None => {
                let error = Payload::Error(ErrorPayload::frame_rejected("Unknown session"));
                return match error.into_frame(FrameHeader::new(Opcode::Error)) {
                    Ok(frame) => {
                        vec![ServerAction::SendToSession { session_id, frame }, ServerAction::Log {
                            level: LogLevel::Warn,
                            message: format!(
                                "KeyPackagePublish from unknown session {}",
                                session_id
                            ),
                            timestamp: now,
                        }]
                    },
                    Err(e) => vec![ServerAction::Log {
                        level: LogLevel::Error,
                        message: format!("failed to encode error response: {}", e),
                        timestamp: now,
                    }],
                };
            },
        };

        let payload = match Payload::from_frame(frame.clone()) {
            Ok(Payload::KeyPackagePublish(req)) => req,
            Ok(_) => {
                let error = Payload::Error(ErrorPayload::invalid_payload(
                    "Expected KeyPackagePublish payload",
                ));
                return match error.into_frame(FrameHeader::new(Opcode::Error)) {
                    Ok(frame) => {
                        vec![ServerAction::SendToSession { session_id, frame }, ServerAction::Log {
                            level: LogLevel::Warn,
                            message: format!(
                                "expected KeyPackagePublish payload from session {}",
                                session_id
                            ),
                            timestamp: now,
                        }]
                    },
                    Err(e) => vec![ServerAction::Log {
                        level: LogLevel::Error,
                        message: format!("failed to encode error response: {}", e),
                        timestamp: now,
                    }],
                };
            },
            Err(e) => {
                let error = Payload::Error(ErrorPayload::invalid_payload(&format!(
                    "Failed to decode KeyPackagePublish: {}",
                    e
                )));
                return match error.into_frame(FrameHeader::new(Opcode::Error)) {
                    Ok(frame) => {
                        vec![ServerAction::SendToSession { session_id, frame }, ServerAction::Log {
                            level: LogLevel::Warn,
                            message: format!("failed to decode KeyPackagePublish: {}", e),
                            timestamp: now,
                        }]
                    },
                    Err(e) => vec![ServerAction::Log {
                        level: LogLevel::Error,
                        message: format!("failed to encode error response: {}", e),
                        timestamp: now,
                    }],
                };
            },
        };

        let store_result = self
            .key_package_registry
            .store(user_id, KeyPackageEntry::new(payload.key_package_bytes, payload.hash_ref));

        let mut actions = vec![ServerAction::Log {
            level: LogLevel::Info,
            message: format!("KeyPackage published for user {}", user_id),
            timestamp: now,
        }];

        if store_result == StoreResult::Evicted {
            actions.push(ServerAction::Log {
                level: LogLevel::Debug,
                message: format!("KeyPackage registry evicted an entry for user {}", user_id),
                timestamp: now,
            });
        }

        actions
    }

    /// Handle KeyPackage fetch request.
    fn handle_key_package_fetch(&mut self, session_id: u64, frame: &Frame) -> Vec<ServerAction> {
        let now = self.env.now();

        // Decode request
        let request = match Payload::from_frame(frame.clone()) {
            Ok(Payload::KeyPackageFetch(req)) => req,
            Ok(_) => {
                let error = Payload::Error(ErrorPayload::invalid_payload(
                    "Expected KeyPackageFetch payload",
                ));
                return match error.into_frame(FrameHeader::new(Opcode::Error)) {
                    Ok(frame) => {
                        vec![ServerAction::SendToSession { session_id, frame }, ServerAction::Log {
                            level: LogLevel::Warn,
                            message: format!(
                                "unexpected payload type in KeyPackageFetch frame from session {}",
                                session_id
                            ),
                            timestamp: now,
                        }]
                    },
                    Err(e) => vec![ServerAction::Log {
                        level: LogLevel::Error,
                        message: format!(
                            "failed to encode error response for KeyPackageFetch: {}",
                            e
                        ),
                        timestamp: now,
                    }],
                };
            },
            Err(e) => {
                let error = Payload::Error(ErrorPayload::invalid_payload(&format!(
                    "Failed to decode KeyPackageFetch: {}",
                    e
                )));
                return match error.into_frame(FrameHeader::new(Opcode::Error)) {
                    Ok(frame) => {
                        vec![ServerAction::SendToSession { session_id, frame }, ServerAction::Log {
                            level: LogLevel::Warn,
                            message: format!(
                                "failed to decode KeyPackageFetch from session {}: {}",
                                session_id, e
                            ),
                            timestamp: now,
                        }]
                    },
                    Err(e) => vec![ServerAction::Log {
                        level: LogLevel::Error,
                        message: format!(
                            "failed to encode error response for KeyPackageFetch: {}",
                            e
                        ),
                        timestamp: now,
                    }],
                };
            },
        };

        // Fetch (and consume) from registry
        match self.key_package_registry.take(request.user_id) {
            Some(entry) => {
                // Build response
                let response = Payload::KeyPackageFetch(KeyPackageFetchPayload {
                    user_id: request.user_id,
                    key_package_bytes: entry.key_package_bytes,
                    hash_ref: entry.hash_ref,
                });

                match response.into_frame(FrameHeader::new(Opcode::KeyPackageFetch)) {
                    Ok(response_frame) => vec![
                        ServerAction::SendToSession { session_id, frame: response_frame },
                        ServerAction::Log {
                            level: LogLevel::Debug,
                            message: format!("KeyPackage fetched for user {}", request.user_id),
                            timestamp: now,
                        },
                    ],
                    Err(e) => vec![ServerAction::Log {
                        level: LogLevel::Error,
                        message: format!("failed to encode KeyPackageFetch response: {}", e),
                        timestamp: now,
                    }],
                }
            },
            None => {
                // No KeyPackage found - return error
                let error = Payload::Error(ErrorPayload::keypackage_not_found(request.user_id));

                match error.into_frame(FrameHeader::new(Opcode::Error)) {
                    Ok(frame) => {
                        vec![ServerAction::SendToSession { session_id, frame }, ServerAction::Log {
                            level: LogLevel::Debug,
                            message: format!(
                                "no KeyPackage found for user {} (requested by session {})",
                                request.user_id, session_id
                            ),
                            timestamp: now,
                        }]
                    },
                    Err(e) => vec![ServerAction::Log {
                        level: LogLevel::Error,
                        message: format!(
                            "failed to encode error response for KeyPackageFetch: {}",
                            e
                        ),
                        timestamp: now,
                    }],
                }
            },
        }
    }

    /// Handle a connection being closed.
    fn handle_connection_closed(
        &mut self,
        session_id: u64,
        reason: &str,
    ) -> Result<Vec<ServerAction>, ServerError> {
        let now = self.env.now();
        let mut actions = Vec::new();

        if let Some(mut conn) = self.connections.remove(&session_id) {
            conn.close();
        }

        if let Some((_info, rooms)) = self.registry.unregister_session(session_id) {
            actions.push(ServerAction::Log {
                level: LogLevel::Info,
                message: format!(
                    "connection {} closed: {}, was in {} rooms",
                    session_id,
                    reason,
                    rooms.len()
                ),
                timestamp: now,
            });
        }

        Ok(actions)
    }

    /// Handle periodic tick for timeout checking.
    fn handle_tick(&mut self) -> Result<Vec<ServerAction>, ServerError> {
        let now = self.env.now();
        let mut actions = Vec::new();

        let session_ids: Vec<u64> = self.connections.keys().copied().collect();

        for session_id in session_ids {
            if let Some(conn) = self.connections.get_mut(&session_id) {
                let conn_actions = conn.tick(now);

                for action in conn_actions {
                    match action {
                        ConnectionAction::SendFrame(f) => {
                            actions.push(ServerAction::SendToSession { session_id, frame: f });
                        },
                        ConnectionAction::Close { reason } => {
                            actions.push(ServerAction::CloseConnection { session_id, reason });
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
        room_action: RoomAction,
        sender_session_id: u64,
    ) -> Vec<ServerAction> {
        match room_action {
            RoomAction::Broadcast { room_id, frame, exclude_sender, .. } => {
                if frame.header.opcode_enum() == Some(Opcode::Welcome) {
                    // Welcome frames are routed to recipients
                    let recipient_id = frame.header.recipient_id();
                    if let Some(session_id) = self.registry.session_id_for_user(recipient_id) {
                        return vec![ServerAction::SendToSession { session_id, frame }];
                    } else {
                        return vec![ServerAction::Log {
                            level: LogLevel::Warn,
                            message: format!(
                                "Welcome recipient {} not connected (room {})",
                                recipient_id, room_id
                            ),
                            timestamp: self.env.now(),
                        }];
                    }
                }

                let is_sender = if exclude_sender { Some(sender_session_id) } else { None };
                vec![ServerAction::BroadcastToRoom { room_id, frame, exclude_session: is_sender }]
            },

            RoomAction::PersistFrame { room_id, log_index, frame, .. } => {
                vec![ServerAction::PersistFrame { room_id, log_index, frame }]
            },

            RoomAction::PersistMlsState { room_id, state, .. } => {
                vec![ServerAction::PersistMlsState { room_id, state }]
            },

            RoomAction::Reject { sender_id, reason, processed_at } => {
                let error = Payload::Error(ErrorPayload::frame_rejected(&reason));
                match error.into_frame(FrameHeader::new(Opcode::Error)) {
                    Ok(frame) => vec![
                        ServerAction::SendToSession { session_id: sender_id, frame },
                        ServerAction::Log {
                            level: LogLevel::Warn,
                            message: format!("rejected frame from {}: {}", sender_id, reason),
                            timestamp: processed_at,
                        },
                    ],
                    Err(_) => vec![ServerAction::Log {
                        level: LogLevel::Warn,
                        message: format!("rejected frame from {}: {}", sender_id, reason),
                        timestamp: processed_at,
                    }],
                }
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
        creator_session_id: u64,
    ) -> Result<Vec<ServerAction>, ServerError> {
        let now = self.env.now();

        let info = self
            .registry
            .sessions(creator_session_id)
            .ok_or(ServerError::SessionNotFound(creator_session_id))?;

        let user_id = info.user_id.unwrap_or(creator_session_id);

        self.room_manager.create_room(room_id, user_id, &self.env)?;
        self.registry.subscribe(creator_session_id, room_id);

        Ok(vec![ServerAction::Log {
            level: LogLevel::Info,
            message: format!("room {:032x} created by session {}", room_id, creator_session_id),
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

    /// All sessions subscribed to a room.
    pub fn sessions_in_room(&self, room_id: u128) -> impl Iterator<Item = u64> + '_ {
        self.registry.sessions_in_room(room_id)
    }

    /// Number of active connections.
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    /// Room exists and is initialized.
    pub fn has_room(&self, room_id: u128) -> bool {
        self.room_manager.has_room(room_id)
    }

    /// Current MLS epoch for a room. `None` if room doesn't exist.
    pub fn room_epoch(&self, room_id: u128) -> Option<u64> {
        self.room_manager.epoch(room_id)
    }

    /// Storage backend for frame/state persistence.
    pub fn storage(&self) -> &S {
        &self.storage
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
    use std::time::Duration;

    use super::*;
    use crate::storage::MemoryStorage;

    #[derive(Clone)]
    struct TestEnv {}

    impl Environment for TestEnv {
        fn now(&self) -> std::time::Instant {
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

        let actions =
            server.process_event(ServerEvent::ConnectionAccepted { session_id: 1 }).unwrap();

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
        server.process_event(ServerEvent::ConnectionAccepted { session_id: 1 }).unwrap();
        server.process_event(ServerEvent::ConnectionAccepted { session_id: 2 }).unwrap();

        // Third should be rejected
        let actions =
            server.process_event(ServerEvent::ConnectionAccepted { session_id: 3 }).unwrap();

        assert_eq!(server.connection_count(), 2);
        assert!(matches!(actions[0], ServerAction::CloseConnection { .. }));
    }

    #[test]
    fn server_handles_connection_closed() {
        let env = TestEnv {};
        let storage = MemoryStorage::new();
        let mut server = ServerDriver::new(env, storage, ServerConfig::default());

        server.process_event(ServerEvent::ConnectionAccepted { session_id: 1 }).unwrap();
        assert_eq!(server.connection_count(), 1);

        server
            .process_event(ServerEvent::ConnectionClosed {
                session_id: 1,
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
        server.process_event(ServerEvent::ConnectionAccepted { session_id: 1 }).unwrap();

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
        server.process_event(ServerEvent::ConnectionAccepted { session_id: 1 }).unwrap();
        server.process_event(ServerEvent::ConnectionAccepted { session_id: 2 }).unwrap();

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

    #[test]
    fn welcome_frame_subscribes_receiver_to_room() {
        use bytes::Bytes;
        use lockframe_proto::FrameHeader;

        let env = TestEnv {};
        let storage = MemoryStorage::new();
        let mut server = ServerDriver::new(env, storage, ServerConfig::default());

        let room_id = 0x1234_5678_90ab_cdef_1234_5678_90ab_cdef;
        let user_id_1 = 1001; // Conn 1's user ID (room creator)
        let user_id_2 = 2002; // Conn 2's user ID (Welcome recipient)

        // Accept two connections
        server.process_event(ServerEvent::ConnectionAccepted { session_id: 1 }).unwrap();
        server.process_event(ServerEvent::ConnectionAccepted { session_id: 2 }).unwrap();

        // Complete Hello handshake for both to set their user_ids
        // Conn 1 handshake
        server.registry.update_session_info(1, SessionInfo::authenticated(user_id_1));
        // Conn 2 handshake
        server.registry.update_session_info(2, SessionInfo::authenticated(user_id_2));

        // Conn 1 creates the room
        server.create_room(room_id, 1).unwrap();

        // Verify only conn 1 is subscribed
        let sessions: Vec<_> = server.sessions_in_room(room_id).collect();
        assert_eq!(sessions, vec![1]);

        // Conn 1 sends a Welcome frame to add conn 2
        // The Welcome frame has recipient_id = user_id_2
        //
        // Note: The Welcome payload doesn't need to be valid MLS for this test
        // because we're testing the subscription logic, not MLS processing.
        // The room_manager.process_frame will fail, but subscription happens first.
        let mut header = FrameHeader::new(Opcode::Welcome);
        header.set_room_id(room_id);
        header.set_recipient_id(user_id_2);
        header.set_sender_id(user_id_1);
        let welcome_frame = Frame::new(header, Bytes::from("fake welcome"));

        // Process the Welcome from conn 1 - it will fail MLS validation but
        // subscription should happen first
        let _ = server
            .process_event(ServerEvent::FrameReceived { session_id: 1, frame: welcome_frame });

        // Verify conn 2 is now subscribed (even if MLS processing failed)
        let sessions: Vec<_> = server.sessions_in_room(room_id).collect();
        assert_eq!(sessions.len(), 2);
        assert!(sessions.contains(&1));
        assert!(sessions.contains(&2));
    }
}
