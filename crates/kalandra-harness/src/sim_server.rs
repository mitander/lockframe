//! Simulation server wrapper for testing with turmoil.
//!
//! This module provides `SimServer`, a wrapper around `ServerDriver` that
//! integrates with turmoil's deterministic simulation for testing.
//!
//! ## Architecture
//!
//! ```text
//! SimServer
//!   ├─ ServerDriver<SimEnv, MemoryStorage>  (Sans-IO core)
//!   ├─ TcpListener                          (turmoil TCP)
//!   └─ connections: HashMap<u64, connection state>
//! ```

use std::{
    collections::HashMap,
    io::{self, ErrorKind},
    sync::Arc,
};

use bytes::BytesMut;
use kalandra_core::{
    server::{LogLevel, ServerAction, ServerConfig, ServerDriver, ServerEvent},
    storage::MemoryStorage,
};
use kalandra_proto::Frame;
use tokio::{
    io::{AsyncWriteExt, WriteHalf},
    sync::Mutex,
};
use turmoil::net::{TcpListener, TcpStream};

use crate::SimEnv;

/// Connection state for a simulated connection.
struct SimConnectionState {
    /// Write half for sending frames
    writer: WriteHalf<TcpStream>,
    /// Read buffer for incoming data
    #[allow(dead_code)]
    read_buffer: BytesMut,
}

/// Simulation server for testing with turmoil.
///
/// Wraps `ServerDriver` and handles the async I/O layer using turmoil's
/// deterministic TCP implementation.
///
/// This server is designed for test-driven usage where tests explicitly
/// drive the server rather than having it run autonomously.
pub struct SimServer {
    /// The Sans-IO server driver
    driver: ServerDriver<SimEnv, MemoryStorage>,
    /// TCP listener for accepting connections
    listener: TcpListener,
    /// Connection state (conn_id → state)
    connections: HashMap<u64, SimConnectionState>,
    /// Next connection ID
    next_conn_id: u64,
}

impl SimServer {
    /// Create and bind a new simulation server.
    ///
    /// # Errors
    ///
    /// Returns error if binding fails (address in use, etc.)
    pub async fn bind(address: &str) -> io::Result<Self> {
        Self::bind_with_config(address, ServerConfig::default()).await
    }

    /// Create and bind a new simulation server with custom config.
    ///
    /// # Errors
    ///
    /// Returns error if binding fails.
    pub async fn bind_with_config(address: &str, config: ServerConfig) -> io::Result<Self> {
        let listener = TcpListener::bind(address).await?;
        let env = SimEnv::new();
        let storage = MemoryStorage::new();
        let driver = ServerDriver::new(env, storage, config);

        Ok(Self { driver, listener, connections: HashMap::new(), next_conn_id: 1 })
    }

    /// Accept a new connection and return its ID.
    ///
    /// This method blocks until a connection is available.
    ///
    /// # Errors
    ///
    /// Returns error if accepting fails.
    pub async fn accept_connection(&mut self) -> io::Result<u64> {
        let (stream, _addr) = self.listener.accept().await?;

        let conn_id = self.next_conn_id;
        self.next_conn_id += 1;

        let actions = self
            .driver
            .process_event(ServerEvent::ConnectionAccepted { conn_id })
            .map_err(|e| io::Error::new(ErrorKind::Other, e.to_string()))?;

        let (_reader, writer) = tokio::io::split(stream);
        self.connections
            .insert(conn_id, SimConnectionState { writer, read_buffer: BytesMut::new() });

        // Execute actions
        self.execute_actions(actions).await?;

        Ok(conn_id)
    }

    /// Process a tick event for timeout handling.
    pub async fn tick(&mut self) -> io::Result<()> {
        let actions = self
            .driver
            .process_event(ServerEvent::Tick)
            .map_err(|e| io::Error::new(ErrorKind::Other, e.to_string()))?;

        self.execute_actions(actions).await
    }

    /// Execute server actions.
    async fn execute_actions(
        &mut self,
        actions: Vec<ServerAction<std::time::Instant>>,
    ) -> io::Result<()> {
        for action in actions {
            match action {
                ServerAction::SendToSession { session_id, frame } => {
                    self.send_frame(session_id, &frame).await?;
                },

                ServerAction::BroadcastToRoom { room_id, frame, exclude_session } => {
                    // Get all sessions in room and send to each
                    let sessions: Vec<u64> = self.driver.sessions_in_room(room_id).collect();
                    for session_id in sessions {
                        if Some(session_id) != exclude_session {
                            self.send_frame(session_id, &frame).await?;
                        }
                    }
                },

                ServerAction::CloseConnection { session_id, reason } => {
                    self.close_connection(session_id, &reason);
                },

                ServerAction::PersistFrame { .. } => {
                    // Storage is handled by the driver internally
                },

                ServerAction::PersistMlsState { .. } => {
                    // Storage is handled by the driver internally
                },

                ServerAction::Log { level, message, .. } => {
                    self.log(level, &message);
                },
            }
        }

        Ok(())
    }

    /// Send a frame to a specific session.
    async fn send_frame(&mut self, session_id: u64, frame: &Frame) -> io::Result<()> {
        if let Some(conn) = self.connections.get_mut(&session_id) {
            let mut buf = Vec::new();
            frame.encode(&mut buf).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
            conn.writer.write_all(&buf).await?;
            conn.writer.flush().await?;
        }
        Ok(())
    }

    /// Close a connection.
    fn close_connection(&mut self, session_id: u64, reason: &str) {
        self.connections.remove(&session_id);

        let _ = self.driver.process_event(ServerEvent::ConnectionClosed {
            conn_id: session_id,
            reason: reason.to_string(),
        });
    }

    /// Log a message.
    fn log(&self, level: LogLevel, message: &str) {
        match level {
            LogLevel::Debug => eprintln!("[DEBUG] {}", message),
            LogLevel::Info => eprintln!("[INFO] {}", message),
            LogLevel::Warn => eprintln!("[WARN] {}", message),
            LogLevel::Error => eprintln!("[ERROR] {}", message),
        }
    }

    /// Process a received frame from a connection.
    ///
    /// Call this when a frame is read from the connection.
    pub async fn process_frame(&mut self, conn_id: u64, frame: Frame) -> io::Result<()> {
        let actions = self
            .driver
            .process_event(ServerEvent::FrameReceived { conn_id, frame })
            .map_err(|e| io::Error::new(ErrorKind::Other, e.to_string()))?;

        self.execute_actions(actions).await
    }

    /// Create a room (for testing convenience).
    ///
    /// The creator connection must already exist.
    pub fn create_room(&mut self, room_id: u128, creator_conn_id: u64) -> io::Result<()> {
        let actions = self
            .driver
            .create_room(room_id, creator_conn_id)
            .map_err(|e| io::Error::new(ErrorKind::Other, e.to_string()))?;

        for action in actions {
            if let ServerAction::Log { level, message, .. } = action {
                self.log(level, &message);
            }
        }

        Ok(())
    }

    /// Check if a room exists.
    pub fn has_room(&self, room_id: u128) -> bool {
        self.driver.has_room(room_id)
    }

    /// Get the number of active connections.
    pub fn connection_count(&self) -> usize {
        self.driver.connection_count()
    }

    /// Subscribe a session to a room.
    pub fn subscribe_to_room(&mut self, session_id: u64, room_id: u128) -> bool {
        self.driver.subscribe_to_room(session_id, room_id)
    }

    /// Get room epoch.
    pub fn room_epoch(&self, room_id: u128) -> Option<u64> {
        self.driver.room_epoch(room_id)
    }

    /// Get a reference to the underlying driver (for testing).
    pub fn driver(&self) -> &ServerDriver<SimEnv, MemoryStorage> {
        &self.driver
    }

    /// Get a mutable reference to the underlying driver (for testing).
    pub fn driver_mut(&mut self) -> &mut ServerDriver<SimEnv, MemoryStorage> {
        &mut self.driver
    }
}

/// A simplified server handle for tests that don't need full async operation.
///
/// This wraps SimServer in an Arc<Mutex<>> for shared access in tests.
pub type SharedSimServer = Arc<Mutex<SimServer>>;

/// Create a shared server for testing.
pub async fn create_shared_server(address: &str) -> io::Result<SharedSimServer> {
    let server = SimServer::bind(address).await?;
    Ok(Arc::new(Mutex::new(server)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sim_server_binds() {
        let mut sim = turmoil::Builder::new().build();

        sim.host("server", || async {
            let server = SimServer::bind("0.0.0.0:443").await?;
            assert_eq!(server.connection_count(), 0);
            Ok(())
        });

        sim.run().unwrap();
    }

    #[test]
    fn sim_server_creates_room() {
        let mut sim = turmoil::Builder::new().build();

        sim.host("server", || async {
            let mut server = SimServer::bind("0.0.0.0:443").await?;
            let room_id = 0x1234_5678_90ab_cdef_1234_5678_90ab_cdef;

            // Need a connection first - use driver directly
            let _ = server.driver.process_event(ServerEvent::ConnectionAccepted { conn_id: 1 });

            server.create_room(room_id, 1)?;
            assert!(server.has_room(room_id));

            Ok(())
        });

        sim.run().unwrap();
    }
}
