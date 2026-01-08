//! Lockframe production server.
//!
//! Production server implementation using Quinn for QUIC transport, Tokio for
//! async runtime, and system time with cryptographic RNG.
//!
//! # Architecture
//!
//! This crate provides production "glue" that wraps [`lockframe_core`]'s
//! action-based logic with real I/O. The [`ServerDriver`] follows the Sans-IO
//! pattern (see [`lockframe_core`] for details), while [`Server`] executes the
//! actions using Quinn QUIC and Tokio async runtime.
//!
//! # Components
//!
//! - [`ServerDriver`]: Action-based orchestrator (pure logic, no I/O)
//! - [`Server`]: Production runtime that executes ServerDriver actions
//! - [`QuinnTransport`]: QUIC transport via Quinn library
//! - [`SystemEnv`]: Production environment (real time, crypto RNG)

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod driver;
mod error;
mod executor;
mod key_package_registry;
mod registry;
mod room_manager;
pub mod sequencer;
mod server_error;
pub mod storage;
mod system_env;
mod transport;

use std::{collections::HashMap, sync::Arc};

use bytes::BytesMut;
pub use driver::{LogLevel, ServerAction, ServerConfig as DriverConfig, ServerDriver, ServerEvent};
pub use error::ServerError;
pub use executor::BroadcastPolicy;
pub use key_package_registry::{KeyPackageEntry, KeyPackageRegistry};
use lockframe_core::env::Environment;
use lockframe_proto::{Frame, FrameHeader};
pub use registry::{ConnectionRegistry, SessionInfo};
pub use room_manager::{RoomAction, RoomError, RoomManager, RoomMetadata};
pub use sequencer::{Sequencer, SequencerAction, SequencerError};
pub use server_error::{ExecutorError, ServerError as DriverError};
pub use storage::{ChaoticStorage, MemoryStorage, Storage, StorageError};
pub use system_env::SystemEnv;
use tokio::sync::RwLock;
pub use transport::{QuinnConnection, QuinnTransport};
use zerocopy::FromBytes;

/// Shared state for all connections.
///
/// This holds connection and stream maps for message routing.
struct SharedState {
    /// Map of session ID to QUIC connection (for closing)
    connections: RwLock<HashMap<u64, QuinnConnection>>,
    /// Map of session ID to persistent outbound stream
    /// All messages to a client go through this single stream, ensuring
    /// ordering.
    outbound_streams: RwLock<HashMap<u64, tokio::sync::Mutex<quinn::SendStream>>>,
}

/// Server configuration for the production runtime.
#[derive(Debug, Clone)]
pub struct ServerRuntimeConfig {
    /// Address to bind to (e.g., "0.0.0.0:4433")
    pub bind_address: String,
    /// Path to TLS certificate (PEM format)
    pub cert_path: Option<String>,
    /// Path to TLS private key (PEM format)
    pub key_path: Option<String>,
    /// Driver configuration (timeouts, limits)
    pub driver: DriverConfig,
}

impl Default for ServerRuntimeConfig {
    fn default() -> Self {
        Self {
            bind_address: "0.0.0.0:4433".to_string(),
            cert_path: None,
            key_path: None,
            driver: DriverConfig::default(),
        }
    }
}

/// Production Lockframe server.
///
/// Wraps `ServerDriver` with Quinn QUIC transport and system environment.
pub struct Server {
    /// The action-based server driver
    driver: ServerDriver<SystemEnv, MemoryStorage>,
    /// QUIC endpoint
    transport: QuinnTransport,
    /// Environment
    env: SystemEnv,
}

impl Server {
    /// Create and bind a new server.
    pub async fn bind(config: ServerRuntimeConfig) -> Result<Self, ServerError> {
        let env = SystemEnv::new();
        let storage = MemoryStorage::new();
        let driver = ServerDriver::new(env.clone(), storage, config.driver);

        let transport =
            QuinnTransport::bind(&config.bind_address, config.cert_path, config.key_path).await?;

        Ok(Self { driver, transport, env })
    }

    /// Run the server, accepting connections and processing frames.
    ///
    /// This method runs until the server is shut down or an error occurs.
    pub async fn run(self) -> Result<(), ServerError> {
        tracing::info!("Server starting on {}", self.transport.local_addr()?);

        let env = self.env;
        let driver = Arc::new(tokio::sync::Mutex::new(self.driver));
        let shared = Arc::new(SharedState {
            connections: RwLock::new(HashMap::new()),
            outbound_streams: RwLock::new(HashMap::new()),
        });

        loop {
            match self.transport.accept().await {
                Ok(conn) => {
                    let driver = Arc::clone(&driver);
                    let shared = Arc::clone(&shared);
                    let env = env.clone();

                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(conn, driver, shared, env).await {
                            tracing::error!("Connection error: {}", e);
                        }
                    });
                },
                Err(e) => {
                    tracing::error!("Accept error: {}", e);
                },
            }
        }
    }

    /// Local address the server is bound to.
    pub fn local_addr(&self) -> Result<std::net::SocketAddr, ServerError> {
        self.transport.local_addr()
    }
}

/// Handle a single QUIC connection.
async fn handle_connection(
    conn: QuinnConnection,
    driver: Arc<tokio::sync::Mutex<ServerDriver<SystemEnv, MemoryStorage>>>,
    shared: Arc<SharedState>,
    env: SystemEnv,
) -> Result<(), ServerError> {
    let session_id = {
        let mut buf = [0u8; 8];
        env.random_bytes(&mut buf);
        u64::from_le_bytes(buf)
    };

    tracing::debug!("New connection: {}", session_id);

    let outbound_stream = conn
        .open_uni()
        .await
        .map_err(|e| ServerError::Internal(format!("Failed to open outbound stream: {}", e)))?;

    {
        let mut connections = shared.connections.write().await;
        connections.insert(session_id, conn.clone());
    }

    {
        let mut streams = shared.outbound_streams.write().await;
        streams.insert(session_id, tokio::sync::Mutex::new(outbound_stream));
    }

    {
        let mut driver = driver.lock().await;
        let actions = driver.process_event(ServerEvent::ConnectionAccepted { session_id })?;
        execute_actions(&mut *driver, actions, &shared).await?;
    }

    loop {
        match conn.accept_bi().await {
            Ok((send, recv)) => {
                let driver = Arc::clone(&driver);
                let shared = Arc::clone(&shared);

                tokio::spawn(async move {
                    if let Err(e) = handle_stream(session_id, send, recv, driver, &shared).await {
                        tracing::debug!("Stream error: {}", e);
                    }
                });
            },
            Err(e) => {
                tracing::debug!("Connection closed: {}", e);
                break;
            },
        }
    }

    {
        let mut connections = shared.connections.write().await;
        connections.remove(&session_id);
    }

    {
        let mut streams = shared.outbound_streams.write().await;
        streams.remove(&session_id);
    }

    {
        let mut driver = driver.lock().await;
        let actions = driver.process_event(ServerEvent::ConnectionClosed {
            session_id,
            reason: "connection closed".to_string(),
        })?;
        execute_actions(&mut *driver, actions, &shared).await?;
    }

    Ok(())
}

/// Handle a single bidirectional stream.
async fn handle_stream(
    session_id: u64,
    send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    driver: Arc<tokio::sync::Mutex<ServerDriver<SystemEnv, MemoryStorage>>>,
    shared: &Arc<SharedState>,
) -> Result<(), ServerError> {
    drop(send); // not used for now

    let mut buf = BytesMut::with_capacity(65536);

    loop {
        buf.clear();
        buf.resize(128, 0);

        match recv.read_exact(&mut buf[..128]).await {
            Ok(()) => {},
            Err(e) => {
                tracing::debug!("Read error: {}", e);
                break;
            },
        }

        let header: &FrameHeader = match FrameHeader::ref_from_bytes(&buf[..128]) {
            Ok(h) => h,
            Err(_) => {
                tracing::warn!("Invalid frame header");
                break;
            },
        };

        let payload_size = header.payload_size() as usize;

        if payload_size > 0 {
            buf.resize(128 + payload_size, 0);
            if let Err(e) = recv.read_exact(&mut buf[128..]).await {
                tracing::debug!("Payload read error: {}", e);
                break;
            }
        }

        let frame = match Frame::decode(&buf) {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!("Frame decode error: {}", e);
                break;
            },
        };

        let actions = {
            let mut driver = driver.lock().await;
            match driver.process_event(ServerEvent::FrameReceived { session_id, frame }) {
                Ok(actions) => actions,
                Err(e) => {
                    tracing::warn!("Frame processing error: {}", e);
                    continue;
                },
            }
        };

        {
            let mut driver = driver.lock().await;
            execute_actions(&mut *driver, actions, shared).await?;
        }
    }

    Ok(())
}

/// Execute server actions.
async fn execute_actions(
    driver: &mut ServerDriver<SystemEnv, MemoryStorage>,
    actions: Vec<ServerAction>,
    shared: &SharedState,
) -> Result<(), ServerError> {
    for action in actions {
        match action {
            ServerAction::SendToSession { session_id, frame } => {
                let mut buf = Vec::new();
                frame.encode(&mut buf).map_err(|e| ServerError::Protocol(e.to_string()))?;

                let streams = shared.outbound_streams.read().await;
                if let Some(stream_mutex) = streams.get(&session_id) {
                    let mut stream = stream_mutex.lock().await;
                    if let Err(e) = stream.write_all(&buf).await {
                        tracing::warn!("SendToSession write failed for {}: {}", session_id, e);
                    }
                } else {
                    tracing::warn!("SendToSession: session {} not found", session_id);
                }
            },

            ServerAction::BroadcastToRoom { room_id, frame, exclude_session } => {
                let sessions: Vec<u64> = driver.sessions_in_room(room_id).collect();

                let mut buf = Vec::new();
                frame.encode(&mut buf).map_err(|e| ServerError::Protocol(e.to_string()))?;

                let streams = shared.outbound_streams.read().await;
                for session_id in sessions {
                    if Some(session_id) != exclude_session {
                        if let Some(stream_mutex) = streams.get(&session_id) {
                            let mut stream = stream_mutex.lock().await;
                            if let Err(e) = stream.write_all(&buf).await {
                                tracing::warn!(
                                    "BroadcastToRoom write failed for {}: {}",
                                    session_id,
                                    e
                                );
                            }
                        }
                    }
                }
            },

            ServerAction::CloseConnection { session_id, reason } => {
                tracing::info!("Closing connection {}: {}", session_id, reason);
                let mut connections = shared.connections.write().await;
                if let Some(conn) = connections.remove(&session_id) {
                    conn.close(0u32.into(), reason.as_bytes());
                }
            },

            ServerAction::PersistFrame { room_id, log_index, frame } => {
                if let Err(e) = driver.storage().store_frame(room_id, log_index, &frame) {
                    tracing::error!("Failed to persist frame: {}", e);

                    // Sequencer state drifted from storage. Re-initialize
                    // room state from storage on next frame to sync
                    if let StorageError::Conflict { .. } = e {
                        tracing::warn!(
                            %room_id,
                            "Clearing sequencer state due to log index conflict"
                        );
                        driver.clear_room_sequencer(room_id);
                    }
                }
            },

            ServerAction::Log { level, message, .. } => match level {
                LogLevel::Debug => tracing::debug!("{}", message),
                LogLevel::Info => tracing::info!("{}", message),
                LogLevel::Warn => tracing::warn!("{}", message),
                LogLevel::Error => tracing::error!("{}", message),
            },
        }
    }

    Ok(())
}
