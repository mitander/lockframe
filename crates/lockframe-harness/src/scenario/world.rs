//! World state for scenario execution.
//!
//! The World manages a single client-server connection pair during scenario
//! execution, tracks metrics, and provides oracle verification helpers.
//!
//! Note: We currently support only 1:1 scenarios (one client, one server).
//! Multi-actor scenarios will require turmoil integration for proper network
//! simulation.

use std::{ops::Sub, time::Duration};

use lockframe_core::connection::{Connection, ConnectionState};

/// Network events that occurred during scenario execution.
#[derive(Debug, Clone, PartialEq)]
pub enum NetworkEvent {
    /// Network partition between client and server
    Partition,
    /// Network partition healed
    PartitionHealed,
    /// Packet loss injected
    PacketLoss { rate: f64 },
    /// Latency injected
    Latency { min_ms: u64, max_ms: u64 },
}

/// World state containing single client-server pair and metrics.
///
/// Generic over `I` (Instant type) to support virtual time in tests.
pub struct World<I = std::time::Instant>
where
    I: Copy + Ord + Send + Sync + Sub<Output = Duration>,
{
    client: Option<Connection<I>>,
    server: Option<Connection<I>>,
    client_frames_sent: usize,
    client_frames_received: usize,
    server_frames_sent: usize,
    server_frames_received: usize,
    network_events: Vec<NetworkEvent>,
}

impl<I> World<I>
where
    I: Copy + Ord + Send + Sync + Sub<Output = Duration>,
{
    /// Create a new empty world.
    pub fn new() -> Self {
        Self {
            client: None,
            server: None,
            client_frames_sent: 0,
            client_frames_received: 0,
            server_frames_sent: 0,
            server_frames_received: 0,
            network_events: Vec::new(),
        }
    }

    /// Set the client connection.
    ///
    /// Panics if client is already set.
    pub(crate) fn set_client(&mut self, connection: Connection<I>) {
        assert!(self.client.is_none(), "client already set");
        self.client = Some(connection);
    }

    /// Set the server connection.
    ///
    /// Panics if server is already set.
    pub(crate) fn set_server(&mut self, connection: Connection<I>) {
        assert!(self.server.is_none(), "server already set");
        self.server = Some(connection);
    }

    /// Client connection state (for oracle/assertions).
    ///
    /// Panics if no client has been set.
    pub fn client(&self) -> &Connection<I> {
        self.client.as_ref().expect("no client in world")
    }

    /// Server connection state (for oracle/assertions).
    ///
    /// Panics if no server has been set.
    pub fn server(&self) -> &Connection<I> {
        self.server.as_ref().expect("no server in world")
    }

    /// Mutable client connection state.
    ///
    /// Panics if no client has been set.
    pub(crate) fn client_mut(&mut self) -> &mut Connection<I> {
        self.client.as_mut().expect("no client in world")
    }

    /// Mutable server connection state.
    ///
    /// Panics if no server has been set.
    pub(crate) fn server_mut(&mut self) -> &mut Connection<I> {
        self.server.as_mut().expect("no server in world")
    }

    /// Record that a frame was sent by the client.
    pub(crate) fn record_client_frame_sent(&mut self) {
        self.client_frames_sent += 1;
    }

    /// Record that a frame was received by the client.
    pub(crate) fn record_client_frame_received(&mut self) {
        self.client_frames_received += 1;
    }

    /// Record that a frame was sent by the server.
    pub(crate) fn record_server_frame_sent(&mut self) {
        self.server_frames_sent += 1;
    }

    /// Record that a frame was received by the server.
    pub(crate) fn record_server_frame_received(&mut self) {
        self.server_frames_received += 1;
    }

    /// Record a network event.
    pub fn record_network_event(&mut self, event: NetworkEvent) {
        self.network_events.push(event);
    }

    /// Number of frames sent by the client.
    pub fn client_frames_sent(&self) -> usize {
        self.client_frames_sent
    }

    /// Number of frames received by the client.
    pub fn client_frames_received(&self) -> usize {
        self.client_frames_received
    }

    /// Number of frames sent by the server.
    pub fn server_frames_sent(&self) -> usize {
        self.server_frames_sent
    }

    /// Number of frames received by the server.
    pub fn server_frames_received(&self) -> usize {
        self.server_frames_received
    }

    /// All network events that occurred during scenario execution.
    pub fn network_events(&self) -> &[NetworkEvent] {
        &self.network_events
    }

    /// Check if both client and server are in Authenticated state.
    pub fn all_authenticated(&self) -> bool {
        self.client().state() == ConnectionState::Authenticated
            && self.server().state() == ConnectionState::Authenticated
    }

    /// Check if client and server have matching session IDs.
    pub fn session_ids_match(&self) -> bool {
        match (self.client().session_id(), self.server().session_id()) {
            (Some(client_id), Some(server_id)) => client_id == server_id,
            _ => false,
        }
    }
}

impl Default for World {
    fn default() -> Self {
        Self::new()
    }
}
