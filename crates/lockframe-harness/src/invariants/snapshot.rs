//! Observable state snapshots for invariant checking.
//!
//! Snapshots capture the observable state of the system at a point in time.
//! Invariants operate on snapshots rather than live state to ensure
//! consistent, atomic checks.

use std::collections::{HashMap, HashSet};

use lockframe_core::mls::RoomId;

/// Snapshot of the entire system state.
///
/// Contains observable state from one or more clients for invariant checking.
#[derive(Debug, Clone, Default)]
pub struct SystemSnapshot {
    /// Per-client state snapshots.
    pub clients: Vec<ClientSnapshot>,
}

impl SystemSnapshot {
    /// Create an empty snapshot (no clients).
    pub fn empty() -> Self {
        Self::default()
    }

    /// Create a snapshot with a single client.
    pub fn single(client: ClientSnapshot) -> Self {
        Self { clients: vec![client] }
    }

    /// Create a snapshot from multiple clients.
    pub fn from_clients(clients: Vec<ClientSnapshot>) -> Self {
        Self { clients }
    }

    /// Add a client snapshot.
    pub fn add_client(&mut self, client: ClientSnapshot) {
        self.clients.push(client);
    }
}

/// Snapshot of a single client's observable state.
#[derive(Debug, Clone, Default)]
pub struct ClientSnapshot {
    /// Client identifier.
    pub id: u64,
    /// Currently active room. `None` if no rooms joined.
    pub active_room: Option<RoomId>,
    /// All rooms this client is in.
    pub rooms: HashMap<RoomId, RoomSnapshot>,
    /// Epoch history per room (for monotonicity checks).
    pub epoch_history: HashMap<RoomId, Vec<u64>>,
}

impl ClientSnapshot {
    /// Create a new client snapshot.
    pub fn new(id: u64) -> Self {
        Self { id, ..Default::default() }
    }

    /// Set active room.
    pub fn with_active_room(mut self, room_id: Option<RoomId>) -> Self {
        self.active_room = room_id;
        self
    }

    /// Add a room to the snapshot.
    pub fn with_room(mut self, room_id: RoomId, snapshot: RoomSnapshot) -> Self {
        self.rooms.insert(room_id, snapshot);
        self
    }

    /// Record an epoch observation for history tracking.
    pub fn record_epoch(&mut self, room_id: RoomId, epoch: u64) {
        self.epoch_history.entry(room_id).or_default().push(epoch);
    }
}

/// Snapshot of a room's observable state.
#[derive(Debug, Clone, Default)]
pub struct RoomSnapshot {
    /// MLS epoch number.
    pub epoch: u64,
    /// Tree hash for convergence checking.
    pub tree_hash: [u8; 32],
    /// Member IDs in this room.
    pub members: HashSet<u64>,
    /// Number of messages received.
    pub message_count: usize,
}

impl RoomSnapshot {
    /// Create a room snapshot with the given epoch.
    pub fn with_epoch(epoch: u64) -> Self {
        Self { epoch, ..Default::default() }
    }

    /// Set tree hash.
    pub fn with_tree_hash(mut self, hash: [u8; 32]) -> Self {
        self.tree_hash = hash;
        self
    }

    /// Add members.
    pub fn with_members(mut self, members: impl IntoIterator<Item = u64>) -> Self {
        self.members.extend(members);
        self
    }

    /// Set message count.
    pub fn with_message_count(mut self, count: usize) -> Self {
        self.message_count = count;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_snapshot() {
        let snapshot = SystemSnapshot::empty();
        assert!(snapshot.clients.is_empty());
    }

    #[test]
    fn client_snapshot_builder() {
        let room = RoomSnapshot::with_epoch(5).with_members([1, 2, 3]).with_message_count(10);

        let client =
            ClientSnapshot::new(42).with_active_room(Some(100)).with_room(100, room.clone());

        assert_eq!(client.id, 42);
        assert_eq!(client.active_room, Some(100));
        assert!(client.rooms.contains_key(&100));
        assert_eq!(client.rooms[&100].epoch, 5);
        assert_eq!(client.rooms[&100].members.len(), 3);
    }
}
