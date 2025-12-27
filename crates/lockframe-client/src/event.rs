//! Client events and actions.

use std::time::Instant;

use lockframe_core::mls::RoomId;
use lockframe_proto::Frame;

/// Events the caller feeds into the client.
///
/// The caller is responsible for:
/// - Receiving frames from the network
/// - Driving time forward via ticks
/// - Forwarding application intents (send message, create room, etc.)
#[derive(Debug, Clone)]
pub enum ClientEvent {
    /// Frame received from server.
    FrameReceived(Frame),

    /// Time tick for timeout processing.
    ///
    /// The caller should send ticks periodically to allow the client
    /// to detect timeouts and perform housekeeping.
    Tick {
        /// Current time from the environment.
        now: Instant,
    },

    /// Application wants to send a message.
    SendMessage {
        /// Target room.
        room_id: RoomId,
        /// Message plaintext.
        plaintext: Vec<u8>,
    },

    /// Application wants to create a new room.
    CreateRoom {
        /// Room ID to create.
        room_id: RoomId,
    },

    /// Application wants to join a room via welcome message.
    JoinRoom {
        /// Room ID to join.
        room_id: RoomId,
        /// MLS Welcome message (TLS-serialized).
        welcome: Vec<u8>,
    },

    /// Application wants to leave a room.
    LeaveRoom {
        /// Room to leave.
        room_id: RoomId,
    },

    /// Application wants to add members to a room.
    AddMembers {
        /// Target room.
        room_id: RoomId,
        /// MLS `KeyPackage` messages (TLS-serialized).
        key_packages: Vec<Vec<u8>>,
    },

    /// Application wants to remove members from a room.
    RemoveMembers {
        /// Target room.
        room_id: RoomId,
        /// Member IDs to remove.
        member_ids: Vec<u64>,
    },
}

/// Serializable snapshot of room state for persistence.
#[derive(Debug, Clone)]
pub struct RoomStateSnapshot {
    /// Room identifier.
    pub room_id: RoomId,
    /// Current epoch.
    pub epoch: u64,
    /// Serialized MLS group state.
    pub mls_state: Vec<u8>,
    /// Our leaf index in the tree.
    pub my_leaf_index: u32,
}

/// Actions the client produces for the caller to execute.
#[derive(Debug, Clone)]
pub enum ClientAction {
    /// Send a frame to the server.
    Send(Frame),

    /// Deliver decrypted message to application layer.
    DeliverMessage {
        /// Room the message is from.
        room_id: RoomId,
        /// Sender's stable ID.
        sender_id: u64,
        /// Decrypted plaintext.
        plaintext: Vec<u8>,
        /// Log index in the room.
        log_index: u64,
        /// Message timestamp (HLC).
        timestamp: u64,
    },

    /// Request missing commits for epoch sync.
    ///
    /// The caller should fetch commits from the server and feed
    /// them back as `FrameReceived` events.
    RequestSync {
        /// Room that needs syncing.
        room_id: RoomId,
        /// Current epoch we have.
        from_epoch: u64,
        /// Target epoch we need.
        to_epoch: u64,
    },

    /// Persist room state.
    ///
    /// The caller decides the storage backend.
    PersistRoom(RoomStateSnapshot),

    /// Room was removed (left, kicked, or error).
    RoomRemoved {
        /// Room that was removed.
        room_id: RoomId,
        /// Reason for removal.
        reason: String,
    },

    /// Log message for debugging.
    Log {
        /// Log message.
        message: String,
    },
}
