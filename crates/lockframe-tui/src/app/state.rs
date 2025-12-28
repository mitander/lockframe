//! UI state types
//!
//! State structures used by the App state machine.

use std::collections::HashSet;

use lockframe_core::mls::RoomId;

/// Connection state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionState {
    /// Not connected to any server.
    Disconnected,

    /// Connection in progress.
    Connecting,

    /// Connected with session ID.
    Connected {
        /// Application-layer session ID.
        session_id: u64,
    },
}

/// Per-room state.
#[derive(Debug, Clone)]
pub struct RoomState {
    /// Room UUID.
    pub room_id: RoomId,
    /// Messages in this room (ordered by receipt).
    pub messages: Vec<Message>,
    /// Current room members.
    pub members: HashSet<u64>,
    /// Unread messages indicator.
    pub unread: bool,
}

impl RoomState {
    /// Create a new empty room state.
    pub fn new(room_id: RoomId) -> Self {
        Self { room_id, messages: Vec::new(), members: HashSet::new(), unread: false }
    }

    /// Add a message to the room.
    pub fn add_message(&mut self, sender_id: u64, content: Vec<u8>) {
        self.messages.push(Message { sender_id, content });
    }
}

/// A message in a room.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Sender's stable identifier.
    pub sender_id: u64,
    /// Message payload.
    pub content: Vec<u8>,
}

impl Message {
    /// Message content as UTF-8 string. Returns lossy conversion if invalid.
    pub fn content_str(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.content)
    }
}
