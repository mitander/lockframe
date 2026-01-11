//! Observable application state types.
//!
//! This module defines the data structures that represent the applications
//! current view of the world, such as [`RoomState`] and [`ConnectionState`].
//!
//! These structures serve as the "View Model" for the application. They contain
//! the subset of protocol state necessary for rendering the UI without exposing
//! the cryptographic complexities of the underlying client.

use std::collections::HashSet;

use lockframe_core::mls::RoomId;

/// Connection state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionState {
    /// Not connected to server.
    Disconnected,
    /// Connection in progress.
    Connecting,
    /// Connected with established session.
    Connected {
        /// Application-layer session ID.
        session_id: u64,
        /// Client's sender ID.
        sender_id: u64,
    },
}

/// Per-room state.
#[derive(Debug, Clone)]
pub struct RoomState {
    /// 128-bit room UUID.
    pub room_id: RoomId,
    /// Messages in this room.
    pub messages: Vec<Message>,
    /// Member IDs in this room.
    pub members: HashSet<u64>,
    /// Room has unread messages.
    pub unread: bool,
}

impl RoomState {
    /// Create empty room state.
    pub fn new(room_id: RoomId) -> Self {
        Self { room_id, messages: Vec::new(), members: HashSet::new(), unread: false }
    }

    /// Add a message to this room.
    pub fn add_message(&mut self, sender_id: u64, content: Vec<u8>) {
        self.messages.push(Message { sender_id, content });
    }
}

/// A message in a room.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// ID of the sender.
    pub sender_id: u64,
    /// Message content bytes.
    pub content: Vec<u8>,
}

impl Message {
    /// Message content as UTF-8 string (lossy conversion).
    pub fn content_str(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.content)
    }
}
