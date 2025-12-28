//! UI events
//!
//! Events fed into the App state machine from terminal input and client
//! notifications.

use crossterm::event::KeyCode;
use lockframe_core::mls::RoomId;

/// Events processed by the App state machine.
#[derive(Debug, Clone)]
pub enum AppEvent {
    /// Keyboard input.
    Key(KeyCode),

    /// Periodic tick (for animations, polling).
    Tick,

    /// Terminal resize (columns, rows).
    Resize(u16, u16),

    /// Connection established with server.
    Connected {
        /// Application-layer session ID.
        session_id: u64,
    },

    /// Successfully joined a room.
    RoomJoined {
        /// Room UUID.
        room_id: RoomId,
    },

    /// Left a room (self-initiated or removed).
    RoomLeft {
        /// Room UUID.
        room_id: RoomId,
    },

    /// Message received in a room.
    MessageReceived {
        /// Room UUID.
        room_id: RoomId,
        /// Sender's stable identifier.
        sender_id: u64,
        /// Message payload.
        content: Vec<u8>,
    },

    /// Member added to a room.
    MemberAdded {
        /// Room UUID.
        room_id: RoomId,
        /// New member's identifier.
        member_id: u64,
    },

    /// Member removed from a room.
    MemberRemoved {
        /// Room UUID.
        room_id: RoomId,
        /// Removed member's identifier.
        member_id: u64,
    },

    /// Error notification.
    Error {
        /// Human-readable error message.
        message: String,
    },
}
