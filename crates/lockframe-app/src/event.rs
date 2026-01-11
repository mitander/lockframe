//! Application input events.
//!
//! This module defines [`AppEvent`], the comprehensive set of inputs that drive
//! the [`crate::App`] state machine.
//!
//! Events originate from two distinct sources:
//! - User interactions (Keyboard, Resize) and system ticks.
//! - Protocol notifications translated from the underlying client.

use lockframe_core::mls::RoomId;

use crate::KeyInput;

/// Events processed by the App state machine.
#[derive(Debug, Clone)]
pub enum AppEvent {
    /// Keyboard input.
    Key(KeyInput),

    /// Periodic tick.
    Tick,

    /// Terminal resize (columns, rows).
    Resize(u16, u16),

    /// Connection in progress.
    Connecting,

    /// Connected to server.
    Connected {
        /// Application-layer session ID.
        session_id: u64,
        /// Client's sender ID.
        sender_id: u64,
    },

    /// Joined a room.
    RoomJoined {
        /// 128-bit room UUID.
        room_id: RoomId,
    },

    /// Left a room.
    RoomLeft {
        /// 128-bit room UUID.
        room_id: RoomId,
    },

    /// Message received.
    MessageReceived {
        /// 128-bit room UUID.
        room_id: RoomId,
        /// ID of the sender.
        sender_id: u64,
        /// Message content bytes.
        content: Vec<u8>,
    },

    /// Member added to room.
    MemberAdded {
        /// 128-bit room UUID.
        room_id: RoomId,
        /// ID of the added member.
        member_id: u64,
    },

    /// Member removed from room.
    MemberRemoved {
        /// 128-bit room UUID.
        room_id: RoomId,
        /// ID of the removed member.
        member_id: u64,
    },

    /// Error occurred.
    Error {
        /// Error description.
        message: String,
    },
}
