//! Application side-effects and intents.
//!
//! This module defines the [`AppAction`] enum, which represents instructions
//! produced by the [`crate::App`] state machine for the runtime to execute.

use lockframe_core::mls::RoomId;

/// Actions produced by the App state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppAction {
    /// Render the UI.
    Render,

    /// Quit the application.
    Quit,

    /// Connect to server.
    Connect {
        /// Server address (host:port).
        server_addr: String,
    },

    /// Create a new room.
    CreateRoom {
        /// 128-bit room UUID.
        room_id: RoomId,
    },

    /// Join an existing room via external commit.
    JoinRoom {
        /// 128-bit room UUID.
        room_id: RoomId,
    },

    /// Leave a room.
    LeaveRoom {
        /// 128-bit room UUID.
        room_id: RoomId,
    },

    /// Send a message.
    SendMessage {
        /// 128-bit room UUID.
        room_id: RoomId,
        /// Message content bytes.
        content: Vec<u8>,
    },

    /// Publish KeyPackage to server.
    PublishKeyPackage,

    /// Add member by fetching their KeyPackage.
    AddMember {
        /// 128-bit room UUID.
        room_id: RoomId,
        /// User ID to add.
        user_id: u64,
    },
}
