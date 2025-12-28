//! UI actions
//!
//! Actions produced by the App state machine for the runtime to execute.

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
        /// Room UUID.
        room_id: RoomId,
    },

    /// Join an existing room.
    JoinRoom {
        /// Room UUID.
        room_id: RoomId,
    },

    /// Leave a room.
    LeaveRoom {
        /// Room UUID.
        room_id: RoomId,
    },

    /// Send a message to a room.
    SendMessage {
        /// Room UUID.
        room_id: RoomId,
        /// Message payload.
        content: Vec<u8>,
    },
}
