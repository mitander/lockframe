//! Application state machine.
//!
//! This module defines the [`App`] state machine, which manages the interactive
//! state of the application completely decoupled from I/O and protocol
//! mechanics.
//!
//! This is a pure state machine: it consumes [`crate::AppEvent`] inputs and
//! produces [`crate::AppAction`] instructions for the runtime to execute.
//!
//! # Responsibilities
//!
//! - Tracks the list of rooms, unread badges, and the currently active room.
//! - Stores terminal dimensions to handle resize events.
//! - Tracks high-level connection state for UI feedback.

use std::collections::HashMap;

use lockframe_core::mls::RoomId;

use crate::{AppAction, AppEvent, ConnectionState, RoomState};

/// Application state machine.
///
/// Pure state machine that processes events and produces actions.
/// No I/O dependencies - fully testable in simulation.
#[derive(Debug, Clone)]
pub struct App {
    /// Connection state.
    state: ConnectionState,
    /// Server address for connection.
    server_addr: String,
    /// Per-room state (messages, members, unread).
    rooms: HashMap<RoomId, RoomState>,
    /// Currently active room. `None` if no room is selected.
    active_room: Option<RoomId>,
    /// Terminal dimensions (columns, rows).
    terminal_size: (u16, u16),
    /// Transient status message. `None` if no message.
    status_message: Option<String>,
}

impl App {
    /// Create a new App with the given server address.
    pub fn new(server_addr: String) -> Self {
        Self {
            state: ConnectionState::Disconnected,
            server_addr,
            rooms: HashMap::new(),
            active_room: None,
            terminal_size: (80, 24),
            status_message: None,
        }
    }

    /// Process an event and return actions.
    pub fn handle(&mut self, event: AppEvent) -> Vec<AppAction> {
        match event {
            AppEvent::Tick => vec![],
            AppEvent::Resize(cols, rows) => {
                self.terminal_size = (cols, rows);
                vec![AppAction::Render]
            },
            AppEvent::Connecting => {
                self.state = ConnectionState::Connecting;
                vec![AppAction::Render]
            },
            AppEvent::Connected { session_id, sender_id } => {
                self.state = ConnectionState::Connected { session_id, sender_id };
                vec![AppAction::Render]
            },
            AppEvent::RoomJoined { room_id } => {
                let is_new = !self.rooms.contains_key(&room_id);
                self.rooms.entry(room_id).or_insert_with(|| RoomState::new(room_id));
                if self.active_room.is_none() {
                    self.active_room = Some(room_id);
                }
                if is_new {
                    self.status_message = Some(format!("Joined room {room_id}"));
                }
                vec![AppAction::Render]
            },
            AppEvent::RoomLeft { room_id } => {
                self.rooms.remove(&room_id);
                if self.active_room == Some(room_id) {
                    self.active_room = self.rooms.keys().next().copied();
                }
                vec![AppAction::Render]
            },
            AppEvent::MessageReceived { room_id, sender_id, content } => {
                if let Some(room) = self.rooms.get_mut(&room_id) {
                    room.add_message(sender_id, content);
                    if self.active_room != Some(room_id) {
                        room.unread = true;
                    }
                }
                vec![AppAction::Render]
            },
            AppEvent::MemberAdded { room_id, member_id } => {
                if let Some(room) = self.rooms.get_mut(&room_id) {
                    room.members.insert(member_id);
                }
                self.status_message = Some(format!("Added member {member_id} to room"));
                vec![AppAction::Render]
            },
            AppEvent::MemberRemoved { room_id, member_id } => {
                if let Some(room) = self.rooms.get_mut(&room_id) {
                    room.members.remove(&member_id);
                }
                vec![AppAction::Render]
            },
            AppEvent::Error { message } => {
                self.status_message = Some(format!("Error: {message}"));
                vec![AppAction::Render]
            },
        }
    }

    /// Set a status message to display to the user.
    pub fn set_status(&mut self, message: impl Into<String>) {
        self.status_message = Some(message.into());
    }

    /// Initiate connection to the server.
    pub fn connect(&mut self) -> Vec<AppAction> {
        self.state = ConnectionState::Connecting;
        vec![AppAction::Connect { server_addr: self.server_addr.clone() }, AppAction::Render]
    }

    /// Create a new room with the given ID.
    pub fn create_room(&mut self, room_id: RoomId) -> Vec<AppAction> {
        self.status_message = Some(format!("Creating room {room_id}..."));
        vec![AppAction::CreateRoom { room_id }, AppAction::Render]
    }

    /// Join an existing room via external commit.
    pub fn join_room(&self, room_id: RoomId) -> Vec<AppAction> {
        vec![AppAction::JoinRoom { room_id }, AppAction::Render]
    }

    /// Leave the specified room.
    pub fn leave_room(&self, room_id: RoomId) -> Vec<AppAction> {
        vec![AppAction::LeaveRoom { room_id }, AppAction::Render]
    }

    /// Publish a key package so others can add us to rooms.
    pub fn publish_key_package(&self) -> Vec<AppAction> {
        vec![AppAction::PublishKeyPackage, AppAction::Render]
    }

    /// Add a member to the specified room by fetching their key package.
    pub fn add_member(&mut self, room_id: RoomId, user_id: u64) -> Vec<AppAction> {
        self.status_message = Some(format!("Adding user {user_id}..."));
        vec![AppAction::AddMember { room_id, user_id }, AppAction::Render]
    }

    /// Send a message to the specified room.
    pub fn send_message(&self, room_id: RoomId, content: Vec<u8>) -> Vec<AppAction> {
        vec![AppAction::SendMessage { room_id, content }, AppAction::Render]
    }

    /// Quit the application.
    pub fn quit(&self) -> Vec<AppAction> {
        vec![AppAction::Quit]
    }

    /// Set the active room.
    pub fn set_active_room(&mut self, room_id: RoomId) {
        if self.rooms.contains_key(&room_id) {
            self.active_room = Some(room_id);
            if let Some(room) = self.rooms.get_mut(&room_id) {
                room.unread = false;
            }
        }
    }

    /// Current connection state.
    pub fn connection_state(&self) -> &ConnectionState {
        &self.state
    }

    /// Server address (host:port).
    pub fn server_addr(&self) -> &str {
        &self.server_addr
    }

    /// All rooms the client has joined.
    pub fn rooms(&self) -> &HashMap<RoomId, RoomState> {
        &self.rooms
    }

    /// Currently selected room. `None` if no rooms joined.
    pub fn active_room(&self) -> Option<RoomId> {
        self.active_room
    }

    /// State of the currently selected room. `None` if no rooms joined.
    pub fn active_room_state(&self) -> Option<&RoomState> {
        self.active_room.and_then(|id| self.rooms.get(&id))
    }

    /// Terminal dimensions (columns, rows).
    pub fn terminal_size(&self) -> (u16, u16) {
        self.terminal_size
    }

    /// Transient status message. `None` if no message.
    pub fn status_message(&self) -> Option<&str> {
        self.status_message.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connected_app() -> App {
        let mut app = App::new("localhost:8080".into());
        app.state = ConnectionState::Connected { session_id: 1, sender_id: 42 };
        app
    }

    #[test]
    fn room_joined_preserves_messages() {
        let mut app = connected_app();
        let _ = app.handle(AppEvent::RoomJoined { room_id: 1 });
        let _ = app.handle(AppEvent::MessageReceived {
            room_id: 1,
            sender_id: 42,
            content: b"hello".to_vec(),
        });

        assert_eq!(app.rooms.get(&1).map(|r| r.messages.len()), Some(1));

        // Second RoomJoined should not clear messages
        let _ = app.handle(AppEvent::RoomJoined { room_id: 1 });
        assert_eq!(app.rooms.get(&1).map(|r| r.messages.len()), Some(1));
    }

    #[test]
    fn api_create_room() {
        let mut app = connected_app();
        let actions = app.create_room(100);

        assert!(matches!(actions.as_slice(), [
            AppAction::CreateRoom { room_id: 100 },
            AppAction::Render
        ]));
    }

    #[test]
    fn api_join_room() {
        let app = connected_app();
        let actions = app.join_room(200);

        assert!(matches!(actions.as_slice(), [
            AppAction::JoinRoom { room_id: 200 },
            AppAction::Render
        ]));
    }

    #[test]
    fn api_leave_room() {
        let app = connected_app();
        let actions = app.leave_room(100);

        assert!(matches!(actions.as_slice(), [
            AppAction::LeaveRoom { room_id: 100 },
            AppAction::Render
        ]));
    }

    #[test]
    fn api_add_member() {
        let mut app = connected_app();
        let actions = app.add_member(100, 42);

        assert!(matches!(actions.as_slice(), [
            AppAction::AddMember { room_id: 100, user_id: 42 },
            AppAction::Render
        ]));
    }

    #[test]
    fn api_send_message() {
        let app = connected_app();
        let actions = app.send_message(100, b"hello".to_vec());

        assert!(matches!(actions.as_slice(), [
            AppAction::SendMessage { room_id: 100, .. },
            AppAction::Render
        ]));
    }

    #[test]
    fn api_connect() {
        let mut app = App::new("localhost:8080".into());
        let actions = app.connect();

        assert!(matches!(actions.as_slice(), [AppAction::Connect { .. }, AppAction::Render]));
        assert!(matches!(app.state, ConnectionState::Connecting));
    }

    #[test]
    fn api_set_active_room() {
        let mut app = connected_app();
        let _ = app.handle(AppEvent::RoomJoined { room_id: 1 });
        let _ = app.handle(AppEvent::RoomJoined { room_id: 2 });

        app.set_active_room(2);
        assert_eq!(app.active_room, Some(2));

        // Setting non-existent room should be ignored
        app.set_active_room(999);
        assert_eq!(app.active_room, Some(2));
    }
}
