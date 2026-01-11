//! Application state machine and UI logic.
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
//! Unlike the protocol client (which handles encryption and sequencing), this
//! module manages transient interaction state:
//!
//! - Manage the text buffer, cursor position, and command parsing.
//! - Tracks the list of rooms, unread badges, and the currently active room.
//! - Stores terminal dimensions to handle resize events.
//! - Tracks high-level connection state for UI feedback.

use std::collections::HashMap;

use lockframe_core::mls::RoomId;

use crate::{AppAction, AppEvent, ConnectionState, KeyInput, RoomState};

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
    /// Input line buffer.
    input_buffer: String,
    /// Cursor position in input buffer.
    input_cursor: usize,
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
            input_buffer: String::new(),
            input_cursor: 0,
            terminal_size: (80, 24),
            status_message: None,
        }
    }

    /// Process an event and return actions.
    pub fn handle(&mut self, event: AppEvent) -> Vec<AppAction> {
        match event {
            AppEvent::Key(key) => self.handle_key(key),
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

    fn handle_key(&mut self, key: KeyInput) -> Vec<AppAction> {
        match key {
            KeyInput::Char(c) => {
                self.input_buffer.insert(self.input_cursor, c);
                self.input_cursor = self.input_cursor.saturating_add(1);
                vec![AppAction::Render]
            },
            KeyInput::Backspace => {
                if self.input_cursor > 0 {
                    self.input_cursor = self.input_cursor.saturating_sub(1);
                    self.input_buffer.remove(self.input_cursor);
                }
                vec![AppAction::Render]
            },
            KeyInput::Delete => {
                if self.input_cursor < self.input_buffer.len() {
                    self.input_buffer.remove(self.input_cursor);
                }
                vec![AppAction::Render]
            },
            KeyInput::Left => {
                self.input_cursor = self.input_cursor.saturating_sub(1);
                vec![AppAction::Render]
            },
            KeyInput::Right => {
                if self.input_cursor < self.input_buffer.len() {
                    self.input_cursor = self.input_cursor.saturating_add(1);
                }
                vec![AppAction::Render]
            },
            KeyInput::Home => {
                self.input_cursor = 0;
                vec![AppAction::Render]
            },
            KeyInput::End => {
                self.input_cursor = self.input_buffer.len();
                vec![AppAction::Render]
            },
            KeyInput::Enter => self.handle_enter(),
            KeyInput::Tab => self.cycle_room(),
            KeyInput::Esc => vec![AppAction::Quit],
            KeyInput::Up | KeyInput::Down => vec![],
        }
    }

    fn handle_enter(&mut self) -> Vec<AppAction> {
        if self.input_buffer.is_empty() {
            return vec![];
        }

        let input = std::mem::take(&mut self.input_buffer);
        self.input_cursor = 0;

        if let Some(cmd) = input.strip_prefix('/') {
            return self.handle_command(cmd);
        }

        self.active_room.map_or_else(
            || vec![AppAction::Render],
            |room_id| {
                vec![
                    AppAction::SendMessage { room_id, content: input.into_bytes() },
                    AppAction::Render,
                ]
            },
        )
    }

    fn handle_command(&mut self, cmd: &str) -> Vec<AppAction> {
        let parts: Vec<&str> = cmd.split_whitespace().collect();
        let command = parts.first().copied().unwrap_or("");

        match command {
            "connect" => {
                self.state = ConnectionState::Connecting;
                vec![
                    AppAction::Connect { server_addr: self.server_addr.clone() },
                    AppAction::Render,
                ]
            },
            "create" => {
                let Some(room_id_str) = parts.get(1) else {
                    self.status_message = Some("Usage: /create <room_id>".into());
                    return vec![AppAction::Render];
                };
                match room_id_str.parse::<u128>() {
                    Ok(room_id) => {
                        self.status_message = Some(format!("Creating room {room_id}..."));
                        vec![AppAction::CreateRoom { room_id }, AppAction::Render]
                    },
                    Err(_) => {
                        self.status_message = Some("Error: Invalid room ID".into());
                        vec![AppAction::Render]
                    },
                }
            },
            "join" => {
                let Some(room_id_str) = parts.get(1) else {
                    self.status_message = Some("Usage: /join <room_id>".into());
                    return vec![AppAction::Render];
                };
                match room_id_str.parse::<u128>() {
                    Ok(room_id) => vec![AppAction::JoinRoom { room_id }, AppAction::Render],
                    Err(_) => {
                        self.status_message = Some("Error: Invalid room ID".into());
                        vec![AppAction::Render]
                    },
                }
            },
            "leave" => self.active_room.map_or_else(
                || vec![AppAction::Render],
                |room_id| vec![AppAction::LeaveRoom { room_id }, AppAction::Render],
            ),
            "publish" => vec![AppAction::PublishKeyPackage, AppAction::Render],
            "add" => {
                if self.active_room.is_none() {
                    self.status_message = Some("Error: No active room".into());
                    return vec![AppAction::Render];
                }
                let Some(user_id_str) = parts.get(1) else {
                    self.status_message = Some("Usage: /add <user_id>".into());
                    return vec![AppAction::Render];
                };
                match (self.active_room, user_id_str.parse::<u64>()) {
                    (Some(room_id), Ok(user_id)) => {
                        self.status_message = Some(format!("Adding user {user_id}..."));
                        vec![AppAction::AddMember { room_id, user_id }, AppAction::Render]
                    },
                    _ => {
                        self.status_message = Some("Error: Invalid user ID".into());
                        vec![AppAction::Render]
                    },
                }
            },
            "quit" | "q" => vec![AppAction::Quit],
            _ => vec![AppAction::Render],
        }
    }

    fn cycle_room(&mut self) -> Vec<AppAction> {
        if self.rooms.is_empty() {
            return vec![];
        }

        let mut room_ids: Vec<_> = self.rooms.keys().copied().collect();
        room_ids.sort_unstable();

        let current_idx = self.active_room.and_then(|id| room_ids.iter().position(|&r| r == id));
        let len = room_ids.len();
        let next_idx = current_idx.map_or(0, |idx| {
            let next = idx.saturating_add(1);
            if next >= len { 0 } else { next }
        });

        if let Some(&next_room) = room_ids.get(next_idx) {
            self.active_room = Some(next_room);
        }

        if let Some(room) = self.active_room.and_then(|id| self.rooms.get_mut(&id)) {
            room.unread = false;
        }

        vec![AppAction::Render]
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

    /// Current text input buffer.
    pub fn input_buffer(&self) -> &str {
        &self.input_buffer
    }

    /// Cursor position within input buffer.
    pub fn input_cursor(&self) -> usize {
        self.input_cursor
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
    fn enter_sends_message() {
        let mut app = connected_app();
        let _ = app.handle(AppEvent::RoomJoined { room_id: 1 });
        app.input_buffer = "hello".into();
        app.input_cursor = 5;

        let actions = app.handle(AppEvent::Key(KeyInput::Enter));

        assert!(matches!(actions.as_slice(), [
            AppAction::SendMessage { room_id: 1, .. },
            AppAction::Render
        ]));
        assert!(app.input_buffer.is_empty());
    }

    #[test]
    fn tab_cycles_rooms() {
        let mut app = connected_app();
        let _ = app.handle(AppEvent::RoomJoined { room_id: 1 });
        let _ = app.handle(AppEvent::RoomJoined { room_id: 2 });
        app.active_room = Some(1);

        let _ = app.handle(AppEvent::Key(KeyInput::Tab));
        assert_eq!(app.active_room, Some(2));

        let _ = app.handle(AppEvent::Key(KeyInput::Tab));
        assert_eq!(app.active_room, Some(1));
    }

    #[test]
    fn esc_quits() {
        let mut app = connected_app();
        let actions = app.handle(AppEvent::Key(KeyInput::Esc));
        assert!(matches!(actions.as_slice(), [AppAction::Quit]));
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
}
