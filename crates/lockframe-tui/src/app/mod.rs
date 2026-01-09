//! UI state machine
//!
//! Pure state machine that processes terminal and client events, producing
//! actions for the runtime to execute. Completely decoupled from I/O.
//!
//! # Architecture
//!
//! The App wraps a [`lockframe_client::Client`] and manages UI-specific state
//! like the input buffer, active room, and terminal size. It translates
//! terminal events into client operations and client events into UI updates.

mod action;
mod event;
mod state;

use std::collections::HashMap;

pub use action::AppAction;
pub use event::AppEvent;
use lockframe_core::mls::RoomId;
pub use state::{ConnectionState, Message, RoomState};

/// UI state machine.
///
/// Manages UI state (input buffer, active room, terminal size) and delegates
/// protocol operations to the wrapped client. Pure and testable.
#[derive(Debug, Clone)]
pub struct App {
    /// Connection state.
    state: ConnectionState,
    /// Server address for connection.
    server_addr: String,
    /// Per-room state (messages, members, unread).
    rooms: HashMap<RoomId, RoomState>,
    /// Currently active room. `None` if no room selected.
    active_room: Option<RoomId>,
    /// Input line buffer.
    input_buffer: String,
    /// Cursor position in input buffer.
    input_cursor: usize,
    /// Terminal dimensions (columns, rows).
    terminal_size: (u16, u16),
    /// Status message to display.
    status_message: Option<String>,
}

impl App {
    /// Create a new App in disconnected state.
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

    /// Process an event and return actions for the runtime.
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
                self.status_message = Some(format!("Error: {}", message));
                vec![AppAction::Render]
            },
        }
    }

    /// Handle keyboard input.
    fn handle_key(&mut self, key: crossterm::event::KeyCode) -> Vec<AppAction> {
        use crossterm::event::KeyCode;

        match key {
            KeyCode::Char(c) => {
                self.input_buffer.insert(self.input_cursor, c);
                self.input_cursor = self.input_cursor.saturating_add(1);
                vec![AppAction::Render]
            },
            KeyCode::Backspace => {
                if self.input_cursor > 0 {
                    self.input_cursor = self.input_cursor.saturating_sub(1);
                    self.input_buffer.remove(self.input_cursor);
                }
                vec![AppAction::Render]
            },
            KeyCode::Delete => {
                if self.input_cursor < self.input_buffer.len() {
                    self.input_buffer.remove(self.input_cursor);
                }
                vec![AppAction::Render]
            },
            KeyCode::Left => {
                self.input_cursor = self.input_cursor.saturating_sub(1);
                vec![AppAction::Render]
            },
            KeyCode::Right => {
                if self.input_cursor < self.input_buffer.len() {
                    self.input_cursor = self.input_cursor.saturating_add(1);
                }
                vec![AppAction::Render]
            },
            KeyCode::Home => {
                self.input_cursor = 0;
                vec![AppAction::Render]
            },
            KeyCode::End => {
                self.input_cursor = self.input_buffer.len();
                vec![AppAction::Render]
            },
            KeyCode::Enter => self.handle_enter(),
            KeyCode::Tab => self.cycle_room(),
            KeyCode::Esc => vec![AppAction::Quit],
            _ => vec![],
        }
    }

    /// Handle Enter key (send message or execute command).
    fn handle_enter(&mut self) -> Vec<AppAction> {
        if self.input_buffer.is_empty() {
            return vec![];
        }

        let input = std::mem::take(&mut self.input_buffer);
        self.input_cursor = 0;

        // Commands start with /
        if let Some(cmd) = input.strip_prefix('/') {
            return self.handle_command(cmd);
        }

        // Send message to active room
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

    /// Handle slash commands.
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
                if parts.get(1).is_none() {
                    self.status_message = Some("Usage: /create <room_id>".into());
                    return vec![AppAction::Render];
                }
                if let Some(room_id_str) = parts.get(1) {
                    if let Ok(room_id) = room_id_str.parse::<u128>() {
                        self.status_message = Some(format!("Creating room {room_id}..."));
                        return vec![AppAction::CreateRoom { room_id }, AppAction::Render];
                    }
                    self.status_message = Some("Error: Invalid room ID".into());
                }
                vec![AppAction::Render]
            },
            "join" => {
                if let Some(room_id_str) = parts.get(1) {
                    if let Ok(room_id) = room_id_str.parse::<u128>() {
                        return vec![AppAction::JoinRoom { room_id }, AppAction::Render];
                    }
                }
                vec![AppAction::Render]
            },
            "leave" => self.active_room.map_or_else(
                || vec![AppAction::Render],
                |room_id| vec![AppAction::LeaveRoom { room_id }, AppAction::Render],
            ),
            "publish" => vec![AppAction::PublishKeyPackage, AppAction::Render],
            "add" => {
                if self.active_room.is_none() {
                    self.status_message = Some("Error: No active room. Use /create first".into());
                    return vec![AppAction::Render];
                }
                if parts.get(1).is_none() {
                    self.status_message = Some("Usage: /add <user_id>".into());
                    return vec![AppAction::Render];
                }
                if let (Some(room_id), Some(user_id_str)) = (self.active_room, parts.get(1)) {
                    if let Ok(user_id) = user_id_str.parse::<u64>() {
                        self.status_message = Some(format!("Adding user {user_id} to room..."));
                        return vec![AppAction::AddMember { room_id, user_id }, AppAction::Render];
                    }
                    self.status_message = Some("Error: Invalid user ID".into());
                }
                vec![AppAction::Render]
            },
            "quit" | "q" => vec![AppAction::Quit],
            _ => vec![AppAction::Render],
        }
    }

    /// Cycle to next room (Tab key).
    fn cycle_room(&mut self) -> Vec<AppAction> {
        if self.rooms.is_empty() {
            return vec![];
        }

        let mut room_ids: Vec<_> = self.rooms.keys().copied().collect();
        room_ids.sort_unstable();

        let current_idx = self.active_room.and_then(|id| room_ids.iter().position(|&r| r == id));

        // Calculate next index with wrapping
        let len = room_ids.len();
        let next_idx = current_idx.map_or(0, |idx| {
            let next = idx.saturating_add(1);
            if next >= len { 0 } else { next }
        });

        // INVARIANT: next_idx is always valid since we checked rooms.is_empty()
        // and the wrapping logic ensures it's within bounds
        if let Some(&next_room) = room_ids.get(next_idx) {
            self.active_room = Some(next_room);
        }

        // Mark as read when switching to room
        if let Some(room) = self.active_room.and_then(|id| self.rooms.get_mut(&id)) {
            room.unread = false;
        }

        vec![AppAction::Render]
    }

    /// Connection state.
    pub fn connection_state(&self) -> &ConnectionState {
        &self.state
    }

    /// Server address.
    pub fn server_addr(&self) -> &str {
        &self.server_addr
    }

    /// All rooms.
    pub fn rooms(&self) -> &HashMap<RoomId, RoomState> {
        &self.rooms
    }

    /// Active room ID. `None` if no room selected.
    pub fn active_room(&self) -> Option<RoomId> {
        self.active_room
    }

    /// Active room state. `None` if no room selected.
    pub fn active_room_state(&self) -> Option<&RoomState> {
        self.active_room.and_then(|id| self.rooms.get(&id))
    }

    /// Input buffer contents.
    pub fn input_buffer(&self) -> &str {
        &self.input_buffer
    }

    /// Cursor position in input buffer.
    pub fn input_cursor(&self) -> usize {
        self.input_cursor
    }

    /// Terminal dimensions (columns, rows).
    pub fn terminal_size(&self) -> (u16, u16) {
        self.terminal_size
    }

    /// Status message to display. `None` if no message.
    pub fn status_message(&self) -> Option<&str> {
        self.status_message.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use crossterm::event::KeyCode;

    use super::*;

    fn new_connected_app() -> App {
        let mut app = App::new("localhost:8080".to_string());
        app.state = ConnectionState::Connected { session_id: 1, sender_id: 42 };
        app
    }

    #[test]
    fn enter_sends_message_and_clears_input() {
        let mut app = new_connected_app();
        let _ = app.handle(AppEvent::RoomJoined { room_id: 1 });
        app.input_buffer = "hello".to_string();
        app.input_cursor = 5;

        let actions = app.handle(AppEvent::Key(KeyCode::Enter));

        assert!(matches!(actions.as_slice(), [
            AppAction::SendMessage { room_id: 1, .. },
            AppAction::Render
        ]));
        assert!(app.input_buffer.is_empty());
        assert_eq!(app.input_cursor, 0);
    }

    #[test]
    fn tab_cycles_through_rooms() {
        let mut app = new_connected_app();
        let _ = app.handle(AppEvent::RoomJoined { room_id: 1 });
        let _ = app.handle(AppEvent::RoomJoined { room_id: 2 });
        let _ = app.handle(AppEvent::RoomJoined { room_id: 3 });
        app.active_room = Some(1);

        let _ = app.handle(AppEvent::Key(KeyCode::Tab));
        assert_eq!(app.active_room, Some(2));

        let _ = app.handle(AppEvent::Key(KeyCode::Tab));
        assert_eq!(app.active_room, Some(3));

        let _ = app.handle(AppEvent::Key(KeyCode::Tab));
        assert_eq!(app.active_room, Some(1));
    }

    #[test]
    fn esc_quits() {
        let mut app = new_connected_app();
        let actions = app.handle(AppEvent::Key(KeyCode::Esc));
        assert!(matches!(actions.as_slice(), [AppAction::Quit]));
    }

    #[test]
    fn connect_command_initiates_connection() {
        let mut app = App::new("localhost:8080".to_string());
        app.input_buffer = "/connect".to_string();
        app.input_cursor = 8;

        let actions = app.handle(AppEvent::Key(KeyCode::Enter));

        assert!(matches!(actions.as_slice(), [AppAction::Connect { .. }, AppAction::Render]));
        assert!(matches!(app.state, ConnectionState::Connecting));
    }

    #[test]
    fn message_received_marks_inactive_room_unread() {
        let mut app = new_connected_app();
        let _ = app.handle(AppEvent::RoomJoined { room_id: 1 });
        let _ = app.handle(AppEvent::RoomJoined { room_id: 2 });
        app.active_room = Some(1);

        let _ = app.handle(AppEvent::MessageReceived {
            room_id: 2,
            sender_id: 42,
            content: b"hello".to_vec(),
        });

        assert!(app.rooms.get(&2).is_some_and(|r| r.unread));
        assert!(app.rooms.get(&1).is_some_and(|r| !r.unread));
    }

    #[test]
    fn room_joined_on_existing_room_preserves_messages() {
        let mut app = new_connected_app();

        // Join room and add a message
        let _ = app.handle(AppEvent::RoomJoined { room_id: 1 });
        let _ = app.handle(AppEvent::MessageReceived {
            room_id: 1,
            sender_id: 42,
            content: b"hello".to_vec(),
        });

        assert_eq!(app.rooms.get(&1).map(|r| r.messages.len()), Some(1));

        // RoomJoined again (e.g., from epoch update after /add) should NOT clear
        // messages
        let _ = app.handle(AppEvent::RoomJoined { room_id: 1 });

        assert_eq!(
            app.rooms.get(&1).map(|r| r.messages.len()),
            Some(1),
            "RoomJoined on existing room should not clear message history"
        );
    }
}
