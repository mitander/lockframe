//! Input state and key handling for the TUI.
//!
//! This module owns all text input state (buffer, cursor) and handles
//! character-level key events. Command parsing happens here on Enter.

use lockframe_app::{App, AppAction};

use crate::commands::{self, Command};

/// Key input events from the terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyInput {
    /// Character input.
    Char(char),
    /// Enter/Return key.
    Enter,
    /// Backspace key.
    Backspace,
    /// Delete key.
    Delete,
    /// Tab key.
    Tab,
    /// Escape key.
    Esc,
    /// Left arrow.
    Left,
    /// Right arrow.
    Right,
    /// Up arrow.
    Up,
    /// Down arrow.
    Down,
    /// Home key.
    Home,
    /// End key.
    End,
}

/// Input state for the TUI.
///
/// Manages the text input buffer and cursor position.
/// Handles all character-level key events.
#[derive(Debug, Default)]
pub struct InputState {
    /// Text buffer for user input.
    buffer: String,
    /// Cursor position within the buffer.
    cursor: usize,
}

impl InputState {
    /// Create a new empty input state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Current text in the input buffer.
    pub fn buffer(&self) -> &str {
        &self.buffer
    }

    /// Current cursor position.
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// Handle a key input event.
    ///
    /// Returns actions to process (may be empty for input-only keys,
    /// or contain protocol actions for commands).
    pub fn handle_key(&mut self, key: KeyInput, app: &mut App) -> Vec<AppAction> {
        match key {
            KeyInput::Char(c) => {
                self.buffer.insert(self.cursor, c);
                self.cursor = self.cursor.saturating_add(1);
                vec![AppAction::Render]
            },
            KeyInput::Backspace => {
                if self.cursor > 0 {
                    self.cursor = self.cursor.saturating_sub(1);
                    self.buffer.remove(self.cursor);
                }
                vec![AppAction::Render]
            },
            KeyInput::Delete => {
                if self.cursor < self.buffer.len() {
                    self.buffer.remove(self.cursor);
                }
                vec![AppAction::Render]
            },
            KeyInput::Left => {
                self.cursor = self.cursor.saturating_sub(1);
                vec![AppAction::Render]
            },
            KeyInput::Right => {
                if self.cursor < self.buffer.len() {
                    self.cursor = self.cursor.saturating_add(1);
                }
                vec![AppAction::Render]
            },
            KeyInput::Home => {
                self.cursor = 0;
                vec![AppAction::Render]
            },
            KeyInput::End => {
                self.cursor = self.buffer.len();
                vec![AppAction::Render]
            },
            KeyInput::Enter => self.handle_enter(app),
            KeyInput::Tab => self.handle_tab(app),
            KeyInput::Esc => vec![AppAction::Quit],
            KeyInput::Up | KeyInput::Down => vec![],
        }
    }

    /// Handle Enter key - parse command and call App API.
    fn handle_enter(&mut self, app: &mut App) -> Vec<AppAction> {
        let text = std::mem::take(&mut self.buffer);
        self.cursor = 0;

        if text.is_empty() {
            return vec![];
        }

        match commands::parse(&text) {
            Command::Connect => {
                app.set_status("Already connected");
                vec![AppAction::Render]
            },
            Command::CreateRoom { room_id } => app.create_room(room_id),
            Command::JoinRoom { room_id } => app.join_room(room_id),
            Command::LeaveActiveRoom => {
                if let Some(room_id) = app.active_room() {
                    app.leave_room(room_id)
                } else {
                    app.set_status("No active room");
                    vec![AppAction::Render]
                }
            },
            Command::PublishKeyPackage => app.publish_key_package(),
            Command::AddMember { user_id } => {
                if let Some(room_id) = app.active_room() {
                    app.add_member(room_id, user_id)
                } else {
                    app.set_status("No active room");
                    vec![AppAction::Render]
                }
            },
            Command::Quit => app.quit(),
            Command::Message { content } => {
                if let Some(room_id) = app.active_room() {
                    app.send_message(room_id, content.into_bytes())
                } else {
                    app.set_status("No active room to send message");
                    vec![AppAction::Render]
                }
            },
            Command::Unknown { input } => {
                app.set_status(format!("Unknown command: {input}"));
                vec![AppAction::Render]
            },
            Command::InvalidArgs { command, error } => {
                app.set_status(format!("/{command}: {error}"));
                vec![AppAction::Render]
            },
        }
    }

    /// Handle Tab key - cycle through rooms.
    ///
    /// Cycles to the next room in sorted order, wrapping around.
    fn handle_tab(&self, app: &mut App) -> Vec<AppAction> {
        let rooms = app.rooms();
        if rooms.is_empty() {
            return vec![];
        }

        let mut room_ids: Vec<_> = rooms.keys().copied().collect();
        room_ids.sort_unstable();

        let current_idx = app.active_room().and_then(|id| room_ids.iter().position(|&r| r == id));
        let len = room_ids.len();
        let next_idx = current_idx.map_or(0, |idx| {
            let next = idx.saturating_add(1);
            if next >= len { 0 } else { next }
        });

        if let Some(&next_room) = room_ids.get(next_idx) {
            app.set_active_room(next_room);
        }

        vec![AppAction::Render]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn char_input_adds_to_buffer() {
        let mut input = InputState::new();
        let mut app = App::new("localhost:4433".into());

        input.handle_key(KeyInput::Char('h'), &mut app);
        input.handle_key(KeyInput::Char('i'), &mut app);

        assert_eq!(input.buffer(), "hi");
        assert_eq!(input.cursor(), 2);
    }

    #[test]
    fn backspace_removes_char() {
        let mut input = InputState::new();
        let mut app = App::new("localhost:4433".into());

        input.handle_key(KeyInput::Char('a'), &mut app);
        input.handle_key(KeyInput::Char('b'), &mut app);
        input.handle_key(KeyInput::Backspace, &mut app);

        assert_eq!(input.buffer(), "a");
        assert_eq!(input.cursor(), 1);
    }

    #[test]
    fn enter_clears_buffer() {
        let mut input = InputState::new();
        let mut app = App::new("localhost:4433".into());

        input.handle_key(KeyInput::Char('t'), &mut app);
        input.handle_key(KeyInput::Char('e'), &mut app);
        input.handle_key(KeyInput::Char('s'), &mut app);
        input.handle_key(KeyInput::Char('t'), &mut app);
        input.handle_key(KeyInput::Enter, &mut app);

        assert!(input.buffer().is_empty());
        assert_eq!(input.cursor(), 0);
    }

    #[test]
    fn cursor_movement() {
        let mut input = InputState::new();
        let mut app = App::new("localhost:4433".into());

        input.handle_key(KeyInput::Char('a'), &mut app);
        input.handle_key(KeyInput::Char('b'), &mut app);
        input.handle_key(KeyInput::Char('c'), &mut app);

        input.handle_key(KeyInput::Home, &mut app);
        assert_eq!(input.cursor(), 0);

        input.handle_key(KeyInput::End, &mut app);
        assert_eq!(input.cursor(), 3);

        input.handle_key(KeyInput::Left, &mut app);
        assert_eq!(input.cursor(), 2);

        input.handle_key(KeyInput::Right, &mut app);
        assert_eq!(input.cursor(), 3);
    }

    #[test]
    fn tab_cycles_rooms() {
        use lockframe_app::AppEvent;

        let mut input = InputState::new();
        let mut app = App::new("localhost:4433".into());

        // Join two rooms
        app.handle(AppEvent::RoomJoined { room_id: 1 });
        app.handle(AppEvent::RoomJoined { room_id: 2 });

        // Initial active room is 1 (first joined)
        assert_eq!(app.active_room(), Some(1));

        // Tab cycles to next room
        input.handle_key(KeyInput::Tab, &mut app);
        assert_eq!(app.active_room(), Some(2));

        // Tab wraps around
        input.handle_key(KeyInput::Tab, &mut app);
        assert_eq!(app.active_room(), Some(1));
    }
}
