//! Terminal-agnostic keyboard input.

/// Keyboard input abstraction.
///
/// Decouples application logic from terminal libraries (crossterm, termion,
/// etc.) enabling deterministic simulation testing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyInput {
    /// Printable character.
    Char(char),
    /// Enter/Return key.
    Enter,
    /// Backspace key (delete character before cursor).
    Backspace,
    /// Delete key (delete character at cursor).
    Delete,
    /// Tab key (cycle rooms).
    Tab,
    /// Escape key (quit).
    Esc,
    /// Left arrow key.
    Left,
    /// Right arrow key.
    Right,
    /// Up arrow key.
    Up,
    /// Down arrow key.
    Down,
    /// Home key (cursor to start).
    Home,
    /// End key (cursor to end).
    End,
}
