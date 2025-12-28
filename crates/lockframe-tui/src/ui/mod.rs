//! UI rendering
//!
//! Rendering functions that convert App state into terminal output using
//! ratatui widgets. All functions are pure (no I/O), taking state and
//! returning widget trees.

mod chat;
mod input;
mod rooms;
mod status;

use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
};

use crate::App;

/// Render the entire UI.
pub fn render(frame: &mut Frame, app: &App) {
    const MAIN_AREA_MIN_HEIGHT: u16 = 3;
    const INPUT_HEIGHT: u16 = 3;
    const STATUS_HEIGHT: u16 = 1;

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(MAIN_AREA_MIN_HEIGHT),
            Constraint::Length(INPUT_HEIGHT),
            Constraint::Length(STATUS_HEIGHT),
        ])
        .split(frame.area());

    let [main_area, input_area, status_area] = chunks.as_ref() else {
        return;
    };

    render_main_area(frame, app, *main_area);
    input::render(frame, app, *input_area);
    status::render(frame, app, *status_area);
}

/// Render the main area (rooms sidebar + chat).
fn render_main_area(frame: &mut Frame, app: &App, area: Rect) {
    const ROOM_SIDEBAR_WIDTH: u16 = 12;
    const CHAT_AREA_MIN_WIDTH: u16 = 20;

    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(ROOM_SIDEBAR_WIDTH), Constraint::Min(CHAT_AREA_MIN_WIDTH)])
        .split(area);

    let [rooms_area, chat_area] = chunks.as_ref() else {
        return;
    };

    rooms::render(frame, app, *rooms_area);
    chat::render(frame, app, *chat_area);
}
