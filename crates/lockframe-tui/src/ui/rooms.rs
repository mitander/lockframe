//! Rooms sidebar
//!
//! Displays the list of joined rooms with unread indicators.

use lockframe_app::App;
use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem},
};

const ACTIVE_PREFIX: &str = ">";
const INACTIVE_PREFIX: &str = " ";
const ROOM_ID_PREFIX: &str = "#";
const UNREAD_MARKER: &str = "*";
const EMPTY_MARKER: &str = "";
const ROOM_ID_HEX_WIDTH: usize = 4;

enum RoomDisplayState {
    Active,
    Unread,
    Normal,
}

/// Render the rooms sidebar.
pub fn render(frame: &mut Frame, app: &App, area: Rect) {
    let mut room_ids: Vec<_> = app.rooms().keys().copied().collect();
    room_ids.sort_unstable();

    let items: Vec<ListItem> = room_ids
        .iter()
        .map(|&room_id| {
            let state = if app.active_room() == Some(room_id) {
                RoomDisplayState::Active
            } else if app.rooms().get(&room_id).is_some_and(|r| r.unread) {
                RoomDisplayState::Unread
            } else {
                RoomDisplayState::Normal
            };

            let full_hex = format!("{room_id:x}");
            let tail = &full_hex[full_hex.len().saturating_sub(ROOM_ID_HEX_WIDTH)..];
            let room_name =
                format!("{ROOM_ID_PREFIX}{tail:0>ROOM_ID_HEX_WIDTH$}");

            let (prefix, suffix, style) = match state {
                RoomDisplayState::Active => (
                    ACTIVE_PREFIX,
                    EMPTY_MARKER,
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                ),
                RoomDisplayState::Unread => {
                    (INACTIVE_PREFIX, UNREAD_MARKER, Style::default().fg(Color::Cyan))
                },
                RoomDisplayState::Normal => (INACTIVE_PREFIX, EMPTY_MARKER, Style::default()),
            };

            let unread_style = Style::default().fg(Color::Red);

            ListItem::new(Line::from(vec![
                Span::raw(prefix),
                Span::styled(room_name, style),
                Span::styled(suffix, unread_style),
            ]))
        })
        .collect();

    let block = Block::default().borders(Borders::ALL).title(" Rooms ");
    let list = List::new(items).block(block);

    frame.render_widget(list, area);
}
