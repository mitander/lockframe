//! Chat area
//!
//! Displays messages in the active room.

use lockframe_app::App;
use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem},
};

const BORDER_SIZE: u16 = 2;

/// Render the chat area.
pub fn render(frame: &mut Frame, app: &App, area: Rect) {
    let title = if let Some(room_id) = app.active_room() {
        format!(" #{:04x} ", room_id as u16)
    } else {
        " No Room ".to_string()
    };

    let block = Block::default().borders(Borders::ALL).title(title);

    let items: Vec<ListItem> = if let Some(room) = app.active_room_state() {
        room.messages
            .iter()
            .map(|msg| {
                let sender = format!("<{:04x}>", msg.sender_id as u16);
                let content = msg.content_str();

                ListItem::new(Line::from(vec![
                    Span::styled(
                        sender,
                        Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(" "),
                    Span::raw(content.into_owned()),
                ]))
            })
            .collect()
    } else {
        vec![ListItem::new(Line::from(Span::styled(
            "Join a room to start chatting",
            Style::default().fg(Color::DarkGray),
        )))]
    };

    let visible_height = area.height.saturating_sub(BORDER_SIZE) as usize;
    let skip = items.len().saturating_sub(visible_height);
    let visible_items: Vec<_> = items.into_iter().skip(skip).collect();

    let list = List::new(visible_items).block(block);

    frame.render_widget(list, area);
}
