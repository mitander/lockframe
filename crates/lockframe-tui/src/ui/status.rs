//! Status bar
//!
//! Displays connection status and room information.

use lockframe_app::{App, ConnectionState};
use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
};

/// Render the status bar.
pub fn render(frame: &mut Frame, app: &App, area: Rect) {
    let connection_status = match app.connection_state() {
        ConnectionState::Disconnected => {
            Span::styled("Disconnected", Style::default().fg(Color::Red))
        },
        ConnectionState::Connecting => {
            Span::styled("Connecting...", Style::default().fg(Color::Yellow))
        },
        ConnectionState::Connected { sender_id, .. } => Span::styled(
            format!("Connected | Your ID: {sender_id}"),
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
        ),
    };

    let room_info = app.active_room_state().map_or_else(String::new, |room| {
        let member_count = room.members.len();
        let msg_count = room.messages.len();
        let room_short = room.room_id as u16;
        format!(" | Room: #{room_short:04x} | Members: {member_count} | Messages: {msg_count}")
    });

    let status_msg = app.status_message().map_or_else(String::new, |msg| format!(" | {msg}"));

    let status_line = Line::from(vec![
        Span::raw(" "),
        connection_status,
        Span::styled(room_info, Style::default().fg(Color::DarkGray)),
        Span::styled(status_msg, Style::default().fg(Color::Red)),
    ]);

    let paragraph =
        Paragraph::new(status_line).style(Style::default().bg(Color::DarkGray).fg(Color::White));

    frame.render_widget(paragraph, area);
}
