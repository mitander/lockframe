//! Input line
//!
//! Displays the input buffer with cursor.

use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Style},
    widgets::{Block, Borders, Paragraph},
};

use crate::InputState;

const PROMPT_WIDTH: u16 = 3; // "> "
const INPUT_LINE_OFFSET_Y: u16 = 1; // inside top border
const RIGHT_PADDING: u16 = 1; // inside right border

/// Render the input line.
pub fn render(frame: &mut Frame, input: &InputState, area: Rect) {
    let block = Block::default().borders(Borders::ALL);

    let input_text = format!("> {}", input.buffer());
    let paragraph =
        Paragraph::new(input_text).style(Style::default().fg(Color::White)).block(block);

    frame.render_widget(paragraph, area);

    let available_width = area.width.saturating_sub(PROMPT_WIDTH + RIGHT_PADDING);
    let cursor_offset = (input.cursor() as u16).min(available_width);

    let cursor_x = area.x.saturating_add(PROMPT_WIDTH).saturating_add(cursor_offset);
    let cursor_y = area.y.saturating_add(INPUT_LINE_OFFSET_Y);
    let max_x = area.x.saturating_add(area.width).saturating_sub(RIGHT_PADDING);
    let cursor_x = cursor_x.min(max_x);

    frame.set_cursor_position((cursor_x, cursor_y));
}
