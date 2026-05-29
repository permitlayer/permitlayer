//! A small key/value detail-pane helper: a left-aligned dim key column
//! and a value column, rendered as a `Paragraph` of `Line`s inside a
//! bordered block.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use crate::cli::ui::theme_bridge;
use crate::cli::ui::views::Ctx;

/// One detail row.
pub struct Row {
    pub key: String,
    pub value: String,
}

impl Row {
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self { key: key.into(), value: value.into() }
    }
}

/// Render `rows` inside a bordered block titled `title`.
pub fn render(frame: &mut Frame, area: Rect, title: &str, rows: &[Row], ctx: &Ctx) {
    let key_width = rows.iter().map(|r| r.key.len()).max().unwrap_or(0);

    let lines: Vec<Line> = rows
        .iter()
        .map(|r| {
            let padded = format!("{:<width$}  ", r.key, width = key_width);
            Line::from(vec![
                Span::styled(padded, theme_bridge::dim(ctx.tokens.text_2, ctx.support)),
                Span::styled(r.value.clone(), theme_bridge::fg(ctx.tokens.text_0, ctx.support)),
            ])
        })
        .collect();

    let block = Block::default()
        .borders(Borders::ALL)
        .title(title.to_owned())
        .border_style(theme_bridge::fg(ctx.tokens.border, ctx.support));

    frame.render_widget(Paragraph::new(lines).block(block).wrap(Wrap { trim: false }), area);
}
