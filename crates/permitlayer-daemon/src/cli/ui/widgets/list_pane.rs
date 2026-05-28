//! Shared bordered list pane: bullet + primary name + dim secondary
//! text, with a highlighted selected row. Used by both the agents and
//! policies views, which previously copy-pasted this rendering.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState};

use crate::cli::ui::theme_bridge;
use crate::cli::ui::views::Ctx;

/// One row: a primary label and an optional dim secondary (e.g. last-seen
/// time, or a policy origin).
pub struct Item {
    pub primary: String,
    pub secondary: String,
}

impl Item {
    pub fn new(primary: impl Into<String>, secondary: impl Into<String>) -> Self {
        Self { primary: primary.into(), secondary: secondary.into() }
    }
}

/// Render a bordered, single-selection list into `area`.
pub fn render(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    items: &[Item],
    selected: usize,
    ctx: &Ctx,
) {
    let g = &ctx.glyphs;
    let bullet = format!("{} ", g.bullet);

    let list_items: Vec<ListItem> = items
        .iter()
        .map(|it| {
            ListItem::new(Line::from(vec![
                Span::styled(bullet.clone(), theme_bridge::dim(ctx.tokens.text_3, ctx.support)),
                Span::styled(it.primary.clone(), theme_bridge::fg(ctx.tokens.text_0, ctx.support)),
                Span::styled(
                    format!("  {}", it.secondary),
                    theme_bridge::dim(ctx.tokens.text_3, ctx.support),
                ),
            ]))
        })
        .collect();

    let block = Block::default()
        .borders(Borders::ALL)
        .title(title.to_owned())
        .border_style(theme_bridge::fg(ctx.tokens.border, ctx.support));

    let highlight = format!("{} ", g.selected);
    let list = List::new(list_items)
        .block(block)
        .highlight_symbol(&highlight)
        .highlight_style(theme_bridge::fg(ctx.tokens.accent, ctx.support));

    let mut state = ListState::default();
    state.select(Some(selected));
    frame.render_stateful_widget(list, area, &mut state);
}
