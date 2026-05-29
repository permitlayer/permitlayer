//! The single-line footer: keybinding hints, a transient error banner,
//! and a `loading…` indicator. Errors take priority over hints.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::cli::ui::app::App;
use crate::cli::ui::theme_bridge;
use crate::cli::ui::views::Ctx;

/// One-line key hints, expanded when `?` is toggled on.
const HINTS_SHORT: &str = "↑/↓ move · Enter detail · Tab view · r refresh · ? help · q quit";
const HINTS_LONG: &str = "↑/↓ or j/k move · Enter focus detail · Esc back · Tab switch view · r refresh · ? help · q/Ctrl-C quit";

pub fn render(frame: &mut Frame, area: Rect, app: &App, ctx: &Ctx) {
    let line = if let Some(err) = &app.footer_error {
        Line::from(Span::styled(err.clone(), theme_bridge::fg(ctx.tokens.danger, ctx.support)))
    } else if app.is_loading() {
        Line::from(vec![
            Span::styled("loading… ", theme_bridge::fg(ctx.tokens.accent, ctx.support)),
            Span::styled(hints(app), theme_bridge::dim(ctx.tokens.text_2, ctx.support)),
        ])
    } else {
        Line::from(Span::styled(hints(app), theme_bridge::dim(ctx.tokens.text_2, ctx.support)))
    };

    frame.render_widget(Paragraph::new(line), area);
}

fn hints(app: &App) -> &'static str {
    if app.show_help { HINTS_LONG } else { HINTS_SHORT }
}
