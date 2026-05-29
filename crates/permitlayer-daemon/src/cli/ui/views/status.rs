//! The always-visible 3-line status header. Reads only from `App.header`
//! (populated by the `/state` fetch) plus the static endpoint label.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::cli::ui::app::{App, HeaderStatus};
use crate::cli::ui::theme_bridge;
use crate::cli::ui::views::Ctx;

pub fn render(frame: &mut Frame, area: Rect, app: &App, ctx: &Ctx) {
    let g = &ctx.glyphs;
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" agentsso ")
        .border_style(theme_bridge::fg(ctx.tokens.border, ctx.support));

    let line = match &app.header {
        HeaderStatus::Unknown => Line::from(Span::styled(
            "daemon: connecting…",
            theme_bridge::dim(ctx.tokens.text_2, ctx.support),
        )),
        HeaderStatus::Running { version, kill_active, token_count } => {
            let (kill_glyph, kill_label, kill_color) = if *kill_active {
                (g.dot_on, "active", ctx.tokens.danger)
            } else {
                (g.dot_off, "inactive", ctx.tokens.muted)
            };
            Line::from(vec![
                Span::styled("daemon: ", theme_bridge::dim(ctx.tokens.text_2, ctx.support)),
                Span::styled(g.dot_on, theme_bridge::fg(ctx.tokens.success, ctx.support)),
                Span::styled(
                    format!(" running v{version}"),
                    theme_bridge::fg(ctx.tokens.text_0, ctx.support),
                ),
                Span::styled("  /  kill: ", theme_bridge::dim(ctx.tokens.text_2, ctx.support)),
                Span::styled(kill_glyph, theme_bridge::fg(kill_color, ctx.support)),
                Span::styled(format!(" {kill_label}"), theme_bridge::fg(kill_color, ctx.support)),
                Span::styled(
                    format!("  /  tokens {token_count}"),
                    theme_bridge::dim(ctx.tokens.text_2, ctx.support),
                ),
                Span::styled(
                    format!("  /  {}", app.endpoint_label),
                    theme_bridge::dim(ctx.tokens.text_3, ctx.support),
                ),
            ])
        }
        HeaderStatus::Unreachable => Line::from(vec![
            Span::styled("daemon: ", theme_bridge::dim(ctx.tokens.text_2, ctx.support)),
            Span::styled("unreachable", theme_bridge::fg(ctx.tokens.warn, ctx.support)),
            Span::styled(
                " — run: agentsso start",
                theme_bridge::dim(ctx.tokens.text_2, ctx.support),
            ),
        ]),
        HeaderStatus::Forbidden => Line::from(vec![
            Span::styled("daemon: ", theme_bridge::dim(ctx.tokens.text_2, ctx.support)),
            Span::styled("forbidden", theme_bridge::fg(ctx.tokens.danger, ctx.support)),
            Span::styled(
                " — control.token unreadable",
                theme_bridge::dim(ctx.tokens.text_2, ctx.support),
            ),
        ]),
        HeaderStatus::Error { status } => Line::from(vec![
            Span::styled("daemon: ", theme_bridge::dim(ctx.tokens.text_2, ctx.support)),
            Span::styled(
                format!("error (HTTP {status})"),
                theme_bridge::fg(ctx.tokens.danger, ctx.support),
            ),
        ]),
    };

    frame.render_widget(Paragraph::new(line).block(block), area);
}
