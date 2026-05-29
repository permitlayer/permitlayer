//! Policies view: left list of names (+ origin) and a right detail pane
//! that renders the lazily-fetched policy TOML.

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::cli::ui::app::{App, Focus, PolicyDetailState};
use crate::cli::ui::theme_bridge;
use crate::cli::ui::views::Ctx;
use crate::cli::ui::widgets::kvtable::{self, Row};
use crate::cli::ui::widgets::list_pane::{self, Item};

pub fn render(frame: &mut Frame, area: Rect, app: &App, ctx: &Ctx) {
    if app.policies.is_empty() {
        render_empty(frame, area, ctx);
        return;
    }

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(area);

    render_list(frame, cols[0], app, ctx);
    render_detail(frame, cols[1], app, ctx);
}

fn render_empty(frame: &mut Frame, area: Rect, ctx: &Ctx) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Policies ")
        .border_style(theme_bridge::fg(ctx.tokens.border, ctx.support));
    let msg = Line::from(Span::styled(
        "No policies loaded — check `agentsso doctor`.",
        theme_bridge::dim(ctx.tokens.text_2, ctx.support),
    ));
    frame.render_widget(Paragraph::new(msg).block(block), area);
}

fn render_list(frame: &mut Frame, area: Rect, app: &App, ctx: &Ctx) {
    let items: Vec<Item> = app
        .policies
        .iter()
        .map(|p| Item::new(p.name.clone(), origin_label(&p.origin).to_owned()))
        .collect();
    list_pane::render(frame, area, " Policies ", &items, app.policies_selected, ctx);
}

/// Render the origin path's basename (the full path is long and slice 1
/// does not classify managed vs operator — that needs prefix rules + a
/// test and is deferred). Falls back to a visible placeholder when the
/// daemon reports an empty origin, so the column never renders blank.
fn origin_label(origin: &str) -> &str {
    origin.rsplit(['/', '\\']).next().filter(|s| !s.is_empty()).unwrap_or("(unknown)")
}

fn render_detail(frame: &mut Frame, area: Rect, app: &App, ctx: &Ctx) {
    if app.focus == Focus::List {
        render_hint(frame, area, "press Enter to inspect", ctx);
        return;
    }

    match &app.policy_detail {
        PolicyDetailState::None => render_hint(frame, area, "press Enter to inspect", ctx),
        PolicyDetailState::Loading => render_hint(frame, area, "loading…", ctx),
        PolicyDetailState::Failed => {
            render_hint(frame, area, "detail unavailable — see footer", ctx)
        }
        PolicyDetailState::Loaded(detail) => {
            // The scopes/resources/rules strings are formatted per draw.
            // Deliberately NOT cached: this is a manual-refresh TUI (it
            // redraws only on a keypress or a fetch result, never on a
            // timer), the per-policy data is small, and the strings only
            // change when a fresh detail lands — so the cost is a handful
            // of tiny allocations per keypress, below any observable
            // threshold. Caching would push formatting into `App` state
            // and muddy the pure `(App, Frame)` render boundary for no
            // measurable gain.
            let g = &ctx.glyphs;
            let scopes = if detail.scopes.is_empty() {
                "(none)".to_owned()
            } else {
                detail.scopes.join(", ")
            };
            let resources = if detail.resources.is_empty() {
                "(none)".to_owned()
            } else {
                detail.resources.join(", ")
            };
            let rules = if detail.rules.is_empty() {
                "(none)".to_owned()
            } else {
                detail
                    .rules
                    .iter()
                    .map(|r| {
                        let action = r.action.as_deref().unwrap_or("?");
                        format!("{} {} {action}", r.id, g.arrow)
                    })
                    .collect::<Vec<_>>()
                    .join("; ")
            };

            let mut rows = vec![
                Row::new("name", detail.name.clone()),
                Row::new("scopes", scopes),
                Row::new("resources", resources),
            ];
            if let Some(mode) = &detail.approval_mode {
                rows.push(Row::new("approval", mode.clone()));
            }
            rows.push(Row::new("rules", rules));

            kvtable::render(frame, area, " Detail ", &rows, ctx);
        }
    }
}

fn render_hint(frame: &mut Frame, area: Rect, text: &str, ctx: &Ctx) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Detail ")
        .border_style(theme_bridge::fg(ctx.tokens.border, ctx.support));
    let line = Line::from(Span::styled(
        text.to_owned(),
        theme_bridge::dim(ctx.tokens.text_3, ctx.support),
    ));
    frame.render_widget(Paragraph::new(line).block(block), area);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_label_takes_basename() {
        assert_eq!(
            origin_label("/etc/agentsso/policies/managed/calendar-ro.toml"),
            "calendar-ro.toml"
        );
        assert_eq!(origin_label("calendar-ro.toml"), "calendar-ro.toml");
        assert_eq!(origin_label(""), "(unknown)");
    }
}
