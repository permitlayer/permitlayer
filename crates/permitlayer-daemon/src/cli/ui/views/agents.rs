//! Agents view: a left list of agent names + right detail pane. The
//! detail is fully in-memory — `policy_name` from the list item, `scopes`
//! via the in-memory policy map — so Enter performs no fetch.

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::cli::ui::app::{App, Focus};
use crate::cli::ui::theme_bridge;
use crate::cli::ui::views::Ctx;
use crate::cli::ui::widgets::kvtable::{self, Row};
use crate::cli::ui::widgets::list_pane::{self, Item};

pub fn render(frame: &mut Frame, area: Rect, app: &App, ctx: &Ctx) {
    if app.agents.is_empty() {
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
        .title(" Agents ")
        .border_style(theme_bridge::fg(ctx.tokens.border, ctx.support));
    let msg = Line::from(Span::styled(
        "No agents registered. Run `agentsso quickstart` to create one.",
        theme_bridge::dim(ctx.tokens.text_2, ctx.support),
    ));
    frame.render_widget(Paragraph::new(msg).block(block), area);
}

fn render_list(frame: &mut Frame, area: Rect, app: &App, ctx: &Ctx) {
    let items: Vec<Item> = app
        .agents
        .iter()
        .map(|a| {
            let last_seen = a.last_seen_at.as_deref().unwrap_or("never");
            Item::new(a.name.clone(), format!("({last_seen})"))
        })
        .collect();
    list_pane::render(frame, area, " Agents ", &items, app.agents_selected, ctx);
}

fn render_detail(frame: &mut Frame, area: Rect, app: &App, ctx: &Ctx) {
    let Some(agent) = app.agents.get(app.agents_selected) else {
        return;
    };

    // Until the user focuses the detail (Enter), show a hint.
    if app.focus == Focus::List {
        let block = Block::default()
            .borders(Borders::ALL)
            .title(" Detail ")
            .border_style(theme_bridge::fg(ctx.tokens.border, ctx.support));
        let hint = Line::from(Span::styled(
            "press Enter to inspect",
            theme_bridge::dim(ctx.tokens.text_3, ctx.support),
        ));
        frame.render_widget(Paragraph::new(hint).block(block), area);
        return;
    }

    let scopes = app.scopes_for_policy(&agent.policy_name);
    let scopes_value =
        if scopes.is_empty() { "(none loaded)".to_owned() } else { scopes.join(", ") };

    let rows = vec![
        Row::new("name", agent.name.clone()),
        Row::new("policy", agent.policy_name.clone()),
        Row::new("created", agent.created_at.clone()),
        Row::new("last seen", agent.last_seen_at.clone().unwrap_or_else(|| "never".to_owned())),
        Row::new("scopes", scopes_value),
    ];

    kvtable::render(frame, area, " Detail ", &rows, ctx);
}
