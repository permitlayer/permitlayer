//! View rendering. Each `render_*` is a pure `(&App, &Ctx, Frame/area)`
//! function — no I/O, no state mutation — so it is snapshot-testable
//! against a `TestBackend`.

pub mod agents;
pub mod policies;
pub mod status;

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout};

use crate::design::terminal::ColorSupport;
use crate::design::tokens::ThemeTokens;

use super::app::{App, View};
use super::glyphs::Glyphs;
use super::widgets::footer;

/// Everything the pure render functions need that is *not* `App`: the
/// resolved theme palette, the color-support level, and the glyph set.
/// Built once at startup so renders stay deterministic for snapshots.
#[derive(Debug, Clone, Copy)]
pub struct Ctx {
    pub tokens: &'static ThemeTokens,
    pub support: ColorSupport,
    pub glyphs: Glyphs,
}

/// Top-level frame layout: status header (3 rows) + main pane + footer
/// (1 row). Dispatches the main pane to the active view.
pub fn render(frame: &mut Frame, app: &App, ctx: &Ctx) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(1), Constraint::Length(1)])
        .split(frame.area());

    status::render(frame, chunks[0], app, ctx);

    match app.view {
        View::Agents => agents::render(frame, chunks[1], app, ctx),
        View::Policies => policies::render(frame, chunks[1], app, ctx),
    }

    footer::render(frame, chunks[2], app, ctx);
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use super::*;
    use crate::cli::ui::app::{
        AgentSummary, Focus, HeaderStatus, PolicyDetail, PolicyDetailState, PolicyListEntry,
    };
    use crate::cli::ui::glyphs::Glyphs;
    use crate::design::theme::Theme;

    /// A deterministic render context: carapace tokens, NoColor (so cell
    /// styles don't churn snapshots), ASCII glyphs (terminal-independent).
    fn test_ctx() -> Ctx {
        Ctx {
            tokens: Theme::Carapace.tokens(),
            support: ColorSupport::NoColor,
            glyphs: Glyphs::ascii(),
        }
    }

    fn draw(app: &App) -> String {
        let backend = TestBackend::new(80, 16);
        let mut terminal = Terminal::new(backend).unwrap();
        let ctx = test_ctx();
        terminal.draw(|f| render(f, app, &ctx)).unwrap();
        format!("{}", terminal.backend())
    }

    fn agent(name: &str, policy: &str) -> AgentSummary {
        AgentSummary {
            name: name.into(),
            policy_name: policy.into(),
            created_at: "2026-05-01T00:00:00Z".into(),
            last_seen_at: Some("2026-05-28T10:00:00Z".into()),
        }
    }

    fn policy(name: &str) -> PolicyListEntry {
        PolicyListEntry {
            name: name.into(),
            origin: format!("/etc/agentsso/policies/managed/{name}.toml"),
            scopes: vec!["https://www.googleapis.com/auth/calendar.readonly".into()],
        }
    }

    fn loaded_app() -> App {
        App {
            header: HeaderStatus::Running {
                version: "1.0.0".into(),
                kill_active: false,
                token_count: 2,
            },
            endpoint_label: "127.0.0.1:3820".into(),
            agents: vec![agent("calendar-bot", "calendar-ro"), agent("drive-sync", "drive-ro")],
            policies: vec![policy("calendar-ro"), policy("drive-ro")],
            ..App::default()
        }
    }

    #[test]
    fn snapshot_agents_loaded() {
        insta::assert_snapshot!("agents_loaded", draw(&loaded_app()));
    }

    #[test]
    fn snapshot_agents_loaded_detail_focus() {
        let mut app = loaded_app();
        app.focus = Focus::Detail;
        insta::assert_snapshot!("agents_loaded_detail", draw(&app));
    }

    #[test]
    fn snapshot_policies_loaded_detail() {
        let mut app = loaded_app();
        app.view = View::Policies;
        app.focus = Focus::Detail;
        app.policy_detail = PolicyDetailState::Loaded(PolicyDetail {
            name: "calendar-ro".into(),
            scopes: vec!["https://www.googleapis.com/auth/calendar.readonly".into()],
            resources: vec!["*".into()],
            approval_mode: Some("auto".into()),
            rules: vec![],
        });
        insta::assert_snapshot!("policies_loaded_detail", draw(&app));
    }

    #[test]
    fn snapshot_loading_first_fetch() {
        // First fetch: no data yet, loading indicator on, Unknown header.
        let app =
            App { pending_fetches: 3, endpoint_label: "127.0.0.1:3820".into(), ..App::default() };
        assert!(app.is_loading());
        insta::assert_snapshot!("loading_first_fetch", draw(&app));
    }

    #[test]
    fn snapshot_loading_after_loaded() {
        // Refresh while data is on screen — proves the no-flicker /
        // keep-last-good invariant: the prior data is still rendered with
        // the loading footer.
        let mut app = loaded_app();
        app.pending_fetches = 3;
        assert!(app.is_loading());
        insta::assert_snapshot!("loading_after_loaded", draw(&app));
    }

    #[test]
    fn snapshot_empty() {
        let app = App {
            header: HeaderStatus::Running {
                version: "1.0.0".into(),
                kill_active: false,
                token_count: 0,
            },
            endpoint_label: "127.0.0.1:3820".into(),
            ..App::default()
        };
        insta::assert_snapshot!("empty", draw(&app));
    }

    #[test]
    fn snapshot_error_daemon_unreachable() {
        let app = App {
            header: HeaderStatus::Unreachable,
            endpoint_label: "127.0.0.1:3820".into(),
            footer_error: Some("daemon not running — run: agentsso start".into()),
            ..App::default()
        };
        insta::assert_snapshot!("error_daemon_unreachable", draw(&app));
    }
}
