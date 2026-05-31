//! TUI state + the **pure** reducer.
//!
//! [`step`] is `(&App, Event) -> (App, Vec<Effect>)` with no I/O: it
//! returns a fresh `App` plus a list of [`Effect`]s describing the I/O
//! the event loop should perform (fetches, quit). This is what makes
//! "`r` triggers a refresh" unit-testable without a network — the test
//! asserts `step` emits [`Effect::Fetch`]. The impure half (executing
//! effects, feeding results back as [`Event::Fetched`]) lives in
//! `super::run`.

use super::client::FetchOutcome;
use super::types::StateBody;
// Re-export the response mirrors that appear in `App` so views/tests have
// a single `app::*` import path for everything the UI state holds.
pub use super::types::{AgentSummary, PolicyDetail, PolicyListEntry};

/// Which list/tab is active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Agents,
    Policies,
}

/// Whether focus is on the list (navigating) or the detail pane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    List,
    Detail,
}

/// Which control-plane resource a fetch targets. The reducer emits these
/// inside [`Effect::Fetch`]; the loop maps each to a `client` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    State,
    Agents,
    Policies,
    /// One policy's TOML detail, by name.
    PolicyDetail(String),
}

/// A side effect the event loop must perform. The reducer never does I/O
/// itself — it returns these. (Quit is signalled via `App::should_quit`,
/// not an effect, since the loop must observe it synchronously after
/// every `step`.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    Fetch(Target),
    /// Slice 2: a mutating control-plane POST (kill / resume). The loop
    /// performs it and feeds the result back as `Fetched::Mutated`.
    Mutate(Mutation),
}

/// A mutating control-plane action. Slice 2 has exactly two (the
/// kill-switch toggle); later slices add reload / rotate / rebind here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mutation {
    Kill,
    Resume,
}

/// A parsed fetch result handed back to the reducer as an event. Mirrors
/// the `client::FetchOutcome` variants but owns its data so it can cross
/// the channel.
#[derive(Debug, Clone)]
pub enum Fetched {
    State(Result<StateBody, FetchError>),
    Agents(Result<Vec<AgentSummary>, FetchError>),
    Policies(Result<Vec<PolicyListEntry>, FetchError>),
    PolicyDetail {
        name: String,
        result: Result<PolicyDetail, FetchError>,
    },
    /// Slice 2: result of a kill/resume mutation.
    Mutated(Result<MutationOutcome, FetchError>),
}

/// The successful outcome of a mutation, carrying the bits the footer
/// confirmation line renders.
#[derive(Debug, Clone)]
pub enum MutationOutcome {
    /// Kill activated. `tokens_invalidated` + whether it was already
    /// active (idempotent repeat).
    Killed { tokens_invalidated: usize, was_already_active: bool },
    /// Resume completed. `was_already_inactive` = nothing to resume.
    Resumed { was_already_inactive: bool },
}

/// View-facing classification of a failed fetch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchError {
    /// Daemon not running (connect refused / socket missing).
    Unreachable,
    /// Daemon answered but the exchange failed (timeout / IO / malformed
    /// response) — running but misbehaving.
    BadResponse {
        summary: String,
    },
    Forbidden {
        code: String,
    },
    Http {
        status: u16,
        code: String,
    },
    Parse {
        summary: String,
    },
}

impl FetchError {
    /// Build from a `client::FetchOutcome` that is known to be non-`Ok`.
    /// Returns `None` for the `Ok` variant.
    pub fn from_outcome<T>(outcome: &FetchOutcome<T>) -> Option<Self> {
        match outcome {
            FetchOutcome::Ok(_) => None,
            FetchOutcome::Unreachable => Some(Self::Unreachable),
            FetchOutcome::BadResponse { summary } => {
                Some(Self::BadResponse { summary: summary.clone() })
            }
            FetchOutcome::Forbidden { code } => Some(Self::Forbidden { code: code.clone() }),
            FetchOutcome::HttpError { status, code } => {
                Some(Self::Http { status: *status, code: code.clone() })
            }
            FetchOutcome::Parse { summary } => Some(Self::Parse { summary: summary.clone() }),
        }
    }
}

/// Input event into the reducer.
#[derive(Debug, Clone)]
pub enum Event {
    Key(Key),
    Fetched(Fetched),
}

/// The key abstraction the reducer reacts to. The event loop translates
/// raw `crossterm::event::KeyEvent`s into these so the reducer stays
/// independent of crossterm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    Up,
    Down,
    Enter,
    Esc,
    Tab,
    Refresh,
    ToggleHelp,
    Quit,
    /// Ctrl-C — always quits.
    CtrlC,
    /// Ctrl-K — toggle the kill switch (opens the confirm modal).
    Kill,
    /// `y` — confirm the pending action.
    ConfirmYes,
    /// `n` — cancel the pending action (Esc also cancels).
    ConfirmNo,
}

/// A mutation awaiting operator confirmation. While `Some`, the confirm
/// modal is open and the reducer blocks all keys except confirm/cancel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmAction {
    Kill,
    Resume,
}

/// Connection/auth status derived from the most recent `/state` fetch,
/// shown in the header.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum HeaderStatus {
    /// No `/state` result yet (first paint).
    #[default]
    Unknown,
    Running {
        version: String,
        kill_active: bool,
        token_count: usize,
    },
    Unreachable,
    Forbidden,
    Error {
        status: u16,
    },
}

/// Detail loaded for the selected policy.
///
/// `Failed` carries no payload: the failure's operator-facing message is
/// surfaced through the footer banner at fetch time (see `set_footer`),
/// and the detail pane only needs to know *that* it failed to render the
/// "see footer" hint.
#[derive(Debug, Clone, Default)]
pub enum PolicyDetailState {
    #[default]
    None,
    Loading,
    Loaded(PolicyDetail),
    Failed,
}

/// The whole TUI state. Cloned by the reducer (slice-1 data is small).
#[derive(Debug, Clone)]
pub struct App {
    pub view: View,
    pub focus: Focus,
    pub header: HeaderStatus,
    /// Endpoint string for the header (derived once at startup).
    pub endpoint_label: String,

    pub agents: Vec<AgentSummary>,
    pub agents_selected: usize,

    pub policies: Vec<PolicyListEntry>,
    pub policies_selected: usize,
    pub policy_detail: PolicyDetailState,

    /// Count of in-flight fetches from the last refresh. `is_loading()`
    /// derives the footer indicator from this — there is no separate
    /// `loading` bool to keep in sync.
    pub pending_fetches: usize,

    /// Transient footer banner (last error). Cleared on a successful
    /// refresh.
    pub footer_error: Option<String>,
    /// Transient footer banner for a NON-error notice (e.g. the
    /// kill/resume success confirmation). Rendered in accent, not danger
    /// red — a successful mutation must not look like an error. Cleared
    /// on the next refresh, same as `footer_error`.
    pub footer_notice: Option<String>,
    /// Whether the `?` key-hint line is expanded.
    pub show_help: bool,
    /// A mutation awaiting `y`/`n` confirmation. `Some` ⇒ the confirm
    /// modal is open and the reducer blocks every key except confirm and
    /// cancel.
    pub pending_confirm: Option<ConfirmAction>,
    /// Set once the reducer has seen a quit key — the loop checks this.
    pub should_quit: bool,
}

impl Default for App {
    fn default() -> Self {
        Self {
            view: View::Agents,
            focus: Focus::List,
            header: HeaderStatus::Unknown,
            endpoint_label: String::new(),
            agents: Vec::new(),
            agents_selected: 0,
            policies: Vec::new(),
            policies_selected: 0,
            policy_detail: PolicyDetailState::None,
            pending_fetches: 0,
            footer_error: None,
            footer_notice: None,
            show_help: false,
            pending_confirm: None,
            should_quit: false,
        }
    }
}

impl App {
    /// The effects that fetch the full screen (status + both lists). Used
    /// at startup and on `r`.
    pub fn refresh_effects() -> Vec<Effect> {
        vec![
            Effect::Fetch(Target::State),
            Effect::Fetch(Target::Agents),
            Effect::Fetch(Target::Policies),
        ]
    }

    /// Name of the currently selected policy, if any.
    fn selected_policy_name(&self) -> Option<String> {
        self.policies.get(self.policies_selected).map(|p| p.name.clone())
    }

    /// Scopes for an agent's policy, resolved from the in-memory policy
    /// list (no HTTP). Empty if the policy isn't loaded.
    pub fn scopes_for_policy(&self, policy_name: &str) -> Vec<String> {
        self.policies
            .iter()
            .find(|p| p.name == policy_name)
            .map(|p| p.scopes.clone())
            .unwrap_or_default()
    }

    /// Whether a refresh is in flight (drives the footer `loading…` line).
    /// Derived from `pending_fetches` — no separate bool to desync.
    pub fn is_loading(&self) -> bool {
        self.pending_fetches > 0
    }
}

/// The pure reducer. No I/O — returns the next state and the effects the
/// loop should run.
pub fn step(app: &App, event: Event) -> (App, Vec<Effect>) {
    let mut next = app.clone();
    let effects = match event {
        Event::Key(key) => reduce_key(&mut next, key),
        // `reduce_fetched` can itself emit effects now — a successful
        // mutation triggers a `/state` re-fetch so the header flips
        // without the operator pressing `r`.
        Event::Fetched(fetched) => reduce_fetched(&mut next, fetched),
    };
    (next, effects)
}

fn reduce_key(app: &mut App, key: Key) -> Vec<Effect> {
    // Modal guard: while a confirmation is pending, the dialog is
    // *blocking* — only confirm (`y`), cancel (`n`/Esc), and Ctrl-C
    // (always quits) are honoured; every other key is swallowed so the
    // operator can't navigate away mid-confirm.
    if let Some(action) = app.pending_confirm {
        return match key {
            Key::ConfirmYes => {
                app.pending_confirm = None;
                let mutation = match action {
                    ConfirmAction::Kill => Mutation::Kill,
                    ConfirmAction::Resume => Mutation::Resume,
                };
                vec![Effect::Mutate(mutation)]
            }
            Key::ConfirmNo | Key::Esc => {
                app.pending_confirm = None;
                Vec::new()
            }
            Key::CtrlC => {
                app.should_quit = true;
                Vec::new()
            }
            _ => Vec::new(),
        };
    }

    match key {
        Key::Quit | Key::CtrlC => {
            // Quit is driven by the `should_quit` flag, which the event
            // loop checks after every `step`. No `Effect` needed.
            app.should_quit = true;
            Vec::new()
        }
        Key::Kill => {
            // Toggle: derive the action from the current kill state. Only
            // possible when we have a live `/state` reading — otherwise
            // there's nothing meaningful to toggle.
            match app.header {
                HeaderStatus::Running { kill_active: true, .. } => {
                    app.pending_confirm = Some(ConfirmAction::Resume);
                }
                HeaderStatus::Running { kill_active: false, .. } => {
                    app.pending_confirm = Some(ConfirmAction::Kill);
                }
                _ => {
                    app.footer_error =
                        Some("cannot toggle kill switch: daemon state unknown".to_owned());
                }
            }
            Vec::new()
        }
        // Confirm keys outside a pending modal are no-ops.
        Key::ConfirmYes | Key::ConfirmNo => Vec::new(),
        Key::ToggleHelp => {
            app.show_help = !app.show_help;
            Vec::new()
        }
        Key::Tab => {
            app.view = match app.view {
                View::Agents => View::Policies,
                View::Policies => View::Agents,
            };
            app.focus = Focus::List;
            Vec::new()
        }
        Key::Up => {
            move_selection(app, -1);
            Vec::new()
        }
        Key::Down => {
            move_selection(app, 1);
            Vec::new()
        }
        Key::Enter => enter_detail(app),
        Key::Esc => {
            app.focus = Focus::List;
            Vec::new()
        }
        Key::Refresh => {
            let effects = App::refresh_effects();
            app.pending_fetches = effects.len();
            app.footer_error = None;
            app.footer_notice = None;
            effects
        }
    }
}

fn move_selection(app: &mut App, delta: isize) {
    match app.view {
        View::Agents => {
            app.agents_selected = clamp_index(app.agents_selected, app.agents.len(), delta);
        }
        View::Policies => {
            app.policies_selected = clamp_index(app.policies_selected, app.policies.len(), delta);
            // Selecting a different policy invalidates the detail pane.
            if app.focus == Focus::Detail {
                app.focus = Focus::List;
            }
            app.policy_detail = PolicyDetailState::None;
        }
    }
}

fn clamp_index(current: usize, len: usize, delta: isize) -> usize {
    if len == 0 {
        return 0;
    }
    let max = len - 1;
    let next = current as isize + delta;
    next.clamp(0, max as isize) as usize
}

fn enter_detail(app: &mut App) -> Vec<Effect> {
    app.focus = Focus::Detail;
    match app.view {
        // Agent detail is fully in memory (policy_name from the list,
        // scopes via the policy map) — no fetch.
        View::Agents => Vec::new(),
        View::Policies => {
            if let Some(name) = app.selected_policy_name() {
                app.policy_detail = PolicyDetailState::Loading;
                vec![Effect::Fetch(Target::PolicyDetail(name))]
            } else {
                Vec::new()
            }
        }
    }
}

fn reduce_fetched(app: &mut App, fetched: Fetched) -> Vec<Effect> {
    // Any non-detail fetch landing decrements the in-flight counter set
    // by the last refresh. Detail fetches and mutations are out-of-band
    // and do not participate in the refresh-loading indicator.
    let mut count_down = true;
    let mut effects = Vec::new();
    match fetched {
        Fetched::State(Ok(state)) => {
            app.header = HeaderStatus::Running {
                version: state.daemon_version,
                kill_active: state.active,
                token_count: state.token_count,
            };
        }
        Fetched::State(Err(err)) => {
            app.header = header_from_error(&err);
            set_footer(app, &err);
        }
        Fetched::Agents(Ok(agents)) => {
            app.agents = agents;
            clamp_selection(&mut app.agents_selected, app.agents.len());
        }
        Fetched::Agents(Err(err)) => set_footer(app, &err),
        Fetched::Policies(Ok(policies)) => {
            app.policies = policies;
            clamp_selection(&mut app.policies_selected, app.policies.len());
        }
        Fetched::Policies(Err(err)) => set_footer(app, &err),
        Fetched::PolicyDetail { name, result } => {
            count_down = false;
            // Ignore a stale detail for a policy the user has navigated
            // away from.
            if app.selected_policy_name().as_deref() == Some(name.as_str()) {
                app.policy_detail = match result {
                    Ok(detail) => PolicyDetailState::Loaded(detail),
                    Err(err) => {
                        set_footer(app, &err);
                        PolicyDetailState::Failed
                    }
                };
            }
        }
        Fetched::Mutated(result) => {
            // Mutations are out-of-band (Ctrl-K, not a refresh), so they
            // never touch `pending_fetches`. The modal was already
            // cleared when the operator confirmed; this is belt-and-
            // suspenders (and clears it if a mutation ever lands without
            // a prior confirm).
            count_down = false;
            app.pending_confirm = None;
            match result {
                Ok(outcome) => {
                    app.footer_notice = Some(mutation_confirmation_line(&outcome));
                    app.footer_error = None;
                    // Re-fetch `/state` so the header's kill ●/○ flips
                    // without the operator pressing `r`. Counts as an
                    // in-flight fetch for the loading indicator.
                    app.pending_fetches += 1;
                    effects.push(Effect::Fetch(Target::State));
                }
                Err(err) => set_footer(app, &err),
            }
        }
    }

    if count_down && app.pending_fetches > 0 {
        app.pending_fetches -= 1;
    }
    effects
}

/// The one-line footer confirmation after a successful kill/resume. Uses
/// the same `footer_error` channel as other transient banners (it is the
/// UI's single transient-message slot, not exclusively for errors).
fn mutation_confirmation_line(outcome: &MutationOutcome) -> String {
    match outcome {
        MutationOutcome::Killed { was_already_active: true, .. } => {
            "kill switch already active".to_owned()
        }
        MutationOutcome::Killed { tokens_invalidated, .. } => {
            let plural = if *tokens_invalidated == 1 { "token" } else { "tokens" };
            format!("kill active \u{00b7} {tokens_invalidated} {plural} invalidated")
        }
        MutationOutcome::Resumed { was_already_inactive: true } => {
            "kill switch was not active \u{2014} nothing to resume".to_owned()
        }
        MutationOutcome::Resumed { .. } => "resumed \u{2014} tokens re-enabled".to_owned(),
    }
}

fn clamp_selection(selected: &mut usize, len: usize) {
    if len == 0 {
        *selected = 0;
    } else if *selected >= len {
        *selected = len - 1;
    }
}

fn header_from_error(err: &FetchError) -> HeaderStatus {
    match err {
        FetchError::Unreachable => HeaderStatus::Unreachable,
        FetchError::Forbidden { .. } => HeaderStatus::Forbidden,
        FetchError::Http { status, .. } => HeaderStatus::Error { status: *status },
        // BadResponse / Parse both mean the daemon answered but the
        // exchange/body was bad — surface as a generic error header.
        FetchError::BadResponse { .. } | FetchError::Parse { .. } => {
            HeaderStatus::Error { status: 0 }
        }
    }
}

fn set_footer(app: &mut App, err: &FetchError) {
    app.footer_error = Some(footer_text(err));
}

/// Operator-facing one-liner for the footer banner.
pub fn footer_text(err: &FetchError) -> String {
    match err {
        FetchError::Unreachable => "daemon not running — run: agentsso start".to_owned(),
        FetchError::BadResponse { summary } => {
            format!("daemon not responding: {summary} — check: agentsso doctor")
        }
        // Reuse the canonical control-plane auth remediation shared by
        // every other `/v1/control/*` CLI consumer (agent / policy /
        // connectors), so the TUI never drifts from the rest.
        FetchError::Forbidden { .. } => {
            format!("control.token unreadable — {}", crate::cli::kill::CONTROL_AUTH_REMEDIATION)
        }
        FetchError::Http { status, code } => {
            format!("HTTP {status}: {code} — press r to retry")
        }
        FetchError::Parse { summary } => format!("parse error: {summary}"),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn key(app: &App, k: Key) -> (App, Vec<Effect>) {
        step(app, Event::Key(k))
    }

    fn app_with_lists() -> App {
        App {
            agents: vec![
                AgentSummary {
                    name: "a1".into(),
                    policy_name: "p1".into(),
                    created_at: "t".into(),
                    last_seen_at: None,
                },
                AgentSummary {
                    name: "a2".into(),
                    policy_name: "p2".into(),
                    created_at: "t".into(),
                    last_seen_at: None,
                },
            ],
            policies: vec![
                PolicyListEntry {
                    name: "p1".into(),
                    origin: "o1".into(),
                    scopes: vec!["s1".into()],
                },
                PolicyListEntry { name: "p2".into(), origin: "o2".into(), scopes: vec![] },
            ],
            ..App::default()
        }
    }

    #[test]
    fn tab_switches_view_and_resets_focus() {
        let app = App { focus: Focus::Detail, ..App::default() };
        let (next, effects) = key(&app, Key::Tab);
        assert_eq!(next.view, View::Policies);
        assert_eq!(next.focus, Focus::List);
        assert!(effects.is_empty());
        let (next2, _) = key(&next, Key::Tab);
        assert_eq!(next2.view, View::Agents);
    }

    #[test]
    fn down_then_up_moves_and_clamps() {
        let app = app_with_lists();
        let (d1, _) = key(&app, Key::Down);
        assert_eq!(d1.agents_selected, 1);
        // Clamp at the bottom.
        let (d2, _) = key(&d1, Key::Down);
        assert_eq!(d2.agents_selected, 1);
        let (u1, _) = key(&d2, Key::Up);
        assert_eq!(u1.agents_selected, 0);
        // Clamp at the top.
        let (u2, _) = key(&u1, Key::Up);
        assert_eq!(u2.agents_selected, 0);
    }

    #[test]
    fn esc_clears_detail_focus() {
        let app = App { focus: Focus::Detail, ..App::default() };
        let (next, effects) = key(&app, Key::Esc);
        assert_eq!(next.focus, Focus::List);
        assert!(effects.is_empty());
    }

    #[test]
    fn r_emits_three_fetch_effects_and_sets_loading() {
        let app = App::default();
        let (next, effects) = key(&app, Key::Refresh);
        assert!(next.is_loading());
        assert_eq!(next.pending_fetches, 3);
        assert_eq!(
            effects,
            vec![
                Effect::Fetch(Target::State),
                Effect::Fetch(Target::Agents),
                Effect::Fetch(Target::Policies),
            ]
        );
    }

    #[test]
    fn q_and_ctrl_c_quit() {
        let app = App::default();
        let (next, effects) = key(&app, Key::Quit);
        assert!(next.should_quit);
        assert!(effects.is_empty(), "quit is driven by should_quit, not an effect");

        let (next2, effects2) = key(&app, Key::CtrlC);
        assert!(next2.should_quit);
        assert!(effects2.is_empty());
    }

    #[test]
    fn enter_on_agents_does_not_fetch() {
        let app = app_with_lists();
        let (next, effects) = key(&app, Key::Enter);
        assert_eq!(next.focus, Focus::Detail);
        assert!(effects.is_empty(), "agent detail is in-memory, no fetch");
    }

    // ── Slice 2: kill-switch toggle (first mutation) ─────────────────

    fn running(kill_active: bool) -> HeaderStatus {
        HeaderStatus::Running { version: "1.1.0".into(), kill_active, token_count: 3 }
    }

    #[test]
    fn ctrl_k_when_inactive_opens_kill_confirm_no_effect() {
        let app = App { header: running(false), ..App::default() };
        let (next, effects) = key(&app, Key::Kill);
        assert_eq!(next.pending_confirm, Some(ConfirmAction::Kill));
        assert!(effects.is_empty(), "opening the confirm modal posts nothing");
    }

    #[test]
    fn ctrl_k_when_active_opens_resume_confirm() {
        let app = App { header: running(true), ..App::default() };
        let (next, _) = key(&app, Key::Kill);
        assert_eq!(next.pending_confirm, Some(ConfirmAction::Resume));
    }

    #[test]
    fn ctrl_k_with_unknown_header_errors_no_modal() {
        // No live /state reading → nothing meaningful to toggle.
        let app = App { header: HeaderStatus::Unreachable, ..App::default() };
        let (next, effects) = key(&app, Key::Kill);
        assert_eq!(next.pending_confirm, None);
        assert!(next.footer_error.is_some());
        assert!(effects.is_empty());
    }

    #[test]
    fn confirm_yes_fires_mutation_and_clears_modal() {
        let app = App { pending_confirm: Some(ConfirmAction::Kill), ..App::default() };
        let (next, effects) = key(&app, Key::ConfirmYes);
        assert_eq!(next.pending_confirm, None);
        assert_eq!(effects, vec![Effect::Mutate(Mutation::Kill)]);
    }

    #[test]
    fn confirm_yes_resume_fires_resume_mutation() {
        let app = App { pending_confirm: Some(ConfirmAction::Resume), ..App::default() };
        let (next, effects) = key(&app, Key::ConfirmYes);
        assert_eq!(next.pending_confirm, None);
        assert_eq!(effects, vec![Effect::Mutate(Mutation::Resume)]);
    }

    #[test]
    fn confirm_no_and_esc_cancel_modal_no_effect() {
        let app = App { pending_confirm: Some(ConfirmAction::Kill), ..App::default() };
        let (n1, e1) = key(&app, Key::ConfirmNo);
        assert_eq!(n1.pending_confirm, None);
        assert!(e1.is_empty());
        let (n2, e2) = key(&app, Key::Esc);
        assert_eq!(n2.pending_confirm, None);
        assert!(e2.is_empty());
    }

    #[test]
    fn modal_is_blocking_other_keys_swallowed() {
        // While a confirm is pending, navigation/refresh/tab do nothing.
        let app = App {
            pending_confirm: Some(ConfirmAction::Kill),
            view: View::Agents,
            ..app_with_lists()
        };
        for k in [Key::Down, Key::Tab, Key::Refresh, Key::Enter] {
            let (next, effects) = key(&app, k);
            assert_eq!(next.pending_confirm, Some(ConfirmAction::Kill), "{k:?} broke the modal");
            assert_eq!(next.view, View::Agents, "{k:?} switched view through the modal");
            assert!(effects.is_empty(), "{k:?} emitted an effect through the modal");
        }
    }

    #[test]
    fn ctrl_c_quits_even_through_modal() {
        let app = App { pending_confirm: Some(ConfirmAction::Kill), ..App::default() };
        let (next, _) = key(&app, Key::CtrlC);
        assert!(next.should_quit);
    }

    #[test]
    fn confirm_keys_are_noops_outside_a_modal() {
        let app = App { header: running(false), ..App::default() };
        let (ny, ey) = key(&app, Key::ConfirmYes);
        assert!(ny.pending_confirm.is_none() && ey.is_empty());
        let (nn, en) = key(&app, Key::ConfirmNo);
        assert!(nn.pending_confirm.is_none() && en.is_empty());
    }

    #[test]
    fn mutated_ok_sets_notice_and_refetches_state() {
        let app = App { pending_confirm: Some(ConfirmAction::Kill), ..App::default() };
        let (next, effects) = step(
            &app,
            Event::Fetched(Fetched::Mutated(Ok(MutationOutcome::Killed {
                tokens_invalidated: 3,
                was_already_active: false,
            }))),
        );
        assert_eq!(next.pending_confirm, None);
        assert!(next.footer_error.is_none());
        let notice = next.footer_notice.unwrap();
        assert!(notice.contains("kill active"));
        assert!(notice.contains('3'));
        // Auto-refresh of /state so the header flips without `r`.
        assert_eq!(effects, vec![Effect::Fetch(Target::State)]);
        assert_eq!(next.pending_fetches, 1);
    }

    #[test]
    fn mutated_idempotent_kill_says_already_active() {
        let app = App::default();
        let (next, _) = step(
            &app,
            Event::Fetched(Fetched::Mutated(Ok(MutationOutcome::Killed {
                tokens_invalidated: 0,
                was_already_active: true,
            }))),
        );
        assert!(next.footer_notice.unwrap().contains("already active"));
    }

    #[test]
    fn mutated_err_surfaces_in_footer_clears_modal() {
        let app = App { pending_confirm: Some(ConfirmAction::Kill), ..App::default() };
        let (next, effects) = step(
            &app,
            Event::Fetched(Fetched::Mutated(Err(FetchError::Forbidden {
                code: "forbidden_missing_control_token".into(),
            }))),
        );
        assert_eq!(next.pending_confirm, None);
        assert!(next.footer_error.is_some());
        assert!(next.footer_notice.is_none());
        assert!(effects.is_empty(), "a failed mutation does not refetch");
    }

    #[test]
    fn enter_on_policies_fetches_detail() {
        let mut app = app_with_lists();
        app.view = View::Policies;
        let (next, effects) = key(&app, Key::Enter);
        assert_eq!(next.focus, Focus::Detail);
        assert!(matches!(next.policy_detail, PolicyDetailState::Loading));
        assert_eq!(effects, vec![Effect::Fetch(Target::PolicyDetail("p1".into()))]);
    }

    #[test]
    fn refresh_loading_clears_only_after_all_three_land() {
        let app = App::default();
        let (mut app, _) = key(&app, Key::Refresh);
        assert!(app.is_loading());
        app = step(
            &app,
            Event::Fetched(Fetched::State(Ok(StateBody {
                active: false,
                activated_at: None,
                token_count: 0,
                daemon_version: "1.0.0".into(),
            }))),
        )
        .0;
        assert!(app.is_loading(), "still loading after 1/3");
        app = step(&app, Event::Fetched(Fetched::Agents(Ok(vec![])))).0;
        assert!(app.is_loading(), "still loading after 2/3");
        app = step(&app, Event::Fetched(Fetched::Policies(Ok(vec![])))).0;
        assert!(!app.is_loading(), "cleared after 3/3");
    }

    #[test]
    fn extra_fetch_after_counter_zero_does_not_underflow() {
        // A late/duplicate non-detail result arriving when the counter is
        // already 0 must not panic (underflow) or wrongly re-enter loading.
        let app = App::default();
        assert_eq!(app.pending_fetches, 0);
        let app = step(&app, Event::Fetched(Fetched::Agents(Ok(vec![])))).0;
        assert_eq!(app.pending_fetches, 0);
        assert!(!app.is_loading());
    }

    #[test]
    fn state_error_sets_header_and_footer() {
        let app = App::default();
        let (app, _) = key(&app, Key::Refresh);
        let app = step(&app, Event::Fetched(Fetched::State(Err(FetchError::Unreachable)))).0;
        assert_eq!(app.header, HeaderStatus::Unreachable);
        assert!(app.footer_error.as_deref().unwrap().contains("agentsso start"));
    }

    #[test]
    fn scopes_resolved_from_policy_map() {
        let app = app_with_lists();
        assert_eq!(app.scopes_for_policy("p1"), vec!["s1".to_string()]);
        assert!(app.scopes_for_policy("p2").is_empty());
        assert!(app.scopes_for_policy("missing").is_empty());
    }

    #[test]
    fn stale_policy_detail_is_ignored() {
        let mut app = app_with_lists();
        app.view = View::Policies;
        // User is on p1, but a detail for p2 arrives late.
        let detail = PolicyDetail {
            name: "p2".into(),
            scopes: vec![],
            resources: vec![],
            approval_mode: None,
            rules: vec![],
        };
        let app = step(
            &app,
            Event::Fetched(Fetched::PolicyDetail { name: "p2".into(), result: Ok(detail) }),
        )
        .0;
        assert!(matches!(app.policy_detail, PolicyDetailState::None));
    }
}
