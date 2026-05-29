//! `agentsso ui` — read-only terminal UI (slice 1).
//!
//! A navigable status / agents / policies console. It is "just another
//! control-plane client": it runs as the operator's UID, reads
//! `<home>/control.token` per fetch, and calls the existing
//! `/v1/control/*` loopback API. No mutations in slice 1.
//!
//! # Shape
//!
//! - [`app`] holds the state and the **pure** reducer
//!   `step(&App, Event) -> (App, Vec<Effect>)`.
//! - [`client`] is the only place that touches HTTP.
//! - [`views`] / [`widgets`] are pure render functions.
//! - This module ([`run`]) is the only impure layer: it owns the
//!   terminal, the keyboard pump, and effect execution.
//!
//! # No tracing subscriber
//!
//! Like `status` / `agent` / `policy`, this command installs **no**
//! tracing subscriber. A stdout subscriber would corrupt the alt-screen;
//! and CLI commands install none anyway, so `tracing::*` here would be a
//! silent no-op. Errors surface through the footer banner (in-session)
//! and stderr printed *after* the terminal is restored.

pub mod app;
pub mod client;
pub mod glyphs;
pub mod theme_bridge;
pub mod types;
pub mod views;
pub mod widgets;

#[cfg(test)]
mod smoke_test;

use std::io::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use tokio::sync::mpsc;

use crate::config::{CliOverrides, DaemonConfig};

use app::{App, Effect, Event, Fetched, Key, Target};
use client::{ControlClient, FetchOutcome};
use glyphs::Glyphs;
use views::Ctx;

/// Arguments for `agentsso ui`. Empty in slice 1 (no flags — `--theme`,
/// `--no-alt-screen`, `--json` are deferred to slice 2+).
#[derive(clap::Args)]
pub struct UiArgs {}

/// Restores raw mode + the alternate screen on drop, so a panic that
/// unwinds through the draw loop still leaves the terminal usable. This
/// is the *single* panic-safety mechanism — no `catch_unwind` (ratatui's
/// `Terminal`/`Frame` aren't `UnwindSafe`, and `Drop` already runs on
/// unwind).
struct TerminalGuard {
    restored: bool,
}

impl TerminalGuard {
    fn enter() -> Result<Self> {
        crossterm::terminal::enable_raw_mode().context("enable raw mode")?;
        let mut out = std::io::stdout();
        crossterm::execute!(out, crossterm::terminal::EnterAlternateScreen)
            .context("enter alternate screen")?;
        Ok(Self { restored: false })
    }

    fn restore(&mut self) {
        if self.restored {
            return;
        }
        self.restored = true;
        // Best-effort: a failure here can't be surfaced from Drop, and
        // we're tearing down regardless.
        let mut out = std::io::stdout();
        let _ = crossterm::execute!(out, crossterm::terminal::LeaveAlternateScreen);
        let _ = crossterm::terminal::disable_raw_mode();
        let _ = out.flush();
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        self.restore();
    }
}

/// Entry point dispatched from `main`.
pub async fn run(_args: UiArgs) -> Result<()> {
    let config = DaemonConfig::load(&CliOverrides::default()).unwrap_or_default();
    let home = config.paths.home.clone();
    let endpoint = crate::cli::kill::resolve_control_endpoint(&config);
    let endpoint_label = endpoint.to_string();

    let client = ControlClient { home, endpoint };

    let ctx = Ctx {
        tokens: crate::design::theme::Theme::load(&client.home).tokens(),
        support: crate::design::terminal::ColorSupport::detect(),
        glyphs: Glyphs::detect(),
    };

    let mut app = App { endpoint_label, ..App::default() };

    // The `TerminalGuard` inside `event_loop` restores the terminal on
    // Drop — including a Drop triggered by panic unwind — so we don't need
    // `catch_unwind` or a spawned-task wrapper for slice 1's panic safety.
    // Any returned error is surfaced on stderr with the terminal already
    // restored.
    event_loop(&mut app, &client, &ctx).await
}

async fn event_loop(app: &mut App, client: &ControlClient, ctx: &Ctx) -> Result<()> {
    let mut guard = TerminalGuard::enter()?;
    let backend = CrosstermBackend::new(std::io::stdout());
    let mut terminal = Terminal::new(backend).context("create terminal")?;

    // Keyboard pump: a blocking task polling crossterm and forwarding key
    // events over an mpsc. `crossterm::event::poll` inside spawn_blocking
    // can't be cancelled, so the pump checks `shutdown` each 50ms tick and
    // returns when set. We set it before leaving the loop; worst-case the
    // pump lingers ≤50ms.
    let shutdown = Arc::new(AtomicBool::new(false));
    let (key_tx, mut key_rx) = mpsc::channel::<Key>(32);
    let pump_shutdown = shutdown.clone();
    let pump = tokio::task::spawn_blocking(move || keyboard_pump(&key_tx, &pump_shutdown));

    // Result channel for in-flight fetches.
    let (fetch_tx, mut fetch_rx) = mpsc::unbounded_channel::<Fetched>();

    // Kick off the initial full refresh by driving a synthetic Refresh
    // through the reducer, so the loading/pending-fetches bookkeeping has
    // exactly one source of truth (the `Key::Refresh` arm).
    {
        let (next, effects) = app::step(app, Event::Key(Key::Refresh));
        *app = next;
        run_effects(effects, client, &fetch_tx);
    }

    terminal.draw(|f| views::render(f, app, ctx)).context("initial draw")?;

    loop {
        let event = tokio::select! {
            maybe_key = key_rx.recv() => match maybe_key {
                Some(key) => Event::Key(key),
                None => break, // pump ended
            },
            maybe_fetch = fetch_rx.recv() => match maybe_fetch {
                Some(fetched) => Event::Fetched(fetched),
                None => continue,
            },
        };

        let (next, effects) = app::step(app, event);
        *app = next;

        if app.should_quit {
            break;
        }

        run_effects(effects, client, &fetch_tx);

        terminal.draw(|f| views::render(f, app, ctx)).context("draw")?;
    }

    // Signal the pump and restore the terminal before returning.
    shutdown.store(true, Ordering::SeqCst);
    guard.restore();
    // The pump returns within one poll tick; await it so we don't leave a
    // blocking task on runtime teardown.
    let _ = pump.await;
    Ok(())
}

/// Execute effects. Fetches are spawned; their parsed results arrive back
/// over `fetch_tx` as [`Fetched`] events.
///
/// Each fetch is spawned so it MUST deliver exactly one `Fetched` back,
/// even if the fetch task panics — otherwise `App::pending_fetches` would
/// never reach 0 and the footer would show `loading…` forever. We run the
/// fetch in an inner task and, if it panics, synthesize a `BadResponse`
/// result for the same `Target` so the counter still settles.
fn run_effects(
    effects: Vec<Effect>,
    client: &ControlClient,
    fetch_tx: &mpsc::UnboundedSender<Fetched>,
) {
    for effect in effects {
        let Effect::Fetch(target) = effect;
        let client = client.clone();
        let tx = fetch_tx.clone();
        tokio::spawn(async move {
            let target_for_fallback = target.clone();
            let inner = tokio::spawn(async move { perform_fetch(&client, target).await });
            let fetched = match inner.await {
                Ok(fetched) => fetched,
                // The fetch task panicked: still emit a result so the
                // pending-fetches counter settles and loading clears.
                Err(join_err) => {
                    let summary = if join_err.is_panic() {
                        "internal error (fetch task panicked)".to_owned()
                    } else {
                        "fetch cancelled".to_owned()
                    };
                    fetched_failure(target_for_fallback, summary)
                }
            };
            let _ = tx.send(fetched);
        });
    }
}

/// Build a failure `Fetched` for the given target, used when a fetch task
/// panics so the reducer still gets exactly one event per spawned fetch.
fn fetched_failure(target: Target, summary: String) -> Fetched {
    let err = app::FetchError::BadResponse { summary };
    match target {
        Target::State => Fetched::State(Err(err)),
        Target::Agents => Fetched::Agents(Err(err)),
        Target::Policies => Fetched::Policies(Err(err)),
        Target::PolicyDetail(name) => Fetched::PolicyDetail { name, result: Err(err) },
    }
}

/// Run one fetch and convert the `client` outcome into a `Fetched` event.
async fn perform_fetch(client: &ControlClient, target: Target) -> Fetched {
    match target {
        Target::State => {
            let outcome = client.fetch_state().await;
            Fetched::State(into_result(outcome, |b| b))
        }
        Target::Agents => {
            let outcome = client.fetch_agents().await;
            Fetched::Agents(into_result(outcome, |b| b))
        }
        Target::Policies => {
            let outcome = client.fetch_policies().await;
            Fetched::Policies(into_result(outcome, |b| b.policies))
        }
        Target::PolicyDetail(name) => {
            let outcome = client.fetch_policy_detail(&name).await;
            // The detail body is a `[[policies]]` array; take its single
            // entry, mapping an empty array to a parse error in one step.
            let result =
                into_result(outcome, |mut b| b.policies.drain(..).next()).and_then(|opt| {
                    opt.ok_or(app::FetchError::Parse { summary: "empty policy body".to_owned() })
                });
            Fetched::PolicyDetail { name, result }
        }
    }
}

/// Convert a `FetchOutcome<T>` into a `Result<U, FetchError>` via `map`,
/// in a single total match (no panic / `expect` / `unreachable!`).
fn into_result<T, U>(
    outcome: FetchOutcome<T>,
    map: impl FnOnce(T) -> U,
) -> Result<U, app::FetchError> {
    match outcome {
        FetchOutcome::Ok(body) => Ok(map(body)),
        // `from_outcome` is `None` only for `Ok`, already handled above;
        // the fallback keeps this total and panic-free.
        other => Err(app::FetchError::from_outcome(&other).unwrap_or_else(|| {
            app::FetchError::BadResponse { summary: "unexpected fetch outcome".to_owned() }
        })),
    }
}

/// The blocking keyboard pump. Polls crossterm and forwards translated
/// keys until `shutdown` is set or the receiver is gone.
fn keyboard_pump(key_tx: &mpsc::Sender<Key>, shutdown: &AtomicBool) {
    loop {
        if shutdown.load(Ordering::SeqCst) {
            return;
        }
        match crossterm::event::poll(Duration::from_millis(50)) {
            Ok(true) => {
                if let Ok(crossterm::event::Event::Key(key_event)) = crossterm::event::read()
                    && let Some(key) = translate_key(key_event)
                {
                    // A full channel (UI wedged) or a closed receiver both
                    // mean "stop pumping".
                    if key_tx.blocking_send(key).is_err() {
                        return;
                    }
                }
            }
            Ok(false) => {} // timeout, loop and re-check shutdown
            Err(_) => return,
        }
    }
}

/// Translate a crossterm `KeyEvent` into the reducer's [`Key`]. Returns
/// `None` for keys the UI ignores.
fn translate_key(ev: KeyEvent) -> Option<Key> {
    // Ignore key-release events (Windows / kitty protocol emit them).
    if ev.kind == KeyEventKind::Release {
        return None;
    }
    if ev.modifiers.contains(KeyModifiers::CONTROL)
        && matches!(ev.code, KeyCode::Char('c') | KeyCode::Char('C'))
    {
        return Some(Key::CtrlC);
    }
    match ev.code {
        KeyCode::Up | KeyCode::Char('k') => Some(Key::Up),
        KeyCode::Down | KeyCode::Char('j') => Some(Key::Down),
        KeyCode::Enter => Some(Key::Enter),
        KeyCode::Esc => Some(Key::Esc),
        KeyCode::Tab => Some(Key::Tab),
        KeyCode::Char('r') | KeyCode::Char('R') => Some(Key::Refresh),
        KeyCode::Char('?') => Some(Key::ToggleHelp),
        KeyCode::Char('q') | KeyCode::Char('Q') => Some(Key::Quit),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translate_ctrl_c() {
        let ev = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert_eq!(translate_key(ev), Some(Key::CtrlC));
    }

    #[test]
    fn translate_vim_keys() {
        assert_eq!(translate_key(KeyEvent::from(KeyCode::Char('j'))), Some(Key::Down));
        assert_eq!(translate_key(KeyEvent::from(KeyCode::Char('k'))), Some(Key::Up));
        assert_eq!(translate_key(KeyEvent::from(KeyCode::Char('q'))), Some(Key::Quit));
        assert_eq!(translate_key(KeyEvent::from(KeyCode::Char('r'))), Some(Key::Refresh));
    }

    #[test]
    fn translate_ignores_release() {
        let mut ev = KeyEvent::from(KeyCode::Char('q'));
        ev.kind = KeyEventKind::Release;
        assert_eq!(translate_key(ev), None);
    }

    #[test]
    fn translate_ignores_unmapped() {
        assert_eq!(translate_key(KeyEvent::from(KeyCode::Char('z'))), None);
    }

    /// Guard: the `ui` module must never install a tracing subscriber.
    /// A stdout `fmt` layer (as `init_tracing` installs) would write log
    /// lines into the alt-screen and corrupt the TUI. Errors surface
    /// through the footer + post-restore stderr instead. Mirrors the
    /// source-scan guard pattern used elsewhere in `cli/`.
    #[test]
    fn ui_module_does_not_install_tracing_subscriber() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/cli/ui");
        let mut offenders = Vec::new();
        for entry in walk(&dir) {
            let src = std::fs::read_to_string(&entry).unwrap_or_default();
            // Strip this guard's own file from the check (it names the
            // symbol in this comment/string).
            if entry.file_name().and_then(|s| s.to_str()) == Some("mod.rs") {
                continue;
            }
            if src.contains("init_tracing") || src.contains("set_global_default") {
                offenders.push(entry.display().to_string());
            }
        }
        assert!(
            offenders.is_empty(),
            "cli/ui must not install a tracing subscriber (alt-screen corruption); offenders: {offenders:?}"
        );
    }

    fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        if let Ok(rd) = std::fs::read_dir(dir) {
            for entry in rd.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    out.extend(walk(&path));
                } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
                    out.push(path);
                }
            }
        }
        out
    }
}
