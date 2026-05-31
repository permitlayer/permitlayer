//! In-process smoke test for the read-only TUI render pipeline.
//!
//! The plan called for `tests/integration/tui_smoke.rs`, but that
//! integration binary drives the real `agentsso` binary as a *subprocess*
//! (see `tests/common/mod.rs::agentsso_bin`), which cannot expose an
//! in-process `ratatui::backend::TestBackend`. So the smoke test lives
//! here, where `client`, `app`, and `views` are reachable in-process — it
//! stands up a hand-rolled listener returning canned control-plane
//! bodies, drives one refresh through the real `client` fetchers into an
//! `App`, renders into a `TestBackend`, and asserts rendered substrings.
//!
//! This is the only place the fetch → reduce → render path is exercised
//! end-to-end without a live daemon.

#![cfg(test)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ratatui::Terminal;
use ratatui::backend::TestBackend;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::cli::kill::ControlEndpoint;

use super::app::{self, App, Event, Fetched, Target};
use super::client::{ControlClient, FetchOutcome};
use super::glyphs::Glyphs;
use super::views::{self, Ctx};

const STATE_JSON: &str =
    r#"{"active":false,"activated_at":null,"token_count":1,"daemon_version":"9.9.9"}"#;
// Real daemon shape: the `{"status":"ok","agents":[...]}` envelope
// (server::control::ListAgentsResponse), NOT a bare array. The prior
// bare-array fixture is exactly what masked the Angie v1.1.0 parse bug.
const AGENTS_JSON: &str = r#"{"status":"ok","agents":[{"name":"smoke-agent","policy_name":"smoke-ro","created_at":"2026-05-28T00:00:00Z","last_seen_at":"2026-05-28T01:00:00Z"}]}"#;
const POLICIES_JSON: &str = r#"{"status":"ok","policies":[{"name":"smoke-ro","origin":"/etc/agentsso/policies/managed/smoke-ro.toml","scopes":["https://example.com/auth/readonly"]}]}"#;
// Real daemon shapes for the slice-2 mutation endpoints (nested
// activation/deactivation envelopes).
const KILL_JSON: &str = r#"{"activation":{"tokens_invalidated":2,"activated_at":"2026-05-30T00:00:00.000Z","was_already_active":false,"reason":"user-initiated"},"daemon_version":"9.9.9"}"#;
const RESUME_JSON: &str = r#"{"deactivation":{"resumed_at":"2026-05-30T00:01:00.000Z","was_already_inactive":false},"daemon_version":"9.9.9"}"#;

/// Serve exactly one HTTP/1.1 request on `stream`, replying with a 200
/// whose body is chosen by the request path. Closes the connection
/// (`Connection: close`), matching what the kill.rs client expects.
async fn serve_one<S>(mut stream: S)
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf).await.unwrap_or(0);
    let req = String::from_utf8_lossy(&buf[..n]);
    let path = req.split_whitespace().nth(1).unwrap_or("");

    let body = if path.contains("/state") {
        STATE_JSON
    } else if path.contains("/agent/list") {
        AGENTS_JSON
    } else if path.contains("/policies") {
        POLICIES_JSON
    } else if path.contains("/kill") {
        KILL_JSON
    } else if path.contains("/resume") {
        RESUME_JSON
    } else {
        "{}"
    };

    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.flush().await;
}

/// Stand up a canned control endpoint. macOS uses UDS (matching
/// `resolve_control_endpoint`); other platforms use loopback TCP. Returns
/// the endpoint plus the spawned acceptor task handle.
async fn canned_endpoint() -> (ControlEndpoint, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();

    #[cfg(target_os = "macos")]
    {
        let sock = dir.path().join("control.sock");
        let listener = tokio::net::UnixListener::bind(&sock).unwrap();
        tokio::spawn(async move {
            // Three refresh fetches + optionally a detail fetch.
            for _ in 0..4 {
                if let Ok((stream, _)) = listener.accept().await {
                    tokio::spawn(serve_one(stream));
                } else {
                    break;
                }
            }
        });
        (ControlEndpoint::Uds(sock), dir)
    }

    #[cfg(not(target_os = "macos"))]
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            for _ in 0..4 {
                if let Ok((stream, _)) = listener.accept().await {
                    tokio::spawn(serve_one(stream));
                } else {
                    break;
                }
            }
        });
        (ControlEndpoint::Tcp(addr), dir)
    }
}

#[tokio::test]
async fn refresh_renders_fixture_state_agents_and_policies() {
    let (endpoint, home) = canned_endpoint().await;
    let client = ControlClient { home: home.path().to_path_buf(), endpoint };

    let ctx = Ctx {
        tokens: crate::design::theme::Theme::Carapace.tokens(),
        support: crate::design::terminal::ColorSupport::NoColor,
        glyphs: Glyphs::ascii(),
    };

    let mut app = App { endpoint_label: "test".into(), ..App::default() };

    // Drive one synthetic refresh: state + agents + policies.
    let state = client.fetch_state().await;
    let agents = client.fetch_agents().await;
    let policies = client.fetch_policies().await;

    // All three must have reached the canned server and parsed.
    assert!(matches!(state, FetchOutcome::Ok(_)), "state fetch failed");
    assert!(matches!(agents, FetchOutcome::Ok(_)), "agents fetch failed");
    assert!(matches!(policies, FetchOutcome::Ok(_)), "policies fetch failed");

    feed(&mut app, Fetched::State(to_result(state, |b| b)));
    feed(&mut app, Fetched::Agents(to_result(agents, |b| b)));
    feed(&mut app, Fetched::Policies(to_result(policies, |b| b.policies)));

    // Render and assert the fixture data is on screen.
    let backend = TestBackend::new(100, 16);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| views::render(f, &app, &ctx)).unwrap();
    let rendered = format!("{}", terminal.backend());

    assert!(rendered.contains("running v9.9.9"), "header should show running version:\n{rendered}");
    assert!(rendered.contains("smoke-agent"), "agent name should render:\n{rendered}");
}

#[tokio::test]
async fn policy_detail_target_is_reachable() {
    // Sanity: the Target::PolicyDetail path resolves against the canned
    // server (it falls through to the `{}` body, which yields a parse
    // error — proving the request was made and classified, not hung).
    let (endpoint, home) = canned_endpoint().await;
    let client = ControlClient { home: home.path().to_path_buf(), endpoint };
    let outcome = client.fetch_policy_detail("smoke-ro").await;
    // `{}` is valid TOML but has no `policies` array → parse error.
    assert!(
        matches!(outcome, FetchOutcome::Parse { .. } | FetchOutcome::Ok(_)),
        "detail fetch should reach the server and classify"
    );
    let _ = Target::PolicyDetail("smoke-ro".into());
}

#[tokio::test]
async fn kill_post_reaches_server_and_drives_reducer() {
    // Slice 2: the full mutation round-trip against the canned server —
    // post_kill parses the real {"activation":{...}} envelope, and
    // feeding the outcome through the reducer sets the notice + emits the
    // /state auto-refresh.
    let (endpoint, home) = canned_endpoint().await;
    let client = ControlClient { home: home.path().to_path_buf(), endpoint };

    let outcome = client.post_kill().await;
    let body = match outcome {
        FetchOutcome::Ok(b) => b,
        other => panic!("post_kill should reach the canned server and parse: {other:?}"),
    };
    assert_eq!(body.activation.tokens_invalidated, 2);
    assert!(!body.activation.was_already_active);

    // Reducer: confirm pending → Mutated(Ok) clears it, sets the notice,
    // and asks for a /state refresh.
    let mut app = App { pending_confirm: Some(app::ConfirmAction::Kill), ..App::default() };
    let mutation = app::MutationOutcome::Killed {
        tokens_invalidated: body.activation.tokens_invalidated,
        was_already_active: body.activation.was_already_active,
    };
    let (next, effects) = app::step(&app, Event::Fetched(Fetched::Mutated(Ok(mutation))));
    app = next;
    assert!(app.pending_confirm.is_none());
    assert!(app.footer_notice.unwrap().contains("kill active"));
    assert_eq!(effects, vec![app::Effect::Fetch(app::Target::State)]);
}

fn feed(app: &mut App, fetched: Fetched) {
    let (next, _) = app::step(app, Event::Fetched(fetched));
    *app = next;
}

fn to_result<T, U>(
    outcome: FetchOutcome<T>,
    map: impl FnOnce(T) -> U,
) -> Result<U, app::FetchError> {
    match outcome {
        FetchOutcome::Ok(b) => Ok(map(b)),
        other => Err(app::FetchError::from_outcome(&other).unwrap()),
    }
}
