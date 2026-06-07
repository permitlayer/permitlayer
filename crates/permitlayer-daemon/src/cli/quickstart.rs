//! `agentsso quickstart <service>` — connect ONE agent to ONE Google
//! service in a single command (UX-overhaul Story 5).
//!
//! ## Model (owner-confirmed, final)
//!
//! The daemon is **headless**. There is NO approval, NO prompt-on-write,
//! NO human-in-the-loop. Access is a binary scope capability chosen up
//! front:
//!
//! - `--read`       → bind the agent to the shipped `<svc>-read-only` policy
//! - `--read-write` → bind the agent to the shipped `<svc>-read-write` policy
//!
//! There is no third option, no `none`, no tier name the operator types,
//! and no danger-confirmation string. Quickstart binds the agent BY
//! NAME to a shipped policy; every shipped policy uses
//! `approval-mode = "auto"` (the only disposition this headless
//! product ships — `prompt` is purged from the bundle because on a
//! headless daemon it could only ever 503). So a `-read-only` tier
//! grants reads only (writes denied by absent scope) and a
//! `-read-write` tier additionally grants that service's write scopes,
//! auto-approved with no gate.
//!
//! ## Flow
//!
//! 1. Validate the service against the same allowlist `connect` uses.
//! 2. Resolve the access level (flag / interactive selection / hard
//!    error when neither a flag nor a TTY is present — we cannot prompt
//!    with no human present, the same reason approvals do not exist).
//! 3. **Kill-switch gate** (before anything mutating) — a killed daemon
//!    must never leave a registered-but-inert agent behind.
//! 4. **Daemon-reachable gate** — reuse `connect`'s structured
//!    install/start remediation block, plus one steer line pointing at
//!    the single privileged step (`sudo agentsso setup`).
//! 5. Register the agent bound to the resolved policy (the bearer token
//!    is held in memory ONLY — quickstart never writes it anywhere).
//! 6. Drive the existing `connect` orchestration: OAuth, seal, verify,
//!    scope-merge, rebind, and MCP-snippet emission. `connect` owns
//!    the snippet emitter (it hardcodes `"transport":"streamable-http"`
//!    via `cli::openclaw`), so quickstart never re-emits a snippet.
//! 7. Print a plain-language summary of what the agent can now do.
//!
//! **Story 11.12/11.13 status:** the `connect <service> --agent`
//! orchestration this command drove is retired (FR23 superseded by
//! `connection add` + `bind`). `run` is a stub that points the operator at
//! the new nouns until **Story 11.15** repoints `quickstart` as a
//! one-liner over `connection add` + `bind` (which needs the `bind` verb,
//! Story 11.14). The pure access-level helpers below are retained for that
//! repoint and exercised by the unit tests.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

use crate::design::render;

// ── Access level → shipped policy name ──────────────────────────────

/// The binary access capability. NOT a tier, NOT an approval mode —
/// just "which shipped policy do we bind the agent to".
///
/// Story 11.13: retained (with the pure helpers below) for the Story
/// 11.15 quickstart repoint; currently exercised only by the unit tests
/// while `run` is a stub.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Access {
    Read,
    ReadWrite,
}

/// Map `(service, write)` to the EXACT shipped policy name.
///
/// No string interpolation — an explicit match so a future bundle
/// rename is a compile/test failure here, not a production
/// `agent.unknown_policy` at register time. The unit tests pin every
/// returned literal against `include_str!("default_policy.toml")`.
#[allow(dead_code)]
fn policy_for(service: &str, write: bool) -> &'static str {
    match (service, write) {
        ("gmail", false) => "gmail-read-only",
        ("gmail", true) => "gmail-read-write",
        ("calendar", false) => "calendar-read-only",
        ("calendar", true) => "calendar-read-write",
        ("drive", false) => "drive-read-only",
        ("drive", true) => "drive-read-write",
        // Unreachable: callers validate `service` against the connector
        // registry (`resolve_selector`) first. Kept total so the fn has no
        // panic path; the empty string would surface as a daemon-side
        // `agent.unknown_policy` (loud) rather than a silent misbind.
        _ => "",
    }
}

/// Parse one interactive selection line into an [`Access`]. `None`
/// means "unrecognized — caller should re-ask once, then default to
/// read". Pure (no I/O) so it is unit-testable.
#[allow(dead_code)]
fn parse_access_line(line: &str) -> Option<Access> {
    match line.trim().to_lowercase().as_str() {
        "" | "1" | "read" => Some(Access::Read),
        "2" | "read-write" | "rw" => Some(Access::ReadWrite),
        _ => None,
    }
}

// ── CLI args ────────────────────────────────────────────────────────

/// Arguments for `agentsso quickstart <service>`.
///
/// `--read` / `--read-write` are mutually exclusive plain flags (clap
/// rejects both). They are NOT a `--tier <enum>` the operator types.
#[derive(Args, Debug)]
pub struct QuickstartArgs {
    /// Service to connect: `gmail`, `calendar`, or `drive`.
    pub service: String,

    /// Bind the agent to the shipped read-only policy and request only
    /// read-only OAuth scopes (the agent can READ; writes are denied).
    #[arg(long, conflicts_with = "read_write")]
    pub read: bool,

    /// Bind the agent to the shipped read-write policy AND request the
    /// write OAuth scopes from Google (gmail.send/compose/modify, …), so
    /// the sealed credential can actually send/modify — not just the
    /// policy binding. The agent can READ and WRITE (send/modify/delete)
    /// with no gate; the daemon is headless. The Google consent screen
    /// will list the write scopes.
    #[arg(long = "read-write", conflicts_with = "read")]
    pub read_write: bool,

    /// Path to a Google OAuth client JSON file. Forwarded to the
    /// `connect` orchestration; still required for the OAuth step.
    #[arg(long = "oauth-client", value_name = "PATH")]
    pub oauth_client: Option<PathBuf>,

    /// Write the OpenClaw MCP config snippet to this path (forwarded
    /// to `connect`, which owns snippet emission).
    #[arg(long = "mcp-config-out", value_name = "PATH")]
    pub mcp_config_out: Option<PathBuf>,

    /// Agent name to create. Defaults to `<service>-quickstart`.
    #[arg(long)]
    pub agent: Option<String>,

    /// Allow running from an effective-root shell with SUDO_USER set
    /// (forwarded to `connect`). CI / embedded installs only.
    #[arg(long)]
    pub allow_root: bool,

    /// Skip all interactive prompts. Without `--read`/`--read-write`
    /// this is a hard error (we cannot prompt with no human present).
    #[arg(long)]
    pub non_interactive: bool,

    /// Show the full per-step progress trace from the underlying
    /// `connect` flow. Forwarded to `connect`; default output collapses
    /// the steps into a one-line summary.
    #[arg(short = 'v', long)]
    pub verbose: bool,
}

// ── Run ─────────────────────────────────────────────────────────────

/// Run the `quickstart` subcommand.
///
/// **Story 11.12/11.13:** `quickstart` previously drove the retired
/// `connect <service> --agent` orchestration (OAuth + seal + agent
/// policy-merge + rebind). That model is gone — an agent's authority is
/// now its set of **bindings**, and credentials live on per-account
/// **connections**. `quickstart`'s repoint onto `connection add` + `bind`
/// (one-liner over the new nouns) is **Story 11.15**, which depends on the
/// `bind` verb (Story 11.14). Until then this stub emits the migration
/// path and exits 2 (operator-correctable). The arg surface is retained so
/// the `#[ignore]`d `quickstart_e2e.rs` tests compile; they stay ignored
/// until 11.15 lands the real flow.
pub async fn run(args: QuickstartArgs) -> Result<()> {
    let _ = &args;
    eprint!(
        "{}",
        render::error_block(
            "quickstart.not_yet_repointed",
            "`agentsso quickstart` is being repointed onto the new connection + binding \
             model and is temporarily unavailable.",
            "create a connection and bind an agent to it:\n\n    \
             agentsso connection add <connector> --name <name> [--read-write]\n    \
             agentsso bind <agent> --connection <name>        # Story 11.14\n\n  \
             (quickstart returns as a one-liner over these in Story 11.15)",
            None,
        )
    );
    Err(crate::cli::oauth_seal::exit2())
}

// ── Tests ───────────────────────────────────────────────────────────
//
// This crate is `#![forbid(unsafe_code)]`; `std::env::set_var` is
// unsafe in edition 2024 — NO env-mutating tests. All unit tests are
// pure (no I/O, no env). End-to-end behavior is covered in
// `tests/integration/quickstart_e2e.rs`.

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Every `policy_for` return value must be EXACTLY the shipped
    /// policy name AND must appear verbatim as `name = "<literal>"` in
    /// the bundled `default_policy.toml`. A future bundle rename then
    /// breaks the build here, not production.
    #[test]
    fn policy_for_returns_exact_shipped_literals() {
        let bundle = include_str!("default_policy.toml");
        let cases: &[(&str, bool, &str)] = &[
            ("gmail", false, "gmail-read-only"),
            ("gmail", true, "gmail-read-write"),
            ("calendar", false, "calendar-read-only"),
            ("calendar", true, "calendar-read-write"),
            ("drive", false, "drive-read-only"),
            ("drive", true, "drive-read-write"),
        ];
        for (svc, write, expected) in cases {
            assert_eq!(
                policy_for(svc, *write),
                *expected,
                "policy_for({svc}, {write}) literal drifted"
            );
            assert!(
                bundle.contains(&format!("name = \"{expected}\"")),
                "shipped default_policy.toml is missing `name = \"{expected}\"` — \
                 quickstart would mis-bind in production"
            );
        }
    }

    #[test]
    fn service_predicate_accepts_known_rejects_others() {
        // Story 11.7: existence now resolves through the connector registry
        // (built-ins). `run` lowercases/trims the arg first, so the registry
        // sees a normalized selector; the registry itself is exact-match
        // (`Gmail`/`drive ` resolve to None).
        let registry = permitlayer_connectors::ConnectorRegistry::load(None).unwrap();
        for ok in ["gmail", "calendar", "drive"] {
            assert!(registry.resolve_selector(ok).is_some(), "{ok} should be supported");
        }
        for bad in ["salesforce", "Gmail", "", "drive ", "slack"] {
            assert!(registry.resolve_selector(bad).is_none(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn parse_access_line_maps_read_inputs() {
        for s in ["", "1", "read", "READ", "  read  ", "\n", " 1 "] {
            assert_eq!(parse_access_line(s), Some(Access::Read), "{s:?} → read");
        }
    }

    #[test]
    fn parse_access_line_maps_read_write_inputs() {
        for s in ["2", "read-write", "rw", "RW", "  Read-Write ", " 2 "] {
            assert_eq!(parse_access_line(s), Some(Access::ReadWrite), "{s:?} → read-write");
        }
    }

    #[test]
    fn parse_access_line_rejects_junk() {
        for s in ["3", "yes", "y", "no", "readwrite", "r/w", "delete-everything"] {
            assert_eq!(parse_access_line(s), None, "{s:?} must be unrecognized");
        }
    }

    /// The interactive parser's documented "re-ask once then default
    /// to read on junk" contract, exercised at the pure level: junk →
    /// `None` (caller re-asks), and a second junk → still `None`
    /// (caller defaults to read). This pins the semantics without the
    /// I/O loop.
    #[test]
    fn junk_then_junk_yields_default_read_semantics() {
        assert_eq!(parse_access_line("garbage"), None);
        assert_eq!(parse_access_line("more-garbage"), None);
        // The fallback the loop applies after two misses:
        let fallback = parse_access_line("garbage").unwrap_or(Access::Read);
        assert_eq!(fallback, Access::Read);
    }
}
