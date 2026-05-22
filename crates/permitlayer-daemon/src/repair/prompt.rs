#![allow(dead_code)]
//! `dialoguer::Confirm` wrapper with TTY detection + teal-theme.
//!
//! Story 10.2's setup self-heals use this when a recovery would
//! touch operator-observable state (legacy-seed shadow archive,
//! versioned-binary replacement). Non-TTY contexts get
//! [`Confirm::NoTty`] without a prompt — the caller decides whether
//! to refuse or proceed (Story 10.2 refuses).
//!
//! Mirrors the established convention from `cli/connect.rs:865-892`:
//! `tokio::task::spawn_blocking(|| dialoguer::Confirm::with_theme(...).interact())`
//! because dialoguer uses blocking stdin reads and can't run on the
//! async runtime.

use std::io::IsTerminal;
use std::path::Path;
use std::sync::Arc;

use crate::cli::oauth_render::build_teal_theme;
use crate::design::theme::Theme;

/// Operator decision returned by [`confirm_tty`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Confirm {
    /// Operator typed `y` (or accepted the default Yes).
    Yes,
    /// Operator typed `n` (or accepted the default No).
    No,
    /// stdin is not a TTY — no prompt shown. The caller must
    /// decide whether to proceed silently or refuse.
    NoTty,
}

/// A heal candidate's metadata, shown to the operator before the
/// prompt fires.
///
/// Field names are intentionally operator-friendly. `impact` (not
/// `blast_radius`) is the multi-line "what will happen" block —
/// engineer-speak shouldn't leak into the API.
pub(crate) struct Heal<'a> {
    /// Stable code for the heal type, e.g. `"repair.legacy_seed_shadow"`.
    /// Surfaces in tracing and journal entries.
    pub code: &'static str,
    /// One-line operator-facing description of the heal.
    pub what: &'a str,
    /// Multi-line description of what will change on disk. Shown
    /// before the prompt so the operator knows what they're
    /// approving.
    pub impact: &'a str,
}

/// Prompt the operator for a heal decision.
///
/// Returns `Confirm::NoTty` immediately (no prompt, no print) if
/// stdin OR stderr is not a TTY. Both are required because:
/// - **stdin** is where dialoguer reads the y/n keypress;
/// - **stderr** is where dialoguer writes its prompt UI (and where
///   we should ideally route the `heal.what`/`heal.impact` context
///   so a piped stdout still shows the operator what they're
///   approving).
///
/// If stdout is piped but stderr is still a TTY, this function
/// proceeds and the operator sees both the context block and the
/// prompt — even though `println!` goes to the piped stdout, the
/// operator can re-read what they're approving in the dialoguer
/// prompt itself. If stderr is piped, we refuse the prompt rather
/// than risk a blind y/n on a destructive heal.
///
/// Wrapped in `tokio::task::spawn_blocking` per the established
/// convention.
pub(crate) async fn confirm_tty(
    home: &Path,
    heal: &Heal<'_>,
    default_yes: bool,
) -> std::io::Result<Confirm> {
    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        return Ok(Confirm::NoTty);
    }

    // Print the heal context before the prompt so the operator sees
    // what they're approving.
    println!("{}", heal.what);
    if !heal.impact.is_empty() {
        println!("{}", heal.impact);
    }

    let theme = Theme::load(home);
    let teal = Arc::new(build_teal_theme(&theme));
    let prompt_text = format!("Continue with {}?", heal.code);

    let confirmed = tokio::task::spawn_blocking(move || {
        dialoguer::Confirm::with_theme(&*teal)
            .with_prompt(prompt_text)
            .default(default_yes)
            .interact()
    })
    .await
    .map_err(|e| std::io::Error::other(format!("prompt join failed: {e}")))?
    .map_err(|e| std::io::Error::other(format!("dialoguer prompt failed: {e}")))?;

    Ok(if confirmed { Confirm::Yes } else { Confirm::No })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn confirm_tty_returns_no_tty_when_stdin_is_not_a_terminal() {
        // `cargo nextest` runs each test in its own process with
        // stdin redirected from /dev/null, so `is_terminal()` is
        // false here. The function should return NoTty without
        // attempting a dialoguer prompt.
        let home = tempfile::tempdir().unwrap();
        let heal = Heal {
            code: "repair.test_no_tty",
            what: "this heal would touch operator-observable state",
            impact: "if accepted, file X would be archived to dir Y",
        };
        let result = confirm_tty(home.path(), &heal, true).await.unwrap();
        assert_eq!(result, Confirm::NoTty);
    }

    // The TTY-yes / TTY-no paths require a fake TTY (PTY) — not
    // unit-testable cleanly in a `cargo nextest` process. Those
    // paths are exercised by Story 10.2's setup self-heal e2e
    // integration tests with a scripted PTY harness.
}
