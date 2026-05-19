use std::path::PathBuf;

pub mod agent;
pub mod atomic_write;
pub mod audit;
pub mod audit_anomaly;
pub mod audit_export;
pub mod audit_follow;
pub mod config;
pub mod connect;
pub mod connect_uds;
pub mod connectors;
pub mod credentials;
pub mod doctor;
pub mod kill;
pub mod logs;
pub mod migrations;
pub mod oauth_render;
pub mod openclaw;
pub mod policy;
pub mod release_verify;
pub mod reload;
pub mod resume;
#[cfg(unix)]
pub mod root_guard;
pub mod rotate_key;
pub mod scrub;
pub mod service;
pub mod setup;
pub mod start;
pub mod status;
pub mod stop;
pub mod uninstall;
pub mod update;

/// Resolve the daemon state-dir.
///
/// Honors the `AGENTSSO_PATHS__HOME` environment variable (the
/// integration-test override seam used by the daemon's config layer
/// and 12+ test files); otherwise delegates to
/// [`permitlayer_core::paths::daemon_state_dir`] for the per-platform
/// default.
///
/// Returns `Err` only when no override is set AND the per-platform
/// default cannot be resolved (Linux/Windows: `dirs::home_dir()`
/// returned `None` AND no env override is set — vanishingly rare,
/// but the `?` callers depend on the fallible signature).
pub(crate) fn agentsso_home() -> anyhow::Result<PathBuf> {
    // Story 7.27 Round-2 review fix (P3): consolidate the env-var
    // lookup through `permitlayer_core::paths::home_override()` so
    // empty-string + whitespace normalization (P1 fix) applies here
    // too. Pre-fix, this fifth inline-`std::env::var` site was
    // missed in the Round-1 consolidation pass (story line 773).
    if let Some(override_path) = permitlayer_core::paths::home_override() {
        return Ok(override_path);
    }
    Ok(permitlayer_core::paths::daemon_state_dir(None))
}

/// Marker error wrapped inside an `anyhow::Error` to tell
/// [`crate::anyhow_to_exit_code`] that the command has ALREADY printed
/// a structured, operator-facing error block to stderr (e.g., via
/// `design::render::error_block`) and the generic `error: {e:#}` line
/// should be suppressed.
///
/// Use via [`silent_cli_error`] rather than constructing directly —
/// this keeps the idiom grep-able and the wrapping uniform.
///
/// Story 5.1 review H2: before this marker existed, every
/// `agentsso audit` error path emitted the polished `error_block` AND
/// the generic `error: ...` line on top of it, so operators saw the
/// same error twice in two different formats. Other CLI commands that
/// also emit `error_block` before returning `Err` (e.g., Story 1.15
/// `start` bootstrap) either panicked-exited cleanly via `StartError`
/// or — in the few non-`start` cases — lived with the duplicate. This
/// marker is the shared fix for any non-`start` command that prints
/// its own structured error and needs `anyhow_to_exit_code` to stay
/// out of its way.
#[derive(Debug)]
pub(crate) struct SilentCliError;

impl std::fmt::Display for SilentCliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("cli error already printed")
    }
}

impl std::error::Error for SilentCliError {}

/// Construct an `anyhow::Error` that flags "I've already printed a
/// structured error block to stderr; do not print the generic
/// `error: ...` follow-up line". The argument is the internal error
/// message used only for logging / test introspection via
/// `{e:?}`-style formatting.
///
/// Usage in a command handler:
/// ```ignore
/// eprint!("{}", error_block("some_code", "message", "remediation", None));
/// return Err(silent_cli_error("internal description of what happened"));
/// ```
pub(crate) fn silent_cli_error(description: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(SilentCliError).context(description.into())
}
