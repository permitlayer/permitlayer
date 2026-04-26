use std::path::PathBuf;

pub mod agent;
pub mod audit;
pub mod audit_anomaly;
pub mod audit_export;
pub mod audit_follow;
pub mod autostart;
pub mod config;
pub mod connectors;
pub mod credentials;
pub mod kill;
pub mod logs;
pub mod reload;
pub mod resume;
pub mod scrub;
pub mod setup;
pub mod start;
pub mod status;
pub mod stop;

/// Resolve the `~/.agentsso/` home directory.
///
/// Honors the `AGENTSSO_PATHS__HOME` environment variable (same as the
/// daemon's config layer) for testing and custom deployments.
pub(crate) fn agentsso_home() -> anyhow::Result<PathBuf> {
    if let Ok(override_path) = std::env::var("AGENTSSO_PATHS__HOME") {
        return Ok(PathBuf::from(override_path));
    }
    let home =
        dirs::home_dir().ok_or_else(|| anyhow::anyhow!("cannot determine home directory"))?;
    Ok(home.join(".agentsso"))
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
