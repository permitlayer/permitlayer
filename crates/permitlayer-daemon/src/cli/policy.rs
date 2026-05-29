//! `agentsso policy show|validate|list` — inspect and validate policies.
//!
//! Story 7.34 adds first-class policy affordances so operators do not
//! have to infer state from source code or logs.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Subcommand};
use serde::Deserialize;

use crate::cli::kill::{
    error_block_daemon_unreachable_endpoint, error_block_protocol_error,
    load_daemon_config_or_default_with_warn, resolve_control_endpoint,
};
use crate::design::render::{self, TableCell, error_block, table};
use crate::design::terminal::{ColorSupport, TableLayout};
use crate::design::theme::Theme;

/// Top-level `policy` subcommand wrapper.
#[derive(Args)]
pub struct PolicyArgs {
    #[command(subcommand)]
    pub command: PolicyCommand,
}

#[derive(Subcommand)]
pub enum PolicyCommand {
    /// Print the resolved in-memory representation of a loaded policy
    /// as TOML, including defaults filled by the parser.
    Show(ShowArgs),
    /// Parse a TOML file against the policy schema without loading it
    /// into the running daemon. Reports parse and semantic errors with
    /// line/column information when available.
    Validate(ValidateArgs),
    /// Print every loaded policy name, source file, and allowlisted scopes,
    /// one per line sorted alphabetically by policy name.
    List,
}

#[derive(Args)]
pub struct ShowArgs {
    /// Policy name to show.
    pub name: String,
}

#[derive(Args)]
pub struct ValidateArgs {
    /// Path to the TOML policy file to validate.
    pub path: PathBuf,
}

pub async fn run(args: PolicyArgs) -> Result<()> {
    match args.command {
        PolicyCommand::Show(a) => show_policy(a).await,
        PolicyCommand::Validate(a) => validate_policy(a),
        PolicyCommand::List => list_policies().await,
    }
}

/// `agentsso policy show <name>` — query the daemon and print TOML.
async fn show_policy(args: ShowArgs) -> Result<()> {
    let config = load_daemon_config_or_default_with_warn("policy show");
    let endpoint = resolve_control_endpoint(&config);
    let token = crate::cli::kill::read_control_token(&config.paths.home);

    let url = format!("/v1/control/policies/{}", args.name);
    let (status, body) =
        match crate::cli::kill::http_get_with_status_via(&endpoint, &url, token.as_deref()).await {
            Ok(b) => b,
            Err(e) => {
                tracing::debug!(error = %e, endpoint = %endpoint, "policy show request failed");
                eprint!("{}", error_block_daemon_unreachable_endpoint("policy show", &endpoint));
                std::process::exit(3);
            }
        };

    if status == 404 {
        if let Ok(err) = serde_json::from_str::<PolicyErrorJson>(&body) {
            let suggested = match err.code.as_str() {
                "policy.not_found" => "list known policies: agentsso policy list".to_owned(),
                _ => "see message above".to_owned(),
            };
            eprint!("{}", error_block(&err.code, &err.message, &suggested, None));
        } else {
            eprint!(
                "{}",
                error_block(
                    "policy.not_found",
                    &format!("policy '{}' is not loaded", args.name),
                    "list known policies: agentsso policy list",
                    None
                )
            );
        }
        std::process::exit(2);
    }

    if status != 200 {
        if let Ok(err) = serde_json::from_str::<PolicyErrorJson>(&body) {
            eprint!("{}", error_block(&err.code, &err.message, "see message above", None));
        } else {
            eprint!(
                "{}",
                error_block(
                    "policy.unexpected_status",
                    &format!("daemon returned HTTP {status}"),
                    "see daemon logs",
                    None
                )
            );
        }
        std::process::exit(2);
    }

    println!("{}", body);
    Ok(())
}

/// `agentsso policy validate <path>` — client-side parse and semantic check.
fn validate_policy(args: ValidateArgs) -> Result<()> {
    let path = &args.path;
    // Story 7.34 review patch: reject non-regular files (FIFOs, devices,
    // symlinks) before blocking on read_to_string.
    match std::fs::metadata(path) {
        Ok(meta) if !meta.is_file() => {
            eprint!(
                "{}",
                error_block(
                    "policy.not_a_regular_file",
                    &format!("not a regular file: {}", path.display()),
                    "provide the path to a regular TOML file",
                    None,
                )
            );
            std::process::exit(2);
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprint!(
                "{}",
                error_block(
                    "policy.file_not_found",
                    &format!("file not found: {}", path.display()),
                    "check the path",
                    None,
                )
            );
            std::process::exit(2);
        }
        Err(e) => {
            eprint!(
                "{}",
                error_block(
                    "policy.read_failed",
                    &format!("could not read {}: {e}", path.display()),
                    "check the path and permissions",
                    None,
                )
            );
            std::process::exit(2);
        }
    }
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            let (code, msg) = match e.kind() {
                std::io::ErrorKind::NotFound => {
                    ("policy.file_not_found", format!("file not found: {}", path.display()))
                }
                std::io::ErrorKind::PermissionDenied => (
                    "policy.permission_denied",
                    format!("permission denied reading: {}", path.display()),
                ),
                _ => ("policy.read_failed", format!("could not read {}: {e}", path.display())),
            };
            eprint!("{}", error_block(code, &msg, "check the path and permissions", None));
            std::process::exit(2);
        }
    };

    match permitlayer_core::policy::PolicySet::compile_from_str(&text, path) {
        Ok(set) => {
            // Route the success glyph through the shared palette via
            // `success_headline` (TTY/NO_COLOR-aware accent ✓) instead of
            // a bare Unicode literal, matching the one CLI output idiom.
            let support = ColorSupport::detect();
            let theme =
                Theme::load(&super::agentsso_home().unwrap_or_else(|_| PathBuf::from(".agentsso")));
            print!(
                "{}",
                render::success_headline(
                    &format!("valid policy file ({} {})", set.len(), policy_count_noun(set.len())),
                    &theme,
                    support,
                )
            );
            Ok(())
        }
        Err(e) => {
            eprint!(
                "{}",
                error_block(
                    "policy.validation_failed",
                    &format!("{e}"),
                    "correct the TOML and retry",
                    None
                )
            );
            std::process::exit(2);
        }
    }
}

fn policy_count_noun(count: usize) -> &'static str {
    if count == 1 { "policy" } else { "policies" }
}

/// Deserialization target for JSON error responses from the policy
/// control endpoints.
#[derive(Debug, Deserialize)]
struct PolicyErrorJson {
    #[allow(dead_code)]
    status: String,
    code: String,
    message: String,
}

/// Deserialization target for `GET /v1/control/policies` list entries.
#[derive(Debug, Deserialize)]
struct PolicyListEntry {
    name: String,
    origin: String,
    scopes: Vec<String>,
}

/// `agentsso policy list` — query the daemon and print sorted lines.
async fn list_policies() -> Result<()> {
    let config = load_daemon_config_or_default_with_warn("policy list");
    let endpoint = resolve_control_endpoint(&config);
    let token = crate::cli::kill::read_control_token(&config.paths.home);

    let response =
        match crate::cli::kill::http_get_via(&endpoint, "/v1/control/policies", token.as_deref())
            .await
        {
            Ok(b) => b,
            Err(e) => {
                tracing::debug!(error = %e, endpoint = %endpoint, "policy list request failed");
                eprint!("{}", error_block_daemon_unreachable_endpoint("policy list", &endpoint));
                std::process::exit(3);
            }
        };

    let parsed: serde_json::Value = match serde_json::from_str(&response) {
        Ok(v) => v,
        Err(e) => {
            tracing::debug!(error = %e, body = %response, "unexpected policy list response");
            eprint!("{}", error_block_protocol_error());
            std::process::exit(3);
        }
    };

    // Bug 2: nested control-plane auth errors carry a top-level
    // `status:"error"` and would otherwise fall into the flat branch
    // below as a useless `policy.unknown_error` AND exit 2 (operator-
    // correctable input) for what is actually an auth failure. Surface
    // them first with the correct exit 3, matching every other
    // `/v1/control/*` consumer. Genuine `policy.*` errors keep exit 2.
    if let Some((code, message)) = crate::cli::kill::nested_control_plane_auth_error(&parsed) {
        eprint!(
            "{}",
            error_block(&code, &message, crate::cli::kill::CONTROL_AUTH_REMEDIATION, None)
        );
        std::process::exit(3);
    }
    let status = parsed["status"].as_str();
    if status == Some("error") {
        let code = parsed["code"].as_str().unwrap_or("policy.unknown_error").to_owned();
        let message = parsed["message"].as_str().unwrap_or("(no message provided)").to_owned();
        eprint!("{}", error_block(&code, &message, "see message above", None));
        std::process::exit(2);
    }
    if status != Some("ok") {
        tracing::debug!(body = %response, "unexpected policy list response: status was neither 'ok' nor 'error'");
        eprint!("{}", error_block_protocol_error());
        std::process::exit(3);
    }

    let entries: Vec<PolicyListEntry> = match serde_json::from_value(parsed["policies"].clone()) {
        Ok(v) => v,
        Err(e) => {
            tracing::debug!(error = %e, body = %response, "policy list policies array parse failed");
            eprint!("{}", error_block_protocol_error());
            std::process::exit(3);
        }
    };

    let support = ColorSupport::detect();
    let theme = Theme::load(&super::agentsso_home().unwrap_or_else(|_| PathBuf::from(".agentsso")));

    if entries.is_empty() {
        print!(
            "{}",
            render::empty_state(
                "no policies loaded",
                "register with:  agentsso policy register <name>"
            )
        );
        return Ok(());
    }

    // Render through the shared `render::table()` pipeline (matching
    // `agent list` / `credentials list`) instead of hand-rolled
    // space-padded `println!` columns — TTY/NO_COLOR-aware, adaptive.
    let layout = TableLayout::detect();
    let headers = &["POLICY", "ORIGIN", "SCOPES"];
    let rows: Vec<Vec<TableCell>> = entries
        .into_iter()
        .map(|entry| {
            vec![
                TableCell::Plain(entry.name),
                TableCell::Plain(entry.origin),
                TableCell::Plain(entry.scopes.join(", ")),
            ]
        })
        .collect();

    match table(headers, &rows, layout, &theme, support) {
        Ok(rendered) => print!("{rendered}"),
        Err(e) => {
            tracing::warn!(error = %e, "table render failed — falling back to plain output");
            for row in &rows {
                let cells: Vec<&str> = row
                    .iter()
                    .map(|c| match c {
                        TableCell::Plain(s) => s.as_str(),
                        _ => "",
                    })
                    .collect();
                println!("{}", cells.join("  "));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_count_noun_pluralizes_correctly() {
        assert_eq!(policy_count_noun(0), "policies");
        assert_eq!(policy_count_noun(1), "policy");
        assert_eq!(policy_count_noun(2), "policies");
        assert_eq!(policy_count_noun(3), "policies");
    }
}
