//! `agentsso connectors list` — enumerate the daemon's plugin
//! registry via the loopback control plane (Story 6.3, FR40).
//!
//! Mirrors [`crate::cli::agent`]'s HTTP-over-loopback pattern:
//! issue `GET /v1/control/connectors`, parse the JSON response,
//! render either a design-system table (default) or raw JSON
//! passthrough (`--json`).
//!
//! The endpoint returns one row per registered connector (built-in
//! or user-installed). Plugin JS source is NOT transported over
//! the wire — only metadata + trust tier + short source hash.

use anyhow::Result;
use clap::Args;

use crate::cli::kill::{
    error_block_daemon_not_running, error_block_daemon_unreachable, error_block_protocol_error,
    http_get, load_daemon_config_or_default_with_warn,
};
use crate::design::render::{TableCell, empty_state, error_block, table, truncate_field};
use crate::design::terminal::{ColorSupport, TableLayout, styled};
use crate::design::theme::Theme;
use crate::lifecycle::pid::PidFile;

#[derive(Args)]
pub struct ListArgs {
    /// Emit the raw JSON response from the control plane instead
    /// of the rendered table. Useful for scripting or piping into
    /// `jq`. Matches Story 5.3's `audit export --json` convention.
    #[arg(long)]
    pub json: bool,
}

pub async fn list_connectors(args: ListArgs) -> Result<()> {
    let config = load_daemon_config_or_default_with_warn("connectors list");
    let home = config.paths.home.clone();

    if PidFile::read(&home)?.is_none() || !PidFile::is_daemon_running(&home)? {
        eprint!("{}", error_block_daemon_not_running("connectors list"));
        std::process::exit(3);
    }

    let bind_addr = config.http.bind_addr;
    let response = match http_get(bind_addr, "/v1/control/connectors").await {
        Ok(b) => b,
        Err(e) => {
            tracing::debug!(error = %e, addr = %bind_addr, "connectors list request failed");
            eprint!("{}", error_block_daemon_unreachable("connectors list", bind_addr));
            std::process::exit(3);
        }
    };

    // --json mode: verify the response is valid JSON, then dump it
    // verbatim. Propagate daemon-side errors via a non-zero exit
    // code so scripts piping `connectors list --json | jq` don't
    // silently consume an error blob as if it were a success.
    if args.json {
        match serde_json::from_str::<serde_json::Value>(&response) {
            Ok(parsed) => {
                println!("{response}");
                if parsed["status"] == "error" {
                    std::process::exit(3);
                }
                return Ok(());
            }
            Err(e) => {
                tracing::debug!(error = %e, body = %response, "connectors list --json response is not valid JSON");
                eprint!("{}", error_block_protocol_error());
                std::process::exit(3);
            }
        }
    }

    let parsed: serde_json::Value = match serde_json::from_str(&response) {
        Ok(v) => v,
        Err(e) => {
            tracing::debug!(error = %e, body = %response, "unexpected connectors list response");
            eprint!("{}", error_block_protocol_error());
            std::process::exit(3);
        }
    };

    if parsed["status"] == "error" {
        let code = parsed["code"].as_str().unwrap_or("connectors.unknown_error").to_owned();
        let message = parsed["message"].as_str().unwrap_or("(no message provided)").to_owned();
        eprint!("{}", error_block(&code, &message, "see message above", None));
        std::process::exit(3);
    }

    let connectors = parsed["connectors"].as_array().cloned().unwrap_or_default();
    let theme = Theme::load(&home);
    let support = ColorSupport::detect();
    let layout = TableLayout::detect();

    if connectors.is_empty() {
        print!(
            "{}",
            empty_state(
                "no connectors registered",
                "install one with:  drop a plugin into ~/.agentsso/plugins/<name>/index.js"
            )
        );
        return Ok(());
    }

    // Scope column budget — keeps narrow terminals legible. Uses
    // `truncate_field` (char-boundary-safe via `chars()`) so a
    // future charset expansion past ASCII does not byte-panic.
    const SCOPE_COL_BUDGET: usize = 40;
    const HASH_CHARS: usize = 12;

    let rows: Vec<Vec<TableCell>> = connectors
        .iter()
        .map(|c| {
            let name = c["name"].as_str().unwrap_or("").to_owned();
            let version = c["version"].as_str().unwrap_or("").to_owned();
            let trust_tier = c["trust_tier"].as_str().unwrap_or("").to_owned();
            let scopes_vec: Vec<String> = c["scopes"]
                .as_array()
                .map(|arr| {
                    arr.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let scopes_joined = scopes_vec.join(", ");
            let scopes = truncate_field(&scopes_joined, SCOPE_COL_BUDGET);
            // Hash short-prefix: char-boundary-safe via chars() even
            // though the wire value is always ASCII hex today.
            let hash_full = c["source_sha256_hex"].as_str().unwrap_or("");
            let hash_short: String = hash_full.chars().take(HASH_CHARS).collect();

            vec![
                TableCell::Plain(name),
                TableCell::Plain(version),
                TableCell::Plain(trust_tier),
                TableCell::Plain(scopes),
                TableCell::Plain(hash_short),
            ]
        })
        .collect();

    let headers = &["CONNECTOR", "VERSION", "TRUST", "SCOPES", "HASH"];
    let table_str = table(headers, &rows, layout, &theme, support)?;

    // Post-render ANSI coloring for the trust column: the table
    // renderer computes column widths from character counts, so the
    // trust values must be plain strings at layout time. We apply
    // color by searching for the exact tier tokens AFTER the table
    // is built — the tokens are unique enough (`builtin`,
    // `trusted-user`, `warn-user`) that false positives are
    // implausible in operator-facing output.
    let colored = colorize_trust_labels(&table_str, &theme, support);
    print!("{colored}");
    if !colored.ends_with('\n') {
        println!();
    }

    Ok(())
}

/// Wrap the three trust-tier tokens with design-system colors:
/// `builtin` → success (green), `trusted-user` → info (blue),
/// `warn-user` → warn (yellow). Matches Story 6.3 AC #16 exactly.
///
/// Works on the already-rendered table string. Tier tokens are
/// matched with word-boundary guards so a scope literally named
/// `builtin` / `warn-user` / `trusted-user` (the scope charset
/// `^[a-z][a-z0-9._-]{0,63}$` does allow these verbatim) does
/// not get accidentally colored as if it were a TRUST cell.
/// Every rendered table cell is padded with spaces, so a
/// boundary of `(space|line-start) TOKEN (space|line-end)` is a
/// reliable marker for the trust column.
fn colorize_trust_labels(table: &str, theme: &Theme, support: ColorSupport) -> String {
    if matches!(support, ColorSupport::NoColor) {
        return table.to_owned();
    }
    let tokens = theme.tokens();
    let mut out = String::with_capacity(table.len());
    // Order matters: match longer tokens first so `trusted-user`
    // is not caught by the `-user` fragment of `warn-user`.
    let styled_tokens: Vec<(&'static str, String)> =
        [("trusted-user", tokens.info), ("warn-user", tokens.warn), ("builtin", tokens.success)]
            .into_iter()
            .map(|(token, color)| (token, styled(token, color, support)))
            .collect();

    for line in table.split_inclusive('\n') {
        let mut rendered_line = line.to_owned();
        for (token, replacement) in &styled_tokens {
            rendered_line = replace_word_bounded(&rendered_line, token, replacement);
        }
        out.push_str(&rendered_line);
    }
    out
}

/// Replace `needle` with `replacement` only where `needle` is
/// surrounded by ASCII whitespace or start/end of string. Prevents
/// substring collisions with scope identifiers that happen to equal
/// a trust-tier token.
fn replace_word_bounded(haystack: &str, needle: &str, replacement: &str) -> String {
    let bytes = haystack.as_bytes();
    let needle_bytes = needle.as_bytes();
    let mut out = String::with_capacity(haystack.len());
    let mut i = 0;
    while i < bytes.len() {
        if i + needle_bytes.len() <= bytes.len()
            && &bytes[i..i + needle_bytes.len()] == needle_bytes
        {
            let left_ok = i == 0 || bytes[i - 1].is_ascii_whitespace();
            let right_ok = i + needle_bytes.len() == bytes.len()
                || bytes[i + needle_bytes.len()].is_ascii_whitespace();
            if left_ok && right_ok {
                out.push_str(replacement);
                i += needle_bytes.len();
                continue;
            }
        }
        // Advance by one byte; `haystack` is UTF-8 but the needles
        // are all ASCII so byte indexing is safe for the literal
        // match, and for the non-match path we copy the byte as-is
        // — but we must push char-aligned data. Copy the next
        // full char to avoid splitting multi-byte chars.
        let ch_len = haystack[i..].chars().next().map(char::len_utf8).unwrap_or(1);
        out.push_str(&haystack[i..i + ch_len]);
        i += ch_len;
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn mk_json(entries: &[(&str, &str, &str, &[&str], &str)]) -> Vec<serde_json::Value> {
        entries
            .iter()
            .map(|(name, version, tier, scopes, hash)| {
                serde_json::json!({
                    "name": name,
                    "version": version,
                    "trust_tier": tier,
                    "scopes": scopes,
                    "source_sha256_hex": hash,
                })
            })
            .collect()
    }

    /// Extract the same logic the live CLI uses: build table cells
    /// from the JSON connector array + render.
    fn render_table_for_test(
        connectors: &[serde_json::Value],
        theme: &Theme,
        support: ColorSupport,
        layout: TableLayout,
    ) -> String {
        const SCOPE_COL_BUDGET: usize = 40;
        const HASH_CHARS: usize = 12;
        let rows: Vec<Vec<TableCell>> = connectors
            .iter()
            .map(|c| {
                let scopes_vec: Vec<String> = c["scopes"]
                    .as_array()
                    .map(|arr| arr.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect())
                    .unwrap_or_default();
                let scopes = truncate_field(&scopes_vec.join(", "), SCOPE_COL_BUDGET);
                let hash_full = c["source_sha256_hex"].as_str().unwrap_or("");
                let hash_short: String = hash_full.chars().take(HASH_CHARS).collect();
                vec![
                    TableCell::Plain(c["name"].as_str().unwrap_or("").to_owned()),
                    TableCell::Plain(c["version"].as_str().unwrap_or("").to_owned()),
                    TableCell::Plain(c["trust_tier"].as_str().unwrap_or("").to_owned()),
                    TableCell::Plain(scopes),
                    TableCell::Plain(hash_short),
                ]
            })
            .collect();
        let headers = &["CONNECTOR", "VERSION", "TRUST", "SCOPES", "HASH"];
        let table_str = table(headers, &rows, layout, theme, support).expect("table render");
        colorize_trust_labels(&table_str, theme, support)
    }

    #[test]
    fn empty_registry_renders_empty_state() {
        // AC #16: empty registry uses design-system empty_state
        // helper with the expected wording.
        let out = crate::design::render::empty_state(
            "no connectors registered",
            "install one with:  drop a plugin into ~/.agentsso/plugins/<name>/index.js",
        );
        assert!(out.contains("no connectors registered"));
        assert!(out.contains("drop a plugin"));
        assert!(out.contains('\u{25D6}'), "Scute glyph must appear");
    }

    #[test]
    fn list_renders_three_builtins() {
        // AC #16: populated table has header + 3 rows and names all
        // three built-in connectors.
        let connectors = mk_json(&[
            (
                "google-calendar",
                "0.0.1",
                "builtin",
                &["calendar.readonly"],
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            (
                "google-drive",
                "0.0.1",
                "builtin",
                &["drive.readonly"],
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ),
            (
                "google-gmail",
                "0.0.1",
                "builtin",
                &["gmail.readonly"],
                "cccccccccccccccccccccccccccccccc",
            ),
        ]);
        // Use a dummy home path — `Theme::load` tolerates missing
        // theme config and falls back to the default.
        let theme = Theme::load(std::path::Path::new("/nonexistent-home"));
        let rendered =
            render_table_for_test(&connectors, &theme, ColorSupport::NoColor, TableLayout::Wide);
        assert!(rendered.contains("CONNECTOR"));
        assert!(rendered.contains("google-calendar"));
        assert!(rendered.contains("google-drive"));
        assert!(rendered.contains("google-gmail"));
        // Exact row count: 1 header + 3 data rows, no trailing blank
        // inside `table`'s output (the caller `print!`s an extra
        // newline if needed).
        let non_empty = rendered.lines().filter(|l| !l.trim().is_empty()).count();
        assert_eq!(non_empty, 4, "expected header + 3 rows, got {non_empty}: <<<{rendered}>>>");
    }

    #[test]
    fn trust_column_colored_by_tier() {
        // AC #16: TRUST column applies semantic colors:
        // builtin → success (green), trusted-user → info (blue),
        // warn-user → warn (yellow).
        let connectors = mk_json(&[
            ("a", "1", "builtin", &[], "11111111111111111111111111111111"),
            ("b", "1", "trusted-user", &[], "22222222222222222222222222222222"),
            ("c", "1", "warn-user", &[], "33333333333333333333333333333333"),
        ]);
        let theme = Theme::load(std::path::Path::new("/nonexistent-home"));
        let rendered =
            render_table_for_test(&connectors, &theme, ColorSupport::TrueColor, TableLayout::Wide);
        // Every tier label should be wrapped with an ANSI escape;
        // the `\x1b[38;2;` prefix is the truecolor SGR opener.
        assert!(
            rendered.contains("\x1b[38;2;"),
            "expected ANSI escape for colored trust column: <<<{rendered}>>>"
        );
    }

    #[test]
    fn no_color_path_emits_plain_tier_labels() {
        let connectors = mk_json(&[("a", "1", "builtin", &[], "11111111111111111111111111111111")]);
        let theme = Theme::load(std::path::Path::new("/nonexistent-home"));
        let rendered =
            render_table_for_test(&connectors, &theme, ColorSupport::NoColor, TableLayout::Wide);
        assert!(!rendered.contains("\x1b["), "no-color path must not emit ANSI escapes");
        assert!(rendered.contains("builtin"));
    }
}
