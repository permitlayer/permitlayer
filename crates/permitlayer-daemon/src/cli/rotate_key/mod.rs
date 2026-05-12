//! `agentsso rotate-key` — master-key rotation for Story 7.6b (FR17).
//!
//! Rotates the 32-byte master key that protects the vault, re-encrypts
//! every sealed credential under the new key, and re-issues every
//! agent's bearer token under the new master-derived subkey. The user
//! keeps every Google connection; no re-OAuth-consent is required.
//! Each agent's existing v1 token is invalidated and replaced with a
//! fresh `agt_v2_<name>_<random>` token printed to stdout for the
//! operator to copy into agent configs.
//!
//! See `_bmad-output/implementation-artifacts/7-6b-rotate-key-v2.md`
//! for the spec, the four strategic-question decisions (Q1–Q4), and
//! the cross-story fences inherited from Stories 1.2 / 1.3 / 1.15 /
//! 7.4 / 7.5 / 7.6a / 8.8b.
//!
//! # Atomicity sequence (Phases A–G)
//!
//! Reproduced here for the dev's eye-line; full table is in the spec's
//! Dev Notes "Crash-recovery state classification":
//!
//! - **A. VaultLock acquire.** `VaultLock::try_acquire(home)`. On
//!   `VaultLockError::Busy` refuse with `RotateKeyExitCode3` +
//!   structured holder info. The lock is held through Phase G.
//! - **B. Read keystore + probe.** Read the OLD primary master key.
//!   Read the rotation-state marker from `<home>/vault/.rotation-state`.
//!   If present → resume from `marker.keystore_phase` (the marker is
//!   the AUTHORITATIVE record of in-flight state — the keystore is
//!   inspected only to read-back-verify each step). If absent and
//!   `previous_master_key()` returns None → fresh rotation. If absent
//!   but previous-slot is populated → REFUSE: ambiguous state, escape
//!   hatch is `agentsso keystore-clear-previous`.
//! - **B'. Resume from marker.** Per-phase recovery:
//!   - `pre-previous` → re-run Phase C' from step 1.
//!   - `pre-primary` → REFUSE: NEW key bytes were lost in the crashed
//!     process and cannot be reconstructed. Operator clears the
//!     marker + previous slot to abandon the rotation.
//!   - `committed` → keystore is fully staged; proceed to Phase D.
//! - **C. Mint new key.** `MasterKey::generate()`; check
//!   `new_key_id = old_key_id.checked_add(1)`.
//! - **C'. Marker-staged dual-slot install.** Three sub-steps, each
//!   marker-fenced and read-back-verified:
//!   1. Write marker `pre-previous(old_kid, new_kid)` and fsync.
//!   2. `keystore.set_previous_master_key(OLD)` then read back and
//!      verify equality with OLD.
//!   3. Write marker `pre-primary` and fsync.
//!   4. `keystore.set_master_key(NEW)` then read back and verify
//!      equality with NEW (and previous still equals OLD).
//!   5. Write marker `committed` and fsync.
//!
//!   From step 5 until Phase F, every crash is recoverable.
//! - **D. Per-envelope reseal under VaultLock.** For each envelope:
//!   if at `new_key_id` already → skip (resume idempotent); if at
//!   `old_key_id` → reseal under NEW; else surface `RotateKeyExitCode5`.
//! - **E. Agent registry rebuild.** Per agent: recompute
//!   `lookup_key_hex` under the new daemon subkey, mint a fresh v2
//!   bearer token, atomic-rewrite the agent file. Idempotent: an
//!   already-rewritten agent (lookup_key matches new subkey) is
//!   skipped.
//! - **F. Clear previous-key slot.**
//!   `keystore.clear_previous_master_key()`. Rotation is now logically
//!   complete.
//! - **G. Audit + cleanup.** Drop the `VaultLock`; emit
//!   `master-key-rotated` audit event; print success line + new
//!   bearer tokens.

use std::path::Path;
use std::time::Instant;

use anyhow::Result;
use clap::Args;

use crate::cli::silent_cli_error;
use crate::design::render;
use crate::design::terminal::ColorSupport;
use permitlayer_keystore::{FallbackMode, KeyStoreKind, KeystoreConfig, default_keystore};

pub(crate) mod keystore_clear_previous;
pub(crate) mod marker;
mod rotation;

pub(crate) use rotation::run_rotation;

// ── Typed exit-code markers (AC #9) ────────────────────────────────
//
// Mirror Story 7.5's pattern (`UpdateExitCode3/4/5`): typed structs
// (not stringly-typed `.context("rotate_key_exit_code:N")`) so
// `main.rs::rotate_key_to_exit_code` can downcast the chain without
// colliding with operator-visible remediation text.

/// Exit-code 3 marker — resource conflict (daemon running, brew-
/// services managing agentsso, vault lock held by another process).
#[derive(Debug)]
pub(crate) struct RotateKeyExitCode3;

impl std::fmt::Display for RotateKeyExitCode3 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("rotate-key: resource conflict")
    }
}

impl std::error::Error for RotateKeyExitCode3 {}

/// Exit-code 4 marker — auth / keystore failure (passphrase adapter
/// rotation refused, set_master_key verify failure, RNG failure,
/// `key_id` overflow at 255).
#[derive(Debug)]
pub(crate) struct RotateKeyExitCode4;

impl std::fmt::Display for RotateKeyExitCode4 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("rotate-key: auth or keystore failure")
    }
}

impl std::error::Error for RotateKeyExitCode4 {}

/// Exit-code 5 marker — re-seal / agent-rebuild / unexpected envelope
/// `key_id` failure. Distinct from 4 so operators can triage "did the
/// keystore reject the swap?" vs "did the on-disk rotation fail
/// mid-flight?" — the latter is recoverable by re-running rotate-key
/// (the previous-slot stays populated through Phase F).
#[derive(Debug)]
pub(crate) struct RotateKeyExitCode5;

impl std::fmt::Display for RotateKeyExitCode5 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("rotate-key: rotation failure (re-run to resume)")
    }
}

impl std::error::Error for RotateKeyExitCode5 {}

pub(crate) fn exit3() -> anyhow::Error {
    anyhow::Error::new(RotateKeyExitCode3).context(crate::cli::SilentCliError)
}

pub(crate) fn exit4() -> anyhow::Error {
    anyhow::Error::new(RotateKeyExitCode4).context(crate::cli::SilentCliError)
}

pub(crate) fn exit5() -> anyhow::Error {
    anyhow::Error::new(RotateKeyExitCode5).context(crate::cli::SilentCliError)
}

// ── Glyph helpers (mirror cli::uninstall + cli::update) ────────────

pub(crate) struct StepGlyphs {
    pub arrow: &'static str,
    pub check: &'static str,
}

pub(crate) fn step_glyphs() -> StepGlyphs {
    match ColorSupport::detect() {
        ColorSupport::NoColor => StepGlyphs { arrow: "->", check: "[ok]" },
        _ => StepGlyphs {
            arrow: "\u{2192}", // →
            check: "\u{2713}", // ✓
        },
    }
}

// ── CLI args ───────────────────────────────────────────────────────

/// Arguments for `agentsso rotate-key`.
#[derive(Args, Debug, Default, Clone)]
pub struct RotateKeyArgs {
    /// Skip the interactive confirmation prompt. REQUIRED when
    /// invoked from a non-tty context (CI, scripts, pipes).
    #[arg(long)]
    pub yes: bool,

    /// Treat the call as non-interactive: implies `--yes` is required.
    /// Mirrors `cli::uninstall`'s and `cli::connect`'s posture.
    #[arg(long)]
    pub non_interactive: bool,
}

// ── Entry point ────────────────────────────────────────────────────

/// Run the `rotate-key` subcommand.
///
/// Pre-flights run BEFORE `init_tracing` so we don't pay the
/// tracing-subscriber setup cost (or risk creating ~/.agentsso/logs/
/// that uninstall would have to delete) when rotate-key is going to
/// refuse anyway. See `cli::start`'s P19/P23 review pattern.
pub async fn run(args: RotateKeyArgs) -> Result<()> {
    use anyhow::Context as _;

    // ── Pre-flight 1: brew-services double-bind detection (macOS) ──
    #[cfg(target_os = "macos")]
    if brew_services_managing_agentsso().await {
        eprint!(
            "{}",
            render::error_block(
                "rotate_key_managed_externally",
                "agentsso is managed by Homebrew (brew services); rotating the master \
                 key would desync brew's view of the daemon and may leave it pointing at \
                 stale credentials.",
                "brew services stop agentsso && agentsso rotate-key",
                None,
            )
        );
        return Err(exit3());
    }

    // ── Pre-flight 2: daemon-running guard (AC #5) ─────────────────
    let home = super::agentsso_home()?;
    let daemon_running = crate::lifecycle::pid::PidFile::is_daemon_running(&home)
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "PID-file probe failed; treating daemon as running for safety");
            true
        });
    if daemon_running {
        eprint!(
            "{}",
            render::error_block(
                "rotate_key_daemon_running",
                "agentsso daemon is running; rotate-key requires the daemon to be \
                 stopped to avoid in-memory key desync.",
                "agentsso stop && agentsso rotate-key",
                None,
            )
        );
        return Err(exit3());
    }

    // Now safe to init tracing.
    let _guards =
        crate::telemetry::init_tracing("info", None, 30).context("tracing init failed")?;

    // ── Pre-flight 3: tty / non-interactive guard (AC #7) ──────────
    let stdout_is_tty = console::Term::stdout().is_term();
    let interactive = !args.non_interactive && stdout_is_tty;
    if !args.yes && !interactive {
        eprint!(
            "{}",
            render::error_block(
                "rotate_key_requires_confirmation",
                "rotate-key is destructive (replaces the master key in your OS keychain) \
                 and requires interactive confirmation OR an explicit `--yes` flag.",
                "agentsso rotate-key --yes",
                None,
            )
        );
        return Err(silent_cli_error("non-interactive rotate-key without --yes"));
    }

    // ── Pre-flight 4: keystore-adapter detection (AC #6) ───────────
    //
    // Story 7.6b round-1 review re-triage (2026-04-28): when the
    // env var `AGENTSSO_TEST_KEYSTORE_FILE_BACKED=1` is set,
    // construct a `FileBackedKeyStore` instead of the OS keychain.
    // Used exclusively by the rotate-key integration tests
    // (`rotate_key_e2e.rs`, `rotate_key_crash_resume_e2e.rs`) so
    // they can exercise the full Phase A→G flow without touching
    // the test runner's real keychain AND so a subprocess crash
    // mid-rotation leaves recoverable state on disk.
    //
    // Story 7.6b round-2 re-triage: the seam is gated by the
    // `test-seam` Cargo feature (NOT `cfg(debug_assertions)`). The
    // feature is enabled by `cargo test`'s integration target via
    // `required-features = ["test-seam"]`; it is OFF for `cargo
    // build`, `cargo build --release`, and `cargo install`. Pre-
    // round-2 the seam was gated by `cfg(debug_assertions)` —
    // which exposed casual-`cargo build` users to leaked-shell-var
    // bypasses of the real keychain. The feature flag makes the
    // boundary an explicit Cargo metadata fact.
    #[cfg(feature = "test-seam")]
    let test_file_keystore: Option<Box<dyn permitlayer_keystore::KeyStore>> =
        if std::env::var("AGENTSSO_TEST_KEYSTORE_FILE_BACKED").is_ok() {
            tracing::warn!(
                "AGENTSSO_TEST_KEYSTORE_FILE_BACKED is set — using file-backed test keystore. \
                 This env var is only honored when agentsso is built with the `test-seam` \
                 Cargo feature, which production builds (`cargo install`) never enable."
            );
            match permitlayer_keystore::FileBackedKeyStore::new(&home) {
                Ok(ks) => Some(Box::new(ks)),
                Err(e) => {
                    eprint!(
                        "{}",
                        render::error_block(
                            "rotate_key_test_keystore_init_failed",
                            &format!("test file-backed keystore init failed: {e}"),
                            "ensure ~/.agentsso is writable",
                            None,
                        )
                    );
                    return Err(exit4());
                }
            }
        } else {
            None
        };
    #[cfg(not(feature = "test-seam"))]
    let test_file_keystore: Option<Box<dyn permitlayer_keystore::KeyStore>> = None;

    // rc.12: rotate-key uses FallbackMode::None instead of Auto. The
    // Auto path now wraps the native keystore in a lazy
    // `FallbackKeyStore` that engages passphrase fallback on a runtime
    // `BackendUnavailable`. For rotate-key that's actively dangerous —
    // a fallback engaging mid-rotation (e.g., during
    // `set_previous_master_key` after the orchestrator has already
    // written `.rotation-state`) would route to a passphrase keystore
    // that returns `PassphraseAdapterImmutable`, leaving the marker
    // on disk in a phase the operator has to clean up by hand.
    //
    // rotate-key is interactive and SHOULD fail loudly if the native
    // keychain isn't accessible. None gives us that: native errors
    // propagate to the operator banner directly. The
    // `kind() == Passphrase` gate below still applies for users who
    // explicitly configured `[keystore].fallback = "passphrase"`.
    let keystore_config = KeystoreConfig { fallback: FallbackMode::None, home: home.clone() };
    let keystore = if let Some(test_ks) = test_file_keystore {
        test_ks
    } else {
        match default_keystore(&keystore_config) {
            Ok(ks) => ks,
            Err(e) => {
                eprint!(
                    "{}",
                    render::error_block(
                        "rotate_key_keystore_unavailable",
                        &format!("keystore initialization failed: {e}"),
                        "verify your OS keychain is available; on Linux this typically \
                         requires libsecret + a running secret-storage daemon (gnome-keyring \
                         / kwallet)",
                        None,
                    )
                );
                return Err(exit4());
            }
        }
    };
    if keystore.kind() == KeyStoreKind::Passphrase {
        eprint!(
            "{}",
            render::error_block(
                "rotate_key_passphrase_adapter",
                "the passphrase keystore rotates by changing the passphrase, not by \
                 minting a new master key. A dedicated `agentsso change-passphrase` \
                 command will be added in a future story; for now, the passphrase-mode \
                 rotation path is unavailable.",
                "(future) agentsso change-passphrase — not yet implemented",
                None,
            )
        );
        return Err(exit4());
    }

    // ── Confirm prompt (AC #7) ─────────────────────────────────────
    if !args.yes {
        let manifest = build_prompt_manifest(&home);
        println!("{manifest}");

        let join = tokio::task::spawn_blocking(|| {
            dialoguer::Confirm::new().with_prompt("Continue?").default(false).interact()
        })
        .await
        .map_err(|e| anyhow::anyhow!("rotate-key confirm join failed: {e}"))?;
        // `dialoguer::Error` (Ctrl-C, stdin closed) → treat as cancel.
        let confirmed: bool = join.unwrap_or_default();
        if !confirmed {
            println!("rotate-key cancelled");
            return Ok(());
        }
    }

    // ── Run the rotation ───────────────────────────────────────────
    let started = Instant::now();
    // The returned new master key is unused — the daemon is stopped
    // during rotate-key by precondition.
    run_rotation(&home, keystore.as_ref(), started).await?;
    Ok(())
}

/// Build the manifest block printed before the confirmation prompt
/// (mirrors Story 7.4 `build_prompt_manifest`). Story 7.6b updates
/// the agent bullet from Q4-B (invalidate) to Q4-A (preserve agents,
/// re-issue tokens).
fn build_prompt_manifest(home: &Path) -> String {
    let vault_dir = home.join("vault");
    let mut s = String::new();
    s.push_str("This will rotate the agentsso master encryption key:\n\n");
    s.push_str(&format!(
        "  • Mint a fresh 32-byte master key from your OS RNG\n  \
         • Re-encrypt every credential in {} under the new key\n  \
         • Replace the old master key in your OS keychain (idempotent overwrite)\n  \
         • Rebuild every agent's HMAC lookup key under the new master-derived subkey \
         AND issue a fresh agt_v2_* bearer token for each agent (operator must update \
         agent configs with the printed tokens — old tokens are invalidated)\n\n",
        vault_dir.display()
    ));
    s.push_str("Existing OAuth refresh tokens are preserved.\n\n");
    s.push_str(
        "If the rotation is interrupted, re-run `agentsso rotate-key` to finish; \
         the keystore stages both keys atomically before any vault write begins, so \
         every crash mode is recoverable.\n",
    );
    s
}

/// macOS-only: probe whether `brew services` is currently managing
/// agentsso. Mirrors `cli::uninstall::brew_services_managing_agentsso`
/// and `cli::update::brew_services_managing_agentsso`.
///
/// **AC #10 fence:** this is the third in-tree caller of the same
/// shell-out. The cli::common refactor that consolidates these three
/// is intentionally deferred per Story 7.6 spec (decision gate AC #10);
/// see deferred-work.md "Cross-story coordination notes from Story 7.6"
/// for the future cleanup ticket.
#[cfg(target_os = "macos")]
async fn brew_services_managing_agentsso() -> bool {
    use std::time::Duration;

    let cmd = tokio::process::Command::new("brew")
        .args(["services", "list", "--json"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output();

    let output = match tokio::time::timeout(Duration::from_secs(30), cmd).await {
        Ok(Ok(o)) => o,
        Ok(Err(_)) => return false, // brew not on PATH — proceed.
        Err(_) => return false,     // brew hung past 30s — proceed.
    };
    if !output.status.success() {
        return false;
    }
    crate::lifecycle::autostart::macos::parse_brew_services_active(&output.stdout)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn build_prompt_manifest_mentions_token_re_issuance() {
        // Story 7.6b: the manifest must call out that operators
        // need to update agent configs with the printed v2 tokens.
        let home = std::path::PathBuf::from("/tmp/test-home");
        let manifest = build_prompt_manifest(&home);
        assert!(manifest.contains("agt_v2_"), "manifest must mention v2 token format");
        assert!(
            manifest.contains("operator must update"),
            "manifest must instruct operator to update configs"
        );
        assert!(
            manifest.contains("OAuth refresh tokens are preserved"),
            "manifest must reassure that OAuth survives"
        );
    }
}
