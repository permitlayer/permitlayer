//! `agentsso keystore-clear-previous` — operator escape hatch for
//! abandoning an in-flight rotation that crashed before Phase D.
//!
//! Story 7.6b round-2 review surfaced that production-facing error
//! banners reference this subcommand (`rotate_key_lost_new_key` and
//! `rotate_key_ambiguous_keystore_state`), but it didn't actually
//! exist. Operators following the remediation hit "unknown
//! subcommand" — a hard documentation/code mismatch.
//!
//! # When to use this
//!
//! `rotate-key` crashed at phase `pre-previous` or `pre-primary`.
//! The new key bytes existed only in the crashed process's RAM and
//! cannot be reconstructed; the rotation cannot resume. The
//! operator needs to abandon the attempt and start fresh:
//!
//! 1. The keystore's `previous` slot is populated (Phase C' wrote
//!    it as part of the in-flight rotation).
//! 2. The marker file at `<home>/vault/.rotation-state` records
//!    that an attempt was in flight.
//!
//! `keystore-clear-previous` clears BOTH of those, leaving the
//! keystore primary slot intact (still holds the OLD key, since the
//! crash happened before the primary swap was confirmed). After
//! this command, the operator can re-run `agentsso rotate-key` from
//! a fresh-rotation posture.
//!
//! # When NOT to use this
//!
//! - The rotation crashed at phase `committed` (Phase D / E / F):
//!   in this case `agentsso rotate-key` resumes idempotently. Do
//!   NOT clear-previous; the previous slot is REQUIRED to decrypt
//!   in-flight envelopes that have not yet been resealed.
//! - The vault contains envelopes at multiple `key_id` values: the
//!   resume path needs both keys.
//!
//! This subcommand REFUSES if the marker phase is `committed` to
//! prevent operator footgun.

use anyhow::Result;
use clap::Args;
use permitlayer_keystore::{FallbackMode, KeystoreConfig, default_keystore};

use crate::cli::silent_cli_error;
use crate::design::render;

use super::marker::{self, KeystorePhase};
use super::{exit3, exit4};

/// Arguments for `agentsso keystore-clear-previous`.
#[derive(Args, Debug, Default, Clone)]
pub struct KeystoreClearPreviousArgs {
    /// Skip the interactive confirmation prompt. REQUIRED when
    /// invoked from a non-tty context (CI, scripts, pipes).
    /// Mirrors the rotate-key / uninstall posture.
    #[arg(long)]
    pub yes: bool,

    /// Treat the call as non-interactive: implies `--yes` is required.
    #[arg(long)]
    pub non_interactive: bool,
}

pub async fn run(args: KeystoreClearPreviousArgs) -> Result<()> {
    use anyhow::Context as _;

    // ── Pre-flight 1: daemon-running guard ────────────────────────
    //
    // Same posture as rotate-key: the daemon caches the daemon-
    // subkey derived from the master key, and clearing the previous
    // slot while the daemon is running could leave the cache stale
    // mid-flight. Refuse cleanly.
    let home = super::super::agentsso_home()?;
    let daemon_running =
        crate::lifecycle::pid::PidFile::is_daemon_running(&home).unwrap_or_else(|e| {
            tracing::warn!(error = %e, "PID-file probe failed; treating daemon as running for safety");
            true
        });
    if daemon_running {
        eprint!(
            "{}",
            render::error_block(
                "keystore_clear_previous_daemon_running",
                "agentsso daemon is running; keystore-clear-previous requires the daemon \
                 to be stopped to avoid in-memory key desync.",
                "agentsso stop && agentsso keystore-clear-previous",
                None,
            )
        );
        return Err(exit3());
    }

    // ── Pre-flight 2: tty / non-interactive guard ─────────────────
    let stdout_is_tty = console::Term::stdout().is_term();
    let interactive = !args.non_interactive && stdout_is_tty;
    if !args.yes && !interactive {
        eprint!(
            "{}",
            render::error_block(
                "keystore_clear_previous_requires_confirmation",
                "keystore-clear-previous abandons an in-flight master-key rotation. \
                 It is destructive (you cannot resume the rotation after this) and \
                 requires interactive confirmation OR an explicit `--yes` flag.",
                "agentsso keystore-clear-previous --yes",
                None,
            )
        );
        return Err(silent_cli_error("non-interactive keystore-clear-previous without --yes"));
    }

    // ── Pre-flight 3: VaultLock ───────────────────────────────────
    //
    // Hold the lock so a concurrent rotate-key (somehow) cannot
    // race against our clear. The lock is released on drop at the
    // end of `run`.
    let _vault_lock = match permitlayer_core::VaultLock::try_acquire(&home) {
        Ok(lock) => lock,
        Err(permitlayer_core::VaultLockError::Busy { holder_pid, holder_command }) => {
            let holder_text = match (holder_pid, holder_command.as_deref()) {
                (Some(pid), Some(cmd)) => format!("pid {pid} ({cmd})"),
                (Some(pid), None) => format!("pid {pid}"),
                (None, Some(cmd)) => cmd.to_owned(),
                (None, None) => "another process".to_owned(),
            };
            eprint!(
                "{}",
                render::error_block(
                    "keystore_clear_previous_vault_busy",
                    &format!(
                        "vault lock at ~/.agentsso/.vault.lock is held by {holder_text}; \
                         keystore-clear-previous cannot proceed while another process is \
                         writing the vault."
                    ),
                    "wait for the other process to finish, or remove ~/.agentsso/.vault.lock if stale",
                    None,
                )
            );
            return Err(exit3());
        }
        Err(other) => {
            tracing::error!(error = %other, "vault lock acquisition failed");
            return Err(silent_cli_error(format!("vault lock: {other}")));
        }
    };

    // ── Inspect the marker ────────────────────────────────────────
    let marker_state = marker::read(&home)
        .context("failed to read rotation-state marker (corrupt? remove it manually)")?;

    // ── Footgun guard: refuse on marker=committed ─────────────────
    if let Some(ref m) = marker_state
        && m.keystore_phase == KeystorePhase::Committed
    {
        eprint!(
            "{}",
            render::error_block(
                "keystore_clear_previous_committed",
                "the rotation-state marker reports keystore_phase=`committed`. The previous \
                 slot is REQUIRED to decrypt vault entries that have not yet been resealed; \
                 clearing it now would be destructive. Re-run `agentsso rotate-key` to \
                 finish the rotation idempotently — Phase D / E / F will skip already- \
                 completed work and converge on the new master key.",
                "agentsso rotate-key --yes",
                None,
            )
        );
        return Err(exit4());
    }

    // ── Build keystore + clear previous slot + delete marker ──────
    let keystore_config = KeystoreConfig { fallback: FallbackMode::Auto, home: home.clone() };
    let keystore = default_keystore(&keystore_config).map_err(|e| {
        eprint!(
            "{}",
            render::error_block(
                "keystore_clear_previous_keystore_unavailable",
                &format!("keystore initialization failed: {e}"),
                "verify your OS keychain is responsive (try `agentsso status`)",
                None,
            )
        );
        exit4()
    })?;

    // ── Confirm prompt ────────────────────────────────────────────
    if !args.yes {
        let manifest = build_prompt_manifest(&home, marker_state.as_ref());
        println!("{manifest}");

        let join = tokio::task::spawn_blocking(|| {
            dialoguer::Confirm::new().with_prompt("Continue?").default(false).interact()
        })
        .await
        .map_err(|e| anyhow::anyhow!("keystore-clear-previous confirm join failed: {e}"))?;
        let confirmed: bool = join.unwrap_or_default();
        if !confirmed {
            println!("keystore-clear-previous cancelled");
            return Ok(());
        }
    }

    // ── Clear the previous slot (idempotent) ──────────────────────
    keystore.clear_previous_master_key().await.map_err(|e| {
        eprint!(
            "{}",
            render::error_block(
                "keystore_clear_previous_clear_failed",
                &format!("could not clear keystore previous slot: {e}"),
                "verify your OS keychain is responsive; on Linux check libsecret/gnome-keyring",
                None,
            )
        );
        exit4()
    })?;
    println!("✓ keystore previous slot cleared");

    // ── Delete the marker (idempotent) ────────────────────────────
    if let Err(e) = marker::finalize(&home) {
        // Best-effort: a marker-delete failure is logged but doesn't
        // fail the command. The previous slot IS cleared, which is
        // the operationally important step. The operator can `rm`
        // the marker by hand.
        tracing::warn!(error = %e, "could not delete rotation-state marker (operator may rm manually)");
        eprintln!(
            "warning: could not delete ~/.agentsso/vault/.rotation-state ({e}); \
             remove it manually before re-running rotate-key"
        );
    } else {
        println!("✓ rotation-state marker removed");
    }

    println!();
    println!(
        "Keystore is now in a fresh-rotation posture. Re-run `agentsso rotate-key` to start over."
    );
    Ok(())
}

fn build_prompt_manifest(
    home: &std::path::Path,
    marker: Option<&marker::RotationStateMarker>,
) -> String {
    let mut s = String::new();
    s.push_str("This will abandon any in-flight master-key rotation:\n\n");
    s.push_str(&format!(
        "  • Clear the keystore's `previous` master-key slot\n  \
         • Delete the rotation-state marker at {}/vault/.rotation-state\n\n",
        home.display()
    ));
    if let Some(m) = marker {
        s.push_str(&format!(
            "Current marker state:\n  \
             keystore_phase = {:?}\n  \
             old_kid        = {}\n  \
             new_kid        = {}\n  \
             pid            = {}\n  \
             started_at     = {}\n\n",
            m.keystore_phase, m.old_kid, m.new_kid, m.pid, m.started_at
        ));
    } else {
        s.push_str("No rotation-state marker on disk.\n\n");
    }
    s.push_str(
        "After this, the keystore primary slot still holds your CURRENT master key. \
         Vault contents are unaffected. Re-run `agentsso rotate-key` to mint a fresh \
         master key from a clean state.\n",
    );
    s
}
