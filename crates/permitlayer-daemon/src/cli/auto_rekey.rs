//! Story 7.22 Task 3.3 / Task 4: codesign-verified auto-recovery
//! vault rekey.
//!
//! Entry point for the macOS keychain-ACL-break recovery flow. Called
//! by `start.rs::handle_acl_break_recovery` after the codesign
//! Designated Requirement has been verified against the persisted
//! trust anchor.
//!
//! # What [`run`] does
//!
//! 1. Constructs a fresh keystore with `FallbackMode::None` and
//!    `AclBreakRecoveryMode::Disabled`. The recovery rotation MUST
//!    NOT engage the passphrase fallback (we're already past the
//!    boot-time -25308 detection and the operator has no TTY) and
//!    MUST NOT loop back into another `AclBreakNeedsRekey` sentinel
//!    if the new keystore call also fails (paranoid second-binary-
//!    swap protection).
//! 2. Invokes `run_rotation(home, keystore, started,
//!    RotationMode::AutoRecover)`. The rotation acquires its own
//!    VaultLock at Phase A; Phase E updates each agent's lookup-key
//!    via the `update_lookup_key_only` trait method (preserving
//!    bearer tokens); Phase E.5 writes nothing (no token-output
//!    file); Phase G re-captures the trust anchor and emits an audit
//!    event with `trigger: "acl-break-recovery"`.
//! 3. On success, returns the freshly-minted master key bytes for
//!    the daemon's boot path to thread into the rest of bootstrap.
//!    On failure, wraps the error in
//!    [`StartError::AutoRekeyFailed`] (exit code 7).

use std::path::Path;
use std::time::Instant;

use permitlayer_keystore::{AclBreakRecoveryMode, FallbackMode, KeystoreConfig, default_keystore};

use super::rotate_key::{RotationMode, run_rotation};
use super::start::StartError;

/// Story 7.22 Task 4 entry point: codesign-verified auto-recovery
/// rekey.
///
/// Caller (`start.rs::handle_acl_break_recovery`) has already:
/// - read the persisted trust anchor at
///   `<home>/keystore/codesign-trust-anchor.req`
/// - verified the running binary's Designated Requirement matches
///   via `permitlayer_keystore::verify_self_against`
///
/// Returns the new master key bytes on success. Wraps any rotation
/// error in [`StartError::AutoRekeyFailed`] so the daemon exits with
/// code 7 and a structured banner pointing operators at recovery.
pub(crate) async fn run(
    home: &Path,
) -> Result<zeroize::Zeroizing<[u8; permitlayer_keystore::MASTER_KEY_LEN]>, StartError> {
    tracing::info!(
        "auto-rekey path entered: codesign DR verified; constructing keystore for \
         RotationMode::AutoRecover"
    );

    // Construct a fresh keystore for the recovery rotation:
    // - `FallbackMode::None` so passphrase fallback NEVER engages
    //   (this is the boot path — there's no TTY).
    // - `AclBreakRecoveryMode::Disabled` so a second `-25308` from
    //   the new keystore call surfaces as a structured error
    //   instead of looping back into auto-recovery.
    let keystore_config = KeystoreConfig {
        fallback: FallbackMode::None,
        home: home.to_path_buf(),
        acl_break_recovery: AclBreakRecoveryMode::Disabled,
    };
    let keystore = default_keystore(&keystore_config).map_err(|source| {
        tracing::error!(
            error = %source,
            "auto-rekey: failed to construct keystore for AutoRecover rotation"
        );
        StartError::AutoRekeyFailed { phase: "pre-A".to_owned(), source: Box::new(source) }
    })?;

    let started = Instant::now();
    match run_rotation(home, keystore.as_ref(), started, RotationMode::AutoRecover).await {
        Ok(new_master_key) => {
            tracing::info!("auto-rekey: rotation complete; daemon boot resumes under new key");
            Ok(new_master_key)
        }
        Err(e) => {
            // run_rotation uses anyhow; wrap into the StartError
            // structured chain. The phase name is best-effort —
            // run_rotation's own audit emit + tracing already record
            // the precise phase. The exit-code-7 banner directs the
            // operator to retry boot (resume is idempotent via the
            // marker file).
            tracing::error!(
                error = %e,
                "auto-rekey: rotation failed; daemon refuses to boot"
            );
            Err(StartError::AutoRekeyFailed {
                phase: "rotation".to_owned(),
                source: Box::new(std::io::Error::other(format!(
                    "AutoRecover rotation failed: {e}"
                ))),
            })
        }
    }
}
