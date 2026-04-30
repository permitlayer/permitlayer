//! Phase A→G single-pass forward rotation for `agentsso rotate-key`.
//!
//! Story 7.6b — full rewrite on top of:
//! - `permitlayer_core::vault::lock::VaultLock` (7.6a primitive),
//! - `permitlayer_credential::SealedCredential.key_id` (envelope v2,
//!   7.6a),
//! - `permitlayer_keystore::KeyStore::set_previous_master_key` /
//!   `set_master_key` / `previous_master_key` / `clear_previous_master_key`
//!   (split single-slot primitives, 7.6b AC #17 round-1 review),
//! - `cli::rotate_key::marker` (rotation-state marker file written
//!   atomically between every keystore step so resume reads
//!   authoritative state instead of guessing from the vault).
//!
//! See `_bmad-output/implementation-artifacts/7-6b-rotate-key-v2.md` for
//! the recoverability table mapping every crash window to a recovery
//! path.

use std::path::Path;
use std::time::Instant;

use anyhow::Result;
use permitlayer_core::agent::{
    LOOKUP_KEY_BYTES, base64_url_no_pad_encode, compute_lookup_key, generate_bearer_token_bytes,
    hash_token, lookup_key_from_hex, lookup_key_to_hex,
};
use permitlayer_core::store::fs::{AgentIdentityFsStore, CredentialFsStore};
use permitlayer_core::store::{AgentIdentityStore, CredentialStore};
use permitlayer_keystore::KeyStore;
use permitlayer_vault::{MasterKey, Vault, reseal};
use zeroize::Zeroizing;

use super::marker::{self, KeystorePhase, RotationStateMarker};
use super::{exit3, exit4, exit5, step_glyphs};

/// Crash-injection seam: the boundary at which the rotation aborts
/// when the env var `AGENTSSO_TEST_ROTATE_CRASH_AT_PHASE` is set to
/// the matching value. Story 7.6b AC #15.
///
/// Story 7.6b round-2 re-triage: gated by the `test-seam` Cargo
/// feature (NOT `cfg(debug_assertions)`). The feature is enabled by
/// `cargo test`'s integration target via `required-features =
/// ["test-seam"]`; OFF for `cargo build` / `cargo build --release`
/// / `cargo install`. Pre-round-2 a casual `cargo build` shipped
/// the seam enabled — the feature flag closes that footgun by
/// making the seam-vs-production boundary an explicit Cargo
/// metadata fact rather than a build-profile inference.
#[cfg(feature = "test-seam")]
fn maybe_inject_crash(phase: &str) {
    if let Ok(target) = std::env::var("AGENTSSO_TEST_ROTATE_CRASH_AT_PHASE")
        && target == phase
    {
        eprintln!("rotate-key: injected crash at phase {phase} (test-seam-only)");
        std::process::exit(99);
    }
}

#[cfg(not(feature = "test-seam"))]
#[inline(always)]
fn maybe_inject_crash(_phase: &str) {}

/// Run the Phase A→G rotation. Caller has already verified daemon is
/// stopped, brew-services not managing, keystore is native, and the
/// confirmation prompt passed (or `--yes`).
pub(crate) async fn run_rotation(
    home: &Path,
    keystore: &dyn KeyStore,
    started: Instant,
) -> Result<()> {
    let g = step_glyphs();
    let vault_dir = home.join("vault");
    let store = CredentialFsStore::new(home.to_path_buf())
        .map_err(|e| anyhow::anyhow!("failed to construct credential store: {e}"))?;
    let agent_store = match AgentIdentityFsStore::new(home.to_path_buf()) {
        Ok(s) => s,
        Err(e) => {
            // Story 7.6b round-1 review: emit the audit event before
            // returning. Q4 says "every `?` exit." No on-disk state
            // changed yet — partial_state is `clean`.
            emit_master_key_rotation_failed_audit(
                home,
                "A",
                &format!("agent_store init failed: {e}"),
                "clean",
            )
            .await;
            eprint!(
                "{}",
                crate::design::render::error_block(
                    "rotate_key_agent_store_init_failed",
                    &format!("could not initialize agent identity store: {e}"),
                    "check ~/.agentsso/agents/ permissions",
                    None,
                )
            );
            return Err(exit5());
        }
    };

    // ── Phase A: acquire VaultLock for the full rotation ───────────
    let vault_lock = match permitlayer_core::VaultLock::try_acquire(home) {
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
                crate::design::render::error_block(
                    "rotate_key_vault_busy",
                    &format!(
                        "vault lock at ~/.agentsso/.vault.lock is held by {holder_text}; \
                         rotation cannot start while another process is writing the vault."
                    ),
                    "wait for the other process to finish, or remove ~/.agentsso/.vault.lock if stale",
                    None,
                )
            );
            return Err(exit3());
        }
        Err(permitlayer_core::VaultLockError::Io(source)) => {
            tracing::error!(error = %source, "vault lock I/O failure during rotate-key Phase A");
            emit_master_key_rotation_failed_audit(
                home,
                "A",
                &format!("vault lock io: {source}"),
                "clean",
            )
            .await;
            return Err(exit5());
        }
        Err(other) => {
            tracing::error!(error = %other, "vault lock unknown error during rotate-key Phase A");
            emit_master_key_rotation_failed_audit(
                home,
                "A",
                &format!("vault lock: {other}"),
                "clean",
            )
            .await;
            return Err(exit5());
        }
    };

    // Story 7.6b round-1 review: with VaultLock held, sweep any
    // `*.sealed.tmp.*` orphans left by previous Phase D crashes.
    // `atomic_write_bytes` only removes its own tempfile on rename
    // failure; a process-kill between rename-attempt and
    // rename-success leaves the tempfile on disk indefinitely. They
    // accumulate over time and confuse manual vault inspection.
    sweep_sealed_tmp_orphans(&vault_dir);

    // Story 7.6b round-2 review: detect stale
    // `<home>/rotate-key-output.<pid>` files from prior runs and
    // SURFACE them to the operator — but do NOT auto-delete.
    // Auto-delete is dangerous: an operator who hasn't yet
    // consumed the prior run's tokens would lose them silently.
    // The next rotation will invalidate those tokens anyway, so
    // we emit a stderr banner naming each orphan path AND its
    // mtime, then proceed. This makes the orphan-accumulation
    // visible without risking the operator's recovery path.
    warn_about_rotate_key_output_orphans(home);

    // ── Phase B: read marker + keystore + probe previous slot ──────
    //
    // Story 7.6b round-1 review (Decision 1+2 resolution): the
    // rotation-state marker file is the AUTHORITATIVE record of
    // in-flight rotation. We read it first; if present, we resume
    // from its recorded `keystore_phase` regardless of what the
    // keystore looks like. If absent, we fall back to keystore-state
    // detection (and refuse if keystore is inconsistent — see below).
    let existing_marker = match marker::read(home) {
        Ok(opt) => opt,
        Err(e) => {
            tracing::error!(error = %e, "marker read failed during Phase B");
            emit_master_key_rotation_failed_audit(
                home,
                "B",
                &format!("rotation-state marker read failed: {e}"),
                "clean",
            )
            .await;
            eprint!(
                "{}",
                crate::design::render::error_block(
                    "rotate_key_marker_read_failed",
                    &format!("could not read rotation-state marker: {e}"),
                    "inspect ~/.agentsso/vault/.rotation-state for corruption; remove it to force a fresh rotation start",
                    None,
                )
            );
            return Err(exit5());
        }
    };

    let old_master_key = match keystore.master_key().await {
        Ok(k) => k,
        Err(e) => {
            emit_master_key_rotation_failed_audit(
                home,
                "B",
                &format!("keystore master_key read failed: {e}"),
                "clean",
            )
            .await;
            eprint!(
                "{}",
                crate::design::render::error_block(
                    "rotate_key_old_key_read_failed",
                    &format!("could not read existing master key: {e}"),
                    "verify your OS keychain is responsive (try `agentsso status`)",
                    None,
                )
            );
            return Err(exit4());
        }
    };

    let previous_slot = match keystore.previous_master_key().await {
        Ok(opt) => opt,
        Err(e) => {
            tracing::error!(error = %e, "previous_master_key read failed during Phase B");
            emit_master_key_rotation_failed_audit(
                home,
                "B",
                &format!("keystore previous_master_key read failed: {e}"),
                "clean",
            )
            .await;
            return Err(exit4());
        }
    };

    // Story 7.6b round-1 review: decide rotation routing using BOTH
    // the marker AND the keystore previous-slot. Three cases:
    //
    //   (a) marker absent + previous-slot None → fresh rotation.
    //   (b) marker present                     → resume from
    //                                             marker.keystore_phase.
    //   (c) marker absent + previous-slot Some → AMBIGUOUS. Either:
    //       - a pre-7.6b-marker rotation crashed, OR
    //       - someone manually wrote to the keystore.
    //       Refuse with a structured error and let the operator
    //       decide (they have `agentsso keystore-clear-previous` as
    //       an escape hatch — added later).
    let resolved = match (existing_marker, previous_slot) {
        (Some(marker), prev_opt) => {
            // Resume — marker is authoritative.
            tracing::info!(
                pid = marker.pid,
                started_at = %marker.started_at,
                keystore_phase = ?marker.keystore_phase,
                old_kid = marker.old_kid,
                new_kid = marker.new_kid,
                "rotate-key: resume from marker"
            );
            match resume_from_marker(home, keystore, &old_master_key, prev_opt, marker).await? {
                ResumeOutcome::Continue(tuple) => Some(tuple),
                ResumeOutcome::AlreadyComplete => None,
            }
        }
        (None, None) => {
            // Fresh rotation.
            let (old_bytes, new_bytes, old_kid, new_kid, marker) =
                begin_fresh_rotation(home, &vault_dir, keystore, old_master_key).await?;
            Some((old_bytes, new_bytes, old_kid, new_kid, marker))
        }
        (None, Some(_prev_bytes)) => {
            // Ambiguous: keystore says rotation is in flight, but
            // there's no marker. Refuse rather than guess.
            emit_master_key_rotation_failed_audit(
                home,
                "B",
                "keystore previous slot populated but no rotation-state marker present",
                "ambiguous-no-marker",
            )
            .await;
            eprint!(
                "{}",
                crate::design::render::error_block(
                    "rotate_key_ambiguous_keystore_state",
                    "the OS keychain holds a 'previous master key' slot but no rotation-state \
                         marker is present in ~/.agentsso/vault/. This means a pre-marker rotation \
                         was attempted, or the keystore was modified outside of agentsso.",
                    "verify the keychain previous-slot is what you expect, then run \
                         `agentsso keystore-clear-previous` to force-clear it before re-running rotate-key",
                    None,
                )
            );
            return Err(exit5());
        }
    };

    // Story 7.6b round-1 review re-triage: short-circuit when
    // `resume_from_marker` reports the rotation is already complete
    // (marker=`committed` + previous-slot empty — Phase F succeeded
    // but the marker delete crashed). Just delete the orphaned
    // marker and exit clean. We do NOT re-emit the
    // `master-key-rotated` audit event because the previous run
    // already emitted it (we'd be double-counting).
    let (old_key_bytes, new_key_bytes, old_key_id, new_key_id, active_marker) = match resolved {
        Some(t) => t,
        None => {
            // Story 7.6b round-2 review: emit a structured audit
            // event so a forensic reviewer can distinguish "operator
            // ran rotate-key twice and the second was a no-op
            // orphan-marker cleanup" from "rotate-key never ran at
            // all". We don't re-emit `master-key-rotated` (that was
            // emitted by the previous run that succeeded), but we
            // DO want a record of the cleanup itself.
            emit_master_key_rotation_orphan_cleanup_audit(home).await;
            if let Err(e) = marker::finalize(home) {
                tracing::warn!(
                    error = %e,
                    "rotate-key: orphan-marker finalize failed (rotation was already complete)"
                );
            }
            drop(vault_lock);
            println!(
                "rotate-key: previous rotation was already complete (orphan marker cleaned up)"
            );
            return Ok(());
        }
    };

    let old_keyid = MasterKey::fingerprint_bytes(&old_key_bytes);
    let new_keyid = MasterKey::fingerprint_bytes(&new_key_bytes);

    tracing::info!(
        old_keyid = %old_keyid,
        new_keyid = %new_keyid,
        old_key_id,
        new_key_id,
        "rotate-key: entering forward pass"
    );

    // Derive the new daemon subkey BEFORE moving new_key_bytes into
    // the new Vault — the bytes are consumed by Vault::new. Same
    // HKDF info string as `cli::start` so auth-time HMAC matches.
    let new_daemon_subkey = derive_agent_lookup_subkey(&new_key_bytes)?;

    // Build the old/new Vault wrappers used by `reseal`. From this
    // point until Phase F's clear, every crash is recoverable by
    // re-running rotate-key (the previous-slot stays populated).
    let old_vault = Vault::new(old_key_bytes, old_key_id);
    let new_vault = Vault::new(new_key_bytes, new_key_id);

    // ── Phase D: per-envelope reseal under VaultLock ───────────────
    //
    // Story 7.6b round-1 review: replaced the detached `tokio::spawn`
    // audit-emit with an awaited call so the audit event is durable
    // before we return Err. Q4 says "every `?` exit, from day one".
    let services = match store.list_services().await {
        Ok(s) => s,
        Err(e) => {
            emit_master_key_rotation_failed_audit(
                home,
                "D",
                &format!("list_services failed: {e}"),
                "both-keys-in-keystore",
            )
            .await;
            eprint!(
                "{}",
                crate::design::render::error_block(
                    "rotate_key_list_services_failed",
                    &format!("could not enumerate vault entries: {e}"),
                    "check ~/.agentsso/vault/ permissions; re-run `agentsso rotate-key`",
                    None,
                )
            );
            return Err(exit5());
        }
    };
    println!("{} re-encrypt vault  {} {} entries to consider", g.arrow, g.check, services.len());

    let mut vault_reseal_count: u32 = 0;
    for service in &services {
        let sealed_old = match store.get(service).await {
            Ok(Some(s)) => s,
            Ok(None) => {
                tracing::warn!(service, "vault entry vanished between list and get; skipping");
                continue;
            }
            Err(e) => {
                tracing::error!(service, error = %e, "Phase D read failed");
                emit_master_key_rotation_failed_audit(
                    home,
                    "D",
                    &format!("get('{service}') failed: {e}"),
                    "both-keys-in-keystore",
                )
                .await;
                return Err(exit5());
            }
        };
        let envelope_key_id = sealed_old.key_id();
        if envelope_key_id == new_key_id {
            // Already rewritten by a previous (crashed) attempt.
            continue;
        }
        if envelope_key_id != old_key_id {
            // Should not happen with monotonic key_id. Surface as a
            // structured failure so the operator investigates.
            tracing::error!(
                service,
                envelope_key_id,
                old_key_id,
                new_key_id,
                "Phase D: envelope at unexpected key_id (not old, not new)"
            );
            emit_master_key_rotation_failed_audit(
                home,
                "D",
                &format!(
                    "envelope '{service}' at unexpected key_id={envelope_key_id} \
                     (old={old_key_id}, new={new_key_id})"
                ),
                "vault-mixed",
            )
            .await;
            return Err(exit5());
        }
        let resealed = match reseal(&old_vault, &new_vault, &sealed_old, service) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(service, error = %e, "reseal failed during Phase D");
                emit_master_key_rotation_failed_audit(
                    home,
                    "D",
                    &format!("reseal('{service}') failed: {e}"),
                    "vault-mixed",
                )
                .await;
                return Err(exit5());
            }
        };
        // Write via the byte-level helper to avoid the store.put
        // re-acquire deadlock on VaultLock (7.6a discipline).
        let target = vault_dir.join(format!("{service}.sealed"));
        let bytes = permitlayer_core::store::fs::credential_fs::encode_envelope(&resealed);
        if let Err(e) =
            permitlayer_core::store::fs::credential_fs::atomic_write_bytes(&target, &bytes)
        {
            tracing::error!(service, error = %e, "Phase D write failed");
            emit_master_key_rotation_failed_audit(
                home,
                "D",
                &format!("atomic_write_bytes('{service}') failed: {e}"),
                "vault-mixed",
            )
            .await;
            return Err(exit5());
        }
        vault_reseal_count += 1;
    }
    maybe_inject_crash("D");

    // ── Phase E: agent registry rebuild ────────────────────────────
    //
    // Story 7.6b round-1 review: replaced detached audit-emit with
    // an awaited call (Q4 contract).
    let agents = match agent_store.list().await {
        Ok(a) => a,
        Err(e) => {
            emit_master_key_rotation_failed_audit(
                home,
                "E",
                &format!("agent_store.list failed: {e}"),
                "vault-uniform-keystore-both",
            )
            .await;
            eprint!(
                "{}",
                crate::design::render::error_block(
                    "rotate_key_agent_list_failed",
                    &format!("could not enumerate registered agents: {e}"),
                    "check ~/.agentsso/agents/ permissions; re-run `agentsso rotate-key`",
                    None,
                )
            );
            return Err(exit5());
        }
    };

    // For each agent: if its on-disk `lookup_key_hex` already
    // matches HMAC(new_subkey, name), it was rewritten by a previous
    // (crashed) attempt — skip. Otherwise rebuild.
    let mut new_tokens: Vec<(String, String)> = Vec::with_capacity(agents.len());
    let mut agents_rerolled_count: u32 = 0;
    for agent in agents {
        let recomputed = compute_lookup_key(&new_daemon_subkey, agent.name().as_bytes());
        let stored = lookup_key_from_hex(&agent.lookup_key_hex);
        if stored == Some(recomputed) {
            tracing::debug!(
                agent_name = %agent.name(),
                "Phase E: agent already rewritten (idempotent skip)"
            );
            continue;
        }
        // Mint a fresh v2 token for this agent.
        let random = generate_bearer_token_bytes();
        let new_token = format!("agt_v2_{}_{}", agent.name(), base64_url_no_pad_encode(&random));
        let new_token_hash = match hash_token(new_token.as_bytes()) {
            Ok(h) => h,
            Err(e) => {
                tracing::error!(
                    agent_name = %agent.name(),
                    error = %e,
                    "Phase E: hash_token failed"
                );
                emit_master_key_rotation_failed_audit(
                    home,
                    "E",
                    &format!("hash_token failed for agent '{}': {e}", agent.name()),
                    "agents-mid-rebuild",
                )
                .await;
                return Err(exit5());
            }
        };
        let new_lookup_hex = lookup_key_to_hex(&recomputed);
        match agent_store
            .update_lookup_key_and_token(agent.name(), new_lookup_hex, new_token_hash)
            .await
        {
            Ok(true) => {
                new_tokens.push((agent.name().to_owned(), new_token));
                agents_rerolled_count += 1;
            }
            Ok(false) => {
                tracing::warn!(
                    agent_name = %agent.name(),
                    "Phase E: agent vanished between list and update; skipping"
                );
            }
            Err(e) => {
                tracing::error!(
                    agent_name = %agent.name(),
                    error = %e,
                    "Phase E: agent rewrite failed"
                );
                emit_master_key_rotation_failed_audit(
                    home,
                    "E",
                    &format!("update_lookup_key_and_token('{}') failed: {e}", agent.name()),
                    "agents-mid-rebuild",
                )
                .await;
                return Err(exit5());
            }
        }
    }
    maybe_inject_crash("E");

    // ── Phase E.5: persist new tokens to disk BEFORE Phase F ───────
    //
    // Story 7.6b round-1 review: if Phase F fails, the operator has
    // already had agents re-rolled (Phase E succeeded) but the
    // process is about to exit Err — the in-memory `new_tokens` Vec
    // would be dropped without ever being printed. Re-running
    // rotate-key picks up the resume path, sees agents already at
    // the new lookup_key, and skips Phase E (idempotent). The
    // operator would be stranded with new agent records on disk but
    // no plaintext tokens.
    //
    // Fix: persist new tokens to `<home>/rotate-key-output.<pid>`
    // (mode 0o600) BEFORE Phase F. On success: print and delete the
    // file in Phase G. On Phase F failure: leave the file so the
    // operator can `cat` it after the retry succeeds.
    let tokens_path = if !new_tokens.is_empty() {
        let path = home.join(format!("rotate-key-output.{}", std::process::id()));
        if let Err(e) = write_tokens_file(&path, &new_tokens) {
            tracing::error!(
                path = %path.display(),
                error = %e,
                "failed to persist new agent tokens to disk; aborting rotation before Phase F"
            );
            emit_master_key_rotation_failed_audit(
                home,
                "E",
                &format!("write tokens file '{}' failed: {e}", path.display()),
                "agents-rerolled-tokens-not-persisted",
            )
            .await;
            return Err(exit5());
        }
        Some(path)
    } else {
        None
    };

    // ── Phase F: clear previous-key slot (finalize rotation) ───────
    if let Err(e) = keystore.clear_previous_master_key().await {
        // Phase F failure is rare (idempotent operation) but
        // recoverable — re-run rotate-key starts fresh because
        // previous-slot is still populated. The tokens file from
        // Phase E.5 stays on disk so the operator can recover the
        // new tokens regardless of how many retries it takes.
        tracing::error!(error = %e, "Phase F: clear_previous_master_key failed");
        if let Some(ref path) = tokens_path {
            eprintln!(
                "rotate-key: Phase F failed; new agent tokens are preserved at {} \
                 (mode 0600). Retry rotate-key to finalize.",
                path.display()
            );
        }
        emit_master_key_rotation_failed_audit(
            home,
            "F",
            &format!("clear_previous_master_key failed: {e}"),
            "vault-uniform-keystore-both",
        )
        .await;
        return Err(exit5());
    }
    println!("{} finalize rotation  {} previous-key slot cleared", g.arrow, g.check);
    maybe_inject_crash("F");

    // Phase F succeeded — rotation is committed. Delete the marker
    // so the next rotate-key invocation starts fresh.
    // `active_marker` was the marker handle returned by Phase B; we
    // don't reference it after Phase F because the on-disk file IS
    // the source of truth. Suppress the unused-binding lint cleanly.
    drop(active_marker);
    if let Err(e) = marker::finalize(home) {
        // Best-effort: a marker-delete failure does NOT roll the
        // rotation back (rotation succeeded). Log it; the marker
        // will be overwritten on the next attempt.
        tracing::warn!(error = %e, "rotate-key: marker delete failed (rotation already committed)");
    }

    // ── Phase G: audit + cleanup ───────────────────────────────────
    drop(vault_lock); // explicit RAII release
    let elapsed_ms = started.elapsed().as_millis() as u64;
    emit_master_key_rotated_audit(
        home,
        &old_keyid,
        &new_keyid,
        vault_reseal_count,
        agents_rerolled_count,
        elapsed_ms,
        tokens_path.as_deref(),
    )
    .await;

    println!();
    println!(
        "{} master key rotated  {} {} → {} ({} entries, {} agents rerolled, {}ms)",
        g.arrow,
        g.check,
        old_keyid,
        new_keyid,
        vault_reseal_count,
        agents_rerolled_count,
        elapsed_ms
    );

    // Story 7.6b round-1 review (re-triage 2026-04-28): plaintext
    // tokens are NEVER printed to stdout. Terminal scrollback,
    // multiplexer scrollback (tmux/screen/zellij), shell history,
    // process accounting, screen recording, screen sharing, CI log
    // capture, and operator-uploaded screenshots are all out of our
    // control. The mode-0o600 file written at Phase E.5 is the
    // ONLY plaintext-bearing surface; Phase G points the operator
    // at it and instructs them to read+remove it manually.
    if let Some(ref path) = tokens_path {
        println!();
        println!("New agent tokens written to:");
        println!("  {}", path.display());
        println!();
        println!("Read the file (mode 0600), update your agent configs, then `rm` it.");
        println!("The previous agt_v1_*/agt_v2_* tokens are now invalid.");
    }

    // The tokens file is intentionally LEFT on disk for the
    // operator. Removing it from rotate-key would (a) lose the
    // tokens if the operator's terminal closes before they update
    // agent configs and (b) require us to print plaintext tokens to
    // stdout to compensate, which is the very thing we just stopped
    // doing. The file is mode 0o600 and the operator removes it
    // manually after saving the tokens.

    println!();
    println!("  next: agentsso start    # bring the daemon back up");
    Ok(())
}

/// Story 7.6b round-1 review (Decision 1+2): begin a fresh rotation
/// — read the active key_id from the vault, mint a new master key,
/// and walk the keystore install one step at a time, advancing the
/// marker between each step and read-back-verifying after every
/// keystore write. Returns the resolved key bytes/IDs and the
/// committed marker.
///
/// Phase boundaries:
/// 1. Read `old_key_id` from vault, compute `new_key_id = old + 1`.
/// 2. Mint NEW key bytes (in RAM only).
/// 3. Write marker `pre-previous(old_kid, new_kid)` and fsync.
/// 4. `set_previous_master_key(OLD)` → read back, verify equality.
/// 5. Write marker `pre-primary` and fsync.
/// 6. `set_master_key(NEW)` → read back, verify equality.
///    Re-read previous slot, verify it still equals OLD.
/// 7. Write marker `committed` and fsync. Return.
async fn begin_fresh_rotation(
    home: &Path,
    vault_dir: &Path,
    keystore: &dyn KeyStore,
    old_master_key: Zeroizing<[u8; 32]>,
) -> Result<(Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>, u8, u8, RotationStateMarker)> {
    let g = step_glyphs();

    // 1. Compute key_ids.
    let old_kid = super::super::start::compute_active_key_id(vault_dir);
    let new_kid = match old_kid.checked_add(1) {
        Some(k) => k,
        None => {
            emit_master_key_rotation_failed_audit(
                home,
                "C",
                "key_id overflow at 255 — vault history exhausted",
                "clean",
            )
            .await;
            eprint!(
                "{}",
                crate::design::render::error_block(
                    "rotate_key_keyid_overflow",
                    "key_id space exhausted (active is 255); manual intervention required \
                     to truncate vault history before another rotation can succeed.",
                    "contact support — this should not happen in normal operation",
                    None,
                )
            );
            return Err(exit4());
        }
    };

    // 2. Mint NEW key bytes. Held only in this stack frame until
    //    we hand them off to the caller.
    let new_key = MasterKey::generate();
    let new_bytes: Zeroizing<[u8; 32]> = Zeroizing::new(*new_key.as_bytes());
    drop(new_key);

    // 3. Write marker at pre-previous, recording the OLD and NEW
    //    master-key fingerprints so the resume path can verify that
    //    the keystore matches what the marker claims (Story 7.6b
    //    round-2 review: closes a tampering-visibility gap on the
    //    `marker=committed + previous=None` short-circuit branch).
    //    From this point a crash is detectable on resume (marker on
    //    disk).
    let old_fp = MasterKey::fingerprint_bytes(&old_master_key);
    let new_fp = MasterKey::fingerprint_bytes(&new_bytes);
    let marker_pre_previous =
        match marker::begin(home, old_kid, new_kid, Some(old_fp), Some(new_fp)) {
            Ok(m) => m,
            Err(e) => {
                emit_master_key_rotation_failed_audit(
                    home,
                    "C",
                    &format!("marker begin failed: {e}"),
                    "clean",
                )
                .await;
                eprint!(
                    "{}",
                    crate::design::render::error_block(
                        "rotate_key_marker_write_failed",
                        &format!("could not write rotation-state marker: {e}"),
                        "check ~/.agentsso/vault/ permissions",
                        None,
                    )
                );
                return Err(exit5());
            }
        };
    maybe_inject_crash("C_pre_previous");

    // 4. Write previous slot, then read-back-verify.
    if let Err(e) = keystore.set_previous_master_key(&old_master_key).await {
        emit_master_key_rotation_failed_audit(
            home,
            "C_prime",
            &format!("set_previous_master_key failed: {e}"),
            "marker-pre-previous",
        )
        .await;
        eprint!(
            "{}",
            crate::design::render::error_block(
                "rotate_key_previous_slot_write_failed",
                &format!("could not write keystore previous slot: {e}"),
                "verify your OS keychain is responsive (try `agentsso status`)",
                None,
            )
        );
        return Err(exit4());
    }
    verify_previous_slot_matches(home, keystore, &old_master_key, "C_prime").await?;

    // 5. Advance marker to pre-primary.
    let marker_pre_primary =
        match marker::advance(home, &marker_pre_previous, KeystorePhase::PrePrimary) {
            Ok(m) => m,
            Err(e) => {
                emit_master_key_rotation_failed_audit(
                    home,
                    "C_prime",
                    &format!("marker advance to pre-primary failed: {e}"),
                    "marker-pre-previous",
                )
                .await;
                return Err(exit5());
            }
        };
    maybe_inject_crash("C_pre_primary");

    // 6. Write primary slot, then read-back-verify (and re-verify
    //    previous slot still equals OLD — primary write must not
    //    disturb the previous slot).
    if let Err(e) = keystore.set_master_key(&new_bytes).await {
        emit_master_key_rotation_failed_audit(
            home,
            "C_prime",
            &format!("set_master_key (primary) failed: {e}"),
            "marker-pre-primary",
        )
        .await;
        eprint!(
            "{}",
            crate::design::render::error_block(
                "rotate_key_primary_slot_write_failed",
                &format!("could not write keystore primary slot: {e}"),
                "verify your OS keychain is responsive (try `agentsso status`)",
                None,
            )
        );
        return Err(exit4());
    }
    verify_primary_matches(home, keystore, &new_bytes, "C_prime").await?;
    verify_previous_slot_matches(home, keystore, &old_master_key, "C_prime").await?;

    println!(
        "{} swap master key  {} keystore staged (NEW primary, OLD previous, both verified)",
        g.arrow, g.check
    );

    // 7. Mark Committed.
    let marker_committed =
        match marker::advance(home, &marker_pre_primary, KeystorePhase::Committed) {
            Ok(m) => m,
            Err(e) => {
                emit_master_key_rotation_failed_audit(
                    home,
                    "C_prime",
                    &format!("marker advance to committed failed: {e}"),
                    "marker-pre-primary",
                )
                .await;
                return Err(exit5());
            }
        };
    maybe_inject_crash("C_prime");

    Ok((old_master_key, new_bytes, old_kid, new_kid, marker_committed))
}

/// What `resume_from_marker` decided. Either we have everything
/// we need to continue Phase D/E/F, or the previous run was already
/// complete (marker=`committed` + previous-slot empty — Phase F
/// succeeded but the marker delete crashed) and we should just
/// clean up the orphan marker and exit.
enum ResumeOutcome {
    Continue((Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>, u8, u8, RotationStateMarker)),
    AlreadyComplete,
}

/// Story 7.6b round-1 review (Decision 1+2): resume from an existing
/// marker. The marker tells us where the previous attempt stopped;
/// we either replay the remaining keystore steps, recognize that the
/// rotation already succeeded (orphan marker), OR refuse-with-
/// instructions for the unrecoverable cases.
async fn resume_from_marker(
    home: &Path,
    keystore: &dyn KeyStore,
    primary_master_key: &Zeroizing<[u8; 32]>,
    previous_slot: Option<Zeroizing<[u8; 32]>>,
    marker: RotationStateMarker,
) -> Result<ResumeOutcome> {
    let g = step_glyphs();

    // Always emit the resume diagnostic with fingerprints so an
    // operator triaging a stuck rotation has the full picture
    // (Story 7.6b round-1 review: was integers-only).
    let primary_fp = MasterKey::fingerprint_bytes(primary_master_key);
    let previous_fp = previous_slot
        .as_ref()
        .map(|p| MasterKey::fingerprint_bytes(p))
        .unwrap_or_else(|| "<absent>".to_owned());
    tracing::info!(
        primary_fp = %primary_fp,
        previous_fp = %previous_fp,
        keystore_phase = ?marker.keystore_phase,
        old_kid = marker.old_kid,
        new_kid = marker.new_kid,
        marker_pid = marker.pid,
        marker_started_at = %marker.started_at,
        "rotate-key: resume diagnostics"
    );

    match marker.keystore_phase {
        KeystorePhase::Committed => {
            // Both slots committed. The primary IS the new key, the
            // previous slot IS the old key. Re-verify both slots
            // against the marker before proceeding to Phase D — this
            // catches the edge case where the keystore entries were
            // tampered with between the crashed run and this resume
            // (manual keychain edit, partial backup-restore, etc.).
            let prev = match previous_slot {
                Some(p) => p,
                None => {
                    // Marker=committed + previous-slot empty is a
                    // VALID terminal state: Phase F completed
                    // (cleared the previous slot) AND then the
                    // marker delete crashed before completing.
                    //
                    // Story 7.6b round-2 review: BEFORE
                    // short-circuiting, verify the keystore primary
                    // fingerprint matches what the marker claims as
                    // the NEW key. Closes the tampering-visibility
                    // gap — an attacker with marker-write access
                    // could otherwise plant a marker with
                    // `keystore_phase=committed` against an
                    // unrotated keystore, and we'd silently delete
                    // it without noticing the rotation never
                    // happened. Markers from pre-round-2 code have
                    // `new_keyid_fp = None`; we accept those
                    // unverified for backward compatibility (the
                    // pid + timestamp in the marker are still
                    // useful for incident triage even without the
                    // fingerprint verify).
                    if let Some(ref expected_new_fp) = marker.new_keyid_fp {
                        let actual_new_fp = MasterKey::fingerprint_bytes(primary_master_key);
                        if &actual_new_fp != expected_new_fp {
                            emit_master_key_rotation_failed_audit(
                                home,
                                "B",
                                &format!(
                                    "marker reports keystore_phase=committed with \
                                     new_keyid_fp={expected_new_fp}, but keystore \
                                     primary fingerprint is {actual_new_fp} — \
                                     marker may have been tampered with"
                                ),
                                "marker-keystore-fingerprint-mismatch",
                            )
                            .await;
                            eprint!(
                                "{}",
                                crate::design::render::error_block(
                                    "rotate_key_marker_fingerprint_mismatch",
                                    &format!(
                                        "rotation-state marker reports `committed` with \
                                         new_keyid_fp={expected_new_fp}, but the keystore \
                                         primary slot fingerprints to {actual_new_fp}. The \
                                         marker may have been tampered with, or the keystore \
                                         was modified outside of agentsso."
                                    ),
                                    "remove ~/.agentsso/vault/.rotation-state by hand and re-run rotate-key (the keystore primary slot is preserved; a fresh rotation will mint a new key on top of it)",
                                    None,
                                )
                            );
                            return Err(exit5());
                        }
                    }
                    // The rotation IS done; the marker is just an
                    // orphan. Tell the caller to delete it and exit
                    // clean. We do NOT re-emit the rotated audit
                    // event because the previous run already
                    // emitted it.
                    tracing::info!(
                        old_kid = marker.old_kid,
                        new_kid = marker.new_kid,
                        "rotate-key: orphan marker detected (rotation already complete) — \
                         will delete marker and exit clean"
                    );
                    return Ok(ResumeOutcome::AlreadyComplete);
                }
            };
            // Re-read primary AND previous through the keystore one
            // more time and confirm both fingerprints match what we
            // already have. The previous-slot match was effectively
            // verified by the `Some(p)` extraction above (the same
            // bytes we'd re-read here came through `previous_slot`),
            // but doing it explicitly via the verify helpers keeps
            // the audit trail symmetric across all three resume
            // phases and surfaces a clear `keystore-write-mismatch`
            // event if the keystore was tampered with.
            verify_primary_matches(home, keystore, primary_master_key, "B").await?;
            verify_previous_slot_matches(home, keystore, &prev, "B").await?;
            println!(
                "{} resume detected  {} marker=committed; keystore staged + verified",
                g.arrow, g.check
            );
            Ok(ResumeOutcome::Continue((
                prev,
                primary_master_key.clone(),
                marker.old_kid,
                marker.new_kid,
                marker,
            )))
        }

        KeystorePhase::PrePrevious => {
            // Marker written, no keystore writes confirmed. The new
            // key bytes were generated in the crashed process's RAM
            // and are LOST — we cannot synthesize them. Refuse with
            // the keystore-clear-previous escape hatch.
            //
            // NOTE: we do not auto-roll-back the previous slot here
            // because doing so would let a malicious actor with
            // marker-write access trick us into wiping the keystore.
            // Operator confirmation (via the explicit
            // keystore-clear-previous subcommand) is the right
            // boundary.
            emit_master_key_rotation_failed_audit(
                home,
                "B",
                "marker at pre-previous; new key bytes were lost in the crashed process",
                "lost-new-key-bytes",
            )
            .await;
            eprint!(
                "{}",
                crate::design::render::error_block(
                    "rotate_key_lost_new_key",
                    "rotation crashed before any keystore write was committed. The new key \
                     bytes existed only in the crashed process and cannot be recovered.",
                    "remove ~/.agentsso/vault/.rotation-state to abandon the in-flight rotation, then re-run rotate-key from scratch",
                    None,
                )
            );
            Err(exit5())
        }

        KeystorePhase::PrePrimary => {
            // Previous slot SHOULD hold OLD; primary SHOULD hold OLD
            // still (the swap to NEW didn't complete). The new key
            // bytes are lost. Same recovery shape as PrePrevious.
            emit_master_key_rotation_failed_audit(
                home,
                "B",
                "marker at pre-primary; new key bytes were lost in the crashed process",
                "lost-new-key-bytes",
            )
            .await;
            eprint!(
                "{}",
                crate::design::render::error_block(
                    "rotate_key_lost_new_key",
                    "rotation crashed after writing the previous-slot but before committing \
                     the primary slot. The new key bytes existed only in the crashed process \
                     and cannot be recovered.",
                    "run `agentsso keystore-clear-previous` to clear the previous-slot AND remove ~/.agentsso/vault/.rotation-state, then re-run rotate-key from scratch",
                    None,
                )
            );
            Err(exit5())
        }
    }
}

/// Read the previous slot and assert byte-equality against the
/// expected value. Used after every previous-slot write so a
/// silently-dropped or coalesced keychain write surfaces immediately.
async fn verify_previous_slot_matches(
    home: &Path,
    keystore: &dyn KeyStore,
    expected: &Zeroizing<[u8; 32]>,
    failure_phase: &str,
) -> Result<()> {
    use subtle::ConstantTimeEq;
    let read_back = match keystore.previous_master_key().await {
        Ok(Some(b)) => b,
        Ok(None) => {
            emit_master_key_rotation_failed_audit(
                home,
                failure_phase,
                "previous slot read back as None after write — keystore silently dropped the write",
                "keystore-write-dropped",
            )
            .await;
            eprint!(
                "{}",
                crate::design::render::error_block(
                    "rotate_key_previous_slot_verify_failed",
                    "the keystore reported `previous_master_key()` is empty immediately \
                     after writing it. The OS keychain may be misconfigured or the entry \
                     was removed by another process.",
                    "verify your OS keychain is responsive (try `agentsso status`); inspect for permission issues",
                    None,
                )
            );
            return Err(exit4());
        }
        Err(e) => {
            emit_master_key_rotation_failed_audit(
                home,
                failure_phase,
                &format!("previous_master_key read-back failed: {e}"),
                "keystore-readback-error",
            )
            .await;
            return Err(exit4());
        }
    };
    let eq: bool = read_back.ct_eq(&**expected).into();
    if !eq {
        emit_master_key_rotation_failed_audit(
            home,
            failure_phase,
            "previous slot read-back differs from value just written",
            "keystore-write-mismatch",
        )
        .await;
        eprint!(
            "{}",
            crate::design::render::error_block(
                "rotate_key_previous_slot_verify_failed",
                "the keystore returned a different value for `previous_master_key()` \
                 immediately after writing it. The keychain may have coalesced writes \
                 or another process is concurrently modifying the entry.",
                "ensure no other agentsso process is running; verify the OS keychain is functioning correctly",
                None,
            )
        );
        return Err(exit4());
    }
    Ok(())
}

/// Read the primary slot and assert byte-equality against the
/// expected value. Used after a primary-slot write to catch silently-
/// dropped writes and concurrent modifications.
async fn verify_primary_matches(
    home: &Path,
    keystore: &dyn KeyStore,
    expected: &Zeroizing<[u8; 32]>,
    failure_phase: &str,
) -> Result<()> {
    use subtle::ConstantTimeEq;
    let read_back = match keystore.master_key().await {
        Ok(b) => b,
        Err(e) => {
            emit_master_key_rotation_failed_audit(
                home,
                failure_phase,
                &format!("master_key read-back failed: {e}"),
                "keystore-readback-error",
            )
            .await;
            return Err(exit4());
        }
    };
    let eq: bool = read_back.ct_eq(&**expected).into();
    if !eq {
        emit_master_key_rotation_failed_audit(
            home,
            failure_phase,
            "primary slot read-back differs from value just written",
            "keystore-write-mismatch",
        )
        .await;
        eprint!(
            "{}",
            crate::design::render::error_block(
                "rotate_key_primary_slot_verify_failed",
                "the keystore returned a different value for `master_key()` immediately \
                 after writing it. The keychain may have coalesced writes or another \
                 process is concurrently modifying the entry.",
                "ensure no other agentsso process is running; verify the OS keychain is functioning correctly",
                None,
            )
        );
        return Err(exit4());
    }
    Ok(())
}

/// Story 7.6b round-1 review: best-effort cleanup of
/// `<svc>.sealed.tmp.<pid>.<n>` orphans left by Phase D crashes.
/// MUST be called only with the VaultLock held — racing against an
/// actively-writing process would race against its rename.
///
/// Failures here are non-fatal: the orphans don't impair correctness
/// (the boot guard already filters `.tmp.` files out of min/max
/// computation), they just clutter the directory. Log + continue.
fn sweep_sealed_tmp_orphans(vault_dir: &Path) {
    let read_dir = match std::fs::read_dir(vault_dir) {
        Ok(rd) => rd,
        Err(_) => return,
    };
    let mut removed: u32 = 0;
    for entry in read_dir.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else { continue };
        // Match the tempfile naming convention used by
        // `atomic_write_bytes`: `<service>.sealed.tmp.<pid>.<n>`.
        if !name.contains(".sealed.tmp.") {
            continue;
        }
        // Only files; never follow symlinks.
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if !meta.file_type().is_file() {
            continue;
        }
        match std::fs::remove_file(&path) {
            Ok(()) => removed += 1,
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "rotate-key: could not delete *.sealed.tmp.* orphan"
                );
            }
        }
    }
    if removed > 0 {
        tracing::info!(removed, "rotate-key: swept sealed.tmp orphans before Phase B");
    }
}

/// Story 7.6b round-2 review: surface (but do NOT delete) stale
/// `<home>/rotate-key-output.<pid>` files from prior runs. The
/// round-1 design intentionally leaves these files on disk for the
/// operator to consume manually; auto-deletion would risk losing
/// tokens an operator hasn't yet read.
///
/// The tokens in those files will be invalidated by the rotation
/// we're about to start (Phase E re-rolls every agent's bearer
/// token), so they're already stale-by-the-time-this-finishes. We
/// emit a stderr banner naming each orphan + mtime so the operator
/// has one last chance to `cat` them before they become useless.
fn warn_about_rotate_key_output_orphans(home: &Path) {
    let read_dir = match std::fs::read_dir(home) {
        Ok(rd) => rd,
        Err(_) => return,
    };
    let our_pid = std::process::id();
    let mut orphans: Vec<(std::path::PathBuf, std::time::SystemTime)> = Vec::new();
    for entry in read_dir.flatten() {
        let Some(name) = entry.file_name().into_string().ok() else { continue };
        let Some(pid_part) = name.strip_prefix("rotate-key-output.") else { continue };
        // Skip if it's OUR pid (vanishingly rare on a fresh process,
        // but guard anyway — we'll write to that path momentarily).
        if pid_part.parse::<u32>().ok() == Some(our_pid) {
            continue;
        }
        let path = entry.path();
        let mtime =
            std::fs::metadata(&path).and_then(|m| m.modified()).unwrap_or(std::time::UNIX_EPOCH);
        orphans.push((path, mtime));
    }
    if orphans.is_empty() {
        return;
    }
    eprintln!();
    eprintln!(
        "warning: {} stale rotate-key-output file(s) detected from prior rotations:",
        orphans.len()
    );
    for (path, mtime) in &orphans {
        let dt: chrono::DateTime<chrono::Utc> = (*mtime).into();
        eprintln!(
            "  {}  (modified {})",
            path.display(),
            dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        );
    }
    eprintln!(
        "These contain bearer tokens that THIS rotation will invalidate. \
         If you have not yet copied the tokens out of them, do so before \
         re-running rotate-key — `cat` each file, update agent configs, \
         then `rm` it. After this rotation completes, the tokens in those \
         files will not authenticate."
    );
    eprintln!();
}

/// Persist new agent tokens to a mode-0o600 file before Phase F so
/// they survive a Phase F failure. Path: `<home>/rotate-key-output.<pid>`.
fn write_tokens_file(path: &Path, new_tokens: &[(String, String)]) -> Result<(), std::io::Error> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    writeln!(
        f,
        "# rotate-key new agent tokens — keep secret, mode 0600\n# Format: <agent_name>=<token>"
    )?;
    for (name, token) in new_tokens {
        writeln!(f, "{name}={token}")?;
    }
    f.sync_all()?;
    Ok(())
}

/// Story 7.6b round-1 review: identify the operator that ran
/// `agentsso rotate-key` for audit-event correlation. Falls back to
/// `"unknown"` if the OS doesn't surface a username (CI containers,
/// some sandboxes). Empty-string actor IDs were rejected by the
/// review because they break downstream audit consumers that expect
/// non-empty actor fields.
fn operator_actor_id() -> String {
    // `USER` (POSIX) and `USERNAME` (Windows) cover the common cases
    // without pulling a `whoami` dep. Fallback `"unknown"` is what
    // earlier audit emissions used when `actor_id` was absent.
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_owned())
}

/// HKDF-SHA256 expand of the new master key into the agent token
/// lookup subkey. Uses the shared
/// [`permitlayer_core::agent::AGENT_LOOKUP_HKDF_INFO`] constant so
/// rotation's derivation cannot drift from `cli::start`'s boot-time
/// derivation — a divergence would silently break v2 token auth.
///
/// Story 7.6b round-2 review: returns `Zeroizing<[u8; 32]>` so the
/// subkey bytes are scrubbed at drop. The subkey is sensitive
/// material (anyone with it can compute lookup_key for any agent
/// name AND brute-force forge token-prefix HMACs); leaving it as
/// plain `[u8; 32]` was a discipline regression vs. `cli::start`'s
/// boot-time derivation which uses `Zeroizing` from line 1.
fn derive_agent_lookup_subkey(master_key: &[u8; 32]) -> Result<Zeroizing<[u8; LOOKUP_KEY_BYTES]>> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let mut subkey: Zeroizing<[u8; LOOKUP_KEY_BYTES]> = Zeroizing::new([0u8; LOOKUP_KEY_BYTES]);
    let hkdf = Hkdf::<Sha256>::new(None, master_key);
    hkdf.expand(permitlayer_core::agent::AGENT_LOOKUP_HKDF_INFO, &mut *subkey)
        .map_err(|e| anyhow::anyhow!("HKDF expand for agent lookup subkey failed: {e}"))?;
    Ok(subkey)
}

/// Emit the `master-key-rotated` audit event. Best-effort: an audit-
/// emit failure is logged via tracing but does not abort the
/// rotation (the rotation has already succeeded by this point).
///
/// Story 7.6b AC #8: `kdf` is now `"HKDF-SHA256"` (the actual KDF for
/// the daemon subkey derivation) — was `"OsRng"` in Story 7.6, which
/// was a misnomer (round-1 P10 fix). `agents_invalidated` renamed to
/// `agents_rerolled_count` to reflect Q4-A semantics.
async fn emit_master_key_rotated_audit(
    home: &Path,
    old_keyid: &str,
    new_keyid: &str,
    vault_reseal_count: u32,
    agents_rerolled_count: u32,
    elapsed_ms: u64,
    tokens_path: Option<&Path>,
) {
    use permitlayer_core::audit::event::AuditEvent;
    use permitlayer_core::scrub::{ScrubEngine, builtin_rules};
    use permitlayer_core::store::AuditStore;
    use permitlayer_core::store::fs::audit_fs::AuditFsStore;
    use std::sync::Arc;

    let scrub_engine = match ScrubEngine::new(builtin_rules().to_vec()) {
        Ok(e) => Arc::new(e),
        Err(e) => {
            tracing::warn!(error = %e, "scrub engine init failed; skipping master-key-rotated audit event");
            return;
        }
    };
    let audit_dir = home.join("audit");
    let store = match AuditFsStore::new(audit_dir, 100_000_000, scrub_engine) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "could not construct audit store; skipping master-key-rotated event");
            return;
        }
    };

    let mut event = AuditEvent::new(
        "cli".into(),
        "rotate-key".into(),
        operator_actor_id(),
        "master-key".into(),
        "ok".into(),
        "master-key-rotated".into(),
    );
    // Story 7.6b round-2 review: include `tokens_path` so an
    // operator reviewing the audit log alone (no captured stdout)
    // can find where the new bearer tokens were written. The path
    // is non-sensitive — it leaks only that a tokens-output file
    // existed, not its contents (mode 0o600 protects the contents
    // from non-owner reads).
    event.extra = serde_json::json!({
        "old_keyid": old_keyid,
        "new_keyid": new_keyid,
        "kdf": "HKDF-SHA256",
        "vault_reseal_count": vault_reseal_count,
        "agents_rerolled_count": agents_rerolled_count,
        "elapsed_ms": elapsed_ms,
        "tokens_path": tokens_path.map(|p| p.display().to_string()),
    });

    if let Err(e) = store.append(event).await {
        tracing::warn!(error = %e, "failed to append master-key-rotated audit event");
    }
}

/// Story 7.6b round-2 review: emit `master-key-rotation-orphan-cleanup`
/// when rotate-key short-circuits via `ResumeOutcome::AlreadyComplete`
/// (marker=committed + previous-slot empty — Phase F succeeded, then
/// the marker delete crashed). The previous run's
/// `master-key-rotated` event recorded the actual rotation; this
/// event records the cleanup-of-the-orphan-marker step as a distinct
/// timestamped artifact so a forensic reviewer can correlate the
/// two without ambiguity.
async fn emit_master_key_rotation_orphan_cleanup_audit(home: &Path) {
    use permitlayer_core::audit::event::AuditEvent;
    use permitlayer_core::scrub::{ScrubEngine, builtin_rules};
    use permitlayer_core::store::AuditStore;
    use permitlayer_core::store::fs::audit_fs::AuditFsStore;
    use std::sync::Arc;

    let scrub_engine = match ScrubEngine::new(builtin_rules().to_vec()) {
        Ok(e) => Arc::new(e),
        Err(e) => {
            tracing::warn!(error = %e, "scrub engine init failed; skipping orphan-cleanup audit event");
            return;
        }
    };
    let audit_dir = home.join("audit");
    let store = match AuditFsStore::new(audit_dir, 100_000_000, scrub_engine) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "could not construct audit store; skipping orphan-cleanup event");
            return;
        }
    };

    let mut event = AuditEvent::new(
        "cli".into(),
        "rotate-key".into(),
        operator_actor_id(),
        "master-key".into(),
        "ok".into(),
        "master-key-rotation-orphan-cleanup".into(),
    );
    event.extra = serde_json::json!({
        "partial_state": "orphan-marker-cleaned",
    });
    if let Err(e) = store.append(event).await {
        tracing::warn!(error = %e, "failed to append orphan-cleanup audit event");
    }
}

/// Emit the `master-key-rotation-failed` audit event from any `?`
/// exit point in `run_rotation`. Story 7.6b AC #8 / Q4 — implemented
/// from day one (Story 7.6 deferred this; round-1 review caught it).
///
/// `failure_phase` ∈ `{"A","B","C_prime","D","E","F"}`.
/// `partial_state` ∈ `{"clean", "both-keys-in-keystore",
/// "vault-mixed", "vault-uniform-keystore-both", "agents-mid-rebuild",
/// "single-slot-clean"}`.
async fn emit_master_key_rotation_failed_audit(
    home: &Path,
    failure_phase: &str,
    failure_reason: &str,
    partial_state: &str,
) {
    use permitlayer_core::audit::event::AuditEvent;
    use permitlayer_core::scrub::{ScrubEngine, builtin_rules};
    use permitlayer_core::store::AuditStore;
    use permitlayer_core::store::fs::audit_fs::AuditFsStore;
    use std::sync::Arc;

    let scrub_engine = match ScrubEngine::new(builtin_rules().to_vec()) {
        Ok(e) => Arc::new(e),
        Err(e) => {
            tracing::warn!(error = %e, "scrub engine init failed; skipping master-key-rotation-failed audit event");
            return;
        }
    };
    let audit_dir = home.join("audit");
    let store = match AuditFsStore::new(audit_dir, 100_000_000, scrub_engine) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "could not construct audit store; skipping master-key-rotation-failed event");
            return;
        }
    };

    let mut event = AuditEvent::new(
        "cli".into(),
        "rotate-key".into(),
        operator_actor_id(),
        "master-key".into(),
        "denied".into(),
        "master-key-rotation-failed".into(),
    );
    event.extra = serde_json::json!({
        "failure_phase": failure_phase,
        "failure_reason": failure_reason,
        "partial_state": partial_state,
    });

    if let Err(e) = store.append(event).await {
        tracing::warn!(error = %e, "failed to append master-key-rotation-failed audit event");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use chrono::Utc;
    use permitlayer_core::agent::{AgentIdentity, parse_v2_token};
    use permitlayer_credential::OAuthToken;
    use permitlayer_keystore::{
        DeleteOutcome, KeyStore, KeyStoreError, KeyStoreKind, MASTER_KEY_LEN,
    };
    use std::sync::Mutex;
    use tempfile::TempDir;

    /// Test KeyStore that tracks the primary + previous slots. Mirrors
    /// the FakeKeyStore in `cli::start::tests` but lives in the
    /// rotate_key module so unit tests can drive Phase A → G against
    /// a mock without OS keychain.
    struct MockKeyStore {
        primary: Mutex<Option<[u8; MASTER_KEY_LEN]>>,
        previous: Mutex<Option<[u8; MASTER_KEY_LEN]>>,
    }

    impl MockKeyStore {
        fn with_primary(key: [u8; MASTER_KEY_LEN]) -> Self {
            Self { primary: Mutex::new(Some(key)), previous: Mutex::new(None) }
        }
    }

    #[async_trait]
    impl KeyStore for MockKeyStore {
        async fn master_key(&self) -> Result<Zeroizing<[u8; MASTER_KEY_LEN]>, KeyStoreError> {
            match *self.primary.lock().unwrap() {
                Some(k) => Ok(Zeroizing::new(k)),
                None => Err(KeyStoreError::PlatformError {
                    backend: "mock",
                    message: "no primary".into(),
                }),
            }
        }

        async fn set_master_key(&self, key: &[u8; MASTER_KEY_LEN]) -> Result<(), KeyStoreError> {
            *self.primary.lock().unwrap() = Some(*key);
            Ok(())
        }

        async fn delete_master_key(&self) -> Result<DeleteOutcome, KeyStoreError> {
            if self.primary.lock().unwrap().take().is_some() {
                Ok(DeleteOutcome::Removed)
            } else {
                Ok(DeleteOutcome::AlreadyAbsent)
            }
        }

        fn kind(&self) -> KeyStoreKind {
            KeyStoreKind::Native
        }

        async fn set_previous_master_key(
            &self,
            previous: &[u8; MASTER_KEY_LEN],
        ) -> Result<(), KeyStoreError> {
            *self.previous.lock().unwrap() = Some(*previous);
            Ok(())
        }

        async fn previous_master_key(
            &self,
        ) -> Result<Option<Zeroizing<[u8; MASTER_KEY_LEN]>>, KeyStoreError> {
            Ok(self.previous.lock().unwrap().map(Zeroizing::new))
        }

        async fn clear_previous_master_key(&self) -> Result<(), KeyStoreError> {
            *self.previous.lock().unwrap() = None;
            Ok(())
        }
    }

    /// Seed a fresh home directory: vault + agents dir + one credential
    /// + N agents. Returns the home + the primary master key so tests
    ///   can assert post-rotation state.
    async fn seed_home(
        n_agents: usize,
        n_credentials: usize,
    ) -> (TempDir, [u8; MASTER_KEY_LEN], Vec<String>) {
        let home = TempDir::new().unwrap();
        let master_key = [0x42u8; MASTER_KEY_LEN];

        // Seed vault entries at key_id = 0 (fresh install posture).
        std::fs::create_dir_all(home.path().join("vault")).unwrap();
        let vault = Vault::new(Zeroizing::new(master_key), 0);
        for i in 0..n_credentials {
            let svc = format!("svc-{i}");
            let token = OAuthToken::from_trusted_bytes(format!("token-{i}").into_bytes());
            let sealed = vault.seal(&svc, &token).unwrap();
            let bytes = permitlayer_core::store::fs::credential_fs::encode_envelope(&sealed);
            std::fs::write(home.path().join("vault").join(format!("{svc}.sealed")), bytes).unwrap();
        }

        // Seed agents. Use the OLD daemon subkey so rotation has work
        // to do (Phase E rebuilds them).
        let old_subkey = derive_agent_lookup_subkey(&master_key).unwrap();
        let mut agent_names = Vec::new();
        let agent_store = AgentIdentityFsStore::new(home.path().to_path_buf()).unwrap();
        for i in 0..n_agents {
            let name = format!("agent-{i}");
            let lookup = compute_lookup_key(&old_subkey, name.as_bytes());
            let token = format!("agt_v2_{name}_oldtokenbase64xxxx");
            let token_hash = hash_token(token.as_bytes()).unwrap();
            let agent = AgentIdentity::new(
                name.clone(),
                "default".to_owned(),
                token_hash,
                lookup_key_to_hex(&lookup),
                Utc::now(),
                None,
            )
            .unwrap();
            agent_store.put(agent).await.unwrap();
            agent_names.push(name);
        }

        (home, master_key, agent_names)
    }

    #[tokio::test]
    async fn run_rotation_happy_path_3_credentials_2_agents() {
        let (home, old_key, _agent_names) = seed_home(2, 3).await;
        let keystore = MockKeyStore::with_primary(old_key);

        run_rotation(home.path(), &keystore, Instant::now()).await.unwrap();

        // Assert primary slot changed; previous slot cleared.
        let primary = keystore.primary.lock().unwrap();
        let previous = keystore.previous.lock().unwrap();
        assert!(primary.is_some());
        assert_ne!(primary.unwrap(), old_key, "primary slot must hold the new key");
        assert!(previous.is_none(), "previous slot must be cleared in Phase F");

        // Assert all 3 vault envelopes are at the new key_id.
        let vault_dir = home.path().join("vault");
        for entry in std::fs::read_dir(&vault_dir).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_str().unwrap().to_owned();
            if !name.ends_with(".sealed") || name.starts_with('.') {
                continue;
            }
            let bytes = std::fs::read(&path).unwrap();
            // v2 envelope; key_id at offset 3.
            assert_eq!(u16::from_le_bytes([bytes[0], bytes[1]]), 2);
            assert_eq!(bytes[3], 1, "envelope {name} should be at key_id=1 after rotation");
        }
    }

    #[tokio::test]
    async fn run_rotation_resumes_when_marker_committed() {
        // Story 7.6b round-1 review (Decision 1+2): the resume path
        // is now driven by the rotation-state marker, not by
        // keystore-state inference. This test exercises the
        // "marker=committed, vault mixed" recovery — previous attempt
        // crashed mid-Phase-D, leaving some envelopes at OLD and some
        // at NEW. Re-running rotate-key resumes Phase D under the
        // committed-marker path and converges the vault.
        use super::super::marker;
        use super::super::marker::KeystorePhase;

        let home = TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join("vault")).unwrap();
        let _ = AgentIdentityFsStore::new(home.path().to_path_buf()).unwrap();

        let old_key = [0x42u8; MASTER_KEY_LEN];
        let new_key = [0x43u8; MASTER_KEY_LEN];

        // Old envelope at key_id=0.
        let old_vault = Vault::new(Zeroizing::new(old_key), 0);
        let old_token = OAuthToken::from_trusted_bytes(b"old".to_vec());
        let old_sealed = old_vault.seal("old-svc", &old_token).unwrap();
        std::fs::write(
            home.path().join("vault").join("old-svc.sealed"),
            permitlayer_core::store::fs::credential_fs::encode_envelope(&old_sealed),
        )
        .unwrap();

        // New envelope at key_id=1 (already-rewritten by the crashed run).
        let new_vault = Vault::new(Zeroizing::new(new_key), 1);
        let new_token = OAuthToken::from_trusted_bytes(b"new".to_vec());
        let new_sealed = new_vault.seal("new-svc", &new_token).unwrap();
        std::fs::write(
            home.path().join("vault").join("new-svc.sealed"),
            permitlayer_core::store::fs::credential_fs::encode_envelope(&new_sealed),
        )
        .unwrap();

        // Pre-seed the marker AT committed (the previous run got past
        // Phase C' before crashing) and the keystore in dual-slot
        // state.
        let m = marker::begin(home.path(), 0, 1, None, None).unwrap();
        marker::advance(home.path(), &m, KeystorePhase::PrePrimary).unwrap();
        let m = marker::read(home.path()).unwrap().unwrap();
        marker::advance(home.path(), &m, KeystorePhase::Committed).unwrap();

        let keystore = MockKeyStore {
            primary: Mutex::new(Some(new_key)),
            previous: Mutex::new(Some(old_key)),
        };

        run_rotation(home.path(), &keystore, Instant::now()).await.unwrap();

        // Both envelopes should now be at key_id=1.
        let bytes = std::fs::read(home.path().join("vault").join("old-svc.sealed")).unwrap();
        assert_eq!(bytes[3], 1, "old-svc must be re-sealed at key_id=1");
        let bytes = std::fs::read(home.path().join("vault").join("new-svc.sealed")).unwrap();
        assert_eq!(bytes[3], 1, "new-svc must remain at key_id=1");

        // Primary stays at NEW; previous slot cleared; marker deleted.
        assert_eq!(keystore.primary.lock().unwrap().unwrap(), new_key);
        assert!(keystore.previous.lock().unwrap().is_none());
        assert!(
            marker::read(home.path()).unwrap().is_none(),
            "marker must be deleted on successful Phase F"
        );
    }

    #[tokio::test]
    async fn run_rotation_refuses_ambiguous_state_without_marker() {
        // Pre-seed: keystore previous=OLD but NO marker on disk.
        // Under the new design this is "ambiguous state" — refuse
        // and instruct the operator to clear-previous.
        let home = TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join("vault")).unwrap();
        let _ = AgentIdentityFsStore::new(home.path().to_path_buf()).unwrap();

        let old_key = [0x42u8; MASTER_KEY_LEN];
        let new_key = [0x43u8; MASTER_KEY_LEN];
        let keystore = MockKeyStore {
            primary: Mutex::new(Some(new_key)),
            previous: Mutex::new(Some(old_key)),
        };

        // Note: no marker::begin call.
        let err = run_rotation(home.path(), &keystore, Instant::now()).await.unwrap_err();
        // The error chain is `cli error already printed` (SilentCliError)
        // wrapping `RotateKeyExitCode5`. Verify the inner type via
        // chain inspection.
        let downcast = err
            .chain()
            .find_map(|e| e.downcast_ref::<crate::cli::rotate_key::RotateKeyExitCode5>());
        assert!(downcast.is_some(), "expected RotateKeyExitCode5 in the error chain");

        // Keystore is unchanged: rotation refused without touching
        // anything.
        assert_eq!(keystore.primary.lock().unwrap().unwrap(), new_key);
        assert_eq!(keystore.previous.lock().unwrap().unwrap(), old_key);
    }

    #[tokio::test]
    async fn run_rotation_refuses_when_marker_at_pre_previous() {
        // Pre-seed: marker says rotation crashed before any keystore
        // write committed. New key bytes are lost; refuse-with-
        // instructions.
        use super::super::marker;
        let home = TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join("vault")).unwrap();
        let _ = AgentIdentityFsStore::new(home.path().to_path_buf()).unwrap();
        marker::begin(home.path(), 0, 1, None, None).unwrap();

        let old_key = [0x42u8; MASTER_KEY_LEN];
        let keystore = MockKeyStore::with_primary(old_key);

        let err = run_rotation(home.path(), &keystore, Instant::now()).await.unwrap_err();
        let downcast = err
            .chain()
            .find_map(|e| e.downcast_ref::<crate::cli::rotate_key::RotateKeyExitCode5>());
        assert!(downcast.is_some(), "expected RotateKeyExitCode5 in the error chain");

        // Marker file is preserved so the operator can inspect it
        // before deciding to delete + restart.
        assert!(marker::read(home.path()).unwrap().is_some());
    }

    #[tokio::test]
    async fn run_rotation_refuses_when_marker_at_pre_primary() {
        // Pre-seed: marker says rotation crashed AFTER previous-slot
        // write but BEFORE primary swap. New key bytes are lost.
        use super::super::marker;
        use super::super::marker::KeystorePhase;
        let home = TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join("vault")).unwrap();
        let _ = AgentIdentityFsStore::new(home.path().to_path_buf()).unwrap();
        let m = marker::begin(home.path(), 0, 1, None, None).unwrap();
        marker::advance(home.path(), &m, KeystorePhase::PrePrimary).unwrap();

        let old_key = [0x42u8; MASTER_KEY_LEN];
        let keystore = MockKeyStore {
            primary: Mutex::new(Some(old_key)),
            previous: Mutex::new(Some(old_key)),
        };

        let err = run_rotation(home.path(), &keystore, Instant::now()).await.unwrap_err();
        let downcast = err
            .chain()
            .find_map(|e| e.downcast_ref::<crate::cli::rotate_key::RotateKeyExitCode5>());
        assert!(downcast.is_some(), "expected RotateKeyExitCode5 in the error chain");
    }

    #[tokio::test]
    async fn run_rotation_skips_envelope_already_at_new_key_id() {
        // Story 7.6b round-1 review: the prior version of this test
        // seeded zero envelopes and never exercised the skip branch.
        // The fixed version pre-seeds:
        //   (a) one envelope at OLD key_id (Phase D must reseal it),
        //   (b) one envelope already at NEW key_id (Phase D must
        //       skip — this is the resume idempotency invariant).
        // Marker is committed; keystore is in dual-slot state.
        use super::super::marker;
        use super::super::marker::KeystorePhase;

        let home = TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join("vault")).unwrap();
        let _ = AgentIdentityFsStore::new(home.path().to_path_buf()).unwrap();

        let old_key = [0xAAu8; MASTER_KEY_LEN];
        let new_key = [0xBBu8; MASTER_KEY_LEN];

        // Old envelope at key_id=0 (the to-be-resealed one).
        let old_vault = Vault::new(Zeroizing::new(old_key), 0);
        let old_token = OAuthToken::from_trusted_bytes(b"to-reseal".to_vec());
        let old_sealed = old_vault.seal("svc-old", &old_token).unwrap();
        std::fs::write(
            home.path().join("vault").join("svc-old.sealed"),
            permitlayer_core::store::fs::credential_fs::encode_envelope(&old_sealed),
        )
        .unwrap();

        // Pre-resealed envelope at key_id=1 (must be skipped).
        let new_vault = Vault::new(Zeroizing::new(new_key), 1);
        let already_resealed_token = OAuthToken::from_trusted_bytes(b"already-done".to_vec());
        let already_sealed = new_vault.seal("svc-already-done", &already_resealed_token).unwrap();
        let already_done_bytes =
            permitlayer_core::store::fs::credential_fs::encode_envelope(&already_sealed);
        let already_done_path = home.path().join("vault").join("svc-already-done.sealed");
        std::fs::write(&already_done_path, &already_done_bytes).unwrap();
        let already_done_mtime_pre =
            std::fs::metadata(&already_done_path).unwrap().modified().unwrap();

        // Marker says committed; keystore in dual-slot state.
        let m = marker::begin(home.path(), 0, 1, None, None).unwrap();
        marker::advance(home.path(), &m, KeystorePhase::PrePrimary).unwrap();
        let m = marker::read(home.path()).unwrap().unwrap();
        marker::advance(home.path(), &m, KeystorePhase::Committed).unwrap();

        let keystore = MockKeyStore {
            primary: Mutex::new(Some(new_key)),
            previous: Mutex::new(Some(old_key)),
        };

        run_rotation(home.path(), &keystore, Instant::now()).await.unwrap();

        // svc-old must be at key_id=1 (resealed).
        let bytes = std::fs::read(home.path().join("vault").join("svc-old.sealed")).unwrap();
        assert_eq!(bytes[3], 1, "svc-old must be resealed at key_id=1");

        // svc-already-done must remain byte-identical AND keep its
        // pre-rotation mtime — the skip branch must not touch it.
        let after_bytes = std::fs::read(&already_done_path).unwrap();
        assert_eq!(
            after_bytes, already_done_bytes,
            "already-resealed envelope must be byte-identical"
        );
        let mtime_post = std::fs::metadata(&already_done_path).unwrap().modified().unwrap();
        assert_eq!(
            mtime_post, already_done_mtime_pre,
            "already-resealed envelope must not be rewritten (mtime unchanged)"
        );
    }

    #[tokio::test]
    async fn run_rotation_persists_tokens_to_file_and_does_not_print_plaintext() {
        // Story 7.6b round-1 review re-triage (2026-04-28): the
        // "stdout-token print is a UX deferral" defer was rejected.
        // Plaintext tokens must NEVER reach stdout — the only
        // plaintext-bearing surface is `<home>/rotate-key-output.<pid>`
        // (mode 0o600), and Phase G prints the FILE PATH only.
        //
        // This test asserts:
        //   (a) the rotate-key-output file is present post-success
        //       (NOT deleted — operator consumes it manually);
        //   (b) the file contains `<name>=<token>` for each agent;
        //   (c) the file is mode 0o600 (cfg(unix));
        //   (d) Phase E ran (lookup_key_hex matches new HMAC).
        //
        // The "no plaintext in stdout" invariant is exercised via
        // a subprocess test in `tests/integration/rotate_key_e2e.rs`
        // — that's the only way to capture stdout reliably. This
        // unit test pins the file-side contract.
        //
        // Story 7.6b round-2 review: seed with 1 credential AND 1
        // agent (was 1+0). Phase D needs at least one envelope to
        // exercise the cross-Phase ordering between Phase D rewrite
        // and Phase E.5 token persist; an ordering regression would
        // not be caught by an empty Phase D.
        let (home, old_key, agent_names) = seed_home(1, 1).await;
        let keystore = MockKeyStore::with_primary(old_key);
        run_rotation(home.path(), &keystore, Instant::now()).await.unwrap();

        // (a) the rotate-key-output file is on disk after Phase G.
        let leftover: Vec<String> = std::fs::read_dir(home.path())
            .unwrap()
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| n.starts_with("rotate-key-output."))
            .collect();
        assert_eq!(
            leftover.len(),
            1,
            "exactly one rotate-key-output.* file must be left for the operator; found {leftover:?}"
        );
        let tokens_path = home.path().join(&leftover[0]);

        // (b) every agent has a `<name>=<token>` line.
        let bytes = std::fs::read_to_string(&tokens_path).unwrap();
        for name in &agent_names {
            let prefix = format!("{name}=agt_v2_{name}_");
            assert!(
                bytes.lines().any(|l| l.starts_with(&prefix)),
                "tokens file missing line for agent '{name}'; file contents:\n{bytes}"
            );
        }

        // (c) file is mode 0o600 on Unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&tokens_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "rotate-key-output file must be mode 0o600");
        }

        // (d) Phase E ran — agent's lookup_key_hex matches new subkey.
        let new_master = *keystore.primary.lock().unwrap().as_ref().unwrap();
        let new_subkey = derive_agent_lookup_subkey(&new_master).unwrap();

        let agent_store = AgentIdentityFsStore::new(home.path().to_path_buf()).unwrap();
        for name in &agent_names {
            let agent = agent_store.get(name).await.unwrap().unwrap();
            let stored = lookup_key_from_hex(&agent.lookup_key_hex).unwrap();
            let recomputed = compute_lookup_key(&new_subkey, name.as_bytes());
            assert_eq!(
                stored, recomputed,
                "agent '{name}' lookup_key_hex must match HMAC(new_subkey, name) after Phase E"
            );
        }
    }

    #[tokio::test]
    async fn run_rotation_preserves_oauth_through_key_rotation() {
        // The acid test: a credential sealed under the OLD key must
        // unseal correctly via the NEW key + new envelope after
        // rotation — proves the AEAD round-trip survives.
        let (home, old_key, _) = seed_home(0, 1).await;
        let keystore = MockKeyStore::with_primary(old_key);
        run_rotation(home.path(), &keystore, Instant::now()).await.unwrap();

        let new_master = *keystore.primary.lock().unwrap().as_ref().unwrap();
        let store = CredentialFsStore::new(home.path().to_path_buf()).unwrap();
        let sealed = store.get("svc-0").await.unwrap().unwrap();
        assert_eq!(sealed.key_id(), 1, "envelope must be at key_id=1 after rotation");

        let vault = Vault::new(Zeroizing::new(new_master), 1);
        let plaintext = vault.unseal("svc-0", &sealed).unwrap();
        assert_eq!(plaintext.reveal(), b"token-0");
    }

    #[test]
    fn parse_v2_token_round_trip_via_agent_module() {
        // Sanity: rotation's token format is parseable by the auth
        // path's parser. Catches "rotation emits a token format that
        // auth can't accept" regressions.
        let random = generate_bearer_token_bytes();
        let token = format!("agt_v2_my-agent_{}", base64_url_no_pad_encode(&random));
        let (name, decoded) = parse_v2_token(&token).unwrap();
        assert_eq!(name, "my-agent");
        assert_eq!(decoded.as_slice(), &random);
    }

    // ── Story 7.6b round-1 review: missing AC #15 unit tests ──────

    #[tokio::test]
    async fn run_rotation_aborts_on_unexpected_envelope_key_id() {
        // Story 7.6b round-2 review: the previous version of this
        // test sealed the "weird" envelope under a third unrelated
        // key (`[0xCC; 32]`). That made the test pass for the wrong
        // reason — even if the key_id-bounds check were removed,
        // `unseal()` would fail with AEAD verification error and
        // produce the same exit5 from a different code path.
        //
        // Fixed: seal the weird envelope under `old_key` (the same
        // key the rotation is using) but with key_id=7. Now ONLY
        // the key_id-bounds check (rotation.rs Phase D's
        // `envelope_key_id != old_key_id && != new_key_id` branch)
        // can produce the exit5 — `unseal` itself would succeed if
        // we got past that check.
        use super::super::marker;
        use super::super::marker::KeystorePhase;

        let home = TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join("vault")).unwrap();
        let _ = AgentIdentityFsStore::new(home.path().to_path_buf()).unwrap();

        let old_key = [0xAAu8; MASTER_KEY_LEN];
        let new_key = [0xBBu8; MASTER_KEY_LEN];

        // Envelope sealed under OLD key but at the unexpected
        // key_id=7. The key_id-bounds check is the ONLY thing that
        // can reject this.
        let weird_vault = Vault::new(Zeroizing::new(old_key), 7);
        let token = OAuthToken::from_trusted_bytes(b"x".to_vec());
        let sealed = weird_vault.seal("svc-weird", &token).unwrap();
        std::fs::write(
            home.path().join("vault").join("svc-weird.sealed"),
            permitlayer_core::store::fs::credential_fs::encode_envelope(&sealed),
        )
        .unwrap();

        // Marker says rotation is mid-flight from 0 → 1.
        let m = marker::begin(home.path(), 0, 1, None, None).unwrap();
        marker::advance(home.path(), &m, KeystorePhase::PrePrimary).unwrap();
        let m = marker::read(home.path()).unwrap().unwrap();
        marker::advance(home.path(), &m, KeystorePhase::Committed).unwrap();

        let keystore = MockKeyStore {
            primary: Mutex::new(Some(new_key)),
            previous: Mutex::new(Some(old_key)),
        };

        let err = run_rotation(home.path(), &keystore, Instant::now()).await.unwrap_err();
        let downcast = err
            .chain()
            .find_map(|e| e.downcast_ref::<crate::cli::rotate_key::RotateKeyExitCode5>());
        assert!(
            downcast.is_some(),
            "envelope at unexpected key_id must surface RotateKeyExitCode5"
        );
    }

    // Story 7.6b round-1 review: a `run_rotation_aborts_on_phase_e_agent_rebuild_error`
    // test was originally drafted against a 0o100 agents dir (no
    // write). It turns out `AgentIdentityFsStore::new` defensively
    // resets the agents dir to 0o700 on every construction (see
    // `agent_fs.rs::create_agents_dir`), so the dir-perms approach
    // can't actually drive Phase E into EACCES. The atomicity
    // invariant is covered at the lower layer by
    // `agent_fs::tests::update_lookup_key_and_token_atomic_no_partial_file`,
    // which exercises the same `update_lookup_key_and_token` write
    // path with a guaranteed-failing rename target. The Phase E
    // exit5 / audit-emit path is exercised by the other Phase E
    // tests in this module (e.g., the marker-state error paths).
    // Adding a redundant rotation-layer assertion against an
    // injected failure would require a fault-injection seam that
    // doesn't exist on `AgentIdentityFsStore` and would be
    // structurally similar to the agent_fs-layer test, so it's
    // intentionally omitted here.

    #[tokio::test]
    async fn run_rotation_refuses_when_key_id_overflow_at_255() {
        // Pre-seed the vault with a single envelope at key_id=255.
        // `compute_active_key_id` returns 255; the new_kid =
        // 255.checked_add(1) is None → exit4 with the structured
        // overflow banner.
        let home = TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join("vault")).unwrap();
        let _ = AgentIdentityFsStore::new(home.path().to_path_buf()).unwrap();

        let old_key = [0xAAu8; MASTER_KEY_LEN];
        let max_vault = Vault::new(Zeroizing::new(old_key), 255);
        let token = OAuthToken::from_trusted_bytes(b"x".to_vec());
        let sealed = max_vault.seal("svc-max", &token).unwrap();
        std::fs::write(
            home.path().join("vault").join("svc-max.sealed"),
            permitlayer_core::store::fs::credential_fs::encode_envelope(&sealed),
        )
        .unwrap();

        let keystore = MockKeyStore::with_primary(old_key);
        let err = run_rotation(home.path(), &keystore, Instant::now()).await.unwrap_err();
        let downcast = err
            .chain()
            .find_map(|e| e.downcast_ref::<crate::cli::rotate_key::RotateKeyExitCode4>());
        assert!(
            downcast.is_some(),
            "key_id overflow at 255 must surface RotateKeyExitCode4 (auth/keystore failure family)"
        );

        // The keystore must be unchanged: rotation refused before
        // any write.
        assert_eq!(keystore.primary.lock().unwrap().unwrap(), old_key);
        assert!(keystore.previous.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn run_rotation_clears_previous_slot_only_after_phase_e_succeeds() {
        // Sanity: at successful Phase G, the keystore's previous slot
        // is None AND the marker is deleted. This is the inverse of
        // `run_rotation_resumes_when_marker_committed` — that test
        // proves recovery from a Phase E crash; this test proves
        // forward-progress's Phase F runs only AFTER Phase E.
        let (home, old_key, _) = seed_home(1, 1).await;
        let keystore = MockKeyStore::with_primary(old_key);
        run_rotation(home.path(), &keystore, Instant::now()).await.unwrap();

        assert!(
            keystore.previous.lock().unwrap().is_none(),
            "Phase F must clear the previous slot after Phase E succeeds"
        );
        assert!(
            super::marker::read(home.path()).unwrap().is_none(),
            "marker must be deleted post-Phase-F"
        );
    }

    #[tokio::test]
    async fn run_rotation_acquires_vault_lock_for_full_duration() {
        // While `run_rotation` is in-flight, an external attempt to
        // acquire VaultLock must observe `Busy`. We can't easily
        // assert the lock is held *during* the run from inside the
        // same process (the test is async and sequential), but we
        // can prove the lock is acquired AT entry by pre-acquiring
        // it in the test and asserting rotate-key surfaces exit3.
        let (home, old_key, _) = seed_home(0, 0).await;

        let _holder =
            permitlayer_core::VaultLock::try_acquire(home.path()).expect("test holds the lock");

        let keystore = MockKeyStore::with_primary(old_key);
        let err = run_rotation(home.path(), &keystore, Instant::now()).await.unwrap_err();
        let downcast = err
            .chain()
            .find_map(|e| e.downcast_ref::<crate::cli::rotate_key::RotateKeyExitCode3>());
        assert!(
            downcast.is_some(),
            "rotate-key must surface RotateKeyExitCode3 when VaultLock is held by another process"
        );
    }
}
