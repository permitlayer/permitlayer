//! `sudo agentsso setup` — the single idempotent install / upgrade /
//! repair command for the privileged macOS daemon (UX-overhaul epic,
//! Story 2 — the keystone).
//!
//! Replaces `agentsso service install` as the primary verb. The
//! install/upgrade UX was unreliable by construction: a two-copy
//! binary split that drifted, copy-before-bootout (`Bootstrap failed:
//! 5` on every upgrade), no version-verify, and a first-run-only
//! policy seed. `setup` fixes all of that *by construction*:
//!
//! - **Versioned-symlink model.** The active binary lives at
//!   `<helper-dir>/agentsso-<V>` (immutable once written). The stable
//!   `<helper-dir>/agentsso` is a **symlink** to it; the LaunchDaemon
//!   plist points at the stable symlink path and **never changes
//!   across upgrades** (launchd re-resolves the symlink at each
//!   `bootstrap`).
//! - **bootout FIRST**, before any binary mutation — kills the
//!   copy-before-bootout `Bootstrap failed: 5` class.
//! - **Atomic cutover.** `symlink(new, .tmp); rename(.tmp, stable)`
//!   (same-dir, parent fsync) — never a half-installed state.
//! - **Self-verifying.** After bootstrap, `setup` polls
//!   `GET /v1/control/whoami` over the control UDS and refuses to
//!   declare success until the daemon reports `version == V`, the
//!   stable symlink resolves to `agentsso-<V>`, that file is
//!   byte-identical to what we staged, and launchd reports it
//!   `running`. Any post-cutover failure rolls the symlink back to
//!   the prior versioned binary and re-bootstraps.
//!
//! ## Trust model (why no signature-verify on the local binary)
//!
//! `setup` stages a copy of **this process's own `current_exe()`** —
//! the already-installed bare binary. The signature trust root lives
//! at the *download* boundary, not here: the curl|sh installer
//! (`install/install.sh`) and the PowerShell installer
//! (`install/install.ps1`) minisign-verify the downloaded release
//! **tarball** against `install/permitlayer.pub` before extracting it;
//! the Homebrew formula sha256-pins the tarball. There is no
//! `.minisig` sidecar on disk for an *extracted* bare binary, so the
//! privileged `setup` path does NOT (and cannot) signature-verify the
//! binary it stages. The local fail-closed control is instead:
//! (a) a content-hash idempotency gate — a pre-existing `agentsso-<V>`
//! whose bytes differ from the staged copy is refused
//! (tamper/corruption), never silently overwritten; and (b) the
//! self-verify activation gate — a binary that won't run or reports
//! the wrong version never becomes the active symlink target. Neither
//! is a signature check; the privileged path is content-hash-verified,
//! not signature-verified.

#[cfg(target_os = "macos")]
use std::path::{Path, PathBuf};
#[cfg(target_os = "macos")]
use std::time::{Duration, Instant};

use anyhow::Result;
use clap::Args;

use crate::cli::silent_cli_error;
use crate::design::render::error_block;

/// Arguments for `agentsso setup`. Mirrors `service::InstallArgs` so
/// the `--from` dev seam (point setup at an alternate source binary)
/// survives the rename.
#[derive(Args, Debug, Default, Clone)]
pub struct SetupArgs {
    /// Dev/test seam: install from this binary path instead of the
    /// running executable. Production operators never pass this.
    #[arg(long)]
    pub from: Option<std::path::PathBuf>,

    /// Answer Yes to every destructive heal in this run: archive
    /// legacy-seed shadow files and wipe operator state for a clean
    /// install. Mutually exclusive with `--upgrade`.
    #[arg(long, conflicts_with = "upgrade")]
    pub fresh_install: bool,

    /// Preserve all operator state (vault, agents, policies) — but
    /// still archive a daemon-crashing legacy-seed shadow aside,
    /// recoverably, so the install proceeds (Story 10.4). The explicit
    /// flag is the consent for that non-destructive archive; everything
    /// else the operator authored is kept. Mutually exclusive with
    /// `--fresh-install` (which ALSO wipes operator state).
    #[arg(long)]
    pub upgrade: bool,

    /// Replace an on-disk versioned binary whose bytes differ from the
    /// binary being installed (same version, different bytes). Without
    /// this flag setup refuses such a mismatch; with it the file is
    /// atomically replaced. Use only for a known-corrupt prior install.
    #[arg(long)]
    pub replace_binary: bool,
}

/// Run `agentsso setup`.
pub async fn run(args: SetupArgs) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        run_macos(args).await
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = args;
        eprint!(
            "{}",
            error_block(
                "setup.macos_only",
                "`agentsso setup` installs a privileged macOS LaunchDaemon and is \
                 macOS-only in this release",
                "on Linux/Windows, run `agentsso start` directly (foreground) — the \
                 privileged-install model is macOS-specific",
                None,
            )
        );
        Err(silent_cli_error("setup is macOS-only"))
    }
}

// ── Glyphs (mirror cli::update / cli::uninstall) ────────────────────

#[cfg(target_os = "macos")]
struct Glyphs {
    arrow: &'static str,
    check: &'static str,
    warn: &'static str,
}

#[cfg(target_os = "macos")]
fn glyphs() -> Glyphs {
    use crate::design::terminal::ColorSupport;
    match ColorSupport::detect() {
        ColorSupport::NoColor => Glyphs { arrow: "->", check: "[ok]", warn: "[!]" },
        _ => Glyphs {
            arrow: "\u{2192}", // →
            check: "\u{2713}", // ✓
            warn: "\u{26A0}",  // ⚠
        },
    }
}

// ── SHA-256 helper ──────────────────────────────────────────────────

#[cfg(target_os = "macos")]
fn sha256_file(path: &Path) -> std::io::Result<String> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(hex_lower(&hasher.finalize()))
}

#[cfg(target_os = "macos")]
fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// ── transient-I/O retry helpers (Epic 10 Story 10.2) ────────────────

/// Retry a fallible `io::Result` op on transient I/O (EAGAIN, EINTR,
/// WouldBlock, TimedOut, EBUSY/ETXTBSY) using the `TRANSIENT_FAST`
/// schedule with ±20% jitter. Terminal errors return immediately.
#[cfg(target_os = "macos")]
fn retry_transient_io<F, T>(op: F) -> std::io::Result<T>
where
    F: FnMut() -> std::io::Result<T>,
{
    use crate::repair::fs_repair::{IoKind, classify_io_kind};
    use crate::repair::retry::{RetryDecision, TRANSIENT_FAST, with_backoff_jittered};
    with_backoff_jittered(
        op,
        |e| {
            if classify_io_kind(e) == IoKind::Transient {
                RetryDecision::Retry
            } else {
                RetryDecision::Final
            }
        },
        TRANSIENT_FAST,
        std::thread::sleep,
    )
}

/// Retry a fallible `anyhow::Result` op on transient I/O. Classifies
/// transience by downcasting the error chain to `io::Error`; anything
/// without a transient io-error source is terminal.
#[cfg(target_os = "macos")]
fn retry_transient_anyhow<F, T>(op: F) -> anyhow::Result<T>
where
    F: FnMut() -> anyhow::Result<T>,
{
    use crate::repair::fs_repair::{IoKind, classify_io_kind};
    use crate::repair::retry::{RetryDecision, TRANSIENT_FAST, with_backoff_jittered};
    with_backoff_jittered(
        op,
        |e: &anyhow::Error| {
            let transient = e
                .chain()
                .find_map(|cause| cause.downcast_ref::<std::io::Error>())
                .map(|io| classify_io_kind(io) == IoKind::Transient)
                .unwrap_or(false);
            if transient { RetryDecision::Retry } else { RetryDecision::Final }
        },
        TRANSIENT_FAST,
        std::thread::sleep,
    )
}

/// Hash a file, retrying on transient I/O.
#[cfg(target_os = "macos")]
fn sha256_file_with_retry(path: &Path) -> std::io::Result<String> {
    retry_transient_io(|| sha256_file(path))
}

/// Hash a file, retrying on transient I/O; on a persistent
/// `PermissionDenied` escalate via `chmod 0o644` and retry once.
/// (Distinct from `repair::fs_repair::remove_file_with_retry` because
/// that primitive *removes* — here we want to *read*.)
#[cfg(target_os = "macos")]
fn sha256_file_with_retry_chmod(path: &Path) -> std::io::Result<String> {
    use crate::repair::fs_repair::{IoKind, classify_io_kind};
    match sha256_file_with_retry(path) {
        Ok(h) => Ok(h),
        Err(e) if classify_io_kind(&e) == IoKind::PermissionDenied => {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(path) {
                let mut perms = meta.permissions();
                perms.set_mode(0o644);
                if std::fs::set_permissions(path, perms).is_ok() {
                    return sha256_file(path);
                }
            }
            Err(e)
        }
        Err(e) => Err(e),
    }
}

/// Clear stale `*.tmp.*` symlink crumbs left in `dir` by a prior
/// crashed `atomic_symlink_swap` (Row 8 pre-clean). Best-effort.
#[cfg(target_os = "macos")]
fn clear_stale_tmp_crumbs(dir: &Path) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("agentsso.tmp.") {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
}

// ── whoami parse (mirror cli::update::parse_whoami_version) ──────────

#[cfg(target_os = "macos")]
fn parse_whoami_version(body: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    v.get("version")?.as_str().map(str::to_owned)
}

// ── macOS implementation ────────────────────────────────────────────

#[cfg(target_os = "macos")]
async fn run_macos(args: SetupArgs) -> Result<()> {
    use crate::cli::service::install_macos as im;

    let g = glyphs();
    let started = Instant::now();

    // (1) Root. Self-elevate under sudo when invoked without it on a
    // TTY (announce + exec — no confirmation prompt; the operator's
    // invocation IS the declaration of intent, per Determinate
    // nix-installer + Homebrew). `AGENTSSO_NO_SUDO_ELEVATE=1` and
    // non-TTY contexts fall through to the existing refusal.
    if !nix::unistd::Uid::effective().is_root() {
        if crate::repair::sudo::should_self_elevate() {
            println!("{} this needs root; re-running with sudo…", g.arrow);
            // Returns ONLY on exec failure; success replaces the process.
            let exec_err = crate::repair::sudo::reexec_under_sudo();
            eprint!(
                "{}",
                error_block(
                    "setup.sudo_reexec_failed",
                    &format!("could not re-run setup under sudo: {exec_err}"),
                    "run `sudo agentsso setup` manually",
                    None,
                )
            );
            return Err(silent_cli_error("sudo re-exec failed"));
        }
        // Non-TTY, or AGENTSSO_NO_SUDO_ELEVATE set: refuse as before.
        eprint!(
            "{}",
            error_block(
                "setup.requires_root",
                "`agentsso setup` installs a privileged system LaunchDaemon and must \
                 run as root",
                "sudo agentsso setup",
                None,
            )
        );
        return Err(silent_cli_error("setup requires root"));
    }

    // (2) Install-lock — serialize against a concurrent setup/install.
    let _lock = im::acquire_install_lock_pub()?;

    // (3) Operator resolution (refuses missing/root SUDO_UID).
    let (operator_uid, operator_username) = im::resolve_operator()?;
    println!("{} setup for operator {operator_username} (uid {operator_uid})", g.arrow);

    // (4) rc.21 LaunchAgent cleanup (idempotent — usually a no-op).
    let cleaned = im::cleanup_rc21_launchagents_pub().await;
    for (path, uid) in &cleaned {
        println!("  {} removed stale rc.21 LaunchAgent: {} (uid {uid})", g.check, path.display());
    }

    // (5) Group + state dirs + keychain (all idempotent / warn-cont).
    im::ensure_permitlayer_clients_group(&operator_username).await?;
    println!("  {} group ensured (operator {operator_username})", g.check);
    im::create_state_dirs()?;
    println!("  {} state + log + runtime dirs ensured", g.check);

    // (5z) `--fresh-install` lost-the-install reset: wipe operator
    // state entirely (the "Yes to all destructive heals, start clean"
    // contract). Runs BEFORE the legacy-seed step (a full wipe subsumes
    // shadow archival — there's nothing left to shadow) and before
    // bootout (the old daemon's open fds stay valid across the
    // unlinks; the subsequent bootout reloads). On `--upgrade` or no
    // flag this is skipped — only an explicit fresh-install wipes.
    if args.fresh_install {
        // Resolve home up front; refuse rather than wipe relative to `/`
        // if it can't be resolved (a destructive op must never rebase to
        // the filesystem root on an unexpected error).
        let home = crate::cli::agentsso_home().map_err(|e| {
            eprint!(
                "{}",
                error_block(
                    "setup.home_unresolved",
                    &format!("could not resolve the agentsso state directory: {e}"),
                    "ensure AGENTSSO_PATHS__HOME (if set) is valid, then re-run",
                    None,
                )
            );
            silent_cli_error("agentsso home unresolved")
        })?;
        let report = crate::repair::wipe::wipe_subdirs(
            &home,
            &["policies", "agents", "vault"],
            crate::repair::wipe::WipePolicy::All,
        )
        .map_err(|e| {
            eprint!(
                "{}",
                error_block(
                    "setup.fresh_install_wipe_failed",
                    &format!("could not wipe operator state for --fresh-install: {e}"),
                    "check filesystem permissions on the state dir and re-run",
                    None,
                )
            );
            silent_cli_error("fresh-install wipe failed")
        })?;
        if !report.errors.is_empty() {
            let stuck = report
                .errors
                .iter()
                .map(|(p, e)| format!("    {} ({e})", p.display()))
                .collect::<Vec<_>>()
                .join("\n");
            eprint!(
                "{}",
                error_block(
                    "setup.fresh_install_wipe_failed",
                    &format!("--fresh-install could not remove some operator state:\n{stuck}"),
                    "these paths are held by something setup can't clear (a running process \
                     with them open, an immutable flag, or a permissions issue) — check the \
                     per-path error above, resolve the holder, then re-run \
                     `sudo agentsso setup --fresh-install`",
                    None,
                )
            );
            return Err(silent_cli_error("fresh-install wipe incomplete"));
        }
        if !report.removed.is_empty() {
            println!("  {} operator state wiped (fresh install)", g.check);
        }
        let _ = crate::repair::journal::record(
            &home,
            "fresh_install_wipe",
            crate::repair::journal::JournalResult::Ok,
            &[("removed", &report.removed.len().to_string())],
        );
    }

    // (5a) Legacy-seed shadow detection + heal (Epic 10). An rc.31-era
    // operator `policies/*.toml` whose declared name(s) duplicate the
    // shipped managed bundle shadows it on first boot and crashloops
    // the daemon (`UnmarkedCrossLayerOverride`). Detect + archive aside
    // (TTY prompt default-Yes; non-TTY refuse unless a flag pre-decides)
    // BEFORE bootout, while the old daemon's open fds stay valid across
    // the rename. Runs as its own step so the heal is daemon-quiesce-
    // safe (rename keeps inodes; the subsequent bootout reloads).
    // (After a --fresh-install wipe above, this finds nothing.)
    match detect_and_heal_legacy_seed_shadow(&args, &g).await? {
        LegacySeedOutcome::NoShadow => {}
        LegacySeedOutcome::Healed { count, snapshot_dir } => {
            println!("  {} archived {count} file(s) to {}", g.check, snapshot_dir.display());
        }
    }

    let keychain_warning = im::disable_keychain_lock_on_sleep();

    // (6) Resolve source binary + version V. The source IS this
    // running executable (unless --from); its compile-time
    // CARGO_PKG_VERSION is therefore the staged binary's version AND
    // exactly what the daemon will report via `whoami.version`
    // (server/control.rs uses the same env! — verified).
    let source = im::resolve_binary_source_path(args.from.as_deref())?;
    let version = env!("CARGO_PKG_VERSION");
    // Row 4: retry the source hash on transient I/O before refusing.
    let staged_hash = sha256_file_with_retry(&source).map_err(|e| {
        eprint!(
            "{}",
            error_block(
                "setup.source_unreadable",
                &format!("could not hash the source binary {}: {e}", source.display()),
                "check the binary exists and is readable",
                None,
            )
        );
        silent_cli_error("source binary unreadable")
    })?;

    let helper_path = Path::new(im::PRIVILEGED_HELPER_PATH);
    let helper_dir = helper_path.parent().unwrap_or(Path::new("/"));
    let versioned = helper_dir.join(format!("agentsso-{version}"));

    // (7) bootout FIRST — before ANY binary mutation. This is the
    // copy-before-bootout `Bootstrap failed: 5` fix.
    im::bootout_daemon()?;
    println!("  {} daemon booted out (pre-mutation)", g.check);

    // (8) Stage the versioned binary. Idempotent + fail-closed.
    // Compute hashes-differ (Row 5: retry the hash on transient I/O; on
    // persistent EACCES escalate via chmod 0o644 + one retry), then let
    // the pure `decide_versioned_binary` pick the action.
    let versioned_exists = versioned.exists();
    // HEAL (Story 10.4): if an EXISTING versioned binary can't be hashed
    // even after the chmod-retry, that slot is setup-owned staging state
    // we are about to (re)write with the same version's bytes anyway —
    // an unreadable/corrupt prior stage is not an operator decision, so
    // self-heal by re-staging rather than refusing with a manual-removal
    // instruction. An UNREADABLE slot sets `force_restage`, which routes
    // straight to an atomic re-stage (below) REGARDLESS of
    // `--replace-binary` — it's setup-owned, not a tamper decision. The
    // genuine tamper case (slot is READABLE but its bytes differ from the
    // staged source) is unaffected: it still flows through
    // `decide_versioned_binary` and its Refuse-unless-`--replace-binary`
    // arm.
    let mut force_restage = false;
    let hashes_differ = if versioned_exists {
        match sha256_file_with_retry_chmod(&versioned) {
            Ok(existing_hash) => existing_hash != staged_hash,
            Err(e) => {
                // The setup-owned slot is unreadable; we re-stage it
                // (it's about to be overwritten with the same version's
                // bytes anyway). Surface a loud line (stderr, like the
                // other heal notices) AND record the heal in the setup
                // journal (epic-AC #7). `home` isn't bound in this block,
                // so resolve it best-effort just for the journal line.
                eprintln!(
                    "  {} existing versioned binary at {} was unreadable ({e}) — re-staging",
                    g.warn,
                    versioned.display()
                );
                if let Ok(home) = crate::cli::agentsso_home() {
                    let _ = crate::repair::journal::record(
                        &home,
                        "versioned_binary_stage",
                        crate::repair::journal::JournalResult::Ok,
                        &[
                            ("heal", "restage_unreadable"),
                            ("path", &versioned.display().to_string()),
                        ],
                    );
                }
                force_restage = true;
                true
            }
        }
    } else {
        false
    };
    // An unreadable existing slot heals by re-staging regardless of the
    // `--replace-binary` flag (it's setup-owned, not a tamper decision).
    let action = if force_restage {
        VersionedBinaryAction::Replace
    } else {
        decide_versioned_binary(versioned_exists, hashes_differ, args.replace_binary)
    };
    match action {
        VersionedBinaryAction::Stage => {
            im::stage_file_atomic(&source, &versioned)?;
            println!("  {} staged {}", g.check, versioned.display());
        }
        VersionedBinaryAction::AlreadyStaged => {
            println!("  {} versioned binary already staged (hash match)", g.check);
        }
        VersionedBinaryAction::Replace => {
            // Row 6 `--replace-binary`: explicit opt-in atomic replace.
            crate::repair::fs_repair::atomic_replace_owned_file(&source, &versioned, 0o755)
                .map_err(|e| {
                    eprint!(
                        "{}",
                        error_block(
                            "setup.versioned_binary_mismatch",
                            &format!(
                                "--replace-binary rewrite of {} failed: {e}",
                                versioned.display()
                            ),
                            "check filesystem permissions and re-run",
                            None,
                        )
                    );
                    silent_cli_error("--replace-binary rewrite failed")
                })?;
            println!("  {} replaced versioned binary at {}", g.check, versioned.display());
        }
        VersionedBinaryAction::Refuse => {
            // Row 6 default: same version, different bytes ⇒ tamper or a
            // botched prior install. Refuse (matches apt/dpkg/rpm —
            // never silently overwrite).
            eprint!(
                "{}",
                error_block(
                    "setup.versioned_binary_mismatch",
                    &format!(
                        "a different agentsso {version} binary is already at {} (same \
                         version, different bytes)",
                        versioned.display()
                    ),
                    &format!(
                        "to replace it, re-run with `--replace-binary` (use this if you know \
                         it's a corrupted prior install); to investigate first: \
                         `codesign --verify {}`",
                        versioned.display()
                    ),
                    None,
                )
            );
            return Err(silent_cli_error("versioned binary content mismatch"));
        }
    }

    // ── EVERYTHING BELOW IS "POST-STEP-5" (post-cutover): any
    //    failure triggers rollback to `prior_target`. ──────────────

    // (9) Record the prior symlink target for rollback, then do the
    // atomic symlink swap.
    let prior_target: Option<PathBuf> = std::fs::read_link(helper_path).ok();
    // Legacy/regular-file migration: pre-symlink installs had a REAL
    // binary at the helper path (not a symlink). We must move it out
    // of the way so the stable symlink can be created — but step 7
    // already booted the daemon out, so if any post-cutover step
    // below fails we'd be left with a hard-down daemon and no binary
    // to restore. So instead of `remove_file` (which is unrecoverable)
    // we RENAME the legacy binary aside to a `.legacy-bak.<pid>`
    // crumb; the restore path below renames it back + re-bootstraps.
    // (The plain symlink-upgrade path keeps using `prior_target` +
    // `rollback()` — only the legacy non-symlink migration needs the
    // crumb because its `prior_target` is `None`.)
    let mut legacy_bak: Option<PathBuf> = None;
    if helper_path.exists() && prior_target.is_none() {
        let bak = helper_dir.join(format!("agentsso.legacy-bak.{}", std::process::id()));
        // Clear any stale crumb from a prior crashed run at this pid.
        let _ = std::fs::remove_file(&bak);
        // Row 7: retry the move-aside on transient I/O. The bak path is
        // fixed (the rollback path is coupled to this exact name), so
        // we retry the rename itself rather than delegate to
        // `repair::fs_repair::rename_aside` (which picks its own name).
        let rename_result = retry_transient_io(|| std::fs::rename(helper_path, &bak));
        if let Err(e) = rename_result {
            eprint!(
                "{}",
                error_block(
                    "setup.legacy_helper_unremovable",
                    &format!(
                        "a non-symlink binary exists at {} and could not be moved aside after \
                         retry: {e}",
                        helper_path.display()
                    ),
                    "setup tried to rename this legacy binary aside (with retry) and the OS \
                     refused — something is holding it (a running process with it open, or a \
                     locked/immutable file). check the error above, clear the holder, then \
                     re-run `sudo agentsso setup`",
                    None,
                )
            );
            return Err(silent_cli_error("legacy helper not movable"));
        }
        legacy_bak = Some(bak);
    }
    // Row 8: clear stale `*.tmp.*` crumbs in helper_dir, then retry the
    // atomic symlink swap on transient I/O before refusing/rolling back.
    clear_stale_tmp_crumbs(helper_dir);
    if let Err(e) = retry_transient_io(|| atomic_symlink_swap(&versioned, helper_path, helper_dir))
    {
        // Swap failed BEFORE the symlink moved. For a plain upgrade
        // the old symlink target is still in place (nothing to roll
        // back). For the legacy migration the real binary was moved
        // aside by us AND the daemon was already booted out at step 7
        // — restore it + re-bootstrap so we don't leave a hard-down
        // daemon behind.
        if let Some(bak) = &legacy_bak {
            return restore_legacy_and_rebootstrap(
                &g,
                bak,
                helper_path,
                &format!(
                    "could not point {} at {}: {e}",
                    helper_path.display(),
                    versioned.display()
                ),
            )
            .await;
        }
        eprint!(
            "{}",
            error_block(
                "setup.symlink_swap_failed",
                &format!(
                    "could not point {} at {}: {e}",
                    helper_path.display(),
                    versioned.display()
                ),
                "check filesystem permissions on /Library/PrivilegedHelperTools and re-run",
                None,
            )
        );
        return Err(silent_cli_error("symlink swap failed"));
    }
    println!("  {} {} → {}", g.check, helper_path.display(), versioned.display());

    // (10) Plist compare-then-write (no-op on upgrades — it already
    // points at the stable symlink path). Row 9: retry on transient
    // I/O before rolling back.
    let plist_result =
        retry_transient_anyhow(|| im::write_launchdaemon_plist(operator_uid, &operator_username));
    let wrote = match plist_result {
        Ok(w) => w,
        Err(e) => {
            if let Some(bak) = &legacy_bak {
                return restore_legacy_and_rebootstrap(
                    &g,
                    bak,
                    helper_path,
                    &format!("plist write failed: {e}"),
                )
                .await;
            }
            return rollback(
                &g,
                prior_target.as_deref(),
                helper_path,
                helper_dir,
                &format!("plist write failed: {e}"),
            )
            .await;
        }
    };
    println!("  {} LaunchDaemon plist {}", g.check, if wrote { "written" } else { "unchanged" });

    // (11) Bootstrap.
    if let Err(e) = im::launchctl_bootstrap_system() {
        if let Some(bak) = &legacy_bak {
            return restore_legacy_and_rebootstrap(
                &g,
                bak,
                helper_path,
                &format!("launchctl bootstrap failed: {e}"),
            )
            .await;
        }
        return rollback(
            &g,
            prior_target.as_deref(),
            helper_path,
            helper_dir,
            &format!("launchctl bootstrap failed: {e}"),
        )
        .await;
    }
    println!("  {} launchctl bootstrap", g.check);

    // (12) Self-verify: poll whoami over the control UDS until the
    // daemon reports version == V; then assert the symlink resolves
    // to agentsso-<V>, that file's hash == staged_hash, and launchd
    // reports it running with a non-zero pid.
    match self_verify(version, &versioned, &staged_hash, Duration::from_secs(15)).await {
        Ok(pid) => {
            println!("  {} self-verified: daemon {version} running (pid {pid})", g.check);
            im::emit_install_complete_audit(
                operator_uid,
                &operator_username,
                pid,
                started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
            );
        }
        Err(reason) => {
            if let Some(bak) = &legacy_bak {
                return restore_legacy_and_rebootstrap(&g, bak, helper_path, &reason).await;
            }
            return rollback(&g, prior_target.as_deref(), helper_path, helper_dir, &reason).await;
        }
    }

    // Setup succeeded. The legacy binary is no longer needed — drop
    // the `.legacy-bak` crumb. Best-effort; a stale crumb left by a
    // crash between here and the `rename` is swept by
    // `gc_old_versions` on the next run.
    if let Some(bak) = &legacy_bak {
        let _ = std::fs::remove_file(bak);
    }

    // (13) GC old versioned binaries — keep current + the single most
    // recent other version. Best-effort; never aborts setup.
    gc_old_versions(&g, helper_dir, version);

    // (14) Caveats.
    println!();
    println!("──────────────────────────────────────────────────────────────");
    println!("{} PermitLayer installed/upgraded as a macOS system service.", g.check);
    println!();
    println!("Daemon log: /Library/Logs/permitlayer/daemon.log");
    if let Some(stderr) = &keychain_warning {
        println!();
        println!("{} System.keychain lock-on-sleep could not be disabled:", g.warn);
        for line in stderr.lines() {
            println!("    {line}");
        }
        println!("  The daemon may re-prompt for the master key after sleep/wake.");
    }
    println!();
    println!("End-users on this Mac connect an agent with:");
    println!("  agentsso quickstart <service>   (gmail | calendar | drive)");
    println!("──────────────────────────────────────────────────────────────");
    Ok(())
}

/// Outcome of the legacy-seed shadow detection step (5a). A refusal
/// is expressed by returning `Err` directly from
/// [`detect_and_heal_legacy_seed_shadow`] (it emits the structured
/// error block first), so the success outcomes are only "nothing to
/// do" or "archived N file(s)".
#[cfg(target_os = "macos")]
enum LegacySeedOutcome {
    /// No operator policy file shadows a managed-bundle name.
    NoShadow,
    /// `count` shadowing file(s) were archived into `snapshot_dir`.
    Healed { count: usize, snapshot_dir: PathBuf },
}

/// Pure decision for the three-state legacy-seed posture, extracted so
/// the truth table is unit-testable without process-global TTY / env /
/// filesystem state. The caller resolves `stdin_tty` and (only when
/// needed) the TTY prompt result, then delegates here.
///
/// Precedence: `--fresh-install` and `--upgrade` both archive the
/// daemon-crashing shadow (Story 10.4: `--upgrade` no longer refuses —
/// it preserves operator config but archives the shadow so the on-screen
/// remedy makes progress instead of looping). They are mutually
/// exclusive at the clap layer, so at most one is set, and they differ
/// elsewhere: `--fresh-install` ALSO wipes operator state, `--upgrade`
/// preserves everything except the shadow. A flag always wins over the
/// TTY prompt.
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LegacySeedDecision {
    /// Archive the shadowing files aside.
    Archive,
    /// Refuse with `setup.heal_needs_decision` (only the non-TTY,
    /// no-flag path — the operator must pick `--upgrade` or
    /// `--fresh-install`, both of which now make progress).
    Refuse,
    /// TTY + no flag: the caller must run the interactive prompt and
    /// re-decide based on the operator's Yes/No.
    Prompt,
}

/// Pure shadow filter: a file shadows iff it declares a managed-bundle
/// name WITHOUT a matching `override = "<that name>"` marker — i.e. a
/// declaration that would produce `UnmarkedCrossLayerOverride` (the
/// rc.31 crashloop the heal targets). A *marked* override
/// (`name = "X"` + `override = "X"`) is legitimate operator config that
/// compiles cleanly and must NOT be archived — matching on name alone
/// would destroy it. Extracted for direct unit testing (detection
/// correctness is load-bearing for a destructive heal).
#[cfg(target_os = "macos")]
fn find_shadowing_files(
    managed: &std::collections::HashSet<String>,
    by_file: Vec<(PathBuf, Vec<permitlayer_core::policy::PolicyDecl>)>,
) -> Vec<PathBuf> {
    by_file
        .into_iter()
        .filter(|(_, decls)| {
            decls.iter().any(|d| {
                // Collides with a managed name…
                managed.contains(&d.name)
                    // …and is NOT a correctly-marked override of that
                    // same name (which would compile fine, not shadow).
                    && d.override_marker.as_deref() != Some(d.name.as_str())
            })
        })
        .map(|(path, _)| path)
        .collect()
}

/// What to do with the versioned binary slot at `<helper-dir>/agentsso-<V>`
/// (Epic 10 row 6). Extracted as a pure decision so both the
/// refuse-by-default and `--replace-binary` arms are unit-testable
/// without root (the real branch does privileged atomic file ops).
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VersionedBinaryAction {
    /// No file at the versioned path yet → stage the source there.
    Stage,
    /// File exists, bytes match the staged source → idempotent no-op.
    AlreadyStaged,
    /// File exists, bytes DIFFER, and `--replace-binary` was passed →
    /// atomically replace it.
    Replace,
    /// File exists, bytes DIFFER, no `--replace-binary` → refuse
    /// (matches apt/dpkg/rpm: never silently overwrite a same-version
    /// artifact with different bytes).
    Refuse,
}

#[cfg(target_os = "macos")]
fn decide_versioned_binary(
    versioned_exists: bool,
    hashes_differ: bool,
    replace_binary: bool,
) -> VersionedBinaryAction {
    if !versioned_exists {
        VersionedBinaryAction::Stage
    } else if !hashes_differ {
        VersionedBinaryAction::AlreadyStaged
    } else if replace_binary {
        VersionedBinaryAction::Replace
    } else {
        VersionedBinaryAction::Refuse
    }
}

#[cfg(target_os = "macos")]
fn decide_legacy_seed(fresh_install: bool, upgrade: bool, stdin_tty: bool) -> LegacySeedDecision {
    if fresh_install || upgrade {
        // Story 10.4 (decision B): both flags archive the shadow. The
        // explicit flag IS the operator's consent (no prompt). They
        // differ only in that `--fresh-install` also wipes operator
        // state; the archive of the daemon-crashing shadow is common to
        // both. `--upgrade` was previously `Refuse`, which made the
        // on-screen remedy loop (heal_needs_decision listed `--upgrade`,
        // but `--upgrade` reproduced the same refusal).
        LegacySeedDecision::Archive
    } else if stdin_tty {
        LegacySeedDecision::Prompt
    } else {
        // Non-TTY + no flag: the only genuine human-decision path. The
        // refusal copy points at `--upgrade` / `--fresh-install`, both
        // of which now make progress.
        LegacySeedDecision::Refuse
    }
}

/// Detect operator policy files that shadow shipped (managed-bundle)
/// policy names, and heal per the three-state TTY posture.
///
/// **Detection** uses the same canonical parser the daemon compiles
/// with: managed names from [`crate::cli::start::embedded_managed_policy_names`]
/// (the embedded bundle for THIS binary — independent of the on-disk
/// `policies-managed/` dir, which may be stale/absent before bootstrap)
/// and operator per-file names from
/// `permitlayer_core::policy::read_policy_decls_by_file`. A file is a
/// shadow iff it declares a managed name WITHOUT a matching `override`
/// marker (a *marked* override is legitimate config — see
/// [`find_shadowing_files`]).
///
/// **Posture** (rev-5 plan § C, amended by Story 10.4):
/// - TTY + no flag → prompt (default Yes); on Yes archive, on No refuse.
/// - TTY/non-TTY + `--fresh-install` → archive the shadow (and wipe
///   operator state elsewhere); a LOUD audit line names what moved.
/// - TTY/non-TTY + `--upgrade` → archive the shadow, preserve all other
///   operator state, continue; a LOUD audit line names what moved.
///   (Story 10.4: was `refuse`, which made the on-screen remedy loop.)
/// - Non-TTY + no flag → refuse (`setup.heal_needs_decision`) — the only
///   remaining refuse path; its copy points at `--upgrade`/`--fresh-install`,
///   both of which now make progress.
///
/// Archival is non-destructive: files move to
/// `policies/.legacy-seed-snapshot-<isotime>/` (operator-recoverable),
/// never deleted. Non-shadowing operator files are never touched.
#[cfg(target_os = "macos")]
async fn detect_and_heal_legacy_seed_shadow(
    args: &SetupArgs,
    g: &Glyphs,
) -> Result<LegacySeedOutcome> {
    use std::io::IsTerminal as _;

    // Resolve home ONCE. A destructive heal (archival) must never
    // operate relative to `/` on an unresolved home — refuse instead.
    let home = crate::cli::agentsso_home().map_err(|e| {
        eprint!(
            "{}",
            error_block(
                "setup.home_unresolved",
                &format!("could not resolve the agentsso state directory: {e}"),
                "ensure AGENTSSO_PATHS__HOME (if set) is valid, then re-run `sudo agentsso setup`",
                None,
            )
        );
        silent_cli_error("agentsso home unresolved")
    })?;
    let policies = permitlayer_core::paths::policies_dir(Some(&home));
    // No operator policy dir yet ⇒ nothing could shadow.
    if !policies.exists() {
        return Ok(LegacySeedOutcome::NoShadow);
    }

    // Managed names for THIS binary (embedded bundle is authoritative).
    // Fail CLOSED: a compile failure of the embedded bundle must NOT be
    // silently treated as "no managed names" (that would fail open — a
    // real shadow would go undetected and crashloop the daemon).
    let managed: std::collections::HashSet<String> =
        crate::cli::start::embedded_managed_policy_names()
            .map_err(|e| {
                eprint!(
                    "{}",
                    error_block(
                        "setup.embedded_bundle_uncompilable",
                        &format!("the embedded managed policy bundle failed to compile: {e}"),
                        "this is a build-time defect in agentsso itself — report it; \
                         do not work around it by editing operator policies",
                        None,
                    )
                );
                silent_cli_error("embedded managed bundle uncompilable")
            })?
            .into_iter()
            .collect();
    if managed.is_empty() {
        // A binary that embeds no managed policies can't be shadowed.
        // (Distinct from a compile FAILURE above — this is an empty but
        // valid bundle. Should never happen given the CI-verified embed.)
        return Ok(LegacySeedOutcome::NoShadow);
    }

    // Per-file operator names via the canonical parser. A parse error
    // here means the operator layer is already broken in a way the
    // daemon would reject; surface it rather than guessing.
    let by_file = permitlayer_core::policy::read_policy_decls_by_file(&policies).map_err(|e| {
        eprint!(
            "{}",
            error_block(
                "setup.operator_policies_unparseable",
                &format!("could not read operator policies in {}: {e}", policies.display()),
                "the error above names the policy file and the parse problem — fix the TOML \
                 syntax in that file, then re-run `sudo agentsso setup` (the policy is your \
                 own config; setup will not delete it for you)",
                None,
            )
        );
        silent_cli_error("operator policies unparseable")
    })?;

    let shadowing = find_shadowing_files(&managed, by_file);

    if shadowing.is_empty() {
        return Ok(LegacySeedOutcome::NoShadow);
    }

    let n = shadowing.len();
    let file_lines =
        shadowing.iter().map(|p| format!("    {}", p.display())).collect::<Vec<_>>().join("\n");

    // Decide: archive or refuse, per the three-state posture.
    let stdin_tty = std::io::stdin().is_terminal();
    // `flag_driven_archive` is the no-prompt flag path (`--upgrade` /
    // `--fresh-install`). It gets a LOUD post-archive notice (AC #11)
    // because, unlike the TTY-Prompt path, it never showed the operator
    // the file list before mutating — a scripted run must still leave an
    // obvious audit trail of what was moved aside.
    let decision = decide_legacy_seed(args.fresh_install, args.upgrade, stdin_tty);
    let flag_driven_archive = decision == LegacySeedDecision::Archive;
    let archive: bool = match decision {
        LegacySeedDecision::Archive => true,
        LegacySeedDecision::Refuse => false,
        LegacySeedDecision::Prompt => {
            // TTY + no flag: prompt (default Yes).
            let heal = crate::repair::prompt::Heal {
                code: "repair.legacy_seed_shadow",
                what: &format!("found {n} policy file(s) duplicated from older agentsso versions"),
                impact: &format!(
                    "{file_lines}\nThese shadow shipped policies and will crash the daemon on boot.\n\
                     They will be archived to policies/.legacy-seed-snapshot-<isotime>/ \
                     (recoverable for ~30 days via `sudo mv`)."
                ),
            };
            match crate::repair::prompt::confirm_tty(&home, &heal, true).await {
                Ok(crate::repair::prompt::Confirm::Yes) => true,
                // Explicit No, or stdin/stderr not a usable TTY after all.
                Ok(_) => false,
                Err(_) => false,
            }
        }
    };

    if !archive {
        eprint!(
            "{}",
            error_block(
                "setup.heal_needs_decision",
                &format!(
                    "found {n} policy file(s) duplicated from older agentsso versions:\n{file_lines}\n\n\
                     setup won't make destructive changes without an explicit choice."
                ),
                "re-run as one of (both move the listed file(s) into a recoverable \
                 policies/.legacy-seed-snapshot-<isotime>/ dir, then continue):\n  \
                 sudo agentsso setup --upgrade         # keep all your config; just archive the shadow(s)\n  \
                 sudo agentsso setup --fresh-install   # archive the shadow(s) AND wipe operator state for a clean slate",
                None,
            )
        );
        let _ = crate::repair::journal::record(
            &home,
            "legacy_seed_detect",
            crate::repair::journal::JournalResult::Fail,
            &[("n", &n.to_string()), ("decision", "refused")],
        );
        return Err(silent_cli_error("legacy-seed shadow needs an explicit flag"));
    }

    // Archive aside (non-destructive rename into a snapshot dir).
    let shadow_refs: Vec<&Path> = shadowing.iter().map(PathBuf::as_path).collect();
    let (snapshot_dir, moved) =
        crate::repair::archive::rename_aside_to_snapshot(&home, "policies", &shadow_refs).map_err(
            |e| {
                eprint!(
                    "{}",
                    error_block(
                        "setup.legacy_seed_archive_failed",
                        &format!("could not archive shadowing policy file(s): {e}"),
                        "check filesystem permissions on the policies/ directory and re-run",
                        None,
                    )
                );
                silent_cli_error("legacy-seed archive failed")
            },
        )?;

    // A partial archive is a FAILURE, not a partial success:
    // `rename_aside_to_snapshot` logs-and-skips per-file rename
    // failures (it returns Ok with a short `moved` list), so if any
    // shadow did not move it is STILL on disk and will crashloop the
    // daemon on the next boot — exactly the failure this heal exists
    // to prevent. Refuse loudly rather than report a hollow success.
    if moved.len() != shadowing.len() {
        let moved_set: std::collections::HashSet<&Path> =
            moved.iter().map(|(orig, _)| orig.as_path()).collect();
        let stuck = shadowing
            .iter()
            .filter(|p| !moved_set.contains(p.as_path()))
            .map(|p| format!("    {}", p.display()))
            .collect::<Vec<_>>()
            .join("\n");
        eprint!(
            "{}",
            error_block(
                "setup.legacy_seed_archive_incomplete",
                &format!(
                    "archived {} of {n} shadowing policy file(s); these could not be moved and \
                     would still crash the daemon:\n{stuck}",
                    moved.len()
                ),
                "the listed file(s) are blocking the daemon; archiving them did not complete \
                 (likely a filesystem-permission issue on policies/). re-run \
                 `sudo agentsso setup --upgrade` to retry the archive",
                None,
            )
        );
        let _ = crate::repair::journal::record(
            &home,
            "legacy_seed_heal",
            crate::repair::journal::JournalResult::Fail,
            &[("moved", &moved.len().to_string()), ("expected", &shadowing.len().to_string())],
        );
        return Err(silent_cli_error("legacy-seed archive incomplete"));
    }

    let _ = crate::repair::journal::record(
        &home,
        "legacy_seed_heal",
        crate::repair::journal::JournalResult::Ok,
        &[("n", &moved.len().to_string()), ("snapshot_dir", &snapshot_dir.display().to_string())],
    );
    // LOUD audit trail for the no-prompt flag path (AC #11): `--upgrade`
    // / `--fresh-install` archived operator-observable state WITHOUT a
    // pre-prompt, so a scripted run must still see exactly what moved and
    // where it can be recovered. The TTY-Prompt path already showed the
    // file list before archiving, so it does not need this.
    if flag_driven_archive {
        let moved_lines = moved
            .iter()
            .map(|(orig, _)| format!("    {}", orig.display()))
            .collect::<Vec<_>>()
            .join("\n");
        eprintln!(
            "{} archived {} legacy-seed shadow file(s) into {} (recoverable for ~30 days):\n{}",
            g.warn,
            moved.len(),
            snapshot_dir.display(),
            moved_lines
        );
    }
    Ok(LegacySeedOutcome::Healed { count: moved.len(), snapshot_dir })
}

/// `symlink(target, <dir>/agentsso.tmp); rename(.tmp, stable)` —
/// atomic on the same filesystem; fsync the parent dir so the swap is
/// durable across a crash.
#[cfg(target_os = "macos")]
fn atomic_symlink_swap(target: &Path, stable: &Path, dir: &Path) -> std::io::Result<()> {
    let tmp = dir.join(format!("agentsso.tmp.{}", std::process::id()));
    // Clean any stale tmp from a prior crashed run.
    let _ = std::fs::remove_file(&tmp);
    std::os::unix::fs::symlink(target, &tmp)?;
    if let Err(e) = std::fs::rename(&tmp, stable) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// Poll `whoami` over the control UDS, then assert symlink integrity +
/// launchd-running. Returns the daemon pid on success, or a
/// human-readable failure reason.
#[cfg(target_os = "macos")]
async fn self_verify(
    expected_version: &str,
    versioned: &Path,
    staged_hash: &str,
    timeout: Duration,
) -> std::result::Result<u32, String> {
    use crate::cli::kill;
    use crate::config::{CliOverrides, DaemonConfig};

    let config = DaemonConfig::load(&CliOverrides::default()).unwrap_or_default();
    let endpoint = kill::resolve_control_endpoint(&config);
    let home = crate::cli::agentsso_home()
        .map_err(|e| format!("could not resolve agentsso home for control token: {e}"))?;

    let start = Instant::now();
    let original_deadline = start + timeout;
    // Row 12: if the last poll failure is the version-mismatch restart
    // race (daemon reports V' ≠ V), extend the deadline ONCE by 10s
    // rather than refuse — a transient restart can outlast 15s. Any
    // other failure mode does not earn the extension.
    let extension = Duration::from_secs(10);
    let interval = Duration::from_millis(250);
    let mut deadline = original_deadline;
    let mut extended = false;
    // Heartbeat every 5s from the start so a slow-but-pre-deadline
    // boot shows visible progress (not only after the deadline).
    let heartbeat_every = Duration::from_secs(5);
    let mut next_heartbeat = start + heartbeat_every;
    let g = glyphs();
    // Latch whether a version-mismatch restart race was seen AT ALL this
    // run — set once, never reset. A transient UDS error on the last
    // poll before the deadline (itself part of a restart) must NOT
    // disqualify the extension the restart race earns; the race was
    // already observed and that's what matters.
    let mut saw_version_race = false;
    let mut last = "control plane never became reachable".to_owned();
    loop {
        if Instant::now() >= deadline {
            // Extend once if a restart race was ever seen; else give up.
            if !extended && saw_version_race {
                extended = true;
                deadline = Instant::now() + extension;
            } else {
                break;
            }
        }
        // Re-read the token every iteration — the daemon mints it on
        // start, so it may not exist on the first poll.
        let token = kill::read_control_token(&home);
        match kill::http_get_via(&endpoint, "/v1/control/whoami", token.as_deref()).await {
            Ok(body) => match parse_whoami_version(&body) {
                Some(v) if v == expected_version => {
                    // Daemon is the right version. Now prove the
                    // symlink topology + content (Decision B: this
                    // replaces an infeasible pid→path check).
                    return finalize_verify(versioned, staged_hash);
                }
                Some(v) => {
                    last = format!(
                        "daemon reports version {v} but {expected_version} was installed \
                         (restart race — still polling)"
                    );
                    saw_version_race = true;
                }
                None => {
                    last = "whoami response had no parseable version field".to_owned();
                }
            },
            Err(_) => {
                last = "control UDS not yet answering".to_owned();
            }
        }
        if Instant::now() >= next_heartbeat {
            println!("{} daemon still starting…", g.arrow);
            next_heartbeat += heartbeat_every;
        }
        tokio::time::sleep(interval).await;
    }
    Err(format!("self-verify timed out after {:?}: {last}", start.elapsed()))
}

/// The non-UDS half of self-verify: the stable symlink resolves to
/// the version we staged, that file is byte-identical to what we
/// staged, and launchd reports the daemon running with a non-zero
/// pid. (Decision B — strongest feasible substitute for pid→path.)
#[cfg(target_os = "macos")]
fn finalize_verify(versioned: &Path, staged_hash: &str) -> std::result::Result<u32, String> {
    use crate::cli::service::install_macos as im;

    let helper_path = Path::new(im::PRIVILEGED_HELPER_PATH);
    let resolved = std::fs::read_link(helper_path)
        .map_err(|e| format!("stable symlink {} unreadable: {e}", helper_path.display()))?;
    // The recorded target is an absolute path under helper_dir; the
    // symlink we wrote is also absolute, so compare directly.
    if resolved != versioned {
        return Err(format!(
            "stable symlink resolves to {} but the active version should be {}",
            resolved.display(),
            versioned.display()
        ));
    }
    let on_disk = sha256_file(versioned)
        .map_err(|e| format!("could not re-hash active binary {}: {e}", versioned.display()))?;
    if on_disk != staged_hash {
        return Err(format!(
            "active binary {} hash {on_disk} != staged hash {staged_hash} (tamper after stage?)",
            versioned.display()
        ));
    }
    // launchd must report it running with a real pid.
    let out = std::process::Command::new("/bin/launchctl")
        .args(["print", "system/dev.permitlayer.daemon"])
        .output()
        .map_err(|e| format!("could not invoke launchctl print: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    match im::parse_launchctl_running(&stdout) {
        Some(pid) => Ok(pid),
        None => Err("launchctl does not report the daemon as `state = running` with a \
                     non-zero pid"
            .to_owned()),
    }
}

/// Best-effort post-rollback reachability poll. After `rollback`
/// re-bootstraps the prior binary we want to confirm the *old* daemon
/// actually came back and report which version it is — but unlike
/// `self_verify` we do NOT know the prior version statically, so this
/// asserts only "control plane answers `whoami` with a parseable
/// version" within a short deadline. Returns the recovered version
/// string, or `None` if it never became reachable in time. NEVER
/// fails rollback — this only enriches the operator report.
#[cfg(target_os = "macos")]
async fn poll_recovered_version(timeout: Duration) -> Option<String> {
    use crate::cli::kill;
    use crate::config::{CliOverrides, DaemonConfig};

    let config = DaemonConfig::load(&CliOverrides::default()).unwrap_or_default();
    let endpoint = kill::resolve_control_endpoint(&config);
    let home = crate::cli::agentsso_home().ok()?;

    let start = Instant::now();
    let deadline = start + timeout;
    let interval = Duration::from_millis(250);
    // Row 13: emit a progress heartbeat every 5s so a long rollback
    // recovery shows visible progress instead of silent waiting.
    let heartbeat_every = Duration::from_secs(5);
    let mut next_heartbeat = start + heartbeat_every;
    let g = glyphs();
    while Instant::now() < deadline {
        let token = kill::read_control_token(&home);
        if let Ok(body) =
            kill::http_get_via(&endpoint, "/v1/control/whoami", token.as_deref()).await
            && let Some(v) = parse_whoami_version(&body)
        {
            return Some(v);
        }
        if Instant::now() >= next_heartbeat {
            println!("{} rollback still in progress…", g.arrow);
            next_heartbeat += heartbeat_every;
        }
        tokio::time::sleep(interval).await;
    }
    None
}

/// Legacy-migration recovery: restore the legacy real binary that was
/// renamed aside to `bak` back to `helper_path`, then re-bootstrap the
/// old daemon. Used ONLY on the pre-symlink-install migration path,
/// where step 7's bootout already brought the daemon down and there is
/// no `prior_target` symlink for [`rollback`] to restore. Emits a
/// TRUTHFUL structured error stating exactly what was (or wasn't)
/// recovered — never the "old target still in place" claim, which is
/// false once the legacy binary has been moved.
#[cfg(target_os = "macos")]
async fn restore_legacy_and_rebootstrap(
    g: &Glyphs,
    bak: &Path,
    helper_path: &Path,
    cause: &str,
) -> Result<()> {
    use crate::cli::service::install_macos as im;

    eprintln!("{} setup failed: {cause}", g.warn);
    eprintln!(
        "{} restoring the prior (pre-symlink) binary {} → {}",
        g.arrow,
        bak.display(),
        helper_path.display()
    );
    // The symlink swap may or may not have created a symlink at
    // `helper_path`; remove whatever is there so the rename can
    // re-establish the real binary.
    let _ = std::fs::remove_file(helper_path);
    let restored = std::fs::rename(bak, helper_path).is_ok();
    if restored {
        // bootout-then-bootstrap to bring the restored binary's daemon
        // back (step 7 already booted the old one out).
        let _ = im::bootout_daemon();
        let rebootstrapped = im::launchctl_bootstrap_system().is_ok();
        if rebootstrapped {
            match poll_recovered_version(Duration::from_secs(15)).await {
                Some(recovered) => {
                    eprint!(
                        "{}",
                        error_block(
                            "setup.rolled_back",
                            &format!(
                                "setup failed ({cause}); the prior pre-symlink binary was \
                                 restored to {} and re-bootstrapped (daemon {recovered} is \
                                 back and answering)",
                                helper_path.display()
                            ),
                            "investigate the failure cause above, then re-run \
                             `sudo agentsso setup`",
                            None,
                        )
                    );
                }
                None => {
                    eprint!(
                        "{}",
                        error_block(
                            "setup.rollback_incomplete",
                            &format!(
                                "setup failed ({cause}); the prior pre-symlink binary was \
                                 restored to {} and re-bootstrapped, but the control plane \
                                 did not confirm the daemon is back within 5s — it may still \
                                 be starting",
                                helper_path.display()
                            ),
                            "check /Library/Logs/permitlayer/daemon.log and \
                             `sudo launchctl print system/dev.permitlayer.daemon`; if the \
                             daemon is down, re-run `sudo agentsso setup`",
                            None,
                        )
                    );
                }
            }
        } else {
            eprint!(
                "{}",
                error_block(
                    "setup.rollback_incomplete",
                    &format!(
                        "setup failed ({cause}); the prior pre-symlink binary was restored \
                         to {} but re-bootstrap failed — the daemon may be down",
                        helper_path.display()
                    ),
                    "manually run `sudo launchctl bootstrap system \
                     /Library/LaunchDaemons/dev.permitlayer.daemon.plist` and check \
                     /Library/Logs/permitlayer/daemon.log",
                    None,
                )
            );
        }
    } else {
        // Restore itself failed — the daemon is down and the legacy
        // binary could not be put back. Be explicit; the staged
        // versioned binary is intact, so the recovery is a re-run.
        eprint!(
            "{}",
            error_block(
                "setup.failed_no_rollback",
                &format!(
                    "setup failed ({cause}) AND the prior pre-symlink binary could not be \
                     restored from {} — the daemon is down. The staged versioned binary is \
                     intact under {}",
                    bak.display(),
                    helper_path
                        .parent()
                        .unwrap_or(Path::new("/Library/PrivilegedHelperTools"))
                        .display()
                ),
                "check /Library/Logs/permitlayer/daemon.log, then re-run \
                 `sudo agentsso setup`",
                None,
            )
        );
    }
    Err(silent_cli_error("setup failed (see rollback report)"))
}

/// Roll the symlink back to `prior_target` and re-bootstrap. Emits a
/// structured error and returns the silent-cli error so the caller
/// just `return rollback(...).await`.
#[cfg(target_os = "macos")]
async fn rollback(
    g: &Glyphs,
    prior_target: Option<&Path>,
    helper_path: &Path,
    helper_dir: &Path,
    cause: &str,
) -> Result<()> {
    use crate::cli::service::install_macos as im;

    eprintln!("{} setup failed: {cause}", g.warn);
    match prior_target {
        Some(prior) if prior.exists() => {
            eprintln!("{} rolling back to prior binary {}", g.arrow, prior.display());
            let swap_ok = atomic_symlink_swap(prior, helper_path, helper_dir).is_ok();
            let _ = im::bootout_daemon();
            let boot_ok = im::launchctl_bootstrap_system().is_ok();
            if swap_ok && boot_ok {
                // Re-verify the old daemon actually came back reachable
                // and report its whoami.version. Best-effort: if it
                // does not answer within the deadline, the rollback
                // mechanics still succeeded (symlink + bootstrap) but
                // we downgrade the report so the operator knows the
                // control plane has not yet confirmed liveness.
                match poll_recovered_version(Duration::from_secs(15)).await {
                    Some(recovered) => {
                        eprint!(
                            "{}",
                            error_block(
                                "setup.rolled_back",
                                &format!(
                                    "setup failed ({cause}); the prior binary at {} was \
                                     restored and re-bootstrapped (daemon {recovered} is back \
                                     and answering)",
                                    prior.display()
                                ),
                                "investigate the failure cause above, then re-run \
                                 `sudo agentsso setup`",
                                None,
                            )
                        );
                    }
                    None => {
                        eprint!(
                            "{}",
                            error_block(
                                "setup.rollback_incomplete",
                                &format!(
                                    "setup failed ({cause}); the prior binary at {} was \
                                     restored and re-bootstrapped, but the control plane did \
                                     not confirm the daemon is back within 5s — it may still \
                                     be starting, or rollback did not fully recover",
                                    prior.display()
                                ),
                                "check /Library/Logs/permitlayer/daemon.log and \
                                 `sudo launchctl print system/dev.permitlayer.daemon`; if the \
                                 daemon is down, re-run `sudo agentsso setup`",
                                None,
                            )
                        );
                    }
                }
            } else {
                eprint!(
                    "{}",
                    error_block(
                        "setup.rollback_incomplete",
                        &format!(
                            "setup failed ({cause}) AND rollback did not fully succeed \
                             (symlink_restored={swap_ok}, rebootstrapped={boot_ok}) — the \
                             daemon may be down"
                        ),
                        "manually run `sudo launchctl bootstrap system \
                         /Library/LaunchDaemons/dev.permitlayer.daemon.plist` and check \
                         /Library/Logs/permitlayer/daemon.log",
                        None,
                    )
                );
            }
        }
        _ => {
            // First install (no prior to roll back to) — daemon may
            // be down; nothing we can restore.
            eprint!(
                "{}",
                error_block(
                    "setup.failed_no_rollback",
                    &format!(
                        "setup failed ({cause}) and there was no prior binary to roll back \
                         to (first install)"
                    ),
                    "check /Library/Logs/permitlayer/daemon.log, then re-run \
                     `sudo agentsso setup`",
                    None,
                )
            );
        }
    }
    Err(silent_cli_error("setup failed (see rollback report)"))
}

/// Keep the current version + the single most-recent other version;
/// delete older `agentsso-<semver>` binaries. Best-effort.
#[cfg(target_os = "macos")]
fn gc_old_versions(g: &Glyphs, helper_dir: &Path, current_version: &str) {
    let Ok(entries) = std::fs::read_dir(helper_dir) else {
        return;
    };
    // (semver, path) for every agentsso-<parseable-semver> file.
    let mut versioned: Vec<(semver::Version, PathBuf)> = Vec::new();
    for e in entries.flatten() {
        let path = e.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        // Sweep a stale `agentsso.legacy-bak.<pid>` crumb left behind
        // if a prior run crashed between the legacy rename-aside and
        // the success cleanup. Safe to delete unconditionally here:
        // any in-flight setup holds the install-lock, so a crumb seen
        // now is necessarily orphaned.
        if name.starts_with("agentsso.legacy-bak.") {
            if std::fs::remove_file(&path).is_ok() {
                println!("  {} gc: removed stale legacy-binary crumb {}", g.check, path.display());
            }
            continue;
        }
        let Some(ver_str) = name.strip_prefix("agentsso-") else {
            continue;
        };
        // Skip the stable symlink itself and tmp crumbs.
        if ver_str.contains(".tmp.") || ver_str.is_empty() {
            continue;
        }
        if let Ok(v) = semver::Version::parse(ver_str) {
            versioned.push((v, path));
        }
    }
    let Ok(current) = semver::Version::parse(current_version) else {
        return;
    };
    // Sort descending by semver.
    versioned.sort_by(|a, b| b.0.cmp(&a.0));
    // Keep: the current version, plus the highest version that isn't
    // the current one (the "previous" rollback target).
    let mut kept_other = false;
    for (v, path) in &versioned {
        if *v == current {
            continue; // always keep current
        }
        if !kept_other {
            kept_other = true; // keep the most-recent non-current
            continue;
        }
        if std::fs::remove_file(path).is_ok() {
            println!("  {} gc: removed old {}", g.check, path.display());
        }
    }
}

// Story 10.4 AC #4.2: a cross-platform source-scan gate asserting no
// operator-facing refusal remediation in this file instructs a manual
// `sudo rm` / "remove … manually". This is the cheapest durable guard
// against the anti-pattern creeping back. It is NOT macOS-gated (it
// scans source text, not behavior) so it runs on every CI platform.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod refusal_copy_gate {
    /// The full source of this module.
    const SELF_SRC: &str = include_str!("mod.rs");

    /// Robust marker: this module's `mod` line is the cut point. Built
    /// at runtime (not a literal of the whole phrase) so it can't itself
    /// be the first textual match.
    fn module_decl_marker() -> String {
        format!("mod {}", "refusal_copy_gate")
    }

    #[test]
    fn no_remediation_copy_instructs_manual_rm() {
        // Only scan PRODUCTION source — stop at this test module, whose
        // own source contains these phrases as string literals and would
        // self-trip. Cut at this module's `mod` declaration line. Fail
        // loudly (not vacuously pass) if the marker is ever absent.
        let marker = module_decl_marker();
        let cut = SELF_SRC.find(&marker).expect("refusal_copy_gate module marker must be present");
        let prod_src = &SELF_SRC[..cut];
        // AC #4.2 pattern: `sudo rm` | `rm -` | "manually remove" |
        // "remove … manually" (any-order). Code-comment lines (`//`) are
        // skipped — the explanatory comments that mention these phrases
        // are not operator-facing remediation copy.
        let simple = ["sudo rm", "rm -", "manually remove"];
        for (lineno, raw) in prod_src.lines().enumerate() {
            if raw.trim_start().starts_with("//") {
                continue;
            }
            let lower = raw.to_lowercase();
            // "remove … manually" in either word order on the same line.
            let remove_then_manually =
                lower.find("remove").is_some_and(|i| lower[i..].contains("manual"));
            assert!(
                !remove_then_manually,
                "refusal-copy gate (AC #4.2): line {} has a 'remove … manually' \
                 instruction in non-comment source:\n  {}",
                lineno + 1,
                raw.trim()
            );
            for pat in simple {
                assert!(
                    !lower.contains(pat),
                    "refusal-copy gate (AC #4.2): line {} contains forbidden \
                     manual-removal phrase {:?} in non-comment source:\n  {}",
                    lineno + 1,
                    pat,
                    raw.trim()
                );
            }
        }
    }
}

#[cfg(all(test, target_os = "macos"))]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Test-only wrapper so `SetupArgs` (a `clap::Args`, not a
    /// top-level `Parser`) can be parsed from an argv fixture.
    #[derive(clap::Parser, Debug)]
    struct TestCli {
        #[command(flatten)]
        args: SetupArgs,
    }

    #[test]
    fn fresh_install_and_upgrade_flags_conflict_at_clap() {
        use clap::Parser as _;
        // Both flags set must fail at parse time, before any setup
        // code runs.
        let result = TestCli::try_parse_from(["agentsso", "--fresh-install", "--upgrade"]);
        assert!(result.is_err(), "--fresh-install and --upgrade must conflict");
        // Each flag alone is accepted.
        assert!(TestCli::try_parse_from(["agentsso", "--fresh-install"]).is_ok());
        assert!(TestCli::try_parse_from(["agentsso", "--upgrade"]).is_ok());
        // --replace-binary composes with either.
        assert!(
            TestCli::try_parse_from(["agentsso", "--fresh-install", "--replace-binary"]).is_ok()
        );
        assert!(TestCli::try_parse_from(["agentsso", "--upgrade", "--replace-binary"]).is_ok());
    }

    // ── Legacy-seed three-state posture truth table (Task 3) ────────

    #[test]
    fn legacy_seed_fresh_install_archives_regardless_of_tty() {
        assert_eq!(decide_legacy_seed(true, false, true), LegacySeedDecision::Archive);
        assert_eq!(decide_legacy_seed(true, false, false), LegacySeedDecision::Archive);
    }

    // Story 10.4 (decision B): `--upgrade` now ARCHIVES (was Refuse).
    // This is the key behavior-change pin — `--upgrade` preserves
    // operator config but archives the daemon-crashing shadow so the
    // on-screen remedy makes progress instead of looping.
    #[test]
    fn legacy_seed_upgrade_archives_regardless_of_tty() {
        assert_eq!(decide_legacy_seed(false, true, true), LegacySeedDecision::Archive);
        assert_eq!(decide_legacy_seed(false, true, false), LegacySeedDecision::Archive);
    }

    #[test]
    fn legacy_seed_tty_no_flag_prompts() {
        assert_eq!(decide_legacy_seed(false, false, true), LegacySeedDecision::Prompt);
    }

    // The ONLY remaining Refuse path: non-TTY with no flag. Both flags
    // (--upgrade / --fresh-install) now make progress, so the
    // heal_needs_decision remedy can never loop.
    #[test]
    fn legacy_seed_non_tty_no_flag_refuses() {
        assert_eq!(decide_legacy_seed(false, false, false), LegacySeedDecision::Refuse);
    }

    // ── Versioned-binary decision (row 6) truth table ───────────────

    #[test]
    fn versioned_binary_absent_stages() {
        // No file yet → stage, regardless of the flag.
        assert_eq!(decide_versioned_binary(false, false, false), VersionedBinaryAction::Stage);
        assert_eq!(decide_versioned_binary(false, false, true), VersionedBinaryAction::Stage);
    }

    #[test]
    fn versioned_binary_present_matching_is_idempotent() {
        // Exists, bytes match → no-op, regardless of the flag.
        assert_eq!(
            decide_versioned_binary(true, false, false),
            VersionedBinaryAction::AlreadyStaged
        );
        assert_eq!(
            decide_versioned_binary(true, false, true),
            VersionedBinaryAction::AlreadyStaged
        );
    }

    #[test]
    fn versioned_binary_mismatch_refuses_without_flag() {
        // Exists, bytes differ, no --replace-binary → refuse (the
        // apt/dpkg/rpm conservative default; never silently overwrite).
        assert_eq!(decide_versioned_binary(true, true, false), VersionedBinaryAction::Refuse);
    }

    #[test]
    fn versioned_binary_mismatch_replaces_with_flag() {
        // Exists, bytes differ, --replace-binary → atomic replace.
        assert_eq!(decide_versioned_binary(true, true, true), VersionedBinaryAction::Replace);
    }

    // ── Detection logic (find_shadowing_files) ──────────────────────

    fn names_set(names: &[&str]) -> std::collections::HashSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    /// Build a `PolicyDecl` with no override marker.
    fn decl(name: &str) -> permitlayer_core::policy::PolicyDecl {
        permitlayer_core::policy::PolicyDecl { name: name.to_owned(), override_marker: None }
    }

    /// Build a `PolicyDecl` carrying an override marker.
    fn decl_override(name: &str, marker: &str) -> permitlayer_core::policy::PolicyDecl {
        permitlayer_core::policy::PolicyDecl {
            name: name.to_owned(),
            override_marker: Some(marker.to_owned()),
        }
    }

    #[test]
    fn find_shadowing_flags_only_overlapping_files() {
        let managed = names_set(&["default", "gmail-read-only"]);
        let by_file = vec![
            // Shadows: declares "default" (unmarked).
            (PathBuf::from("/p/default.toml"), vec![decl("default")]),
            // Operator-authored, no overlap → untouched.
            (PathBuf::from("/p/my-ops.toml"), vec![decl("ops-calendar")]),
            // Multi-policy file where ONE name overlaps (unmarked) → shadows.
            (PathBuf::from("/p/bundle.toml"), vec![decl("custom"), decl("gmail-read-only")]),
        ];
        let shadowing = find_shadowing_files(&managed, by_file);
        assert_eq!(shadowing.len(), 2);
        assert!(shadowing.iter().any(|p| p.ends_with("default.toml")));
        assert!(shadowing.iter().any(|p| p.ends_with("bundle.toml")));
        assert!(!shadowing.iter().any(|p| p.ends_with("my-ops.toml")));
    }

    #[test]
    fn find_shadowing_empty_when_no_overlap() {
        let managed = names_set(&["default"]);
        let by_file = vec![(PathBuf::from("/p/ops.toml"), vec![decl("ops")])];
        assert!(find_shadowing_files(&managed, by_file).is_empty());
    }

    #[test]
    fn find_shadowing_spares_marked_override() {
        // F1 regression guard: a legitimately MARKED override of a
        // managed name (`name = "default"` + `override = "default"`)
        // compiles cleanly and must NOT be archived. Only the unmarked
        // collision in the same set is a shadow.
        let managed = names_set(&["default", "gmail-read-only"]);
        let by_file = vec![
            // Marked override → spared.
            (PathBuf::from("/p/marked.toml"), vec![decl_override("default", "default")]),
            // Unmarked collision → shadow.
            (PathBuf::from("/p/legacy.toml"), vec![decl("gmail-read-only")]),
            // Override marker pointing at a DIFFERENT name than the
            // declaration's own name does NOT spare it (that's a
            // DanglingOverrideMarker class, still a collision on the
            // declared managed name).
            (PathBuf::from("/p/mismatched.toml"), vec![decl_override("default", "something-else")]),
        ];
        let shadowing = find_shadowing_files(&managed, by_file);
        assert!(!shadowing.iter().any(|p| p.ends_with("marked.toml")), "marked override spared");
        assert!(shadowing.iter().any(|p| p.ends_with("legacy.toml")), "unmarked collision flagged");
        assert!(
            shadowing.iter().any(|p| p.ends_with("mismatched.toml")),
            "override marker must match the declaration's own name to spare it"
        );
        assert_eq!(shadowing.len(), 2);
    }

    // ── Archival mechanics end-to-end (real tempdir fs) ─────────────
    //
    // The full `detect_and_heal_legacy_seed_shadow` reads process-global
    // home/TTY, but its load-bearing pieces — name detection via the
    // canonical parser + non-destructive archival — are exercised here
    // against a real filesystem. (The interactive root+TTY prompt path
    // is verified in the epic-closeout operator pass, consistent with
    // the launchctl-bootstrap-in-CI boundary.)

    #[test]
    fn legacy_seed_archival_moves_shadow_keeps_others() {
        let home = tempfile::tempdir().unwrap();
        let policies = home.path().join("policies");
        std::fs::create_dir_all(&policies).unwrap();
        // Shadow file (name "default" overlaps the managed bundle).
        std::fs::write(
            policies.join("default.toml"),
            "[[policies]]\nname = \"default\"\nscopes = []\nresources = [\"*\"]\napproval-mode = \"deny\"\n",
        )
        .unwrap();
        // Operator-authored, non-shadow.
        std::fs::write(
            policies.join("my-ops.toml"),
            "[[policies]]\nname = \"ops-calendar\"\nscopes = [\"calendar.readonly\"]\nresources = [\"*\"]\napproval-mode = \"auto\"\n",
        )
        .unwrap();

        // Detect via the canonical parser.
        let by_file = permitlayer_core::policy::read_policy_decls_by_file(&policies).unwrap();
        let managed = names_set(&["default"]);
        let shadowing = find_shadowing_files(&managed, by_file);
        assert_eq!(shadowing.len(), 1);

        // Archive the shadow aside.
        let refs: Vec<&Path> = shadowing.iter().map(PathBuf::as_path).collect();
        let (snapshot_dir, moved) =
            crate::repair::archive::rename_aside_to_snapshot(home.path(), "policies", &refs)
                .unwrap();
        assert_eq!(moved.len(), 1);
        // Shadow gone from the live dir, present in the snapshot.
        assert!(!policies.join("default.toml").exists(), "shadow moved out");
        assert!(snapshot_dir.join("default.toml").is_file(), "shadow in snapshot");
        // Non-shadow untouched.
        assert!(policies.join("my-ops.toml").exists(), "operator file untouched");

        // Journal records the heal.
        crate::repair::journal::record(
            home.path(),
            "legacy_seed_heal",
            crate::repair::journal::JournalResult::Ok,
            &[("n", "1")],
        )
        .unwrap();
        let journal = std::fs::read_to_string(home.path().join("logs/setup-journal.log")).unwrap();
        assert!(journal.contains("step=legacy_seed_heal result=ok n=1"));
    }

    #[test]
    fn parse_whoami_version_extracts() {
        assert_eq!(
            parse_whoami_version(r#"{"pid":7,"version":"0.3.0-rc.36"}"#),
            Some("0.3.0-rc.36".to_owned())
        );
        assert_eq!(parse_whoami_version(r#"{"pid":7}"#), None);
        assert_eq!(parse_whoami_version("not json"), None);
    }

    #[test]
    fn sha256_file_is_stable_and_distinguishes_content() {
        let d = tempfile::tempdir().unwrap();
        let a = d.path().join("a");
        let b = d.path().join("b");
        std::fs::write(&a, b"hello").unwrap();
        std::fs::write(&b, b"hello").unwrap();
        assert_eq!(sha256_file(&a).unwrap(), sha256_file(&b).unwrap());
        std::fs::write(&b, b"world").unwrap();
        assert_ne!(sha256_file(&a).unwrap(), sha256_file(&b).unwrap());
        // Known vector for "hello".
        assert_eq!(
            sha256_file(&a).unwrap(),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn atomic_symlink_swap_repoints_and_is_idempotent() {
        let d = tempfile::tempdir().unwrap();
        let v1 = d.path().join("agentsso-0.1.0");
        let v2 = d.path().join("agentsso-0.2.0");
        std::fs::write(&v1, b"one").unwrap();
        std::fs::write(&v2, b"two").unwrap();
        let stable = d.path().join("agentsso");

        atomic_symlink_swap(&v1, &stable, d.path()).unwrap();
        assert_eq!(std::fs::read_link(&stable).unwrap(), v1);
        // Re-point (upgrade) — replaces the existing symlink.
        atomic_symlink_swap(&v2, &stable, d.path()).unwrap();
        assert_eq!(std::fs::read_link(&stable).unwrap(), v2);
        // No tmp crumb left behind.
        assert!(
            !d.path().join(format!("agentsso.tmp.{}", std::process::id())).exists(),
            "swap must not leave a tmp symlink"
        );
    }

    #[test]
    fn gc_keeps_current_and_one_previous() {
        let d = tempfile::tempdir().unwrap();
        for v in ["0.1.0", "0.2.0", "0.3.0", "0.3.0-rc.36"] {
            std::fs::write(d.path().join(format!("agentsso-{v}")), v.as_bytes()).unwrap();
        }
        // A non-versioned file + the stable symlink-name must be
        // untouched.
        std::fs::write(d.path().join("README"), b"x").unwrap();
        std::fs::write(d.path().join("agentsso"), b"sym").unwrap();

        let g = Glyphs { arrow: "->", check: "ok", warn: "!" };
        gc_old_versions(&g, d.path(), "0.3.0");

        assert!(d.path().join("agentsso-0.3.0").exists(), "current kept");
        // Highest non-current is 0.3.0-rc.36? No — 0.3.0 > 0.3.0-rc.36
        // in semver (release > its prerelease). Descending order:
        // 0.3.0, 0.3.0-rc.36, 0.2.0, 0.1.0. Current=0.3.0 skipped;
        // first non-current kept = 0.3.0-rc.36; rest deleted.
        assert!(d.path().join("agentsso-0.3.0-rc.36").exists(), "most-recent non-current kept");
        assert!(!d.path().join("agentsso-0.2.0").exists(), "older deleted");
        assert!(!d.path().join("agentsso-0.1.0").exists(), "older deleted");
        assert!(d.path().join("README").exists(), "non-versioned untouched");
        assert!(d.path().join("agentsso").exists(), "stable symlink-name untouched");
    }
}
