//! Shared recovery primitives consumed by both `cli::setup` and
//! `cli::doctor`.
//!
//! **Story 10.1 ships this module standalone**; Stories 10.2
//! (setup self-heals at ~14 refusal sites) and 10.3 (doctor
//! truthfulness via `IoKind`) consume these primitives. Until
//! those stories merge, every public item is dead code from the
//! binary's perspective — each submodule file declares
//! `#![allow(dead_code)]` to silence the warnings under the daemon
//! crate's `-D warnings` clippy gate. Remove those allows once
//! Story 10.2 lands.
//!
//! Introduced in Epic 10 (rc.41) to back the self-healing setup
//! posture (FR8a) and doctor truthfulness fixes (FR8b). The polestar
//! is "operator never has to be a Unix mastermind": setup heals what
//! it can, prompts before touching operator-observable state, refuses
//! only for genuine human decisions. Doctor reports the truth via
//! the same `IoKind` classification this module provides.
//!
//! # Submodules
//!
//! - [`retry`] — generic with-backoff retry + classifier + jittered
//!   schedule constants. Backs the legacy `launchctl_bootstrap_system_inner`
//!   EIO-retry shape, generalized for any transient-error class.
//! - [`fs_repair`] — atomic file operations + `classify_io_kind`.
//!   The classifier is shared with doctor (Story 10.3).
//! - [`wipe`] — operator-state wipe with policy (`All` for
//!   `--fresh-install`; `Predicate` for the legacy-seed heal).
//! - [`archive`] — `rename_aside_to_snapshot` moves shadowing files
//!   into a timestamped snapshot dir; operator-recoverable for ≤30
//!   days, then GC'd by `doctor --fix` (Story 10.3).
//! - [`prompt`] — `dialoguer::Confirm` wrapper with TTY detection +
//!   the project's teal-theme convention.
//! - [`sudo`] — self-elevation under sudo when setup is invoked
//!   without it. First sudo self-elevation in the codebase.
//! - [`journal`] — append-only one-line-per-step log at
//!   `/Library/Logs/permitlayer/setup-journal.log`. Forensic trail
//!   for setup runs; complements `daemon.log` (operational state).
//!
//! # Consumers
//!
//! - `cli::setup` calls `retry`, `fs_repair`, `wipe`, `archive`,
//!   `prompt`, `sudo`, and `journal` at the ~14 refusal sites Story
//!   10.2 rewrites.
//! - `cli::doctor` reuses `fs_repair::classify_io_kind` for the
//!   EACCES distinction in `managed_policy_staleness` and
//!   `operator_layer_compile` (Story 10.3).
//!
//! # Design references
//!
//! - Rev-5 plan: `~/.claude/plans/linked-petting-starlight.md` § A
//! - SCP: `_bmad-output/planning-artifacts/sprint-change-proposal-2026-05-21.md`
//! - Epic charter: `_bmad-output/planning-artifacts/epics.md` Epic 10
//! - Story file: `_bmad-output/implementation-artifacts/10-1-repair-module-and-launchctl-refactor.md`

pub(crate) mod archive;
pub(crate) mod fs_repair;
pub(crate) mod journal;
pub(crate) mod prompt;
pub(crate) mod retry;
#[cfg(unix)]
pub(crate) mod sudo;
pub(crate) mod wipe;
