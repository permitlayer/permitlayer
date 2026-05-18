//! On-disk schema-migration framework.
//!
//! **UX-overhaul epic (Story 3) re-host:** this framework was
//! previously triggered from the deleted `agentsso update --apply`
//! orchestrator. `agentsso update` is now a drift detector that
//! performs no filesystem mutation. On-disk schema migration belongs
//! on the daemon boot path — where the daemon, before serving any
//! request, brings the persistent vault/credential schema up to the
//! version the running binary understands. The trigger now lives in
//! `cli::start::run` (see the `migrations::apply_pending` call after
//! the boot-time vault-lock release, before the TCP bind).
//!
//! The registry ships the first real migration today
//! ([`envelope_v1_to_v2`]); a future [`SEALED_CREDENTIAL_VERSION`][1]
//! increment or an `AUDIT_SCHEMA_VERSION` bump slots in by appending
//! one entry to [`registry`].
//!
//! # Reversibility
//!
//! Migrations are forward-only. Reversibility is provided by Story
//! 2's versioned-symlink rollback: a failed upgrade re-points the
//! `<helper-dir>/agentsso` symlink at the prior versioned binary and
//! re-bootstraps it; the old binary still understands the
//! pre-migration on-disk schema because [`apply_pending`] is invoked
//! only by the *new* binary's boot path and is contractually
//! idempotent (a migration that has already run is a no-op). If the
//! new binary's first boot fails the migration, it refuses to serve
//! (fail-closed) and `setup` rolls the symlink back.
//!
//! # Audit emission
//!
//! [`apply_pending`] returns a [`MigrationOutcome`] that the boot
//! path emits as the `daemon-migrations-applied` audit event. The
//! `migrations_applied` field is `0` when the registry has no
//! pending work.
//!
//! [1]: permitlayer_credential::SEALED_CREDENTIAL_VERSION

use std::path::Path;

use thiserror::Error;

mod envelope_v1_to_v2;

/// A single forward migration. See module docs.
///
/// # Why this framework ships empty at MVP
///
/// Per `feedback_no_lazy_deferrals.md` (saved memory): "fix issues
/// now whenever possible; defer ONLY when blocked by a hard future-
/// story dependency". Punting the framework would force Story 7.6
/// (rotate-key) to re-litigate the same design when it bumps
/// `SEALED_CREDENTIAL_VERSION` for the first real schema change.
/// Shipping the trait + registry empty + smoke-tested today means
/// Story 7.6 (and any future schema bump) appends one entry to
/// [`registry`] and the wiring is already proven.
///
/// # Schema-version source of truth
///
/// The audit-schema policy at `permitlayer-core::audit::event:30`
/// commits to `schema_version: u32` forward-compat for additive
/// fields; `permitlayer-credential::SEALED_CREDENTIAL_VERSION = 1`
/// and `permitlayer-plugins::host_api::HOST_API_VERSION = "1.0.0-rc.1"`
/// are the other two version anchors. The first migration that
/// ships will most likely target a `SEALED_CREDENTIAL_VERSION`
/// bump (rotate-key) or an `AUDIT_SCHEMA_VERSION = 3` bump (a
/// breaking audit-field rename or removal). At that point the
/// migration's `apply` function reads the on-disk version and
/// writes the new schema atomically.
///
/// **Review patch P18 (F27 — Auditor).** Doc-comment now points
/// at the `audit/event.rs:30` schema-version policy AND the
/// `feedback_no_lazy_deferrals.md` rationale, per spec AC #3.
#[allow(dead_code)] // No registered migrations at MVP — exercised by tests + future stories.
pub(crate) trait Migration: Send + Sync {
    /// Stable identifier for audit logging — kebab-case,
    /// e.g., `"audit-schema-v2-to-v3"`.
    fn id(&self) -> &'static str;

    /// Apply the migration. Receives the resolved `~/.agentsso/`
    /// path. MUST be idempotent: re-running on an already-migrated
    /// tree returns `Ok(())` without error.
    fn apply(&self, home: &Path) -> Result<(), MigrationError>;
}

/// Outcome of [`apply_pending`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MigrationOutcome {
    /// No migrations were registered, OR all registered migrations
    /// were already applied (idempotent).
    NoChange,
    /// One or more migrations ran. `ids` is the list of applied
    /// migration identifiers in the order they ran.
    Applied { ids: Vec<&'static str> },
}

impl MigrationOutcome {
    /// Number of migrations that ran. `0` for [`NoChange`].
    #[must_use]
    pub(crate) fn count(&self) -> u32 {
        match self {
            Self::NoChange => 0,
            Self::Applied { ids } => u32::try_from(ids.len()).unwrap_or(u32::MAX),
        }
    }

    /// Identifiers of migrations that ran. Empty for [`NoChange`].
    #[must_use]
    pub(crate) fn ids(&self) -> &[&'static str] {
        match self {
            Self::NoChange => &[],
            Self::Applied { ids } => ids,
        }
    }
}

/// Errors that abort the migration. The daemon boot path
/// (`cli::start::run`) propagates these as a fail-closed
/// `StartError` — the daemon refuses to serve a half-migrated
/// vault, and Story 2's `setup` rolls the versioned symlink back to
/// the prior binary.
#[derive(Debug, Error)]
#[allow(dead_code)] // Only `Custom` is constructed in tests today.
pub(crate) enum MigrationError {
    #[error("migration {id} ({ctx}): {source}")]
    Io {
        id: &'static str,
        /// Step description (e.g. `"rename vault to backup"`) so the
        /// operator-facing message names which point in the migration
        /// failed.
        ctx: &'static str,
        source: std::io::Error,
    },

    #[error("migration {id}: {message}")]
    Custom { id: &'static str, message: String },

    /// Verification step failed AFTER the rewrite — backup is preserved
    /// at `backup_path`. Distinguishes "rewrite produced bad bytes" from
    /// pre-rewrite IO/filesystem failures so forensics retains the
    /// `io::Error` source chain.
    #[error("migration {id}: verification failed; backup preserved at {backup_path}")]
    Verification {
        id: &'static str,
        backup_path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Build the registry of migrations known to this binary.
///
/// Empty at MVP. New migrations append to the returned `Vec` in
/// chronological order. The runner ([`apply_pending`]) walks the
/// registry in order and runs every migration whose `apply` reports
/// real work was needed.
///
/// Returning an owned `Vec` (rather than a `&'static [...]`) keeps
/// the test surface flexible — tests can build their own registry
/// via [`apply_pending_with`].
fn registry() -> Vec<Box<dyn Migration>> {
    // Story 7.6a: first real migration — bump the on-disk
    // SealedCredential envelope from v1 to v2 (adds `key_id: u8`
    // for Story 7.6b's rotate-key v2). See
    // `envelope_v1_to_v2.rs` module docs for the full atomicity
    // model + recovery posture.
    vec![Box::new(envelope_v1_to_v2::EnvelopeV1ToV2)]
}

/// Run any pending migrations.
///
/// `from_version`/`to_version` are forensic-correlation labels only;
/// they do NOT gate which migrations run (the framework is forward-
/// linear and idempotent — every registered migration's `apply` is
/// invoked, and each migration decides for itself whether it has
/// already run). The daemon boot path passes
/// `env!("CARGO_PKG_VERSION")` for both (the running binary is the
/// only version in play — there is no separate "target release"
/// since the apply/swap flow was deleted in the UX-overhaul epic).
///
/// # Errors
///
/// Returns the first migration that fails. The daemon boot path
/// (`cli::start::run`) MUST treat `Err` as fail-closed — refuse to
/// serve (via `StartError::SchemaMigrationFailed`) rather than run
/// against a half-migrated vault.
pub(crate) async fn apply_pending(
    home: &Path,
    _from_version: &str,
    _to_version: &str,
) -> Result<MigrationOutcome, MigrationError> {
    apply_pending_with(home, registry()).await
}

/// Test seam — accepts an explicit registry so unit tests can inject
/// a mock migration without mutating global state.
pub(crate) async fn apply_pending_with(
    home: &Path,
    registry: Vec<Box<dyn Migration>>,
) -> Result<MigrationOutcome, MigrationError> {
    if registry.is_empty() {
        return Ok(MigrationOutcome::NoChange);
    }

    let mut applied: Vec<&'static str> = Vec::with_capacity(registry.len());
    for migration in &registry {
        let id = migration.id();
        let home = home.to_path_buf();
        // **Review patch P2 (F2 — Blind + Edge):** wrap the
        // migration's `apply` in `std::panic::catch_unwind` so a
        // panicking migration produces a `MigrationError::Custom`
        // the boot path can surface as a fail-closed `StartError`.
        //
        // Without `catch_unwind`, a `migration.apply()` panic
        // would unwind through `apply_pending`'s future, propagate
        // to `cli::start::run`'s `?`, and bypass the structured
        // refuse-to-serve path entirely — the daemon would crash
        // mid-boot with a raw panic instead of a clean exit + an
        // operator-facing diagnostic. This is exactly the failure
        // mode the migration framework is supposed to prevent.
        //
        // `AssertUnwindSafe` is required because trait objects
        // aren't `UnwindSafe` by default. Migrations are pure
        // filesystem mutators (idempotent by contract), so the
        // unwind-safety assertion is honest.
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| migration.apply(&home)));
        match result {
            Ok(Ok(())) => applied.push(id),
            Ok(Err(e)) => return Err(e),
            Err(panic_payload) => {
                // Best-effort: extract the panic message if it's
                // a `&str` or `String`, otherwise stringify the
                // type. Surfaced in the rollback audit event.
                let message = if let Some(s) = panic_payload.downcast_ref::<&str>() {
                    (*s).to_string()
                } else if let Some(s) = panic_payload.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "migration panicked with non-string payload".to_string()
                };
                return Err(MigrationError::Custom { id, message });
            }
        }
    }

    Ok(MigrationOutcome::Applied { ids: applied })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Mock migration whose `apply` increments a shared counter.
    struct MockMigration {
        id: &'static str,
        calls: Arc<AtomicU32>,
        fail_with: Option<&'static str>,
    }

    impl Migration for MockMigration {
        fn id(&self) -> &'static str {
            self.id
        }

        fn apply(&self, _home: &Path) -> Result<(), MigrationError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            match self.fail_with {
                None => Ok(()),
                Some(message) => {
                    Err(MigrationError::Custom { id: self.id, message: message.into() })
                }
            }
        }
    }

    #[tokio::test]
    async fn empty_registry_via_test_seam_returns_no_change() {
        // Story 7.6a: production registry is no longer empty (it
        // ships envelope-v1-to-v2). The framework's own
        // "empty registry → NoChange" invariant is now exercised
        // via the `apply_pending_with` test seam.
        let home = std::env::temp_dir();
        let outcome = apply_pending_with(&home, Vec::new()).await.unwrap();
        assert_eq!(outcome, MigrationOutcome::NoChange);
        assert_eq!(outcome.count(), 0);
        assert!(outcome.ids().is_empty());
    }

    #[tokio::test]
    async fn registered_migration_runs_and_records_id() {
        let home = std::env::temp_dir();
        let calls = Arc::new(AtomicU32::new(0));
        let registry: Vec<Box<dyn Migration>> = vec![Box::new(MockMigration {
            id: "test-migration",
            calls: Arc::clone(&calls),
            fail_with: None,
        })];

        let outcome = apply_pending_with(&home, registry).await.unwrap();
        assert_eq!(outcome, MigrationOutcome::Applied { ids: vec!["test-migration"] });
        assert_eq!(outcome.count(), 1);
        assert_eq!(outcome.ids(), &["test-migration"]);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn migration_failure_returns_first_error() {
        let home = std::env::temp_dir();
        let calls = Arc::new(AtomicU32::new(0));
        let registry: Vec<Box<dyn Migration>> = vec![
            Box::new(MockMigration { id: "first", calls: Arc::clone(&calls), fail_with: None }),
            Box::new(MockMigration {
                id: "second-fails",
                calls: Arc::clone(&calls),
                fail_with: Some("simulated failure"),
            }),
            // This third migration must NOT run — first failure aborts.
            Box::new(MockMigration {
                id: "third-must-not-run",
                calls: Arc::clone(&calls),
                fail_with: None,
            }),
        ];

        let result = apply_pending_with(&home, registry).await;
        match result {
            Err(MigrationError::Custom { id, message }) => {
                assert_eq!(id, "second-fails");
                assert_eq!(message, "simulated failure");
            }
            other => panic!("expected MigrationError::Custom, got {other:?}"),
        }
        // 1st ran (success) + 2nd ran (failed) = 2; 3rd must not have run.
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn idempotent_re_run_is_safe_when_migration_treats_already_applied_as_ok() {
        // Mock-migration's contract: idempotent. Running it twice
        // should report "applied" each time without side-effect drift
        // beyond the call counter. A real migration whose apply
        // detects "already done" should `Ok(())` without modifying
        // disk state — this test asserts the framework re-invokes
        // every entry in the registry on every call, leaving the
        // idempotency contract to each individual migration.
        let home = std::env::temp_dir();
        let calls = Arc::new(AtomicU32::new(0));
        let registry: Vec<Box<dyn Migration>> = vec![Box::new(MockMigration {
            id: "idempotent-migration",
            calls: Arc::clone(&calls),
            fail_with: None,
        })];
        let _ = apply_pending_with(&home, registry).await.unwrap();
        let registry2: Vec<Box<dyn Migration>> = vec![Box::new(MockMigration {
            id: "idempotent-migration",
            calls: Arc::clone(&calls),
            fail_with: None,
        })];
        let outcome = apply_pending_with(&home, registry2).await.unwrap();
        assert_eq!(outcome.count(), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn production_registry_contains_envelope_v1_to_v2() {
        // Story 7.6a: the first real migration ships in this story.
        // The empty-registry invariant from MVP no longer holds.
        let r = registry();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].id(), "envelope-v1-to-v2");
    }

    /// Mock migration that panics inside `apply`. P2 (review F2):
    /// the framework MUST catch the panic and convert it to a
    /// `MigrationError::Custom` so the orchestrator can roll back.
    struct PanickingMigration;

    impl Migration for PanickingMigration {
        fn id(&self) -> &'static str {
            "panicking-migration"
        }

        fn apply(&self, _home: &Path) -> Result<(), MigrationError> {
            panic!("this migration intentionally panics");
        }
    }

    #[tokio::test]
    async fn panicking_migration_is_caught_and_converted_to_error() {
        // Suppress panic-print noise during the test — `set_hook`
        // installs a no-op so the panic doesn't print a giant
        // stack trace to stderr while the test asserts the catch.
        let prev_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));

        let home = std::env::temp_dir();
        let registry: Vec<Box<dyn Migration>> = vec![Box::new(PanickingMigration)];
        let result = apply_pending_with(&home, registry).await;

        // Restore the panic hook for any tests that run after.
        std::panic::set_hook(prev_hook);

        match result {
            Err(MigrationError::Custom { id, message }) => {
                assert_eq!(id, "panicking-migration");
                assert!(
                    message.contains("intentionally panics"),
                    "expected panic message in error; got: {message}"
                );
            }
            other => panic!("expected Custom error from panicking migration, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn panicking_migration_aborts_subsequent_migrations() {
        let prev_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));

        let home = std::env::temp_dir();
        let calls = Arc::new(AtomicU32::new(0));
        let registry: Vec<Box<dyn Migration>> = vec![
            Box::new(PanickingMigration),
            // Subsequent migration must NOT run.
            Box::new(MockMigration {
                id: "must-not-run",
                calls: Arc::clone(&calls),
                fail_with: None,
            }),
        ];
        let result = apply_pending_with(&home, registry).await;

        std::panic::set_hook(prev_hook);

        assert!(result.is_err(), "panic should abort the registry walk");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "subsequent migration must not have been called after panic"
        );
    }
}
