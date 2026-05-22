#![allow(dead_code)]
//! Generic with-backoff retry + classifier-driven decision + jittered
//! schedule constants.
//!
//! This module generalizes the rc.40 `launchctl_bootstrap_system_inner`
//! EIO-retry shape (see `cli/service/install_macos.rs:1326-1452`)
//! into a primitive callable from any transient-error site.
//!
//! # Shape
//!
//! ```ignore
//! let result = with_backoff(
//!     || some_fallible_op(),
//!     |err| if err.is_transient() { RetryDecision::Retry } else { RetryDecision::Final },
//!     LAUNCHCTL_RACE,
//! );
//! ```
//!
//! Both sync ([`with_backoff`]) and async ([`with_backoff_async`])
//! variants are provided. The sync variant takes an injectable
//! `sleep: impl FnMut(Duration)` parameter for testability.
//!
//! # Jitter
//!
//! Each scheduled delay is multiplied by `1.0 ± 0.2` (uniform random)
//! to prevent phase-locked re-collisions on kernel-level races.
//! Standard production-retry-lib discipline (AWS SDK, gRPC, et al).

use rand::Rng;
use std::time::Duration;

/// The classifier's decision on whether an error should retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RetryDecision {
    /// The error is transient; retry with the next scheduled delay.
    Retry,
    /// The error is terminal; return immediately.
    Final,
}

/// Fast transient-error schedule (50/150/400 ms with ±20% jitter).
/// Suitable for file I/O retries where the contention is expected
/// to clear within ~600 ms total. Worst-case wall time ~720 ms after
/// jitter.
pub(crate) const TRANSIENT_FAST: &[Duration] =
    &[Duration::from_millis(50), Duration::from_millis(150), Duration::from_millis(400)];

/// Launchctl-race schedule (250/500/1000 ms with ±20% jitter).
/// Matches the rc.40 `BACKOFFS` const in `install_macos.rs`; used for
/// launchctl bootstrap retries where the kernel-level race takes
/// longer to clear. Worst-case wall time ~2.1s after jitter.
pub(crate) const LAUNCHCTL_RACE: &[Duration] =
    &[Duration::from_millis(250), Duration::from_millis(500), Duration::from_millis(1000)];

/// Apply ±20% uniform jitter to a scheduled delay. Public for tests
/// only; production code goes through [`with_backoff`] /
/// [`with_backoff_async`].
#[doc(hidden)]
pub(crate) fn jittered(d: Duration) -> Duration {
    let factor: f64 = rand::thread_rng().gen_range(0.8..=1.2);
    let nanos = d.as_nanos() as f64 * factor;
    Duration::from_nanos(nanos as u64)
}

/// Generic with-backoff retry — **exact schedule, no jitter**.
///
/// Calls `op` up to `schedule.len() + 1` times. After each failure,
/// `classify(&err)` decides whether to retry. If `Retry`, the next
/// element of `schedule` is passed to `sleep` verbatim; if `Final`,
/// returns the error immediately. After exhausting the schedule,
/// returns the last error.
///
/// The `sleep` parameter is injectable so unit tests can capture
/// the observed delays without actually sleeping. The schedule is
/// honored exactly — tests can assert `observed == schedule` slice
/// equality. Use this variant when call-site tests need
/// deterministic timing (e.g. the launchctl bootstrap retry).
///
/// For general transient-error retries that benefit from jitter
/// (kernel-level races where many callers could phase-lock), use
/// [`with_backoff_jittered`].
pub(crate) fn with_backoff<F, T, E, C, S>(
    mut op: F,
    classify: C,
    schedule: &[Duration],
    mut sleep: S,
) -> Result<T, E>
where
    F: FnMut() -> Result<T, E>,
    C: Fn(&E) -> RetryDecision,
    S: FnMut(Duration),
{
    let max_attempts = schedule.len() + 1;
    for attempt in 0..max_attempts {
        match op() {
            Ok(value) => return Ok(value),
            Err(err) => {
                let decision = classify(&err);
                if decision == RetryDecision::Final || attempt == schedule.len() {
                    return Err(err);
                }
                sleep(schedule[attempt]);
            }
        }
    }
    // Unreachable: the loop above always returns from inside (either
    // Ok on success, or Err on Final classification / schedule
    // exhaustion). Rust's type checker can't see that, so we encode
    // the impossibility explicitly.
    unreachable!("with_backoff loop terminated without returning")
}

/// Generic with-backoff retry with **±20% uniform jitter** on each
/// scheduled delay.
///
/// Standard production-retry-lib discipline (AWS SDK, gRPC, et al)
/// to prevent phase-locked re-collisions when many callers retry
/// on the same kernel-level race. Use for transient I/O retries
/// (`fs_repair::remove_file_with_retry`); use the non-jittered
/// [`with_backoff`] when call-site tests need deterministic timing.
pub(crate) fn with_backoff_jittered<F, T, E, C, S>(
    mut op: F,
    classify: C,
    schedule: &[Duration],
    mut sleep: S,
) -> Result<T, E>
where
    F: FnMut() -> Result<T, E>,
    C: Fn(&E) -> RetryDecision,
    S: FnMut(Duration),
{
    let max_attempts = schedule.len() + 1;
    for attempt in 0..max_attempts {
        match op() {
            Ok(value) => return Ok(value),
            Err(err) => {
                let decision = classify(&err);
                if decision == RetryDecision::Final || attempt == schedule.len() {
                    return Err(err);
                }
                sleep(jittered(schedule[attempt]));
            }
        }
    }
    unreachable!("with_backoff_jittered loop terminated without returning")
}

/// Async variant of [`with_backoff`]. Uses `tokio::time::sleep`
/// internally (no injectable sleep — tokio's test runtime pauses
/// time itself).
///
/// **Cancellation:** this future is NOT cancel-safe. If the caller
/// drops the future between attempts (e.g. inside a `tokio::select!`
/// branch that loses the race), any side effects from `op()`s that
/// already ran are observable but the per-attempt state (which
/// `op` returned what) is lost. Callers needing cancel-safety
/// should wrap the call in `tokio::spawn(...).await` so the inner
/// future runs to completion regardless of the caller's lifetime.
pub(crate) async fn with_backoff_async<F, Fut, T, E, C>(
    mut op: F,
    classify: C,
    schedule: &[Duration],
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
    C: Fn(&E) -> RetryDecision,
{
    let max_attempts = schedule.len() + 1;
    for attempt in 0..max_attempts {
        match op().await {
            Ok(value) => return Ok(value),
            Err(err) => {
                let decision = classify(&err);
                if decision == RetryDecision::Final || attempt == schedule.len() {
                    return Err(err);
                }
                let delay = jittered(schedule[attempt]);
                tokio::time::sleep(delay).await;
            }
        }
    }
    unreachable!("with_backoff_async loop terminated without returning")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// Always-transient classifier for tests.
    fn classify_always_retry<E>(_: &E) -> RetryDecision {
        RetryDecision::Retry
    }

    /// Always-terminal classifier for tests.
    fn classify_always_final<E>(_: &E) -> RetryDecision {
        RetryDecision::Final
    }

    #[test]
    fn with_backoff_succeeds_on_first_attempt() {
        let observed: RefCell<Vec<Duration>> = RefCell::new(Vec::new());
        let attempts = RefCell::new(0u32);
        let result: Result<&str, ()> = with_backoff(
            || {
                *attempts.borrow_mut() += 1;
                Ok("first")
            },
            |_| RetryDecision::Retry,
            TRANSIENT_FAST,
            |d| observed.borrow_mut().push(d),
        );
        assert_eq!(result.unwrap(), "first");
        assert_eq!(*attempts.borrow(), 1);
        assert!(observed.borrow().is_empty(), "no sleeps should occur on first-attempt success");
    }

    #[test]
    fn with_backoff_retries_transient_then_succeeds() {
        let observed: RefCell<Vec<Duration>> = RefCell::new(Vec::new());
        let attempts = RefCell::new(0u32);
        let result: Result<&str, &str> = with_backoff(
            || {
                let n = *attempts.borrow() + 1;
                *attempts.borrow_mut() = n;
                if n < 3 { Err("transient") } else { Ok("ok") }
            },
            classify_always_retry,
            TRANSIENT_FAST,
            |d| observed.borrow_mut().push(d),
        );
        assert_eq!(result.unwrap(), "ok");
        assert_eq!(*attempts.borrow(), 3);
        assert_eq!(observed.borrow().len(), 2, "two sleeps before the third attempt");
        // Exact schedule honored (no jitter): sleeps == schedule[0..2].
        assert_eq!(observed.borrow().as_slice(), &[TRANSIENT_FAST[0], TRANSIENT_FAST[1]],);
    }

    #[test]
    fn with_backoff_returns_immediately_on_final_classification() {
        let attempts = RefCell::new(0u32);
        let observed: RefCell<Vec<Duration>> = RefCell::new(Vec::new());
        let result: Result<&str, &str> = with_backoff(
            || {
                *attempts.borrow_mut() += 1;
                Err("terminal")
            },
            classify_always_final,
            TRANSIENT_FAST,
            |d| observed.borrow_mut().push(d),
        );
        assert!(result.is_err());
        assert_eq!(*attempts.borrow(), 1, "terminal classification means one attempt only");
        assert!(observed.borrow().is_empty());
    }

    #[test]
    fn with_backoff_exhausts_schedule_then_returns_last_error() {
        let attempts = RefCell::new(0u32);
        let observed: RefCell<Vec<Duration>> = RefCell::new(Vec::new());
        let result: Result<&str, u32> = with_backoff(
            || {
                let n = *attempts.borrow() + 1;
                *attempts.borrow_mut() = n;
                Err(n)
            },
            classify_always_retry,
            TRANSIENT_FAST,
            |d| observed.borrow_mut().push(d),
        );
        // 4 attempts total = 1 initial + 3 retries; final error is 4.
        assert_eq!(result.unwrap_err(), 4);
        assert_eq!(*attempts.borrow(), 4);
        assert_eq!(observed.borrow().len(), 3, "three sleeps for three retries");
        assert_eq!(observed.borrow().as_slice(), TRANSIENT_FAST);
    }

    #[test]
    fn jittered_stays_within_plus_minus_20_percent() {
        // Sample many times — the jitter is randomized per call, so
        // we want statistical confidence that the bound holds.
        let scheduled = Duration::from_millis(1000);
        let low = Duration::from_millis(800);
        let high = Duration::from_millis(1200);
        for _ in 0..1000 {
            let actual = jittered(scheduled);
            assert!(
                actual >= low && actual <= high,
                "jittered({scheduled:?}) = {actual:?} outside [{low:?}, {high:?}]"
            );
        }
    }

    #[test]
    fn with_backoff_jittered_observes_delays_within_plus_minus_20_percent() {
        let observed: RefCell<Vec<Duration>> = RefCell::new(Vec::new());
        let _: Result<(), ()> = with_backoff_jittered(
            || Err(()),
            classify_always_retry,
            TRANSIENT_FAST,
            |d| observed.borrow_mut().push(d),
        );
        let observed = observed.borrow();
        assert_eq!(observed.len(), 3);
        // Each observed delay should be within ±20% of the scheduled.
        for (i, &actual) in observed.iter().enumerate() {
            let scheduled = TRANSIENT_FAST[i];
            let low = Duration::from_nanos((scheduled.as_nanos() as f64 * 0.8) as u64);
            let high = Duration::from_nanos((scheduled.as_nanos() as f64 * 1.2) as u64);
            assert!(
                actual >= low && actual <= high,
                "attempt {i}: observed {actual:?} outside [{low:?}, {high:?}] of scheduled {scheduled:?}"
            );
        }
    }

    #[tokio::test]
    async fn with_backoff_async_succeeds_first_attempt() {
        let attempts = RefCell::new(0u32);
        let result: Result<&str, ()> = with_backoff_async(
            || {
                *attempts.borrow_mut() += 1;
                async { Ok("first") }
            },
            |_| RetryDecision::Retry,
            TRANSIENT_FAST,
        )
        .await;
        assert_eq!(result.unwrap(), "first");
        assert_eq!(*attempts.borrow(), 1);
    }

    #[tokio::test]
    async fn with_backoff_async_retries_transient_then_succeeds() {
        let attempts = RefCell::new(0u32);
        let result: Result<&str, &str> = with_backoff_async(
            || {
                let n = *attempts.borrow() + 1;
                *attempts.borrow_mut() = n;
                async move { if n < 3 { Err("transient") } else { Ok("ok") } }
            },
            |_| RetryDecision::Retry,
            // Use very-short schedule so the test runs fast.
            &[Duration::from_millis(1), Duration::from_millis(1)],
        )
        .await;
        assert_eq!(result.unwrap(), "ok");
        assert_eq!(*attempts.borrow(), 3);
    }
}
