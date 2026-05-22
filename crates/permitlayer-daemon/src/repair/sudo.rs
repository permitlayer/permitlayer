#![allow(dead_code)]
//! Self-elevation under sudo.
//!
//! First sudo self-elevation in the codebase. Story 10.2 wires this
//! into `cli/setup/mod.rs:178`: when the operator runs `agentsso
//! setup` without sudo on a TTY, setup announces re-exec and calls
//! [`reexec_under_sudo`]. Operator sees one sudo password prompt
//! (from sudo itself, not from us) and setup continues as root.
//!
//! Matches Determinate nix-installer + Homebrew patterns:
//! announce-and-go rather than double-prompt. The operator's
//! invocation of `agentsso setup` IS the declaration of intent.
//!
//! Escape hatch: `AGENTSSO_NO_SUDO_ELEVATE=1` disables the heal —
//! the call to [`should_self_elevate`] returns false and setup
//! refuses with the existing `setup.requires_root` error.
//!
//! `CommandExt::exec()` is safe under `#![forbid(unsafe_code)]`
//! (the trait method itself is safe; the underlying syscall safety
//! is handled inside libstd).
//!
//! Cfg-gated `#[cfg(unix)]` at the module level (see `repair/mod.rs`)
//! because `CommandExt` doesn't exist on Windows.

use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Environment variable an operator can set to opt out of the
/// sudo self-elevation heal. If set (to any value), setup refuses
/// without attempting re-exec.
const NO_ELEVATE_ENV: &str = "AGENTSSO_NO_SUDO_ELEVATE";

/// Pure-fn truth table for [`should_self_elevate`]. Extracted so the
/// four meaningful input combinations are unit-testable without
/// process-global state (uid, tty fd, env vars). The wrapper
/// [`should_self_elevate`] reads the live state and delegates here.
pub(crate) fn should_self_elevate_decision(
    is_root: bool,
    stdin_is_tty: bool,
    no_elevate_env_set: bool,
) -> bool {
    !is_root && stdin_is_tty && !no_elevate_env_set
}

/// Return `true` iff setup should attempt sudo self-elevation:
/// - effective uid is not root,
/// - stdin is a TTY (interactive operator can respond to sudo's
///   password prompt),
/// - the `AGENTSSO_NO_SUDO_ELEVATE` env var is NOT set (any value,
///   including empty string, opts out — we check presence, not
///   content).
pub(crate) fn should_self_elevate() -> bool {
    use std::io::IsTerminal as _;
    should_self_elevate_decision(
        nix::unistd::Uid::effective().is_root(),
        std::io::stdin().is_terminal(),
        std::env::var_os(NO_ELEVATE_ENV).is_some(),
    )
}

/// Build the argv passed to `sudo`. Pure-fn for testability —
/// [`reexec_under_sudo`] composes the live `std::env::args()` and
/// `std::env::current_exe()` and calls this. Preserves whitespace
/// in args without re-quoting (each arg travels as a separate
/// CString to `execvp`).
pub(crate) fn build_sudo_argv(args: &[String], current_exe: &Path) -> Vec<String> {
    let mut argv: Vec<String> = Vec::with_capacity(args.len() + 4);
    argv.push("/usr/bin/sudo".to_owned());
    argv.push(
        "--preserve-env=RUST_LOG,AGENTSSO_PATHS__HOME,AGENTSSO_LOG_FORMAT,NO_COLOR,TERM".to_owned(),
    );
    argv.push("--".to_owned());
    argv.push(current_exe.to_string_lossy().into_owned());
    // Skip args[0] (the original binary path) — `current_exe` is
    // the absolute path we want sudo to invoke, not whatever
    // argv[0] was (which could be a brew shim, a symlink, or
    // relative).
    for arg in args.iter().skip(1) {
        argv.push(arg.clone());
    }
    argv
}

/// Re-execute the current process under `sudo`. Returns ONLY on
/// exec failure (sudo missing, etc.); on success, the current
/// process is replaced by sudo and never returns from this call.
///
/// `#[allow(dead_code)]` because Story 10.1 ships the primitive but
/// Story 10.2 does the wire-in at `cli/setup/mod.rs:178`. Without
/// the allow, `cargo clippy --all-features -- -D warnings` fails.
#[allow(dead_code)]
pub(crate) fn reexec_under_sudo() -> std::io::Error {
    let args: Vec<String> = std::env::args().collect();
    // Resolve the binary sudo should re-invoke. `current_exe()` is
    // the canonical path; if it fails AND argv[0] isn't absolute,
    // refuse rather than fall through to PATH resolution under root
    // (which would let an attacker-controlled PATH pick the binary).
    let current_exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            let argv0 = args.first().map(PathBuf::from);
            match argv0 {
                Some(p) if p.is_absolute() => p,
                _ => {
                    return std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("cannot resolve self-exe for sudo re-exec: {e}"),
                    );
                }
            }
        }
    };
    let argv = build_sudo_argv(&args, &current_exe);
    // First arg to Command::new is the executable; remaining are args.
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    cmd.exec()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn build_sudo_argv_preserves_spaces_in_original_args() {
        let args = vec![
            "agentsso".to_owned(),
            "setup".to_owned(),
            "--from".to_owned(),
            "/path with spaces/agentsso".to_owned(),
        ];
        let current_exe = Path::new("/usr/local/bin/agentsso");
        let argv = build_sudo_argv(&args, current_exe);
        assert_eq!(argv[0], "/usr/bin/sudo");
        assert_eq!(
            argv[1],
            "--preserve-env=RUST_LOG,AGENTSSO_PATHS__HOME,AGENTSSO_LOG_FORMAT,NO_COLOR,TERM"
        );
        assert_eq!(argv[2], "--");
        assert_eq!(argv[3], "/usr/local/bin/agentsso");
        assert_eq!(argv[4], "setup");
        assert_eq!(argv[5], "--from");
        // The space-containing arg is preserved as a single
        // element (NOT re-quoted, NOT split).
        assert_eq!(argv[6], "/path with spaces/agentsso");
        assert_eq!(argv.len(), 7);
    }

    #[test]
    fn build_sudo_argv_uses_current_exe_not_argv0() {
        let args = vec![
            // argv[0] is a shim path (e.g. brew's wrapper).
            "/opt/homebrew/bin/agentsso".to_owned(),
            "setup".to_owned(),
        ];
        // current_exe is the canonical resolved path.
        let current_exe = Path::new("/opt/homebrew/Cellar/agentsso/0.3.0-rc.41/bin/agentsso");
        let argv = build_sudo_argv(&args, current_exe);
        // argv[3] is the exe sudo will run — must be `current_exe`,
        // not the original argv[0].
        assert_eq!(argv[3], current_exe.to_string_lossy().to_string());
    }

    #[test]
    fn build_sudo_argv_env_list_includes_all_required() {
        let args = vec!["agentsso".to_owned(), "setup".to_owned()];
        let argv = build_sudo_argv(&args, Path::new("/x"));
        let preserve_env = &argv[1];
        // Parse the `--preserve-env=A,B,C` arg into the actual list
        // of env-var names. We can't use substring-on-the-whole-string
        // because e.g. `AGENTSSO_PATHS__HOME` substring-matches `HOME`,
        // creating false positives for the "NOT preserved" assertions
        // below.
        let preserve_list: Vec<&str> = preserve_env
            .strip_prefix("--preserve-env=")
            .expect("arg 1 should start with --preserve-env=")
            .split(',')
            .collect();
        assert!(preserve_list.contains(&"RUST_LOG"));
        assert!(preserve_list.contains(&"AGENTSSO_PATHS__HOME"));
        assert!(preserve_list.contains(&"AGENTSSO_LOG_FORMAT"));
        assert!(preserve_list.contains(&"NO_COLOR"));
        assert!(preserve_list.contains(&"TERM"));
        // HOME and PATH intentionally NOT preserved — sudo's
        // defaults for root are correct (secure_path; root's HOME).
        assert!(!preserve_list.contains(&"HOME"));
        assert!(!preserve_list.contains(&"PATH"));
    }

    #[test]
    fn build_sudo_argv_empty_args_after_argv0_works() {
        // If args only has argv[0] (no other args), the resulting
        // sudo argv has just sudo + preserve-env + -- + exe.
        let args = vec!["agentsso".to_owned()];
        let argv = build_sudo_argv(&args, Path::new("/x"));
        assert_eq!(argv.len(), 4);
    }

    // ── should_self_elevate_decision truth table ───────────────────
    //
    // Four meaningful combinations of (is_root, stdin_is_tty,
    // no_elevate_env_set). Only `(false, true, false)` elevates.

    #[test]
    fn should_self_elevate_decision_yes_when_non_root_tty_no_optout() {
        assert!(should_self_elevate_decision(false, true, false));
    }

    #[test]
    fn should_self_elevate_decision_no_when_already_root() {
        assert!(!should_self_elevate_decision(true, true, false));
    }

    #[test]
    fn should_self_elevate_decision_no_when_stdin_not_tty() {
        assert!(!should_self_elevate_decision(false, false, false));
    }

    #[test]
    fn should_self_elevate_decision_no_when_opt_out_env_set() {
        assert!(!should_self_elevate_decision(false, true, true));
    }

    #[test]
    fn should_self_elevate_decision_no_when_every_disqualifier_present() {
        // Defense-in-depth: any single disqualifier suffices, all
        // three is still no.
        assert!(!should_self_elevate_decision(true, false, true));
    }

    #[test]
    fn no_elevate_env_constant_name_is_documented_value() {
        // Pin the env var name in tests — operators rely on this
        // spelling per the module docstring's escape-hatch note.
        assert_eq!(NO_ELEVATE_ENV, "AGENTSSO_NO_SUDO_ELEVATE");
    }
}
