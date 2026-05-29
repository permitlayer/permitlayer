//! Cross-user file writing for daemon→client handoff.
//!
//! On the privileged macOS install the daemon runs as root and MCP
//! clients (the operator's agent) run as the operator's user. A file the
//! daemon writes for a client to read must be made group-readable to the
//! `permitlayer-clients` group — the same mechanism `control.token` uses
//! (`0o640 root:permitlayer-clients`). On single-user tiers (Linux /
//! `~/.agentsso`) the agent IS the operator, so `0o600` suffices.
//!
//! This module extracts that write-and-reconcile pattern (previously
//! inlined in the daemon's `control_token` minting) so both the daemon
//! lifecycle code and the proxy can share one audited implementation.
//! `permitlayer-proxy` cannot depend on `permitlayer-daemon`, so the
//! shared helper lives here in core (both depend on core).

use std::io::Write as _;
use std::path::Path;

/// Error writing a client-readable file.
#[derive(Debug, thiserror::Error)]
pub enum FileWriteError {
    #[error("I/O error writing {path}: {source}")]
    Io {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("path {0} has no parent directory")]
    NoParent(std::path::PathBuf),
}

/// Atomically write `bytes` to `path`, then make the file readable by the
/// MCP client.
///
/// Write discipline (identical to `control.token` minting): a sibling
/// temp file is opened mode `0o600` (Unix) so the restrictive mode
/// travels through `rename` with no world-readable window, contents are
/// `fsync`ed, then `rename`d into place. On macOS the file is then
/// reconciled to `0o640 root:permitlayer-clients` for cross-user read
/// (graceful fallback: if the group is absent the file stays `0o600` —
/// never widened). On Linux/Windows the `0o600` (or ACL-owner) mode is
/// left as-is; the agent runs as the same user.
///
/// The parent directory must already exist with appropriate perms (the
/// caller / setup owns directory creation + traversal bits).
pub fn write_client_readable_file(path: &Path, bytes: &[u8]) -> Result<(), FileWriteError> {
    let parent = path.parent().ok_or_else(|| FileWriteError::NoParent(path.to_path_buf()))?;
    std::fs::create_dir_all(parent)
        .map_err(|source| FileWriteError::Io { path: parent.to_path_buf(), source })?;

    let tmp_path = path.with_extension("tmp");
    {
        let mut f = open_tmp(&tmp_path)?;
        f.write_all(bytes)
            .map_err(|source| FileWriteError::Io { path: tmp_path.clone(), source })?;
        f.sync_all().map_err(|source| FileWriteError::Io { path: tmp_path.clone(), source })?;
    }
    std::fs::rename(&tmp_path, path)
        .map_err(|source| FileWriteError::Io { path: path.to_path_buf(), source })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Defense-in-depth: re-assert 0o600 (no-op given the tmp open mode).
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|source| FileWriteError::Io { path: path.to_path_buf(), source })?;
    }

    #[cfg(target_os = "macos")]
    reconcile_macos_client_group(path);

    Ok(())
}

/// Open the temp file with a restrictive mode from creation, so the mode
/// is correct before any data lands at the final path post-rename.
fn open_tmp(tmp_path: &Path) -> Result<std::fs::File, FileWriteError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(tmp_path)
            .map_err(|source| FileWriteError::Io { path: tmp_path.to_path_buf(), source })
    }
    #[cfg(not(unix))]
    {
        // Windows: files created under the per-user `%USERPROFILE%` tree
        // inherit owner-scoped ACLs; no mode bits to set.
        std::fs::File::create(tmp_path)
            .map_err(|source| FileWriteError::Io { path: tmp_path.to_path_buf(), source })
    }
}

/// macOS: chgrp the file to `permitlayer-clients` + chmod `0o640` so a
/// client running as the operator (a group member) can read it. Mirrors
/// `control_token::reconcile_macos_cross_user_perms` exactly, including
/// the fail-closed semantics: any failure RE-NARROWS to `0o600` and never
/// widens. Best-effort + logged (cannot fail the write — the file is
/// already at `0o600`, which is safe, just not cross-user-readable).
#[cfg(target_os = "macos")]
fn reconcile_macos_client_group(path: &Path) {
    if !nix::unistd::getuid().is_root() {
        // Non-root (single-user dev / tests): leave at 0o600. The agent
        // is the same user; group reconciliation is neither possible nor
        // needed.
        return;
    }
    use std::os::unix::fs::PermissionsExt;
    match nix::unistd::Group::from_name("permitlayer-clients") {
        Ok(Some(group)) => {
            let chown_result = nix::unistd::chown(
                path,
                Some(nix::unistd::Uid::from_raw(0)),
                Some(nix::unistd::Gid::from_raw(group.gid.as_raw())),
            );
            if let Err(e) = chown_result {
                // Fail closed: re-narrow to 0o600 so a prior group-read
                // mode can't linger.
                let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
                tracing::warn!(
                    target: "media_file",
                    event = "media_file.chgrp_failed",
                    path = %path.display(),
                    error = %e,
                    "failed to chgrp media file to permitlayer-clients; re-narrowed to 0o600"
                );
            } else if let Err(e) =
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o640))
            {
                tracing::warn!(
                    target: "media_file",
                    event = "media_file.chmod_failed",
                    path = %path.display(),
                    error = %e,
                    "chgrp'd media file but chmod 0640 failed; agent may not be able to read it"
                );
            }
        }
        Ok(None) => {
            tracing::warn!(
                target: "media_file",
                event = "media_file.permitlayer_clients_group_missing",
                path = %path.display(),
                "permitlayer-clients group not found — media file stays 0600 root-only; \
                 the agent will not be able to read it. Run `sudo agentsso setup`."
            );
        }
        Err(e) => {
            tracing::warn!(
                target: "media_file",
                event = "media_file.permitlayer_clients_lookup_failed",
                path = %path.display(),
                error = %e,
                "nss lookup for permitlayer-clients group failed — media file stays 0600 root-only"
            );
        }
    }
}

/// Decode Gmail-style URL-safe base64 that MAY carry `=` padding.
///
/// Gmail's `messages.attachments.get` returns `data` as base64url; the
/// core decoder ([`crate::agent::base64_url_no_pad_decode`]) is no-pad, so
/// strip any trailing `=` first. Returns `None` on any non-alphabet byte.
pub fn decode_base64url_maybe_padded(s: &str) -> Option<Vec<u8>> {
    let trimmed = s.trim_end_matches('=');
    crate::agent::base64_url_no_pad_decode(trimmed)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn writes_file_with_contents() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("out.bin");
        write_client_readable_file(&path, b"hello bytes").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"hello bytes");
    }

    #[cfg(unix)]
    #[test]
    fn non_root_write_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.bin");
        write_client_readable_file(&path, b"x").unwrap();
        // In the test process (non-root) the macOS reconcile is a no-op,
        // so the mode is the restrictive 0o600 the write asserts.
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn no_leftover_tmp_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.bin");
        write_client_readable_file(&path, b"x").unwrap();
        assert!(!path.with_extension("tmp").exists());
    }

    #[test]
    fn decode_padded_and_unpadded_base64url() {
        // "hello" → aGVsbG8 (no pad) / aGVsbG8= would be standard; base64url
        // of "hi" is "aGk" (no pad). Verify padded input decodes.
        let unpadded = crate::agent::base64_url_no_pad_encode(b"hi");
        let padded = format!("{unpadded}=");
        assert_eq!(decode_base64url_maybe_padded(&unpadded).unwrap(), b"hi");
        assert_eq!(decode_base64url_maybe_padded(&padded).unwrap(), b"hi");
    }
}
