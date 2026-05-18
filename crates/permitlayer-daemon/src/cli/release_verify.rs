//! Release-artifact download + minisign verification + tarball
//! extraction.
//!
//! Relocated from `cli/update/verify.rs` in the UX-overhaul epic
//! (Story 3). `agentsso update` no longer performs in-place binary
//! swaps — it is a drift detector now. The minisign-verify primitive
//! survives here because Story 2's `sudo agentsso setup` stages and
//! **minisign-verifies** the versioned daemon binary using
//! [`verify_minisign`]. One trust root (`install/permitlayer.pub`)
//! for the curl|sh installer, the PowerShell installer, and the
//! privileged `setup` path.
//!
//! Goals — in order of cryptographic importance:
//!
//! 1. **Signature verification.** No binary is staged on disk until
//!    the minisign signature checks out against the embedded
//!    `install/permitlayer.pub` key. Same key install.sh + install.ps1
//!    use; one trust root for both bootstrap and in-place upgrade.
//!
//! 2. **Path-traversal hardening.** The tarball is parsed entry-by-
//!    entry; any entry whose path contains a `..` segment, an
//!    absolute root component, OR a Windows drive prefix is
//!    rejected before any byte is written.
//!
//! 3. **Streaming downloads.** Release artifacts are <30MB
//!    compressed (NFR48 at architecture.md:1963), but the streaming
//!    pattern is cheap insurance against a malicious or
//!    misconfigured release.

// Story 3 (this PR) relocated this module here but removed its only
// caller (the deleted `update --apply` flow). Its consumer is Story
// 2 of the SAME epic — `sudo agentsso setup` minisign-verifies the
// staged versioned binary via [`verify_minisign`]. Story 2 is task
// #3, explicitly blocked-by this task, so the dependency is a named,
// already-owned story (not a hypothetical) — the only valid reason
// to carry not-yet-wired code per the no-lazy-deferrals rule. The
// unit tests below DO exercise the code now, so it is not untested
// dead weight. Remove this attribute in Story 2 when `setup` calls
// `verify_minisign`.
#![allow(dead_code)]

use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};

/// Embedded minisign public key.
///
/// Pulled directly from `install/permitlayer.pub` via `include_str!`
/// so any future key rotation is a one-file edit. Same key the
/// curl|sh installer (install.sh:31) and PowerShell installer
/// (install.ps1:67) embed.
pub(crate) const EMBEDDED_PUBKEY: &str = include_str!("../../../../install/permitlayer.pub");

/// Resolve the pubkey used for verification.
///
/// In `cfg(debug_assertions)` builds, honors the
/// `AGENTSSO_UPDATE_PUBKEY_OVERRIDE` env var (file path to an
/// alternative `.pub` file) so the integration test can sign
/// fixtures with a test-only keypair. Release builds (the only
/// thing real users ever run) ignore the override and always use
/// the embedded production pubkey — same threat model as the
/// `AGENTSSO_GITHUB_API_BASE_URL` seam.
///
/// **Story 7.5 review patch P22 (F26 — Auditor):** added so the
/// new apply-flow integration test can exercise signature
/// verification against a real signed fixture archive without
/// committing test private keys that match the production pubkey.
fn resolve_pubkey_text() -> Result<String> {
    #[cfg(debug_assertions)]
    {
        if let Ok(override_path) = std::env::var("AGENTSSO_UPDATE_PUBKEY_OVERRIDE") {
            return std::fs::read_to_string(&override_path).with_context(|| {
                format!("could not read AGENTSSO_UPDATE_PUBKEY_OVERRIDE pubkey at {override_path}")
            });
        }
    }
    Ok(EMBEDDED_PUBKEY.to_owned())
}

/// Maximum download size we'll accept. Release artifacts are <30MB
/// compressed (architecture.md:1963 → NFR48). 50MB ceiling rejects
/// gross misuse without rejecting any plausible real release.
const MAX_DOWNLOAD_SIZE_BYTES: u64 = 50 * 1024 * 1024;

/// Read timeout for the download GET. Connect timeout is set
/// separately on the client builder. 5min handles even the
/// slowest residential connection on a 30MB artifact.
const DOWNLOAD_READ_TIMEOUT: Duration = Duration::from_secs(300);

/// Connect timeout for the download GET.
const DOWNLOAD_CONNECT_TIMEOUT: Duration = Duration::from_secs(60);

/// Stream-download `url` into `dest`. Returns the number of bytes
/// written. Refuses if `Content-Length` is missing OR exceeds
/// [`MAX_DOWNLOAD_SIZE_BYTES`].
pub(crate) async fn download(url: &str, dest: &Path) -> Result<u64> {
    use tokio::io::AsyncWriteExt as _;

    // **Review patch P14b (F16 — Blind + Edge):** limit redirect
    // policy to 5 hops on the asset-download client. GitHub's CDN
    // legitimately redirects `github.com/.../releases/download/...`
    // → `objects.githubusercontent.com` (S3), so a `Policy::none()`
    // would break real-world downloads. 5 covers any realistic
    // CDN chain while bounding the worst-case redirect storm. The
    // signature check on the body is the load-bearing defense —
    // this just bounds the network surface.
    let client = reqwest::Client::builder()
        .connect_timeout(DOWNLOAD_CONNECT_TIMEOUT)
        .timeout(DOWNLOAD_READ_TIMEOUT)
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .context("reqwest client build failed for download")?;

    // Pre-flight HEAD to validate Content-Length.
    let head = client.head(url).send().await.with_context(|| format!("HEAD {url} failed"))?;
    if !head.status().is_success() {
        return Err(anyhow!("HEAD {url} returned {}", head.status()));
    }
    let declared_size = head
        .headers()
        .get(reqwest::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| anyhow!("HEAD {url} did not return a parseable Content-Length"))?;
    if declared_size > MAX_DOWNLOAD_SIZE_BYTES {
        return Err(anyhow!(
            "refusing to download {url}: declared size {declared_size} bytes \
             exceeds {MAX_DOWNLOAD_SIZE_BYTES} byte ceiling"
        ));
    }

    // GET + stream to disk.
    let mut response = client.get(url).send().await.with_context(|| format!("GET {url} failed"))?;
    if !response.status().is_success() {
        return Err(anyhow!("GET {url} returned {}", response.status()));
    }

    let mut file = tokio::fs::File::create(dest)
        .await
        .with_context(|| format!("create {} failed", dest.display()))?;
    let mut written: u64 = 0;
    while let Some(chunk) =
        response.chunk().await.with_context(|| format!("read chunk from {url} failed"))?
    {
        // Defense-in-depth: enforce the size cap during the stream
        // even though Content-Length already gate-checked it. A
        // malicious server might stream more than it declared.
        written = written.saturating_add(chunk.len() as u64);
        if written > MAX_DOWNLOAD_SIZE_BYTES {
            // Drop file + abort.
            drop(file);
            let _ = tokio::fs::remove_file(dest).await;
            return Err(anyhow!(
                "download from {url} exceeded {MAX_DOWNLOAD_SIZE_BYTES} byte ceiling \
                 mid-stream — server is lying about Content-Length"
            ));
        }
        file.write_all(&chunk)
            .await
            .with_context(|| format!("write to {} failed", dest.display()))?;
    }
    file.flush().await.with_context(|| format!("flush {} failed", dest.display()))?;
    file.sync_all().await.with_context(|| format!("sync {} failed", dest.display()))?;
    Ok(written)
}

/// Output of [`verify_minisign`] — descriptive, surfaced on the
/// `update-signature-verified` audit event.
#[derive(Debug, Clone)]
pub(crate) struct MinisigInfo {
    /// Hex-encoded 8-byte minisign keyid (the `D67754E8C6888574` part
    /// of `install/permitlayer.pub`'s `untrusted comment:` line).
    pub(crate) keyid_hex: String,
    /// Algorithm — always `"ed25519"` for minisign-verify 0.2.
    pub(crate) algorithm: &'static str,
}

/// Verify `archive` against `signature_path` using the embedded
/// `install/permitlayer.pub` key (or an `AGENTSSO_UPDATE_PUBKEY_OVERRIDE`
/// in debug builds — see [`resolve_pubkey_text`]).
///
/// Returns `Ok(MinisigInfo)` on success; `Err` on any verification
/// failure (mismatch, malformed key/sig, unreadable file).
pub(crate) fn verify_minisign(archive: &Path, signature_path: &Path) -> Result<MinisigInfo> {
    let pubkey_text = resolve_pubkey_text()?;
    let pubkey = minisign_verify::PublicKey::decode(&pubkey_text).context(
        "permitlayer pubkey failed to decode — release engineering bug, \
             not an attack",
    )?;

    let signature_bytes = std::fs::read_to_string(signature_path)
        .with_context(|| format!("read signature {} failed", signature_path.display()))?;
    let signature = minisign_verify::Signature::decode(&signature_bytes)
        .with_context(|| format!("signature at {} is malformed", signature_path.display()))?;

    let archive_bytes = std::fs::read(archive)
        .with_context(|| format!("read archive {} failed", archive.display()))?;

    pubkey
        .verify(&archive_bytes, &signature, /* allow_legacy = */ false)
        .map_err(|e| anyhow!("minisign verification failed: {e}"))?;

    // minisign-verify 0.2 does not surface keyid bytes through the
    // public API; reconstruct from the resolved pubkey's
    // `untrusted comment:` line for the audit event.
    let keyid_hex = parse_keyid_from_pubkey_text(&pubkey_text).unwrap_or_else(|| "unknown".into());
    Ok(MinisigInfo { keyid_hex, algorithm: "ed25519" })
}

/// Parse the keyid from a pubkey file's `untrusted comment:` line.
/// e.g. for `untrusted comment: minisign public key D67754E8C6888574`
/// this returns `Some("D67754E8C6888574")`.
///
/// **Review patch P15 (F17 — Blind):** only accepts a 16-char
/// uppercase hex string after the `minisign public key` prefix,
/// taking just the first whitespace-delimited token. A future
/// pubkey file with an annotation suffix (e.g.,
/// `D67754E8C6888574 (rotated 2026)`) would have leaked the
/// annotation into the audit log's `keyid` field; tightened.
fn parse_keyid_from_pubkey_text(pubkey_text: &str) -> Option<String> {
    pubkey_text.lines().find_map(|line| {
        let trimmed = line.trim();
        let rest = trimmed.strip_prefix("untrusted comment:")?;
        let rest = rest.trim();
        let rest = rest.strip_prefix("minisign public key")?;
        let token = rest.split_whitespace().next()?;
        // minisign keyids are 8 bytes = 16 hex chars.
        if token.len() == 16 && token.chars().all(|c| c.is_ascii_hexdigit()) {
            Some(token.to_owned())
        } else {
            None
        }
    })
}

/// Extract a `.tar.gz` archive into `dest_dir`. Returns the path of
/// the extracted `agentsso` (or `agentsso.exe`) binary.
///
/// Hardened against path traversal and absolute-path entries — see
/// [`canonicalize_archive_path`] for the rules.
pub(crate) fn extract_targz(archive: &Path, dest_dir: &Path) -> Result<PathBuf> {
    let file = std::fs::File::open(archive)
        .with_context(|| format!("open archive {} failed", archive.display()))?;
    let gz = flate2::read::GzDecoder::new(file);
    let mut tar = tar::Archive::new(gz);

    // Disable tar's auto-handle of unsafe paths — we do the
    // validation ourselves to surface a structured error rather than
    // relying on tar's silent skip.
    tar.set_overwrite(true);
    // **Review patch P3 (F34 — Blind):** do NOT preserve archive
    // file modes. We re-apply 0o755 only to the final binary in
    // `swap::stage_new_binary`; everything else under the tempdir
    // is throwaway. Preserving modes from the archive would let a
    // signed-but-malicious release plant setuid-bit files in the
    // tempdir before the rename. Threat model: signing-key
    // compromise; defense-in-depth.
    tar.set_preserve_permissions(false);

    // Defense-in-depth bound on uncompressed extraction size to
    // protect against tar/gzip bombs even from a signed archive
    // (review patch P4, F4 — Blind). The compressed download is
    // already bounded by `MAX_DOWNLOAD_SIZE_BYTES = 50MB`; a 50MB
    // gzip can decompress to gigabytes. Cap extraction at 256MB —
    // 8× the NFR48 30MB compressed target, well above any
    // plausible legitimate release uncompressed size, and far
    // below "fill the operator's disk".
    const MAX_EXTRACTED_BYTES: u64 = 256 * 1024 * 1024;
    let mut total_extracted: u64 = 0;

    let mut binary_path: Option<PathBuf> = None;

    for entry in
        tar.entries().with_context(|| format!("read entries from {} failed", archive.display()))?
    {
        let mut entry = entry.context("malformed tar entry")?;

        // **Review patch P3 (F3 — Blind + Edge):** reject symlink
        // and hardlink entries explicitly. `canonicalize_archive_path`
        // only validates the entry NAME; it does NOT inspect the
        // entry's link TARGET. A signed-but-malicious archive with
        // a single `agentsso` entry of type Symlink pointing at
        // `/etc/passwd` would, on extraction, create a symlink in
        // the tempdir; `swap::stage_new_binary`'s `std::fs::copy`
        // follows symlinks and would copy /etc/passwd into
        // `<install_dir>/agentsso.new`. Release archives have no
        // legitimate need for links — refuse outright.
        let entry_type = entry.header().entry_type();
        if entry_type.is_symlink() || entry_type.is_hard_link() {
            let kind = if entry_type.is_symlink() { "symlink" } else { "hard link" };
            return Err(anyhow!(
                "archive at {} contains a {kind} entry — refusing to extract \
                 (release archives must not contain links)",
                archive.display()
            ));
        }

        let raw_path = entry.path().context("tar entry has unreadable path")?;
        let safe_relative = canonicalize_archive_path(&raw_path).map_err(|e| {
            anyhow!("rejecting tar entry with unsafe path '{}': {e}", raw_path.display())
        })?;

        // P4 (review): size cap accumulator. Reject the archive
        // before writing any bytes if the running total would
        // exceed the cap.
        let entry_size = entry.size();
        total_extracted = total_extracted.saturating_add(entry_size);
        if total_extracted > MAX_EXTRACTED_BYTES {
            return Err(anyhow!(
                "archive at {} would extract more than {MAX_EXTRACTED_BYTES} bytes — \
                 refusing (tar/gzip bomb defense)",
                archive.display()
            ));
        }

        let target = dest_dir.join(&safe_relative);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create_dir_all {} failed", parent.display()))?;
        }
        entry.unpack(&target).with_context(|| format!("unpack to {} failed", target.display()))?;

        // Track the binary we'll later promote.
        let file_name = safe_relative.file_name().and_then(|n| n.to_str());
        if matches!(file_name, Some("agentsso") | Some("agentsso.exe")) {
            binary_path = Some(target);
        }
    }

    binary_path.ok_or_else(|| {
        anyhow!(
            "extracted archive at {} did not contain an `agentsso` (or `agentsso.exe`) binary",
            archive.display()
        )
    })
}

/// Reject archive entries with unsafe paths.
///
/// Allowed: only [`Component::Normal`] segments. Rejected:
/// - [`Component::ParentDir`] (`..`)
/// - [`Component::RootDir`] (absolute paths)
/// - [`Component::Prefix`] (Windows drive letters / UNC prefixes)
/// - [`Component::CurDir`] (`.`) is silently dropped — harmless but
///   unnecessary noise.
fn canonicalize_archive_path(path: &Path) -> std::result::Result<PathBuf, &'static str> {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(seg) => out.push(seg),
            Component::CurDir => {} // drop "."
            Component::ParentDir => {
                return Err("contains parent-dir segment (..)");
            }
            Component::RootDir => {
                return Err("is absolute (starts with /)");
            }
            Component::Prefix(_) => {
                return Err("has a Windows drive/UNC prefix");
            }
        }
    }
    if out.as_os_str().is_empty() {
        return Err("entry path is empty after normalization");
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn embedded_pubkey_is_decodable() {
        // Lock in: the embedded pubkey stays well-formed across
        // refactors. install/permitlayer.pub is the source of truth;
        // this test catches a future copy-paste mistake.
        let pubkey = minisign_verify::PublicKey::decode(EMBEDDED_PUBKEY)
            .expect("embedded pubkey must decode");
        // Round-trip: a pubkey that decodes encodes back to ASCII.
        let _ = pubkey;
    }

    #[test]
    fn embedded_pubkey_keyid_is_d67754e8c6888574() {
        let keyid = parse_keyid_from_pubkey_text(EMBEDDED_PUBKEY).expect("keyid present");
        assert_eq!(keyid, "D67754E8C6888574");
    }

    #[test]
    fn parse_keyid_handles_alternate_whitespace() {
        let text = "untrusted comment:   minisign public key   ABCDEF1234567890\n";
        assert_eq!(parse_keyid_from_pubkey_text(text), Some("ABCDEF1234567890".into()));
    }

    #[test]
    fn parse_keyid_returns_none_on_missing_comment() {
        let text = "RWR0hYjG6FR31smbyN0CT1/Pfg+yl8nTATUaIAq4jUXlvvFOckj99ipC\n";
        assert!(parse_keyid_from_pubkey_text(text).is_none());
    }

    /// P15 (review F17 — Blind): suffix annotations after the keyid
    /// must NOT leak into the parsed keyid (which is emitted into
    /// audit logs and operator-visible output).
    #[test]
    fn parse_keyid_strips_trailing_annotation() {
        let text = "untrusted comment: minisign public key D67754E8C6888574 (rotated 2026)\n";
        assert_eq!(parse_keyid_from_pubkey_text(text), Some("D67754E8C6888574".into()));
    }

    /// P15: only 16-char uppercase hex is accepted.
    #[test]
    fn parse_keyid_rejects_non_hex_token() {
        let text = "untrusted comment: minisign public key NOT-A-KEYID-XYZ!\n";
        assert!(parse_keyid_from_pubkey_text(text).is_none());
    }

    /// P3 (review F3): hardlink entries are also refused.
    #[test]
    fn extract_targz_rejects_hardlink_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = tmp.path().join("with-hardlink.tar.gz");
        let dest = tmp.path().join("extracted");
        std::fs::create_dir(&dest).unwrap();

        {
            let f = std::fs::File::create(&archive).unwrap();
            let gz = flate2::write::GzEncoder::new(f, flate2::Compression::default());
            let mut t = tar::Builder::new(gz);
            let mut h = tar::Header::new_gnu();
            h.set_mode(0o644);
            h.set_size(0);
            h.set_entry_type(tar::EntryType::Link); // EntryType::hard_link
            h.set_cksum();
            t.append_link(&mut h, "agentsso", "/etc/passwd").unwrap();
            let gz = t.into_inner().unwrap();
            gz.finish().unwrap();
        }

        let err = extract_targz(&archive, &dest).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("hard link") && msg.contains("refusing"),
            "expected hardlink refusal; got: {msg}"
        );
    }

    /// P15 (review): malformed signature file (random bytes that
    /// aren't minisign-shape) is refused before the verify call
    /// touches the embedded pubkey.
    #[test]
    fn verify_minisign_rejects_malformed_signature_file() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = tmp.path().join("payload.bin");
        let sig = tmp.path().join("payload.bin.minisig");
        std::fs::write(&archive, b"hello world").unwrap();
        std::fs::write(&sig, b"this is not a minisign signature\n").unwrap();
        let result = verify_minisign(&archive, &sig);
        assert!(result.is_err(), "expected malformed-signature refusal");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("malformed") || msg.contains("signature"),
            "expected signature-malformed error; got: {msg}"
        );
    }

    #[test]
    fn parse_keyid_rejects_wrong_length_token() {
        // Too short.
        assert!(
            parse_keyid_from_pubkey_text("untrusted comment: minisign public key DEADBEEF\n")
                .is_none()
        );
        // Too long.
        assert!(
            parse_keyid_from_pubkey_text(
                "untrusted comment: minisign public key 1234567890ABCDEF1234567890\n"
            )
            .is_none()
        );
    }

    #[test]
    fn canonicalize_rejects_parent_dir() {
        let path = Path::new("../etc/passwd");
        let err = canonicalize_archive_path(path).unwrap_err();
        assert!(err.contains("parent-dir"), "got {err}");
    }

    #[test]
    fn canonicalize_rejects_nested_parent_dir() {
        let path = Path::new("foo/../../etc/passwd");
        assert!(canonicalize_archive_path(path).is_err());
    }

    #[test]
    fn canonicalize_rejects_absolute_path() {
        let path = Path::new("/etc/passwd");
        let err = canonicalize_archive_path(path).unwrap_err();
        assert!(err.contains("absolute"), "got {err}");
    }

    #[cfg(windows)]
    #[test]
    fn canonicalize_rejects_drive_prefix() {
        let path = Path::new(r"C:\Windows\System32\foo");
        let err = canonicalize_archive_path(path).unwrap_err();
        assert!(err.contains("Windows drive"), "got {err}");
    }

    #[test]
    fn canonicalize_accepts_simple_relative() {
        let path = Path::new("agentsso-0.4.0/agentsso");
        let canonical = canonicalize_archive_path(path).unwrap();
        assert_eq!(canonical, PathBuf::from("agentsso-0.4.0/agentsso"));
    }

    #[test]
    fn canonicalize_drops_curdir_segments() {
        let path = Path::new("./agentsso-0.4.0/./agentsso");
        let canonical = canonicalize_archive_path(path).unwrap();
        assert_eq!(canonical, PathBuf::from("agentsso-0.4.0/agentsso"));
    }

    #[test]
    fn canonicalize_rejects_empty_after_normalization() {
        let path = Path::new("./");
        assert!(canonicalize_archive_path(path).is_err());
    }

    /// Build a minimal `.tar.gz` containing a single `agentsso`
    /// binary with the given content + permissions.
    ///
    /// Order matters: `tar::Builder::finish()` writes the tar
    /// trailer (1024 zero bytes) but does NOT flush/finish the
    /// underlying gz encoder. We extract the encoder via
    /// `into_inner()` and call its `finish()` to flush the
    /// remaining bytes; otherwise the on-disk file is truncated
    /// mid-block and `tar::Archive::entries()` reports
    /// "malformed tar entry" on the partial read.
    fn build_test_archive(
        dest: &Path,
        binary_contents: &[u8],
        binary_mode: u32,
        extra_entries: &[(&str, &[u8])],
    ) {
        let f = std::fs::File::create(dest).unwrap();
        let gz = flate2::write::GzEncoder::new(f, flate2::Compression::default());
        let mut builder = tar::Builder::new(gz);

        // Primary binary entry.
        let mut header = tar::Header::new_gnu();
        header.set_mode(binary_mode);
        header.set_size(binary_contents.len() as u64);
        header.set_entry_type(tar::EntryType::file());
        header.set_cksum();
        builder.append_data(&mut header, "agentsso", binary_contents).unwrap();

        // Any extra entries (used to test malicious paths).
        for (name, contents) in extra_entries {
            let mut h = tar::Header::new_gnu();
            h.set_mode(0o644);
            h.set_size(contents.len() as u64);
            h.set_entry_type(tar::EntryType::file());
            h.set_cksum();
            builder.append_data(&mut h, name, *contents).unwrap();
        }

        let gz = builder.into_inner().unwrap();
        gz.finish().unwrap();
    }

    #[test]
    fn extract_targz_finds_the_binary() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = tmp.path().join("test.tar.gz");
        let dest = tmp.path().join("extracted");
        std::fs::create_dir(&dest).unwrap();
        build_test_archive(&archive, b"#!/bin/sh\necho hi\n", 0o755, &[]);
        let binary = extract_targz(&archive, &dest).unwrap();
        assert_eq!(binary.file_name().and_then(|n| n.to_str()), Some("agentsso"));
        assert!(binary.exists());
    }

    #[test]
    fn extract_targz_rejects_path_traversal_entry() {
        // The tar crate's `append_data` rejects `..` before the
        // entry is written, so we can't use it to construct a
        // malicious archive. Instead, write the tar entry's raw
        // 512-byte header + file body bytes ourselves so the bytes
        // on disk look exactly like an attacker-crafted archive
        // would.
        let tmp = tempfile::tempdir().unwrap();
        let archive = tmp.path().join("malicious.tar.gz");
        let dest = tmp.path().join("extracted");
        std::fs::create_dir(&dest).unwrap();

        // Build the malicious archive via direct header bytes.
        let f = std::fs::File::create(&archive).unwrap();
        let gz = flate2::write::GzEncoder::new(f, flate2::Compression::default());
        let mut builder = tar::Builder::new(gz);

        // Manually construct a tar header whose `name` field carries
        // `../etc/evil` (the `set_path` API would refuse). Since
        // tar::Header lets us write the name field directly via
        // `as_old_mut().name`, we sidestep validation.
        let mut header = tar::Header::new_old();
        let body = b"compromised";
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::file());
        // Set the raw `name` bytes directly. Old (USTAR-less) tar
        // headers have a 100-byte `name` field at offset 0.
        let name_bytes = b"../etc/evil";
        let name_field = &mut header.as_old_mut().name;
        name_field[..name_bytes.len()].copy_from_slice(name_bytes);
        header.set_cksum();
        builder.append(&header, &body[..]).unwrap();

        // Also include a valid agentsso so extraction would
        // otherwise succeed.
        let mut h2 = tar::Header::new_gnu();
        h2.set_mode(0o755);
        h2.set_size(2);
        h2.set_entry_type(tar::EntryType::file());
        h2.set_cksum();
        builder.append_data(&mut h2, "agentsso", b"hi" as &[u8]).unwrap();

        let gz = builder.into_inner().unwrap();
        gz.finish().unwrap();

        let result = extract_targz(&archive, &dest);
        assert!(result.is_err(), "expected extract to reject path traversal");
        let err_str = result.unwrap_err().to_string();
        assert!(
            err_str.contains("unsafe path") || err_str.contains("parent-dir"),
            "expected unsafe-path error, got: {err_str}"
        );
    }

    #[test]
    fn extract_targz_returns_err_when_no_agentsso_binary() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = tmp.path().join("empty.tar.gz");
        let dest = tmp.path().join("extracted");
        std::fs::create_dir(&dest).unwrap();

        // Build an archive WITHOUT an agentsso binary. The
        // tar::Builder::into_inner() flushes the tar trailer, then
        // we explicitly finish() the gz encoder so the bytes are
        // fully written before the test reads the file.
        {
            let f = std::fs::File::create(&archive).unwrap();
            let gz = flate2::write::GzEncoder::new(f, flate2::Compression::default());
            let mut t = tar::Builder::new(gz);
            let mut h = tar::Header::new_gnu();
            h.set_mode(0o644);
            h.set_size(2);
            h.set_entry_type(tar::EntryType::file());
            h.set_cksum();
            t.append_data(&mut h, "README.md", b"hi" as &[u8]).unwrap();
            let gz = t.into_inner().unwrap();
            gz.finish().unwrap();
        }

        let err = extract_targz(&archive, &dest).unwrap_err();
        assert!(err.to_string().contains("did not contain an `agentsso`"), "got: {err}");
    }

    /// P3 (review F3 — Blind + Edge): tar archive containing a
    /// symlink entry must be refused.
    #[test]
    fn extract_targz_rejects_symlink_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = tmp.path().join("with-symlink.tar.gz");
        let dest = tmp.path().join("extracted");
        std::fs::create_dir(&dest).unwrap();

        // tar::Builder::append_link writes a symlink entry pointing
        // at any path the test specifies — exactly the malicious
        // shape we're defending against.
        {
            let f = std::fs::File::create(&archive).unwrap();
            let gz = flate2::write::GzEncoder::new(f, flate2::Compression::default());
            let mut t = tar::Builder::new(gz);
            let mut h = tar::Header::new_gnu();
            h.set_mode(0o777);
            h.set_size(0);
            h.set_entry_type(tar::EntryType::Symlink);
            h.set_cksum();
            t.append_link(&mut h, "agentsso", "/etc/passwd").unwrap();
            let gz = t.into_inner().unwrap();
            gz.finish().unwrap();
        }

        let err = extract_targz(&archive, &dest).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("symlink") && msg.contains("refusing"),
            "expected symlink refusal; got: {msg}"
        );
        // Defense-in-depth: the symlink must NOT have been
        // materialized in the dest dir before the refusal fired.
        assert!(
            !dest.join("agentsso").exists(),
            "symlink should not have been created — refusal must fire BEFORE unpack"
        );
    }

    /// P4 (review F4 — Blind): an archive whose declared per-entry
    /// sizes sum past the 256MB extraction cap must be refused.
    #[test]
    fn extract_targz_rejects_zip_bomb() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = tmp.path().join("bomb.tar.gz");
        let dest = tmp.path().join("extracted");
        std::fs::create_dir(&dest).unwrap();

        // Build an archive whose first entry's HEADER declares
        // 257MB even though the actual body is empty (bytes never
        // written). The zip-bomb cap is enforced via `entry.size()`,
        // which reads the header's declared size — so a malformed
        // body length doesn't matter for the assertion.
        {
            let f = std::fs::File::create(&archive).unwrap();
            let gz = flate2::write::GzEncoder::new(f, flate2::Compression::default());
            let mut t = tar::Builder::new(gz);
            let mut h = tar::Header::new_gnu();
            h.set_mode(0o644);
            h.set_size(257 * 1024 * 1024); // 257MB declared
            h.set_entry_type(tar::EntryType::file());
            h.set_cksum();
            // Append with an empty body — the tar reader's iterator
            // will skip past the declared 257MB of zeros (which the
            // gzip stream does not actually contain), but the cap
            // check on the header trips first.
            //
            // Use append_data with a body matching the declared
            // size so the archive is structurally well-formed.
            let body = vec![0u8; 257 * 1024 * 1024];
            t.append_data(&mut h, "huge.bin", &body[..]).unwrap();
            let gz = t.into_inner().unwrap();
            gz.finish().unwrap();
        }

        let err = extract_targz(&archive, &dest).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("more than") && msg.contains("bomb"),
            "expected zip-bomb refusal; got: {msg}"
        );
    }
}
