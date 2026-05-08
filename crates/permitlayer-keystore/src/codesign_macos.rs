//! Self-codesign verification primitives for Story 7.22 auto-recovery.
//!
//! When the macOS keychain returns OSStatus -25308 ("User interaction is
//! not allowed") on a master-key probe, the daemon's auto-recovery path
//! needs to verify the running binary is "the same publisher" as the
//! binary that originally minted the keychain entry — only then is it
//! safe to mint a new master key under the new ACL and rekey the vault.
//!
//! The Apple-blessed pattern (per Quinn "The Eskimo!" on Apple Dev
//! Forums thread/128586 + Apple TN2206) is to persist the binary's
//! Designated Requirement (DR) string captured on first successful run,
//! then verify the recovering binary's `SecCode::for_self()` against
//! the stored DR via `SecCodeCheckValidity`. The DR encodes
//! `anchor apple generic and identifier "X" and certificate leaf[...]`
//! automatically — it's stable across rebuilds by the same signer +
//! same identifier, but changes if either the identifier or the
//! signing identity changes.
//!
//! # rc.17 scope: adhoc-CDHash semantics (Codex Finding 1)
//!
//! The release pipeline at `.github/workflows/release.yml` ships rc.X
//! tarballs with ed25519/minisign signatures only — there is no Apple
//! Developer ID signing in CI today (`docs/user-guide/install.md:251`
//! documents this as deferred). Both dev builds (`cargo build`) and
//! release builds (`cargo build --release` shipped via brew tap) carry
//! adhoc signatures (the linker's default), not Developer-ID signatures.
//!
//! Adhoc-signed binaries DO have a valid DR — `SecRequirementCopyString`
//! returns a parseable DR for them. The DR captures the CDHash
//! (per-build SHA256 of the binary's load commands + executable
//! segments) plus the identifier (the bundle/binary identifier, stable
//! across rebuilds by the same source tree). For rc.17, "matches the
//! stored DR" effectively means: same identifier AND same CDHash —
//! i.e., byte-identical at the codesigned-hash level.
//!
//! This is weaker than Developer-ID-bound verification (no Team ID
//! filtering, no "rejects different signer" guarantee), but it's the
//! right scope for what the release pipeline actually ships today. A
//! future story (when Apple Developer ID enrollment + release.yml
//! signing land) will tighten the DR to include `certificate leaf[...]`
//! constraints; the same code path captures the stronger DR
//! automatically — this module is forward-compatible.
//!
//! # Threat model (rc.17, honestly stated)
//!
//! Protects against: post-install binary swaps that aren't byte-identical
//! to the previously-trusted binary. Specifically the rc.16 → rc.17
//! brew-upgrade case: the new binary has a different CDHash, so its
//! DR string differs, so verification CORRECTLY rejects unless the
//! upgrade was a legitimate same-publisher rebuild that keeps the same
//! signing identity (in adhoc-land: the same source tree → same
//! identifier → eventual code-path "trust on first use" of the new
//! anchor on subsequent boots).
//!
//! Does NOT protect against:
//! - A second adhoc-signed binary built by a different developer (no
//!   signing identity in adhoc-land to distinguish them).
//! - An attacker who can write to `<home>/keystore/` AND can produce
//!   an adhoc binary that they then install at `/usr/local/bin/agentsso`.
//!   (Mitigated by filesystem permissions on the home directory and on
//!   the binary install location, NOT by codesign in rc.17 scope.)
//! - First-boot TOFU window: if an attacker can drop a malicious anchor
//!   at `<home>/keystore/codesign-trust-anchor.req` BEFORE the
//!   operator's first run, they capture a malicious DR. Documented
//!   limitation; same attack surface as `passphrase.state` already.
//!
//! # API surface
//!
//! - [`capture_self_designated_requirement`]: extract the DR string from
//!   the running process. Used at first-run TOFU + Phase G re-capture.
//! - [`verify_self_against`]: assert the running process matches a
//!   stored DR. Used at ACL-break recovery time.
//! - [`CodesignError`]: structured failure type with operator-actionable
//!   `Display` text.
//!
//! Cross-platform: on non-macOS the module compiles to stub functions
//! returning `CodesignError::PlatformUnsupported` so the daemon's
//! call sites build identically across platforms.

#[cfg(target_os = "macos")]
pub use macos_impl::{capture_self_designated_requirement, verify_self_against};

pub use error::CodesignError;
pub use trust_anchor::{
    read_trust_anchor, trust_anchor_path, write_trust_anchor, write_trust_anchor_force,
};

#[cfg(not(target_os = "macos"))]
pub fn capture_self_designated_requirement() -> Result<String, CodesignError> {
    Err(CodesignError::PlatformUnsupported)
}

#[cfg(not(target_os = "macos"))]
pub fn verify_self_against(_stored_dr: &str) -> Result<(), CodesignError> {
    Err(CodesignError::PlatformUnsupported)
}

mod trust_anchor {
    //! On-disk persistence of the captured Designated Requirement.
    //!
    //! File: `<home>/keystore/codesign-trust-anchor.req`. Mode 0600 on
    //! Unix. Atomic-tempfile-rename via `persist_noclobber` to refuse
    //! racing first-run writers (mirrors the `passphrase.state`
    //! discipline at `passphrase.rs:374`).
    //!
    //! Reading validates the file's content parses as a `SecRequirement`
    //! via the same `FromStr` path used at recovery time. A corrupted
    //! file (hand-edited or partially-written) returns an `io::Error`
    //! kind `InvalidData` rather than `Some(garbage)` — callers MUST
    //! NOT trust the content without parsing.
    //!
    //! Cross-platform: on non-macOS the read/write functions still work
    //! (the file is just bytes) but the parse-validation step uses
    //! `verify_self_against`'s parse-only check via a new
    //! [`super::CodesignError::RequirementParseFailed`] indirect, so
    //! non-macOS targets surface a `PlatformUnsupported` error from
    //! the parse step. In practice this module is only called from
    //! `cfg(target_os = "macos")` code paths.

    use std::fs;
    use std::io::{self, Write as _};
    use std::path::{Path, PathBuf};

    use super::CodesignError;

    /// Resolve the trust-anchor file path under the given `<home>` dir.
    ///
    /// Always `<home>/keystore/codesign-trust-anchor.req`. Lives
    /// alongside `passphrase.state` in the same `keystore/` directory
    /// so a single `<home>/keystore/` lock-down (mode 0700, owner
    /// only) protects both files.
    pub fn trust_anchor_path(home: &Path) -> PathBuf {
        home.join("keystore").join("codesign-trust-anchor.req")
    }

    /// Persist a captured Designated Requirement string atomically.
    ///
    /// - Creates `<home>/keystore/` if missing.
    /// - Tempfile + `persist_noclobber` (refuses to overwrite an
    ///   existing anchor; callers that want to replace MUST first
    ///   delete the existing file).
    /// - Mode 0600 on Unix.
    /// - File + parent-dir fsync for durability.
    ///
    /// Story 7.22 Task 4.6 (Phase G re-capture) DOES need the
    /// overwrite case. For that path use [`write_trust_anchor_force`]
    /// — separate function so the no-clobber default is harder to
    /// accidentally bypass.
    pub fn write_trust_anchor(home: &Path, dr: &str) -> io::Result<()> {
        write_inner(home, dr, /* force = */ false)
    }

    /// Atomically overwrite the trust-anchor file. Used by Phase G of
    /// the AutoRecover rotation to refresh the anchor under the binary
    /// that just successfully completed the rotation (Codex Finding 5).
    // Wired in Task 4.6 (Phase G re-capture). Allow-dead-code until then;
    // removing it would re-introduce the rc.17→crash→rc.18 stranding
    // corner that Codex Finding 5 caught.
    #[allow(dead_code)]
    pub fn write_trust_anchor_force(home: &Path, dr: &str) -> io::Result<()> {
        write_inner(home, dr, /* force = */ true)
    }

    fn write_inner(home: &Path, dr: &str, force: bool) -> io::Result<()> {
        let path = trust_anchor_path(home);
        let parent = path.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "trust anchor path has no parent")
        })?;
        fs::create_dir_all(parent)?;

        let mut builder = tempfile::Builder::new();
        builder.prefix(".tmp-trust-anchor-").suffix(".part");
        let mut tmp = builder.tempfile_in(parent)?;
        tmp.as_file_mut().write_all(dr.as_bytes())?;
        tmp.as_file_mut().sync_all()?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = tmp.as_file().metadata()?.permissions();
            perms.set_mode(0o600);
            tmp.as_file().set_permissions(perms)?;
        }

        if force {
            // Allow overwrite for Phase G re-capture.
            tmp.persist(&path).map_err(|e| e.error)?;
        } else {
            // Race-safe refuse-if-exists for first-run TOFU.
            tmp.persist_noclobber(&path).map_err(|e| e.error)?;
        }

        // Parent-dir fsync for rename durability.
        if let Ok(parent_dir) = fs::File::open(parent) {
            let _ = parent_dir.sync_all();
        }

        Ok(())
    }

    /// Read the persisted trust anchor.
    ///
    /// Returns `Ok(None)` if the file is absent (fresh install or
    /// pre-rc.17 install with no anchor yet). Returns
    /// `Ok(Some(dr_string))` if present AND content parses as a
    /// `SecRequirement`. Returns `Err(io::Error::InvalidData)` if the
    /// file exists but content is corrupted (hand-edited, partially
    /// written by a non-atomic writer, or just garbage). Callers MUST
    /// NOT use a returned `dr_string` without re-parsing — but this
    /// reader has already validated parseability so the recovery code
    /// path can trust the format.
    pub fn read_trust_anchor(home: &Path) -> io::Result<Option<String>> {
        let path = trust_anchor_path(home);
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let s = String::from_utf8(bytes).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "trust anchor file is not valid UTF-8")
        })?;
        // Validate the content parses as a SecRequirement. On non-macOS
        // this returns PlatformUnsupported and we treat it as
        // unparseable for safety — a non-macOS daemon should never be
        // reading a macOS DR file in the first place.
        super::verify_self_against(&s).map(|_| ()).or_else(|err| match err {
            // `RequirementMismatch` is the EXPECTED outcome: the file
            // parses cleanly but doesn't match the running binary.
            // That's fine for a parse-validation read.
            CodesignError::RequirementMismatch { .. } => Ok(()),
            CodesignError::Unsigned => Ok(()),
            CodesignError::SecFrameworkCall { .. } => Ok(()),
            // These are the actual "file is garbage" cases.
            CodesignError::RequirementParseFailed { .. } => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "trust anchor file content is not a valid SecRequirement string",
            )),
            CodesignError::PlatformUnsupported => {
                Err(io::Error::other("trust anchor parse-validation requires macOS"))
            }
            CodesignError::Other { code, message } => Err(io::Error::other(format!(
                "trust anchor parse-validation failed (OSStatus {code}): {message}"
            ))),
        })?;
        Ok(Some(s))
    }

    #[cfg(test)]
    #[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    mod tests {
        use super::*;
        use tempfile::TempDir;

        /// Helper: capture a real DR from the running test binary.
        /// Used as the "valid input" for round-trip tests.
        #[cfg(target_os = "macos")]
        fn real_dr() -> String {
            super::super::capture_self_designated_requirement()
                .expect("test binary should have a captureable DR")
        }

        #[test]
        fn trust_anchor_path_lives_under_keystore_subdir() {
            let home = Path::new("/tmp/some-home");
            assert_eq!(
                trust_anchor_path(home),
                Path::new("/tmp/some-home/keystore/codesign-trust-anchor.req")
            );
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn write_then_read_round_trips_a_real_dr() {
            let home = TempDir::new().unwrap();
            let dr = real_dr();
            write_trust_anchor(home.path(), &dr).unwrap();
            let read_back = read_trust_anchor(home.path()).unwrap();
            assert_eq!(read_back.as_deref(), Some(dr.as_str()));
        }

        #[test]
        fn read_returns_none_when_file_absent() {
            let home = TempDir::new().unwrap();
            let result = read_trust_anchor(home.path()).unwrap();
            assert_eq!(result, None);
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn read_rejects_corrupted_content_with_invalid_data() {
            let home = TempDir::new().unwrap();
            // Pre-create the keystore dir + file with garbage content.
            let path = trust_anchor_path(home.path());
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, "this is not a sec requirement string at all !!!").unwrap();

            let err = read_trust_anchor(home.path()).expect_err("garbage must reject");
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        }

        #[cfg(unix)]
        #[cfg(target_os = "macos")]
        #[test]
        fn write_uses_0600_perms() {
            use std::os::unix::fs::PermissionsExt;
            let home = TempDir::new().unwrap();
            let dr = real_dr();
            write_trust_anchor(home.path(), &dr).unwrap();
            let mode =
                fs::metadata(trust_anchor_path(home.path())).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "trust anchor file must be 0o600");
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn write_refuses_to_clobber_existing_anchor() {
            let home = TempDir::new().unwrap();
            let dr = real_dr();
            // First write succeeds.
            write_trust_anchor(home.path(), &dr).unwrap();
            // Second write to the same path with the same content
            // returns AlreadyExists. Callers that want to update (Phase
            // G re-capture per Codex Finding 5) MUST use the explicit
            // `write_trust_anchor_force`.
            let err = write_trust_anchor(home.path(), &dr).expect_err("second write must refuse");
            assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn force_write_overwrites_existing_anchor() {
            let home = TempDir::new().unwrap();
            let dr = real_dr();
            write_trust_anchor(home.path(), &dr).unwrap();
            // The second write with `force=true` succeeds, and the
            // file content matches the second-write input. Used by
            // Phase G re-capture.
            write_trust_anchor_force(home.path(), &dr).unwrap();
            let read_back = read_trust_anchor(home.path()).unwrap();
            assert_eq!(read_back.as_deref(), Some(dr.as_str()));
        }
    }
}

mod error {
    /// Structured failure type for codesign verification.
    ///
    /// Each variant's `Display` is operator-facing (lands in stderr +
    /// the structured-error renderer at `start.rs::StartError::render_banner`).
    /// The variants intentionally distinguish the rejection reasons
    /// because the operator's remediation differs:
    /// - `Unsigned`: the binary lacks any signature at all (extremely
    ///   rare in practice; would mean a custom-built binary stripped of
    ///   adhoc signing).
    /// - `RequirementMismatch`: the binary IS signed but doesn't match
    ///   the stored DR. In rc.17 adhoc-CDHash semantics, this means the
    ///   CDHash or identifier differs — typically a legitimate upgrade
    ///   the operator should explicitly re-trust, OR an unauthorized
    ///   binary swap.
    /// - `RequirementParseFailed`: the persisted DR string itself is
    ///   malformed — `<home>/keystore/codesign-trust-anchor.req` was
    ///   corrupted or hand-edited.
    /// - `SecFrameworkCall`: an Apple Security framework call returned
    ///   an unexpected error code.
    /// - `Other`: catch-all for `OSStatus` codes we don't have specific
    ///   variants for; surfaces the raw code so operators / forensics
    ///   can decode via `security_framework`'s error mapping.
    /// - `PlatformUnsupported`: stub for non-macOS builds.
    #[derive(thiserror::Error, Debug)]
    #[non_exhaustive]
    pub enum CodesignError {
        /// `errSecCSUnsigned` (-67062). The binary has no codesign
        /// signature at all (not even adhoc). Should be impossible for
        /// `cargo build` output on macOS but possible for hand-stripped
        /// or cross-compiled binaries.
        #[error(
            "running binary is not codesigned (errSecCSUnsigned). \
             Adhoc signing is the macOS default; if you see this, the \
             binary was likely stripped or built outside the standard \
             cargo + macOS toolchain"
        )]
        Unsigned,

        /// `errSecCSReqFailed` (-67050). The binary's signature is
        /// valid but does NOT match the stored DR. In rc.17 scope this
        /// almost always means the CDHash or identifier changed —
        /// either a legitimate upgrade requiring explicit re-trust, or
        /// an unauthorized binary swap.
        ///
        /// The `stored_dr_preview` is truncated to ~80 chars to avoid
        /// dumping a full DR string into shared logs (DRs can include
        /// Team IDs and certificate fingerprints in non-adhoc cases;
        /// while rc.17's adhoc DRs don't carry that risk, we apply the
        /// truncation prophylactically for forward-compat with the
        /// Story 7.24 Developer-ID work).
        #[error(
            "running binary's codesign does not match the stored trust anchor \
             (errSecCSReqFailed). Stored anchor preview: {stored_dr_preview}"
        )]
        RequirementMismatch {
            /// First ~80 chars of the stored DR string.
            stored_dr_preview: String,
        },

        /// The persisted DR string at
        /// `<home>/keystore/codesign-trust-anchor.req` could not be
        /// parsed by `SecRequirementCreateWithString`. The file is
        /// corrupted or hand-edited.
        #[error(
            "stored codesign requirement string is malformed (could not parse as a SecRequirement)"
        )]
        RequirementParseFailed {
            #[source]
            source: security_framework::base::Error,
        },

        /// Some other Security framework call failed unexpectedly.
        #[error("Apple Security framework call failed: {source}")]
        SecFrameworkCall {
            #[source]
            source: security_framework::base::Error,
        },

        /// Catch-all OSStatus surface for codes we don't have variants
        /// for. The numeric code is preserved so forensics / future
        /// bug reports can decode via Apple's
        /// `errSecCS*`/`SecCopyErrorMessageString`.
        #[error("codesign verification failed with OSStatus {code}: {message}")]
        Other {
            /// The raw `OSStatus` integer.
            code: i32,
            /// Human-readable Apple-supplied message.
            message: String,
        },

        /// Stub for non-macOS builds. The daemon's call sites should
        /// gate on `cfg(target_os = "macos")` and not hit this path,
        /// but the variant exists so the signature compiles uniformly.
        #[error("codesign verification is only implemented on macOS")]
        PlatformUnsupported,
    }
}

#[cfg(target_os = "macos")]
mod macos_impl {
    //! macOS-only implementation of the codesign primitives.
    //!
    //! Two FFI surfaces:
    //!
    //! 1. **Safe wrapper from `security-framework` 3.7**: `SecCode::for_self`
    //!    and `SecCode::check_validity` are wrapped cleanly. Used by
    //!    `verify_self_against`.
    //!
    //! 2. **Raw FFI for `SecCodeCopySigningInformation`** + CFDictionary
    //!    traversal for `kSecCodeInfoDesignatedRequirement`: NOT yet
    //!    wrapped in `security-framework` 3.7's safe layer. ~30 LOC of
    //!    `unsafe` block. Used by `capture_self_designated_requirement`.
    //!
    //! Both pull through `core-foundation` 0.10's safe `CFString` /
    //! `CFDictionary` types where possible to keep `unsafe` blocks
    //! narrow.
    //!
    //! # `SecCSFlags` choice
    //!
    //! Use `Flags::CHECK_ALL_ARCHITECTURES` for universal-binary
    //! support (Apple Silicon + Intel). DO NOT set
    //! `Flags::CHECK_GATEKEEPER_ARCHITECTURES` — that pulls in network
    //! revocation checks which block on launchd-spawned daemons that
    //! don't have network yet.

    use core_foundation::base::TCFType;
    use core_foundation::dictionary::{CFDictionary, CFDictionaryRef};
    use core_foundation::string::CFString;
    use core_foundation_sys::base::OSStatus;
    use security_framework::os::macos::code_signing::{Flags, SecCode, SecRequirement};
    use security_framework_sys::code_signing::{SecCodeRef, SecRequirementRef};
    use std::ptr;
    use std::str::FromStr;

    use super::CodesignError;

    /// Apple `OSStatus` for `errSecCSUnsigned`. The binary has no codesign at all.
    const ERR_SEC_CS_UNSIGNED: i32 = -67062;
    /// Apple `OSStatus` for `errSecCSReqFailed`. Signature exists but
    /// doesn't satisfy the requirement.
    const ERR_SEC_CS_REQ_FAILED: i32 = -67050;
    /// Apple flag bit for `kSecCSRequirementInformation` in
    /// `SecCodeCopySigningInformation`'s flags arg.
    /// (Not exposed by `security-framework-sys` 2.17 either.)
    const K_SEC_CS_REQUIREMENT_INFORMATION: u32 = 1 << 2;

    unsafe extern "C" {
        /// `SecCodeCopySigningInformation(SecCodeRef, SecCSFlags, CFDictionaryRef*) -> OSStatus`.
        ///
        /// Not wrapped in `security-framework-sys` 2.17 yet; declared here
        /// directly. Returns a CFDictionary whose keys vary by the
        /// `flags` arg. With `kSecCSRequirementInformation`, the dict
        /// contains `kSecCodeInfoDesignatedRequirement` (a SecRequirement).
        fn SecCodeCopySigningInformation(
            code: SecCodeRef,
            flags: u32,
            information: *mut CFDictionaryRef,
        ) -> OSStatus;

        /// `SecRequirementCopyString(SecRequirementRef, SecCSFlags, CFStringRef*) -> OSStatus`.
        ///
        /// Renders a `SecRequirement` back to its source-text form. The
        /// stable string we persist as the trust anchor.
        fn SecRequirementCopyString(
            requirement: SecRequirementRef,
            flags: u32,
            text: *mut core_foundation_sys::string::CFStringRef,
        ) -> OSStatus;

        /// Apple-supplied human-readable message for an OSStatus.
        /// Returns NULL for codes Apple doesn't have a message for; we
        /// fall back to "(no message)".
        fn SecCopyErrorMessageString(
            status: OSStatus,
            reserved: *mut std::ffi::c_void,
        ) -> core_foundation_sys::string::CFStringRef;

        /// Apple-supplied symbol for the `kSecCodeInfoDesignatedRequirement`
        /// CFString key. We resolve it at runtime to look up the DR
        /// inside the CFDictionary returned by
        /// `SecCodeCopySigningInformation`.
        static kSecCodeInfoDesignatedRequirement: core_foundation_sys::string::CFStringRef;
    }

    /// Capture the running binary's Designated Requirement string.
    ///
    /// Called at first-run TOFU (Task 2 in Story 7.22) and at Phase G
    /// re-capture after a successful auto-recovery rotation (Task 4.6).
    ///
    /// Steps:
    /// 1. `SecCode::for_self(Flags::NONE)` — get the dynamic SecCode for the running process.
    /// 2. `SecCodeCopySigningInformation(code, kSecCSRequirementInformation, &mut dict)`.
    /// 3. Look up `kSecCodeInfoDesignatedRequirement` inside the dict — yields a `SecRequirementRef`.
    /// 4. `SecRequirementCopyString(req, 0, &mut cfstr)` → render to text.
    /// 5. `CFString` → Rust `String`.
    pub fn capture_self_designated_requirement() -> Result<String, CodesignError> {
        let me = SecCode::for_self(Flags::NONE)
            .map_err(|e| CodesignError::SecFrameworkCall { source: e })?;

        // SAFETY: We hand `SecCodeCopySigningInformation` a valid
        // `SecCodeRef` (just constructed via `for_self`, kept alive by
        // `me`'s ownership of the underlying CF object via TCFType),
        // a flags constant, and an out-parameter pointing at a properly
        // typed local. The function fills `info_ptr` with a +1
        // CFDictionary that we wrap with `wrap_under_create_rule` to
        // tie its lifetime to the `info` binding. If the call fails we
        // bail before any use.
        let info: CFDictionary<CFString, core_foundation::base::CFType> = unsafe {
            let mut info_ptr: CFDictionaryRef = ptr::null();
            let status = SecCodeCopySigningInformation(
                me.as_concrete_TypeRef(),
                K_SEC_CS_REQUIREMENT_INFORMATION,
                &mut info_ptr,
            );
            if status != 0 {
                return Err(map_oss_status(status));
            }
            if info_ptr.is_null() {
                return Err(CodesignError::Other {
                    code: 0,
                    message: "SecCodeCopySigningInformation returned NULL dictionary".to_owned(),
                });
            }
            CFDictionary::wrap_under_create_rule(info_ptr)
        };

        // Look up the Designated Requirement entry.
        // SAFETY: `kSecCodeInfoDesignatedRequirement` is an Apple-supplied
        // static; we wrap it under "get rule" (no retain) to construct
        // a temporary CFString key. The dictionary's `find` returns a
        // borrowed reference if the key exists.
        let dr_value = unsafe {
            let key = CFString::wrap_under_get_rule(kSecCodeInfoDesignatedRequirement);
            info.find(&key)
        };
        let dr_value = dr_value.ok_or_else(|| CodesignError::Other {
            code: 0,
            message: "signing information dictionary missing kSecCodeInfoDesignatedRequirement"
                .to_owned(),
        })?;

        // The value is a SecRequirement (CFTypeRef). Cast through the
        // type-id check to make sure that's actually what we got.
        // SAFETY: we treat the borrowed CFTypeRef as a SecRequirementRef
        // for the duration of the SecRequirementCopyString call. The
        // CFDictionary `info` keeps the underlying object alive.
        let dr_string = unsafe {
            let req_ref: SecRequirementRef = dr_value.as_CFTypeRef() as SecRequirementRef;
            let mut text_ptr: core_foundation_sys::string::CFStringRef = ptr::null();
            let status = SecRequirementCopyString(req_ref, 0, &mut text_ptr);
            if status != 0 {
                return Err(map_oss_status(status));
            }
            if text_ptr.is_null() {
                return Err(CodesignError::Other {
                    code: 0,
                    message: "SecRequirementCopyString returned NULL".to_owned(),
                });
            }
            // Wrap +1 CFString and convert to Rust String.
            let cf = CFString::wrap_under_create_rule(text_ptr);
            cf.to_string()
        };

        Ok(dr_string)
    }

    /// Verify the running binary against a previously-captured DR string.
    ///
    /// Called at ACL-break recovery time (Task 3 in Story 7.22).
    /// `errSecCSUnsigned` → `Unsigned`, `errSecCSReqFailed` →
    /// `RequirementMismatch`, parse failure → `RequirementParseFailed`,
    /// other Security framework errors → `SecFrameworkCall` / `Other`.
    pub fn verify_self_against(stored_dr: &str) -> Result<(), CodesignError> {
        let req = SecRequirement::from_str(stored_dr)
            .map_err(|e| CodesignError::RequirementParseFailed { source: e })?;
        let me = SecCode::for_self(Flags::NONE)
            .map_err(|e| CodesignError::SecFrameworkCall { source: e })?;
        // `Flags::NONE` is the correct flag set for a *dynamic* SecCode
        // (the running process). `CHECK_ALL_ARCHITECTURES` is only valid
        // for static codes (binaries on disk via `SecStaticCodeCreateWithPath`)
        // and would return errSecCSInvalidFlags (-67070) here. For
        // dynamic verification of the running process, the running
        // architecture is implicit — no architecture-walk needed.
        me.check_validity(Flags::NONE, &req).map_err(|e| match e.code() {
            ERR_SEC_CS_UNSIGNED => CodesignError::Unsigned,
            ERR_SEC_CS_REQ_FAILED => CodesignError::RequirementMismatch {
                stored_dr_preview: truncate_for_display(stored_dr),
            },
            _ => CodesignError::SecFrameworkCall { source: e },
        })
    }

    /// Map a non-zero `OSStatus` from a raw FFI call to a `CodesignError`.
    fn map_oss_status(status: OSStatus) -> CodesignError {
        let message = oss_status_message(status);
        match status {
            ERR_SEC_CS_UNSIGNED => CodesignError::Unsigned,
            // Don't fold `ERR_SEC_CS_REQ_FAILED` here — that's only
            // produced by `SecCodeCheckValidity`, not by the FFI calls
            // this helper wraps.
            other => CodesignError::Other { code: other, message },
        }
    }

    /// Look up Apple's human-readable message for an OSStatus, or
    /// fall back to "(no message)" if Apple doesn't have one.
    fn oss_status_message(status: OSStatus) -> String {
        // SAFETY: `SecCopyErrorMessageString` returns either NULL or a
        // +1 CFString. We wrap with `wrap_under_create_rule` to manage
        // the retain count via `to_string`.
        unsafe {
            let cf = SecCopyErrorMessageString(status, ptr::null_mut());
            if cf.is_null() {
                "(no message)".to_owned()
            } else {
                CFString::wrap_under_create_rule(cf).to_string()
            }
        }
    }

    /// Truncate a DR string for inclusion in operator-facing error
    /// messages. DRs can be long; ~80 chars is enough to identify the
    /// stored anchor without dumping certificate fingerprints into
    /// shared logs.
    fn truncate_for_display(s: &str) -> String {
        const MAX: usize = 80;
        if s.chars().count() <= MAX {
            s.to_owned()
        } else {
            let mut out: String = s.chars().take(MAX).collect();
            out.push('…');
            out
        }
    }

    #[cfg(test)]
    #[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    mod tests {
        use super::*;

        /// Capturing the running binary's DR returns a non-empty
        /// string that round-trips through `SecRequirement::from_str`.
        ///
        /// This is the load-bearing TOFU path — if `cargo test`'s test
        /// binary can't capture its own DR, neither can the production
        /// daemon at first-run.
        #[test]
        fn capture_self_dr_returns_nonempty_parseable_string() {
            let dr = capture_self_designated_requirement()
                .expect("capture should succeed for adhoc-signed test binary");
            assert!(!dr.is_empty(), "DR string must be non-empty");
            // Round-trip: the captured DR string must parse as a valid
            // SecRequirement. If this fails, our captured string is
            // corrupted or the DR format is unparseable.
            SecRequirement::from_str(&dr).expect("captured DR must round-trip through FromStr");
        }

        /// Verifying the running binary against ITS OWN captured DR
        /// succeeds. This is the steady-state recovery success path.
        #[test]
        fn verify_self_against_own_dr_succeeds() {
            let dr = capture_self_designated_requirement().expect("capture");
            verify_self_against(&dr).expect(
                "the running binary should verify successfully against its own captured DR",
            );
        }

        /// Verifying against a DR that doesn't match returns
        /// `RequirementMismatch` (not `Unsigned`, not generic
        /// `SecFrameworkCall`). Pins the operator-facing error code.
        #[test]
        fn verify_against_mismatched_dr_returns_requirement_mismatch() {
            // A clearly-different identifier the running binary cannot match.
            let mismatched_dr = r#"identifier "com.never.matches.permitlayer.test""#;
            let err = verify_self_against(mismatched_dr).expect_err("mismatched DR must reject");
            match err {
                CodesignError::RequirementMismatch { stored_dr_preview } => {
                    assert!(
                        stored_dr_preview.contains("never.matches"),
                        "preview should echo the stored DR for forensics: {stored_dr_preview}"
                    );
                }
                other => panic!("expected RequirementMismatch, got {other:?}"),
            }
        }

        /// A malformed DR string returns `RequirementParseFailed`,
        /// distinguishable from `RequirementMismatch`. Operator's
        /// remediation differs: a malformed DR means the trust-anchor
        /// file on disk is corrupted, not that the binary changed.
        #[test]
        fn verify_against_malformed_dr_returns_parse_failure() {
            // Not valid Code Signing Requirement Language.
            let garbage = "this is not a sec requirement string at all !!!~~~";
            let err = verify_self_against(garbage).expect_err("garbage DR must reject");
            assert!(
                matches!(err, CodesignError::RequirementParseFailed { .. }),
                "expected RequirementParseFailed, got {err:?}"
            );
        }

        /// `truncate_for_display` rejects long strings cleanly without
        /// panicking on multi-byte UTF-8 boundaries (DRs are ASCII
        /// today but defense-in-depth).
        #[test]
        fn truncate_for_display_caps_at_80_chars() {
            let long: String = "x".repeat(200);
            let truncated = truncate_for_display(&long);
            // 80 'x' + 1 '…' = 81 chars
            assert_eq!(truncated.chars().count(), 81);
            assert!(truncated.ends_with('…'));
        }

        /// Short strings pass through unchanged.
        #[test]
        fn truncate_for_display_short_string_unchanged() {
            let short = r#"identifier "com.example.app""#;
            assert_eq!(truncate_for_display(short), short);
        }
    }
}
