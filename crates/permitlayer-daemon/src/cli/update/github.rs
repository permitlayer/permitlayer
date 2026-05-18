//! GitHub Releases API client for `agentsso update`.
//!
//! Hits `https://api.github.com/repos/permitlayer/permitlayer/releases?per_page=100`
//! (matching the same `REPO_OWNER`/`REPO_NAME` constants the curl|sh
//! installer hardcodes at `install/install.sh:17-18`, which is also
//! the minisign-trusted release source) and selects the highest
//! semver release among the non-draft entries.
//!
//! # Why `/releases` and not `/releases/latest` (UX-overhaul Story 3)
//!
//! `/releases/latest` excludes *every* prerelease. All `permitlayer`
//! releases to date are prereleases (`v0.3.0-rc.NN`), so
//! `/releases/latest` returns 404 and the self-updater never finds
//! anything — issue #58. We now list all releases, drop `draft`
//! entries (and tags that don't parse as semver — so the lexical
//! fallback can't mis-rank `rc.9` above `rc.10`), and pick the
//! maximum by [`semver::Version`]. `prerelease` is no longer a
//! rejection criterion: shipping only prereleases is this project's
//! actual release posture.
//!
//! # Test seam
//!
//! `AGENTSSO_GITHUB_API_BASE_URL` overrides the API base URL, but
//! ONLY in `cfg(test)` builds OR when `cfg(feature = "test-seam")`
//! is set on the crate. A production runtime override would let an
//! attacker who can set environment variables redirect the update
//! flow at a malicious release stream.

use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use reqwest::header::{ACCEPT, HeaderMap, HeaderValue, USER_AGENT};
use serde::Deserialize;

/// Production API base URL.
pub(crate) const PRODUCTION_API_BASE_URL: &str = "https://api.github.com";

/// Repo path (relative to the API base).
///
/// **UX-overhaul Story 3 supply-chain fix:** this was
/// `/repos/botsdown/permitlayer` — a stale org that did not match
/// `install/install.sh:17-18` (`permitlayer/permitlayer`, the
/// minisign-trusted release source). A drift detector that points
/// at a different repo than the install/upgrade path is a
/// supply-chain correctness bug, not a cosmetic mismatch:
/// `repo_path_matches_install_sh` pins them together.
pub(crate) const REPO_PATH: &str = "/repos/permitlayer/permitlayer";

/// Resolve the API base URL.
///
/// In `cfg(debug_assertions)` builds, honors `AGENTSSO_GITHUB_API_BASE_URL`
/// so integration tests can point a subprocess-spawned `agentsso
/// update` at a `mockito` mock server. Release builds (the only
/// thing real users ever run) ignore the env var entirely so an
/// attacker who can set env vars cannot redirect the update flow at
/// a malicious release stream.
///
/// Mirrors the `AGENTSSO_TEST_FROZEN_DATE` pattern at
/// `cli/connectors/new.rs::scaffold_date` — same threat model, same
/// debug-only seam.
pub(crate) fn api_base_url() -> String {
    #[cfg(debug_assertions)]
    {
        if let Ok(override_url) = std::env::var("AGENTSSO_GITHUB_API_BASE_URL") {
            return override_url;
        }
    }
    PRODUCTION_API_BASE_URL.to_owned()
}

/// Test seam — explicit base URL parameter so unit tests don't need
/// `unsafe { env::set_var }` to drive the URL resolution.
///
/// Used by [`fetch_latest_release_with`] in the test paths AND by the
/// integration test (which still uses the env var via `cfg(test)` for
/// subprocess-spawned `agentsso update` runs against a mockito server
/// — the env var is the cross-process mechanism).
#[cfg(test)]
pub(crate) fn api_base_url_with(override_url: Option<&str>) -> String {
    match override_url {
        Some(url) => url.to_owned(),
        None => api_base_url(),
    }
}

/// Subset of the GitHub Releases response the drift report consumes.
///
/// Field-by-field justification — each field has a real consumer in
/// the drift report (no deserialize-but-never-read fields):
/// - `tag_name` → version comparison + the canonical version label.
/// - `name` → human-readable release title, shown in the report.
/// - `published_at` → "published:" line in the report.
/// - `draft` → excluded during selection (unpublished).
/// - `prerelease` → report label (`(prerelease)`); NOT a rejection
///   criterion (this project ships only prereleases — issue #58).
///
/// `body`/`assets` are intentionally NOT modeled: the drift report
/// shows neither release notes nor asset URLs (the apply/download
/// flow that needed them was deleted). serde ignores unknown JSON
/// fields by default, so dropping them keeps deserialization
/// forward-compatible without carrying unread fields.
#[derive(Debug, Deserialize, Clone)]
pub(crate) struct ReleaseInfo {
    pub(crate) tag_name: String,
    pub(crate) name: Option<String>,
    pub(crate) published_at: Option<String>,
    #[serde(default)]
    pub(crate) draft: bool,
    /// Surfaced in the drift-report label (e.g. `0.3.0-rc.36
    /// (prerelease)`) so the operator knows the channel. NOT a
    /// rejection criterion — see the module docs.
    #[serde(default)]
    pub(crate) prerelease: bool,
}

impl ReleaseInfo {
    /// Strip a leading `v` from `tag_name`. GitHub Releases conventions
    /// vary; cargo-dist tags as `v0.4.0` while the workspace version
    /// is `0.4.0`. Comparisons happen on the stripped string.
    pub(crate) fn version(&self) -> &str {
        self.tag_name.strip_prefix('v').unwrap_or(&self.tag_name)
    }

    /// Parse [`Self::version`] as a [`semver::Version`].
    ///
    /// Selection (UX-overhaul Story 3) drops releases whose tag does
    /// not parse — otherwise the lexical fallback in
    /// [`compare_versions`] mis-ranks (`rc.9` sorts after `rc.10`
    /// lexically). A release we cannot semver-order is a release we
    /// must not silently pick as "latest".
    pub(crate) fn semver_version(&self) -> Option<semver::Version> {
        semver::Version::parse(self.version()).ok()
    }
}

/// Compare two version strings using semver. Strings WITHOUT a `v`
/// prefix.
///
/// Returns `Ordering::Less` when `current < latest` (an update is
/// available), `Equal` when versions match, `Greater` when the
/// running binary is somehow newer than the published release
/// (shouldn't happen in production but the orchestrator tolerates
/// it as "already on the latest").
///
/// **Review patch P13 (F15 — Blind + Edge):** on parse failure,
/// emit a `tracing::warn!` so the operator sees the malformed
/// version surface in the operational log. Lex-compare is still
/// the fallback (better than a panic), but silent acceptance was
/// the wrong default for a security-relevant compare.
pub(crate) fn compare_versions(current: &str, latest: &str) -> std::cmp::Ordering {
    use semver::Version;
    match (Version::parse(current), Version::parse(latest)) {
        (Ok(c), Ok(l)) => c.cmp(&l),
        (Err(e), _) => {
            tracing::warn!(
                target: "update",
                current,
                error = %e,
                "current version is not parseable as semver — falling back to lexicographic compare"
            );
            current.cmp(latest)
        }
        (_, Err(e)) => {
            tracing::warn!(
                target: "update",
                latest,
                error = %e,
                "latest version is not parseable as semver — falling back to lexicographic compare"
            );
            current.cmp(latest)
        }
    }
}

/// Build the `User-Agent`, `Accept`, and `X-GitHub-Api-Version`
/// headers GitHub's API expects.
fn default_headers(current_version: &str) -> Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    let ua = format!("agentsso/{current_version}");
    headers.insert(USER_AGENT, HeaderValue::from_str(&ua).context("invalid UA header")?);
    headers.insert(ACCEPT, HeaderValue::from_static("application/vnd.github+json"));
    headers.insert("X-GitHub-Api-Version", HeaderValue::from_static("2022-11-28"));
    Ok(headers)
}

/// Fetch + select the highest-semver published release. 30s total
/// timeout.
pub(crate) async fn fetch_latest_release(current_version: &str) -> Result<ReleaseInfo> {
    fetch_latest_release_with(current_version, &api_base_url()).await
}

/// Test seam — explicit base URL.
pub(crate) async fn fetch_latest_release_with(
    current_version: &str,
    base: &str,
) -> Result<ReleaseInfo> {
    // `per_page=100` is GitHub's max page size. The project has far
    // fewer than 100 releases; if that ever changes, selection would
    // miss older pages — but "the newest release is on page 1" holds
    // for any project that releases monotonically, and we sort by
    // semver within the page rather than trusting list order.
    let url = format!("{base}{REPO_PATH}/releases?per_page=100");
    // Single-hop redirect policy (was: review patch P14). The JSON
    // metadata is emitted into operator-visible output verbatim, so
    // keep it un-redirectable; an attacker who can MITM cannot chain
    // through hosts serving forged release JSON. The integrity-
    // critical path (Story 2's binary staging) is minisign-verified
    // separately.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::limited(1))
        .default_headers(default_headers(current_version)?)
        .build()
        .context("reqwest client build failed")?;

    let response = client.get(&url).send().await.with_context(|| format!("GET {url} failed"))?;

    let status = response.status();
    if !status.is_success() {
        return Err(anyhow!("GitHub Releases API returned {status} for {url}"));
    }

    // Bound the JSON read (was: review patch P10). A full release
    // list is larger than a single `/latest` object; 4MB is ~100
    // releases of generously-sized notes and still rejects a
    // multi-GB OOM attempt.
    const MAX_RELEASE_JSON_BYTES: usize = 4 * 1024 * 1024;
    let body_bytes =
        response.bytes().await.with_context(|| format!("read body from {url} failed"))?;
    if body_bytes.len() > MAX_RELEASE_JSON_BYTES {
        return Err(anyhow!(
            "GitHub releases body for {url} is {} bytes — exceeds {MAX_RELEASE_JSON_BYTES} byte cap",
            body_bytes.len()
        ));
    }
    let releases: Vec<ReleaseInfo> = serde_json::from_slice(&body_bytes)
        .with_context(|| format!("could not deserialize GitHub Releases list from {url}"))?;

    select_latest(releases)
        .ok_or_else(|| anyhow!("GitHub returned no usable (non-draft, semver-tagged) release"))
}

/// Pick the highest-[`semver::Version`] release among the non-draft
/// entries whose tag parses as semver.
///
/// - `draft` releases are excluded (unpublished — not deliverable).
/// - `prerelease` releases are KEPT (issue #58: this project ships
///   only prereleases; excluding them was the bug).
/// - Tags that fail `semver::Version::parse` are DROPPED before the
///   max, not lexically ranked — `compare_versions`'s lexical
///   fallback mis-orders (`rc.9 > rc.10` as strings); an
///   unparseable tag must never win selection.
pub(crate) fn select_latest(releases: Vec<ReleaseInfo>) -> Option<ReleaseInfo> {
    releases
        .into_iter()
        .filter(|r| !r.draft)
        .filter_map(|r| r.semver_version().map(|v| (v, r)))
        .max_by(|(a, _), (b, _)| a.cmp(b))
        .map(|(_, r)| r)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Construct a `ReleaseInfo` with just the fields selection
    /// cares about.
    fn mk(tag: &str, draft: bool, prerelease: bool) -> ReleaseInfo {
        ReleaseInfo { tag_name: tag.into(), name: None, published_at: None, draft, prerelease }
    }

    #[test]
    fn version_strips_v_prefix() {
        assert_eq!(mk("v0.4.0", false, false).version(), "0.4.0");
        assert_eq!(mk("0.4.0", false, false).version(), "0.4.0");
    }

    #[test]
    fn select_latest_picks_highest_among_all_prereleases() {
        // Issue #58: every permitlayer release is a prerelease.
        // `/releases/latest` would 404; selection must still work
        // and must pick rc.36 over rc.35/rc.34 (and NOT lexically
        // rank rc.9 above rc.10).
        let releases = vec![
            mk("v0.3.0-rc.34", false, true),
            mk("v0.3.0-rc.9", false, true),
            mk("v0.3.0-rc.36", false, true),
            mk("v0.3.0-rc.10", false, true),
            mk("v0.3.0-rc.35", false, true),
        ];
        let picked = select_latest(releases).expect("a release is selectable");
        assert_eq!(picked.tag_name, "v0.3.0-rc.36");
    }

    #[test]
    fn select_latest_drops_unparseable_tags_not_lexically_ranks_them() {
        // A garbage tag sorts lexically AFTER "0.3.0-rc.36" but is
        // not a valid version — it must be dropped, not selected.
        let releases = vec![mk("nightly-zzz", false, true), mk("v0.3.0-rc.36", false, true)];
        let picked = select_latest(releases).expect("the valid release wins");
        assert_eq!(picked.tag_name, "v0.3.0-rc.36");
    }

    #[test]
    fn select_latest_excludes_draft_releases() {
        // A draft with a higher version is unpublished — not
        // deliverable. The highest *non-draft* wins.
        let releases = vec![
            mk("v0.4.0", true, false), // draft, higher
            mk("v0.3.0-rc.36", false, true),
        ];
        let picked = select_latest(releases).expect("non-draft selected");
        assert_eq!(picked.tag_name, "v0.3.0-rc.36");
    }

    #[test]
    fn select_latest_returns_none_when_no_usable_release() {
        // All draft or all unparseable → nothing to select.
        let releases = vec![mk("v9.9.9", true, false), mk("not-semver", false, true)];
        assert!(select_latest(releases).is_none());
    }

    #[test]
    fn select_latest_prefers_stable_over_prerelease_at_same_base() {
        // semver orders 0.3.0 > 0.3.0-rc.36 (a prerelease is LESS
        // than its release). If a stable ever ships, it wins.
        let releases = vec![mk("v0.3.0-rc.36", false, true), mk("v0.3.0", false, false)];
        let picked = select_latest(releases).expect("stable wins");
        assert_eq!(picked.tag_name, "v0.3.0");
    }

    #[test]
    fn compare_versions_handles_double_digit_minor_correctly() {
        // String-sort would put 0.10.0 < 0.2.0 — the bug semver
        // protects against. Verify the semver path runs.
        assert_eq!(compare_versions("0.2.1", "0.10.0"), std::cmp::Ordering::Less);
        assert_eq!(compare_versions("0.10.0", "0.2.1"), std::cmp::Ordering::Greater);
        assert_eq!(compare_versions("0.4.0", "0.4.0"), std::cmp::Ordering::Equal);
    }

    #[test]
    fn compare_versions_falls_back_to_lex_on_parse_failure() {
        // Either side unparseable — semver crate rejects, fallback
        // to string comparison so we don't panic.
        assert_eq!(compare_versions("not-a-version", "0.4.0"), "not-a-version".cmp("0.4.0"));
    }

    #[test]
    fn api_base_url_with_explicit_override() {
        // Use the explicit-parameter seam rather than `set_var` —
        // the daemon crate forbids unsafe code, and Rust 2024 made
        // `env::set_var` unsafe.
        assert_eq!(api_base_url_with(Some("https://localhost:9999")), "https://localhost:9999");
        assert_eq!(api_base_url_with(None), api_base_url());
    }

    #[test]
    fn production_api_base_url_is_github_dot_com() {
        // Lock in the production URL so a typo in the constant
        // surfaces as a test failure (not an in-the-wild outage).
        assert_eq!(PRODUCTION_API_BASE_URL, "https://api.github.com");
    }

    #[test]
    fn repo_path_matches_minisign_trusted_install_source() {
        // Supply-chain pin (UX-overhaul Story 3): the drift-detector
        // MUST query the SAME repo the curl|sh installer trusts.
        // install.sh is the minisign-trusted source; if `REPO_PATH`
        // and install.sh's REPO_OWNER/REPO_NAME diverge, the updater
        // tells operators "you're behind" against a repo that isn't
        // the one they actually install from. Read install.sh at
        // compile time and assert the derived path equals REPO_PATH
        // — not a hardcoded mirror string that could itself drift.
        let install_sh = include_str!("../../../../../install/install.sh");
        let owner = install_sh
            .lines()
            .find_map(|l| l.trim().strip_prefix("REPO_OWNER="))
            .map(|v| v.trim().trim_matches('"'))
            .expect("install.sh defines REPO_OWNER");
        let name = install_sh
            .lines()
            .find_map(|l| l.trim().strip_prefix("REPO_NAME="))
            .map(|v| v.trim().trim_matches('"'))
            .expect("install.sh defines REPO_NAME");
        assert_eq!(
            REPO_PATH,
            format!("/repos/{owner}/{name}"),
            "drift-detector repo must match the minisign-trusted install source"
        );
    }
}
