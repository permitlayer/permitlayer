//! Story 11.16 — clean-install / v2-only residue guard.
//!
//! Epic 11 moves the whole credential model to v2 (Connection/Binding +
//! `(ConnectionId, Slot)` keying) with NO migration: a fresh install is
//! v2-only, and an upgrade is wipe-and-reseal. This test is the durable
//! backstop for AC#2 — it walks the workspace `src/` trees and fails if
//! any forbidden v1-keying residue reappears (a regression that
//! reintroduces the overloaded `service` keying, the deleted bridges, or
//! a credential-domain migration).
//!
//! It scans SOURCE only (`crates/*/src/**.rs`), excluding `tests/`, and
//! ignores comment-only lines + string-literal mentions in negative
//! assertions — the goal is "no live v1-keying CODE", not "the tokens
//! never appear in prose". Each forbidden token has a precise rationale
//! so a future contributor knows why it's banned.

use std::path::{Path, PathBuf};

/// Workspace root = two levels up from this crate's manifest dir
/// (`crates/permitlayer-daemon` → repo root).
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..").canonicalize().unwrap()
}

/// Walk every `crates/*/src/**/*.rs` file (production source — NOT tests).
fn iter_src_files() -> Vec<PathBuf> {
    let crates = workspace_root().join("crates");
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&crates).expect("read crates/") {
        let krate = entry.unwrap().path();
        let src = krate.join("src");
        if src.is_dir() {
            collect_rs(&src, &mut out);
        }
    }
    out
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let p = entry.unwrap().path();
        if p.is_dir() {
            collect_rs(&p, out);
        } else if p.extension().is_some_and(|e| e == "rs") {
            out.push(p);
        }
    }
}

/// A code line is one that is not blank and not a `//`/`///`/`//!`
/// comment. (Trailing `// ...` on a code line is fine — we only skip
/// lines whose first non-whitespace is a comment marker.)
fn is_code_line(line: &str) -> bool {
    let t = line.trim_start();
    !t.is_empty() && !t.starts_with("//")
}

/// Assert no `src/` code line contains `needle`. `allow` is a predicate
/// for legitimate code-line exceptions (e.g. a banned substring that is
/// part of a still-valid identifier in a specific file).
fn assert_no_code_hit(needle: &str, why: &str, allow: impl Fn(&Path, &str) -> bool) {
    let mut hits = Vec::new();
    for f in iter_src_files() {
        let body = std::fs::read_to_string(&f).unwrap_or_default();
        for (i, line) in body.lines().enumerate() {
            // Stop at the file's test module: `#[cfg(test)]` fixtures are
            // not production residue (and may legitimately exercise the
            // removed shapes for regression coverage).
            let trimmed = line.trim_start();
            if trimmed.starts_with("#[cfg(test)]") || trimmed == "mod tests {" {
                break;
            }
            if is_code_line(line) && line.contains(needle) && !allow(&f, line) {
                hits.push(format!("{}:{}: {}", f.display(), i + 1, line.trim()));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "forbidden v1-keying residue `{needle}` in source code ({why}):\n{}",
        hits.join("\n")
    );
}

#[test]
fn no_service_shim_or_bridge_residue() {
    // The 11.8→11.9/11.12 bridges. Both public (credential crate) and the
    // private proxy/daemon `conn_shim` modules are deleted by 11.10/11.12.
    assert_no_code_hit(
        "from_service_shim",
        "the service→ConnectionId shim is deleted",
        |_, _| false,
    );
    assert_no_code_hit(
        "connection_slot_from_service_key",
        "the service-key decomposition bridge is deleted",
        |_, _| false,
    );
    // `conn_shim` may appear in a comment referencing the retired module
    // (those are not code lines); a live `conn_shim::` path or `mod
    // conn_shim` is forbidden.
    assert_no_code_hit(
        "conn_shim",
        "the conn_shim modules are deleted (proxy 11.10, daemon 11.12)",
        |_, line| {
            // Allow nothing on a code line — any code reference is a regression.
            let _ = line;
            false
        },
    );
}

#[test]
fn no_closed_service_enum_residue() {
    // The three closed service enums retired in 11.7 + 11.12.
    assert_no_code_hit(
        "SUPPORTED_SERVICES",
        "connector existence is a registry query, not a closed enum",
        |_, _| false,
    );
    assert_no_code_hit(
        "CREDENTIAL_SUPPORTED_SERVICES",
        "the credential-side closed service enum is retired (11.12)",
        |_, _| false,
    );
}

#[test]
fn no_meta_json_provenance_residue() {
    // The `{service}-meta.json` provenance scheme is replaced by the
    // ConnectionStore record (11.12) and the proxy refresh path now reads
    // the sealed Client slot (11.16). No source code may read/write a
    // `-meta.json` credential provenance file.
    assert_no_code_hit(
        "-meta.json",
        "the -meta.json provenance scheme is replaced by ConnectionRecord",
        |f, line| {
            // Allow the `ProxyHostServices` `listConnectedServices` doc/enum
            // ONLY if it's not actually doing a meta read — but to keep this
            // strict, allow NO code hit. (The accessor doc that mentioned it
            // was updated in 11.16.) If this trips, the residue is real.
            let _ = (f, line);
            false
        },
    );
}

#[test]
fn no_agent_identity_policy_name_field() {
    // The precise thing deleted in 11.9 is the `policy_name` FIELD on the
    // `AgentIdentity` (+ its `AgentIdentityRaw` mirror) — an agent's
    // authority is now its set of bindings. `policy_name` legitimately
    // survives elsewhere as "the name of a policy" (register/bind DTOs,
    // the policy module, approval requests, audit attribution), so the
    // guard is scoped to the agent-identity module only.
    let identity = workspace_root().join("crates/permitlayer-core/src/agent/identity.rs");
    let body = std::fs::read_to_string(&identity).expect("read agent/identity.rs");
    let live: Vec<_> = body
        .lines()
        .enumerate()
        // Stop at the test module — its negative assertion
        // (`!toml_str.contains("policy_name")`) is the guard, not residue.
        .take_while(|(_, l)| {
            let t = l.trim_start();
            !(t.starts_with("#[cfg(test)]") || t == "mod tests {")
        })
        .filter(|(_, l)| is_code_line(l) && l.contains("policy_name"))
        .map(|(i, l)| format!("identity.rs:{}: {}", i + 1, l.trim()))
        .collect();
    assert!(
        live.is_empty(),
        "AgentIdentity.policy_name field must stay deleted (authority = bindings):\n{}",
        live.join("\n")
    );
}

#[test]
fn no_credential_domain_migration_residue() {
    // Epic 11 forbids a v1→v2 *keying-domain* migration (no
    // `<service>.sealed` → `<ulid>-<slot>.sealed` converter, no dual-read).
    // The pre-existing `envelope_v1_to_v2` migration is the ORTHOGONAL
    // on-disk envelope-SCHEMA migration (23→24-byte header, Story 7.6a) —
    // allowed. We ban the keying-domain v1 prefix appearing as a live
    // construction anywhere (the only legitimate mention is the
    // negative-assertion test in vault/seal.rs, which is a test line, not
    // src code under this scan's `is_code_line` for that crate — but it IS
    // src, so allow that one precise file+line shape).
    assert_no_code_hit(
        "permitlayer-vault-v1",
        "the v1 keying domain is gone; no dual-read/migration",
        |f, line| {
            // The vault seal.rs carries a `!contains(...v1...)` negative
            // assertion proving the domain is gone — that's the guard, not a
            // regression. Allow it only in that file when it's an assertion.
            f.to_string_lossy().contains("permitlayer-vault/src/seal.rs")
                && (line.contains("assert") || line.contains("contains_subsequence"))
        },
    );
}
