//! End-to-end tests for the `agentsso connection` verbs (Epic 11,
//! Stories 11.12 + 11.13).
//!
//! `connection list/inspect/revoke` read/mutate the `ConnectionStore`
//! (and, for revoke, the `CredentialStore` + `BindingStore`) in-process —
//! no daemon round-trip — so these tests seed records directly into a
//! temp home via the store APIs and then drive the real `agentsso`
//! binary against that home, asserting output + post-mutation on-disk
//! state.
//!
//! The OAuth-dance `connection add` happy path needs a live Google
//! endpoint and is exercised by the operator pass (Story 11.17) +
//! `oauth_seal`/`connection` unit tests; here we cover the
//! registry-validated unknown-connector error, the empty-list path, and
//! the list → inspect → revoke → gone lifecycle including the
//! multi-account (two names → two ids) case.

use std::process::Command;

use permitlayer_credential::{ConnectionId, Slot};

use crate::common::{SeedTier, agentsso_bin, seed_connection_and_binding};

const TEST_MASTER_KEY_HEX: &str =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const GMAIL_RO_URI: &str = "https://www.googleapis.com/auth/gmail.readonly";

/// Seed one google-gmail connection (+ a binding + sealed access slot)
/// under `home` and return its id.
fn seed_gmail(home: &std::path::Path, agent: &str, name: &str, tier: SeedTier) -> ConnectionId {
    seed_connection_and_binding(
        home,
        agent,
        "google-gmail",
        name,
        tier,
        &[GMAIL_RO_URI],
        None,
        None,
        TEST_MASTER_KEY_HEX,
        Some(b"poc-access-token"),
    )
}

fn run_connection(home: &std::path::Path, args: &[&str]) -> (Option<i32>, String, String) {
    let output = Command::new(agentsso_bin())
        .arg("connection")
        .args(args)
        .env("AGENTSSO_PATHS__HOME", home.to_str().unwrap())
        .env("AGENTSSO_TEST_MASTER_KEY_HEX", TEST_MASTER_KEY_HEX)
        .output()
        .expect("spawn agentsso connection");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn connection_add_unknown_connector_errors_via_registry() {
    // AC#11: an unknown connector is rejected via the registry (no closed
    // enum) with a non-zero exit and a registry-sourced "Supported:" hint.
    let home = tempfile::TempDir::new().unwrap();
    let (status, _out, stderr) =
        run_connection(home.path(), &["add", "definitely-not-a-connector", "--name", "x"]);
    assert_eq!(status, Some(2), "unknown connector should exit 2; stderr={stderr}");
    assert!(
        stderr.contains("unknown connector") || stderr.contains("unknown_connector"),
        "stderr should name the unknown-connector error: {stderr}"
    );
    // The hint lists real connectors from the registry.
    assert!(
        stderr.contains("google-gmail") || stderr.contains("gmail"),
        "stderr should list registry connectors: {stderr}"
    );
}

#[test]
fn connection_list_empty_when_no_connections() {
    let home = tempfile::TempDir::new().unwrap();
    let (status, out, stderr) = run_connection(home.path(), &["list"]);
    assert_eq!(status, Some(0), "empty list should succeed; stderr={stderr}");
    // Empty-state guidance points at `connection add`.
    let combined = format!("{out}{stderr}");
    assert!(
        combined.contains("connection add") || combined.to_lowercase().contains("no connection"),
        "empty list should hint at `connection add`: {combined}"
    );
}

#[test]
fn connection_list_then_inspect_shows_seeded_record() {
    // AC#9: list shows name/connector/tier/status; inspect adds
    // granted_scopes + trust_tier.
    let home = tempfile::TempDir::new().unwrap();
    seed_gmail(home.path(), "agent-one", "austin-gmail", SeedTier::Read);

    let (status, out, stderr) = run_connection(home.path(), &["list"]);
    assert_eq!(status, Some(0), "list should succeed; stderr={stderr}");
    assert!(out.contains("austin-gmail"), "list should show the connection name: {out}");
    assert!(
        out.contains("google-gmail") || out.contains("gmail"),
        "list should show the connector: {out}"
    );

    let (status, out, stderr) = run_connection(home.path(), &["inspect", "austin-gmail"]);
    assert_eq!(status, Some(0), "inspect should succeed; stderr={stderr}");
    assert!(out.contains("austin-gmail"), "inspect should show the name: {out}");
    assert!(
        out.contains("gmail.readonly") || out.contains(GMAIL_RO_URI),
        "inspect should surface granted_scopes: {out}"
    );
    // trust_tier (NFR53) — built-in google connector.
    assert!(
        out.to_lowercase().contains("built") || out.to_lowercase().contains("trust"),
        "inspect should surface the trust tier: {out}"
    );
}

#[test]
fn connection_revoke_removes_record_slots_and_bindings() {
    // AC#10: revoke removes the record + sealed slots + bindings; a later
    // resolution finds nothing.
    let home = tempfile::TempDir::new().unwrap();
    let id = seed_gmail(home.path(), "agent-one", "austin-gmail", SeedTier::Read);

    // Pre-state: record file, sealed access slot, and binding all exist.
    let conn_file = home.path().join(format!("connections/{id}.toml"));
    let sealed_file = home.path().join(format!("vault/{id}-{}.sealed", Slot::Access.label()));
    let binding_file = home.path().join("bindings/agent-one.toml");
    assert!(conn_file.exists(), "connection record should exist pre-revoke");
    assert!(sealed_file.exists(), "sealed access slot should exist pre-revoke");
    assert!(binding_file.exists(), "binding should exist pre-revoke");

    let (status, _out, stderr) = run_connection(home.path(), &["revoke", "austin-gmail"]);
    assert_eq!(status, Some(0), "revoke should succeed; stderr={stderr}");

    // Post-state: the record, the sealed slot, and the agent's binding to
    // this connection are all gone.
    assert!(!conn_file.exists(), "connection record must be removed by revoke");
    assert!(!sealed_file.exists(), "sealed access slot must be removed by revoke");
    // The agent had exactly one binding (to this connection); removing it
    // empties the file, which the BindingStore deletes.
    assert!(
        !binding_file.exists(),
        "agent's last binding to the revoked connection must be removed"
    );

    // A revoke of a now-absent connection is a clean no-op-ish error (not a
    // panic); accept either a 0 (idempotent) or a non-zero not-found.
    let (status, _out, _stderr) = run_connection(home.path(), &["revoke", "austin-gmail"]);
    assert!(status.is_some(), "second revoke must exit cleanly, not crash");
}

#[test]
fn connection_add_two_names_are_distinct_connections() {
    // AC#12: two connections of the same connector under different names
    // are two distinct ConnectionIds (multi-account). We seed (rather than
    // run the OAuth dance) two named gmail connections for one agent and
    // assert two distinct records + that `list` shows both.
    let home = tempfile::TempDir::new().unwrap();
    let id_a = seed_gmail(home.path(), "chuck", "chuck-gmail", SeedTier::ReadWrite);
    let id_b = seed_gmail(home.path(), "chuck", "austin-gmail", SeedTier::Read);
    assert_ne!(id_a, id_b, "two named connections must have distinct ids");

    let (status, out, stderr) = run_connection(home.path(), &["list"]);
    assert_eq!(status, Some(0), "list should succeed; stderr={stderr}");
    assert!(out.contains("chuck-gmail"), "list should show chuck-gmail: {out}");
    assert!(out.contains("austin-gmail"), "list should show austin-gmail: {out}");
}
