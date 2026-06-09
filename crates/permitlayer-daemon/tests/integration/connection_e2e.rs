//! End-to-end tests for the `agentsso connection` verbs (Epic 11,
//! Stories 11.12 + 11.13, re-pointed in Story 11.18).
//!
//! **Story 11.18 regression guard (AC#6).** On a privileged macOS install
//! the daemon state dir is root-private (`home` = `0o710
//! root:permitlayer-clients`, the `connections/`/`bindings/`/`vault/`
//! subdirs `0o700 root`). The original 11.12/11.13 `connection
//! list/inspect/revoke` verbs read/mutated those stores **in-process** as
//! the unprivileged operator, which EPERM'd (`Operation not permitted`,
//! os error 1) — the verbs only worked under `sudo`. Story 11.18
//! re-points every connection verb through the daemon **control plane**
//! (loopback + control-token gated; the root daemon opens the stores), so
//! the unprivileged operator never opens a store in-process.
//!
//! These tests therefore boot the REAL daemon and drive the `agentsso`
//! binary against it — the verbs MUST succeed talking to the control
//! plane, NOT by reading the on-disk store directly. (A true root-vs-
//! operator uid split is not reproducible in a single-user CI test; the
//! load-bearing guarantee — "no connection verb opens a store
//! in-process" — is asserted structurally by
//! `connection_verbs_do_not_open_stores_in_process` below, and the
//! end-to-end control-plane routing is asserted by booting the daemon
//! here.)
//!
//! The OAuth-dance `connection add` happy path needs a live Google
//! endpoint and is exercised by the operator pass (Story 11.17) +
//! `oauth_seal`/`connection` unit tests; here we cover the
//! registry-validated unknown-connector error (daemon-free — the registry
//! check precedes the daemon gate), the empty-list path, and the
//! list → inspect → revoke → gone lifecycle including the multi-account
//! (two names → two ids) case.

use std::process::Command;

use permitlayer_credential::{ConnectionId, Slot};

use crate::common::{
    DaemonHandle, DaemonTestConfig, SeedTier, TEST_MASTER_KEY_HEX, agentsso_bin,
    http_request_with_headers, read_test_control_token, seed_connection_and_binding,
    start_daemon as start_daemon_common, wait_for_health,
};

const GMAIL_RO_URI: &str = "https://www.googleapis.com/auth/gmail.readonly";

fn start_daemon(home: &std::path::Path) -> DaemonHandle {
    let handle = start_daemon_common(DaemonTestConfig {
        port: 0,
        home: home.to_path_buf(),
        ..Default::default()
    });
    assert!(wait_for_health(handle.port), "daemon must boot healthy");
    handle
}

/// Run an `agentsso connection <args>` subcommand against the running
/// daemon (control-plane routed, Story 11.18).
fn run_connection(
    home: &std::path::Path,
    port: u16,
    args: &[&str],
) -> (Option<i32>, String, String) {
    let output = Command::new(agentsso_bin())
        .arg("connection")
        .args(args)
        .env("AGENTSSO_PATHS__HOME", home.to_str().unwrap())
        .env("AGENTSSO_HTTP__BIND_ADDR", format!("127.0.0.1:{port}"))
        .env("AGENTSSO_TEST_MASTER_KEY_HEX", TEST_MASTER_KEY_HEX)
        .output()
        .expect("spawn agentsso connection");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// `agentsso connection add <connector>` WITHOUT a daemon — only valid
/// for the unknown-connector path, which the registry rejects before the
/// daemon-reachable gate.
fn run_connection_no_daemon(
    home: &std::path::Path,
    args: &[&str],
) -> (Option<i32>, String, String) {
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

#[test]
fn connection_add_unknown_connector_errors_via_registry() {
    // AC#11: an unknown connector is rejected via the registry (no closed
    // enum) with a non-zero exit and a registry-sourced "Supported:" hint.
    // The registry check precedes the daemon-reachable gate, so this path
    // needs no daemon.
    let home = tempfile::TempDir::new().unwrap();
    let (status, _out, stderr) = run_connection_no_daemon(
        home.path(),
        &["add", "definitely-not-a-connector", "--name", "x"],
    );
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
fn connection_add_duplicate_name_rejected_via_control_plane_before_oauth() {
    // AC#3 (Story 11.18): the F7 duplicate-name pre-check goes through the
    // daemon control plane (the operator can't read the root-private store),
    // and runs BEFORE any OAuth/interactive work. Seed a connection named
    // `austin-gmail`, then `connection add ... --name austin-gmail` must exit
    // 2 with "already exists" — exercising the control-plane
    // `get_connection_record` Ok branch (connection.rs F7 check) without the
    // OAuth dance.
    let home = tempfile::TempDir::new().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    let daemon = start_daemon(home.path());
    seed_gmail(home.path(), "agent-one", "austin-gmail", SeedTier::Read);

    let (status, out, stderr) = run_connection(
        home.path(),
        daemon.port,
        &["add", "google-gmail", "--name", "austin-gmail", "--non-interactive"],
    );
    let combined = format!("{out}{stderr}");
    assert_eq!(status, Some(2), "duplicate --name should exit 2; out+err={combined}");
    assert!(
        combined.contains("already exists") || combined.contains("duplicate_name"),
        "should name the duplicate-name rejection (control-plane F7 check): {combined}"
    );
    drop(daemon);
}

#[test]
fn connection_list_empty_when_no_connections() {
    let home = tempfile::TempDir::new().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    let daemon = start_daemon(home.path());
    let (status, out, stderr) = run_connection(home.path(), daemon.port, &["list"]);
    assert_eq!(status, Some(0), "empty list should succeed; stderr={stderr}");
    // Empty-state guidance points at `connection add`.
    let combined = format!("{out}{stderr}");
    assert!(
        combined.contains("connection add") || combined.to_lowercase().contains("no connection"),
        "empty list should hint at `connection add`: {combined}"
    );
    drop(daemon);
}

#[test]
fn connection_list_then_inspect_shows_seeded_record() {
    // AC#9: list shows name/connector/tier/status; inspect adds
    // granted_scopes + trust_tier. Both verbs route through the daemon
    // control plane (Story 11.18).
    let home = tempfile::TempDir::new().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    let daemon = start_daemon(home.path());
    seed_gmail(home.path(), "agent-one", "austin-gmail", SeedTier::Read);

    let (status, out, stderr) = run_connection(home.path(), daemon.port, &["list"]);
    assert_eq!(status, Some(0), "list should succeed; stderr={stderr}");
    assert!(out.contains("austin-gmail"), "list should show the connection name: {out}");
    assert!(
        out.contains("google-gmail") || out.contains("gmail"),
        "list should show the connector: {out}"
    );

    let (status, out, stderr) =
        run_connection(home.path(), daemon.port, &["inspect", "austin-gmail"]);
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
    drop(daemon);
}

#[test]
fn connection_revoke_removes_record_slots_and_bindings() {
    // AC#10: revoke removes the record + sealed slots + bindings; a later
    // resolution finds nothing. The cascade runs DAEMON-SIDE (Story 11.18)
    // — the operator never mutates the root-private store in-process.
    let home = tempfile::TempDir::new().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    let daemon = start_daemon(home.path());
    let id = seed_gmail(home.path(), "agent-one", "austin-gmail", SeedTier::Read);

    // Pre-state: record file, sealed access slot, and binding all exist.
    let conn_file = home.path().join(format!("connections/{id}.toml"));
    let sealed_file = home.path().join(format!("vault/{id}-{}.sealed", Slot::Access.label()));
    let binding_file = home.path().join("bindings/agent-one.toml");
    assert!(conn_file.exists(), "connection record should exist pre-revoke");
    assert!(sealed_file.exists(), "sealed access slot should exist pre-revoke");
    assert!(binding_file.exists(), "binding should exist pre-revoke");

    let (status, _out, stderr) =
        run_connection(home.path(), daemon.port, &["revoke", "austin-gmail"]);
    assert_eq!(status, Some(0), "revoke should succeed; stderr={stderr}");

    // Post-state: the record, the sealed slot, and the agent's binding to
    // this connection are all gone (the daemon-side cascade).
    assert!(!conn_file.exists(), "connection record must be removed by revoke");
    assert!(!sealed_file.exists(), "sealed access slot must be removed by revoke");
    // The agent had exactly one binding (to this connection); removing it
    // empties the file, which the BindingStore deletes.
    assert!(
        !binding_file.exists(),
        "agent's last binding to the revoked connection must be removed"
    );

    // A revoke of a now-absent connection is a clean error (not a panic):
    // `connection.not_found` → exit 2.
    let (status, _out, _stderr) =
        run_connection(home.path(), daemon.port, &["revoke", "austin-gmail"]);
    assert_eq!(status, Some(2), "second revoke → connection.not_found exit 2");
    drop(daemon);
}

#[test]
fn connection_revoke_cascade_detaches_binding_observed_at_proxy() {
    // AC#6 + AC#10: after a control-plane revoke, the agent's binding to
    // the revoked connection is gone — a subsequent proxy request on that
    // selector resolves to `binding.not_found` (403), proving the cascade
    // detached the binding end-to-end, not just the on-disk file.
    let home = tempfile::TempDir::new().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();

    // Seed the connection + binding + sealed credential BEFORE boot:
    // `try_build_proxy_service` only wires the real proxy when a sealed
    // credential already exists on disk at boot (otherwise the `/v1/tools`
    // routes serve 501 stubs). The binding keys on the agent NAME, which
    // is stable; the bearer is minted at register (after boot).
    seed_connection_and_binding(
        home.path(),
        "chuck",
        "google-gmail",
        "chuck-gmail",
        SeedTier::Read,
        &[GMAIL_RO_URI],
        None,
        Some("chuck-gmail"),
        TEST_MASTER_KEY_HEX,
        Some(b"chuck-access-token"),
    );

    let daemon = start_daemon(home.path());
    let port = daemon.port;

    // Register the agent (mints a bearer); the seeded binding already
    // references "chuck" by name.
    let body = serde_json::json!({ "name": "chuck", "policy_name": "gmail-read-only" }).to_string();
    let ctl = read_test_control_token(home.path());
    let headers = [("X-Agentsso-Control", ctl.as_str()), ("content-type", "application/json")];
    let (rstatus, rresp) = crate::common::http_post_control(
        home.path(),
        port,
        "/v1/control/agent/register",
        &body,
        &headers,
    );
    assert_eq!(rstatus, 200, "agent register should succeed: {rresp}");
    let token = serde_json::from_str::<serde_json::Value>(&rresp).unwrap()["bearer_token"]
        .as_str()
        .expect("register returns a bearer")
        .to_owned();

    // Pre-revoke: a read request on the selector PASSES authz (reaches
    // dispatch — NOT a 403 binding/tier denial).
    let (pre_status, pre_body) = http_request_with_headers(
        port,
        "GET",
        "/v1/tools/chuck-gmail/users/me",
        None,
        &[("authorization", &format!("Bearer {token}")), ("x-agentsso-scope", "gmail.readonly")],
    );
    assert_ne!(pre_status, 403, "pre-revoke read must pass authz (reach dispatch): {pre_body}");

    // Revoke via the CLI (control-plane cascade).
    let (status, _out, stderr) = run_connection(home.path(), port, &["revoke", "chuck-gmail"]);
    assert_eq!(status, Some(0), "revoke should succeed; stderr={stderr}");

    // Post-revoke: the SAME request now resolves to binding.not_found (403)
    // — the cascade detached the binding.
    let (post_status, post_body) = http_request_with_headers(
        port,
        "GET",
        "/v1/tools/chuck-gmail/users/me",
        None,
        &[("authorization", &format!("Bearer {token}")), ("x-agentsso-scope", "gmail.readonly")],
    );
    assert_eq!(post_status, 403, "post-revoke request must 403: {post_body}");
    let json: serde_json::Value = serde_json::from_str(&post_body).unwrap_or_default();
    assert_eq!(
        json["error"]["code"].as_str().unwrap_or(""),
        "binding.not_found",
        "post-revoke selector → binding.not_found (cascade detached the binding): {post_body}"
    );
    drop(daemon);
}

#[test]
fn connection_add_two_names_are_distinct_connections() {
    // AC#12: two connections of the same connector under different names
    // are two distinct ConnectionIds (multi-account). We seed (rather than
    // run the OAuth dance) two named gmail connections for one agent and
    // assert two distinct records + that `list` (control-plane) shows both.
    let home = tempfile::TempDir::new().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    let daemon = start_daemon(home.path());
    let id_a = seed_gmail(home.path(), "chuck", "chuck-gmail", SeedTier::ReadWrite);
    let id_b = seed_gmail(home.path(), "chuck", "austin-gmail", SeedTier::Read);
    assert_ne!(id_a, id_b, "two named connections must have distinct ids");

    let (status, out, stderr) = run_connection(home.path(), daemon.port, &["list"]);
    assert_eq!(status, Some(0), "list should succeed; stderr={stderr}");
    assert!(out.contains("chuck-gmail"), "list should show chuck-gmail: {out}");
    assert!(out.contains("austin-gmail"), "list should show austin-gmail: {out}");
    drop(daemon);
}

#[test]
fn connection_verbs_do_not_open_stores_in_process() {
    // Story 11.18 structural regression guard (AC#6): the EPERM defect was
    // caused by the connection/bind/agent verbs opening the root-private
    // stores IN-PROCESS as the unprivileged operator. The fix re-points
    // every verb through the control plane, so the CLI verb modules must
    // contain NO `*FsStore::new(...)` store-constructor calls. This guard
    // fails loudly if a future edit reintroduces an in-process store open.
    let verb_files = [
        ("connection.rs", include_str!("../../src/cli/connection.rs")),
        ("bind.rs", include_str!("../../src/cli/bind.rs")),
        ("agent.rs", include_str!("../../src/cli/agent.rs")),
    ];
    for (name, src) in verb_files {
        for needle in ["ConnectionFsStore::new", "BindingFsStore::new", "CredentialFsStore::new"] {
            assert!(
                !src.contains(needle),
                "cli/{name} must not open a store in-process (found `{needle}`) — \
                 the operator can't read the root-private state dir; route via the \
                 control plane (Story 11.18 regression)"
            );
        }
    }
}
