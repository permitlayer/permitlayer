//! Story 11.17 — multi-account end-to-end validation (automated).
//!
//! The originating blocker for Epic 11: ONE agent holding TWO accounts of
//! the SAME connector (Chuck = {chuck-gmail rw, austin-gmail ro}),
//! addressed by distinct `/mcp/<name>` (here `/v1/tools/<name>/…`)
//! selectors, each minting its own connection's token, with the
//! read-only account denying writes — and the two sealed credentials
//! cryptographically isolated (NFR51).
//!
//! Coverage split (matches the charter's AC#6 + the "Angie validation at
//! END" note):
//! - **Automated (this file, CI):** one agent, two gmail connections at
//!   distinct tiers + selectors; a write scope on the read-only selector
//!   is denied (`tier.denied`); a read scope on each selector passes authz
//!   and reaches dispatch (distinguishable from a 403); the two
//!   connections are distinct ids; their sealed credentials are
//!   cryptographically isolated.
//! - **Live (operator-run, Story 11.17 closeout):** the real send via
//!   `/mcp/chuck-gmail` reaching Chuck's mailbox + read via
//!   `/mcp/austin-gmail` reaching Austin's, on a freshly-wiped angie-2.
//!   That needs real Google OAuth and is NOT mockable in CI — it is the
//!   operator pass recorded at closeout, not this test.
//!
//! A real upstream Google API is not available in CI, so the "minting the
//! correct token" property is asserted at the boundary CI CAN observe: a
//! request that passes the tier ∩ granted-scope gate reaches dispatch
//! (and then fails to reach real Google — a non-403 upstream/internal
//! error), which is distinguishable from a request DENIED at authz (403).
//! The proxy-level `connection_binding_poc` (Story 11.11) already proved
//! per-connection token routing against a mock upstream.

use permitlayer_credential::{ConnectionId, Slot};
use permitlayer_vault::Vault;
use zeroize::Zeroizing;

use crate::common::{
    DaemonTestConfig, SeedTier, TEST_MASTER_KEY_HEX, decode_master_key_hex, http_post_control,
    http_request_with_headers, read_test_control_token, seed_connection_and_binding, start_daemon,
    wait_for_health,
};

const GMAIL_RO_URI: &str = "https://www.googleapis.com/auth/gmail.readonly";
const GMAIL_SEND_URI: &str = "https://www.googleapis.com/auth/gmail.send";
const GMAIL_MODIFY_URI: &str = "https://www.googleapis.com/auth/gmail.modify";
const GMAIL_COMPOSE_URI: &str = "https://www.googleapis.com/auth/gmail.compose";

fn boot(home: &std::path::Path) -> crate::common::DaemonHandle {
    let handle =
        start_daemon(DaemonTestConfig { port: 0, home: home.to_path_buf(), ..Default::default() });
    assert!(wait_for_health(handle.port), "daemon must come up healthy");
    handle
}

fn register_agent(port: u16, home: &std::path::Path, name: &str) -> String {
    // `register` still validates `--policy` against the shipped policy set
    // (the identity record carries it for display/audit; an agent's actual
    // request-time authority is its bindings, Story 11.9). Use a real
    // shipped policy name.
    let body = serde_json::json!({ "name": name, "policy_name": "gmail-read-only" }).to_string();
    let ctl = read_test_control_token(home);
    let headers = [("X-Agentsso-Control", ctl.as_str()), ("content-type", "application/json")];
    let (status, resp) =
        http_post_control(home, port, "/v1/control/agent/register", &body, &headers);
    assert_eq!(status, 200, "agent register should succeed for {name}: {resp}");
    let json: serde_json::Value = serde_json::from_str(&resp).unwrap();
    json["bearer_token"].as_str().expect("register returns a bearer").to_owned()
}

/// Drive a tool request through the proxy ingress and return the HTTP
/// status (the authz decision boundary CI can observe). The binding-
/// resolving proxy route is `/v1/tools/<selector>/...` — `<selector>` is
/// the connection name/alias, which `ProxyService::handle_inner` resolves
/// to the agent's binding → connection (Story 11.10). (The `/mcp/<sel>`
/// route is the connector-level MCP transport, NOT the per-connection
/// proxy path.)
fn tool_request(port: u16, selector: &str, token: &str, scope: &str) -> (u16, String) {
    http_request_with_headers(
        port,
        "GET",
        &format!("/v1/tools/{selector}/users/me"),
        None,
        &[("authorization", &format!("Bearer {token}")), ("x-agentsso-scope", scope)],
    )
}

#[test]
fn one_agent_two_gmail_connections_distinct_selectors_tier_enforced() {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();

    // Seed BEFORE boot: `try_build_proxy_service` only wires the real
    // proxy when sealed credentials already exist on disk (otherwise the
    // /mcp routes serve 501 stubs). Two gmail connections of the SAME
    // connector, distinct accounts, bound to agent "chuck" at distinct
    // tiers + selectors (aliases). The bearer is minted at register
    // (below); the binding keys on the agent NAME, which is stable.
    let rw_id = seed_connection_and_binding(
        home.path(),
        "chuck",
        "google-gmail",
        "chuck-gmail",
        SeedTier::ReadWrite,
        &[GMAIL_RO_URI, GMAIL_SEND_URI, GMAIL_MODIFY_URI, GMAIL_COMPOSE_URI],
        None,
        Some("chuck-gmail"),
        TEST_MASTER_KEY_HEX,
        Some(b"chuck-account-access-token"),
    );
    let ro_id = seed_connection_and_binding(
        home.path(),
        "chuck",
        "google-gmail",
        "austin-gmail",
        SeedTier::Read,
        &[GMAIL_RO_URI],
        None,
        Some("austin-gmail"),
        TEST_MASTER_KEY_HEX,
        Some(b"austin-account-access-token"),
    );
    // AC: two distinct connections (multi-account, FR47).
    assert_ne!(rw_id, ro_id, "the two accounts must be distinct connections");

    let handle = boot(home.path());
    let port = handle.port;

    // One agent — register mints its bearer; the seeded bindings already
    // reference "chuck" by name.
    let token = register_agent(port, home.path(), "chuck");

    // AC: a WRITE scope on the read-only selector is denied at the tier
    // gate (default-deny) — distinct from a missing binding.
    let (status, body) = tool_request(port, "austin-gmail", &token, "gmail.send");
    assert_eq!(status, 403, "write scope on the read-only selector must 403: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
    let code = json["error"]["code"].as_str().unwrap_or("");
    assert_eq!(code, "tier.denied", "read-only selector + write scope → tier.denied: {body}");

    // AC: a READ scope on the read-only selector PASSES authz (reaches
    // dispatch — which then fails to reach real Google in CI, a non-403
    // upstream/internal error, NOT an authz denial). The key signal is
    // "not 403 binding/tier/scope-denied".
    let (ro_read_status, ro_read_body) =
        tool_request(port, "austin-gmail", &token, "gmail.readonly");
    assert_ne!(
        ro_read_status, 403,
        "read scope on the read-only selector must PASS authz (reach dispatch), got 403: {ro_read_body}"
    );

    // AC: a READ scope on the read-write selector also passes authz and
    // routes to the OTHER connection (distinct selector → distinct
    // connection).
    let (rw_read_status, rw_read_body) =
        tool_request(port, "chuck-gmail", &token, "gmail.readonly");
    assert_ne!(
        rw_read_status, 403,
        "read scope on the read-write selector must PASS authz, got 403: {rw_read_body}"
    );

    // AC: an UNKNOWN selector for this agent → binding.not_found (403),
    // distinct from the tier-denial class.
    let (unknown_status, unknown_body) =
        tool_request(port, "no-such-conn", &token, "gmail.readonly");
    assert_eq!(unknown_status, 403, "unknown selector → 403: {unknown_body}");
    let uj: serde_json::Value = serde_json::from_str(&unknown_body).unwrap_or_default();
    assert_eq!(
        uj["error"]["code"].as_str().unwrap_or(""),
        "binding.not_found",
        "unknown selector → binding.not_found: {unknown_body}"
    );
}

#[test]
fn two_account_sealed_credentials_are_cryptographically_isolated() {
    // NFR51 end-to-end at the persisted-credential layer: the two
    // accounts' sealed access tokens, keyed on distinct ConnectionIds,
    // do not unseal under each other's id.
    let home = tempfile::tempdir().unwrap();
    let chuck_id = seed_connection_and_binding(
        home.path(),
        "chuck",
        "google-gmail",
        "chuck-gmail",
        SeedTier::ReadWrite,
        &[GMAIL_RO_URI, GMAIL_SEND_URI],
        None,
        Some("chuck-gmail"),
        TEST_MASTER_KEY_HEX,
        Some(b"chuck-account-access-token"),
    );
    let austin_id = seed_connection_and_binding(
        home.path(),
        "chuck",
        "google-gmail",
        "austin-gmail",
        SeedTier::Read,
        &[GMAIL_RO_URI],
        None,
        Some("austin-gmail"),
        TEST_MASTER_KEY_HEX,
        Some(b"austin-account-access-token"),
    );
    assert_ne!(chuck_id, austin_id);

    // Read the two sealed access envelopes off disk and confirm each
    // unseals ONLY under its own id (NFR51).
    let key = decode_master_key_hex(TEST_MASTER_KEY_HEX);
    let mut master = [0u8; permitlayer_keystore::MASTER_KEY_LEN];
    master.copy_from_slice(&key);
    let vault = Vault::new(Zeroizing::new(master), 0);

    let read_sealed = |id: ConnectionId| {
        let path = home.path().join(format!("vault/{id}-{}.sealed", Slot::Access.label()));
        let bytes = std::fs::read(&path).expect("sealed access envelope on disk");
        permitlayer_core::store::fs::credential_fs::decode_envelope(&bytes)
            .expect("decode envelope")
    };
    let chuck_sealed = read_sealed(chuck_id);
    let austin_sealed = read_sealed(austin_id);

    // Same id round-trips to the right account's token.
    let chuck_tok = vault.unseal(chuck_id, Slot::Access, &chuck_sealed).expect("chuck unseals");
    assert_eq!(chuck_tok.reveal(), b"chuck-account-access-token");
    let austin_tok = vault.unseal(austin_id, Slot::Access, &austin_sealed).expect("austin unseals");
    assert_eq!(austin_tok.reveal(), b"austin-account-access-token");

    // Cross-account: each sealed blob must NOT unseal under the other's id.
    assert!(
        vault.unseal(chuck_id, Slot::Access, &austin_sealed).is_err(),
        "austin's sealed bytes must not unseal under chuck's id (NFR51)"
    );
    assert!(
        vault.unseal(austin_id, Slot::Access, &chuck_sealed).is_err(),
        "chuck's sealed bytes must not unseal under austin's id (NFR51)"
    );
}
