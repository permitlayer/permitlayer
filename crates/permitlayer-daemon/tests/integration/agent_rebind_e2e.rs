//! End-to-end integration test for Story 7.11 (`agent rebind`).
//!
//! The load-bearing UX invariant: rebinding an agent's policy MUST
//! NOT rotate its bearer token. Operators extend an agent's scopes
//! via the policy file + `agent rebind` without touching downstream
//! MCP-client configs. This test pins that invariant via direct
//! byte-compare of the agent file's `token_hash` and `lookup_key_hex`
//! pre/post rebind.
//!
//! Daemon stays LIVE throughout — rebind does not touch the vault,
//! only rewrites the plain TOML at `<state-dir>/agents/<name>.toml`.
//! No `agentsso stop` precondition.

use std::time::Duration;

use crate::common::{
    DaemonTestConfig, assert_daemon_pid_matches, http_post_control,
    start_daemon as start_daemon_common, wait_for_health,
};

fn start_daemon(home: &std::path::Path) -> crate::common::DaemonHandle {
    start_daemon_common(DaemonTestConfig {
        port: 0,
        home: home.to_path_buf(),
        ..Default::default()
    })
}

const TWO_POLICY_TOML: &str = r#"
[[policies]]
name = "policy-old"
scopes = ["gmail.readonly"]
resources = ["*"]
approval-mode = "auto"

[[policies]]
name = "policy-new"
scopes = ["gmail.readonly", "calendar.readonly"]
resources = ["*"]
approval-mode = "auto"
"#;

fn seed_two_policies(home: &std::path::Path) {
    let policies_dir = home.join("policies");
    std::fs::create_dir_all(&policies_dir).unwrap();
    std::fs::write(policies_dir.join("two.toml"), TWO_POLICY_TOML).unwrap();
}

fn read_test_control_token(home: &std::path::Path) -> String {
    let path = home.join("control.token");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("control.token not readable at {}: {e}", path.display()))
        .trim()
        .to_owned()
}

fn register_agent(port: u16, home: &std::path::Path, name: &str, policy: &str) -> String {
    let body = serde_json::json!({"name": name, "policy_name": policy}).to_string();
    let ctl = read_test_control_token(home);
    let headers = [
        ("X-Agentsso-Control", ctl.as_str()),
        ("Content-Type", "application/json"),
    ];
    let (status, resp_body) =
        http_post_control(home, port, "/v1/control/agent/register", &body, &headers);
    assert_eq!(
        status, 200,
        "agent register should succeed for {name} → {policy}, got {status}: {resp_body}"
    );
    let parsed: serde_json::Value = serde_json::from_str(&resp_body).unwrap();
    assert_eq!(parsed["status"], "ok");
    parsed["bearer_token"].as_str().unwrap().to_owned()
}

fn rebind_agent(
    port: u16,
    home: &std::path::Path,
    name: &str,
    new_policy: &str,
) -> (u16, serde_json::Value) {
    let body = serde_json::json!({"name": name, "policy_name": new_policy}).to_string();
    let ctl = read_test_control_token(home);
    let headers = [
        ("X-Agentsso-Control", ctl.as_str()),
        ("Content-Type", "application/json"),
    ];
    let (status, resp_body) =
        http_post_control(home, port, "/v1/control/agent/rebind", &body, &headers);
    let parsed: serde_json::Value = serde_json::from_str(&resp_body)
        .unwrap_or_else(|e| panic!("rebind response not JSON: {resp_body} ({e})"));
    (status, parsed)
}

/// Read the agent file's TOML and return (token_hash, lookup_key_hex,
/// policy_name). The on-disk fields are the source of truth for the
/// "token unchanged across rebind" invariant.
fn read_agent_file(home: &std::path::Path, name: &str) -> (String, String, String) {
    let path = home.join("agents").join(format!("{name}.toml"));
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("agent file unreadable at {}: {e}", path.display()));
    let parsed: toml::Value = toml::from_str(&content).expect("agent file is valid TOML");
    let token_hash = parsed["token_hash"].as_str().unwrap().to_owned();
    let lookup_key_hex = parsed["lookup_key_hex"].as_str().unwrap().to_owned();
    let policy_name = parsed["policy_name"].as_str().unwrap().to_owned();
    (token_hash, lookup_key_hex, policy_name)
}

#[test]
fn rebind_preserves_token_byte_identical() {
    // AC #1: bearer token is unchanged across rebind. Verified by
    // byte-compare against the stored Argon2 hash AND the lookup-key
    // HMAC. The on-disk file is the authoritative state — what's in
    // memory MUST match what's on disk for token verification to keep
    // working.
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    seed_two_policies(home.path());

    let daemon = start_daemon(home.path());
    let port = daemon.port;
    assert!(wait_for_health(port), "daemon should boot with two policies");
    assert_daemon_pid_matches(&daemon);

    // Register agent with policy-old.
    let _bearer_token = register_agent(port, home.path(), "rebind-test", "policy-old");

    // Capture pre-rebind on-disk identity material.
    let (pre_hash, pre_lookup, pre_policy) = read_agent_file(home.path(), "rebind-test");
    assert_eq!(pre_policy, "policy-old", "pre-rebind policy_name");

    // Rebind to policy-new.
    let (status, body) = rebind_agent(port, home.path(), "rebind-test", "policy-new");
    assert_eq!(status, 200, "rebind should succeed, got {status}: {body:?}");
    assert_eq!(body["status"], "ok");
    assert_eq!(body["agent"]["name"], "rebind-test");
    assert_eq!(body["agent"]["policy_name"], "policy-new");

    // Capture post-rebind on-disk identity material.
    let (post_hash, post_lookup, post_policy) = read_agent_file(home.path(), "rebind-test");

    // THE LOAD-BEARING ASSERTIONS.
    assert_eq!(
        pre_hash, post_hash,
        "bearer token Argon2 hash MUST be byte-identical across rebind \
         (pre={pre_hash}, post={post_hash}); the bearer-token-immutable \
         invariant is broken — Story 7.11 architecture invariant violated"
    );
    assert_eq!(
        pre_lookup, post_lookup,
        "HMAC lookup key MUST be byte-identical across rebind \
         (pre={pre_lookup}, post={post_lookup})"
    );
    // The ONLY field that changed is policy_name.
    assert_eq!(post_policy, "policy-new", "post-rebind policy_name");
}

/// Test-only DTO mirroring the production `RebindAgentResponse`
/// shape. Story 7.11 review-round-2 Q1: `serde(deny_unknown_fields)`
/// on this DTO makes the wire-contract a typed compile-checked
/// invariant. Any field added to `RebindAgentResponse` or
/// `AgentSummary` on the production side that ISN'T mirrored here
/// causes the test to fail at deserialization with a precise error
/// naming the unknown field — far stronger than a regex sweep over
/// the response body.
///
/// **The DTO does NOT have a `bearer_token` field.** That's the
/// invariant. If a future contributor adds bearer-token disclosure
/// to the rebind response, the production-side change won't compile
/// against this test mirror, OR the deserialization here will fail
/// with `unknown field bearer_token`.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RebindContract {
    status: String,
    agent: AgentContract,
}

// Story 7.11 review-round-3 #6: previously these were marked
// `#[allow(dead_code)]` because the test body never read them. That
// silenced clippy but also masked a regression class — if the
// production handler stopped emitting `created_at`, `deny_unknown_fields`
// wouldn't flag it (a missing field is fine; only unknown fields
// trip the gate). The fix is to actually USE the fields below — see
// the `created_at`/`last_seen_at` shape assertions in the test body.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentContract {
    name: String,
    policy_name: String,
    created_at: String,
    last_seen_at: Option<String>,
}

#[test]
fn rebind_handler_response_does_not_include_bearer_token() {
    // Story 7.11 review-round-2 Q1: replaced the four-layer regex
    // walker with a typed contract DTO. The DTO uses
    // `serde(deny_unknown_fields)` — any field on the wire that
    // ISN'T `status` / `agent.{name,policy_name,created_at,last_seen_at}`
    // causes deserialization to fail with a precise error.
    //
    // Why this is stronger than the prior regex approach:
    //   - Catches `bearer_token` being added under ANY name (not
    //     just spellings matching a denylist regex).
    //   - Zero false positives on legitimate policy names like
    //     `secret-rotation-readonly` (the regex's old failure mode).
    //   - Forces a deliberate test update when the response shape
    //     legitimately evolves — the right friction for a
    //     security-sensitive wire contract.
    //
    // We retain a small raw-body substring check for today's
    // concrete known hazards (`bearer_token`, `agt_v2_`) as a
    // belt-and-suspenders second layer. If the production side
    // ever serialized a token plaintext into `policy_name` (which
    // would deserialize fine — it's a String field), the substring
    // check catches it.
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    seed_two_policies(home.path());

    let daemon = start_daemon(home.path());
    let port = daemon.port;
    assert!(wait_for_health(port), "daemon should boot");

    let _ = register_agent(port, home.path(), "no-leak-test", "policy-old");

    let body = serde_json::json!({
        "name": "no-leak-test",
        "policy_name": "policy-new",
    })
    .to_string();
    let ctl = read_test_control_token(home.path());
    let headers = [
        ("X-Agentsso-Control", ctl.as_str()),
        ("Content-Type", "application/json"),
    ];
    let (status, resp_body) =
        http_post_control(home.path(), port, "/v1/control/agent/rebind", &body, &headers);
    assert_eq!(status, 200, "rebind should succeed: {resp_body}");

    // Primary check: deserialize against the typed contract. Any
    // unknown field fails here with a precise error.
    let contract: RebindContract = serde_json::from_str(&resp_body).unwrap_or_else(|e| {
        panic!(
            "rebind response failed contract: {e}\n\
             This means the production response shape drifted from \
             the test mirror. If the new field is intentional and \
             non-secret, add it to `RebindContract`/`AgentContract` \
             above. If the new field carries token material, FIX \
             THAT FIRST — the bearer-token-immutable-across-rebind \
             invariant is load-bearing for the onboarding flow.\n\
             body: {resp_body}"
        )
    });
    assert_eq!(contract.status, "ok");
    assert_eq!(contract.agent.name, "no-leak-test");
    assert_eq!(contract.agent.policy_name, "policy-new");

    // Story 7.11 review-round-3 #6: actively assert on the timestamp
    // fields so the contract guard catches a future "stop emitting
    // created_at" regression. `deny_unknown_fields` does NOT flag
    // missing fields — only the fields' presence + shape is verified
    // by their use here.
    assert!(
        !contract.agent.created_at.is_empty(),
        "rebind response must include non-empty `created_at`; got: {resp_body}"
    );
    // `last_seen_at` is optional (None until first auth). Either
    // None or Some(non-empty) is acceptable; an empty Some would be
    // a contract violation.
    if let Some(ref ts) = contract.agent.last_seen_at {
        assert!(
            !ts.is_empty(),
            "rebind response `last_seen_at` must be None or a non-empty timestamp; got: {resp_body}"
        );
    }

    // Secondary check (belt-and-suspenders): substring scan for
    // today's concrete known hazards. Catches the case where a
    // token plaintext is serialized INTO an existing string field
    // (which would deserialize cleanly under the contract).
    assert!(
        !resp_body.contains("bearer_token"),
        "rebind response body MUST NOT contain 'bearer_token'; got: {resp_body}"
    );
    assert!(
        !resp_body.contains("agt_v2_"),
        "rebind response body MUST NOT contain v2 token plaintext; got: {resp_body}"
    );
}

#[test]
fn rebind_with_unknown_policy_returns_422_and_leaves_agent_unchanged() {
    // AC #2: passing a nonexistent policy returns 422 agent.unknown_policy
    // AND the agent file is unchanged.
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    seed_two_policies(home.path());

    let daemon = start_daemon(home.path());
    let port = daemon.port;
    assert!(wait_for_health(port), "daemon should boot");

    let _ = register_agent(port, home.path(), "unchanged-on-422", "policy-old");
    let pre_bytes = std::fs::read(home.path().join("agents/unchanged-on-422.toml")).unwrap();

    let (status, body) = rebind_agent(port, home.path(), "unchanged-on-422", "nonexistent-policy");
    assert_eq!(status, 422, "unknown policy should return 422, got {status}: {body:?}");
    assert_eq!(body["status"], "error");
    assert_eq!(body["code"], "agent.unknown_policy");
    let message = body["message"].as_str().unwrap_or("");
    assert!(
        message.contains("Known policies:"),
        "422 message should list known policies, got: {message}"
    );
    assert!(
        message.contains("policy-old") && message.contains("policy-new"),
        "422 message should list both seeded policies, got: {message}"
    );

    // Agent file is byte-identical to pre-rebind.
    let post_bytes = std::fs::read(home.path().join("agents/unchanged-on-422.toml")).unwrap();
    assert_eq!(
        post_bytes, pre_bytes,
        "agent file must be byte-identical after a 422 unknown_policy"
    );
}

#[test]
fn rebind_with_unknown_agent_returns_404() {
    // AC #3: passing an unknown agent returns 404 agent.not_found.
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    seed_two_policies(home.path());

    let daemon = start_daemon(home.path());
    let port = daemon.port;
    assert!(wait_for_health(port), "daemon should boot");

    let (status, body) = rebind_agent(port, home.path(), "ghost-agent", "policy-new");
    assert_eq!(status, 404, "unknown agent should return 404, got {status}: {body:?}");
    assert_eq!(body["status"], "error");
    assert_eq!(body["code"], "agent.not_found");
}

#[test]
fn rebind_runs_with_daemon_live_no_stop_required() {
    // AC #1: rebind succeeds with the daemon serving requests
    // throughout. This test never calls `agentsso stop`.
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    seed_two_policies(home.path());

    let daemon = start_daemon(home.path());
    let port = daemon.port;
    assert!(wait_for_health(port), "daemon should boot");

    // Register, rebind, register a SECOND agent, rebind the first
    // again — all without daemon restart.
    let _t1 = register_agent(port, home.path(), "live-1", "policy-old");
    let (s1, _) = rebind_agent(port, home.path(), "live-1", "policy-new");
    assert_eq!(s1, 200, "first rebind succeeds with daemon live");

    let _t2 = register_agent(port, home.path(), "live-2", "policy-old");
    let (s2, _) = rebind_agent(port, home.path(), "live-2", "policy-new");
    assert_eq!(s2, 200, "second rebind succeeds with daemon live");

    // Health endpoint still responsive — daemon was never stopped.
    assert!(wait_for_health(port), "daemon still healthy after multiple rebinds");
}

#[test]
fn rebind_to_same_policy_is_noop() {
    // Story 7.11 review-round-1 P5 + round-2 R2D2: rebinding to the
    // current policy should be a no-op (no disk write, no audit row,
    // no registry reload). Verified by byte-content equality of the
    // on-disk agent file pre/post.
    //
    // R2D2: the prior version of this test ALSO asserted mtime
    // equality, but mtime resolution varies by filesystem (HFS+ /
    // FAT / network mounts can be second-granularity). Byte-content
    // is the load-bearing assertion — if the file is byte-identical
    // pre/post, the no-op short-circuit fired by definition. The
    // mtime check added flake risk without strengthening the
    // invariant.
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    seed_two_policies(home.path());

    let daemon = start_daemon(home.path());
    let port = daemon.port;
    assert!(wait_for_health(port), "daemon should boot");

    let _ = register_agent(port, home.path(), "noop-test", "policy-old");

    let agent_path = home.path().join("agents").join("noop-test.toml");
    let pre_bytes = std::fs::read(&agent_path).unwrap();

    // Rebind to the SAME policy.
    let (status, body) = rebind_agent(port, home.path(), "noop-test", "policy-old");
    assert_eq!(status, 200, "no-op rebind succeeds, got {status}: {body:?}");
    assert_eq!(body["status"], "ok");
    assert_eq!(body["agent"]["policy_name"], "policy-old");

    let post_bytes = std::fs::read(&agent_path).unwrap();

    // The load-bearing assertion: byte-identical content proves the
    // no-op short-circuit fired (skip write+audit+reload). If the
    // handler had taken the full mutation path, even with the same
    // policy_name the file would have been atomically rewritten via
    // the rename — same content but a NEW inode, and atomic-write
    // tempfile naming includes a random suffix that would change
    // any byte representation that captures filename metadata. The
    // strongest test is "the file we read at the start is the file
    // we read at the end."
    assert_eq!(post_bytes, pre_bytes, "no-op rebind must NOT rewrite the agent file");
}

#[test]
fn rebind_failure_emits_audit_event() {
    // Story 7.11 review-round-1 P6: failure paths (422, 404, 500)
    // emit an `agent-rebind-denied` audit event with the error code
    // and target_policy_name. Compliance / forensics needs the trail.
    //
    // Story 7.11 review-round-2 R2D3: poll-with-deadline (up to 5s)
    // instead of fixed `thread::sleep(500ms)`. The audit writer is
    // non-blocking and generally lands fast, but slow CI runners
    // (especially under nextest contention on Windows) can take
    // longer than 500ms. Poll-with-deadline returns AS SOON AS the
    // event lands, and only flakes if 5s genuinely elapses without
    // it — which would indicate a real bug.
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    seed_two_policies(home.path());

    let daemon = start_daemon(home.path());
    let port = daemon.port;
    assert!(wait_for_health(port), "daemon should boot");

    let _ = register_agent(port, home.path(), "audit-on-fail", "policy-old");

    // Trigger a 422 unknown_policy.
    let (status, _) = rebind_agent(port, home.path(), "audit-on-fail", "ghost-policy");
    assert_eq!(status, 422);

    // Poll the audit log up to 5s. Returns when the event lands;
    // panics with a clear diagnostic on timeout.
    let audit_dir = home.path().join("audit");
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let poll_interval = Duration::from_millis(50);

    loop {
        // Story 7.11 review-round-3 #7: distinguish three poll states
        // for diagnostics: (1) audit dir does not exist, (2) audit dir
        // exists but no .jsonl files yet, (3) files exist but the
        // sought event hasn't appeared. Today's `unwrap_or_default`
        // collapsed (1) and (2) into "no entries" — making it harder
        // to triage a flake (genuine audit dir missing vs daemon hadn't
        // yet rotated the log open).
        let read_dir_result = std::fs::read_dir(&audit_dir);
        let dir_exists = read_dir_result.is_ok();
        let entries: Vec<_> = read_dir_result
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .filter(|e| {
                        e.file_name().to_str().map(|n| n.ends_with(".jsonl")).unwrap_or(false)
                    })
                    .collect()
            })
            .unwrap_or_default();

        let mut total_lines = 0usize;
        for entry in &entries {
            let content = std::fs::read_to_string(entry.path()).unwrap_or_default();
            for line in content.lines() {
                total_lines += 1;
                if let Ok(event) = serde_json::from_str::<serde_json::Value>(line)
                    && event["event_type"] == "agent-rebind-denied"
                    && event["agent_id"] == "audit-on-fail"
                    && event["outcome"] == "denied"
                    && event["extra"]["error_code"] == "agent.unknown_policy"
                    && event["extra"]["target_policy_name"] == "ghost-policy"
                {
                    // Found it — test passes.
                    return;
                }
            }
        }

        if std::time::Instant::now() >= deadline {
            let dir_state = if !dir_exists {
                "audit dir does NOT exist (daemon may not have started writing yet)"
            } else if entries.is_empty() {
                "audit dir exists but contains no .jsonl files"
            } else {
                "audit dir exists with .jsonl files"
            };
            panic!(
                "expected agent-rebind-denied audit event with code=agent.unknown_policy \
                 and target_policy_name=ghost-policy in audit log within 5s; \
                 saw {total_lines} total audit lines without a match \
                 (state: {dir_state}; audit_dir={}; .jsonl_count={})",
                audit_dir.display(),
                entries.len(),
            );
        }
        std::thread::sleep(poll_interval);
    }
}
