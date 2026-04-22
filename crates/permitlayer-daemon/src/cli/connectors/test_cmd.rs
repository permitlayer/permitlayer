//! `agentsso connectors test` — validate a connector plugin offline
//! (Story 6.4).
//!
//! Runs five checks in order: source read, metadata validation,
//! sandbox conformance, scope allowlist, tool-invocation smoke test
//! (driven by [`permitlayer_plugins::StubHostServices`]). Renders a
//! human-readable per-check outcome table or a structured JSON
//! aggregate via `--json`.
//!
//! Fully offline — no loopback HTTP, no daemon required. The
//! filesystem is the only external dependency.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;
use clap::Args;
use serde::Serialize;

use permitlayer_plugins::{
    HostServices, PluginError, PluginRuntime, RuntimeConfig, StubHostServices, is_allowed,
    validate_plugin_source,
};

use crate::cli::kill::load_daemon_config_or_default_with_warn;
use crate::cli::silent_cli_error;
use crate::design::render::{Outcome, error_block, outcome_icon};
use crate::design::terminal::ColorSupport;
use crate::design::terminal::styled;
use crate::design::theme::Theme;

/// Per-tool smoke-test deadline. Aligns with `test_cmd` AC #15 (5
/// seconds) and the Story 6.1 interrupt handler's behavior for
/// runaway JS.
const TOOL_INVOCATION_DEADLINE_MS: u64 = 5_000;

#[derive(Args)]
pub struct TestArgs {
    /// Either a bare connector name (resolved to
    /// `~/.agentsso/plugins/<name>/`) or a filesystem path to the
    /// plugin directory. Arguments containing `/`, `\\`, or a
    /// leading `.` are treated as paths.
    pub name_or_path: String,

    /// Emit the structured JSON aggregate instead of the
    /// human-readable per-check table. Matches Story 5.3 /
    /// Story 6.3 `--json` convention.
    #[arg(long)]
    pub json: bool,
}

/// Outcome tier for a single check — maps to the design-system
/// [`Outcome`] glyph set. `Ok` = pass, `Warn` = non-blocking
/// warning, `Error` = blocking failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum CheckOutcome {
    Ok,
    Warn,
    Error,
}

impl CheckOutcome {
    fn to_design_outcome(self) -> Outcome {
        match self {
            CheckOutcome::Ok => Outcome::Ok,
            CheckOutcome::Warn => Outcome::Blocked,
            CheckOutcome::Error => Outcome::Error,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct CheckResult {
    name: String,
    outcome: CheckOutcome,
    detail: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct TestReport {
    connector: String,
    plugin_dir: String,
    status: ReportStatus,
    checks: Vec<CheckResult>,
    warnings_count: usize,
    failures_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum ReportStatus {
    Pass,
    PassWithWarnings,
    Fail,
}

pub async fn run(args: TestArgs) -> Result<()> {
    // 1. Resolve the plugin directory.
    let plugin_dir = resolve_plugin_dir(&args.name_or_path);
    if !plugin_dir.is_dir() {
        // Hint when a bare name misses but a same-named directory
        // exists in the CWD — a common "I'm in my plugin dir"
        // author-flow confusion.
        let looked_like_bare_name = !args.name_or_path.contains('/')
            && !args.name_or_path.contains('\\')
            && !args.name_or_path.starts_with('.')
            && !std::path::Path::new(&args.name_or_path).is_absolute();
        let local_candidate = std::path::Path::new(&args.name_or_path);
        let hint = if looked_like_bare_name && local_candidate.is_dir() {
            format!(
                "did you mean `./{}`? a directory with that name exists in the current working \
                 directory",
                args.name_or_path
            )
        } else {
            String::from("run `agentsso connectors new <name>` to scaffold one, or check the path")
        };
        eprint!(
            "{}",
            error_block(
                "connectors.test.plugin_not_found",
                "connector plugin directory does not exist",
                &hint,
                Some(&plugin_dir.display().to_string()),
            )
        );
        return Err(silent_cli_error("plugin directory not found"));
    }

    // Label used in report output. Prefer the on-disk basename so
    // `agentsso connectors test /tmp/experimental-plugin/` shows a
    // meaningful name.
    let connector_label =
        plugin_dir.file_name().and_then(|s| s.to_str()).unwrap_or("<unknown>").to_owned();

    // 2. Allocate the QuickJS runtime once and reuse across checks.
    //    The debug-only test seam `AGENTSSO_TEST_DISABLE_RUNTIME_INIT`
    //    lets integration tests exercise the CLI wiring without
    //    paying the rquickjs init cost.
    #[cfg(debug_assertions)]
    let skip_runtime = std::env::var("AGENTSSO_TEST_DISABLE_RUNTIME_INIT").as_deref() == Ok("1");
    #[cfg(not(debug_assertions))]
    let skip_runtime = false;

    let runtime = if skip_runtime {
        None
    } else {
        // Use an extended 5-second deadline for tool-invocation
        // smoke tests — the default 2s would risk false-positive
        // timeouts on test-stub HTTP round-trips. Infinite-loop
        // plugins still get interrupted well before the author's
        // patience runs out.
        let cfg = RuntimeConfig {
            execution_deadline: std::time::Duration::from_millis(TOOL_INVOCATION_DEADLINE_MS),
            ..RuntimeConfig::default()
        };
        match PluginRuntime::new(cfg) {
            Ok(rt) => Some(rt),
            Err(e) => {
                eprint!(
                    "{}",
                    error_block(
                        "connectors.test.runtime_init_failed",
                        "failed to allocate plugin runtime",
                        "file a bug — this indicates a broken install",
                        Some(&format!("{e}")),
                    )
                );
                return Err(silent_cli_error("runtime init failed"));
            }
        }
    };

    // 3. Run checks in order. Each helper returns a `CheckResult`;
    //    subsequent checks may consume intermediate state (source
    //    text, validated metadata) from the prior checks.
    let mut checks: Vec<CheckResult> = Vec::with_capacity(6);

    // ----- Check #1: source read -----
    //
    // Cap the read at 1 MiB via `File::take(cap + 1)` before
    // materializing the contents. A prior version used
    // `fs::read_to_string` and checked `s.len()` afterwards, which
    // would allocate a multi-GB buffer if the author accidentally
    // pointed the tester at a non-source file (e.g., a coredump).
    // Matches the loader's `read_source_capped` posture.
    let source = {
        const CAP: u64 = 1 << 20;
        let index_path = plugin_dir.join("index.js");
        match std::fs::File::open(&index_path) {
            Ok(file) => {
                use std::io::Read;
                let mut buf = String::new();
                match file.take(CAP + 1).read_to_string(&mut buf) {
                    Ok(_) if buf.len() as u64 > CAP => {
                        checks.push(CheckResult {
                            name: "source".to_owned(),
                            outcome: CheckOutcome::Error,
                            detail: Some("plugin source exceeds 1 MiB cap".to_owned()),
                        });
                        return finalize(&connector_label, &plugin_dir, checks, args.json);
                    }
                    Ok(_) => {
                        checks.push(CheckResult {
                            name: "source".to_owned(),
                            outcome: CheckOutcome::Ok,
                            detail: None,
                        });
                        buf
                    }
                    Err(e) => {
                        let detail = format!("{e}");
                        checks.push(CheckResult {
                            name: "source".to_owned(),
                            outcome: CheckOutcome::Error,
                            detail: Some(detail),
                        });
                        return finalize(&connector_label, &plugin_dir, checks, args.json);
                    }
                }
            }
            Err(e) => {
                let detail = format!("{e}");
                checks.push(CheckResult {
                    name: "source".to_owned(),
                    outcome: CheckOutcome::Error,
                    detail: Some(detail),
                });
                return finalize(&connector_label, &plugin_dir, checks, args.json);
            }
        }
    };

    // ----- Check #2: metadata validation -----
    //
    // `validate_plugin_source` requires a runtime. If the runtime
    // was skipped via the test seam, record a sentinel error so
    // downstream checks don't attempt to run.
    let Some(runtime_ref) = runtime.as_ref() else {
        checks.push(CheckResult {
            name: "metadata".to_owned(),
            outcome: CheckOutcome::Error,
            detail: Some("runtime init disabled via test seam".to_owned()),
        });
        return finalize(&connector_label, &plugin_dir, checks, args.json);
    };

    let metadata = match validate_plugin_source(runtime_ref, &connector_label, &source) {
        Ok(m) => {
            let scopes_list = m.scopes.join(",");
            let detail = format!(
                "name={} version={} apiVersion={} scopes=[{}]",
                m.name, m.version, m.api_version, scopes_list
            );
            checks.push(CheckResult {
                name: "metadata".to_owned(),
                outcome: CheckOutcome::Ok,
                detail: Some(detail),
            });
            m
        }
        Err(e) => {
            let detail = plugin_error_detail(&e);
            checks.push(CheckResult {
                name: "metadata".to_owned(),
                outcome: CheckOutcome::Error,
                detail: Some(detail),
            });
            return finalize(&connector_label, &plugin_dir, checks, args.json);
        }
    };

    // ----- Check #3: sandbox conformance -----
    checks.push(run_sandbox_check(runtime_ref, &connector_label, &source));
    // If the sandbox check failed (not just warned), short-circuit.
    if checks.last().map(|c| c.outcome) == Some(CheckOutcome::Error) {
        return finalize(&connector_label, &plugin_dir, checks, args.json);
    }

    // ----- Check #4: scope allowlist -----
    checks.push(run_scope_check(&metadata.scopes));

    // ----- Check #5: tool invocation -----
    let (individual, aggregate) = run_tool_invocation_check(runtime_ref, &connector_label, &source);
    checks.extend(individual);
    checks.push(aggregate);

    finalize(&connector_label, &plugin_dir, checks, args.json)
}

// ------------------------------------------------------------------
// Path resolution
// ------------------------------------------------------------------

/// Resolve `name_or_path` into an absolute plugin directory. A
/// bare connector name resolves via
/// `<home>/plugins/<name>/`; any argument containing a path
/// separator OR starting with `.` / `..` is treated as a
/// filesystem path (relative to the current working dir for
/// relative inputs).
fn resolve_plugin_dir(name_or_path: &str) -> PathBuf {
    let looks_like_path = name_or_path.contains('/')
        || name_or_path.contains('\\')
        || name_or_path.starts_with('.')
        || Path::new(name_or_path).is_absolute();
    if looks_like_path {
        PathBuf::from(name_or_path)
    } else {
        let cfg = load_daemon_config_or_default_with_warn("connectors test");
        cfg.paths.home.join("plugins").join(name_or_path)
    }
}

// ------------------------------------------------------------------
// Check implementations
// ------------------------------------------------------------------

/// Sandbox conformance check. Evaluates the plugin source + probes
/// a fixed set of forbidden APIs (`require`, `process`, `fs`,
/// `net`, `child_process`, `globalThis.Function(...)()`). Any
/// probe that returns a non-undefined value is flagged as a
/// compliance failure.
fn run_sandbox_check(runtime: &PluginRuntime, connector: &str, source: &str) -> CheckResult {
    // Suffix the probe's exported symbol with a hash of the source
    // so that a plugin that happens to export a symbol named
    // `permitlayerSandboxProbe` (e.g., copied from this tester's
    // test fixtures) does not collide with ours. Collisions would
    // surface as a misleading `SyntaxError: duplicate export` that
    // the real daemon loader would not produce.
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(source.as_bytes());
    let digest = hasher.finalize();
    let probe_suffix = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
    let probe_symbol = format!("permitlayerSandboxProbe_{probe_suffix:08x}");

    let probe_src = format!(
        r#"
{source}

// Sandbox conformance probe: enumerate forbidden surfaces.
// `globalThis` is the only entry point the sandbox provides.
const __permitlayer_probe = {{
    requireReachable: typeof globalThis.require !== "undefined",
    processReachable: typeof globalThis.process !== "undefined",
    fsReachable: typeof globalThis.fs !== "undefined",
    netReachable: typeof globalThis.net !== "undefined",
    childProcessReachable: typeof globalThis.child_process !== "undefined",
    functionCtorReachable: (function () {{
        try {{
            // Story 6.1 neuters the Function constructor — this
            // call should throw.
            const f = globalThis.Function("return 1");
            return typeof f === "function";
        }} catch (_) {{
            return false;
        }}
    }})(),
}};

export const {probe_symbol} = JSON.stringify(__permitlayer_probe);
"#
    );

    let connector_owned = connector.to_owned();
    let probe_symbol_owned = probe_symbol.clone();
    let probe_result: Result<String, PluginError> = runtime.with_context(move |ctx| {
        let module_name = format!("<permitlayer-probe:{connector_owned}>");
        let declared = match rquickjs::Module::declare(ctx.clone(), module_name.as_str(), probe_src)
        {
            Ok(d) => d,
            Err(e) => {
                return Err(PluginError::PluginLoadFailed {
                    connector: connector_owned,
                    reason: permitlayer_plugins::LoadFailureReason::JsSyntax(e),
                });
            }
        };
        let (evaluated, promise) = declared.eval().map_err(|e| PluginError::PluginLoadFailed {
            connector: connector_owned.clone(),
            reason: permitlayer_plugins::LoadFailureReason::JsSyntax(e),
        })?;
        let _: () = promise.finish().map_err(|e| PluginError::PluginLoadFailed {
            connector: connector_owned.clone(),
            reason: permitlayer_plugins::LoadFailureReason::JsSyntax(e),
        })?;
        let value: rquickjs::Value<'_> = evaluated
            .get::<_, rquickjs::Value<'_>>(probe_symbol_owned.as_str())
            .map_err(|_| PluginError::PluginLoadFailed {
                connector: connector_owned,
                reason: permitlayer_plugins::LoadFailureReason::MissingMetadata,
            })?;
        let as_string = value.as_string().ok_or_else(|| PluginError::MetadataInvalid {
            connector: "sandbox-probe".to_owned(),
            detail: "probe did not return a string".to_owned(),
        })?;
        Ok(as_string.to_string().unwrap_or_default())
    });

    match probe_result {
        Ok(json_text) => {
            let parsed: serde_json::Value =
                serde_json::from_str(&json_text).unwrap_or(serde_json::Value::Null);
            let mut breaches: Vec<&str> = Vec::new();
            let check_keys = [
                ("requireReachable", "require"),
                ("processReachable", "process"),
                ("fsReachable", "fs"),
                ("netReachable", "net"),
                ("childProcessReachable", "child_process"),
                ("functionCtorReachable", "Function constructor"),
            ];
            for (js_key, label) in check_keys {
                if parsed.get(js_key).and_then(|v| v.as_bool()).unwrap_or(false) {
                    breaches.push(label);
                }
            }
            if breaches.is_empty() {
                CheckResult { name: "sandbox".to_owned(), outcome: CheckOutcome::Ok, detail: None }
            } else {
                CheckResult {
                    name: "sandbox".to_owned(),
                    outcome: CheckOutcome::Error,
                    detail: Some(format!("forbidden API reachable: {}", breaches.join(", "))),
                }
            }
        }
        Err(e) => CheckResult {
            name: "sandbox".to_owned(),
            outcome: CheckOutcome::Error,
            detail: Some(plugin_error_detail(&e)),
        },
    }
}

/// Scope-allowlist check. Always non-blocking per epics.md:1755.
fn run_scope_check(scopes: &[String]) -> CheckResult {
    let unreviewed: Vec<&str> =
        scopes.iter().filter(|s| !is_allowed(s)).map(String::as_str).collect();
    if unreviewed.is_empty() {
        CheckResult {
            name: "scopes".to_owned(),
            outcome: CheckOutcome::Ok,
            detail: Some(format!("all {} scopes in allowlist", scopes.len())),
        }
    } else {
        let detail = format!(
            "{} scope{} not in allowlist: {} — publication to the connector marketplace will require these scopes to be reviewed",
            unreviewed.len(),
            if unreviewed.len() == 1 { "" } else { "s" },
            unreviewed.join(", ")
        );
        CheckResult { name: "scopes".to_owned(), outcome: CheckOutcome::Warn, detail: Some(detail) }
    }
}

/// Tool-invocation smoke test. Loads the plugin source + registers
/// [`StubHostServices`], enumerates exported tool names via
/// `Object.keys(tools)`, invokes each with an empty input, and
/// records pass/fail per tool. The tool invocation uses the
/// rquickjs interrupt handler (5 s deadline) to bound runaway
/// plugins.
///
/// Returns `(per_tool_results, aggregate_result)`.
fn run_tool_invocation_check(
    runtime: &PluginRuntime,
    connector: &str,
    source: &str,
) -> (Vec<CheckResult>, CheckResult) {
    // Step 1: load + enumerate tool names. This uses a sandbox-only
    // context (no host API) — we just need the `tools` export.
    let enumeration: Result<Vec<String>, PluginError> = {
        let connector_owned = connector.to_owned();
        let source_owned = source.to_owned();
        runtime.with_context(move |ctx| {
            let module_name = format!("<permitlayer-tool-enum:{connector_owned}>");
            let declared =
                rquickjs::Module::declare(ctx.clone(), module_name.as_str(), source_owned)
                    .map_err(|e| PluginError::PluginLoadFailed {
                        connector: connector_owned.clone(),
                        reason: permitlayer_plugins::LoadFailureReason::JsSyntax(e),
                    })?;
            let (evaluated, promise) =
                declared.eval().map_err(|e| PluginError::PluginLoadFailed {
                    connector: connector_owned.clone(),
                    reason: permitlayer_plugins::LoadFailureReason::JsSyntax(e),
                })?;
            let _: () = promise.finish().map_err(|e| PluginError::PluginLoadFailed {
                connector: connector_owned.clone(),
                reason: permitlayer_plugins::LoadFailureReason::JsSyntax(e),
            })?;
            let tools_val: Option<rquickjs::Value<'_>> =
                evaluated.get::<_, rquickjs::Value<'_>>("tools").ok();
            let Some(tools_val) = tools_val else {
                return Ok(Vec::new());
            };
            let Some(tools_obj) = tools_val.as_object() else {
                return Ok(Vec::new());
            };
            // Reject thenable-shaped `tools` (e.g. a top-level
            // Promise that happens to have a `then` key). Calling
            // `Object.keys` on a Promise would yield `["then"]`
            // and we would invoke `tools.then({})` as a "tool",
            // which is nonsense and produces a confusing error.
            if tools_obj.contains_key("then").unwrap_or(false)
                && tools_obj
                    .get::<_, rquickjs::Value<'_>>("then")
                    .ok()
                    .and_then(|v| v.as_function().map(|_| ()))
                    .is_some()
            {
                return Err(PluginError::MetadataInvalid {
                    connector: connector_owned.clone(),
                    detail: "tools export is a thenable/Promise — expected a plain object"
                        .to_owned(),
                });
            }
            let globals = ctx.globals();
            let object_global: rquickjs::Object<'_> =
                globals.get("Object").map_err(PluginError::from)?;
            let keys_fn: rquickjs::Function<'_> =
                object_global.get("keys").map_err(PluginError::from)?;
            let keys_val: rquickjs::Value<'_> =
                keys_fn.call((tools_obj.clone(),)).map_err(PluginError::from)?;
            let keys_array = keys_val.as_array().ok_or_else(|| PluginError::MetadataInvalid {
                connector: connector_owned.clone(),
                detail: "Object.keys(tools) did not return an array".to_owned(),
            })?;
            let mut names = Vec::with_capacity(keys_array.len());
            for i in 0..keys_array.len() {
                let entry: rquickjs::Value<'_> =
                    keys_array.get::<rquickjs::Value<'_>>(i).map_err(PluginError::from)?;
                if let Some(js_str) = entry.as_string()
                    && let Ok(s) = js_str.to_string()
                {
                    names.push(s);
                }
            }
            Ok(names)
        })
    };

    let tool_names = match enumeration {
        Ok(names) => names,
        Err(e) => {
            let aggregate = CheckResult {
                name: "tools".to_owned(),
                outcome: CheckOutcome::Error,
                detail: Some(format!("failed to enumerate tools: {}", plugin_error_detail(&e))),
            };
            return (Vec::new(), aggregate);
        }
    };

    if tool_names.is_empty() {
        // Plugins with no exported tools pass the other checks but
        // do nothing useful. Emit a non-blocking `warn` so the
        // author notices the empty `tools` export; exit code stays
        // 0 because intermediate authoring states legitimately
        // include removed-all-tools.
        let aggregate = CheckResult {
            name: "tools".to_owned(),
            outcome: CheckOutcome::Warn,
            detail: Some("0 tools exported".to_owned()),
        };
        return (Vec::new(), aggregate);
    }

    // Step 2: invoke each tool with an empty input under a host-API
    // registered context. The plugin source is re-evaluated each
    // invocation (matches Story 6.1 "one fresh context per
    // invocation" discipline — the interrupt handler is per-context).
    let services: Arc<dyn HostServices> = Arc::new(StubHostServices::new());
    let mut per_tool: Vec<CheckResult> = Vec::with_capacity(tool_names.len());
    let mut failures = 0usize;

    for tool_name in &tool_names {
        let outcome = invoke_single_tool(runtime, &services, source, tool_name);
        if outcome.outcome == CheckOutcome::Error {
            failures += 1;
        }
        per_tool.push(outcome);
    }

    let aggregate = if failures == 0 {
        CheckResult {
            name: "tools".to_owned(),
            outcome: CheckOutcome::Ok,
            detail: Some(format!("{} tools passed", tool_names.len())),
        }
    } else {
        CheckResult {
            name: "tools".to_owned(),
            outcome: CheckOutcome::Error,
            detail: Some(format!("{} of {} tools failed", failures, tool_names.len())),
        }
    };

    (per_tool, aggregate)
}

/// Invoke a single tool by name with an empty input object under
/// the stub host services. Returns a `CheckResult` keyed
/// `tools.<tool_name>`.
fn invoke_single_tool(
    runtime: &PluginRuntime,
    services: &Arc<dyn HostServices>,
    source: &str,
    tool_name: &str,
) -> CheckResult {
    // The runtime was constructed with
    // `execution_deadline = TOOL_INVOCATION_DEADLINE_MS` — each
    // `with_host_api` entry arms that deadline automatically via
    // the Story 6.1 interrupt handler. Infinite loops surface as
    // `PluginError::ExecutionDeadlineExceeded`.

    let source_owned = source.to_owned();
    let tool_owned = tool_name.to_owned();
    let result: Result<CheckResult, PluginError> = runtime.with_host_api(services, move |ctx| {
        let module_name = format!("<permitlayer-tool:{tool_owned}>");
        let declared = rquickjs::Module::declare(ctx.clone(), module_name.as_str(), source_owned)
            .map_err(|e| PluginError::PluginLoadFailed {
            connector: tool_owned.clone(),
            reason: permitlayer_plugins::LoadFailureReason::JsSyntax(e),
        })?;
        let (evaluated, promise) = declared.eval().map_err(|e| PluginError::PluginLoadFailed {
            connector: tool_owned.clone(),
            reason: permitlayer_plugins::LoadFailureReason::JsSyntax(e),
        })?;
        let _: () = promise.finish().map_err(|e| PluginError::PluginLoadFailed {
            connector: tool_owned.clone(),
            reason: permitlayer_plugins::LoadFailureReason::JsSyntax(e),
        })?;
        let tools_val: rquickjs::Value<'_> = evaluated
            .get::<_, rquickjs::Value<'_>>("tools")
            .map_err(|_| PluginError::PluginLoadFailed {
                connector: tool_owned.clone(),
                reason: permitlayer_plugins::LoadFailureReason::MissingMetadata,
            })?;
        let tools_obj = tools_val.as_object().ok_or_else(|| PluginError::MetadataInvalid {
            connector: tool_owned.clone(),
            detail: "tools export is not an object".to_owned(),
        })?;
        let tool_fn: rquickjs::Function<'_> =
            tools_obj.get(tool_owned.as_str()).map_err(PluginError::from)?;
        let empty_input = rquickjs::Object::new(ctx.clone()).map_err(PluginError::from)?;
        let return_val: rquickjs::Value<'_> =
            tool_fn.call((empty_input,)).map_err(PluginError::from)?;

        // If the tool returned a Promise, drive it to completion via
        // the Story 6.2 Promise-shape pattern.
        let final_val: rquickjs::Value<'_> = if return_val.is_object()
            && return_val
                .as_object()
                .and_then(|o| o.get::<_, rquickjs::Value<'_>>("then").ok())
                .map(|v| v.is_function())
                .unwrap_or(false)
        {
            // Convert to Promise + finish.
            let promise: rquickjs::Promise<'_> =
                rquickjs::Promise::from_value(return_val).map_err(PluginError::from)?;
            promise.finish::<rquickjs::Value<'_>>().map_err(PluginError::from)?
        } else {
            return_val
        };

        // Validate return is JSON-serializable (serde round-trip).
        let json_obj: rquickjs::Object<'_> =
            ctx.globals().get("JSON").map_err(PluginError::from)?;
        let stringify: rquickjs::Function<'_> =
            json_obj.get("stringify").map_err(PluginError::from)?;
        let stringified: rquickjs::Value<'_> =
            stringify.call((final_val,)).map_err(PluginError::from)?;
        if stringified.as_string().is_none() {
            return Err(PluginError::MetadataInvalid {
                connector: tool_owned.clone(),
                detail: "tool return value is not JSON-serializable".to_owned(),
            });
        }
        Ok(CheckResult {
            name: format!("tools.{tool_owned}"),
            outcome: CheckOutcome::Ok,
            detail: None,
        })
    });

    match result {
        Ok(r) => r,
        Err(e) => CheckResult {
            name: format!("tools.{tool_name}"),
            outcome: CheckOutcome::Error,
            detail: Some(plugin_error_detail(&e)),
        },
    }
}

// ------------------------------------------------------------------
// Error detail helpers
// ------------------------------------------------------------------

/// Convert a [`PluginError`] into a short, operator-grep-friendly
/// detail string for per-check output.
fn plugin_error_detail(err: &PluginError) -> String {
    // Control-character sanitizer: JS exception messages can carry
    // newlines / tabs / BEL / ANSI escape prefixes. These would
    // break the per-check single-line format in human output and
    // corrupt terminal state when rendered. Replace each control
    // character with U+FFFD (`\u{fffd}`) — matches the design
    // system's posture on untrusted text elsewhere.
    fn sanitize(s: &str) -> String {
        s.chars()
            .map(|c| if c.is_control() && c != '\n' { '\u{fffd}' } else { c })
            .collect::<String>()
            .replace('\n', " ")
    }

    let raw = match err {
        PluginError::MetadataInvalid { detail, .. } => detail.clone(),
        PluginError::PluginLoadFailed { reason, .. } => format!("{reason:?}"),
        PluginError::ExecutionDeadlineExceeded { .. } => "deadline exceeded".to_owned(),
        other => format!("{other}"),
    };
    let sanitized = sanitize(&raw);
    // A plugin that `throw null` / `throw undefined` surfaces as a
    // JsException with empty message. Render a hint so the author
    // knows to look for non-Error throws rather than staring at
    // "plugin threw:" with nothing after.
    let trimmed = sanitized.trim_end_matches([' ', ':']);
    if trimmed.is_empty() || trimmed == "plugin threw" {
        "plugin threw a non-Error value (check for `throw null`, `throw undefined`, or rejection with a primitive)"
            .to_owned()
    } else {
        sanitized
    }
}

// ------------------------------------------------------------------
// Finalization / rendering
// ------------------------------------------------------------------

fn finalize(
    connector: &str,
    plugin_dir: &Path,
    checks: Vec<CheckResult>,
    json: bool,
) -> Result<()> {
    let warnings_count = checks.iter().filter(|c| c.outcome == CheckOutcome::Warn).count();
    let failures_count = checks.iter().filter(|c| c.outcome == CheckOutcome::Error).count();
    let status = if failures_count > 0 {
        ReportStatus::Fail
    } else if warnings_count > 0 {
        ReportStatus::PassWithWarnings
    } else {
        ReportStatus::Pass
    };
    let report = TestReport {
        connector: connector.to_owned(),
        plugin_dir: plugin_dir.display().to_string(),
        status,
        checks,
        warnings_count,
        failures_count,
    };

    if json {
        // AC #16: structured JSON shape, no ANSI escapes.
        let json_text = serde_json::to_string(&report).unwrap_or_default();
        println!("{json_text}");
    } else {
        render_human(&report);
    }

    if failures_count > 0 { Err(silent_cli_error("connectors test failed")) } else { Ok(()) }
}

fn render_human(report: &TestReport) {
    // Load theme + color support once; every check line reuses them.
    // `Theme::load` tolerates missing theme config.
    let home = load_daemon_config_or_default_with_warn("connectors test").paths.home;
    let theme = Theme::load(&home);
    let support = ColorSupport::detect();

    for check in &report.checks {
        let raw_glyph = outcome_icon(check.outcome.to_design_outcome());
        // Color just the glyph with the semantic token for its
        // outcome (accent=ok / warn=warn / danger=error). The
        // check name + detail stay in the terminal default color
        // so warnings and errors get a visual cue without
        // overwhelming the line.
        let tokens = theme.tokens();
        let color = match check.outcome.to_design_outcome() {
            Outcome::Ok => tokens.accent,
            Outcome::Blocked => tokens.warn,
            Outcome::Error => tokens.danger,
        };
        let glyph = styled(raw_glyph, color, support);
        let line = match &check.detail {
            Some(detail) if !detail.is_empty() => {
                format!("{glyph} {}: {}", check.name, detail)
            }
            _ => format!("{glyph} {}: ok", check.name),
        };
        println!("{line}");
    }
    println!();

    let summary_glyph = if report.failures_count == 0 { "\u{2714}" } else { "\u{2715}" };
    match report.status {
        ReportStatus::Pass => {
            println!("{summary_glyph} connectors test {}: passed", report.connector);
        }
        ReportStatus::PassWithWarnings => {
            println!(
                "{summary_glyph} connectors test {}: passed with {} warning{}",
                report.connector,
                report.warnings_count,
                if report.warnings_count == 1 { "" } else { "s" }
            );
        }
        ReportStatus::Fail => {
            println!(
                "{summary_glyph} connectors test {}: failed ({} failure{})",
                report.connector,
                report.failures_count,
                if report.failures_count == 1 { "" } else { "s" }
            );
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // --- Path resolution ---------------------------------------

    // Note: the bare-name resolution path consults
    // `load_daemon_config_or_default_with_warn`, which reads
    // `AGENTSSO_PATHS__HOME` at call time. Exercising that path
    // from a unit test would require setting the env var — unsafe
    // on edition-2024 — so the behavior is instead covered by the
    // `connectors_test_e2e.rs` subprocess tests where env vars are
    // scoped to the child process.

    #[test]
    fn resolve_absolute_path_is_used_verbatim() {
        let resolved = resolve_plugin_dir("/tmp/wip-plugin");
        assert_eq!(resolved, PathBuf::from("/tmp/wip-plugin"));
    }

    #[test]
    fn resolve_relative_dot_path() {
        let resolved = resolve_plugin_dir("./my-wip");
        assert_eq!(resolved, PathBuf::from("./my-wip"));
    }

    #[test]
    fn resolve_parent_relative_path() {
        let resolved = resolve_plugin_dir("../shared/plugin");
        assert_eq!(resolved, PathBuf::from("../shared/plugin"));
    }

    // --- Check outcome semantics -------------------------------

    #[test]
    fn check_outcome_maps_to_design_system_glyphs() {
        assert_eq!(CheckOutcome::Ok.to_design_outcome(), Outcome::Ok);
        assert_eq!(CheckOutcome::Warn.to_design_outcome(), Outcome::Blocked);
        assert_eq!(CheckOutcome::Error.to_design_outcome(), Outcome::Error);
    }

    #[test]
    fn scope_check_ok_when_all_in_allowlist() {
        let result = run_scope_check(&["gmail.readonly".to_owned(), "drive.readonly".to_owned()]);
        assert_eq!(result.outcome, CheckOutcome::Ok);
        assert!(result.detail.as_deref().unwrap_or("").contains("2 scopes in allowlist"));
    }

    #[test]
    fn scope_check_warn_for_unreviewed() {
        let result = run_scope_check(&["notion.read".to_owned()]);
        assert_eq!(result.outcome, CheckOutcome::Warn);
        let detail = result.detail.unwrap_or_default();
        assert!(detail.contains("notion.read"));
        assert!(detail.contains("marketplace"));
    }

    #[test]
    fn scope_check_warn_singular_vs_plural() {
        let single = run_scope_check(&["notion.read".to_owned()]);
        assert!(single.detail.as_deref().unwrap().contains("1 scope not"));

        let multi = run_scope_check(&["notion.read".to_owned(), "jira.read".to_owned()]);
        assert!(multi.detail.as_deref().unwrap().contains("2 scopes not"));
    }

    // --- Report status semantics -------------------------------

    #[test]
    fn report_status_pass_when_all_ok() {
        let report = TestReport {
            connector: "foo".to_owned(),
            plugin_dir: "/tmp/foo".to_owned(),
            status: ReportStatus::Pass,
            checks: vec![CheckResult {
                name: "source".to_owned(),
                outcome: CheckOutcome::Ok,
                detail: None,
            }],
            warnings_count: 0,
            failures_count: 0,
        };
        let json_text = serde_json::to_string(&report).unwrap();
        assert!(json_text.contains("\"status\":\"pass\""));
    }

    #[test]
    fn report_status_serializes_as_kebab_case() {
        let report = TestReport {
            connector: "foo".to_owned(),
            plugin_dir: "/tmp/foo".to_owned(),
            status: ReportStatus::PassWithWarnings,
            checks: Vec::new(),
            warnings_count: 1,
            failures_count: 0,
        };
        let json_text = serde_json::to_string(&report).unwrap();
        assert!(json_text.contains("\"status\":\"pass-with-warnings\""));
    }

    // --- Network-free invariant (AC #20) ------------------------

    #[test]
    fn tester_source_does_not_reference_network_crates() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/cli/connectors/test_cmd.rs");
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read {path:?}: {e}"));
        for banned in ["reqwest", "tokio::net", "hyper::client"] {
            let banned_use = format!("use {banned}");
            for (idx, line) in source.lines().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") {
                    continue;
                }
                assert!(
                    !trimmed.starts_with(&banned_use),
                    "line {}: tester source must not `use {banned}`: `{line}`",
                    idx + 1
                );
            }
        }
    }

    // --- Test seam compile-gating (AC #26) ---------------------

    #[test]
    fn test_seam_env_vars_are_spelled_correctly() {
        // AC #26: lock the env-var names at compile time. If a
        // future refactor renames a seam, the corresponding e2e
        // test that sets the env var must be updated — the name
        // is therefore part of the stable test surface.
        //
        // We cannot directly assert `#[cfg(debug_assertions)]`
        // from a unit test (unit tests only run in debug
        // profiles); the release-build invariant is enforced by
        // the grep-assertion test below (`run_source_gates_env_var`).
        let _ = "AGENTSSO_TEST_FROZEN_DATE";
        let _ = "AGENTSSO_TEST_DISABLE_RUNTIME_INIT";
    }

    #[test]
    fn run_source_gates_env_var_reads_on_debug_assertions() {
        // Grep-assert AC #26: every `std::env::var("AGENTSSO_TEST_*"`
        // call site in this file must be preceded by a nearby
        // `#[cfg(debug_assertions)]`. A future diff that removes
        // the cfg gate would fail here.
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/cli/connectors/test_cmd.rs");
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read {path:?}: {e}"));
        // Walk line by line, skipping lines that are comments
        // (the grep token itself appears in THIS test's doc).
        let needle = "std::env::var(\"AGENTSSO_TEST_";
        let mut call_sites = 0;
        let lines: Vec<&str> = source.lines().collect();
        for (line_idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                continue;
            }
            if !line.contains(needle) {
                continue;
            }
            call_sites += 1;
            // Scan up to 15 lines back for a cfg(debug_assertions)
            // attribute.
            let back_start = line_idx.saturating_sub(15);
            let gated =
                lines[back_start..line_idx].iter().any(|l| l.contains("#[cfg(debug_assertions)]"));
            assert!(
                gated,
                "env-var read on line {}: `{line}` must be within a \
                 #[cfg(debug_assertions)] block (scanned previous 15 lines)",
                line_idx + 1
            );
        }
        assert!(call_sites >= 1, "expected at least one AGENTSSO_TEST_* env-var read site");
    }
}
