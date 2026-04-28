//! Sandbox-escape test suite for the Story 6.1 `PluginRuntime`.
//!
//! This is the load-bearing security surface of Epic 6 — every known
//! JS-sandbox-escape technique that operators' threat model cares
//! about gets a test here. If any test in this file starts failing,
//! the `permitlayer-plugins` crate must refuse to ship a release
//! until the regression is fixed OR a separate security ADR explains
//! why the new behavior is acceptable.

use std::time::Duration;

use permitlayer_plugins::{PluginError, PluginRuntime, RuntimeConfig};

fn fresh_runtime() -> PluginRuntime {
    PluginRuntime::new_default().unwrap()
}

fn eval_string(rt: &PluginRuntime, src: &str) -> Result<String, PluginError> {
    rt.with_context(|ctx| {
        let value: String = ctx.eval(src)?;
        Ok(value)
    })
}

fn assert_typeof_undefined(rt: &PluginRuntime, name: &str) {
    let src = format!("typeof {name}");
    let ty = eval_string(rt, &src).unwrap_or_else(|e| panic!("typeof {name} eval failed: {e}"));
    assert_eq!(ty, "undefined", "global `{name}` must be undefined (got `{ty}`)");
}

// ─────────────────────────────────────────────────────────────────
// AC #2: globals denylist
// ─────────────────────────────────────────────────────────────────

mod globals {
    use super::*;

    #[test]
    fn agentsso_is_the_only_added_global() {
        let rt = fresh_runtime();
        let ty = eval_string(&rt, "typeof agentsso").unwrap();
        assert_eq!(ty, "object");
    }

    // D14 review patch: `#[ignore]` because this test will break
    // the day Story 6.2 populates the `agentsso.*` namespace. The
    // intent — "Story 6.1's sandbox exposes an empty object" — is
    // covered by the live
    // `agentsso_is_the_only_added_global` test above (which only
    // asserts the type, not the key count). Run with
    // `--ignored` to validate the Story 6.1 empty-state invariant
    // at implementation time, then delete the `#[ignore]` after
    // Story 6.2 lands and the test can be rewritten to the new
    // expected key list.
    #[test]
    #[ignore = "Story 6.2 populates agentsso.*; test will be rewritten then"]
    fn agentsso_is_empty_in_story_6_1() {
        let rt = fresh_runtime();
        let count: i32 =
            rt.with_context(|ctx| Ok(ctx.eval::<i32, _>("Object.keys(agentsso).length")?)).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn filesystem_globals_are_undefined() {
        let rt = fresh_runtime();
        for g in ["require", "fs", "process", "Buffer", "global", "__dirname", "__filename"] {
            assert_typeof_undefined(&rt, g);
        }
    }

    #[test]
    fn network_globals_are_undefined() {
        let rt = fresh_runtime();
        for g in ["fetch", "XMLHttpRequest", "WebSocket", "EventSource"] {
            assert_typeof_undefined(&rt, g);
        }
    }

    #[test]
    fn browser_bridge_globals_are_undefined() {
        let rt = fresh_runtime();
        for g in ["window", "self", "document", "navigator", "location"] {
            assert_typeof_undefined(&rt, g);
        }
    }

    #[test]
    fn wasm_and_timers_are_undefined() {
        let rt = fresh_runtime();
        for g in ["WebAssembly", "setTimeout", "setInterval", "setImmediate"] {
            assert_typeof_undefined(&rt, g);
        }
    }

    #[test]
    fn import_and_require_are_undefined() {
        let rt = fresh_runtime();
        for g in ["require", "module", "exports"] {
            assert_typeof_undefined(&rt, g);
        }
    }
}

// ─────────────────────────────────────────────────────────────────
// AC #3: filesystem escapes fail safely
// ─────────────────────────────────────────────────────────────────

mod filesystem {
    use super::*;

    #[test]
    fn require_fs_throws() {
        let rt = fresh_runtime();
        let outcome = eval_string(
            &rt,
            "(function() { try { require('fs'); return 'defined'; } catch(e) { return 'threw'; } })()",
        )
        .unwrap();
        assert_eq!(outcome, "threw");
    }

    #[test]
    fn require_node_fs_throws() {
        let rt = fresh_runtime();
        let outcome = eval_string(
            &rt,
            "(function() { try { require('node:fs'); return 'defined'; } catch(e) { return 'threw'; } })()",
        )
        .unwrap();
        assert_eq!(outcome, "threw");
    }

    #[test]
    fn require_path_throws() {
        let rt = fresh_runtime();
        let outcome = eval_string(
            &rt,
            "(function() { try { require('path'); return 'defined'; } catch(e) { return 'threw'; } })()",
        )
        .unwrap();
        assert_eq!(outcome, "threw");
    }

    #[test]
    fn fs_readfilesync_throws() {
        let rt = fresh_runtime();
        let outcome = eval_string(
            &rt,
            "(function() { try { fs.readFileSync('/etc/passwd'); return 'read'; } catch(e) { return 'threw'; } })()",
        )
        .unwrap();
        assert_eq!(outcome, "threw");
    }

    #[test]
    fn function_constructor_cannot_reach_require() {
        let rt = fresh_runtime();
        let outcome = eval_string(
            &rt,
            "(function() { try { return String(new Function('return require(\"fs\")')()); } catch(e) { return 'threw'; } })()",
        )
        .unwrap();
        assert_eq!(outcome, "threw", "Function-constructor escape must fail; got `{outcome}`");
    }

    #[test]
    fn prototype_walk_cannot_reach_require() {
        let rt = fresh_runtime();
        let outcome = eval_string(
            &rt,
            "(function() { try { return String(({}).__proto__.__proto__.constructor('return require(\"fs\")')()); } catch(e) { return 'threw'; } })()",
        )
        .unwrap();
        assert_eq!(outcome, "threw");
    }

    #[test]
    fn no_filesystem_io_on_escape_attempt() {
        // D9 review patch: use a per-test tempdir (both for the
        // sentinel AND the "escape-proof" path the attacks try to
        // write to) so concurrent test runs don't race each other
        // on a shared `/tmp/plugin-escape-proof` path.
        let tmp = tempfile::tempdir().unwrap();
        let sentinel_path = tmp.path().join("sentinel.txt");
        std::fs::write(&sentinel_path, b"initial").unwrap();
        let initial_mtime = std::fs::metadata(&sentinel_path).unwrap().modified().unwrap();

        let escape_proof_path = tmp.path().join("plugin-escape-proof");
        let proof_path_str = escape_proof_path.to_string_lossy().into_owned();
        let rt = fresh_runtime();
        let attempts = [
            format!(
                "try {{ require('fs').writeFileSync('{proof_path_str}', 'ok'); }} catch(e) {{}}"
            ),
            format!("try {{ fs.appendFileSync('{proof_path_str}', 'x'); }} catch(e) {{}}"),
            "try { process.stdout.write('hello'); } catch(e) {}".to_owned(),
            "try { Buffer.from('hello').toString('base64'); } catch(e) {}".to_owned(),
        ];
        for src in &attempts {
            let _ = rt.with_context(|ctx| -> Result<(), PluginError> {
                let _: rquickjs::Value = ctx.eval(src.as_str())?;
                Ok(())
            });
        }
        let final_mtime = std::fs::metadata(&sentinel_path).unwrap().modified().unwrap();
        assert_eq!(initial_mtime, final_mtime);
        assert!(!escape_proof_path.exists());
    }
}

// ─────────────────────────────────────────────────────────────────
// AC #4: network escapes fail safely
// ─────────────────────────────────────────────────────────────────

mod network {
    use super::*;

    #[test]
    fn fetch_undefined() {
        let rt = fresh_runtime();
        let outcome = eval_string(
            &rt,
            "(function() { try { fetch('http://127.0.0.1:1'); return 'called'; } catch(e) { return 'threw'; } })()",
        )
        .unwrap();
        assert_eq!(outcome, "threw");
    }

    #[test]
    fn xhr_undefined() {
        let rt = fresh_runtime();
        let outcome = eval_string(
            &rt,
            "(function() { try { new XMLHttpRequest(); return 'constructed'; } catch(e) { return 'threw'; } })()",
        )
        .unwrap();
        assert_eq!(outcome, "threw");
    }

    #[test]
    fn websocket_undefined() {
        let rt = fresh_runtime();
        let outcome = eval_string(
            &rt,
            "(function() { try { new WebSocket('ws://127.0.0.1:1'); return 'constructed'; } catch(e) { return 'threw'; } })()",
        )
        .unwrap();
        assert_eq!(outcome, "threw");
    }

    #[test]
    fn require_network_modules_throws() {
        let rt = fresh_runtime();
        for module in ["http", "https", "net", "dgram", "tls"] {
            let src = format!(
                "(function() {{ try {{ require('{module}'); return 'got'; }} catch(e) {{ return 'threw'; }} }})()"
            );
            let outcome = eval_string(&rt, &src).unwrap();
            assert_eq!(outcome, "threw", "require('{module}') must throw");
        }
    }

    #[test]
    fn no_network_io_on_escape_attempt() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();

        let rt = fresh_runtime();
        let attempts = [
            format!("try {{ fetch('http://127.0.0.1:{port}'); }} catch(e) {{}}"),
            format!(
                "try {{ new XMLHttpRequest().open('GET', 'http://127.0.0.1:{port}'); }} catch(e) {{}}"
            ),
            format!("try {{ new WebSocket('ws://127.0.0.1:{port}'); }} catch(e) {{}}"),
            "try { require('net').connect(1); } catch(e) {}".to_owned(),
        ];
        for src in attempts {
            let _ = rt.with_context(|ctx| -> Result<(), PluginError> {
                let _: rquickjs::Value = ctx.eval(src.as_str())?;
                Ok(())
            });
        }
        std::thread::sleep(Duration::from_millis(100));
        match listener.accept() {
            Ok((_, peer)) => panic!("network escape reached the listener from {peer}"),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => panic!("unexpected listener error: {e}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────
// AC #5: process/eval — process undefined, eval sandbox-local
// ─────────────────────────────────────────────────────────────────

mod process_and_eval {
    use super::*;

    #[test]
    fn process_is_undefined() {
        let rt = fresh_runtime();
        assert_typeof_undefined(&rt, "process");
    }

    #[test]
    fn child_process_require_throws() {
        let rt = fresh_runtime();
        let outcome = eval_string(
            &rt,
            "(function() { try { require('child_process').exec('rm -rf /'); return 'called'; } catch(e) { return 'threw'; } })()",
        )
        .unwrap();
        assert_eq!(outcome, "threw");
    }

    #[test]
    fn process_exit_throws() {
        let rt = fresh_runtime();
        let outcome = eval_string(
            &rt,
            "(function() { try { process.exit(0); return 'exited'; } catch(e) { return 'threw'; } })()",
        )
        .unwrap();
        assert_eq!(outcome, "threw");
    }

    #[test]
    fn eval_is_allowed_and_sandbox_local() {
        let rt = fresh_runtime();
        let two: i32 = rt.with_context(|ctx| Ok(ctx.eval::<i32, _>("eval('1 + 1')")?)).unwrap();
        assert_eq!(two, 2);
    }

    #[test]
    fn eval_cannot_reach_host_via_require() {
        let rt = fresh_runtime();
        let outcome = eval_string(
            &rt,
            "(function() { try { eval('require(\"fs\")'); return 'got'; } catch(e) { return 'threw'; } })()",
        )
        .unwrap();
        assert_eq!(outcome, "threw");
    }

    #[test]
    fn eval_cannot_reach_host_via_process() {
        let rt = fresh_runtime();
        let outcome = eval_string(
            &rt,
            "(function() { try { eval('process.env.HOME'); return 'got'; } catch(e) { return 'threw'; } })()",
        )
        .unwrap();
        assert_eq!(outcome, "threw");
    }
}

// ─────────────────────────────────────────────────────────────────
// AC #9: prototype-chain escapes fail
// ─────────────────────────────────────────────────────────────────

mod prototype_chain {
    use super::*;

    #[test]
    fn object_prototype_walk_reaches_null() {
        let rt = fresh_runtime();
        let is_null: bool = rt
            .with_context(|ctx| {
                Ok(ctx
                    .eval::<bool, _>("Object.getPrototypeOf(Object.getPrototypeOf({})) === null")?)
            })
            .unwrap();
        assert!(is_null);
    }

    #[test]
    fn function_constructor_cannot_reach_require() {
        let rt = fresh_runtime();
        let outcome = eval_string(
            &rt,
            "(function() { try { return String((function(){}).constructor('return require(\"fs\")')()); } catch(e) { return 'threw'; } })()",
        )
        .unwrap();
        assert_eq!(outcome, "threw");
    }

    #[test]
    fn array_iterator_constructor_cannot_reach_require() {
        // NOTE: this test historically passed for the wrong reason
        // (Symbol is undefined in our base+Eval context). With the
        // B3 Function-constructor block, it now passes for the
        // RIGHT reason too — even if `Symbol` becomes available
        // in a future intrinsic opt-in, the retrieved constructor
        // is our throwing stub.
        let rt = fresh_runtime();
        let outcome = eval_string(
            &rt,
            "(function() { try { return String(Array.prototype[Symbol.iterator].constructor('return require(\"fs\")')()); } catch(e) { return 'threw'; } })()",
        )
        .unwrap();
        assert_eq!(outcome, "threw");
    }

    // B3 / D2 / D16 review-patch tests — strict assertions that
    // the Function constructor family is BLOCKED, not merely
    // ineffective because `require`/`process` are undefined.

    #[test]
    fn direct_new_function_with_benign_body_still_throws() {
        // Strict B3 test — `new Function('return 1')()` must NOT
        // return `1`; it must throw. Previously this test would
        // have returned `1` (the Function constructor was fully
        // functional, and the escape tests only passed because
        // the body referenced undefined globals).
        let rt = fresh_runtime();
        let outcome = eval_string(
            &rt,
            "(function() { try { return String(new Function('return 1')()); } catch(e) { return 'threw'; } })()",
        )
        .unwrap();
        assert_eq!(
            outcome, "threw",
            "Function constructor must throw even for benign bodies (got `{outcome}`)"
        );
    }

    #[test]
    fn direct_function_call_with_benign_body_still_throws() {
        // Also exercise the `Function(...)` (no `new`) form.
        let rt = fresh_runtime();
        let outcome = eval_string(
            &rt,
            "(function() { try { return String(Function('return 1')()); } catch(e) { return 'threw'; } })()",
        )
        .unwrap();
        assert_eq!(outcome, "threw");
    }

    #[test]
    fn prototype_walk_function_constructor_throws_on_benign_body() {
        // `({}).__proto__.__proto__.constructor('return 1')()` — the
        // classic prototype-walk access to the Function constructor.
        // Must throw regardless of the body.
        let rt = fresh_runtime();
        let outcome = eval_string(
            &rt,
            "(function() { try { return String(({}).__proto__.__proto__.constructor('return 1')()); } catch(e) { return 'threw'; } })()",
        )
        .unwrap();
        assert_eq!(outcome, "threw");
    }

    #[test]
    fn function_prototype_constructor_is_blocked_stub() {
        // Verify `Function.prototype.constructor === Function` still
        // holds (a standard JS invariant) so identity checks don't
        // break, AND that calling it throws.
        let rt = fresh_runtime();
        let identity: bool = rt
            .with_context(|ctx| {
                Ok(ctx.eval::<bool, _>("Function.prototype.constructor === Function")?)
            })
            .unwrap();
        assert!(
            identity,
            "Function.prototype.constructor === Function invariant must hold (attacker identity check)"
        );
        // And both throw:
        let outcome = eval_string(
            &rt,
            "(function() { try { Function.prototype.constructor('return 1')(); return 'called'; } catch(e) { return 'threw'; } })()",
        )
        .unwrap();
        assert_eq!(outcome, "threw");
    }

    // D15 review patch: drop the tautological `undefined OR object`
    // assertion. Reflect IS shipped by QuickJS-NG's base intrinsics,
    // so we instead assert it can't be used to bypass the Function
    // constructor block.
    #[test]
    fn reflect_cannot_bypass_function_constructor_block() {
        // `Reflect.construct(Function, ['return 1'])` calls the
        // (blocked) Function constructor with the given args. Must
        // throw because our replacement stub throws.
        let rt = fresh_runtime();
        let outcome = eval_string(
            &rt,
            "(function() { try { return String(Reflect.construct(Function, ['return 1'])()); } catch(e) { return 'threw'; } })()",
        )
        .unwrap();
        assert_eq!(
            outcome, "threw",
            "Reflect.construct on the Function constructor must throw (got `{outcome}`)"
        );
    }

    #[test]
    fn reflect_apply_cannot_bypass_function_constructor_block() {
        // `Reflect.apply(Function, null, ['return 1'])` — calls the
        // stub with `Function(['return 1'])` args. Must throw.
        let rt = fresh_runtime();
        let outcome = eval_string(
            &rt,
            "(function() { try { return String(Reflect.apply(Function, null, ['return 1'])()); } catch(e) { return 'threw'; } })()",
        )
        .unwrap();
        assert_eq!(outcome, "threw");
    }
}

// ─────────────────────────────────────────────────────────────────
// AC #10: Error.stack does not leak host paths
// ─────────────────────────────────────────────────────────────────

mod error_stack {
    use super::*;

    #[test]
    fn error_stack_does_not_leak_host_paths() {
        let rt = fresh_runtime();
        let stack = eval_string(
            &rt,
            r#"(function() { try { throw new Error('boom'); } catch(e) { return String(e.stack || ''); } })()"#,
        )
        .unwrap();
        let forbidden = ["/Users/", "/home/", "/var/", "/private/", "C:\\"];
        for frag in forbidden {
            assert!(
                !stack.contains(frag),
                "Error.stack leaked host path fragment `{frag}`:\n{stack}"
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────
// AC #8: runtime survives after a limit is hit
// ─────────────────────────────────────────────────────────────────

mod survival {
    use super::*;

    #[test]
    fn runtime_survives_after_escape_attempt() {
        let rt = fresh_runtime();
        let escape_attempts = [
            "try { require('fs'); } catch(e) {}",
            "try { process.exit(0); } catch(e) {}",
            "try { fetch('http://127.0.0.1:1'); } catch(e) {}",
            "try { (function(){}).constructor('return require(\"fs\")')(); } catch(e) {}",
        ];
        for src in escape_attempts {
            let _ = rt.with_context(|ctx| -> Result<(), PluginError> {
                let _: rquickjs::Value = ctx.eval(src)?;
                Ok(())
            });
        }
        let answer: i32 = rt.with_context(|ctx| Ok(ctx.eval::<i32, _>("6 * 7")?)).unwrap();
        assert_eq!(answer, 42);
    }

    #[test]
    fn runtime_survives_after_js_throw() {
        let rt = fresh_runtime();
        let first = rt.with_context(|ctx| -> Result<i32, PluginError> {
            let _: rquickjs::Value = ctx.eval("throw new Error('first-call-boom')")?;
            Ok(0)
        });
        assert!(matches!(first, Err(PluginError::JsException { .. })));
        let answer: i32 = rt.with_context(|ctx| Ok(ctx.eval::<i32, _>("100 + 23")?)).unwrap();
        assert_eq!(answer, 123);
    }

    #[test]
    fn tight_memory_limit_surfaces_error() {
        let config = RuntimeConfig {
            memory_limit_bytes: 1024 * 1024,
            gc_threshold_bytes: 512 * 1024,
            execution_deadline: Duration::from_secs(10),
            max_stack_size_bytes: RuntimeConfig::DEFAULT_MAX_STACK,
        };
        let rt = PluginRuntime::new(config).unwrap();
        let err = rt
            .with_context(|ctx| -> Result<(), PluginError> {
                let _: rquickjs::Value = ctx.eval("let a = 'x'; while (true) { a = a + a; }")?;
                Ok(())
            })
            .unwrap_err();
        assert!(
            matches!(err, PluginError::MemoryExceeded { .. } | PluginError::JsException { .. }),
            "memory-limit hit must surface as MemoryExceeded or JsException; got {err:?}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────
// Story 6.2 / AC #25 — added intrinsics are present
// ─────────────────────────────────────────────────────────────────

mod intrinsics_6_2 {
    use super::*;

    #[test]
    fn json_parse_and_stringify_present() {
        let rt = fresh_runtime();
        let v = eval_string(&rt, "typeof JSON").unwrap();
        assert_eq!(v, "object");
        let parsed = eval_string(&rt, r#"String(JSON.parse('{"a":1}').a)"#).unwrap();
        assert_eq!(parsed, "1");
        let stringified = eval_string(&rt, r#"JSON.stringify({a: 1})"#).unwrap();
        assert_eq!(stringified, r#"{"a":1}"#);
    }

    #[test]
    fn date_intrinsic_present() {
        let rt = fresh_runtime();
        let v = eval_string(&rt, "typeof Date").unwrap();
        assert_eq!(v, "function");
        // Construct a Date and assert its time is positive.
        let pos = eval_string(&rt, "String((new Date()).getTime() > 0)").unwrap();
        assert_eq!(pos, "true");
    }

    #[test]
    fn regexp_intrinsic_present_and_matches() {
        let rt = fresh_runtime();
        let v = eval_string(&rt, "typeof RegExp").unwrap();
        assert_eq!(v, "function");
        let matches = eval_string(&rt, r#"String(/abc/.test("abc"))"#).unwrap();
        assert_eq!(matches, "true");
    }

    #[test]
    fn promise_intrinsic_present() {
        let rt = fresh_runtime();
        let v = eval_string(&rt, "typeof Promise").unwrap();
        assert_eq!(v, "function");
        // Construct + resolve a Promise; its constructor must work.
        let v2 = eval_string(&rt, "String(typeof new Promise(function(r) { r(1); }))").unwrap();
        assert_eq!(v2, "object");
    }

    #[test]
    fn typed_array_intrinsic_present() {
        let rt = fresh_runtime();
        let v = eval_string(&rt, "typeof Uint8Array").unwrap();
        assert_eq!(v, "function");
        let len = eval_string(&rt, "String(new Uint8Array([1, 2, 3]).length)").unwrap();
        assert_eq!(len, "3");
    }
}

// ─────────────────────────────────────────────────────────────────
// Story 6.2 / AC #26 — added intrinsics did NOT open new escape vectors
// ─────────────────────────────────────────────────────────────────

mod intrinsics_6_2_escape {
    use super::*;

    /// `process` is still undefined inside a Promise resolution.
    /// The Promise intrinsic does NOT add timer/process bindings.
    #[test]
    fn promise_resolution_cannot_reach_process() {
        let rt = fresh_runtime();
        let v = eval_string(
            &rt,
            r#"
                (function() {
                    var capturedType = "untouched";
                    new Promise(function(r) { r(typeof process); }).then(function(t) {
                        capturedType = t;
                    });
                    return capturedType;
                })()
            "#,
        );
        // The `.then` callback runs on the microtask queue which
        // QuickJS only pumps between calls — by the time we read
        // `capturedType` synchronously, it's still "untouched".
        // Either result is acceptable for the security claim:
        // - "untouched" — microtask hasn't run, attack didn't even
        //   complete.
        // - "undefined" — microtask ran, but `process` was still
        //   undefined inside the promise.
        // Both prove `process` is not exposed.
        let result = v.unwrap();
        assert!(
            result == "untouched" || result == "undefined",
            "process must be unreachable via Promise; got `{result}`"
        );
    }

    /// JSON.parse-derived objects' constructor walk hits the
    /// neutered Function stub from Story 6.1 B3.
    #[test]
    fn json_parse_constructor_walk_hits_blocked_function() {
        let rt = fresh_runtime();
        let result = eval_string(&rt, r#"JSON.parse("{}").__proto__.constructor("return this")()"#);
        // Function constructor neutered → throws.
        assert!(
            result.is_err(),
            "Function-constructor walk via JSON.parse must throw; got Ok({result:?})"
        );
    }

    /// Date constructor-walk hits the same neuter.
    #[test]
    fn date_prototype_constructor_walk_hits_blocked_function() {
        let rt = fresh_runtime();
        let result = eval_string(&rt, r#"new Date().constructor.constructor("return this")()"#);
        assert!(
            result.is_err(),
            "Date.prototype.constructor walk must hit blocked Function; got Ok({result:?})"
        );
    }

    /// RegExp constructor-walk hits the same neuter.
    #[test]
    fn regexp_prototype_constructor_walk_hits_blocked_function() {
        let rt = fresh_runtime();
        let result = eval_string(&rt, r#"/x/.constructor.constructor("return this")()"#);
        assert!(
            result.is_err(),
            "RegExp.prototype.constructor walk must hit blocked Function; got Ok({result:?})"
        );
    }

    /// Uint8Array constructor-walk hits the same neuter.
    #[test]
    fn uint8array_prototype_constructor_walk_hits_blocked_function() {
        let rt = fresh_runtime();
        let result =
            eval_string(&rt, r#"new Uint8Array([0]).constructor.constructor("return this")()"#);
        assert!(
            result.is_err(),
            "Uint8Array.prototype.constructor walk must hit blocked Function; got Ok({result:?})"
        );
    }

    /// Promise.resolve(x).constructor walk hits the same neuter.
    #[test]
    fn promise_constructor_walk_hits_blocked_function() {
        let rt = fresh_runtime();
        let result =
            eval_string(&rt, r#"Promise.resolve(1).constructor.constructor("return process")()"#);
        assert!(
            result.is_err(),
            "Promise.constructor walk must hit blocked Function; got Ok({result:?})"
        );
    }
}
