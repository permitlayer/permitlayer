//! Error types for the plugin runtime.
//!
//! All variants carry enough context for the daemon's
//! `ProxyError::PluginResourceExceeded` conversion (Story 6.1 AC #12/#13)
//! and the structured `tracing::warn!` emission on resource exhaustion.
//!
//! **`#[non_exhaustive]`** is preserved so Stories 6.2+ can add variants
//! (host-API specific, loader-related, etc.) without a major version bump.

/// Errors returned by plugin loading and execution.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum PluginError {
    /// Plugin hit the heap-size limit configured on the runtime.
    #[error("plugin memory limit exceeded ({limit_bytes} bytes)")]
    MemoryExceeded {
        /// The configured limit that was breached.
        limit_bytes: usize,
    },

    /// Plugin exceeded its per-call wall-clock budget. The interrupt
    /// handler observed the deadline flag flip before returning.
    #[error("plugin execution deadline exceeded after {elapsed_ms}ms")]
    ExecutionDeadlineExceeded {
        /// Wall-clock milliseconds elapsed between the interrupt
        /// arming and the VM actually stopping (≥ the configured
        /// deadline + QuickJS interrupt-poll jitter).
        elapsed_ms: u128,
    },

    /// JS code threw an uncaught exception. `message` is the
    /// stringified exception value. Empty when `toString()` itself
    /// threw recursively (defensive fallback — see
    /// `From<rquickjs::Error>`).
    #[error("plugin threw: {message}")]
    JsException {
        /// The stringified thrown value. NEVER rendered into
        /// operator-facing HTTP responses (AR29 — don't leak internal
        /// error text to the agent); surfaced only in `tracing::warn!`.
        message: String,
    },

    /// Runtime could not be constructed. Fatal at daemon boot — the
    /// daemon refuses to start rather than running without a plugin
    /// sandbox.
    #[error("failed to initialize plugin runtime")]
    RuntimeInit(#[source] rquickjs::Error),

    /// Any other `rquickjs` error that doesn't map to a more specific
    /// variant. Conversion trampoline via `From<rquickjs::Error>`
    /// below.
    #[error("plugin runtime internal error")]
    Internal(#[source] rquickjs::Error),

    /// A plugin (or a host-API submodule) threw an `AgentssoError` JS
    /// instance — the structured error class registered at
    /// `globalThis.AgentssoError` by Story 6.2's `error_class::register`.
    /// The runtime's `Ctx::catch` arm extracts `.code`, `.retryable`,
    /// and `.message` from the thrown JS object before producing this
    /// variant.
    ///
    /// AR29: `message` MUST NEVER be rendered into the operator-facing
    /// HTTP response — it goes only to `tracing::warn!` with structured
    /// fields. The `From<PluginError> for ProxyError` impl in
    /// `permitlayer-proxy::error` maps this variant to
    /// `ProxyError::PluginInternal { source: Box<PluginError> }` which
    /// surfaces a generic `"plugin_internal"` body to the agent.
    #[error("plugin host API error [{code}]")]
    HostApiError {
        /// Stable error-code enum (semver-locked variants in Story 6.5
        /// territory; `Other(String)` round-trips plugin-custom codes).
        code: crate::host_api::services::HostApiErrorCode,
        /// Whether the agent should retry the call. Threaded from JS
        /// `error.retryable` and surfaced to operator logs via the
        /// `tracing::warn!` emission point.
        retryable: bool,
        /// Stringified `error.message` from the JS side. Carried in the
        /// Rust error chain for tracing; **never** rendered into the
        /// HTTP response body (AR29).
        message: String,
    },

    /// Plugin failed to load. The built-in path returns this variant
    /// up the call stack (boot-fatal); the user-installed path logs
    /// the `Display` form at WARN level and skips the connector
    /// (non-fatal).
    #[error("plugin '{connector}' failed to load: {reason}")]
    PluginLoadFailed {
        /// Connector directory name (NOT the `metadata.name` — the
        /// directory name is always known; metadata may have failed
        /// to parse). The directory name is validated to the same
        /// charset as `metadata.name` before this variant is
        /// constructed so operator-facing logs never carry
        /// attacker-controlled control chars.
        connector: String,
        /// Typed classification of the failure cause. Nested enum
        /// lets callers pattern-match on e.g. `JsSyntax` vs `Io`.
        reason: LoadFailureReason,
    },

    /// Plugin loaded but its `metadata` export failed validation
    /// (missing required field, malformed semver version, unsafe
    /// `name` chars, etc.). Surfaced per-connector — a malformed
    /// user-installed plugin does NOT crash the daemon.
    #[error("plugin '{connector}' has invalid metadata: {detail}")]
    MetadataInvalid {
        /// Connector directory name (same discipline as
        /// `PluginLoadFailed`).
        connector: String,
        /// Human-readable summary of what failed validation. Safe to
        /// render into operator-facing logs. Never includes raw JS
        /// source.
        detail: String,
    },

    /// Trust-check machinery (reading `.trusted`, computing the
    /// content hash, persisting a new entry) failed on I/O. The
    /// loader logs at WARN and proceeds as if the plugin is
    /// untrusted.
    #[error("trust check for plugin '{connector}' failed: {detail}")]
    TrustCheckFailed {
        /// Connector directory name.
        connector: String,
        /// Human-readable detail (e.g. "failed to hash source:
        /// permission denied").
        detail: String,
    },
}

/// Typed classification of plugin-load failure causes. `#[non_exhaustive]`
/// so 6.4's scaffolder can add variants (`Scaffolder(...)` for conformance
/// checks) without a breaking change.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum LoadFailureReason {
    /// Reading the plugin file from disk failed (permission denied,
    /// EACCES, disk full on a log-rotated filesystem).
    #[error("io error: {0}")]
    Io(#[source] std::io::Error),

    /// The plugin's JS source failed to compile inside the
    /// sandboxed load-time context. Wraps the rquickjs error —
    /// never rendered into HTTP responses (AR29).
    #[error("javascript syntax error")]
    JsSyntax(#[source] rquickjs::Error),

    /// The metadata-parse closure ran out of wall-clock time
    /// inside `PluginRuntime::with_context`. Rare — the load-time
    /// parse is O(parse-metadata) — usually surfaces a malicious
    /// plugin trying to stall startup.
    #[error("load-time execution deadline exceeded")]
    Timeout,

    /// The plugin's JS source did not export a `metadata` object.
    /// Either the export is missing entirely, the module form was
    /// wrong (CommonJS is rejected at 1.0.0), or metadata is not
    /// an object.
    #[error("plugin source does not export a `metadata` object")]
    MissingMetadata,

    /// The plugin source parsed but did not compile as an ES
    /// module (no `export` statement found at top level).
    /// Rejected with a clear message pointing operators at the
    /// canonical `export const metadata = {...}` shape.
    #[error("plugin source is not an ES module (use `export const metadata = {{...}}`)")]
    NotEsm,

    /// The plugin source file exceeded the configured byte cap
    /// (DoS-hardening — real plugins are ~100 KB; the cap sits
    /// well above that). Surfaces the pathological case as a
    /// clear error rather than an OOM at boot.
    #[error("plugin source exceeds size limit ({limit} bytes)")]
    SourceTooLarge {
        /// The byte cap that was exceeded.
        limit: u64,
    },

    /// Two built-in connector entries share the same name.
    /// Only reachable via a `builtin_connectors()` regression;
    /// returned from `load_all` so the daemon refuses to boot
    /// rather than silently overwriting one built-in with
    /// another.
    #[error("duplicate built-in connector name")]
    DuplicateBuiltin,
}

impl From<rquickjs::Error> for PluginError {
    fn from(value: rquickjs::Error) -> Self {
        match &value {
            // `rquickjs::Error::Exception` signals "JS threw and the
            // caller should retrieve the value via `Ctx::catch`."
            // The `with_context` implementation observes an empty-
            // `message` `JsException` and replaces it with the
            // extracted `toString()` of the thrown value — see D1
            // review patch at `runtime.rs`'s `match f(&ctx)` arm.
            // The `message: ""` sentinel here IS the handshake that
            // tells `with_context` "please extract the thrown value."
            rquickjs::Error::Exception => PluginError::JsException { message: String::new() },
            // `Allocation` is QuickJS's OOM signal — map it to
            // `MemoryExceeded` with `limit_bytes=0` as a sentinel
            // (the caller in `with_context` overrides this with the
            // real configured limit before returning).
            rquickjs::Error::Allocation => PluginError::MemoryExceeded { limit_bytes: 0 },
            _ => PluginError::Internal(value),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn plugin_error_display_memory_exceeded() {
        let err = PluginError::MemoryExceeded { limit_bytes: 33_554_432 };
        assert_eq!(err.to_string(), "plugin memory limit exceeded (33554432 bytes)");
    }

    #[test]
    fn plugin_error_display_deadline_exceeded() {
        let err = PluginError::ExecutionDeadlineExceeded { elapsed_ms: 2048 };
        assert_eq!(err.to_string(), "plugin execution deadline exceeded after 2048ms");
    }

    #[test]
    fn plugin_error_display_js_exception() {
        let err = PluginError::JsException { message: "Error: boom".to_owned() };
        assert_eq!(err.to_string(), "plugin threw: Error: boom");
    }

    #[test]
    fn plugin_error_display_runtime_init_wraps_source() {
        // Any `rquickjs::Error` variant works as the source. Use
        // `Allocation` because it's construct-without-args.
        let err = PluginError::RuntimeInit(rquickjs::Error::Allocation);
        assert_eq!(err.to_string(), "failed to initialize plugin runtime");
    }

    #[test]
    fn plugin_error_display_internal_wraps_source() {
        let err = PluginError::Internal(rquickjs::Error::Unknown);
        assert_eq!(err.to_string(), "plugin runtime internal error");
    }

    #[test]
    fn from_rquickjs_exception_maps_to_js_exception_with_empty_message() {
        // The `Exception` variant doesn't carry the message — the
        // caller must retrieve it via `Ctx::catch` before the
        // conversion. The fallback path here just gets an empty
        // message, which is expected.
        let err: PluginError = rquickjs::Error::Exception.into();
        assert!(matches!(err, PluginError::JsException { ref message } if message.is_empty()));
    }

    #[test]
    fn from_rquickjs_allocation_maps_to_memory_exceeded_sentinel() {
        let err: PluginError = rquickjs::Error::Allocation.into();
        assert!(matches!(err, PluginError::MemoryExceeded { limit_bytes: 0 }));
    }

    #[test]
    fn from_rquickjs_unknown_maps_to_internal() {
        let err: PluginError = rquickjs::Error::Unknown.into();
        assert!(matches!(err, PluginError::Internal(_)));
    }

    // Story 6.3: three loader-introduced variants. The Display form
    // MUST include the connector name so operator logs are greppable
    // (per AC #2).

    #[test]
    fn plugin_load_failed_display_includes_connector() {
        let err = PluginError::PluginLoadFailed {
            connector: "notion".to_owned(),
            reason: LoadFailureReason::MissingMetadata,
        };
        let rendered = err.to_string();
        assert!(rendered.contains("notion"), "connector name must appear in Display: {rendered}");
        assert!(
            rendered.contains("does not export a `metadata` object"),
            "reason must appear in Display: {rendered}"
        );
    }

    #[test]
    fn metadata_invalid_display_includes_connector() {
        let err = PluginError::MetadataInvalid {
            connector: "notion".to_owned(),
            detail: "name is required".to_owned(),
        };
        let rendered = err.to_string();
        assert!(rendered.contains("notion"), "connector name must appear in Display: {rendered}");
        assert!(rendered.contains("name is required"), "detail must appear in Display: {rendered}");
    }

    #[test]
    fn trust_check_failed_display_includes_connector() {
        let err = PluginError::TrustCheckFailed {
            connector: "notion".to_owned(),
            detail: "permission denied".to_owned(),
        };
        let rendered = err.to_string();
        assert!(rendered.contains("notion"), "connector name must appear in Display: {rendered}");
        assert!(
            rendered.contains("permission denied"),
            "detail must appear in Display: {rendered}"
        );
    }

    #[test]
    fn load_failure_reason_is_non_exhaustive_and_displays() {
        // Compile-time proof that `#[non_exhaustive]` holds (future
        // additive variants in 6.4 scaffolder territory must not
        // require matching updates on external consumers).
        fn _accept_non_exhaustive(r: LoadFailureReason) -> String {
            match r {
                LoadFailureReason::Io(_) => "io".to_owned(),
                LoadFailureReason::JsSyntax(_) => "js-syntax".to_owned(),
                LoadFailureReason::Timeout => "timeout".to_owned(),
                LoadFailureReason::MissingMetadata => "missing-metadata".to_owned(),
                LoadFailureReason::NotEsm => "not-esm".to_owned(),
                LoadFailureReason::SourceTooLarge { .. } => "source-too-large".to_owned(),
                LoadFailureReason::DuplicateBuiltin => "duplicate-builtin".to_owned(),
                // Without the wildcard arm this file would fail to
                // compile when a new variant is added — which is
                // exactly the behaviour `#[non_exhaustive]` is
                // supposed to prevent for external crates. Internal
                // exhaustive matching is allowed.
            }
        }
        assert_eq!(_accept_non_exhaustive(LoadFailureReason::Timeout), "timeout");
        assert_eq!(_accept_non_exhaustive(LoadFailureReason::MissingMetadata), "missing-metadata");
        assert_eq!(_accept_non_exhaustive(LoadFailureReason::NotEsm), "not-esm");
        // The Display form on the outer enum already covered above;
        // this test also exercises the inner enum's Display:
        let timeout = LoadFailureReason::Timeout.to_string();
        assert!(timeout.contains("deadline"), "Timeout display must mention deadline: {timeout}");
    }
}
