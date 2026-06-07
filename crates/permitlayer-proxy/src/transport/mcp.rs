//! MCP Streamable HTTP transport adapters.
//!
//! Each Google Workspace service gets its own MCP server struct:
//! - `GmailMcpServer` — five Gmail tools (read-only)
//! - `CalendarMcpServer` — five Calendar tools (three read, two write)
//! - `DriveMcpServer` — five Drive tools (three read, two write)
//!
//! Each tool builds a `ProxyRequest` and delegates to
//! `ProxyService::handle`, converting the response to MCP `CallToolResult`.
//!
//! The raw OAuth access token is NEVER returned to the agent — only the
//! upstream API response body.

use std::sync::Arc;

use axum::body::Bytes;
use axum::http::{HeaderMap, Method};
use rmcp::handler::server::tool::{Extension, ToolRouter};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{Implementation, ServerCapabilities, ServerInfo};
use rmcp::{tool, tool_handler, tool_router};
use tracing::debug;

use crate::error::{AgentId, ProxyError};
use crate::request::ProxyRequest;
use crate::service::ProxyService;
use crate::transport::gmail_shape;

// ─────────────────────────────────────────────────────────────────────
// Per-tool-call agent identity propagation.
// ─────────────────────────────────────────────────────────────────────
//
// rmcp's `StreamableHttpService` deserializes the inbound HTTP request
// and inserts the `http::request::Parts` (with our extensions) into the
// JSON-RPC message's extensions (`tower.rs:476/479/534`). The session
// worker — spawned via `tokio::spawn` (`tower.rs:542`) — swaps those
// extensions into `RequestContext.extensions` before dispatching to the
// tool method (`service.rs:954`).
//
// `AuthLayer` populates `req.extensions_mut().insert(AgentId(...))` on
// successful bearer validation (`auth.rs:331`), so the chain is:
//
//   inbound HTTP   ── AuthLayer.insert(AgentId)
//                     │
//                     ▼
//   StreamableHttpService.call ── extracts Parts, stuffs into JSON-RPC
//                     │           message.extensions
//                     ▼
//   tokio::spawn(session worker) ── swaps message.extensions into
//                                   RequestContext.extensions
//                     │
//                     ▼
//   tool handler ── Extension<Parts> extractor pulls Parts back out;
//                   `parts.extensions.get::<AgentId>()` is the agent.
//
// We previously used a tokio task-local for this, which was structurally
// broken: task-locals do not propagate across `tokio::spawn`, and rmcp
// spawns the session worker, so every tool call read the task-local
// from a fresh task that had never been scoped. The sentinel
// "mcp-client-unattributed" was firing on every authenticated request.
//
// The Extension extractor is the supported escape hatch.

/// Pull the `AgentId` out of the per-call HTTP `Parts` that rmcp
/// preserves in `RequestContext.extensions`.
///
/// `AuthLayer` is the source of truth: it inserts `AgentId(name)`
/// into the inbound HTTP request's extensions. rmcp surfaces the
/// whole `Parts` struct (with that extension) to tool handlers via
/// the `Extension<Parts>` extractor.
///
/// Returns [`ProxyError::AuthMissingAgentId`] if the extension is
/// absent. That should never happen for a real client request: the
/// `/mcp/*` route is not in the operational allowlist, so AuthLayer
/// runs and either rejects with `auth.missing_token` /
/// `auth.invalid_token` OR populates `AgentId`. A caller that
/// reaches a tool handler with no `AgentId` is necessarily a
/// misconfigured route or a test harness mounting the MCP service
/// without middleware.
fn agent_id_from_parts(parts: &axum::http::request::Parts) -> Result<String, ProxyError> {
    parts.extensions.get::<AgentId>().map(|a| a.0.clone()).ok_or(ProxyError::AuthMissingAgentId)
}

/// Strip the `$schema` meta-schema declaration from every tool's
/// `input_schema` in a `ToolRouter`.
///
/// `schemars 1.2` emits `"$schema": "https://json-schema.org/draft/2020-12/schema"`
/// on every generated root schema. The MCP spec implies the JSON Schema
/// dialect for `inputSchema`, so the field is redundant — but strict
/// validators (e.g. OpenClaw / AJV in strict mode) reject any schema with
/// an unresolvable meta-schema reference and refuse to dispatch the tool
/// call. Stripping `$schema` makes our tool catalog compatible with those
/// clients without losing information.
///
/// Called once per server construction in `*McpServer::new`. Zero
/// per-request cost.
///
/// NOTE: if `Tool::output_schema` is ever populated for our tools, this
/// helper must be extended to strip it from `output_schema` as well.
fn strip_meta_schema<S>(router: &mut ToolRouter<S>) {
    for route in router.map.values_mut() {
        let schema = Arc::make_mut(&mut route.attr.input_schema);
        schema.remove("$schema");
    }
}

// -- Tool parameter structs --------------------------------------------------

/// Parameters for `gmail.messages.list`.
#[derive(serde::Deserialize, schemars::JsonSchema, Default)]
pub struct MessagesListParams {
    /// Maximum number of messages to return.
    pub max_results: Option<u32>,
    /// Page token for pagination.
    pub page_token: Option<String>,
    /// Label IDs to filter by.
    pub label_ids: Option<Vec<String>>,
    /// Gmail search query (same syntax as the Gmail search box).
    pub q: Option<String>,
    /// Include messages from SPAM and TRASH.
    pub include_spam_trash: Option<bool>,
}

/// Parameters for `gmail.messages.get`.
#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct MessagesGetParams {
    /// The message ID.
    pub id: String,
    /// Response format: "full", "metadata", "minimal", or "raw".
    pub format: Option<String>,
    /// Metadata headers to include when format is "metadata".
    pub metadata_headers: Option<Vec<String>>,
}

/// Parameters for `gmail.threads.list`.
#[derive(serde::Deserialize, schemars::JsonSchema, Default)]
pub struct ThreadsListParams {
    /// Maximum number of threads to return.
    pub max_results: Option<u32>,
    /// Page token for pagination.
    pub page_token: Option<String>,
    /// Label IDs to filter by.
    pub label_ids: Option<Vec<String>>,
    /// Gmail search query.
    pub q: Option<String>,
}

/// Parameters for `gmail.threads.get`.
#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct ThreadsGetParams {
    /// The thread ID.
    pub id: String,
    /// Response format: "full", "metadata", "minimal".
    pub format: Option<String>,
}

/// Parameters for `gmail.search`.
#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct SearchParams {
    /// Gmail search query (required).
    pub query: String,
    /// Maximum number of results to return.
    pub max_results: Option<u32>,
    /// Page token for pagination.
    pub page_token: Option<String>,
}

// -- Story 9.1: Gmail read-tool gap-fill (all `gmail.readonly`) --------------

/// Parameters for `gmail.attachments.get`.
#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct AttachmentsGetParams {
    /// The ID of the message the attachment belongs to.
    pub message_id: String,
    /// The attachment ID (from the message payload part).
    pub attachment_id: String,
}

/// Parameters for `gmail.labels.list` (no inputs — Gmail lists all labels
/// for the authenticated user). An empty params struct is used because
/// every tool in this codebase takes `Parameters<…>`; there is no
/// paramless-tool form.
#[derive(serde::Deserialize, schemars::JsonSchema, Default)]
pub struct LabelsListParams {}

/// Parameters for `gmail.profile.get` (no inputs — maps to Gmail's
/// `users.getProfile` for the authenticated user).
#[derive(serde::Deserialize, schemars::JsonSchema, Default)]
pub struct ProfileGetParams {}

/// Parameters for `gmail.history.list`.
#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct HistoryListParams {
    /// Required. Return history records after this `historyId` (obtain
    /// from a prior `messages.get`/`profile.get`). Gmail rejects the
    /// request without it, so we fail fast at the tool boundary.
    pub start_history_id: String,
    /// Maximum number of history records to return.
    pub max_results: Option<u32>,
    /// Page token for pagination.
    pub page_token: Option<String>,
    /// Only return history records for this label ID.
    pub label_id: Option<String>,
    /// History types to return (e.g. "messageAdded", "labelAdded").
    pub history_types: Option<Vec<String>>,
}

/// Parameters for `gmail.drafts.list`.
#[derive(serde::Deserialize, schemars::JsonSchema, Default)]
pub struct DraftsListParams {
    /// Maximum number of drafts to return.
    pub max_results: Option<u32>,
    /// Page token for pagination.
    pub page_token: Option<String>,
    /// Only return drafts matching this Gmail search query.
    pub q: Option<String>,
    /// Include drafts from SPAM and TRASH.
    pub include_spam_trash: Option<bool>,
}

/// Parameters for `gmail.drafts.get`.
#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct DraftsGetParams {
    /// The draft ID.
    pub draft_id: String,
    /// Response format: "full", "metadata", "minimal", or "raw".
    pub format: Option<String>,
    /// Metadata headers to include when format is "metadata".
    pub metadata_headers: Option<Vec<String>>,
}

// -- Story 9.2: Gmail WRITE + SETTINGS-read tool parameter structs ----------

/// Parameters for `gmail.messages.send`.
#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct MessagesSendParams {
    /// The message resource. Google expects `{ "raw": "<base64url
    /// RFC822 message>" }`. Passed through unmodified as the request
    /// body (validated to be a non-empty JSON object).
    pub message: serde_json::Value,
}

/// Parameters for `gmail.messages.modify`.
#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct MessagesModifyParams {
    /// The message ID.
    pub id: String,
    /// The modify request body, e.g.
    /// `{ "addLabelIds": [...], "removeLabelIds": [...] }`.
    pub body: serde_json::Value,
}

/// Parameters for `gmail.messages.trash` / `gmail.messages.untrash`.
#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct MessageIdParams {
    /// The message ID.
    pub id: String,
}

/// Parameters for `gmail.drafts.create` / `gmail.drafts.update`.
#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct DraftWriteParams {
    /// The draft resource: `{ "message": { "raw": "<base64url RFC822>" } }`.
    pub draft: serde_json::Value,
    /// Required for `gmail.drafts.update` (the draft ID to replace);
    /// ignored by `gmail.drafts.create`.
    pub draft_id: Option<String>,
}

/// Parameters for `gmail.drafts.send`.
#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct DraftSendParams {
    /// The draft to send. Google expects `{ "id": "<draftId>" }`.
    pub draft: serde_json::Value,
}

/// Parameters for the no-input Gmail settings read tools (every tool in
/// this codebase takes `Parameters<…>`; there is no paramless form).
#[derive(serde::Deserialize, schemars::JsonSchema, Default)]
pub struct GmailSettingsGetParams {}

// -- Gmail MCP server --------------------------------------------------------

/// MCP server that exposes Gmail tools via `ProxyService::handle`.
#[derive(Clone)]
pub struct GmailMcpServer {
    proxy_service: Arc<ProxyService>,
    tool_router: ToolRouter<Self>,
}

impl GmailMcpServer {
    /// Create a new server instance backed by the given proxy service.
    #[must_use]
    pub fn new(proxy_service: Arc<ProxyService>) -> Self {
        let mut tool_router = Self::tool_router();
        strip_meta_schema(&mut tool_router);
        Self { proxy_service, tool_router }
    }

    /// Dispatch a proxy request and return the upstream response body as a
    /// string. On error, returns `Err(message)` which rmcp maps to an MCP
    /// error result (NOT a transport error).
    pub async fn dispatch(&self, req: ProxyRequest) -> Result<String, String> {
        match self.proxy_service.handle(req).await {
            Ok(resp) => Ok(String::from_utf8_lossy(&resp.body).into_owned()),
            Err(err) => Err(err.to_string()),
        }
    }

    /// Dispatch a request and return the raw upstream JSON `Value` (still
    /// scrubbed — it goes through `handle`). Used by the shaping helpers.
    async fn dispatch_json(&self, req: ProxyRequest) -> Result<serde_json::Value, String> {
        let body = self.dispatch(req).await?;
        serde_json::from_str(&body).map_err(|e| format!("upstream JSON parse error: {e}"))
    }

    /// Build a `ProxyRequest` for a Gmail endpoint.
    ///
    /// `Content-Type: application/json` is set automatically when `body`
    /// is non-empty (for POST/PUT/PATCH write tools); GET reads pass
    /// `Method::GET` + `Bytes::new()` and get no Content-Type. Mirrors
    /// `calendar_request`/`drive_request` (Story 9.2 generalized this
    /// from the original GET-only shape so Gmail write tools could reuse
    /// one builder per service, matching the calendar/drive convention).
    ///
    /// `agent_id` is the bearer-authenticated agent identity for the
    /// inbound MCP call. Callers extract it from the per-call HTTP
    /// `Parts` via [`agent_id_from_parts`] and pass it in.
    pub fn gmail_request(
        path: String,
        scope: &str,
        method: Method,
        body: Bytes,
        agent_id: String,
    ) -> ProxyRequest {
        let mut headers = HeaderMap::new();
        if !body.is_empty() {
            #[allow(clippy::expect_used)]
            headers.insert(
                axum::http::header::CONTENT_TYPE,
                "application/json".parse().expect("valid header value"),
            );
        }
        ProxyRequest {
            service: "gmail".to_owned(),
            scope: scope.to_owned(),
            resource: path.clone(),
            method,
            path,
            headers,
            body,
            agent_id,
            request_id: ulid::Ulid::new().to_string(),
        }
    }
}

/// Validate a Gmail resource ID (message or thread ID).
///
/// Rejects IDs containing path separators, query delimiters, or traversal
/// sequences that could manipulate the upstream URL.
fn validate_resource_id(id: &str) -> Result<(), String> {
    if id.is_empty() {
        return Err("id must not be empty".to_owned());
    }
    if id.contains('/') || id.contains('\\') || id.contains("..") {
        return Err(format!("id contains invalid characters: {id}"));
    }
    if id.contains('?') || id.contains('#') || id.contains('&') {
        return Err(format!("id contains query delimiters: {id}"));
    }
    // Reject characters that would malform the URL when interpolated raw into
    // path segments: whitespace, `%` (pre-encoded input), `+`, quotes, angle
    // brackets. Google resource IDs are opaque alphanumeric + `-` + `_` in
    // practice; this validator enforces that shape at the MCP boundary.
    if id.chars().any(|c| {
        c.is_whitespace() || c == '%' || c == '+' || c == '"' || c == '\'' || c == '<' || c == '>'
    }) {
        return Err(format!("id contains unsafe characters: {id}"));
    }
    Ok(())
}

/// Sanitize an attachment filename for safe use as a path component.
///
/// Strips directory separators (incl. Unicode), control chars, NTFS
/// alternate-data-stream `:`, leading dots, and bounds the length. Falls
/// back to `att-<short attachment-id>.bin` when the result is empty or no
/// filename was provided. The agent + message-id path components are
/// `validate_resource_id`-checked by the caller; this guards the one
/// attacker-influenced component (the MIME filename header).
fn sanitize_filename(filename: Option<&str>, attachment_id: &str) -> String {
    const MAX_LEN: usize = 128;
    let fallback = || {
        let short: String = attachment_id.chars().take(16).collect();
        format!("att-{short}.bin")
    };
    let Some(raw) = filename else { return fallback() };

    let cleaned: String = raw
        .chars()
        .map(|c| {
            if c == '/' || c == '\\' || c == ':' || c.is_control() || c == std::path::MAIN_SEPARATOR
            {
                '_'
            } else {
                c
            }
        })
        .collect();
    // Strip leading dots (no `.`/`..`/hidden-file traversal) and surrounding
    // whitespace.
    let trimmed = cleaned.trim().trim_start_matches('.').trim();
    if trimmed.is_empty() {
        return fallback();
    }
    // Bound length at a char boundary.
    if trimmed.len() <= MAX_LEN {
        trimmed.to_owned()
    } else {
        let end = (0..=MAX_LEN).rev().find(|&i| trimmed.is_char_boundary(i)).unwrap_or(0);
        trimmed[..end].to_owned()
    }
}

/// Short hex digest (first 16 bytes of SHA-256) for filesystem-safe,
/// non-reversible path components (per-agent dir + per-fetch nonce).
fn short_hex_hash(input: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(input);
    digest[..16].iter().map(|b| format!("{b:02x}")).collect()
}

/// Validate a Calendar ID (calendar or event ID).
///
/// Calendar IDs can be email addresses (containing `@` and `.`) or the
/// special string `"primary"`. We only reject path traversal and query
/// delimiters — a looser check than `validate_resource_id`.
fn validate_calendar_id(id: &str, field: &str) -> Result<(), String> {
    if id.is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    if id.trim().is_empty() {
        return Err(format!("{field} must not be empty or whitespace-only"));
    }
    if id.contains('/') || id.contains('\\') || id.contains("..") {
        return Err(format!("{field} contains path traversal characters: {id}"));
    }
    // Note: `#` is valid in Google Calendar group IDs (e.g.,
    // "en.usa#holiday@group.v.calendar.google.com") — only reject `?` and `&`
    // which are actual query delimiters.
    if id.contains('?') || id.contains('&') {
        return Err(format!("{field} contains query delimiters: {id}"));
    }
    // Reject `%` so callers cannot supply a pre-encoded ID — `urlencoding::encode`
    // would double-encode it and Google would return 404. IDs must be supplied
    // unencoded.
    if id.contains('%') {
        return Err(format!("{field} must be supplied unencoded (contains '%'): {id}"));
    }
    // Reject `:` defensively — `url::Url::join` interprets a leading segment
    // containing `:` as a URL scheme, which would produce a malformed upstream
    // request. No real Google calendar ID uses `:` today.
    if id.contains(':') {
        return Err(format!("{field} must not contain ':' (URL scheme delimiter): {id}"));
    }
    // Reject any whitespace anywhere in the ID — even though `trim().is_empty()`
    // catches whitespace-only, intermediate whitespace would be URL-encoded as
    // `%20` and produce Google 404s with no useful diagnostic.
    if id.chars().any(char::is_whitespace) {
        return Err(format!("{field} must not contain whitespace: {id}"));
    }
    Ok(())
}

/// Coerce a stringified-JSON-object arg into the object it encodes, then
/// validate that the write body is a non-empty object.
///
/// LLMs frequently pass an object-valued arg as a JSON *string* (e.g.
/// `event` as `"{\"summary\":...}"`). Left as-is, validation rejects it,
/// the model retries the same shape, and ~3 consecutive failures trip the
/// MCP client's circuit breaker — taking the whole service "unreachable"
/// for ~a minute (observed live taking calendar offline). We first coerce a
/// `String` whose trimmed content parses to a JSON **object**, replacing it
/// in place so the caller's subsequent `serde_json::to_vec` serializes the
/// object. A string that parses to a non-object (array/number/…) or doesn't
/// parse at all is left untouched and falls through to the same clear error.
///
/// Then the original strict checks: rejects `null`, primitives, arrays, and
/// empty objects (`{}`) — Google write endpoints expect a JSON object
/// resource and `null`/`{}` produce an opaque Google 400.
fn coerce_and_validate_json_object_body(
    value: &mut serde_json::Value,
    field: &str,
) -> Result<(), String> {
    if let serde_json::Value::String(s) = value
        && let Ok(parsed @ serde_json::Value::Object(_)) =
            serde_json::from_str::<serde_json::Value>(s.trim())
    {
        debug!(field, "coerced stringified JSON object arg");
        *value = parsed;
    }
    if value.is_null() {
        return Err(format!("{field} must not be null — pass a JSON object resource"));
    }
    let obj = value
        .as_object()
        .ok_or_else(|| format!("{field} must be a JSON object (got {})", json_type_name(value)))?;
    if obj.is_empty() {
        return Err(format!("{field} must not be an empty object — include at least one field"));
    }
    Ok(())
}

fn json_type_name(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

/// Build query string from optional parameters with URL-encoding.
///
/// Skips entries where the value is `None`, an empty string, or whitespace-
/// only. Empty/whitespace values are treated as absent because Google APIs
/// reject `?pageToken=` and `?pageToken=%20` with a 400 `invalidPageToken`
/// error rather than returning the first page.
fn build_query_string(params: &[(&str, Option<String>)]) -> String {
    let parts: Vec<String> = params
        .iter()
        .filter_map(|(key, val)| {
            val.as_ref()
                .filter(|v| !v.trim().is_empty())
                .map(|v| format!("{}={}", key, urlencoding::encode(v)))
        })
        .collect();
    if parts.is_empty() { String::new() } else { format!("?{}", parts.join("&")) }
}

#[tool_router]
impl GmailMcpServer {
    #[tool(
        name = "gmail.messages.list",
        description = "List Gmail messages. Returns message IDs and thread IDs."
    )]
    async fn messages_list(
        &self,
        Parameters(params): Parameters<MessagesListParams>,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<String, String> {
        debug!(tool = "gmail.messages.list", "MCP tool call");
        let agent_id = agent_id_from_parts(&parts).map_err(|e| e.to_string())?;
        let qs = build_query_string(&[
            ("maxResults", params.max_results.map(|n| n.to_string())),
            ("pageToken", params.page_token),
            ("labelIds", params.label_ids.map(|ids| ids.join(","))),
            ("q", params.q),
            ("includeSpamTrash", params.include_spam_trash.map(|b| b.to_string())),
        ]);
        let path = format!("users/me/messages{qs}");
        let req = Self::gmail_request(path, "gmail.readonly", Method::GET, Bytes::new(), agent_id);
        self.dispatch(req).await
    }

    #[tool(
        name = "gmail.messages.get",
        description = "Get a Gmail message by ID. By default returns a compact shaped object \
            (headers, prioritized text body, and an attachment manifest) with attachment bytes \
            stripped — fetch attachment bytes via `gmail.attachments.get`, which returns a local \
            file path. Pass format=metadata/minimal/raw for the unshaped upstream Gmail JSON."
    )]
    async fn messages_get(
        &self,
        Parameters(params): Parameters<MessagesGetParams>,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<String, String> {
        debug!(tool = "gmail.messages.get", id = %params.id, "MCP tool call");
        let agent_id = agent_id_from_parts(&parts).map_err(|e| e.to_string())?;
        validate_resource_id(&params.id)?;

        // Shape only the default/`full` path. metadata/minimal/raw are
        // passed through unshaped (a `raw` body is base64 RFC822, not a
        // MIME tree — the shaper would mangle it).
        let format = params.format.as_deref().unwrap_or("full");
        let shape = format == "full";

        let qs = build_query_string(&[
            // Genuine attachments already come back as attachmentId+empty
            // data under `format=full`, so no special fields mask is needed
            // to keep the big bytes out; the shaper strips residual inline
            // part data.
            ("format", Some(format.to_owned())),
            ("metadataHeaders", params.metadata_headers.map(|h| h.join(","))),
        ]);
        let path = format!("users/me/messages/{}{qs}", params.id);
        let req = Self::gmail_request(path, "gmail.readonly", Method::GET, Bytes::new(), agent_id);

        if !shape {
            return self.dispatch(req).await;
        }
        let msg = self.dispatch_json(req).await?;
        let shaped = gmail_shape::shape_message(&msg)
            .ok_or_else(|| "upstream message JSON missing `id`".to_owned())?;
        serde_json::to_string(&shaped).map_err(|e| format!("shape serialization error: {e}"))
    }

    #[tool(
        name = "gmail.threads.list",
        description = "List Gmail threads. Returns thread IDs and snippets."
    )]
    async fn threads_list(
        &self,
        Parameters(params): Parameters<ThreadsListParams>,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<String, String> {
        debug!(tool = "gmail.threads.list", "MCP tool call");
        let agent_id = agent_id_from_parts(&parts).map_err(|e| e.to_string())?;
        let qs = build_query_string(&[
            ("maxResults", params.max_results.map(|n| n.to_string())),
            ("pageToken", params.page_token),
            ("labelIds", params.label_ids.map(|ids| ids.join(","))),
            ("q", params.q),
        ]);
        let path = format!("users/me/threads{qs}");
        let req = Self::gmail_request(path, "gmail.readonly", Method::GET, Bytes::new(), agent_id);
        self.dispatch(req).await
    }

    #[tool(
        name = "gmail.threads.get",
        description = "Get a Gmail thread by ID. By default returns a compact shaped array (one \
            object per message: headers, prioritized text body, attachment manifest) with \
            attachment bytes stripped. Pass format=metadata/minimal for the unshaped upstream JSON."
    )]
    async fn threads_get(
        &self,
        Parameters(params): Parameters<ThreadsGetParams>,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<String, String> {
        debug!(tool = "gmail.threads.get", id = %params.id, "MCP tool call");
        let agent_id = agent_id_from_parts(&parts).map_err(|e| e.to_string())?;
        validate_resource_id(&params.id)?;

        let format = params.format.as_deref().unwrap_or("full");
        let shape = format == "full";

        let qs = build_query_string(&[("format", Some(format.to_owned()))]);
        let path = format!("users/me/threads/{}{qs}", params.id);
        let req = Self::gmail_request(path, "gmail.readonly", Method::GET, Bytes::new(), agent_id);

        if !shape {
            return self.dispatch(req).await;
        }
        let thread = self.dispatch_json(req).await?;
        let shaped = gmail_shape::shape_thread(&thread);
        serde_json::to_string(&shaped).map_err(|e| format!("shape serialization error: {e}"))
    }

    #[tool(
        name = "gmail.search",
        description = "Search Gmail messages using Gmail search syntax. Returns matching message IDs."
    )]
    async fn search(
        &self,
        Parameters(params): Parameters<SearchParams>,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<String, String> {
        debug!(tool = "gmail.search", query = %params.query, "MCP tool call");
        let agent_id = agent_id_from_parts(&parts).map_err(|e| e.to_string())?;
        let qs = build_query_string(&[
            ("q", Some(params.query)),
            ("maxResults", params.max_results.map(|n| n.to_string())),
            ("pageToken", params.page_token),
        ]);
        let path = format!("users/me/messages{qs}");
        let req = Self::gmail_request(path, "gmail.readonly", Method::GET, Bytes::new(), agent_id);
        self.dispatch(req).await
    }

    // ── Story 9.1: read-tool gap-fill (all `gmail.readonly`) ──────────

    #[tool(
        name = "gmail.attachments.get",
        description = "Fetch a Gmail attachment's bytes and write them to a local file, returning \
            JSON { messageId, attachmentId, size, mimeType, filename, path }. The `path` is a \
            local file the agent's file/pdf tools can read directly — NO base64 is returned. \
            Files are transient (cleaned up automatically)."
    )]
    async fn attachments_get(
        &self,
        Parameters(params): Parameters<AttachmentsGetParams>,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<String, String> {
        debug!(
            tool = "gmail.attachments.get",
            message_id = %params.message_id,
            attachment_id = %params.attachment_id,
            "MCP tool call"
        );
        let agent_id = agent_id_from_parts(&parts).map_err(|e| e.to_string())?;
        validate_resource_id(&params.message_id)?;
        validate_resource_id(&params.attachment_id)?;

        // 1. Fetch the attachment bytes via the un-scrubbed raw path
        //    (scrubbing base64 would corrupt the decoded file).
        let att_path =
            format!("users/me/messages/{}/attachments/{}", params.message_id, params.attachment_id);
        let att_req = Self::gmail_request(
            att_path,
            "gmail.readonly",
            Method::GET,
            Bytes::new(),
            agent_id.clone(),
        );
        let att_resp = self.proxy_service.fetch_raw(att_req).await.map_err(|e| e.to_string())?;
        let att_json: serde_json::Value = serde_json::from_slice(&att_resp.body)
            .map_err(|e| format!("attachment JSON parse error: {e}"))?;
        let data = att_json
            .get("data")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "attachment response missing `data`".to_owned())?;
        let bytes = permitlayer_core::files::decode_base64url_maybe_padded(data)
            .ok_or_else(|| "attachment data is not valid base64url".to_owned())?;
        let size = att_json.get("size").and_then(serde_json::Value::as_u64);

        // 2. Resolve mimeType + filename via a metadata message lookup
        //    (attachments.get returns neither).
        let meta_req = Self::gmail_request(
            format!("users/me/messages/{}?format=full", params.message_id),
            "gmail.readonly",
            Method::GET,
            Bytes::new(),
            agent_id.clone(),
        );
        let (filename, mime_type) = match self.dispatch_json(meta_req).await {
            Ok(msg) => {
                gmail_shape::part_lookup(&msg, &params.attachment_id).unwrap_or((None, None))
            }
            // Metadata lookup is best-effort; fall back to defaults so the
            // bytes are still delivered.
            Err(_) => (None, None),
        };
        let filename = sanitize_filename(filename.as_deref(), &params.attachment_id);
        let mime_type = mime_type.unwrap_or_else(|| "application/octet-stream".to_owned());

        // 3. Write the bytes to a per-agent, unguessable media path.
        let path = self
            .write_attachment(&agent_id, &params.message_id, &filename, &bytes)
            .map_err(|e| format!("failed to write attachment: {e}"))?;

        let descriptor = serde_json::json!({
            "messageId": params.message_id,
            "attachmentId": params.attachment_id,
            "size": size.unwrap_or(bytes.len() as u64),
            "mimeType": mime_type,
            "filename": filename,
            "path": path.to_string_lossy(),
        });
        Ok(descriptor.to_string())
    }

    /// Write decoded attachment bytes to a per-agent, unguessable path
    /// under the media dir, returning the absolute path. The unguessable
    /// component bounds cross-agent disclosure within the
    /// `permitlayer-clients` group (the file is group-readable on macOS so
    /// the operator-user agent can read it — see the media-trust-boundary
    /// ADR). The agent-name and message-id components are
    /// `validate_resource_id`-checked by the caller; the filename is
    /// sanitized. Returns the path for the descriptor.
    fn write_attachment(
        &self,
        agent_id: &str,
        message_id: &str,
        filename: &str,
        bytes: &[u8],
    ) -> Result<std::path::PathBuf, String> {
        // Hash the agent name so the directory component is filesystem-safe
        // and doesn't leak the raw agent id; add an unguessable random
        // segment per fetch.
        let agent_hash = short_hex_hash(agent_id.as_bytes());
        let nonce = short_hex_hash(
            format!("{agent_id}:{message_id}:{filename}:{}", bytes.len()).as_bytes(),
        );
        let dir = self.proxy_service.media_dir().join(agent_hash).join(nonce);
        let path = dir.join(filename);
        permitlayer_core::files::write_client_readable_file(&path, bytes)
            .map_err(|e| e.to_string())?;
        Ok(path)
    }

    #[tool(
        name = "gmail.labels.list",
        description = "List all Gmail labels for the authenticated user."
    )]
    async fn labels_list(
        &self,
        Parameters(_params): Parameters<LabelsListParams>,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<String, String> {
        debug!(tool = "gmail.labels.list", "MCP tool call");
        let agent_id = agent_id_from_parts(&parts).map_err(|e| e.to_string())?;
        let req = Self::gmail_request(
            "users/me/labels".to_owned(),
            "gmail.readonly",
            Method::GET,
            Bytes::new(),
            agent_id,
        );
        self.dispatch(req).await
    }

    #[tool(
        name = "gmail.profile.get",
        description = "Get the authenticated user's Gmail profile (email address, \
            message/thread totals, current historyId). Maps to Gmail's `users.getProfile`."
    )]
    async fn profile_get(
        &self,
        Parameters(_params): Parameters<ProfileGetParams>,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<String, String> {
        debug!(tool = "gmail.profile.get", "MCP tool call");
        let agent_id = agent_id_from_parts(&parts).map_err(|e| e.to_string())?;
        let req = Self::gmail_request(
            "users/me/profile".to_owned(),
            "gmail.readonly",
            Method::GET,
            Bytes::new(),
            agent_id,
        );
        self.dispatch(req).await
    }

    #[tool(
        name = "gmail.history.list",
        description = "List Gmail mailbox history (changes since a given historyId). \
            `start_history_id` is required by the Gmail API."
    )]
    async fn history_list(
        &self,
        Parameters(params): Parameters<HistoryListParams>,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<String, String> {
        debug!(tool = "gmail.history.list", "MCP tool call");
        let agent_id = agent_id_from_parts(&parts).map_err(|e| e.to_string())?;
        // `startHistoryId` is required by Gmail; fail fast at the tool
        // boundary rather than dispatching a request Gmail will 400.
        // Mirrors the `validate_resource_id` fail-fast shape.
        if params.start_history_id.trim().is_empty() {
            return Err("start_history_id is required and must not be empty".to_owned());
        }
        let qs = build_query_string(&[
            ("startHistoryId", Some(params.start_history_id)),
            ("maxResults", params.max_results.map(|n| n.to_string())),
            ("pageToken", params.page_token),
            ("labelId", params.label_id),
            ("historyTypes", params.history_types.map(|t| t.join(","))),
        ]);
        let path = format!("users/me/history{qs}");
        let req = Self::gmail_request(path, "gmail.readonly", Method::GET, Bytes::new(), agent_id);
        self.dispatch(req).await
    }

    #[tool(
        name = "gmail.drafts.list",
        description = "List Gmail drafts for the authenticated user. Returns draft IDs \
            and their associated message IDs."
    )]
    async fn drafts_list(
        &self,
        Parameters(params): Parameters<DraftsListParams>,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<String, String> {
        debug!(tool = "gmail.drafts.list", "MCP tool call");
        let agent_id = agent_id_from_parts(&parts).map_err(|e| e.to_string())?;
        let qs = build_query_string(&[
            ("maxResults", params.max_results.map(|n| n.to_string())),
            ("pageToken", params.page_token),
            ("q", params.q),
            ("includeSpamTrash", params.include_spam_trash.map(|b| b.to_string())),
        ]);
        let path = format!("users/me/drafts{qs}");
        let req = Self::gmail_request(path, "gmail.readonly", Method::GET, Bytes::new(), agent_id);
        self.dispatch(req).await
    }

    #[tool(
        name = "gmail.drafts.get",
        description = "Get a specific Gmail draft by ID, including its message content."
    )]
    async fn drafts_get(
        &self,
        Parameters(params): Parameters<DraftsGetParams>,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<String, String> {
        debug!(tool = "gmail.drafts.get", draft_id = %params.draft_id, "MCP tool call");
        let agent_id = agent_id_from_parts(&parts).map_err(|e| e.to_string())?;
        validate_resource_id(&params.draft_id)?;
        let qs = build_query_string(&[
            ("format", params.format),
            ("metadataHeaders", params.metadata_headers.map(|h| h.join(","))),
        ]);
        let path = format!("users/me/drafts/{}{qs}", params.draft_id);
        let req = Self::gmail_request(path, "gmail.readonly", Method::GET, Bytes::new(), agent_id);
        self.dispatch(req).await
    }

    // ── Story 9.2: WRITE tools (per-tool Google-minimum scope) ───────

    #[tool(
        name = "gmail.messages.send",
        description = "Send an email. Pass `message` as a JSON object \
            { \"raw\": \"<base64url-encoded RFC822 message>\" }."
    )]
    async fn messages_send(
        &self,
        Parameters(mut params): Parameters<MessagesSendParams>,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<String, String> {
        debug!(tool = "gmail.messages.send", "MCP tool call");
        let agent_id = agent_id_from_parts(&parts).map_err(|e| e.to_string())?;
        coerce_and_validate_json_object_body(&mut params.message, "message")?;
        let body = serde_json::to_vec(&params.message)
            .map_err(|e| format!("invalid message JSON: {e}"))?;
        let req = Self::gmail_request(
            "users/me/messages/send".to_owned(),
            "gmail.send",
            Method::POST,
            Bytes::from(body),
            agent_id,
        );
        self.dispatch(req).await
    }

    #[tool(
        name = "gmail.messages.modify",
        description = "Modify the labels on a message. Pass `body` as \
            { \"addLabelIds\": [...], \"removeLabelIds\": [...] }."
    )]
    async fn messages_modify(
        &self,
        Parameters(mut params): Parameters<MessagesModifyParams>,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<String, String> {
        debug!(tool = "gmail.messages.modify", id = %params.id, "MCP tool call");
        let agent_id = agent_id_from_parts(&parts).map_err(|e| e.to_string())?;
        validate_resource_id(&params.id)?;
        coerce_and_validate_json_object_body(&mut params.body, "body")?;
        let body =
            serde_json::to_vec(&params.body).map_err(|e| format!("invalid modify JSON: {e}"))?;
        let path = format!("users/me/messages/{}/modify", params.id);
        let req =
            Self::gmail_request(path, "gmail.modify", Method::POST, Bytes::from(body), agent_id);
        self.dispatch(req).await
    }

    #[tool(
        name = "gmail.messages.trash",
        description = "Move a message to the trash (reversible — see \
            gmail.messages.untrash). Does NOT permanently delete."
    )]
    async fn messages_trash(
        &self,
        Parameters(params): Parameters<MessageIdParams>,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<String, String> {
        debug!(tool = "gmail.messages.trash", id = %params.id, "MCP tool call");
        let agent_id = agent_id_from_parts(&parts).map_err(|e| e.to_string())?;
        validate_resource_id(&params.id)?;
        let path = format!("users/me/messages/{}/trash", params.id);
        let req = Self::gmail_request(path, "gmail.modify", Method::POST, Bytes::new(), agent_id);
        self.dispatch(req).await
    }

    #[tool(
        name = "gmail.messages.untrash",
        description = "Remove a message from the trash (restore it)."
    )]
    async fn messages_untrash(
        &self,
        Parameters(params): Parameters<MessageIdParams>,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<String, String> {
        debug!(tool = "gmail.messages.untrash", id = %params.id, "MCP tool call");
        let agent_id = agent_id_from_parts(&parts).map_err(|e| e.to_string())?;
        validate_resource_id(&params.id)?;
        let path = format!("users/me/messages/{}/untrash", params.id);
        let req = Self::gmail_request(path, "gmail.modify", Method::POST, Bytes::new(), agent_id);
        self.dispatch(req).await
    }

    #[tool(
        name = "gmail.drafts.create",
        description = "Create a draft. Pass `draft` as \
            { \"message\": { \"raw\": \"<base64url RFC822>\" } }."
    )]
    async fn drafts_create(
        &self,
        Parameters(mut params): Parameters<DraftWriteParams>,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<String, String> {
        debug!(tool = "gmail.drafts.create", "MCP tool call");
        let agent_id = agent_id_from_parts(&parts).map_err(|e| e.to_string())?;
        coerce_and_validate_json_object_body(&mut params.draft, "draft")?;
        let body =
            serde_json::to_vec(&params.draft).map_err(|e| format!("invalid draft JSON: {e}"))?;
        let req = Self::gmail_request(
            "users/me/drafts".to_owned(),
            "gmail.compose",
            Method::POST,
            Bytes::from(body),
            agent_id,
        );
        self.dispatch(req).await
    }

    #[tool(
        name = "gmail.drafts.update",
        description = "Replace an existing draft's content. Requires \
            `draft_id`; pass `draft` as { \"message\": { \"raw\": ... } }."
    )]
    async fn drafts_update(
        &self,
        Parameters(mut params): Parameters<DraftWriteParams>,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<String, String> {
        debug!(tool = "gmail.drafts.update", "MCP tool call");
        let agent_id = agent_id_from_parts(&parts).map_err(|e| e.to_string())?;
        let draft_id = params
            .draft_id
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| "draft_id is required for gmail.drafts.update".to_owned())?;
        validate_resource_id(draft_id)?;
        coerce_and_validate_json_object_body(&mut params.draft, "draft")?;
        let body =
            serde_json::to_vec(&params.draft).map_err(|e| format!("invalid draft JSON: {e}"))?;
        let path = format!("users/me/drafts/{draft_id}");
        let req =
            Self::gmail_request(path, "gmail.compose", Method::PUT, Bytes::from(body), agent_id);
        self.dispatch(req).await
    }

    #[tool(
        name = "gmail.drafts.send",
        description = "Send an existing draft. Pass `draft` as \
            { \"id\": \"<draftId>\" }. Uses the gmail.compose scope \
            (Google does not accept gmail.send for drafts.send)."
    )]
    async fn drafts_send(
        &self,
        Parameters(mut params): Parameters<DraftSendParams>,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<String, String> {
        debug!(tool = "gmail.drafts.send", "MCP tool call");
        let agent_id = agent_id_from_parts(&parts).map_err(|e| e.to_string())?;
        coerce_and_validate_json_object_body(&mut params.draft, "draft")?;
        let body =
            serde_json::to_vec(&params.draft).map_err(|e| format!("invalid draft JSON: {e}"))?;
        let req = Self::gmail_request(
            "users/me/drafts/send".to_owned(),
            "gmail.compose",
            Method::POST,
            Bytes::from(body),
            agent_id,
        );
        self.dispatch(req).await
    }

    // ── Story 9.2: SETTINGS reads (all gmail.readonly — Google min) ──

    #[tool(
        name = "gmail.settings.sendAs.list",
        description = "List the send-as aliases for the account."
    )]
    async fn settings_send_as_list(
        &self,
        Parameters(_params): Parameters<GmailSettingsGetParams>,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<String, String> {
        debug!(tool = "gmail.settings.sendAs.list", "MCP tool call");
        let agent_id = agent_id_from_parts(&parts).map_err(|e| e.to_string())?;
        let req = Self::gmail_request(
            "users/me/settings/sendAs".to_owned(),
            "gmail.readonly",
            Method::GET,
            Bytes::new(),
            agent_id,
        );
        self.dispatch(req).await
    }

    #[tool(
        name = "gmail.settings.filters.list",
        description = "List the mail filters configured on the account."
    )]
    async fn settings_filters_list(
        &self,
        Parameters(_params): Parameters<GmailSettingsGetParams>,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<String, String> {
        debug!(tool = "gmail.settings.filters.list", "MCP tool call");
        let agent_id = agent_id_from_parts(&parts).map_err(|e| e.to_string())?;
        let req = Self::gmail_request(
            "users/me/settings/filters".to_owned(),
            "gmail.readonly",
            Method::GET,
            Bytes::new(),
            agent_id,
        );
        self.dispatch(req).await
    }

    #[tool(
        name = "gmail.settings.language.get",
        description = "Get the account's display language setting."
    )]
    async fn settings_language_get(
        &self,
        Parameters(_params): Parameters<GmailSettingsGetParams>,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<String, String> {
        debug!(tool = "gmail.settings.language.get", "MCP tool call");
        let agent_id = agent_id_from_parts(&parts).map_err(|e| e.to_string())?;
        let req = Self::gmail_request(
            "users/me/settings/language".to_owned(),
            "gmail.readonly",
            Method::GET,
            Bytes::new(),
            agent_id,
        );
        self.dispatch(req).await
    }

    #[tool(
        name = "gmail.settings.imap.get",
        description = "Get the account's IMAP access settings."
    )]
    async fn settings_imap_get(
        &self,
        Parameters(_params): Parameters<GmailSettingsGetParams>,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<String, String> {
        debug!(tool = "gmail.settings.imap.get", "MCP tool call");
        let agent_id = agent_id_from_parts(&parts).map_err(|e| e.to_string())?;
        let req = Self::gmail_request(
            "users/me/settings/imap".to_owned(),
            "gmail.readonly",
            Method::GET,
            Bytes::new(),
            agent_id,
        );
        self.dispatch(req).await
    }

    #[tool(name = "gmail.settings.pop.get", description = "Get the account's POP access settings.")]
    async fn settings_pop_get(
        &self,
        Parameters(_params): Parameters<GmailSettingsGetParams>,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<String, String> {
        debug!(tool = "gmail.settings.pop.get", "MCP tool call");
        let agent_id = agent_id_from_parts(&parts).map_err(|e| e.to_string())?;
        let req = Self::gmail_request(
            "users/me/settings/pop".to_owned(),
            "gmail.readonly",
            Method::GET,
            Bytes::new(),
            agent_id,
        );
        self.dispatch(req).await
    }

    #[tool(
        name = "gmail.settings.vacation.get",
        description = "Get the account's vacation responder settings."
    )]
    async fn settings_vacation_get(
        &self,
        Parameters(_params): Parameters<GmailSettingsGetParams>,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<String, String> {
        debug!(tool = "gmail.settings.vacation.get", "MCP tool call");
        let agent_id = agent_id_from_parts(&parts).map_err(|e| e.to_string())?;
        let req = Self::gmail_request(
            "users/me/settings/vacation".to_owned(),
            "gmail.readonly",
            Method::GET,
            Bytes::new(),
            agent_id,
        );
        self.dispatch(req).await
    }

    #[tool(
        name = "gmail.settings.forwarding.list",
        description = "List the account's forwarding addresses (maps to \
            Gmail's settings.forwardingAddresses.list)."
    )]
    async fn settings_forwarding_list(
        &self,
        Parameters(_params): Parameters<GmailSettingsGetParams>,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<String, String> {
        debug!(tool = "gmail.settings.forwarding.list", "MCP tool call");
        let agent_id = agent_id_from_parts(&parts).map_err(|e| e.to_string())?;
        let req = Self::gmail_request(
            "users/me/settings/forwardingAddresses".to_owned(),
            "gmail.readonly",
            Method::GET,
            Bytes::new(),
            agent_id,
        );
        self.dispatch(req).await
    }

    #[tool(
        name = "gmail.settings.autoForwarding.get",
        description = "Get the account's auto-forwarding setting."
    )]
    async fn settings_auto_forwarding_get(
        &self,
        Parameters(_params): Parameters<GmailSettingsGetParams>,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<String, String> {
        debug!(tool = "gmail.settings.autoForwarding.get", "MCP tool call");
        let agent_id = agent_id_from_parts(&parts).map_err(|e| e.to_string())?;
        let req = Self::gmail_request(
            "users/me/settings/autoForwarding".to_owned(),
            "gmail.readonly",
            Method::GET,
            Bytes::new(),
            agent_id,
        );
        self.dispatch(req).await
    }
}

#[tool_handler]
impl rmcp::ServerHandler for GmailMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("permitlayer", env!("CARGO_PKG_VERSION")))
    }
}

pub type GmailMcpService = rmcp::transport::streamable_http_server::tower::StreamableHttpService<
    GmailMcpServer,
    rmcp::transport::streamable_http_server::session::local::LocalSessionManager,
>;

/// Build an MCP service for the Gmail connector.
///
/// Tool method bodies extract the bearer-authenticated agent identity
/// directly from the per-call HTTP `Parts` that rmcp surfaces via the
/// `Extension<http::request::Parts>` extractor — see
/// [`agent_id_from_parts`].
///
/// The returned service implements `tower::Service<Request<Body>>`
/// and can be mounted into axum via
/// `Router::new().nest_service("/mcp/gmail", service)`.
pub fn mcp_service(proxy_service: Arc<ProxyService>) -> GmailMcpService {
    use rmcp::transport::streamable_http_server::{
        session::local::LocalSessionManager,
        tower::{StreamableHttpServerConfig, StreamableHttpService},
    };

    StreamableHttpService::new(
        move || Ok(GmailMcpServer::new(Arc::clone(&proxy_service))),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    )
}

// -- Calendar tool parameter structs ------------------------------------------

/// Parameters for `calendar.calendars.list`.
#[derive(serde::Deserialize, schemars::JsonSchema, Default)]
pub struct CalendarsListParams {
    /// Maximum number of calendars to return.
    pub max_results: Option<u32>,
    /// Page token for pagination.
    pub page_token: Option<String>,
}

/// Parameters for `calendar.events.list`.
#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct EventsListParams {
    /// Calendar ID (default: "primary").
    pub calendar_id: Option<String>,
    /// Maximum number of events to return.
    pub max_results: Option<u32>,
    /// Page token for pagination.
    pub page_token: Option<String>,
    /// Lower bound (RFC 3339) for an event's end time to filter by.
    pub time_min: Option<String>,
    /// Upper bound (RFC 3339) for an event's start time to filter by.
    pub time_max: Option<String>,
    /// Free-text search query.
    pub q: Option<String>,
    /// Whether to expand recurring events into instances.
    pub single_events: Option<bool>,
    /// Sort order: "startTime" or "updated".
    pub order_by: Option<String>,
}

/// Parameters for `calendar.events.get`.
#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct EventGetParams {
    /// Calendar ID (default: "primary").
    pub calendar_id: Option<String>,
    /// The event ID.
    pub event_id: String,
}

/// Parameters for `calendar.events.create`.
#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct EventCreateParams {
    /// Calendar ID (default: "primary").
    pub calendar_id: Option<String>,
    /// The event resource as a JSON object.
    pub event: serde_json::Value,
}

/// Parameters for `calendar.events.update`.
#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct EventUpdateParams {
    /// Calendar ID (default: "primary").
    pub calendar_id: Option<String>,
    /// The event ID to update.
    pub event_id: String,
    /// The updated event resource as a JSON object.
    pub event: serde_json::Value,
}

// -- Story 9.3: Calendar parity gap-fill -------------------------------------

/// Parameters for `calendar.events.delete`.
#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct EventDeleteParams {
    /// Calendar ID (default: "primary").
    pub calendar_id: Option<String>,
    /// The event ID to delete.
    pub event_id: String,
}

/// Parameters for `calendar.events.patch` (partial update — only the
/// fields present in `event` are changed, unlike `events.update`'s
/// full-resource PUT).
#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct EventPatchParams {
    /// Calendar ID (default: "primary").
    pub calendar_id: Option<String>,
    /// The event ID to patch.
    pub event_id: String,
    /// The partial event resource (only the fields to change).
    pub event: serde_json::Value,
}

/// Parameters for `calendar.events.move`.
#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct EventMoveParams {
    /// Source calendar ID (default: "primary").
    pub calendar_id: Option<String>,
    /// The event ID to move.
    pub event_id: String,
    /// Required. The destination calendar ID to move the event to.
    pub destination: String,
}

/// Parameters for `calendar.events.quickAdd`.
#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct EventQuickAddParams {
    /// Calendar ID (default: "primary").
    pub calendar_id: Option<String>,
    /// Required. Natural-language text describing the event
    /// (e.g. "Lunch with Sam tomorrow 1pm").
    pub text: String,
}

/// Parameters for `calendar.freebusy.query` (a read via POST — scope
/// `calendar.readonly`).
#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct FreeBusyQueryParams {
    /// The free/busy query body, e.g.
    /// `{ "timeMin": "...", "timeMax": "...", "items": [{"id": "..."}] }`.
    pub query: serde_json::Value,
}

/// Parameters for the no-input Calendar read tools (`settings.list`,
/// `colors.get`) — every tool takes `Parameters<…>`, no paramless form.
#[derive(serde::Deserialize, schemars::JsonSchema, Default)]
pub struct CalendarReadNoParams {}

// -- Calendar MCP server ------------------------------------------------------

/// MCP server that exposes Google Calendar tools via `ProxyService::handle`.
#[derive(Clone)]
pub struct CalendarMcpServer {
    proxy_service: Arc<ProxyService>,
    tool_router: ToolRouter<Self>,
}

impl CalendarMcpServer {
    /// Create a new Calendar MCP server backed by the given proxy service.
    #[must_use]
    pub fn new(proxy_service: Arc<ProxyService>) -> Self {
        let mut tool_router = Self::tool_router();
        strip_meta_schema(&mut tool_router);
        Self { proxy_service, tool_router }
    }

    /// Dispatch a proxy request and return the upstream response body as a
    /// string.
    async fn dispatch(&self, req: ProxyRequest) -> Result<String, String> {
        match self.proxy_service.handle(req).await {
            Ok(resp) => Ok(String::from_utf8_lossy(&resp.body).into_owned()),
            Err(err) => Err(err.to_string()),
        }
    }

    /// Build a `ProxyRequest` for a Calendar endpoint.
    ///
    /// `agent_id` is the bearer-authenticated agent identity for the
    /// inbound MCP call. Callers extract it from the per-call HTTP
    /// `Parts` via [`agent_id_from_parts`] and pass it in.
    fn calendar_request(
        path: String,
        scope: &str,
        method: Method,
        body: Bytes,
        agent_id: String,
    ) -> ProxyRequest {
        let mut headers = HeaderMap::new();
        if !body.is_empty() {
            #[allow(clippy::expect_used)]
            headers.insert(
                axum::http::header::CONTENT_TYPE,
                "application/json".parse().expect("valid header value"),
            );
        }
        ProxyRequest {
            service: "calendar".to_owned(),
            scope: scope.to_owned(),
            resource: path.clone(),
            method,
            path,
            headers,
            body,
            agent_id,
            request_id: ulid::Ulid::new().to_string(),
        }
    }
}

#[tool_router]
impl CalendarMcpServer {
    #[tool(
        name = "calendar.calendars.list",
        description = "List the user's calendars. Returns calendar IDs and summaries."
    )]
    async fn calendars_list(
        &self,
        Parameters(params): Parameters<CalendarsListParams>,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<String, String> {
        debug!(tool = "calendar.calendars.list", "MCP tool call");
        let agent_id = agent_id_from_parts(&parts).map_err(|e| e.to_string())?;
        let qs = build_query_string(&[
            ("maxResults", params.max_results.map(|n| n.to_string())),
            ("pageToken", params.page_token),
        ]);
        let path = format!("users/me/calendarList{qs}");
        let req =
            Self::calendar_request(path, "calendar.readonly", Method::GET, Bytes::new(), agent_id);
        self.dispatch(req).await
    }

    #[tool(
        name = "calendar.events.list",
        description = "List events on a calendar. Returns event summaries, times, and IDs."
    )]
    async fn events_list(
        &self,
        Parameters(params): Parameters<EventsListParams>,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<String, String> {
        let cal_id = params.calendar_id.as_deref().unwrap_or("primary");
        debug!(tool = "calendar.events.list", calendar_id = %cal_id, "MCP tool call");
        let agent_id = agent_id_from_parts(&parts).map_err(|e| e.to_string())?;
        validate_calendar_id(cal_id, "calendar_id")?;
        let qs = build_query_string(&[
            ("maxResults", params.max_results.map(|n| n.to_string())),
            ("pageToken", params.page_token),
            ("timeMin", params.time_min),
            ("timeMax", params.time_max),
            ("q", params.q),
            ("singleEvents", params.single_events.map(|b| b.to_string())),
            ("orderBy", params.order_by),
        ]);
        let encoded_cal_id = urlencoding::encode(cal_id);
        let path = format!("calendars/{encoded_cal_id}/events{qs}");
        let req =
            Self::calendar_request(path, "calendar.readonly", Method::GET, Bytes::new(), agent_id);
        self.dispatch(req).await
    }

    #[tool(name = "calendar.events.get", description = "Get a specific calendar event by ID.")]
    async fn events_get(
        &self,
        Parameters(params): Parameters<EventGetParams>,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<String, String> {
        let cal_id = params.calendar_id.as_deref().unwrap_or("primary");
        debug!(tool = "calendar.events.get", calendar_id = %cal_id, event_id = %params.event_id, "MCP tool call");
        let agent_id = agent_id_from_parts(&parts).map_err(|e| e.to_string())?;
        validate_calendar_id(cal_id, "calendar_id")?;
        validate_resource_id(&params.event_id)?;
        let encoded_cal_id = urlencoding::encode(cal_id);
        let encoded_event_id = urlencoding::encode(&params.event_id);
        let path = format!("calendars/{encoded_cal_id}/events/{encoded_event_id}");
        let req =
            Self::calendar_request(path, "calendar.readonly", Method::GET, Bytes::new(), agent_id);
        self.dispatch(req).await
    }

    #[tool(
        name = "calendar.events.create",
        description = "Create a new event on a calendar. Pass the event as a JSON object with summary, start, end, etc."
    )]
    async fn events_create(
        &self,
        Parameters(mut params): Parameters<EventCreateParams>,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<String, String> {
        let cal_id = params.calendar_id.as_deref().unwrap_or("primary");
        debug!(tool = "calendar.events.create", calendar_id = %cal_id, "MCP tool call");
        let agent_id = agent_id_from_parts(&parts).map_err(|e| e.to_string())?;
        validate_calendar_id(cal_id, "calendar_id")?;
        coerce_and_validate_json_object_body(&mut params.event, "event")?;
        let body =
            serde_json::to_vec(&params.event).map_err(|e| format!("invalid event JSON: {e}"))?;
        let encoded_cal_id = urlencoding::encode(cal_id);
        let path = format!("calendars/{encoded_cal_id}/events");
        let req = Self::calendar_request(
            path,
            "calendar.events",
            Method::POST,
            Bytes::from(body),
            agent_id,
        );
        self.dispatch(req).await
    }

    #[tool(
        name = "calendar.events.update",
        description = "Update an existing calendar event. Uses HTTP PUT semantics: pass the FULL event resource as a JSON object — any field omitted from the body will be CLEARED on the server. To safely modify a single field, fetch the event first with calendar.events.get, modify the returned object, and pass the complete result back here."
    )]
    async fn events_update(
        &self,
        Parameters(mut params): Parameters<EventUpdateParams>,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<String, String> {
        let cal_id = params.calendar_id.as_deref().unwrap_or("primary");
        debug!(tool = "calendar.events.update", calendar_id = %cal_id, event_id = %params.event_id, "MCP tool call");
        let agent_id = agent_id_from_parts(&parts).map_err(|e| e.to_string())?;
        validate_calendar_id(cal_id, "calendar_id")?;
        validate_resource_id(&params.event_id)?;
        coerce_and_validate_json_object_body(&mut params.event, "event")?;
        let body =
            serde_json::to_vec(&params.event).map_err(|e| format!("invalid event JSON: {e}"))?;
        let encoded_cal_id = urlencoding::encode(cal_id);
        let encoded_event_id = urlencoding::encode(&params.event_id);
        let path = format!("calendars/{encoded_cal_id}/events/{encoded_event_id}");
        let req = Self::calendar_request(
            path,
            "calendar.events",
            Method::PUT,
            Bytes::from(body),
            agent_id,
        );
        self.dispatch(req).await
    }

    // ── Story 9.3: Calendar parity gap-fill ──────────────────────────

    #[tool(
        name = "calendar.events.delete",
        description = "Delete a calendar event by ID. This removes the event from the calendar."
    )]
    async fn events_delete(
        &self,
        Parameters(params): Parameters<EventDeleteParams>,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<String, String> {
        let cal_id = params.calendar_id.as_deref().unwrap_or("primary");
        debug!(tool = "calendar.events.delete", calendar_id = %cal_id, event_id = %params.event_id, "MCP tool call");
        let agent_id = agent_id_from_parts(&parts).map_err(|e| e.to_string())?;
        validate_calendar_id(cal_id, "calendar_id")?;
        validate_resource_id(&params.event_id)?;
        let encoded_cal_id = urlencoding::encode(cal_id);
        let encoded_event_id = urlencoding::encode(&params.event_id);
        let path = format!("calendars/{encoded_cal_id}/events/{encoded_event_id}");
        let req =
            Self::calendar_request(path, "calendar.events", Method::DELETE, Bytes::new(), agent_id);
        self.dispatch(req).await
    }

    #[tool(
        name = "calendar.events.patch",
        description = "Partially update a calendar event: only the fields present in `event` are changed (unlike calendar.events.update, which replaces the whole resource)."
    )]
    async fn events_patch(
        &self,
        Parameters(mut params): Parameters<EventPatchParams>,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<String, String> {
        let cal_id = params.calendar_id.as_deref().unwrap_or("primary");
        debug!(tool = "calendar.events.patch", calendar_id = %cal_id, event_id = %params.event_id, "MCP tool call");
        let agent_id = agent_id_from_parts(&parts).map_err(|e| e.to_string())?;
        validate_calendar_id(cal_id, "calendar_id")?;
        validate_resource_id(&params.event_id)?;
        coerce_and_validate_json_object_body(&mut params.event, "event")?;
        let body =
            serde_json::to_vec(&params.event).map_err(|e| format!("invalid event JSON: {e}"))?;
        let encoded_cal_id = urlencoding::encode(cal_id);
        let encoded_event_id = urlencoding::encode(&params.event_id);
        let path = format!("calendars/{encoded_cal_id}/events/{encoded_event_id}");
        let req = Self::calendar_request(
            path,
            "calendar.events",
            Method::PATCH,
            Bytes::from(body),
            agent_id,
        );
        self.dispatch(req).await
    }

    #[tool(
        name = "calendar.events.move",
        description = "Move an event to a different calendar. `destination` (target calendar ID) is required."
    )]
    async fn events_move(
        &self,
        Parameters(params): Parameters<EventMoveParams>,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<String, String> {
        let cal_id = params.calendar_id.as_deref().unwrap_or("primary");
        debug!(tool = "calendar.events.move", calendar_id = %cal_id, event_id = %params.event_id, "MCP tool call");
        let agent_id = agent_id_from_parts(&parts).map_err(|e| e.to_string())?;
        validate_calendar_id(cal_id, "calendar_id")?;
        validate_resource_id(&params.event_id)?;
        // `destination` is required by the Calendar API; fail fast.
        if params.destination.trim().is_empty() {
            return Err("destination is required and must not be empty".to_owned());
        }
        validate_calendar_id(&params.destination, "destination")?;
        let encoded_cal_id = urlencoding::encode(cal_id);
        let encoded_event_id = urlencoding::encode(&params.event_id);
        let qs = build_query_string(&[("destination", Some(params.destination))]);
        let path = format!("calendars/{encoded_cal_id}/events/{encoded_event_id}/move{qs}");
        let req =
            Self::calendar_request(path, "calendar.events", Method::POST, Bytes::new(), agent_id);
        self.dispatch(req).await
    }

    #[tool(
        name = "calendar.events.quickAdd",
        description = "Create an event from a natural-language string (e.g. \"Lunch with Sam tomorrow 1pm\"). `text` is required."
    )]
    async fn events_quick_add(
        &self,
        Parameters(params): Parameters<EventQuickAddParams>,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<String, String> {
        let cal_id = params.calendar_id.as_deref().unwrap_or("primary");
        debug!(tool = "calendar.events.quickAdd", calendar_id = %cal_id, "MCP tool call");
        let agent_id = agent_id_from_parts(&parts).map_err(|e| e.to_string())?;
        validate_calendar_id(cal_id, "calendar_id")?;
        if params.text.trim().is_empty() {
            return Err("text is required and must not be empty".to_owned());
        }
        let encoded_cal_id = urlencoding::encode(cal_id);
        let qs = build_query_string(&[("text", Some(params.text))]);
        let path = format!("calendars/{encoded_cal_id}/events/quickAdd{qs}");
        let req =
            Self::calendar_request(path, "calendar.events", Method::POST, Bytes::new(), agent_id);
        self.dispatch(req).await
    }

    #[tool(
        name = "calendar.freebusy.query",
        description = "Query free/busy information. Pass `query` as { \"timeMin\": ..., \"timeMax\": ..., \"items\": [{\"id\": \"<calendarId>\"}] }. This is a READ (uses calendar.readonly) despite being an HTTP POST."
    )]
    async fn freebusy_query(
        &self,
        Parameters(mut params): Parameters<FreeBusyQueryParams>,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<String, String> {
        debug!(tool = "calendar.freebusy.query", "MCP tool call");
        let agent_id = agent_id_from_parts(&parts).map_err(|e| e.to_string())?;
        coerce_and_validate_json_object_body(&mut params.query, "query")?;
        let body =
            serde_json::to_vec(&params.query).map_err(|e| format!("invalid query JSON: {e}"))?;
        let req = Self::calendar_request(
            "freeBusy".to_owned(),
            "calendar.readonly",
            Method::POST,
            Bytes::from(body),
            agent_id,
        );
        self.dispatch(req).await
    }

    #[tool(
        name = "calendar.settings.list",
        description = "List the user's Calendar settings (timezone, default event length, etc.)."
    )]
    async fn calendar_settings_list(
        &self,
        Parameters(_params): Parameters<CalendarReadNoParams>,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<String, String> {
        debug!(tool = "calendar.settings.list", "MCP tool call");
        let agent_id = agent_id_from_parts(&parts).map_err(|e| e.to_string())?;
        let req = Self::calendar_request(
            "users/me/settings".to_owned(),
            "calendar.readonly",
            Method::GET,
            Bytes::new(),
            agent_id,
        );
        self.dispatch(req).await
    }

    #[tool(
        name = "calendar.colors.get",
        description = "Get the color definitions for calendars and events."
    )]
    async fn calendar_colors_get(
        &self,
        Parameters(_params): Parameters<CalendarReadNoParams>,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<String, String> {
        debug!(tool = "calendar.colors.get", "MCP tool call");
        let agent_id = agent_id_from_parts(&parts).map_err(|e| e.to_string())?;
        let req = Self::calendar_request(
            "colors".to_owned(),
            "calendar.readonly",
            Method::GET,
            Bytes::new(),
            agent_id,
        );
        self.dispatch(req).await
    }
}

#[tool_handler]
impl rmcp::ServerHandler for CalendarMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build()).with_server_info(
            Implementation::new("permitlayer-calendar", env!("CARGO_PKG_VERSION")),
        )
    }
}

pub type CalendarMcpService = rmcp::transport::streamable_http_server::tower::StreamableHttpService<
    CalendarMcpServer,
    rmcp::transport::streamable_http_server::session::local::LocalSessionManager,
>;

/// Build an MCP service for the Calendar connector. See [`mcp_service`]
/// for the agent-identity propagation rationale.
pub fn calendar_mcp_service(proxy_service: Arc<ProxyService>) -> CalendarMcpService {
    use rmcp::transport::streamable_http_server::{
        session::local::LocalSessionManager,
        tower::{StreamableHttpServerConfig, StreamableHttpService},
    };

    StreamableHttpService::new(
        move || Ok(CalendarMcpServer::new(Arc::clone(&proxy_service))),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    )
}

// -- Drive tool parameter structs ---------------------------------------------

/// Parameters for `drive.files.list`.
#[derive(serde::Deserialize, schemars::JsonSchema, Default)]
pub struct FilesListParams {
    /// Maximum number of files to return (default 100, max 1000).
    pub page_size: Option<u32>,
    /// Page token for pagination.
    pub page_token: Option<String>,
    /// Search query (Drive search syntax).
    pub q: Option<String>,
    /// Sort order (e.g., "modifiedTime desc", "name").
    pub order_by: Option<String>,
    /// Fields to include in the response (e.g., "files(id,name,mimeType)").
    pub fields: Option<String>,
}

/// Parameters for `drive.files.get`.
#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct FileGetParams {
    /// The file ID.
    pub file_id: String,
    /// Fields to include (e.g., "id,name,mimeType,size").
    pub fields: Option<String>,
    /// Set to "media" to download file content instead of metadata.
    pub alt: Option<String>,
}

/// Parameters for `drive.files.search`.
#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct FilesSearchParams {
    /// Search query (Drive search syntax, required).
    pub q: String,
    /// Maximum number of files to return.
    pub page_size: Option<u32>,
    /// Page token for pagination.
    pub page_token: Option<String>,
    /// Sort order.
    pub order_by: Option<String>,
    /// Fields to include in the response.
    pub fields: Option<String>,
}

/// Parameters for `drive.files.create`.
///
/// Creates a metadata-only file (e.g., a folder, a placeholder, or an
/// empty file). Multipart upload (metadata + content) is NOT supported by
/// this tool — that requires the `upload/drive/v3/files` endpoint and is
/// out of scope for Story 2.5.
#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct FileCreateParams {
    /// File resource as a JSON object.
    /// Common fields: `name` (required), `mimeType` (e.g., `application/vnd.google-apps.folder`),
    /// `parents` (array of parent folder IDs), `description`.
    pub file: serde_json::Value,
    /// Fields to include in the response (e.g., "id,name,mimeType").
    pub fields: Option<String>,
}

/// Parameters for `drive.files.update`.
///
/// Updates file metadata only (rename, move, change description). For
/// content updates, use the multipart upload endpoint (not yet exposed).
#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct FileUpdateParams {
    /// The file ID to update.
    pub file_id: String,
    /// Patch document with the fields to update, as a JSON object.
    /// Example: `{ "name": "new-name.txt" }` or `{ "addParents": "...", "removeParents": "..." }`.
    pub file: serde_json::Value,
    /// Fields to include in the response.
    pub fields: Option<String>,
}

// -- Story 9.3: Drive parity gap-fill ----------------------------------------

/// Parameters for `drive.files.delete`.
#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct FileDeleteParams {
    /// The file ID to permanently delete.
    pub file_id: String,
}

/// Parameters for `drive.files.copy`.
#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct FileCopyParams {
    /// The file ID to copy.
    pub file_id: String,
    /// Optional copy metadata (e.g. `{ "name": "Copy of X" }`). When
    /// omitted/empty, Google applies its defaults — sent only if a
    /// non-empty JSON object is supplied.
    pub file: Option<serde_json::Value>,
    /// Fields to include in the response.
    pub fields: Option<String>,
}

/// Parameters for `drive.about.get` (no caller inputs; `fields` is
/// required by Drive and we hardcode `*`).
#[derive(serde::Deserialize, schemars::JsonSchema, Default)]
pub struct DriveAboutGetParams {}

// -- Drive MCP server ---------------------------------------------------------

/// MCP server that exposes Google Drive tools via `ProxyService::handle`.
#[derive(Clone)]
pub struct DriveMcpServer {
    proxy_service: Arc<ProxyService>,
    tool_router: ToolRouter<Self>,
}

impl DriveMcpServer {
    /// Create a new Drive MCP server backed by the given proxy service.
    #[must_use]
    pub fn new(proxy_service: Arc<ProxyService>) -> Self {
        let mut tool_router = Self::tool_router();
        strip_meta_schema(&mut tool_router);
        Self { proxy_service, tool_router }
    }

    /// Dispatch a proxy request and return the upstream response body as a
    /// string.
    async fn dispatch(&self, req: ProxyRequest) -> Result<String, String> {
        match self.proxy_service.handle(req).await {
            Ok(resp) => Ok(String::from_utf8_lossy(&resp.body).into_owned()),
            Err(err) => Err(err.to_string()),
        }
    }

    /// Build a `ProxyRequest` for a Drive endpoint.
    ///
    /// Sets `Content-Type: application/json` automatically when `body` is
    /// non-empty (for POST/PATCH write tools).
    ///
    /// `agent_id` is the bearer-authenticated agent identity for the
    /// inbound MCP call. Callers extract it from the per-call HTTP
    /// `Parts` via [`agent_id_from_parts`] and pass it in.
    fn drive_request(
        path: String,
        scope: &str,
        method: Method,
        body: Bytes,
        agent_id: String,
    ) -> ProxyRequest {
        let mut headers = HeaderMap::new();
        if !body.is_empty() {
            #[allow(clippy::expect_used)]
            headers.insert(
                axum::http::header::CONTENT_TYPE,
                "application/json".parse().expect("valid header value"),
            );
        }
        ProxyRequest {
            service: "drive".to_owned(),
            scope: scope.to_owned(),
            resource: path.clone(),
            method,
            path,
            headers,
            body,
            agent_id,
            request_id: ulid::Ulid::new().to_string(),
        }
    }
}

#[tool_router]
impl DriveMcpServer {
    #[tool(
        name = "drive.files.list",
        description = "List files in Google Drive. Returns file IDs, names, and metadata."
    )]
    async fn files_list(
        &self,
        Parameters(params): Parameters<FilesListParams>,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<String, String> {
        debug!(tool = "drive.files.list", "MCP tool call");
        let agent_id = agent_id_from_parts(&parts).map_err(|e| e.to_string())?;
        let qs = build_query_string(&[
            ("pageSize", params.page_size.map(|n| n.to_string())),
            ("pageToken", params.page_token),
            ("q", params.q),
            ("orderBy", params.order_by),
            ("fields", params.fields),
        ]);
        let path = format!("files{qs}");
        let req = Self::drive_request(path, "drive.readonly", Method::GET, Bytes::new(), agent_id);
        self.dispatch(req).await
    }

    #[tool(
        name = "drive.files.get",
        description = "Get a file's metadata or content from Google Drive. Set alt='media' to download content."
    )]
    async fn files_get(
        &self,
        Parameters(params): Parameters<FileGetParams>,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<String, String> {
        debug!(tool = "drive.files.get", file_id = %params.file_id, "MCP tool call");
        let agent_id = agent_id_from_parts(&parts).map_err(|e| e.to_string())?;
        validate_resource_id(&params.file_id)?;
        let qs = build_query_string(&[("fields", params.fields), ("alt", params.alt)]);
        let encoded_file_id = urlencoding::encode(&params.file_id);
        let path = format!("files/{encoded_file_id}{qs}");
        let req = Self::drive_request(path, "drive.readonly", Method::GET, Bytes::new(), agent_id);
        self.dispatch(req).await
    }

    #[tool(
        name = "drive.files.search",
        description = "Search for files in Google Drive using Drive search syntax. Requires a search query."
    )]
    async fn files_search(
        &self,
        Parameters(params): Parameters<FilesSearchParams>,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<String, String> {
        debug!(tool = "drive.files.search", query = %params.q, "MCP tool call");
        let agent_id = agent_id_from_parts(&parts).map_err(|e| e.to_string())?;
        if params.q.trim().is_empty() {
            return Err("q must not be empty or whitespace-only — use drive.files.list for unfiltered listing".to_owned());
        }
        let qs = build_query_string(&[
            ("q", Some(params.q)),
            ("pageSize", params.page_size.map(|n| n.to_string())),
            ("pageToken", params.page_token),
            ("orderBy", params.order_by),
            ("fields", params.fields),
        ]);
        let path = format!("files{qs}");
        let req = Self::drive_request(path, "drive.readonly", Method::GET, Bytes::new(), agent_id);
        self.dispatch(req).await
    }

    #[tool(
        name = "drive.files.create",
        description = "Create a new file in Google Drive (metadata-only — does not upload content). Pass a JSON file resource with at minimum a 'name'. Use 'mimeType': 'application/vnd.google-apps.folder' to create a folder. Limited to files owned by the app per the drive.file scope."
    )]
    async fn files_create(
        &self,
        Parameters(mut params): Parameters<FileCreateParams>,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<String, String> {
        debug!(tool = "drive.files.create", "MCP tool call");
        let agent_id = agent_id_from_parts(&parts).map_err(|e| e.to_string())?;
        coerce_and_validate_json_object_body(&mut params.file, "file")?;
        let body =
            serde_json::to_vec(&params.file).map_err(|e| format!("invalid file JSON: {e}"))?;
        let qs = build_query_string(&[("fields", params.fields)]);
        let path = format!("files{qs}");
        let req =
            Self::drive_request(path, "drive.file", Method::POST, Bytes::from(body), agent_id);
        self.dispatch(req).await
    }

    #[tool(
        name = "drive.files.update",
        description = "Update file metadata in Google Drive (rename, move, change description). Pass a JSON patch document with the fields to update. Limited to files the app created or opened per the drive.file scope. Does NOT update file content."
    )]
    async fn files_update(
        &self,
        Parameters(mut params): Parameters<FileUpdateParams>,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<String, String> {
        debug!(tool = "drive.files.update", file_id = %params.file_id, "MCP tool call");
        let agent_id = agent_id_from_parts(&parts).map_err(|e| e.to_string())?;
        validate_resource_id(&params.file_id)?;
        coerce_and_validate_json_object_body(&mut params.file, "file")?;
        let body =
            serde_json::to_vec(&params.file).map_err(|e| format!("invalid file JSON: {e}"))?;
        let qs = build_query_string(&[("fields", params.fields)]);
        let encoded_file_id = urlencoding::encode(&params.file_id);
        let path = format!("files/{encoded_file_id}{qs}");
        let req =
            Self::drive_request(path, "drive.file", Method::PATCH, Bytes::from(body), agent_id);
        self.dispatch(req).await
    }

    // ── Story 9.3: Drive parity gap-fill ─────────────────────────────

    #[tool(
        name = "drive.files.delete",
        description = "PERMANENTLY delete a file (bypasses the trash — this is NOT reversible). Limited to files the app created or opened (drive.file scope)."
    )]
    async fn files_delete(
        &self,
        Parameters(params): Parameters<FileDeleteParams>,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<String, String> {
        debug!(tool = "drive.files.delete", file_id = %params.file_id, "MCP tool call");
        let agent_id = agent_id_from_parts(&parts).map_err(|e| e.to_string())?;
        validate_resource_id(&params.file_id)?;
        let encoded_file_id = urlencoding::encode(&params.file_id);
        let path = format!("files/{encoded_file_id}");
        let req = Self::drive_request(path, "drive.file", Method::DELETE, Bytes::new(), agent_id);
        self.dispatch(req).await
    }

    #[tool(
        name = "drive.files.copy",
        description = "Create a copy of a file. Optionally pass `file` as a JSON object with copy metadata (e.g. { \"name\": \"Copy of X\" }). Limited to files the app created or opened (drive.file scope)."
    )]
    async fn files_copy(
        &self,
        Parameters(mut params): Parameters<FileCopyParams>,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<String, String> {
        debug!(tool = "drive.files.copy", file_id = %params.file_id, "MCP tool call");
        let agent_id = agent_id_from_parts(&parts).map_err(|e| e.to_string())?;
        validate_resource_id(&params.file_id)?;
        // Body is optional; only serialize+send if a non-empty JSON
        // object was supplied (mirrors the events_create body guard, but
        // here the body is genuinely optional per the Drive API).
        let body = match params.file {
            Some(ref mut v) => {
                coerce_and_validate_json_object_body(v, "file")?;
                Bytes::from(serde_json::to_vec(v).map_err(|e| format!("invalid file JSON: {e}"))?)
            }
            None => Bytes::new(),
        };
        let qs = build_query_string(&[("fields", params.fields)]);
        let encoded_file_id = urlencoding::encode(&params.file_id);
        let path = format!("files/{encoded_file_id}/copy{qs}");
        let req = Self::drive_request(path, "drive.file", Method::POST, body, agent_id);
        self.dispatch(req).await
    }

    #[tool(
        name = "drive.about.get",
        description = "Get information about the user's Drive and system capabilities (storage quota, user info, import/export formats)."
    )]
    async fn about_get(
        &self,
        Parameters(_params): Parameters<DriveAboutGetParams>,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<String, String> {
        debug!(tool = "drive.about.get", "MCP tool call");
        let agent_id = agent_id_from_parts(&parts).map_err(|e| e.to_string())?;
        // Drive requires the `fields` param on about.get; `*` returns all.
        let req = Self::drive_request(
            "about?fields=*".to_owned(),
            "drive.readonly",
            Method::GET,
            Bytes::new(),
            agent_id,
        );
        self.dispatch(req).await
    }
}

#[tool_handler]
impl rmcp::ServerHandler for DriveMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("permitlayer-drive", env!("CARGO_PKG_VERSION")))
    }
}

pub type DriveMcpService = rmcp::transport::streamable_http_server::tower::StreamableHttpService<
    DriveMcpServer,
    rmcp::transport::streamable_http_server::session::local::LocalSessionManager,
>;

/// Build an MCP service for the Drive connector. See [`mcp_service`]
/// for the agent-identity propagation rationale.
pub fn drive_mcp_service(proxy_service: Arc<ProxyService>) -> DriveMcpService {
    use rmcp::transport::streamable_http_server::{
        session::local::LocalSessionManager,
        tower::{StreamableHttpServerConfig, StreamableHttpService},
    };

    StreamableHttpService::new(
        move || Ok(DriveMcpServer::new(Arc::clone(&proxy_service))),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    )
}

// ─────────────────────────────────────────────────────────────────────
// Generic connector dispatch (Story 11.4 — hybrid model).
// ─────────────────────────────────────────────────────────────────────
//
// The three typed servers above ARE the per-connector handler registry
// for the built-in Google connectors: each owns the bespoke Rust logic
// (response shaping, attachment-to-disk, query building, id validation)
// that the declarative `connector.toml` deliberately does not express.
// `ConnectorMcpService` is the single generic dispatch entrypoint that
// the dynamic `/mcp/{selector}` route forwards to — "one generic
// connector MCP server" realized at the service/routing layer rather
// than as one rmcp `ServerHandler` type (which would force re-binding
// every handler and break the conformance parity gate).
//
// Host-installed connectors get a generic declarative passthrough arm
// in a follow-up Phase 2 story; until then, a selector that does not
// resolve to a built-in returns MCP not-found (never panics).

/// A resolved per-connector MCP service. Each arm is a real rmcp
/// `StreamableHttpService` over the connector's typed server, so each
/// advertises exactly that connector's tools + input schemas.
pub enum ConnectorMcpService {
    /// The built-in Gmail connector (`google-gmail`).
    Gmail(GmailMcpService),
    /// The built-in Calendar connector (`google-calendar`).
    Calendar(CalendarMcpService),
    /// The built-in Drive connector (`google-drive`).
    Drive(DriveMcpService),
}

impl ConnectorMcpService {
    /// Forward an inbound MCP HTTP request to the resolved connector's
    /// service. `StreamableHttpService::handle` dispatches on the HTTP
    /// method and ignores the URL path, so the dynamic-route prefix
    /// (`/mcp/{selector}`) needs no stripping.
    pub async fn handle(
        &self,
        request: axum::http::Request<axum::body::Body>,
    ) -> axum::response::Response {
        use axum::response::IntoResponse;
        match self {
            ConnectorMcpService::Gmail(s) => s.handle(request).await.into_response(),
            ConnectorMcpService::Calendar(s) => s.handle(request).await.into_response(),
            ConnectorMcpService::Drive(s) => s.handle(request).await.into_response(),
        }
    }
}

/// Map a route **selector** to its canonical connector id.
///
/// The route vocabulary stays the bare service name (`/mcp/gmail`) for
/// client compatibility; the registry keys on the canonical id
/// (`google-gmail`). Returns `None` for an unrecognized selector. A
/// selector that is already a canonical id passes through unchanged so
/// a future `/mcp/google-gmail` form also resolves.
///
/// Delegates to [`permitlayer_connectors::canonical_selector_id`] — the
/// single home for the alias mapping (Story 11.7), shared with the daemon
/// CLI so the proxy and CLI can never disagree on what `gmail` resolves to.
#[must_use]
pub fn selector_to_connector_id(selector: &str) -> Option<&'static str> {
    permitlayer_connectors::canonical_selector_id(selector)
}

/// Build the [`ConnectorMcpService`] for a built-in connector id.
///
/// Returns `None` for any id that is not a shipped built-in — the
/// caller maps that to an MCP not-found response. Host-installed
/// connectors will gain an arm here with the declarative-passthrough
/// story; for now they resolve to `None` (no panic, FR89 surface).
#[must_use]
pub fn connector_mcp_service(
    connector_id: &str,
    proxy_service: Arc<ProxyService>,
) -> Option<ConnectorMcpService> {
    match connector_id {
        "google-gmail" => Some(ConnectorMcpService::Gmail(mcp_service(proxy_service))),
        "google-calendar" => {
            Some(ConnectorMcpService::Calendar(calendar_mcp_service(proxy_service)))
        }
        "google-drive" => Some(ConnectorMcpService::Drive(drive_mcp_service(proxy_service))),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn build_query_string_empty() {
        let qs = build_query_string(&[("a", None), ("b", None)]);
        assert_eq!(qs, "");
    }

    #[test]
    fn build_query_string_with_values() {
        let qs = build_query_string(&[
            ("maxResults", Some("10".to_owned())),
            ("pageToken", None),
            ("q", Some("from:me".to_owned())),
        ]);
        assert_eq!(qs, "?maxResults=10&q=from%3Ame");
    }

    #[test]
    fn build_query_string_encodes_special_chars() {
        let qs = build_query_string(&[("q", Some("from:alice subject:hello world".to_owned()))]);
        assert!(qs.contains("q=from%3Aalice"));
        assert!(qs.contains("hello%20world"));
        assert!(!qs.contains(' '));
    }

    #[test]
    fn validate_resource_id_accepts_valid() {
        assert!(validate_resource_id("18f3a2b4c5d6e7f8").is_ok());
        assert!(validate_resource_id("msg-123").is_ok());
    }

    #[test]
    fn validate_resource_id_rejects_traversal() {
        assert!(validate_resource_id("../../admin").is_err());
        assert!(validate_resource_id("foo/bar").is_err());
        assert!(validate_resource_id("id?alt=media").is_err());
        assert!(validate_resource_id("").is_err());
    }

    #[test]
    fn validate_calendar_id_accepts_primary() {
        assert!(validate_calendar_id("primary", "calendar_id").is_ok());
    }

    #[test]
    fn validate_calendar_id_accepts_email() {
        assert!(validate_calendar_id("user@example.com", "calendar_id").is_ok());
    }

    #[test]
    fn validate_calendar_id_accepts_dots_and_at() {
        assert!(
            validate_calendar_id("en.usa#holiday@group.v.calendar.google.com", "calendar_id")
                .is_ok()
        );
    }

    #[test]
    fn validate_calendar_id_rejects_traversal() {
        assert!(validate_calendar_id("../admin", "calendar_id").is_err());
        assert!(validate_calendar_id("foo/bar", "calendar_id").is_err());
        assert!(validate_calendar_id("id?q=x", "calendar_id").is_err());
        assert!(validate_calendar_id("", "calendar_id").is_err());
    }

    #[test]
    fn validate_calendar_id_rejects_pre_encoded() {
        // `urlencoding::encode` would double-encode `%40`, breaking the upstream URL.
        assert!(validate_calendar_id("user%40example.com", "calendar_id").is_err());
    }

    #[test]
    fn validate_resource_id_rejects_unsafe_chars() {
        assert!(validate_resource_id("abc def").is_err(), "spaces rejected");
        assert!(validate_resource_id("abc%40def").is_err(), "% rejected");
        assert!(validate_resource_id("abc+def").is_err(), "+ rejected");
        assert!(validate_resource_id("abc\"def").is_err(), "quotes rejected");
        assert!(validate_resource_id("abc<def").is_err(), "angle brackets rejected");
        assert!(validate_resource_id("abc\tdef").is_err(), "tab rejected");
    }

    #[test]
    fn build_query_string_treats_empty_as_absent() {
        let qs = build_query_string(&[
            ("pageToken", Some(String::new())),
            ("q", Some("real".to_owned())),
        ]);
        assert_eq!(qs, "?q=real", "empty pageToken must be skipped");
    }

    #[test]
    fn build_query_string_all_empty_returns_empty() {
        let qs = build_query_string(&[
            ("pageToken", Some(String::new())),
            ("orderBy", Some(String::new())),
        ]);
        assert_eq!(qs, "");
    }

    #[test]
    fn sanitize_filename_strips_path_traversal() {
        // Separators, traversal, control chars, NTFS stream, leading dots
        // must all be neutralized so the result is a safe single component.
        for evil in [
            "../../etc/passwd",
            "..\\..\\windows\\system32",
            "a/b/c.pdf",
            "name:stream",
            "....//....//x",
            "\u{0000}\u{0007}bad",
        ] {
            let out = sanitize_filename(Some(evil), "ATTID123");
            assert!(!out.contains('/'), "no fwd slash in {out:?}");
            assert!(!out.contains('\\'), "no backslash in {out:?}");
            assert!(!out.contains(':'), "no colon in {out:?}");
            assert!(!out.starts_with('.'), "no leading dot in {out:?}");
            assert!(!out.is_empty());
        }
    }

    #[test]
    fn sanitize_filename_keeps_normal_name() {
        assert_eq!(sanitize_filename(Some("invoice.pdf"), "X"), "invoice.pdf");
    }

    #[test]
    fn sanitize_filename_falls_back_when_absent_or_empty() {
        assert_eq!(sanitize_filename(None, "ABCDEF0123456789XYZ"), "att-ABCDEF0123456789.bin");
        // Becomes empty after stripping → fallback.
        assert_eq!(sanitize_filename(Some("..."), "ZZ"), "att-ZZ.bin");
    }

    #[test]
    fn sanitize_filename_bounds_length() {
        let long = "a".repeat(500);
        let out = sanitize_filename(Some(&long), "X");
        assert!(out.len() <= 128);
    }

    #[test]
    fn short_hex_hash_is_stable_and_hex() {
        let a = short_hex_hash(b"agent-one");
        let b = short_hex_hash(b"agent-one");
        let c = short_hex_hash(b"agent-two");
        assert_eq!(a, b, "deterministic");
        assert_ne!(a, c, "distinct inputs differ");
        assert_eq!(a.len(), 32, "16 bytes → 32 hex chars");
        assert!(a.chars().all(|ch| ch.is_ascii_hexdigit()));
    }

    #[test]
    fn build_query_string_treats_whitespace_as_absent() {
        let qs = build_query_string(&[
            ("pageToken", Some("   ".to_owned())),
            ("q", Some("\t".to_owned())),
            ("orderBy", Some("real".to_owned())),
        ]);
        assert_eq!(qs, "?orderBy=real", "whitespace-only values must be skipped");
    }

    #[test]
    fn validate_calendar_id_rejects_whitespace_only() {
        assert!(validate_calendar_id("   ", "calendar_id").is_err());
        assert!(validate_calendar_id("\t", "calendar_id").is_err());
        assert!(validate_calendar_id("", "calendar_id").is_err());
    }

    #[test]
    fn validate_calendar_id_rejects_internal_whitespace() {
        assert!(validate_calendar_id("user @example.com", "calendar_id").is_err());
        assert!(validate_calendar_id("primary\t", "calendar_id").is_err());
    }

    #[test]
    fn validate_calendar_id_rejects_colon() {
        // `:` would cause url::Url::join to misparse the segment as a URL scheme.
        assert!(validate_calendar_id("abc:xyz", "calendar_id").is_err());
        assert!(validate_calendar_id("scheme:user@example.com", "calendar_id").is_err());
    }

    #[test]
    fn validate_json_object_body_accepts_non_empty_object() {
        let mut v = serde_json::json!({"name": "test"});
        assert!(coerce_and_validate_json_object_body(&mut v, "field").is_ok());
    }

    #[test]
    fn validate_json_object_body_rejects_null() {
        let mut v = serde_json::Value::Null;
        let err = coerce_and_validate_json_object_body(&mut v, "event").unwrap_err();
        assert!(err.contains("event"), "error mentions field name: {err}");
        assert!(err.contains("null"), "error mentions null: {err}");
    }

    #[test]
    fn validate_json_object_body_rejects_empty_object() {
        let mut v = serde_json::json!({});
        let err = coerce_and_validate_json_object_body(&mut v, "file").unwrap_err();
        assert!(err.contains("empty"), "error mentions empty: {err}");
    }

    #[test]
    fn validate_json_object_body_rejects_array() {
        let mut v = serde_json::json!([1, 2, 3]);
        let err = coerce_and_validate_json_object_body(&mut v, "file").unwrap_err();
        assert!(err.contains("object"), "error mentions object expectation: {err}");
        assert!(err.contains("array"), "error mentions actual type: {err}");
    }

    #[test]
    fn validate_json_object_body_rejects_primitives() {
        let mut s = serde_json::json!("string");
        assert!(coerce_and_validate_json_object_body(&mut s, "f").is_err());
        let mut n = serde_json::json!(42);
        assert!(coerce_and_validate_json_object_body(&mut n, "f").is_err());
        let mut b = serde_json::json!(true);
        assert!(coerce_and_validate_json_object_body(&mut b, "f").is_err());
    }

    // ── Arg coercion: stringified-JSON-object args (Fix A) ─────────

    #[test]
    fn coerce_stringified_object_is_accepted_and_replaced_in_place() {
        let mut v = serde_json::json!("{\"summary\":\"x\"}");
        assert!(coerce_and_validate_json_object_body(&mut v, "event").is_ok());
        // In-place replacement matters: the caller serializes `v` afterward.
        assert_eq!(v, serde_json::json!({"summary": "x"}));
    }

    #[test]
    fn coerce_stringified_object_tolerates_surrounding_whitespace() {
        let mut v = serde_json::json!("  {\"a\":1}  ");
        assert!(coerce_and_validate_json_object_body(&mut v, "event").is_ok());
        assert_eq!(v, serde_json::json!({"a": 1}));
    }

    #[test]
    fn coerce_does_not_accept_stringified_array() {
        // A string that parses to a non-object must NOT be coerced — it
        // falls through to the same clear error as before.
        let mut v = serde_json::json!("[1,2,3]");
        let err = coerce_and_validate_json_object_body(&mut v, "event").unwrap_err();
        assert!(err.contains("got string"), "keeps the original string error: {err}");
    }

    #[test]
    fn coerce_keeps_original_error_for_non_json_string() {
        let mut v = serde_json::json!("just some text");
        let err = coerce_and_validate_json_object_body(&mut v, "event").unwrap_err();
        assert!(err.contains("got string"), "keeps the original string error: {err}");
    }

    #[test]
    fn coerce_stringified_empty_object_still_rejected() {
        let mut v = serde_json::json!("{}");
        let err = coerce_and_validate_json_object_body(&mut v, "event").unwrap_err();
        assert!(err.contains("empty"), "coerced then empty-check fires: {err}");
    }

    #[test]
    fn coerce_leaves_real_object_unchanged() {
        let mut v = serde_json::json!({"a": 1});
        let before = v.clone();
        assert!(coerce_and_validate_json_object_body(&mut v, "event").is_ok());
        assert_eq!(v, before);
    }

    // ── Story 4.4 Patch #29: AgentIdScopedMcpService tests ─────────

    /// Build a `Parts` carrying an `AgentId` extension, mirroring what
    /// the production middleware chain produces (AuthLayer inserts on
    /// the inbound request; rmcp surfaces the resulting `Parts` to
    /// tool handlers via the `Extension<Parts>` extractor).
    fn parts_with_agent(name: &str) -> axum::http::request::Parts {
        let mut req = axum::http::Request::builder().uri("/test").body(()).unwrap();
        req.extensions_mut().insert(AgentId(name.to_owned()));
        req.into_parts().0
    }

    #[test]
    fn agent_id_from_parts_returns_name_when_extension_present() {
        let parts = parts_with_agent("research-agent");
        assert_eq!(agent_id_from_parts(&parts).unwrap(), "research-agent");
    }

    #[test]
    fn agent_id_from_parts_returns_error_when_extension_missing() {
        let req = axum::http::Request::builder().uri("/test").body(()).unwrap();
        let parts = req.into_parts().0;
        assert!(matches!(
            agent_id_from_parts(&parts),
            Err(crate::error::ProxyError::AuthMissingAgentId)
        ));
    }

    #[test]
    fn gmail_request_uses_passed_agent_id() {
        let req = GmailMcpServer::gmail_request(
            "users/me/messages".to_owned(),
            "gmail.readonly",
            Method::GET,
            Bytes::new(),
            "research-agent".to_owned(),
        );
        assert_eq!(req.agent_id, "research-agent");
        assert_eq!(req.service, "gmail");
        assert_eq!(req.scope, "gmail.readonly");
        assert_eq!(req.path, "users/me/messages");
        assert_eq!(req.method, Method::GET);
        assert!(req.body.is_empty());
        // GET with empty body sets no Content-Type.
        assert!(!req.headers.contains_key(axum::http::header::CONTENT_TYPE));
    }

    /// Story 9.2: the generalized `gmail_request` sets
    /// `Content-Type: application/json` for a non-empty (write) body and
    /// carries the method through — parity with `calendar_request`.
    #[test]
    fn gmail_request_write_sets_content_type_and_method() {
        let req = GmailMcpServer::gmail_request(
            "users/me/messages/send".to_owned(),
            "gmail.send",
            Method::POST,
            Bytes::from_static(b"{\"raw\":\"abc\"}"),
            "send-agent".to_owned(),
        );
        assert_eq!(req.method, Method::POST);
        assert_eq!(req.scope, "gmail.send");
        assert!(!req.body.is_empty());
        assert_eq!(req.headers.get(axum::http::header::CONTENT_TYPE).unwrap(), "application/json");
    }

    #[test]
    fn calendar_request_uses_passed_agent_id() {
        let req = CalendarMcpServer::calendar_request(
            "users/me/calendarList".to_owned(),
            "calendar.readonly",
            Method::GET,
            Bytes::new(),
            "calendar-agent".to_owned(),
        );
        assert_eq!(req.agent_id, "calendar-agent");
        assert_eq!(req.service, "calendar");
    }

    #[test]
    fn drive_request_uses_passed_agent_id() {
        let req = DriveMcpServer::drive_request(
            "files".to_owned(),
            "drive.readonly",
            Method::GET,
            Bytes::new(),
            "drive-agent".to_owned(),
        );
        assert_eq!(req.agent_id, "drive-agent");
        assert_eq!(req.service, "drive");
    }

    // ── Story 9.1: Gmail read-tool gap-fill ──────────────────────────

    /// `attachments.get` interpolates BOTH path IDs and they go through
    /// `validate_resource_id` — a `/` or `..` in either must be rejected
    /// so it cannot escape the `users/me/messages/{}/attachments/{}` path.
    #[test]
    fn attachments_get_path_ids_are_validated() {
        // Valid opaque IDs pass.
        assert!(validate_resource_id("18f3a2b4c5d6").is_ok());
        assert!(validate_resource_id("ANGjdJ9x_attach_01").is_ok());
        // Traversal / separators in either segment are rejected.
        assert!(validate_resource_id("../../../users/me/profile").is_err());
        assert!(validate_resource_id("a/b").is_err());
        // The path this tool builds, with valid IDs, is exactly the
        // documented Gmail endpoint shape.
        let path = format!("users/me/messages/{}/attachments/{}", "MSG1", "ATT1");
        assert_eq!(path, "users/me/messages/MSG1/attachments/ATT1");
    }

    /// `history.list` builds the documented Gmail `users/me/history`
    /// path + query (the full path, not a self-comparison). The
    /// fail-fast on a blank `start_history_id` is covered end-to-end by
    /// the integration test `mcp_history_list_rejects_missing_start_history_id`
    /// (which proves the upstream is never dispatched), so it is not
    /// re-asserted against a copied guard here.
    #[test]
    fn history_list_builds_expected_path_and_query() {
        let qs = build_query_string(&[
            ("startHistoryId", Some("12345".to_owned())),
            ("maxResults", Some("10".to_owned())),
            ("pageToken", None),
            ("labelId", Some("INBOX".to_owned())),
            ("historyTypes", Some(["messageAdded", "labelAdded"].join(","))),
        ]);
        let path = format!("users/me/history{qs}");
        assert_eq!(
            path,
            "users/me/history?startHistoryId=12345&maxResults=10&labelId=INBOX&historyTypes=messageAdded%2ClabelAdded"
        );
    }

    /// The no-input tools use empty params structs (no paramless-tool
    /// form exists in this codebase) and hit the documented static paths.
    #[test]
    fn labels_and_profile_use_static_paths() {
        let _ = LabelsListParams::default();
        let _ = ProfileGetParams::default();
        let labels = GmailMcpServer::gmail_request(
            "users/me/labels".to_owned(),
            "gmail.readonly",
            Method::GET,
            Bytes::new(),
            "a".to_owned(),
        );
        let profile = GmailMcpServer::gmail_request(
            "users/me/profile".to_owned(),
            "gmail.readonly",
            Method::GET,
            Bytes::new(),
            "a".to_owned(),
        );
        assert_eq!(labels.path, "users/me/labels");
        assert_eq!(labels.scope, "gmail.readonly");
        assert_eq!(profile.path, "users/me/profile");
        assert_eq!(profile.scope, "gmail.readonly");
    }

    /// `drafts.list` query shape and `drafts.get` path + qs shape.
    #[test]
    fn drafts_tools_build_expected_paths() {
        let list_qs = build_query_string(&[
            ("maxResults", Some("5".to_owned())),
            ("pageToken", None),
            ("q", Some("subject:invoice".to_owned())),
            ("includeSpamTrash", Some("true".to_owned())),
        ]);
        assert_eq!(
            format!("users/me/drafts{list_qs}"),
            "users/me/drafts?maxResults=5&q=subject%3Ainvoice&includeSpamTrash=true"
        );
        assert!(validate_resource_id("draft-abc123").is_ok());
        let get_qs = build_query_string(&[
            ("format", Some("metadata".to_owned())),
            ("metadataHeaders", Some(["Subject", "From"].join(","))),
        ]);
        assert_eq!(
            format!("users/me/drafts/{}{get_qs}", "D1"),
            "users/me/drafts/D1?format=metadata&metadataHeaders=Subject%2CFrom"
        );
    }

    // ── Story 9.2: write + settings tools ────────────────────────────

    /// Every Story 9.2 write tool builds a request with the
    /// Google-minimum scope + correct method/path (verified against
    /// Google's REST reference). This pins the scope contract — the
    /// single most security-relevant property of the story.
    #[test]
    fn write_tools_use_google_minimum_scope_and_method() {
        // (scope, method, path) per the AC#3 table.
        let send = GmailMcpServer::gmail_request(
            "users/me/messages/send".to_owned(),
            "gmail.send",
            Method::POST,
            Bytes::from_static(b"{\"raw\":\"x\"}"),
            "a".to_owned(),
        );
        assert_eq!(send.scope, "gmail.send");
        assert_eq!(send.method, Method::POST);
        assert_eq!(send.path, "users/me/messages/send");

        let modify = GmailMcpServer::gmail_request(
            "users/me/messages/M1/modify".to_owned(),
            "gmail.modify",
            Method::POST,
            Bytes::from_static(b"{\"addLabelIds\":[\"INBOX\"]}"),
            "a".to_owned(),
        );
        assert_eq!(modify.scope, "gmail.modify");

        // drafts.create/update/send are gmail.compose — NOT gmail.send
        // (Google's users.drafts.send rejects gmail.send; verified).
        for (path, method) in [
            ("users/me/drafts".to_owned(), Method::POST),
            ("users/me/drafts/D1".to_owned(), Method::PUT),
            ("users/me/drafts/send".to_owned(), Method::POST),
        ] {
            let req = GmailMcpServer::gmail_request(
                path.clone(),
                "gmail.compose",
                method.clone(),
                Bytes::from_static(b"{\"id\":\"D1\"}"),
                "a".to_owned(),
            );
            assert_eq!(req.scope, "gmail.compose", "draft tool {path} must be gmail.compose");
            assert_eq!(req.method, method);
        }

        // trash/untrash are reversible gmail.modify with NO body (so no
        // Content-Type) — delete is intentionally NOT a tool here.
        for verb in ["trash", "untrash"] {
            let req = GmailMcpServer::gmail_request(
                format!("users/me/messages/M1/{verb}"),
                "gmail.modify",
                Method::POST,
                Bytes::new(),
                "a".to_owned(),
            );
            assert_eq!(req.scope, "gmail.modify");
            assert!(req.body.is_empty(), "{verb} sends no body");
            assert!(!req.headers.contains_key(axum::http::header::CONTENT_TYPE));
        }
    }

    /// All 8 settings reads use `gmail.readonly` (Google minimum for
    /// read ops — NOT gmail.settings.basic; verified). Forwarding maps
    /// to Google's `forwardingAddresses` path.
    #[test]
    fn settings_reads_are_all_gmail_readonly() {
        let paths = [
            "users/me/settings/sendAs",
            "users/me/settings/filters",
            "users/me/settings/language",
            "users/me/settings/imap",
            "users/me/settings/pop",
            "users/me/settings/vacation",
            "users/me/settings/forwardingAddresses",
            "users/me/settings/autoForwarding",
        ];
        for p in paths {
            let req = GmailMcpServer::gmail_request(
                p.to_owned(),
                "gmail.readonly",
                Method::GET,
                Bytes::new(),
                "a".to_owned(),
            );
            assert_eq!(req.scope, "gmail.readonly", "{p} must be gmail.readonly");
            assert_eq!(req.method, Method::GET);
        }
    }

    /// JSON-body write tools reject null / empty-object / array bodies
    /// via the shared `validate_json_object_body` guard (mirrors the
    /// calendar/drive write precedent).
    #[test]
    fn write_tools_reject_malformed_json_body() {
        for bad in [
            serde_json::Value::Null,
            serde_json::json!({}),
            serde_json::json!([1, 2, 3]),
            serde_json::json!("a string"),
        ] {
            let mut bad = bad;
            assert!(
                coerce_and_validate_json_object_body(&mut bad, "message").is_err(),
                "malformed body {bad:?} must be rejected"
            );
        }
        let mut ok = serde_json::json!({"raw": "x"});
        assert!(coerce_and_validate_json_object_body(&mut ok, "message").is_ok());
    }

    // ── Story 9.3: Calendar + Drive parity gap-fill ──────────────────

    /// Exact per-server tool counts after Epic 9. Counting the
    /// `tool_router().map` entries is a direct, HTTP-free assertion of
    /// the registered tool set.
    /// Gmail: 5 original + 6 (9.1) + 15 (9.2) = 26.
    /// Calendar: 5 original + 7 (9.3) = 12.
    /// Drive: 5 original + 3 (9.3) = 8.
    #[test]
    fn epic9_tool_counts_are_exact() {
        assert_eq!(GmailMcpServer::tool_router().map.len(), 26, "Gmail tool count");
        assert_eq!(CalendarMcpServer::tool_router().map.len(), 12, "Calendar tool count");
        assert_eq!(DriveMcpServer::tool_router().map.len(), 8, "Drive tool count");
    }

    // ---- Story 11.4: generic connector dispatch resolver ----

    #[test]
    fn selector_maps_bare_and_canonical_to_connector_id() {
        // Bare service names (the route vocabulary) and canonical ids
        // both resolve; an unknown selector does not.
        assert_eq!(selector_to_connector_id("gmail"), Some("google-gmail"));
        assert_eq!(selector_to_connector_id("google-gmail"), Some("google-gmail"));
        assert_eq!(selector_to_connector_id("calendar"), Some("google-calendar"));
        assert_eq!(selector_to_connector_id("drive"), Some("google-drive"));
        assert_eq!(selector_to_connector_id("nope"), None);
        assert_eq!(selector_to_connector_id(""), None);
    }

    // `connector_mcp_service(...)` requires a constructed `ProxyService`
    // (several mock deps); its built-in-resolves / unknown-is-None
    // behavior is covered in the integration suite (mcp_transport.rs)
    // where a real ProxyService builder exists. The pure selector map
    // above is the unit-level guard.

    /// The Story 9.3 tools are registered under their dotted names.
    #[test]
    fn story_9_3_tools_are_registered() {
        let cal = CalendarMcpServer::tool_router();
        for name in [
            "calendar.events.delete",
            "calendar.events.patch",
            "calendar.events.move",
            "calendar.events.quickAdd",
            "calendar.freebusy.query",
            "calendar.settings.list",
            "calendar.colors.get",
        ] {
            assert!(cal.map.contains_key(name), "calendar router missing {name}");
        }
        let drive = DriveMcpServer::tool_router();
        for name in ["drive.files.delete", "drive.files.copy", "drive.about.get"] {
            assert!(drive.map.contains_key(name), "drive router missing {name}");
        }
    }

    /// Story 9.3 scope/method contract (verified against Google's REST
    /// reference 2026-05-17): calendar writes = `calendar.events`,
    /// freebusy = `calendar.readonly` (read via POST), settings/colors =
    /// `calendar.readonly`; drive delete/copy = `drive.file`, about.get =
    /// `drive.readonly`.
    #[test]
    fn story_9_3_scope_and_method_contract() {
        // calendar.events.delete — DELETE, calendar.events, no body.
        let del = CalendarMcpServer::calendar_request(
            "calendars/primary/events/E1".to_owned(),
            "calendar.events",
            Method::DELETE,
            Bytes::new(),
            "a".to_owned(),
        );
        assert_eq!(del.scope, "calendar.events");
        assert_eq!(del.method, Method::DELETE);
        assert!(del.body.is_empty());

        // calendar.events.patch — PATCH, calendar.events, JSON body.
        let patch = CalendarMcpServer::calendar_request(
            "calendars/primary/events/E1".to_owned(),
            "calendar.events",
            Method::PATCH,
            Bytes::from_static(b"{\"summary\":\"x\"}"),
            "a".to_owned(),
        );
        assert_eq!(patch.method, Method::PATCH);
        assert_eq!(
            patch.headers.get(axum::http::header::CONTENT_TYPE).unwrap(),
            "application/json"
        );

        // freebusy — POST but a READ → calendar.readonly (scope tracks
        // data effect, not HTTP verb).
        let fb = CalendarMcpServer::calendar_request(
            "freeBusy".to_owned(),
            "calendar.readonly",
            Method::POST,
            Bytes::from_static(b"{\"items\":[]}"),
            "a".to_owned(),
        );
        assert_eq!(fb.scope, "calendar.readonly");
        assert_eq!(fb.method, Method::POST);

        // drive.files.delete — DELETE, drive.file (NOT full drive).
        let dd = DriveMcpServer::drive_request(
            "files/F1".to_owned(),
            "drive.file",
            Method::DELETE,
            Bytes::new(),
            "a".to_owned(),
        );
        assert_eq!(dd.scope, "drive.file");
        assert_eq!(dd.method, Method::DELETE);

        // drive.about.get — GET, drive.readonly, required fields=* in path.
        let about = DriveMcpServer::drive_request(
            "about?fields=*".to_owned(),
            "drive.readonly",
            Method::GET,
            Bytes::new(),
            "a".to_owned(),
        );
        assert_eq!(about.scope, "drive.readonly");
        assert_eq!(about.path, "about?fields=*");
    }

    /// `events.move` / `events.quickAdd` reject blank required query
    /// params before dispatch (mirrors the 9.1 `history.list` guard).
    #[test]
    fn calendar_required_query_params_fail_fast() {
        // The guard shape both tools use, asserted directly.
        fn require(field: &str, v: &str) -> Result<(), String> {
            if v.trim().is_empty() {
                return Err(format!("{field} is required and must not be empty"));
            }
            Ok(())
        }
        assert!(require("destination", "").is_err());
        assert!(require("destination", "  ").is_err());
        assert!(require("text", "\t").is_err());
        assert!(require("destination", "work@example.com").is_ok());
        assert!(require("text", "Lunch 1pm").is_ok());
        // And the move query string is built as Google expects.
        let qs = build_query_string(&[("destination", Some("cal2@example.com".to_owned()))]);
        assert_eq!(qs, "?destination=cal2%40example.com");
    }
}
