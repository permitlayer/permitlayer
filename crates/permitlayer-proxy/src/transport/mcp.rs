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

use std::convert::Infallible;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::{Body, Bytes};
use axum::http::{HeaderMap, Method, Request, Response};
use rmcp::handler::server::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{Implementation, ServerCapabilities, ServerInfo};
use rmcp::{tool, tool_handler, tool_router};
use tower::Service;
use tracing::debug;

use crate::error::AgentId;
use crate::request::ProxyRequest;
use crate::service::ProxyService;

// ─────────────────────────────────────────────────────────────────────
// Story 4.4 Patch #29: real `AgentId` plumbing through rmcp.
// ─────────────────────────────────────────────────────────────────────
//
// rmcp's `StreamableHttpService::handle` receives the raw axum
// `Request<Body>` but its tool-dispatch machinery does not expose the
// request extensions to tool method bodies (`gmail.messages.list`,
// `calendar.events.create`, etc.). Those method bodies only see
// `&self` and the deserialized `Parameters<P>`. The inbound request
// and its `AgentId` extension are dropped before the tool sees them.
//
// The fix is a tower adapter [`AgentIdScopedMcpService`] that:
//   1. Reads `AgentId` from the inbound request's extensions.
//   2. Stashes it in a tokio task-local `CURRENT_AGENT_ID`.
//   3. Calls the inner rmcp service inside `CURRENT_AGENT_ID.scope(...)`.
//   4. Tool method bodies read the task-local when they build a
//      `ProxyRequest` via [`current_mcp_agent_id`].
//
// Tokio task-locals are inherited across `.await` points within the
// same task, so they survive rmcp's internal futures machinery. Unlike
// thread-locals, they are also inherited correctly when rmcp spawns
// child tasks via `tokio::spawn` inside a scope — the child observes
// the parent's task-local value at spawn time.
//
// The previous story shipped a literal `"mcp-client-unattributed"`
// sentinel at three call sites and deferred the real plumbing. The
// sentinel is retained here ONLY for the genuinely unreachable path
// (tool called outside any `AgentIdScopedMcpService::call` scope —
// which should never happen in production because the canonical
// middleware chain routes every MCP request through the adapter).
// An audit event with `agent_id="mcp-client-unattributed"` is a
// grep-distinguishable red flag rather than a silent panic.

tokio::task_local! {
    /// The agent ID stamped onto the inbound rmcp request by the
    /// outer [`AgentIdScopedMcpService`] adapter. Read by tool method
    /// bodies via [`current_mcp_agent_id`] when they build a
    /// `ProxyRequest`.
    ///
    /// ONLY set while a request is in flight inside the adapter's
    /// `call`. Outside a scope, [`current_mcp_agent_id`] returns the
    /// `"mcp-client-unattributed"` sentinel — see the module-level
    /// comment for why the fallback exists.
    static CURRENT_AGENT_ID: String;
}

/// The `agent_id` value used by the MCP tool dispatch path when no
/// `AgentId` extension was threaded through (via the
/// [`AgentIdScopedMcpService`] adapter). This should NEVER appear in
/// a production audit log — `AuthLayer` populates `AgentId` on every
/// authenticated request and the adapter stamps it into the
/// task-local before calling rmcp. Seeing this sentinel in the wild
/// means either the middleware chain was misassembled or the tool
/// was invoked outside the adapter (e.g., from a test harness that
/// bypasses the transport layer).
pub(crate) const MCP_UNATTRIBUTED_SENTINEL: &str = "mcp-client-unattributed";

/// Read the current agent ID from the task-local set by
/// [`AgentIdScopedMcpService`]. Returns `MCP_UNATTRIBUTED_SENTINEL`
/// when the task-local is unset (tool invoked outside a scope).
fn current_mcp_agent_id() -> String {
    CURRENT_AGENT_ID.try_with(Clone::clone).unwrap_or_else(|_| MCP_UNATTRIBUTED_SENTINEL.to_owned())
}

/// Tower adapter that threads the `AgentId` extension from an inbound
/// axum `Request<Body>` into a tokio task-local so that rmcp tool
/// dispatch method bodies can read it when they build a `ProxyRequest`.
///
/// Wraps any inner `tower::Service<Request<Body>>` — in practice
/// rmcp's `StreamableHttpService`. The wrapper is transparent
/// (same `Response`, `Error`, `Future` types) so it drops in to
/// `axum::Router::nest_service(...)` without any call-site changes.
pub struct AgentIdScopedMcpService<S> {
    inner: S,
}

impl<S: Clone> Clone for AgentIdScopedMcpService<S> {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone() }
    }
}

impl<S> AgentIdScopedMcpService<S> {
    /// Wrap an inner rmcp tower service with the task-local scoping
    /// adapter.
    #[must_use]
    pub fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S, ResBody> Service<Request<Body>> for AgentIdScopedMcpService<S>
where
    S: Service<Request<Body>, Response = Response<ResBody>, Error = Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
    ResBody: Send + 'static,
{
    type Response = Response<ResBody>;
    type Error = Infallible;
    type Future =
        Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        // Read the agent ID from the inbound request's extensions.
        // `AuthLayer` populates `AgentId` on every authenticated
        // request before the middleware chain reaches the nested
        // rmcp service. Missing means the request bypassed auth
        // (operational path) or the middleware chain was misassembled
        // — either way we fall through to the sentinel.
        let agent_id = req.extensions().get::<AgentId>().map(|a| a.0.clone());

        // Swap inner services to satisfy Service's "call after
        // poll_ready" contract — the standard tower pattern for
        // cloneable inner services. See `AuthService::call` for the
        // same pattern.
        let inner_clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, inner_clone);

        Box::pin(async move {
            let fut = inner.call(req);
            match agent_id {
                Some(id) => CURRENT_AGENT_ID.scope(id, fut).await,
                None => fut.await,
            }
        })
    }
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

    /// Build a `ProxyRequest` for a Gmail GET endpoint.
    ///
    /// # `agent_id` discipline (Story 4.4 Patch #29)
    ///
    /// Reads the real `AgentId` from the `CURRENT_AGENT_ID`
    /// task-local stamped by [`AgentIdScopedMcpService`]. If the
    /// task-local is unset (tool called outside an adapter scope —
    /// should be structurally impossible in production), falls
    /// through to `MCP_UNATTRIBUTED_SENTINEL` so the event shows
    /// up in audit logs as an obvious red flag rather than
    /// panicking.
    pub fn gmail_request(path: String, scope: &str) -> ProxyRequest {
        ProxyRequest {
            service: "gmail".to_owned(),
            scope: scope.to_owned(),
            resource: path.clone(),
            method: Method::GET,
            path,
            headers: HeaderMap::new(),
            body: Bytes::new(),
            agent_id: current_mcp_agent_id(),
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

/// Validate that a JSON write body is a non-empty object.
///
/// Rejects `null`, primitives, arrays, and empty objects (`{}`). Google
/// Calendar/Drive write endpoints expect a JSON object resource; sending
/// `null` or `{}` produces an opaque Google 400. This pre-rejects at the
/// MCP boundary with a clear error message.
fn validate_json_object_body(value: &serde_json::Value, field: &str) -> Result<(), String> {
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
    ) -> Result<String, String> {
        debug!(tool = "gmail.messages.list", "MCP tool call");
        let qs = build_query_string(&[
            ("maxResults", params.max_results.map(|n| n.to_string())),
            ("pageToken", params.page_token),
            ("labelIds", params.label_ids.map(|ids| ids.join(","))),
            ("q", params.q),
            ("includeSpamTrash", params.include_spam_trash.map(|b| b.to_string())),
        ]);
        let path = format!("users/me/messages{qs}");
        let req = Self::gmail_request(path, "gmail.readonly");
        self.dispatch(req).await
    }

    #[tool(
        name = "gmail.messages.get",
        description = "Get a specific Gmail message by ID. Returns full message content."
    )]
    async fn messages_get(
        &self,
        Parameters(params): Parameters<MessagesGetParams>,
    ) -> Result<String, String> {
        debug!(tool = "gmail.messages.get", id = %params.id, "MCP tool call");
        validate_resource_id(&params.id)?;
        let qs = build_query_string(&[
            ("format", params.format),
            ("metadataHeaders", params.metadata_headers.map(|h| h.join(","))),
        ]);
        let path = format!("users/me/messages/{}{qs}", params.id);
        let req = Self::gmail_request(path, "gmail.readonly");
        self.dispatch(req).await
    }

    #[tool(
        name = "gmail.threads.list",
        description = "List Gmail threads. Returns thread IDs and snippets."
    )]
    async fn threads_list(
        &self,
        Parameters(params): Parameters<ThreadsListParams>,
    ) -> Result<String, String> {
        debug!(tool = "gmail.threads.list", "MCP tool call");
        let qs = build_query_string(&[
            ("maxResults", params.max_results.map(|n| n.to_string())),
            ("pageToken", params.page_token),
            ("labelIds", params.label_ids.map(|ids| ids.join(","))),
            ("q", params.q),
        ]);
        let path = format!("users/me/threads{qs}");
        let req = Self::gmail_request(path, "gmail.readonly");
        self.dispatch(req).await
    }

    #[tool(
        name = "gmail.threads.get",
        description = "Get a specific Gmail thread by ID. Returns all messages in the thread."
    )]
    async fn threads_get(
        &self,
        Parameters(params): Parameters<ThreadsGetParams>,
    ) -> Result<String, String> {
        debug!(tool = "gmail.threads.get", id = %params.id, "MCP tool call");
        validate_resource_id(&params.id)?;
        let qs = build_query_string(&[("format", params.format)]);
        let path = format!("users/me/threads/{}{qs}", params.id);
        let req = Self::gmail_request(path, "gmail.readonly");
        self.dispatch(req).await
    }

    #[tool(
        name = "gmail.search",
        description = "Search Gmail messages using Gmail search syntax. Returns matching message IDs."
    )]
    async fn search(&self, Parameters(params): Parameters<SearchParams>) -> Result<String, String> {
        debug!(tool = "gmail.search", query = %params.query, "MCP tool call");
        let qs = build_query_string(&[
            ("q", Some(params.query)),
            ("maxResults", params.max_results.map(|n| n.to_string())),
            ("pageToken", params.page_token),
        ]);
        let path = format!("users/me/messages{qs}");
        let req = Self::gmail_request(path, "gmail.readonly");
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

/// Build an MCP service for the Gmail connector, wrapped in the
/// [`AgentIdScopedMcpService`] adapter so tool method bodies see the
/// real bearer agent via the `CURRENT_AGENT_ID` task-local.
///
/// The returned service implements `tower::Service<Request<Body>>`
/// and can be mounted into axum via
/// `Router::new().nest_service("/mcp", service)`.
pub fn mcp_service(
    proxy_service: Arc<ProxyService>,
) -> AgentIdScopedMcpService<
    rmcp::transport::streamable_http_server::tower::StreamableHttpService<
        GmailMcpServer,
        rmcp::transport::streamable_http_server::session::local::LocalSessionManager,
    >,
> {
    use rmcp::transport::streamable_http_server::{
        session::local::LocalSessionManager,
        tower::{StreamableHttpServerConfig, StreamableHttpService},
    };

    let inner = StreamableHttpService::new(
        move || Ok(GmailMcpServer::new(Arc::clone(&proxy_service))),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    );
    AgentIdScopedMcpService::new(inner)
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
    /// Reads the real `AgentId` from the `CURRENT_AGENT_ID`
    /// task-local (see Story 4.4 Patch #29 and the `gmail_request`
    /// doc comment for the full rationale).
    fn calendar_request(path: String, scope: &str, method: Method, body: Bytes) -> ProxyRequest {
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
            agent_id: current_mcp_agent_id(),
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
    ) -> Result<String, String> {
        debug!(tool = "calendar.calendars.list", "MCP tool call");
        let qs = build_query_string(&[
            ("maxResults", params.max_results.map(|n| n.to_string())),
            ("pageToken", params.page_token),
        ]);
        let path = format!("users/me/calendarList{qs}");
        let req = Self::calendar_request(path, "calendar.readonly", Method::GET, Bytes::new());
        self.dispatch(req).await
    }

    #[tool(
        name = "calendar.events.list",
        description = "List events on a calendar. Returns event summaries, times, and IDs."
    )]
    async fn events_list(
        &self,
        Parameters(params): Parameters<EventsListParams>,
    ) -> Result<String, String> {
        let cal_id = params.calendar_id.as_deref().unwrap_or("primary");
        debug!(tool = "calendar.events.list", calendar_id = %cal_id, "MCP tool call");
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
        let req = Self::calendar_request(path, "calendar.readonly", Method::GET, Bytes::new());
        self.dispatch(req).await
    }

    #[tool(name = "calendar.events.get", description = "Get a specific calendar event by ID.")]
    async fn events_get(
        &self,
        Parameters(params): Parameters<EventGetParams>,
    ) -> Result<String, String> {
        let cal_id = params.calendar_id.as_deref().unwrap_or("primary");
        debug!(tool = "calendar.events.get", calendar_id = %cal_id, event_id = %params.event_id, "MCP tool call");
        validate_calendar_id(cal_id, "calendar_id")?;
        validate_resource_id(&params.event_id)?;
        let encoded_cal_id = urlencoding::encode(cal_id);
        let encoded_event_id = urlencoding::encode(&params.event_id);
        let path = format!("calendars/{encoded_cal_id}/events/{encoded_event_id}");
        let req = Self::calendar_request(path, "calendar.readonly", Method::GET, Bytes::new());
        self.dispatch(req).await
    }

    #[tool(
        name = "calendar.events.create",
        description = "Create a new event on a calendar. Pass the event as a JSON object with summary, start, end, etc."
    )]
    async fn events_create(
        &self,
        Parameters(params): Parameters<EventCreateParams>,
    ) -> Result<String, String> {
        let cal_id = params.calendar_id.as_deref().unwrap_or("primary");
        debug!(tool = "calendar.events.create", calendar_id = %cal_id, "MCP tool call");
        validate_calendar_id(cal_id, "calendar_id")?;
        validate_json_object_body(&params.event, "event")?;
        let body =
            serde_json::to_vec(&params.event).map_err(|e| format!("invalid event JSON: {e}"))?;
        let encoded_cal_id = urlencoding::encode(cal_id);
        let path = format!("calendars/{encoded_cal_id}/events");
        let req = Self::calendar_request(path, "calendar.events", Method::POST, Bytes::from(body));
        self.dispatch(req).await
    }

    #[tool(
        name = "calendar.events.update",
        description = "Update an existing calendar event. Uses HTTP PUT semantics: pass the FULL event resource as a JSON object — any field omitted from the body will be CLEARED on the server. To safely modify a single field, fetch the event first with calendar.events.get, modify the returned object, and pass the complete result back here."
    )]
    async fn events_update(
        &self,
        Parameters(params): Parameters<EventUpdateParams>,
    ) -> Result<String, String> {
        let cal_id = params.calendar_id.as_deref().unwrap_or("primary");
        debug!(tool = "calendar.events.update", calendar_id = %cal_id, event_id = %params.event_id, "MCP tool call");
        validate_calendar_id(cal_id, "calendar_id")?;
        validate_resource_id(&params.event_id)?;
        validate_json_object_body(&params.event, "event")?;
        let body =
            serde_json::to_vec(&params.event).map_err(|e| format!("invalid event JSON: {e}"))?;
        let encoded_cal_id = urlencoding::encode(cal_id);
        let encoded_event_id = urlencoding::encode(&params.event_id);
        let path = format!("calendars/{encoded_cal_id}/events/{encoded_event_id}");
        let req = Self::calendar_request(path, "calendar.events", Method::PUT, Bytes::from(body));
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

/// Build an MCP service for the Calendar connector, wrapped in the
/// [`AgentIdScopedMcpService`] adapter.
pub fn calendar_mcp_service(
    proxy_service: Arc<ProxyService>,
) -> AgentIdScopedMcpService<
    rmcp::transport::streamable_http_server::tower::StreamableHttpService<
        CalendarMcpServer,
        rmcp::transport::streamable_http_server::session::local::LocalSessionManager,
    >,
> {
    use rmcp::transport::streamable_http_server::{
        session::local::LocalSessionManager,
        tower::{StreamableHttpServerConfig, StreamableHttpService},
    };

    let inner = StreamableHttpService::new(
        move || Ok(CalendarMcpServer::new(Arc::clone(&proxy_service))),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    );
    AgentIdScopedMcpService::new(inner)
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
    /// Reads the real `AgentId` from the `CURRENT_AGENT_ID`
    /// task-local (see Story 4.4 Patch #29 and the `gmail_request`
    /// doc comment for the full rationale).
    fn drive_request(path: String, scope: &str, method: Method, body: Bytes) -> ProxyRequest {
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
            agent_id: current_mcp_agent_id(),
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
    ) -> Result<String, String> {
        debug!(tool = "drive.files.list", "MCP tool call");
        let qs = build_query_string(&[
            ("pageSize", params.page_size.map(|n| n.to_string())),
            ("pageToken", params.page_token),
            ("q", params.q),
            ("orderBy", params.order_by),
            ("fields", params.fields),
        ]);
        let path = format!("files{qs}");
        let req = Self::drive_request(path, "drive.readonly", Method::GET, Bytes::new());
        self.dispatch(req).await
    }

    #[tool(
        name = "drive.files.get",
        description = "Get a file's metadata or content from Google Drive. Set alt='media' to download content."
    )]
    async fn files_get(
        &self,
        Parameters(params): Parameters<FileGetParams>,
    ) -> Result<String, String> {
        debug!(tool = "drive.files.get", file_id = %params.file_id, "MCP tool call");
        validate_resource_id(&params.file_id)?;
        let qs = build_query_string(&[("fields", params.fields), ("alt", params.alt)]);
        let encoded_file_id = urlencoding::encode(&params.file_id);
        let path = format!("files/{encoded_file_id}{qs}");
        let req = Self::drive_request(path, "drive.readonly", Method::GET, Bytes::new());
        self.dispatch(req).await
    }

    #[tool(
        name = "drive.files.search",
        description = "Search for files in Google Drive using Drive search syntax. Requires a search query."
    )]
    async fn files_search(
        &self,
        Parameters(params): Parameters<FilesSearchParams>,
    ) -> Result<String, String> {
        debug!(tool = "drive.files.search", query = %params.q, "MCP tool call");
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
        let req = Self::drive_request(path, "drive.readonly", Method::GET, Bytes::new());
        self.dispatch(req).await
    }

    #[tool(
        name = "drive.files.create",
        description = "Create a new file in Google Drive (metadata-only — does not upload content). Pass a JSON file resource with at minimum a 'name'. Use 'mimeType': 'application/vnd.google-apps.folder' to create a folder. Limited to files owned by the app per the drive.file scope."
    )]
    async fn files_create(
        &self,
        Parameters(params): Parameters<FileCreateParams>,
    ) -> Result<String, String> {
        debug!(tool = "drive.files.create", "MCP tool call");
        validate_json_object_body(&params.file, "file")?;
        let body =
            serde_json::to_vec(&params.file).map_err(|e| format!("invalid file JSON: {e}"))?;
        let qs = build_query_string(&[("fields", params.fields)]);
        let path = format!("files{qs}");
        let req = Self::drive_request(path, "drive.file", Method::POST, Bytes::from(body));
        self.dispatch(req).await
    }

    #[tool(
        name = "drive.files.update",
        description = "Update file metadata in Google Drive (rename, move, change description). Pass a JSON patch document with the fields to update. Limited to files the app created or opened per the drive.file scope. Does NOT update file content."
    )]
    async fn files_update(
        &self,
        Parameters(params): Parameters<FileUpdateParams>,
    ) -> Result<String, String> {
        debug!(tool = "drive.files.update", file_id = %params.file_id, "MCP tool call");
        validate_resource_id(&params.file_id)?;
        validate_json_object_body(&params.file, "file")?;
        let body =
            serde_json::to_vec(&params.file).map_err(|e| format!("invalid file JSON: {e}"))?;
        let qs = build_query_string(&[("fields", params.fields)]);
        let encoded_file_id = urlencoding::encode(&params.file_id);
        let path = format!("files/{encoded_file_id}{qs}");
        let req = Self::drive_request(path, "drive.file", Method::PATCH, Bytes::from(body));
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

/// Build an MCP service for the Drive connector, wrapped in the
/// [`AgentIdScopedMcpService`] adapter.
pub fn drive_mcp_service(
    proxy_service: Arc<ProxyService>,
) -> AgentIdScopedMcpService<
    rmcp::transport::streamable_http_server::tower::StreamableHttpService<
        DriveMcpServer,
        rmcp::transport::streamable_http_server::session::local::LocalSessionManager,
    >,
> {
    use rmcp::transport::streamable_http_server::{
        session::local::LocalSessionManager,
        tower::{StreamableHttpServerConfig, StreamableHttpService},
    };

    let inner = StreamableHttpService::new(
        move || Ok(DriveMcpServer::new(Arc::clone(&proxy_service))),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    );
    AgentIdScopedMcpService::new(inner)
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
        let v = serde_json::json!({"name": "test"});
        assert!(validate_json_object_body(&v, "field").is_ok());
    }

    #[test]
    fn validate_json_object_body_rejects_null() {
        let v = serde_json::Value::Null;
        let err = validate_json_object_body(&v, "event").unwrap_err();
        assert!(err.contains("event"), "error mentions field name: {err}");
        assert!(err.contains("null"), "error mentions null: {err}");
    }

    #[test]
    fn validate_json_object_body_rejects_empty_object() {
        let v = serde_json::json!({});
        let err = validate_json_object_body(&v, "file").unwrap_err();
        assert!(err.contains("empty"), "error mentions empty: {err}");
    }

    #[test]
    fn validate_json_object_body_rejects_array() {
        let v = serde_json::json!([1, 2, 3]);
        let err = validate_json_object_body(&v, "file").unwrap_err();
        assert!(err.contains("object"), "error mentions object expectation: {err}");
        assert!(err.contains("array"), "error mentions actual type: {err}");
    }

    #[test]
    fn validate_json_object_body_rejects_primitives() {
        assert!(validate_json_object_body(&serde_json::json!("string"), "f").is_err());
        assert!(validate_json_object_body(&serde_json::json!(42), "f").is_err());
        assert!(validate_json_object_body(&serde_json::json!(true), "f").is_err());
    }

    // ── Story 4.4 Patch #29: AgentIdScopedMcpService tests ─────────

    #[tokio::test]
    async fn current_mcp_agent_id_returns_sentinel_outside_scope() {
        // No task-local set — builder falls through to the sentinel.
        assert_eq!(current_mcp_agent_id(), MCP_UNATTRIBUTED_SENTINEL);
    }

    #[tokio::test]
    async fn current_mcp_agent_id_reads_task_local_inside_scope() {
        // Inside a scope, the builder sees the real agent name.
        CURRENT_AGENT_ID
            .scope("email-triage".to_owned(), async {
                assert_eq!(current_mcp_agent_id(), "email-triage");
            })
            .await;
    }

    #[tokio::test]
    async fn gmail_request_picks_up_task_local_agent_id() {
        CURRENT_AGENT_ID
            .scope("research-agent".to_owned(), async {
                let req =
                    GmailMcpServer::gmail_request("users/me/messages".to_owned(), "gmail.readonly");
                assert_eq!(req.agent_id, "research-agent");
                assert_eq!(req.service, "gmail");
                assert_eq!(req.scope, "gmail.readonly");
            })
            .await;
    }

    #[tokio::test]
    async fn gmail_request_outside_scope_falls_back_to_sentinel() {
        // Invariant: tool invoked outside an adapter scope (should be
        // structurally impossible in production) still produces a
        // valid ProxyRequest, just with the grep-distinguishable
        // sentinel agent_id.
        let req = GmailMcpServer::gmail_request("users/me/messages".to_owned(), "gmail.readonly");
        assert_eq!(req.agent_id, MCP_UNATTRIBUTED_SENTINEL);
    }

    #[tokio::test]
    async fn calendar_request_picks_up_task_local_agent_id() {
        CURRENT_AGENT_ID
            .scope("calendar-agent".to_owned(), async {
                let req = CalendarMcpServer::calendar_request(
                    "users/me/calendarList".to_owned(),
                    "https://www.googleapis.com/auth/calendar.readonly",
                    Method::GET,
                    Bytes::new(),
                );
                assert_eq!(req.agent_id, "calendar-agent");
                assert_eq!(req.service, "calendar");
            })
            .await;
    }

    #[tokio::test]
    async fn drive_request_picks_up_task_local_agent_id() {
        CURRENT_AGENT_ID
            .scope("drive-agent".to_owned(), async {
                let req = DriveMcpServer::drive_request(
                    "files".to_owned(),
                    "https://www.googleapis.com/auth/drive.readonly",
                    Method::GET,
                    Bytes::new(),
                );
                assert_eq!(req.agent_id, "drive-agent");
                assert_eq!(req.service, "drive");
            })
            .await;
    }

    #[tokio::test]
    async fn task_local_is_per_task_not_global() {
        // Two concurrent tasks with different scoped agent IDs must
        // not see each other's values. Proves tokio task-locals give
        // us per-request isolation (the whole point of this design
        // over `Arc<Mutex<Option<AgentId>>>`).
        let task_a = tokio::spawn(CURRENT_AGENT_ID.scope("agent-a".to_owned(), async {
            // Small yield so task B gets scheduled in between.
            tokio::task::yield_now().await;
            current_mcp_agent_id()
        }));
        let task_b = tokio::spawn(CURRENT_AGENT_ID.scope("agent-b".to_owned(), async {
            tokio::task::yield_now().await;
            current_mcp_agent_id()
        }));
        let a_result = task_a.await.unwrap();
        let b_result = task_b.await.unwrap();
        assert_eq!(a_result, "agent-a");
        assert_eq!(b_result, "agent-b");
    }

    #[tokio::test]
    async fn agent_id_scoped_service_stamps_task_local_from_extension() {
        // Minimal inner service that reads CURRENT_AGENT_ID and
        // returns it in the response body. Proves the adapter
        // actually sets the task-local before calling the inner.
        use axum::body::to_bytes;
        use tower::ServiceExt as _;

        #[derive(Clone)]
        struct RecordingService;
        impl Service<Request<Body>> for RecordingService {
            type Response = Response<Body>;
            type Error = Infallible;
            type Future = Pin<
                Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
            >;
            fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
                Poll::Ready(Ok(()))
            }
            fn call(&mut self, _req: Request<Body>) -> Self::Future {
                Box::pin(async move {
                    let observed = current_mcp_agent_id();
                    Ok(Response::new(Body::from(observed)))
                })
            }
        }

        let mut svc = AgentIdScopedMcpService::new(RecordingService);

        // (a) With AgentId extension → inner observes the real name.
        let mut req = Request::builder().uri("/test").body(Body::empty()).unwrap();
        req.extensions_mut().insert(AgentId("email-triage".to_owned()));
        let resp = svc.ready().await.unwrap().call(req).await.unwrap();
        let body_bytes = to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(&body_bytes[..], b"email-triage");

        // (b) Without AgentId extension → inner sees the sentinel.
        let req = Request::builder().uri("/test").body(Body::empty()).unwrap();
        let resp = svc.ready().await.unwrap().call(req).await.unwrap();
        let body_bytes = to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(&body_bytes[..], MCP_UNATTRIBUTED_SENTINEL.as_bytes());
    }
}
