// Story 6.3: built-in Calendar connector placeholder.
//
// See `google-gmail/index.js` for the rationale behind the
// metadata-only placeholder shape; the proxy's hand-rolled Rust
// MCP service at
// `crates/permitlayer-proxy/src/transport/mcp/calendar.rs` remains
// the production dispatch path until the JS tools port lands.
export const metadata = {
    name: "google-calendar",
    version: "0.0.1",
    apiVersion: ">=1.0",
    scopes: ["calendar.readonly", "calendar.events"],
    description: "Google Calendar connector (stub; dispatch via Rust MCP service until JS tools port lands)",
};
