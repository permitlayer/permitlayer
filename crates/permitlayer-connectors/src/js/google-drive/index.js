// Story 6.3: built-in Drive connector placeholder.
//
// See `google-gmail/index.js` for the rationale behind the
// metadata-only placeholder shape; the proxy's hand-rolled Rust
// MCP service at
// `crates/permitlayer-proxy/src/transport/mcp/drive.rs` remains
// the production dispatch path until the JS tools port lands.
export const metadata = {
    name: "google-drive",
    version: "0.0.1",
    apiVersion: ">=1.0",
    scopes: ["drive.readonly", "drive.file"],
    description: "Google Drive connector (stub; dispatch via Rust MCP service until JS tools port lands)",
};
