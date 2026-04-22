// Story 6.3: built-in Gmail connector placeholder.
//
// The loader parses `metadata` and registers this connector so
// `agentsso connectors list` shows it and FR38 ("System loads JS
// connector plugins from `~/.agentsso/plugins/` at daemon start")
// has an end-to-end proof-of-concept. The JS port of Gmail's tools
// (metadata -> auth -> tools) is a later story; until then, the
// proxy's hand-rolled Rust MCP service at
// `crates/permitlayer-proxy/src/transport/mcp/gmail.rs` remains the
// production dispatch path. Removing either file without the other
// will regress FR39 ("ships with built-in Gmail connector").
export const metadata = {
    name: "google-gmail",
    version: "0.0.1",
    apiVersion: ">=1.0",
    scopes: ["gmail.readonly", "gmail.search", "gmail.modify"],
    description: "Google Gmail connector (stub; dispatch via Rust MCP service until JS tools port lands)",
};
