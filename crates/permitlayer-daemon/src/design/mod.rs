//! Design system: tokens, themes, terminal detection, formatting, and rendering.
//!
//! All CLI surfaces use this module for consistent visual language. Color tokens
//! are generated from `tokens.json` at build time — see `build.rs`.

// Many public functions are intentionally unused within this story — they form
// the design-system API consumed by subsequent stories (audit tables, scrub
// views, kill banner, etc.).
#[allow(dead_code)]
pub mod format;
#[allow(dead_code)]
pub mod kill_banner;
#[allow(dead_code)]
pub mod render;
#[allow(dead_code)]
pub mod scrub_inline;
#[allow(dead_code)]
pub mod terminal;
pub mod theme;

#[path = "generated_tokens.rs"]
#[allow(dead_code)]
pub mod tokens;
