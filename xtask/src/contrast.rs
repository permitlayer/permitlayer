//! WCAG 2.2 AA contrast ratio validation for design tokens.
//!
//! Loads `tokens.json`, computes relative luminance for each text/background
//! pair per theme, and asserts minimum contrast ratios.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};

/// Required contrast ratios per WCAG 2.2 AA.
const TEXT_CONTRAST_MIN: f64 = 4.5;
const UI_CONTRAST_MIN: f64 = 3.0;

/// Text-on-background pairs to validate (text token, background token, minimum ratio).
const PAIRS: &[(&str, &str, f64)] = &[
    ("text-0", "bg-0", TEXT_CONTRAST_MIN),
    ("text-1", "bg-0", TEXT_CONTRAST_MIN),
    ("text-2", "bg-1", TEXT_CONTRAST_MIN),
    ("accent", "bg-0", UI_CONTRAST_MIN),
    ("warn", "bg-0", UI_CONTRAST_MIN),
    ("danger", "bg-0", UI_CONTRAST_MIN),
    ("success", "bg-0", UI_CONTRAST_MIN),
    ("info", "bg-0", UI_CONTRAST_MIN),
];

pub fn run() -> Result<()> {
    let tokens_path = Path::new("tokens.json");
    let contents = std::fs::read_to_string(tokens_path).context("failed to read tokens.json")?;

    let root: serde_json::Value =
        serde_json::from_str(&contents).context("tokens.json is not valid JSON")?;

    let colors = root["color"].as_object().context("tokens.json: missing `color` object")?;

    let mut failures = Vec::new();
    let mut checked = 0u32;

    for (theme_name, theme_value) in colors {
        let tokens: BTreeMap<String, String> = theme_value
            .as_object()
            .context(format!("theme `{theme_name}` is not an object"))?
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    v.as_str()
                        .unwrap_or_else(|| panic!("token {k} in {theme_name} is not a string"))
                        .to_owned(),
                )
            })
            .collect();

        for &(fg_token, bg_token, min_ratio) in PAIRS {
            let Some(fg_hex) = tokens.get(fg_token) else {
                failures.push(format!("{theme_name}: missing token `{fg_token}`"));
                continue;
            };
            let Some(bg_hex) = tokens.get(bg_token) else {
                failures.push(format!("{theme_name}: missing token `{bg_token}`"));
                continue;
            };

            let fg_lum = relative_luminance(fg_hex);
            let bg_lum = relative_luminance(bg_hex);
            let ratio = contrast_ratio(fg_lum, bg_lum);

            checked += 1;

            if ratio < min_ratio {
                failures.push(format!(
                    "{theme_name}: {fg_token} ({fg_hex}) on {bg_token} ({bg_hex}): \
                     ratio {ratio:.2}:1 < required {min_ratio}:1"
                ));
            }
        }
    }

    println!("Checked {checked} contrast pairs across {} themes", colors.len());

    if failures.is_empty() {
        println!("All pairs pass WCAG 2.2 AA contrast requirements.");
        Ok(())
    } else {
        for f in &failures {
            eprintln!("  FAIL: {f}");
        }
        anyhow::bail!("{} contrast pair(s) failed WCAG 2.2 AA requirements", failures.len());
    }
}

/// Compute WCAG relative luminance from a hex color string.
///
/// Formula: `L = 0.2126*R + 0.7152*G + 0.0722*B` with sRGB linearization.
fn relative_luminance(hex: &str) -> f64 {
    let hex = hex.strip_prefix('#').unwrap_or(hex);
    let r = u8::from_str_radix(&hex[0..2], 16).unwrap_or(0);
    let g = u8::from_str_radix(&hex[2..4], 16).unwrap_or(0);
    let b = u8::from_str_radix(&hex[4..6], 16).unwrap_or(0);

    let r_lin = linearize(r);
    let g_lin = linearize(g);
    let b_lin = linearize(b);

    0.2126 * r_lin + 0.7152 * g_lin + 0.0722 * b_lin
}

/// sRGB linearization: convert 0-255 channel to linear 0.0-1.0.
fn linearize(channel: u8) -> f64 {
    let s = channel as f64 / 255.0;
    if s <= 0.04045 { s / 12.92 } else { ((s + 0.055) / 1.055).powf(2.4) }
}

/// WCAG contrast ratio: `(L1 + 0.05) / (L2 + 0.05)` where L1 >= L2.
fn contrast_ratio(lum1: f64, lum2: f64) -> f64 {
    let (lighter, darker) = if lum1 >= lum2 { (lum1, lum2) } else { (lum2, lum1) };
    (lighter + 0.05) / (darker + 0.05)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn black_on_white_max_contrast() {
        let black = relative_luminance("#000000");
        let white = relative_luminance("#FFFFFF");
        let ratio = contrast_ratio(white, black);
        assert!((ratio - 21.0).abs() < 0.1, "expected ~21:1, got {ratio}");
    }

    #[test]
    fn same_color_min_contrast() {
        let lum = relative_luminance("#808080");
        let ratio = contrast_ratio(lum, lum);
        assert!((ratio - 1.0).abs() < 0.01, "expected ~1:1, got {ratio}");
    }

    #[test]
    fn carapace_text0_on_bg0() {
        // #F4F5F7 on #0E1014 should have high contrast.
        let fg = relative_luminance("#F4F5F7");
        let bg = relative_luminance("#0E1014");
        let ratio = contrast_ratio(fg, bg);
        assert!(
            ratio >= TEXT_CONTRAST_MIN,
            "carapace text-0 on bg-0: {ratio:.2}:1 < {TEXT_CONTRAST_MIN}:1"
        );
    }
}
