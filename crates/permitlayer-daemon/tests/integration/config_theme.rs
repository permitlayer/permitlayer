//! Integration test: `agentsso config set theme=<name>` persists and reads back.

use std::process::Command;

/// Run `agentsso config set theme=molt` and verify `ui.toml` is written.
#[test]
fn config_set_theme_persists() {
    let tmp = tempfile::tempdir().expect("create tempdir");
    let home = tmp.path();

    // Set theme to molt.
    let output = Command::new(env!("CARGO_BIN_EXE_agentsso"))
        .args(["config", "set", "theme=molt"])
        .env("AGENTSSO_PATHS__HOME", home.as_os_str())
        .output()
        .expect("run agentsso config set");

    assert!(
        output.status.success(),
        "config set failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("theme set to molt"), "stdout: {stdout}");

    // Verify ui.toml was written.
    let ui_toml = home.join("config").join("ui.toml");
    assert!(ui_toml.exists(), "ui.toml should exist");
    let contents = std::fs::read_to_string(&ui_toml).expect("read ui.toml");
    assert!(contents.contains("molt"), "ui.toml: {contents}");

    // Read it back.
    let output = Command::new(env!("CARGO_BIN_EXE_agentsso"))
        .args(["config", "get", "theme"])
        .env("AGENTSSO_PATHS__HOME", home.as_os_str())
        .output()
        .expect("run agentsso config get");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim(), "molt");
}

/// Verify invalid theme is rejected.
#[test]
fn config_set_invalid_theme_rejected() {
    let tmp = tempfile::tempdir().expect("create tempdir");
    let home = tmp.path();

    let output = Command::new(env!("CARGO_BIN_EXE_agentsso"))
        .args(["config", "set", "theme=invalid"])
        .env("AGENTSSO_PATHS__HOME", home.as_os_str())
        .output()
        .expect("run agentsso config set");

    assert!(!output.status.success(), "should reject invalid theme");
}

/// Verify default theme is carapace when no ui.toml exists.
#[test]
fn config_get_default_theme() {
    let tmp = tempfile::tempdir().expect("create tempdir");
    let home = tmp.path();

    let output = Command::new(env!("CARGO_BIN_EXE_agentsso"))
        .args(["config", "get", "theme"])
        .env("AGENTSSO_PATHS__HOME", home.as_os_str())
        .output()
        .expect("run agentsso config get");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim(), "carapace");
}
