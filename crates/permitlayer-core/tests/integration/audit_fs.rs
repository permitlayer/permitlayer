//! Integration tests for the audit filesystem store.
//!
//! Tests cover: single append, concurrency (NFR42), size-based rotation,
//! date-based rotation, retention sweep, JSON validity, and schema version.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use permitlayer_core::audit::event::{AUDIT_SCHEMA_VERSION, AuditEvent};
use permitlayer_core::scrub::{ScrubEngine, builtin_rules};
use permitlayer_core::store::AuditStore;
use permitlayer_core::store::fs::AuditFsStore;
use tempfile::TempDir;

fn test_scrub_engine() -> Arc<ScrubEngine> {
    Arc::new(ScrubEngine::new(builtin_rules().to_vec()).expect("builtin rules must compile"))
}

fn test_event() -> AuditEvent {
    AuditEvent::new(
        "agent-integration".into(),
        "gmail".into(),
        "mail.readonly".into(),
        "messages/test".into(),
        "ok".into(),
        "api-call".into(),
    )
}

#[tokio::test]
async fn single_append_creates_jsonl_file() {
    let tmp = TempDir::new().unwrap();
    let audit_dir = tmp.path().join("audit");
    let store =
        AuditFsStore::new(audit_dir.clone(), 100 * 1024 * 1024, test_scrub_engine()).unwrap();

    store.append(test_event()).await.unwrap();

    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let file_path = audit_dir.join(format!("{today}.jsonl"));
    assert!(file_path.exists());

    let content = std::fs::read_to_string(&file_path).unwrap();
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(lines.len(), 1);

    // Verify valid JSON and correct type.
    let event: AuditEvent = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(event.service, "gmail");
    assert_eq!(event.event_type, "api-call");
}

#[tokio::test]
async fn concurrent_appends_produce_exact_count() {
    let tmp = TempDir::new().unwrap();
    let audit_dir = tmp.path().join("audit");
    let store = std::sync::Arc::new(
        AuditFsStore::new(audit_dir.clone(), 100 * 1024 * 1024, test_scrub_engine()).unwrap(),
    );

    let mut handles = Vec::new();
    for i in 0..1000 {
        let store = store.clone();
        handles.push(tokio::spawn(async move {
            let event = AuditEvent::new(
                format!("agent-{i}"),
                "gmail".into(),
                "mail.readonly".into(),
                format!("messages/{i}"),
                "ok".into(),
                "api-call".into(),
            );
            store.append(event).await.unwrap();
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }

    // Count total entries across all files and validate each is valid JSON.
    let mut total_entries = 0;
    for entry in std::fs::read_dir(&audit_dir).unwrap() {
        let entry = entry.unwrap();
        let content = std::fs::read_to_string(entry.path()).unwrap();
        for line in content.lines() {
            let event: AuditEvent = serde_json::from_str(line).unwrap_or_else(|e| {
                panic!("invalid AuditEvent JSON under concurrency: {e}\nline: {line}")
            });
            assert_eq!(event.schema_version, AUDIT_SCHEMA_VERSION);
            total_entries += 1;
        }
    }

    assert_eq!(total_entries, 1000, "NFR42: exactly 1000 entries expected, got {total_entries}");
}

#[tokio::test]
async fn size_rotation_triggers_at_threshold() {
    let tmp = TempDir::new().unwrap();
    let audit_dir = tmp.path().join("audit");
    // Very small threshold to trigger rotation.
    let store = AuditFsStore::new(audit_dir.clone(), 100, test_scrub_engine()).unwrap();

    for _ in 0..20 {
        store.append(test_event()).await.unwrap();
    }

    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let entries: Vec<String> = std::fs::read_dir(&audit_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();

    // Should have rotated files.
    let rotated: Vec<&String> = entries
        .iter()
        .filter(|n| n.starts_with(&format!("{today}-")) && n.ends_with(".jsonl"))
        .collect();
    assert!(!rotated.is_empty(), "expected rotated files, got: {entries:?}");

    // Current file should exist.
    assert!(entries.contains(&format!("{today}.jsonl")), "current file missing: {entries:?}");
}

#[tokio::test]
async fn multiple_rotations_produce_incrementing_suffixes() {
    let tmp = TempDir::new().unwrap();
    let audit_dir = tmp.path().join("audit");
    let store = AuditFsStore::new(audit_dir.clone(), 50, test_scrub_engine()).unwrap();

    for _ in 0..50 {
        store.append(test_event()).await.unwrap();
    }

    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let entries: Vec<String> = std::fs::read_dir(&audit_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();

    let mut suffixes: Vec<u32> = entries
        .iter()
        .filter_map(|n| {
            n.strip_prefix(&format!("{today}-"))
                .and_then(|rest| rest.strip_suffix(".jsonl"))
                .and_then(|num| num.parse().ok())
        })
        .collect();
    suffixes.sort();

    assert!(suffixes.len() >= 3, "expected >= 3 rotations, got: {suffixes:?}");
    for (i, &suffix) in suffixes.iter().enumerate() {
        assert_eq!(suffix, (i as u32) + 1, "suffixes should be 1,2,3,...: {suffixes:?}");
    }
}

#[tokio::test]
async fn retention_sweep_deletes_old_files() {
    let tmp = TempDir::new().unwrap();
    let audit_dir = tmp.path().join("audit");
    let store =
        AuditFsStore::new(audit_dir.clone(), 100 * 1024 * 1024, test_scrub_engine()).unwrap();

    // Create files with old dates.
    let old_date = (chrono::Utc::now().date_naive() - chrono::Duration::days(100))
        .format("%Y-%m-%d")
        .to_string();
    std::fs::write(audit_dir.join(format!("{old_date}.jsonl")), "{}\n").unwrap();
    std::fs::write(audit_dir.join(format!("{old_date}-1.jsonl")), "{}\n").unwrap();

    let deleted = store.sweep_retention(90).await.unwrap();
    assert_eq!(deleted, 2);
    assert!(!audit_dir.join(format!("{old_date}.jsonl")).exists());
    assert!(!audit_dir.join(format!("{old_date}-1.jsonl")).exists());
}

#[tokio::test]
async fn retention_sweep_preserves_recent_files() {
    let tmp = TempDir::new().unwrap();
    let audit_dir = tmp.path().join("audit");
    let store =
        AuditFsStore::new(audit_dir.clone(), 100 * 1024 * 1024, test_scrub_engine()).unwrap();

    // Write a recent event.
    store.append(test_event()).await.unwrap();
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();

    let deleted = store.sweep_retention(90).await.unwrap();
    assert_eq!(deleted, 0);
    assert!(audit_dir.join(format!("{today}.jsonl")).exists());
}

#[tokio::test]
async fn every_line_is_valid_json_and_deserializes_to_audit_event() {
    let tmp = TempDir::new().unwrap();
    let audit_dir = tmp.path().join("audit");
    let store =
        AuditFsStore::new(audit_dir.clone(), 100 * 1024 * 1024, test_scrub_engine()).unwrap();

    for i in 0..10 {
        let event = AuditEvent::new(
            format!("agent-{i}"),
            "gmail".into(),
            "mail.readonly".into(),
            format!("msg/{i}"),
            "ok".into(),
            "api-call".into(),
        );
        store.append(event).await.unwrap();
    }

    for entry in std::fs::read_dir(&audit_dir).unwrap() {
        let entry = entry.unwrap();
        let content = std::fs::read_to_string(entry.path()).unwrap();
        for (line_num, line) in content.lines().enumerate() {
            let event: AuditEvent = serde_json::from_str(line).unwrap_or_else(|e| {
                panic!(
                    "line {} in {} is not valid AuditEvent JSON: {e}\nline: {line}",
                    line_num + 1,
                    entry.path().display()
                )
            });
            assert!(!event.timestamp.is_empty());
            assert!(!event.request_id.is_empty());
        }
    }
}

#[tokio::test]
async fn schema_version_matches_audit_schema_version_const() {
    let tmp = TempDir::new().unwrap();
    let audit_dir = tmp.path().join("audit");
    let store =
        AuditFsStore::new(audit_dir.clone(), 100 * 1024 * 1024, test_scrub_engine()).unwrap();

    store.append(test_event()).await.unwrap();

    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let content = std::fs::read_to_string(audit_dir.join(format!("{today}.jsonl"))).unwrap();
    let event: AuditEvent = serde_json::from_str(content.lines().next().unwrap()).unwrap();
    assert_eq!(event.schema_version, AUDIT_SCHEMA_VERSION);
}
