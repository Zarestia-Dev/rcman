//! Sub-Settings Integration Tests
//!
//! Tests for per-entity configuration files including:
//! - Multi-file mode (one file per entity)
//! - Single-file mode (all entities in one JSON file)
//! - CRUD operations
//! - Migration support
//! - Change callbacks

mod common;

use common::TestFixture;
use rcman::{SettingsManager, SubSettingsConfig};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::{Arc, Mutex};
use tempfile::TempDir;

// =============================================================================
// Test Data Structures
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct RemoteConfig {
    #[serde(rename = "type")]
    remote_type: String,
    endpoint: Option<String>,
    bucket: Option<String>,
}

// =============================================================================
// Multi-File Mode Tests
// =============================================================================

#[test]
fn test_multi_file_mode_creates_directory() {
    let fixture = TestFixture::with_sub_settings();

    let remotes = fixture.manager.sub_settings("remotes").unwrap();
    remotes.set("gdrive", &json!({"type": "drive"})).unwrap();

    // Should create a directory
    let remotes_dir = fixture.config_dir().join("remotes");
    assert!(remotes_dir.is_dir());

    // Should create individual file
    let gdrive_file = remotes_dir.join("gdrive.json");
    assert!(gdrive_file.exists());
}

#[test]
fn test_multi_file_separate_files() {
    let fixture = TestFixture::with_sub_settings();

    let remotes = fixture.manager.sub_settings("remotes").unwrap();
    remotes.set("gdrive", &json!({"type": "drive"})).unwrap();
    remotes.set("s3", &json!({"type": "s3"})).unwrap();
    remotes.set("b2", &json!({"type": "b2"})).unwrap();

    let remotes_dir = fixture.config_dir().join("remotes");

    // Each entity should have its own file
    assert!(remotes_dir.join("gdrive.json").exists());
    assert!(remotes_dir.join("s3.json").exists());
    assert!(remotes_dir.join("b2.json").exists());
}

// =============================================================================
// Single-File Mode Tests
// =============================================================================

#[test]
fn test_single_file_mode_creates_file() {
    let fixture = TestFixture::with_sub_settings();

    let backends = fixture.manager.sub_settings("backends").unwrap();
    backends
        .set("local", &json!({"host": "localhost", "port": 5572}))
        .unwrap();

    // Should create a single file, not a directory
    let backends_file = fixture.config_dir().join("backends.json");
    assert!(backends_file.exists());
    assert!(backends_file.is_file());
}

#[test]
fn test_single_file_all_entities_in_one() {
    let fixture = TestFixture::with_sub_settings();

    let backends = fixture.manager.sub_settings("backends").unwrap();
    backends
        .set("local", &json!({"host": "localhost"}))
        .unwrap();
    backends
        .set("remote", &json!({"host": "192.168.1.1"}))
        .unwrap();

    // Read the file directly
    let backends_file = fixture.config_dir().join("backends.json");
    let content = std::fs::read_to_string(&backends_file).unwrap();
    let json: serde_json::Value = serde_json::from_str(&content).unwrap();

    // Both entries should be in the same file
    assert!(json.get("local").is_some());
    assert!(json.get("remote").is_some());
}

// =============================================================================
// CRUD Operations
// =============================================================================

#[test]
fn test_create_entry() {
    let fixture = TestFixture::with_sub_settings();
    let remotes = fixture.manager.sub_settings("remotes").unwrap();

    // Create
    remotes
        .set(
            "gdrive",
            &RemoteConfig {
                remote_type: "drive".into(),
                endpoint: None,
                bucket: None,
            },
        )
        .unwrap();

    // Verify it exists
    assert!(remotes.exists("gdrive").unwrap());
}

#[test]
fn test_read_entry() {
    let fixture = TestFixture::with_sub_settings();
    let remotes = fixture.manager.sub_settings("remotes").unwrap();

    let original = RemoteConfig {
        remote_type: "s3".into(),
        endpoint: Some("https://s3.amazonaws.com".into()),
        bucket: Some("my-bucket".into()),
    };

    remotes.set("aws", &original).unwrap();

    // Read back
    let loaded: RemoteConfig = remotes.get("aws").unwrap();
    assert_eq!(loaded, original);
}

#[test]
fn test_update_entry() {
    let fixture = TestFixture::with_sub_settings();
    let remotes = fixture.manager.sub_settings("remotes").unwrap();

    // Create initial
    remotes
        .set(
            "myremote",
            &RemoteConfig {
                remote_type: "s3".into(),
                endpoint: None,
                bucket: Some("old-bucket".into()),
            },
        )
        .unwrap();

    // Update
    remotes
        .set(
            "myremote",
            &RemoteConfig {
                remote_type: "s3".into(),
                endpoint: Some("https://new-endpoint.com".into()),
                bucket: Some("new-bucket".into()),
            },
        )
        .unwrap();

    // Verify update
    let loaded: RemoteConfig = remotes.get("myremote").unwrap();
    assert_eq!(loaded.bucket, Some("new-bucket".into()));
    assert_eq!(loaded.endpoint, Some("https://new-endpoint.com".into()));
}

#[test]
fn test_delete_entry() {
    let fixture = TestFixture::with_sub_settings();
    let remotes = fixture.manager.sub_settings("remotes").unwrap();

    // Create
    remotes.set("to_delete", &json!({"type": "test"})).unwrap();
    assert!(remotes.exists("to_delete").unwrap());

    // Delete
    remotes.delete("to_delete").unwrap();

    // Should no longer exist
    assert!(!remotes.exists("to_delete").unwrap());
}

#[test]
fn test_delete_removes_file_in_multi_file_mode() {
    let fixture = TestFixture::with_sub_settings();
    let remotes = fixture.manager.sub_settings("remotes").unwrap();

    remotes.set("temp", &json!({"type": "temp"})).unwrap();
    let file_path = fixture.config_dir().join("remotes").join("temp.json");
    assert!(file_path.exists());

    remotes.delete("temp").unwrap();
    assert!(!file_path.exists());
}

// =============================================================================
// List Entries
// =============================================================================

#[test]
fn test_list_entries() {
    let fixture = TestFixture::with_sub_settings();
    let remotes = fixture.manager.sub_settings("remotes").unwrap();

    remotes.set("alpha", &json!({})).unwrap();
    remotes.set("beta", &json!({})).unwrap();
    remotes.set("gamma", &json!({})).unwrap();

    let mut list = remotes.list().unwrap();
    list.sort();

    assert_eq!(list, vec!["alpha", "beta", "gamma"]);
}

#[test]
fn test_list_empty() {
    let fixture = TestFixture::with_sub_settings();
    let remotes = fixture.manager.sub_settings("remotes").unwrap();

    let list = remotes.list().unwrap();
    assert!(list.is_empty());
}

// =============================================================================
// Entry Not Found
// =============================================================================

#[test]
fn test_get_nonexistent_entry() {
    let fixture = TestFixture::with_sub_settings();
    let remotes = fixture.manager.sub_settings("remotes").unwrap();

    let result = remotes.get_value("does_not_exist");
    assert!(result.is_err());

    let err = result.unwrap_err();
    assert!(err.is_not_found());
}

#[test]
fn test_exists_returns_false_for_missing() {
    let fixture = TestFixture::with_sub_settings();
    let remotes = fixture.manager.sub_settings("remotes").unwrap();

    assert!(!remotes.exists("missing").unwrap());
}

// =============================================================================
// Migration Support
// =============================================================================

#[test]
fn test_migrator_adds_field() {
    let temp_dir = TempDir::new().unwrap();

    // Create manager with migrator
    let manager = SettingsManager::builder("test-app", "1.0.0")
        .with_config_dir(temp_dir.path())
        .with_sub_settings(
            SubSettingsConfig::new("configs").with_migrator(|mut value| {
                if let Some(obj) = value.as_object_mut() {
                    if !obj.contains_key("version") {
                        obj.insert("version".into(), json!(2));
                    }
                }
                value
            }),
        )
        .build()
        .unwrap();

    // Create a config without version field by writing directly
    let configs_dir = temp_dir.path().join("configs");
    std::fs::create_dir_all(&configs_dir).unwrap();
    std::fs::write(configs_dir.join("old.json"), r#"{"name": "old config"}"#).unwrap();

    // Load the config - migrator should add version field
    let configs = manager.sub_settings("configs").unwrap();
    let loaded = configs.get_value("old").unwrap();

    assert_eq!(loaded["version"], json!(2));
    assert_eq!(loaded["name"], json!("old config"));
}

#[test]
fn test_migrator_upgrades_schema() {
    let temp_dir = TempDir::new().unwrap();

    let manager = SettingsManager::builder("test-app", "1.0.0")
        .with_config_dir(temp_dir.path())
        .with_sub_settings(
            SubSettingsConfig::new("remotes").with_migrator(|mut value| {
                // Migrate old field name to new
                if let Some(obj) = value.as_object_mut() {
                    if let Some(old_value) = obj.remove("remote_type") {
                        obj.insert("type".into(), old_value);
                    }
                }
                value
            }),
        )
        .build()
        .unwrap();

    // Write old format directly
    let remotes_dir = temp_dir.path().join("remotes");
    std::fs::create_dir_all(&remotes_dir).unwrap();
    std::fs::write(
        remotes_dir.join("old_remote.json"),
        r#"{"remote_type": "drive"}"#,
    )
    .unwrap();

    // Load - should get migrated value
    let remotes = manager.sub_settings("remotes").unwrap();
    let loaded = remotes.get_value("old_remote").unwrap();

    assert!(loaded.get("remote_type").is_none());
    assert_eq!(loaded["type"], json!("drive"));
}

// =============================================================================
// Change Callbacks
// =============================================================================

#[test]
fn test_on_change_callback() {
    let fixture = TestFixture::with_sub_settings();
    let remotes = fixture.manager.sub_settings("remotes").unwrap();

    // Track changes
    let changes = Arc::new(Mutex::new(Vec::new()));
    let changes_clone = changes.clone();

    let _ = remotes.set_on_change(move |name, action| {
        changes_clone
            .lock()
            .unwrap()
            .push((name.to_string(), action));
    });

    // Perform operations
    remotes.set("new_remote", &json!({})).unwrap();
    remotes
        .set("new_remote", &json!({"updated": true}))
        .unwrap();
    remotes.delete("new_remote").unwrap();

    // Verify callbacks
    let recorded = changes.lock().unwrap();
    assert_eq!(recorded.len(), 3);
    assert_eq!(recorded[0].0, "new_remote");
    assert_eq!(recorded[1].0, "new_remote");
    assert_eq!(recorded[2].0, "new_remote");
}

// =============================================================================
// Sub-Settings Not Registered
// =============================================================================

#[test]
fn test_unregistered_sub_settings_error() {
    let fixture = TestFixture::new(); // No sub-settings configured

    let result = fixture.manager.sub_settings("unregistered");
    assert!(result.is_err());
}

// =============================================================================
// Special Characters in Names
// =============================================================================

#[test]
fn test_special_characters_in_entry_name() {
    let fixture = TestFixture::with_sub_settings();
    let remotes = fixture.manager.sub_settings("remotes").unwrap();

    // Names with special characters that should be handled
    remotes.set("my-remote", &json!({})).unwrap();
    remotes.set("my_remote", &json!({})).unwrap();
    remotes.set("remote123", &json!({})).unwrap();

    assert!(remotes.exists("my-remote").unwrap());
    assert!(remotes.exists("my_remote").unwrap());
    assert!(remotes.exists("remote123").unwrap());

    let list = remotes.list().unwrap();
    assert_eq!(list.len(), 3);
}
