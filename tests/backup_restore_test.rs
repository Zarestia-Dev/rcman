//! Backup & Restore Integration Tests
//!
//! Tests for the backup/restore functionality including:
//! - Creating encrypted and unencrypted backups
//! - Analyzing backups
//! - Restoring from backups
//! - Sub-settings inclusion in backups

mod common;

use common::{TestFixture, TestSettings};
use rcman::{BackupOptions, RestoreOptions};
use serde_json::json;
use tempfile::TempDir;

// =============================================================================
// Helper Functions
// =============================================================================

fn create_fixture_with_data() -> TestFixture {
    let fixture = TestFixture::with_sub_settings();

    // Load and set some non-default settings
    let _ = fixture.manager.settings().unwrap();
    fixture
        .manager
        .save_setting("ui", "theme", json!("light"))
        .unwrap();
    fixture
        .manager
        .save_setting("ui", "font_size", json!(18.0))
        .unwrap();

    // Add some sub-settings data
    let remotes = fixture.manager.sub_settings("remotes").unwrap();
    remotes
        .set("gdrive", &json!({"type": "drive", "scope": "drive"}))
        .unwrap();
    remotes
        .set("s3", &json!({"type": "s3", "bucket": "my-bucket"}))
        .unwrap();

    fixture
}

// =============================================================================
// Create Backup Tests
// =============================================================================

#[test]
fn test_create_unencrypted_backup() {
    let fixture = create_fixture_with_data();
    let backup_dir = TempDir::new().unwrap();

    let backup_path = fixture
        .manager
        .backup()
        .create(&BackupOptions::new().output_dir(backup_dir.path()))
        .unwrap();

    // Verify backup file exists
    assert!(backup_path.exists());
    // Extension is .rcman (a zip file)
    assert_eq!(backup_path.extension().unwrap(), "rcman");

    // Verify it's not encrypted (can be opened without password)
    let analysis = fixture.manager.backup().analyze(&backup_path).unwrap();
    assert!(!analysis.requires_password);
    assert!(analysis.is_valid);
}

#[test]
fn test_create_encrypted_backup() {
    let fixture = create_fixture_with_data();
    let backup_dir = TempDir::new().unwrap();

    let backup_path = fixture
        .manager
        .backup()
        .create(
            &BackupOptions::new()
                .output_dir(backup_dir.path())
                .password("test_password_123"),
        )
        .unwrap();

    // Verify backup file exists
    assert!(backup_path.exists());

    // Verify it's encrypted
    let analysis = fixture.manager.backup().analyze(&backup_path).unwrap();
    assert!(analysis.requires_password);
    assert!(analysis.is_valid);
}

#[test]
fn test_create_backup_with_note() {
    let fixture = create_fixture_with_data();
    let backup_dir = TempDir::new().unwrap();

    let backup_path = fixture
        .manager
        .backup()
        .create(
            &BackupOptions::new()
                .output_dir(backup_dir.path())
                .note("Weekly backup before update"),
        )
        .unwrap();

    let analysis = fixture.manager.backup().analyze(&backup_path).unwrap();
    assert_eq!(
        analysis.manifest.backup.user_note,
        Some("Weekly backup before update".to_string())
    );
}

// =============================================================================
// Analyze Backup Tests
// =============================================================================

#[test]
fn test_analyze_backup_contents() {
    let fixture = create_fixture_with_data();
    let backup_dir = TempDir::new().unwrap();

    let backup_path = fixture
        .manager
        .backup()
        .create(&BackupOptions::new().output_dir(backup_dir.path()))
        .unwrap();

    let analysis = fixture.manager.backup().analyze(&backup_path).unwrap();

    // Check manifest info
    assert_eq!(analysis.manifest.backup.app_name, "test-app");
    assert_eq!(analysis.manifest.backup.app_version, "1.0.0");
    assert!(analysis.is_valid);
    assert!(analysis.warnings.is_empty());

    // Check contents include settings
    assert!(analysis.manifest.contents.settings);
}

#[test]
fn test_analyze_encrypted_backup() {
    let fixture = create_fixture_with_data();
    let backup_dir = TempDir::new().unwrap();

    let backup_path = fixture
        .manager
        .backup()
        .create(
            &BackupOptions::new()
                .output_dir(backup_dir.path())
                .password("secret123"),
        )
        .unwrap();

    let analysis = fixture.manager.backup().analyze(&backup_path).unwrap();

    assert!(analysis.requires_password);
    // Even encrypted, we can still read the manifest (it's unencrypted)
    assert_eq!(analysis.manifest.backup.app_name, "test-app");
}

// =============================================================================
// Restore Backup Tests
// =============================================================================

#[test]
fn test_restore_backup() {
    let original_fixture = create_fixture_with_data();
    let backup_dir = TempDir::new().unwrap();

    // Create backup
    let backup_path = original_fixture
        .manager
        .backup()
        .create(&BackupOptions::new().output_dir(backup_dir.path()))
        .unwrap();

    // Create a new fresh fixture (simulating fresh install)
    let new_fixture = TestFixture::with_sub_settings();

    // Restore
    let result = new_fixture
        .manager
        .backup()
        .restore(&RestoreOptions::from_path(&backup_path).overwrite(true))
        .unwrap();

    // Verify restoration happened
    assert!(result.restored.contains(&"settings.json".to_string()));

    // Invalidate cache to pick up restored files
    new_fixture.manager.invalidate_cache();

    // Verify settings were restored via metadata (not struct deserialization)
    let metadata = new_fixture.manager.load_settings().unwrap();
    let theme_value = metadata.get("ui.theme").unwrap().value.clone();
    assert_eq!(theme_value, Some(json!("light")));

    let font_size_value = metadata.get("ui.font_size").unwrap().value.clone();
    assert_eq!(font_size_value, Some(json!(18.0)));
}

#[test]
fn test_restore_encrypted_backup() {
    let original_fixture = create_fixture_with_data();
    let backup_dir = TempDir::new().unwrap();
    let password = "secure_password_456";

    // Create encrypted backup
    let backup_path = original_fixture
        .manager
        .backup()
        .create(
            &BackupOptions::new()
                .output_dir(backup_dir.path())
                .password(password),
        )
        .unwrap();

    // Create a new fresh fixture
    let new_fixture = TestFixture::with_sub_settings();

    // Restore with correct password
    let result = new_fixture
        .manager
        .backup()
        .restore(
            &RestoreOptions::from_path(&backup_path)
                .password(password)
                .overwrite(true),
        )
        .unwrap();

    assert!(result.restored.contains(&"settings.json".to_string()));

    new_fixture.manager.invalidate_cache();

    // Verify settings were restored
    let metadata = new_fixture.manager.load_settings().unwrap();
    let theme_value = metadata.get("ui.theme").unwrap().value.clone();
    assert_eq!(theme_value, Some(json!("light")));
}

#[test]
fn test_restore_wrong_password_fails() {
    let original_fixture = create_fixture_with_data();
    let backup_dir = TempDir::new().unwrap();

    // Create encrypted backup
    let backup_path = original_fixture
        .manager
        .backup()
        .create(
            &BackupOptions::new()
                .output_dir(backup_dir.path())
                .password("correct_password"),
        )
        .unwrap();

    // Create a new fixture
    let new_fixture = TestFixture::with_sub_settings();

    // Try to restore with wrong password
    let result = new_fixture.manager.backup().restore(
        &RestoreOptions::from_path(&backup_path)
            .password("wrong_password")
            .overwrite(true),
    );

    assert!(result.is_err());
}

#[test]
fn test_restore_without_password_when_encrypted_fails() {
    let original_fixture = create_fixture_with_data();
    let backup_dir = TempDir::new().unwrap();

    // Create encrypted backup
    let backup_path = original_fixture
        .manager
        .backup()
        .create(
            &BackupOptions::new()
                .output_dir(backup_dir.path())
                .password("some_password"),
        )
        .unwrap();

    // Create a new fixture
    let new_fixture = TestFixture::with_sub_settings();

    // Try to restore without providing password
    let result = new_fixture
        .manager
        .backup()
        .restore(&RestoreOptions::from_path(&backup_path).overwrite(true));

    assert!(result.is_err());
}

// =============================================================================
// Sub-Settings in Backup
// =============================================================================

#[test]
fn test_backup_includes_sub_settings() {
    let fixture = create_fixture_with_data();
    let backup_dir = TempDir::new().unwrap();

    // Create backup - explicitly include sub-settings
    let backup_path = fixture
        .manager
        .backup()
        .create(
            &BackupOptions::new()
                .output_dir(backup_dir.path())
                .include_sub_settings("remotes"),
        )
        .unwrap();

    // Create a new fixture and restore
    let new_fixture = TestFixture::with_sub_settings();
    let result = new_fixture
        .manager
        .backup()
        .restore(&RestoreOptions::from_path(&backup_path).overwrite(true))
        .unwrap();

    // Verify sub-settings were restored
    assert!(result.restored.iter().any(|s| s.contains("remotes/gdrive")));
    assert!(result.restored.iter().any(|s| s.contains("remotes/s3")));

    // Actually verify we can read the restored sub-settings
    let remotes = new_fixture.manager.sub_settings("remotes").unwrap();
    let gdrive = remotes.get_value("gdrive").unwrap();
    assert_eq!(gdrive["type"], "drive");

    let s3 = remotes.get_value("s3").unwrap();
    assert_eq!(s3["type"], "s3");
}

// =============================================================================
// Restore Modes
// =============================================================================

#[test]
fn test_restore_skip_existing() {
    let original_fixture = create_fixture_with_data();
    let backup_dir = TempDir::new().unwrap();

    // Create backup with theme=light
    let backup_path = original_fixture
        .manager
        .backup()
        .create(&BackupOptions::new().output_dir(backup_dir.path()))
        .unwrap();

    // Create a new fixture with different settings
    let new_fixture = TestFixture::new();
    let _ = new_fixture.manager.settings().unwrap();
    new_fixture
        .manager
        .save_setting("ui", "theme", json!("system"))
        .unwrap();

    // Restore WITHOUT overwrite (should skip existing)
    let result = new_fixture
        .manager
        .backup()
        .restore(&RestoreOptions::from_path(&backup_path).overwrite(false))
        .unwrap();

    // The settings file should have been skipped
    assert!(!result.skipped.is_empty() || result.restored.is_empty());
}

#[test]
fn test_restore_overwrite_existing() {
    let original_fixture = create_fixture_with_data();
    let backup_dir = TempDir::new().unwrap();

    // Create backup with theme=light
    let backup_path = original_fixture
        .manager
        .backup()
        .create(&BackupOptions::new().output_dir(backup_dir.path()))
        .unwrap();

    // Create a new fixture with different settings
    let new_fixture = TestFixture::new();
    let _ = new_fixture.manager.settings().unwrap();
    new_fixture
        .manager
        .save_setting("ui", "theme", json!("system"))
        .unwrap();

    // Restore WITH overwrite
    new_fixture
        .manager
        .backup()
        .restore(&RestoreOptions::from_path(&backup_path).overwrite(true))
        .unwrap();

    new_fixture.manager.invalidate_cache();

    // Verify the restored value via metadata
    let metadata = new_fixture.manager.load_settings().unwrap();
    let theme_value = metadata.get("ui.theme").unwrap().value.clone();
    assert_eq!(theme_value, Some(json!("light"))); // from backup, not "system"
}
