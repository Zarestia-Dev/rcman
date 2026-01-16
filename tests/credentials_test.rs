//! Credentials Integration Tests
//!
//! Tests for secret settings and credential management including:
//! - Secret settings stored in credential manager (not in JSON)
//! - Memory backend for testing
//! - Reset removes secrets from credential store
//!
//! Note: When running with `keychain` feature, tests use the OS keychain
//! which persists data. To avoid cross-contamination, each test uses
//! unique identifiers.

mod common;

use common::TestSettings;
use rcman::{SettingsConfig, SettingsManager};
use serde_json::json;
use std::sync::atomic::{AtomicU32, Ordering};
use tempfile::TempDir;

// Counter for unique test identifiers
static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);

fn unique_app_name() -> String {
    let count = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
    format!("rcman-test-{}-{}", std::process::id(), count)
}

// =============================================================================
// Helper to create manager with credentials enabled
// =============================================================================

fn create_manager_with_credentials() -> (TempDir, SettingsManager<rcman::JsonStorage, TestSettings>)
{
    let temp_dir = TempDir::new().unwrap();
    let app_name = unique_app_name();
    let config = SettingsConfig::builder(&app_name, "1.0.0")
        .with_config_dir(temp_dir.path())
        .with_schema::<TestSettings>()
        .with_credentials()
        .build();
    let manager = SettingsManager::new(config).unwrap();
    (temp_dir, manager)
}

// =============================================================================
// Secret Settings Not Stored in JSON
// =============================================================================

#[test]
#[ignore = "Requires Secret Service daemon (not available in CI)"]
fn test_secret_not_in_json_file() {
    let (temp_dir, manager) = create_manager_with_credentials();

    // Load settings
    let _ = manager.get_all().unwrap();

    // Save a secret setting
    manager
        .save_setting("api", "key", &json!("super_secret_api_key_123"))
        .unwrap();

    // Read the JSON file directly
    let settings_path = temp_dir.path().join("settings.json");
    if settings_path.exists() {
        let content = std::fs::read_to_string(&settings_path).unwrap();
        // Secret should NOT be in the JSON file
        assert!(!content.contains("super_secret_api_key_123"));
        assert!(!content.contains("api.key"));
    }
}

#[test]
#[ignore = "Requires Secret Service daemon (not available in CI)"]
fn test_secret_retrieved_correctly() {
    let (_temp_dir, manager) = create_manager_with_credentials();

    // Load settings
    let _ = manager.get_all().unwrap();

    // Save a secret
    manager
        .save_setting("api", "key", &json!("my_secret_value"))
        .unwrap();

    // Load settings again
    let metadata = manager.metadata().unwrap();
    let api_key_meta = metadata.get("api.key").unwrap();

    // Should have the correct value
    assert_eq!(api_key_meta.value, Some(json!("my_secret_value")));
}

// =============================================================================
// Reset Secret Settings
// =============================================================================

#[test]
#[ignore = "Requires Secret Service daemon (not available in CI)"]
fn test_reset_secret_clears_value() {
    let (_temp_dir, manager) = create_manager_with_credentials();

    // Load and set secret
    let _ = manager.get_all().unwrap();
    manager
        .save_setting("api", "key", &json!("secret_to_reset"))
        .unwrap();

    // Verify it's set
    let metadata = manager.metadata().unwrap();
    assert_eq!(
        metadata.get("api.key").unwrap().value,
        Some(json!("secret_to_reset"))
    );

    // Reset
    let default_value = manager.reset_setting("api", "key").unwrap();

    // Default is empty string
    assert_eq!(default_value, json!(""));

    // Should now be the default (empty)
    let metadata = manager.metadata().unwrap();
    assert_eq!(metadata.get("api.key").unwrap().value, Some(json!("")));
}

#[test]
#[ignore = "Requires Secret Service daemon (not available in CI)"]
fn test_reset_all_clears_secrets() {
    let (_temp_dir, manager) = create_manager_with_credentials();

    // Load and set secret
    let _ = manager.get_all().unwrap();
    manager
        .save_setting("api", "key", &json!("will_be_cleared"))
        .unwrap();

    // Reset all
    manager.reset_all().unwrap();

    // Secret should be cleared
    let metadata = manager.metadata().unwrap();
    let api_key_value = metadata.get("api.key").unwrap().value.clone();

    // Should be back to default (empty string)
    assert_eq!(api_key_value, Some(json!("")));
}

// =============================================================================
// Secret Default Value Behavior
// =============================================================================

#[test]
#[ignore = "Requires Secret Service daemon (not available in CI)"]
fn test_secret_default_not_stored() {
    let (_temp_dir, manager) = create_manager_with_credentials();

    // Load settings
    let _ = manager.get_all().unwrap();

    // Set to non-default first
    manager
        .save_setting("api", "key", &json!("temporary_key"))
        .unwrap();

    // Now set back to default (empty string)
    manager.save_setting("api", "key", &json!("")).unwrap();

    // Load again - should get default
    let metadata = manager.metadata().unwrap();
    assert_eq!(metadata.get("api.key").unwrap().value, Some(json!("")));
}

// =============================================================================
// Multiple Secrets
// =============================================================================

#[test]
#[ignore = "Requires Secret Service daemon (not available in CI)"]
fn test_multiple_secrets() {
    let (_temp_dir, manager) = create_manager_with_credentials();

    // Load settings
    let _ = manager.get_all().unwrap();

    // Save secret
    manager
        .save_setting("api", "key", &json!("secret1"))
        .unwrap();

    // Also save a non-secret
    manager
        .save_setting("ui", "theme", &json!("light"))
        .unwrap();

    // Verify both are retrievable
    let metadata = manager.metadata().unwrap();

    assert_eq!(
        metadata.get("api.key").unwrap().value,
        Some(json!("secret1"))
    );
    assert_eq!(
        metadata.get("ui.theme").unwrap().value,
        Some(json!("light"))
    );
}

// =============================================================================
// Credentials Manager Access (requires keychain or encrypted-file feature)
// =============================================================================

#[cfg(any(feature = "keychain", feature = "encrypted-file"))]
#[test]
fn test_credentials_manager_available() {
    let (_temp_dir, manager) = create_manager_with_credentials();

    // Credentials should be available
    assert!(manager.credentials().is_some());
}

#[cfg(any(feature = "keychain", feature = "encrypted-file"))]
#[test]
fn test_credentials_not_available_when_disabled() {
    let temp_dir = TempDir::new().unwrap();
    let app_name = unique_app_name();
    let config = SettingsConfig::builder(&app_name, "1.0.0")
        .with_config_dir(temp_dir.path())
        // Note: NOT calling .with_credentials()
        .build();
    let manager = SettingsManager::new(config).unwrap();

    // Credentials should NOT be available
    assert!(manager.credentials().is_none());
}

// =============================================================================
// Persistence Across Sessions
// =============================================================================

#[test]
#[ignore = "Requires Secret Service daemon (not available in CI)"]
fn test_secret_persists_across_sessions() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().to_path_buf();
    let app_name = unique_app_name();

    // First session
    {
        let config = SettingsConfig::builder(&app_name, "1.0.0")
            .with_config_dir(&config_path)
            .with_schema::<TestSettings>()
            .with_credentials()
            .build();
        let manager = SettingsManager::new(config).unwrap();

        manager.get_all().unwrap();
        manager
            .save_setting("api", "key", &json!("persistent_secret"))
            .unwrap();
    }

    // Second session (new manager instance with SAME app_name)
    {
        let config = SettingsConfig::builder(&app_name, "1.0.0")
            .with_config_dir(&config_path)
            .with_schema::<TestSettings>()
            .with_credentials()
            .build();
        let manager = SettingsManager::new(config).unwrap();

        // In a real keychain scenario, this would retrieve "persistent_secret"
        // With memory backend (default for tests unless feature enabled), it might be empty
        // BUT since we are running with --all-features, keychain IS enabled.
        let metadata = manager.metadata().unwrap();
        let value = metadata.get("api.key").unwrap().value.clone();

        // If using keychain, it should persist.
        // If memory backend (no feature), it won't.
        #[cfg(feature = "keychain")]
        assert_eq!(value, Some(json!("persistent_secret")));

        // If using memory backend, we just verify it doesn't crash
        #[cfg(not(feature = "keychain"))]
        let _ = value;
    }
}

// =============================================================================
// Secret Metadata Flags
// =============================================================================

#[test]
fn test_secret_has_correct_metadata() {
    let (_temp_dir, manager) = create_manager_with_credentials();

    // Verify metadata reflects secret status
    let metadata = manager.metadata().unwrap();
    let api_key_meta = metadata.get("api.key").unwrap();
    #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
    assert!(api_key_meta.is_secret());
    #[cfg(not(any(feature = "keychain", feature = "encrypted-file")))]
    assert!(!api_key_meta.is_secret());

    let theme_meta = metadata.get("ui.theme").unwrap();
    assert!(!theme_meta.is_secret());
}
