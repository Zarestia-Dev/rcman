//! Credentials Integration Tests
//!
//! Tests for secret settings and credential management including:
//! - Secret settings stored in credential manager (not in JSON)
//! - Memory backend for testing
//! - Reset removes secrets from credential store
//!
//! ### Test Isolation & Keyring Cleanup
//! When running with the `keychain` feature on desktop/mobile platforms, tests use
//! the OS keychain (e.g. Linux Secret Service, macOS Keychain, Windows Credential Manager).
//! To avoid cross-contamination and leftover secrets:
//! - Each test generates a globally unique service name (`rcman-test-<pid>-<count>`).
//! - Tests employ RAII [`TestCredentialsGuard`] to purge credentials upon completion or panic.
//! - Deletions are strictly scoped to the exact test service name (`<service_name>:*`),
//!   guaranteeing that other tests or existing user keys (even if named `rcman-test-*`)
//!   are never modified or deleted.

mod common;

use common::{TestCredentialsGuard, TestSettings, unique_app_name};
use rcman::{SettingsConfig, SettingsManager};
use serde_json::json;
use tempfile::TempDir;

// =============================================================================
// Helper to create manager with credentials enabled
// =============================================================================

fn create_manager_with_credentials() -> (
    TempDir,
    SettingsManager<rcman::JsonStorage, TestSettings>,
    TestCredentialsGuard,
) {
    let temp_dir = TempDir::new().unwrap();
    let app_name = unique_app_name();
    let guard = TestCredentialsGuard::new(&app_name);
    let config = SettingsConfig::builder(&app_name, "1.0.0")
        .with_config_dir(temp_dir.path())
        .with_schema::<TestSettings>()
        .with_credentials()
        .build();
    let manager = SettingsManager::new(config).unwrap();
    (temp_dir, manager, guard)
}

// =============================================================================
// Secret Settings Not Stored in JSON
// =============================================================================

#[test]
#[ignore = "Requires Secret Service daemon (not available in CI)"]
fn test_secret_not_in_json_file() {
    let (temp_dir, manager, _guard) = create_manager_with_credentials();

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
    let (_temp_dir, manager, _guard) = create_manager_with_credentials();

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
    let (_temp_dir, manager, _guard) = create_manager_with_credentials();

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
    let (_temp_dir, manager, _guard) = create_manager_with_credentials();

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

#[cfg(any(feature = "keychain", feature = "encrypted-file"))]
#[test]
#[cfg_attr(
    feature = "keychain",
    ignore = "Requires Secret Service daemon (not available in CI)"
)]
fn test_clear_from_fresh_manager_deletes_secrets_and_metadata() {
    let app_name = unique_app_name();
    let _guard = TestCredentialsGuard::new(&app_name);
    let temp_dir = TempDir::new().unwrap();

    // 1. Session 1: Store a secret
    {
        let config = SettingsConfig::builder(&app_name, "1.0.0")
            .with_config_dir(temp_dir.path())
            .with_schema::<TestSettings>()
            .with_credentials()
            .build();
        let manager = SettingsManager::new(config).unwrap();
        manager
            .save_setting("api", "key", &json!("secret_to_purge"))
            .unwrap();

        let creds = manager.credentials().unwrap();
        assert_eq!(
            creds.get("api.key").unwrap(),
            Some("secret_to_purge".to_string())
        );
    }

    // 2. Fresh manager instance (simulating TestCredentialsGuard::drop) calls clear()
    {
        let fresh_creds = rcman::CredentialManager::new(&app_name);
        fresh_creds.clear().unwrap();
    }

    // 3. Session 2: Verify secret and __rcman_secrets__ are purged
    {
        let check_creds = rcman::CredentialManager::new(&app_name);
        assert_eq!(check_creds.get("api.key").unwrap(), None);
        assert_eq!(check_creds.get("__rcman_secrets__").unwrap(), None);
    }
}

#[cfg(any(feature = "keychain", feature = "encrypted-file"))]
#[test]
#[cfg_attr(
    feature = "keychain",
    ignore = "Requires Secret Service daemon (not available in CI)"
)]
fn test_invalidate_cache_clears_credential_metadata_cache() {
    let app_name = unique_app_name();
    let _guard = TestCredentialsGuard::new(&app_name);
    let temp_dir = TempDir::new().unwrap();

    let config = SettingsConfig::builder(&app_name, "1.0.0")
        .with_config_dir(temp_dir.path())
        .with_schema::<TestSettings>()
        .with_credentials()
        .build();
    let manager = SettingsManager::new(config).unwrap();

    // 1. Save initial secret
    manager
        .save_setting("api", "key", &json!("initial_secret"))
        .unwrap();

    let metadata = manager.metadata().unwrap();
    assert_eq!(
        metadata.get("api.key").unwrap().value,
        Some(json!("initial_secret"))
    );

    // 2. Modify secret directly in credential store (simulating external update)
    let raw_creds = rcman::CredentialManager::new(&app_name);
    raw_creds
        .store("api.key", "externally_updated_secret")
        .unwrap();

    // 3. Invalidate cache on the manager
    manager.invalidate_cache();

    // 4. Verify manager reads fresh value from credential store
    let fresh_metadata = manager.metadata().unwrap();
    assert_eq!(
        fresh_metadata.get("api.key").unwrap().value,
        Some(json!("externally_updated_secret"))
    );
}

// =============================================================================
// Secret Default Value Behavior
// =============================================================================

#[test]
#[ignore = "Requires Secret Service daemon (not available in CI)"]
fn test_secret_default_not_stored() {
    let (_temp_dir, manager, _guard) = create_manager_with_credentials();

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
    let (_temp_dir, manager, _guard) = create_manager_with_credentials();

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
    let (_temp_dir, manager, _guard) = create_manager_with_credentials();

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

#[cfg(all(feature = "keychain", any(target_os = "android", target_os = "ios")))]
#[test]
fn test_mobile_keychain_store_retrieve_remove() {
    let (_temp_dir, manager, _guard) = create_manager_with_credentials();

    // Store a secret value
    manager
        .save_setting("api", "key", &json!("mobile_secret_123"))
        .unwrap();

    // Retrieve via metadata
    let metadata = manager.metadata().unwrap();
    assert_eq!(
        metadata.get("api.key").unwrap().value,
        Some(json!("mobile_secret_123"))
    );

    // Remove secret
    let reset_val = manager.reset_setting("api", "key").unwrap();
    assert!(reset_val == json!("") || reset_val.is_null());
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
    let _guard = TestCredentialsGuard::new(&app_name);

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
    let (_temp_dir, manager, _guard) = create_manager_with_credentials();

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

// =============================================================================
// Encrypted Fallback Tests
// =============================================================================

#[cfg(all(feature = "keychain", feature = "encrypted-file"))]
#[test]
fn test_encrypted_fallback_with_env_password() {
    use rcman::SecretPasswordSource;
    let temp_dir = TempDir::new().unwrap();
    let app_name = unique_app_name();
    let _guard = TestCredentialsGuard::new(&app_name);
    let fallback_path = temp_dir.path().join("secrets.enc.json");

    // Set env var for test
    let env_var = format!("PASS_{}", app_name.replace("-", "_"));
    unsafe { std::env::set_var(&env_var, "super-secure-password") };

    let config = SettingsConfig::builder(&app_name, "1.0.0")
        .with_config_dir(temp_dir.path())
        .with_schema::<TestSettings>()
        .with_encrypted_fallback(
            &fallback_path,
            SecretPasswordSource::Environment(env_var.clone()),
        )
        .build();

    let manager = SettingsManager::new(config).unwrap();

    // Store a secret - this might hit keychain OR fallback depending on CI env
    manager
        .save_setting("api", "key", &json!("secret-value"))
        .unwrap();

    // Verify it can be retrieved
    let val = manager.get_value("api.key").unwrap();
    assert_eq!(val, json!("secret-value"));

    unsafe { std::env::remove_var(&env_var) };
}

#[cfg(all(feature = "keychain", feature = "encrypted-file"))]
#[test]
fn test_encrypted_fallback_with_file_password() {
    use rcman::SecretPasswordSource;
    let temp_dir = TempDir::new().unwrap();
    let app_name = unique_app_name();
    let _guard = TestCredentialsGuard::new(&app_name);
    let fallback_path = temp_dir.path().join("secrets.enc.json");
    let password_path = temp_dir.path().join("password.txt");

    std::fs::write(&password_path, "file-password-123").unwrap();

    let config = SettingsConfig::builder(&app_name, "1.0.0")
        .with_config_dir(temp_dir.path())
        .with_schema::<TestSettings>()
        .with_encrypted_fallback(&fallback_path, SecretPasswordSource::File(password_path))
        .build();

    let manager = SettingsManager::new(config).unwrap();

    manager
        .save_setting("api", "key", &json!("secret-value"))
        .unwrap();

    let val = manager.get_value("api.key").unwrap();
    assert_eq!(val, json!("secret-value"));
}

#[test]
fn test_secret_password_source_helpers() {
    let env_src = rcman::SecretPasswordSource::env("RCMAN_TEST_PASS");
    unsafe {
        std::env::set_var("RCMAN_TEST_PASS", "env_pass_val");
    }
    assert_eq!(env_src.resolve().unwrap(), "env_pass_val");
    unsafe {
        std::env::remove_var("RCMAN_TEST_PASS");
    }

    let prov_src = rcman::SecretPasswordSource::provided("direct_pass_val");
    assert_eq!(prov_src.resolve().unwrap(), "direct_pass_val");

    let temp_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(temp_file.path(), "file_pass_val\n").unwrap();
    let file_src = rcman::SecretPasswordSource::file(temp_file.path());
    assert_eq!(file_src.resolve().unwrap(), "file_pass_val");
}

// =============================================================================
// Bidirectional Migration Tests
// =============================================================================

#[cfg(any(feature = "keychain", feature = "encrypted-file"))]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Default)]
struct MigrationNormalSettings {
    pub api: MigrationApiSettings,
}

#[cfg(any(feature = "keychain", feature = "encrypted-file"))]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Default)]
struct MigrationApiSettings {
    pub key: String,
}

#[cfg(any(feature = "keychain", feature = "encrypted-file"))]
impl rcman::SettingsSchema for MigrationNormalSettings {
    fn get_metadata() -> rcman::IndexMap<String, rcman::SettingMetadata> {
        rcman::settings! {
            "api.key" => rcman::SettingMetadata::text("")
                .meta_str("label", "API Key")
        }
    }
}

#[cfg(any(feature = "keychain", feature = "encrypted-file"))]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Default)]
struct MigrationSecretSettings {
    pub api: MigrationApiSettings,
}

#[cfg(any(feature = "keychain", feature = "encrypted-file"))]
impl rcman::SettingsSchema for MigrationSecretSettings {
    fn get_metadata() -> rcman::IndexMap<String, rcman::SettingMetadata> {
        rcman::settings! {
            "api.key" => {
                let s = rcman::SettingMetadata::text("")
                    .meta_str("label", "API Key");
                #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
                let s = s.secret();
                s
            }
        }
    }
}

#[cfg(any(feature = "keychain", feature = "encrypted-file"))]
#[test]
fn test_migration_normal_to_secret() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let app_name = unique_app_name();
    let _guard = TestCredentialsGuard::new(&app_name);

    // 1. Write the setting as a NORMAL setting using MigrationNormalSettings schema
    {
        let config = SettingsConfig::builder(&app_name, "1.0.0")
            .with_config_dir(temp_dir.path())
            .with_schema::<MigrationNormalSettings>()
            .with_credentials()
            .build();
        let manager = SettingsManager::new(config).unwrap();
        manager
            .save_setting("api", "key", &json!("my-plain-text-key"))
            .unwrap();

        // Verify it was written to the settings JSON file on disk
        let settings_path = temp_dir.path().join("settings.json");
        let content = std::fs::read_to_string(&settings_path).unwrap();
        assert!(content.contains("my-plain-text-key"));
    }

    // 2. Load the settings with MigrationSecretSettings schema (key is now secret)
    {
        let config = SettingsConfig::builder(&app_name, "1.0.0")
            .with_config_dir(temp_dir.path())
            .with_schema::<MigrationSecretSettings>()
            .with_credentials()
            .build();
        let manager = SettingsManager::new(config).unwrap();

        // 3. Verify it migrated:
        // - Value is in credential store
        let creds = manager.credentials().unwrap();
        let stored_secret = creds.get("api.key").unwrap();
        assert_eq!(stored_secret, Some("my-plain-text-key".to_string()));

        // - Value is removed from the settings file JSON
        let settings_path = temp_dir.path().join("settings.json");
        let content = std::fs::read_to_string(&settings_path).unwrap();
        assert!(!content.contains("my-plain-text-key"));
        assert!(!content.contains("api.key"));

        // - Reading the setting still returns the correct value
        let val: String = manager.get("api.key").unwrap();
        assert_eq!(val, "my-plain-text-key");
    }
}

#[cfg(any(feature = "keychain", feature = "encrypted-file"))]
#[test]
#[ignore = "Requires Secret Service daemon (not available in CI)"]
fn test_migration_secret_to_normal() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let app_name = unique_app_name();
    let _guard = TestCredentialsGuard::new(&app_name);

    // 1. Write the setting as a SECRET setting using MigrationSecretSettings schema
    {
        let config = SettingsConfig::builder(&app_name, "1.0.0")
            .with_config_dir(temp_dir.path())
            .with_schema::<MigrationSecretSettings>()
            .with_credentials()
            .build();
        let manager = SettingsManager::new(config).unwrap();
        manager
            .save_setting("api", "key", &json!("my-secret-key-value"))
            .unwrap();

        // Verify it is NOT in settings.json
        let settings_path = temp_dir.path().join("settings.json");
        if settings_path.exists() {
            let content = std::fs::read_to_string(&settings_path).unwrap();
            assert!(!content.contains("my-secret-key-value"));
        }

        // Verify it IS in credential store
        let creds = manager.credentials().unwrap();
        assert_eq!(
            creds.get("api.key").unwrap(),
            Some("my-secret-key-value".to_string())
        );
    }

    // 2. Load the settings with MigrationNormalSettings schema (key is now normal)
    {
        let config = SettingsConfig::builder(&app_name, "1.0.0")
            .with_config_dir(temp_dir.path())
            .with_schema::<MigrationNormalSettings>()
            .with_credentials()
            .build();
        let manager = SettingsManager::new(config).unwrap();

        // 3. Verify it migrated:
        // - Value is in settings.json
        let settings_path = temp_dir.path().join("settings.json");
        let content = std::fs::read_to_string(&settings_path).unwrap();
        assert!(content.contains("my-secret-key-value"));

        // - Value is removed from the credential store
        let creds = manager.credentials().unwrap();
        assert_eq!(creds.get("api.key").unwrap(), None);

        // - Reading the setting still returns the correct value
        let val: String = manager.get("api.key").unwrap();
        assert_eq!(val, "my-secret-key-value");
    }
}

#[cfg(any(feature = "keychain", feature = "encrypted-file"))]
#[test]
#[ignore = "Requires Secret Service daemon (not available in CI)"]
fn test_migration_upgrade_path() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let app_name = unique_app_name();
    let _guard = TestCredentialsGuard::new(&app_name);

    // 1. Write the secret setting using the new library first
    {
        let config = SettingsConfig::builder(&app_name, "1.0.0")
            .with_config_dir(temp_dir.path())
            .with_schema::<MigrationSecretSettings>()
            .with_credentials()
            .build();
        let manager = SettingsManager::new(config).unwrap();
        manager
            .save_setting("api", "key", &json!("old-version-secret"))
            .unwrap();

        // Verify it was stored in credential store
        let creds = manager.credentials().unwrap();
        assert_eq!(
            creds.get("api.key").unwrap(),
            Some("old-version-secret".to_string())
        );

        // Simulating upgrade: manually remove '__rcman_secrets__'
        creds.remove("__rcman_secrets__").unwrap();
    }

    // 2. Instantiate SettingsManager again (simulating upgrade)
    {
        let config = SettingsConfig::builder(&app_name, "1.0.0")
            .with_config_dir(temp_dir.path())
            .with_schema::<MigrationSecretSettings>()
            .with_credentials()
            .build();
        let manager = SettingsManager::new(config).unwrap();

        // Verify that the one-time scan was triggered and recreated '__rcman_secrets__'
        let creds = manager.credentials().unwrap();
        let list_str = creds.get("__rcman_secrets__").unwrap().unwrap();
        let list: Vec<String> = serde_json::from_str(&list_str).unwrap();
        assert!(list.contains(&"api.key".to_string()));

        // Verify the value is still there and correct
        let val: String = manager.get("api.key").unwrap();
        assert_eq!(val, "old-version-secret");
    }

    // 3. Migrate back to Normal settings
    {
        let config = SettingsConfig::builder(&app_name, "1.0.0")
            .with_config_dir(temp_dir.path())
            .with_schema::<MigrationNormalSettings>()
            .with_credentials()
            .build();
        let manager = SettingsManager::new(config).unwrap();

        // Verify that it migrated back to settings.json
        let settings_path = temp_dir.path().join("settings.json");
        let content = std::fs::read_to_string(&settings_path).unwrap();
        assert!(content.contains("old-version-secret"));

        // Verify it was removed from credential store
        let creds = manager.credentials().unwrap();
        assert_eq!(creds.get("api.key").unwrap(), None);

        // Verify that '__rcman_secrets__' list is empty
        let list_str = creds.get("__rcman_secrets__").unwrap().unwrap();
        let list: Vec<String> = serde_json::from_str(&list_str).unwrap();
        assert!(list.is_empty());
    }
}

#[cfg(any(feature = "keychain", feature = "encrypted-file"))]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Default)]
struct SubMigrationNormalSettings {
    pub host: String,
    pub token: String,
}

#[cfg(any(feature = "keychain", feature = "encrypted-file"))]
impl rcman::SettingsSchema for SubMigrationNormalSettings {
    fn get_metadata() -> rcman::IndexMap<String, rcman::SettingMetadata> {
        rcman::settings! {
            "host" => rcman::SettingMetadata::text(""),
            "token" => rcman::SettingMetadata::text("")
        }
    }
}

#[cfg(any(feature = "keychain", feature = "encrypted-file"))]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Default)]
struct SubMigrationSecretSettings {
    pub host: String,
    pub token: String,
}

#[cfg(any(feature = "keychain", feature = "encrypted-file"))]
impl rcman::SettingsSchema for SubMigrationSecretSettings {
    fn get_metadata() -> rcman::IndexMap<String, rcman::SettingMetadata> {
        rcman::settings! {
            "host" => rcman::SettingMetadata::text(""),
            "token" => {
                let s = rcman::SettingMetadata::text("");
                #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
                let s = s.secret();
                s
            }
        }
    }
}

#[cfg(any(feature = "keychain", feature = "encrypted-file"))]
#[test]
#[ignore = "Requires Secret Service daemon (not available in CI)"]
fn test_subsettings_migration() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let app_name = unique_app_name();
    let _guard = TestCredentialsGuard::new(&app_name);

    // 1. Save entry as a NORMAL setting in the sub-setting file
    {
        let config = SettingsConfig::builder(&app_name, "1.0.0")
            .with_config_dir(temp_dir.path())
            .with_credentials()
            .build();
        let manager = SettingsManager::new(config).unwrap();
        manager
            .register_sub_settings(
                rcman::SubSettingsConfig::new("remotes")
                    .with_schema::<SubMigrationNormalSettings>(),
            )
            .unwrap();

        let remotes = manager.sub_settings("remotes").unwrap();
        remotes
            .set(
                "gdrive",
                &json!({
                    "host": "example.com",
                    "token": "plain_token_123"
                }),
            )
            .unwrap();

        // Verify it was written to the sub-settings file
        let file_path = temp_dir.path().join("remotes").join("gdrive.json");
        let content = std::fs::read_to_string(&file_path).unwrap();
        assert!(content.contains("plain_token_123"));
        assert!(content.contains("example.com"));
    }

    // 2. Re-create manager, register with SECRET schema (token is now secret)
    {
        let config = SettingsConfig::builder(&app_name, "1.0.0")
            .with_config_dir(temp_dir.path())
            .with_credentials()
            .build();
        let manager = SettingsManager::new(config).unwrap();
        manager
            .register_sub_settings(
                rcman::SubSettingsConfig::new("remotes")
                    .with_schema::<SubMigrationSecretSettings>(),
            )
            .unwrap();

        let remotes = manager.sub_settings("remotes").unwrap();

        // Verification:
        // - Value is removed from the settings file JSON
        let file_path = temp_dir.path().join("remotes").join("gdrive.json");
        let content = std::fs::read_to_string(&file_path).unwrap();
        assert!(!content.contains("plain_token_123"));
        assert!(content.contains("example.com"));

        // - Value is in credential store
        let creds = manager.credentials().unwrap();
        let stored_secret = creds.get("sub.remotes.gdrive.token").unwrap();
        assert_eq!(stored_secret, Some("plain_token_123".to_string()));

        // - Reading the setting still returns the correct value
        let val: serde_json::Value = remotes.get_value("gdrive").unwrap();
        assert_eq!(val["token"], json!("plain_token_123"));
        assert_eq!(val["host"], json!("example.com"));
    }

    // 3. Migrate back to Normal settings
    {
        let config = SettingsConfig::builder(&app_name, "1.0.0")
            .with_config_dir(temp_dir.path())
            .with_credentials()
            .build();
        let manager = SettingsManager::new(config).unwrap();
        manager
            .register_sub_settings(
                rcman::SubSettingsConfig::new("remotes")
                    .with_schema::<SubMigrationNormalSettings>(),
            )
            .unwrap();

        let remotes = manager.sub_settings("remotes").unwrap();

        // Verification:
        // - Value is back in the settings file JSON
        let file_path = temp_dir.path().join("remotes").join("gdrive.json");
        let content = std::fs::read_to_string(&file_path).unwrap();
        assert!(content.contains("plain_token_123"));
        assert!(content.contains("example.com"));

        // - Value is removed from the credential store
        let creds = manager.credentials().unwrap();
        assert_eq!(creds.get("sub.remotes.gdrive.token").unwrap(), None);

        // - Reading the setting still returns the correct value
        let val: serde_json::Value = remotes.get_value("gdrive").unwrap();
        assert_eq!(val["token"], json!("plain_token_123"));
        assert_eq!(val["host"], json!("example.com"));
    }
}

#[cfg(any(feature = "keychain", feature = "encrypted-file"))]
#[test]
#[ignore = "Requires Secret Service daemon (not available in CI)"]
fn test_subsettings_migration_upgrade_path() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let app_name = unique_app_name();
    let _guard = TestCredentialsGuard::new(&app_name);

    // 1. Write the secret setting using the new library first
    {
        let config = SettingsConfig::builder(&app_name, "1.0.0")
            .with_config_dir(temp_dir.path())
            .with_credentials()
            .build();
        let manager = SettingsManager::new(config).unwrap();
        manager
            .register_sub_settings(
                rcman::SubSettingsConfig::new("remotes")
                    .with_schema::<SubMigrationSecretSettings>(),
            )
            .unwrap();

        let remotes = manager.sub_settings("remotes").unwrap();
        remotes
            .set(
                "gdrive",
                &json!({
                    "host": "example.com",
                    "token": "upgrade-secret-token"
                }),
            )
            .unwrap();

        // Verify it was stored in credential store
        let creds = manager.credentials().unwrap();
        assert_eq!(
            creds.get("sub.remotes.gdrive.token").unwrap(),
            Some("upgrade-secret-token".to_string())
        );

        // Simulating upgrade: manually remove '__rcman_secrets__'
        creds.remove("__rcman_secrets__").unwrap();
    }

    // 2. Instantiate SettingsManager again (simulating upgrade)
    {
        let config = SettingsConfig::builder(&app_name, "1.0.0")
            .with_config_dir(temp_dir.path())
            .with_credentials()
            .build();
        let manager = SettingsManager::new(config).unwrap();
        manager
            .register_sub_settings(
                rcman::SubSettingsConfig::new("remotes")
                    .with_schema::<SubMigrationSecretSettings>(),
            )
            .unwrap();

        let remotes = manager.sub_settings("remotes").unwrap();

        // Verify that the one-time scan was triggered and recreated '__rcman_secrets__'
        let creds = manager.credentials().unwrap();
        let list_str = creds.get("__rcman_secrets__").unwrap().unwrap();
        let list: Vec<String> = serde_json::from_str(&list_str).unwrap();
        assert!(list.contains(&"sub.remotes.gdrive.token".to_string()));

        // Verify the value is still there and correct
        let val: serde_json::Value = remotes.get_value("gdrive").unwrap();
        assert_eq!(val["token"], json!("upgrade-secret-token"));
    }

    // 3. Migrate back to Normal settings
    {
        let config = SettingsConfig::builder(&app_name, "1.0.0")
            .with_config_dir(temp_dir.path())
            .with_credentials()
            .build();
        let manager = SettingsManager::new(config).unwrap();
        manager
            .register_sub_settings(
                rcman::SubSettingsConfig::new("remotes")
                    .with_schema::<SubMigrationNormalSettings>(),
            )
            .unwrap();

        let _remotes = manager.sub_settings("remotes").unwrap();

        // Verify that it migrated back to the settings file
        let file_path = temp_dir.path().join("remotes").join("gdrive.json");
        let content = std::fs::read_to_string(&file_path).unwrap();
        assert!(content.contains("upgrade-secret-token"));

        // Verify it was removed from credential store
        let creds = manager.credentials().unwrap();
        assert_eq!(creds.get("sub.remotes.gdrive.token").unwrap(), None);

        // Verify that '__rcman_secrets__' list does not contain sub.remotes.gdrive.token
        let list_str = creds.get("__rcman_secrets__").unwrap().unwrap();
        let list: Vec<String> = serde_json::from_str(&list_str).unwrap();
        assert!(!list.contains(&"sub.remotes.gdrive.token".to_string()));
    }
}

// =============================================================================
// Runtime Keychain Disconnect Resilience & Zero-Stale Verification
// =============================================================================

#[cfg(any(feature = "keychain", feature = "encrypted-file"))]
#[test]
fn test_runtime_keychain_disconnect_resilience_and_zero_stale() {
    use rcman::CredentialBackend;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, RwLock};

    struct SimulatedOsKeychain {
        store: RwLock<std::collections::HashMap<String, String>>,
        is_disconnected: AtomicBool,
    }

    impl CredentialBackend for SimulatedOsKeychain {
        fn store(&self, key: &str, value: &str) -> rcman::Result<()> {
            if self.is_disconnected.load(Ordering::Relaxed) {
                return Err(rcman::Error::Credential(
                    "OS Keychain daemon disconnected".into(),
                ));
            }
            self.store
                .write()
                .unwrap()
                .insert(key.to_string(), value.to_string());
            Ok(())
        }

        fn get(&self, key: &str) -> rcman::Result<Option<String>> {
            if self.is_disconnected.load(Ordering::Relaxed) {
                return Err(rcman::Error::Credential(
                    "OS Keychain daemon disconnected".into(),
                ));
            }
            Ok(self.store.read().unwrap().get(key).cloned())
        }

        fn remove(&self, key: &str) -> rcman::Result<()> {
            self.store.write().unwrap().remove(key);
            Ok(())
        }

        fn list_keys(&self) -> rcman::Result<Vec<String>> {
            Ok(self.store.read().unwrap().keys().cloned().collect())
        }

        fn backend_name(&self) -> &'static str {
            "simulated_os_keychain"
        }
    }

    let temp_dir = tempfile::tempdir().unwrap();
    let keychain_backend = Arc::new(SimulatedOsKeychain {
        store: RwLock::new(std::collections::HashMap::new()),
        is_disconnected: AtomicBool::new(false),
    });

    let config = SettingsConfig::builder("resilience-app", "1.0.0")
        .with_config_dir(temp_dir.path())
        .with_schema::<TestSettings>()
        .with_credential_config(rcman::CredentialConfig::Custom(
            keychain_backend.clone() as Arc<dyn CredentialBackend>
        ))
        .build();
    let manager = SettingsManager::new(config).unwrap();

    // 1. Store secret while OS Keychain is healthy
    manager
        .save_setting("api", "key", &json!("secret-token-123"))
        .unwrap();

    let creds = manager.credentials().unwrap();

    // Verify it is in OS Keychain
    assert_eq!(
        creds.get("api.key").unwrap(),
        Some("secret-token-123".to_string())
    );

    // 2. Simulate OS Keychain crash / disconnect during active session
    keychain_backend
        .is_disconnected
        .store(true, Ordering::Relaxed);

    // Manager should seamlessly fall back to volatile memory safety net without error
    let recovered_val = creds.get("api.key").unwrap();
    assert_eq!(
        recovered_val,
        Some("secret-token-123".to_string()),
        "Should recover secret from in-memory safety net when OS Keychain is unavailable"
    );

    // Also verify via manager metadata retrieval
    let meta = manager.metadata().unwrap();
    assert_eq!(
        meta.get("api.key").unwrap().value,
        Some(json!("secret-token-123"))
    );

    // 3. Simulate OS Keychain coming back online with external modification
    keychain_backend
        .is_disconnected
        .store(false, Ordering::Relaxed);
    keychain_backend.store.write().unwrap().insert(
        "resilience-app:api.key".to_string(),
        "external-changed-token-456".to_string(),
    );

    // Zero-stale guarantee: Manager must prioritize the live OS Keychain value over in-memory cache
    let fresh_val = creds.get("api.key").unwrap();
    assert_eq!(
        fresh_val,
        Some("external-changed-token-456".to_string()),
        "Must immediately return the latest OS Keychain value (zero stale data)"
    );

    let fresh_meta = manager.metadata().unwrap();
    assert_eq!(
        fresh_meta.get("api.key").unwrap().value,
        Some(json!("external-changed-token-456"))
    );
}
