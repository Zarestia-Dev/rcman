//! Profiles Feature Integration Tests
//!
//! Tests for profile management in sub-settings including:
//! - Profile CRUD operations
//! - Profile switching and cache invalidation
//! - Multi-file and single-file mode with profiles
//! - Profile events

mod common;

use rcman::{SettingsConfig, SettingsManager, SubSettingsConfig};
use serde_json::json;
use std::sync::{Arc, Mutex};
use tempfile::TempDir;

// =============================================================================
// Profile CRUD Operations
// =============================================================================

#[test]
fn test_create_profile() {
    let temp_dir = TempDir::new().unwrap();

    let manager = SettingsManager::builder("test-app", "1.0.0")
        .with_config_dir(temp_dir.path())
        .with_sub_settings(SubSettingsConfig::new("remotes").with_profiles())
        .build()
        .unwrap();

    let remotes = manager.sub_settings("remotes").unwrap();
    let profiles = remotes.profiles().unwrap();

    // Create a new profile
    profiles.create("work").unwrap();

    // Verify it exists
    let list = profiles.list().unwrap();
    assert!(list.contains(&"default".to_string()));
    assert!(list.contains(&"work".to_string()));
}

#[test]
fn test_switch_profile() {
    let temp_dir = TempDir::new().unwrap();

    let manager = SettingsManager::builder("test-app", "1.0.0")
        .with_config_dir(temp_dir.path())
        .with_sub_settings(SubSettingsConfig::new("remotes").with_profiles())
        .build()
        .unwrap();

    let remotes = manager.sub_settings("remotes").unwrap();
    let profiles = remotes.profiles().unwrap();

    profiles.create("work").unwrap();
    profiles.switch("work").unwrap();

    assert_eq!(profiles.active().unwrap(), "work");
}

#[test]
fn test_seamless_profile_switching() {
    let temp_dir = TempDir::new().unwrap();

    let manager = SettingsManager::builder("test-app", "1.0.0")
        .with_config_dir(temp_dir.path())
        .with_sub_settings(SubSettingsConfig::new("remotes").with_profiles())
        .build()
        .unwrap();

    let remotes = manager.sub_settings("remotes").unwrap();

    // Add data to default profile
    remotes
        .set("personal-gdrive", &json!({"type": "drive"}))
        .unwrap();
    assert!(remotes.exists("personal-gdrive").unwrap());

    // Create work profile and switch to it using the convenience method
    remotes.profiles().unwrap().create("work").unwrap();
    remotes.switch_profile("work").unwrap();

    // In work profile, personal-gdrive should not exist (different directory)
    assert!(!remotes.exists("personal-gdrive").unwrap());

    // Add work-specific data
    remotes
        .set("company-drive", &json!({"type": "sharepoint"}))
        .unwrap();
    assert!(remotes.exists("company-drive").unwrap());

    // Switch back to default
    remotes.switch_profile("default").unwrap();

    // Back in default, personal-gdrive exists, company-drive does not
    assert!(remotes.exists("personal-gdrive").unwrap());
    assert!(!remotes.exists("company-drive").unwrap());
}

#[test]
fn test_delete_profile() {
    let temp_dir = TempDir::new().unwrap();

    let manager = SettingsManager::builder("test-app", "1.0.0")
        .with_config_dir(temp_dir.path())
        .with_sub_settings(SubSettingsConfig::new("remotes").with_profiles())
        .build()
        .unwrap();

    let remotes = manager.sub_settings("remotes").unwrap();
    let profiles = remotes.profiles().unwrap();

    profiles.create("temp").unwrap();
    assert!(profiles.exists("temp").unwrap());

    profiles.delete("temp").unwrap();
    assert!(!profiles.exists("temp").unwrap());
}

#[test]
fn test_cannot_delete_active_profile() {
    let temp_dir = TempDir::new().unwrap();

    let manager = SettingsManager::builder("test-app", "1.0.0")
        .with_config_dir(temp_dir.path())
        .with_sub_settings(SubSettingsConfig::new("remotes").with_profiles())
        .build()
        .unwrap();

    let remotes = manager.sub_settings("remotes").unwrap();
    let profiles = remotes.profiles().unwrap();

    // default is active, can't delete it
    let result = profiles.delete("default");
    assert!(result.is_err());
}

#[test]
fn test_rename_profile() {
    let temp_dir = TempDir::new().unwrap();

    let manager = SettingsManager::builder("test-app", "1.0.0")
        .with_config_dir(temp_dir.path())
        .with_sub_settings(SubSettingsConfig::new("remotes").with_profiles())
        .build()
        .unwrap();

    let remotes = manager.sub_settings("remotes").unwrap();
    let profiles = remotes.profiles().unwrap();

    profiles.create("old-name").unwrap();
    profiles.rename("old-name", "new-name").unwrap();

    let list = profiles.list().unwrap();
    assert!(!list.contains(&"old-name".to_string()));
    assert!(list.contains(&"new-name".to_string()));
}

#[test]
fn test_duplicate_profile() {
    let temp_dir = TempDir::new().unwrap();

    let manager = SettingsManager::builder("test-app", "1.0.0")
        .with_config_dir(temp_dir.path())
        .with_sub_settings(SubSettingsConfig::new("remotes").with_profiles())
        .build()
        .unwrap();

    let remotes = manager.sub_settings("remotes").unwrap();

    // Add some data to default profile
    remotes.set("gdrive", &json!({"type": "drive"})).unwrap();

    let profiles = remotes.profiles().unwrap();
    profiles.duplicate("default", "backup").unwrap();

    // Verify both profiles exist
    let list = profiles.list().unwrap();
    assert!(list.contains(&"default".to_string()));
    assert!(list.contains(&"backup".to_string()));

    // Verify the backup profile has the data
    let backup_dir = temp_dir
        .path()
        .join("remotes")
        .join("profiles")
        .join("backup");
    assert!(backup_dir.join("gdrive.json").exists());
}

// =============================================================================
// Profile Events
// =============================================================================

#[test]
fn test_profile_events() {
    let temp_dir = TempDir::new().unwrap();

    let manager = SettingsManager::builder("test-app", "1.0.0")
        .with_config_dir(temp_dir.path())
        .with_sub_settings(SubSettingsConfig::new("remotes").with_profiles())
        .build()
        .unwrap();

    let remotes = manager.sub_settings("remotes").unwrap();
    let profiles = remotes.profiles().unwrap();

    let events = Arc::new(Mutex::new(Vec::new()));
    let events_clone = events.clone();

    profiles.set_on_event(move |event| {
        events_clone.lock().unwrap().push(format!("{:?}", event));
    });

    profiles.create("work").unwrap();
    profiles.switch("work").unwrap();
    profiles.rename("work", "job").unwrap();

    let recorded = events.lock().unwrap();
    assert_eq!(recorded.len(), 3);
}

// =============================================================================
// Profiles Not Enabled
// =============================================================================

#[test]
fn test_profiles_not_enabled_error() {
    let temp_dir = TempDir::new().unwrap();

    let manager = SettingsManager::builder("test-app", "1.0.0")
        .with_config_dir(temp_dir.path())
        .with_sub_settings(SubSettingsConfig::new("remotes")) // No .with_profiles()
        .build()
        .unwrap();

    let remotes = manager.sub_settings("remotes").unwrap();
    let result = remotes.profiles();

    assert!(result.is_err());
}

// =============================================================================
// Profile Directory Structure
// =============================================================================

#[test]
fn test_profile_directory_structure() {
    let temp_dir = TempDir::new().unwrap();

    let manager = SettingsManager::builder("test-app", "1.0.0")
        .with_config_dir(temp_dir.path())
        .with_sub_settings(SubSettingsConfig::new("remotes").with_profiles())
        .build()
        .unwrap();

    let remotes = manager.sub_settings("remotes").unwrap();

    // Add data to default profile
    remotes.set("gdrive", &json!({"type": "drive"})).unwrap();

    // Create and switch to work profile
    let profiles = remotes.profiles().unwrap();
    profiles.create("work").unwrap();

    // Verify directory structure
    let remotes_dir = temp_dir.path().join("remotes");
    assert!(remotes_dir.join(".profiles.json").exists());
    assert!(remotes_dir.join("profiles").join("default").is_dir());
    assert!(remotes_dir.join("profiles").join("work").is_dir());
    assert!(remotes_dir
        .join("profiles")
        .join("default")
        .join("gdrive.json")
        .exists());
}

// =============================================================================
// Single-File Mode with Profiles
// =============================================================================

#[test]
fn test_single_file_mode_with_profiles() {
    let temp_dir = TempDir::new().unwrap();

    let manager = SettingsManager::builder("test-app", "1.0.0")
        .with_config_dir(temp_dir.path())
        .with_sub_settings(SubSettingsConfig::singlefile("backends").with_profiles())
        .build()
        .unwrap();

    let backends = manager.sub_settings("backends").unwrap();

    // Add data
    backends
        .set("local", &json!({"host": "localhost"}))
        .unwrap();

    let profiles = backends.profiles().unwrap();
    profiles.create("work").unwrap();

    // Verify single file in profile directory
    let backends_dir = temp_dir.path().join("backends");
    assert!(backends_dir.join(".profiles.json").exists());
    assert!(backends_dir
        .join("profiles")
        .join("default")
        .join("backends.json")
        .exists());
}

// =============================================================================
// Main Settings Profiles
// =============================================================================

#[test]
fn test_main_settings_profiles() {
    use rcman::{SettingMetadata, SettingsSchema};
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;

    #[derive(Serialize, Deserialize, Default)]
    struct TestSettings {
        #[serde(default)]
        general: GeneralSettings,
    }

    #[derive(Serialize, Deserialize)]
    struct GeneralSettings {
        #[serde(default = "default_theme")]
        theme: String,
    }

    fn default_theme() -> String {
        "light".to_string()
    }

    impl Default for GeneralSettings {
        fn default() -> Self {
            Self {
                theme: default_theme(),
            }
        }
    }

    impl SettingsSchema for TestSettings {
        fn get_metadata() -> HashMap<String, SettingMetadata> {
            let mut map = HashMap::new();
            map.insert(
                "general.theme".to_string(),
                SettingMetadata::text("Theme", "light"),
            );
            map
        }
    }

    let temp_dir = TempDir::new().unwrap();

    let config = SettingsConfig::builder("test-app", "1.0.0")
        .with_config_dir(temp_dir.path())
        .with_schema::<TestSettings>()
        .with_profiles() // Enable profiles for main settings
        .build();
    let manager = SettingsManager::new(config).unwrap();

    // Verify profiles are enabled
    assert!(manager.is_profiles_enabled());

    // Check default profile
    assert_eq!(manager.active_profile().unwrap(), "default");

    // Save setting in default profile
    manager
        .save_setting("general", "theme", json!("dark"))
        .unwrap();

    // Create and switch to work profile
    manager.create_profile("work").unwrap();
    manager.switch_profile("work").unwrap();

    assert_eq!(manager.active_profile().unwrap(), "work");

    // Work profile should have default theme (light)
    let settings: TestSettings = manager.get_all().unwrap();
    assert_eq!(settings.general.theme, "light");

    // Save a different theme in work profile
    manager
        .save_setting("general", "theme", json!("ocean"))
        .unwrap();

    // Switch back to default - should have dark theme
    manager.switch_profile("default").unwrap();
    let settings: TestSettings = manager.get_all().unwrap();
    assert_eq!(settings.general.theme, "dark");

    // Switch to work - should have ocean theme
    manager.switch_profile("work").unwrap();
    let settings: TestSettings = manager.get_all().unwrap();
    assert_eq!(settings.general.theme, "ocean");
}

#[test]
fn test_main_settings_profiles_directory_structure() {
    use rcman::{SettingMetadata, SettingsSchema};
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;

    #[derive(Default, Serialize, Deserialize)]
    struct TestSettings {
        ui: UiSettings,
    }

    #[derive(Default, Serialize, Deserialize)]
    struct UiSettings {
        theme: String,
    }

    impl SettingsSchema for TestSettings {
        fn get_metadata() -> HashMap<String, SettingMetadata> {
            let mut map = HashMap::new();
            map.insert(
                "ui.theme".to_string(),
                SettingMetadata::text("Theme", "light"),
            );
            map
        }
    }

    let temp_dir = TempDir::new().unwrap();

    let config = SettingsConfig::builder("test-app", "1.0.0")
        .with_config_dir(temp_dir.path())
        .with_schema::<TestSettings>()
        .with_profiles()
        .build();
    let manager = SettingsManager::new(config).unwrap();

    // Save something to create the default profile directory
    manager.save_setting("ui", "theme", json!("dark")).unwrap();

    manager.create_profile("work").unwrap();

    // Check directory structure
    // .profiles.json should exist at config root
    assert!(
        temp_dir.path().join(".profiles.json").exists(),
        ".profiles.json should exist"
    );

    // profiles/ directory should exist
    let profiles_dir = temp_dir.path().join("profiles");
    assert!(profiles_dir.exists(), "profiles/ directory should exist");

    // work profile dir exists because we created it
    assert!(
        profiles_dir.join("work").exists(),
        "work profile directory should exist"
    );

    // default profile dir should exist after saving
    assert!(
        profiles_dir.join("default").exists(),
        "default profile directory should exist after saving"
    );
    assert!(
        profiles_dir.join("default").join("settings.json").exists(),
        "settings.json should exist in default profile"
    );
}
