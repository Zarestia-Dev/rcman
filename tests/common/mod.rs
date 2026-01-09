//! Common test utilities for rcman integration tests
//!
//! Provides shared test fixtures, settings schemas, and helper functions.

#![allow(dead_code)]

use rcman::{
    opt, settings, SettingMetadata, SettingsConfig, SettingsManager, SettingsSchema,
    SubSettingsConfig,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use tempfile::TempDir;

// =============================================================================
// Test Settings Schema
// =============================================================================

/// A comprehensive test settings struct covering all setting types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct TestSettings {
    pub ui: UiSettings,
    pub general: GeneralSettings,
    pub api: ApiSettings,
    pub paths: PathsSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UiSettings {
    pub theme: String,
    pub font_size: f64,
}

impl Default for UiSettings {
    fn default() -> Self {
        Self {
            theme: "dark".to_string(),
            font_size: 14.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GeneralSettings {
    #[serde(rename = "tray_enabled")]
    pub tray_enabled: bool,
    pub language: String,
}

impl Default for GeneralSettings {
    fn default() -> Self {
        Self {
            tray_enabled: true,
            language: "en".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApiSettings {
    pub key: String,
}

impl Default for ApiSettings {
    fn default() -> Self {
        Self {
            key: "".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PathsSettings {
    #[serde(rename = "config_dir")]
    pub config_dir: String,
    #[serde(rename = "log_file")]
    pub log_file: String,
}

impl Default for PathsSettings {
    fn default() -> Self {
        Self {
            config_dir: "".to_string(),
            log_file: "".to_string(),
        }
    }
}

impl SettingsSchema for TestSettings {
    fn get_metadata() -> HashMap<String, SettingMetadata> {
        settings! {
            "ui.theme" => SettingMetadata::select("Theme", "dark", vec![
                opt("light", "Light"),
                opt("dark", "Dark"),
                opt("system", "System"),
            ])
            .category("appearance")
            .description("Application color theme")
            .order(1),

            "ui.font_size" => SettingMetadata::number("Font Size", 14.0)
                .category("appearance")
                .description("Base font size in pixels")
                .min(8.0)
                .max(32.0)
                .step(1.0)
                .order(2),

            "general.tray_enabled" => SettingMetadata::toggle("Enable Tray", true)
                .category("general")
                .description("Show system tray icon")
                .order(1),

            "general.language" => SettingMetadata::select("Language", "en", vec![
                opt("en", "English"),
                opt("tr", "Turkish"),
                opt("de", "German"),
            ])
            .category("general")
            .order(2),

            "api.key" => SettingMetadata::password("API Key", "")
                .category("security")
                .description("Secret API key for external services")
                .secret(),

            "paths.config_dir" => SettingMetadata::path("Config Directory", "")
                .category("paths")
                .description("Directory for configuration files"),

            "paths.log_file" => SettingMetadata::file("Log File", "")
                .category("paths")
                .description("Path to the log file"),
        }
    }
}

// =============================================================================
// Test Fixtures
// =============================================================================

/// Test fixture that provides a temporary directory and configured SettingsManager
pub struct TestFixture {
    pub temp_dir: TempDir,
    pub manager: SettingsManager<rcman::storage::JsonStorage, TestSettings>,
}

impl TestFixture {
    /// Create a new test fixture with default configuration
    pub fn new() -> Self {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let config = SettingsConfig::builder("test-app", "1.0.0")
            .with_config_dir(temp_dir.path())
            .with_schema::<TestSettings>()
            .build();
        let manager = SettingsManager::new(config).expect("Failed to create manager");

        Self { temp_dir, manager }
    }

    /// Create a fixture with sub-settings configured
    pub fn with_sub_settings() -> Self {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let config = SettingsConfig::builder("test-app", "1.0.0")
            .with_config_dir(temp_dir.path())
            .with_schema::<TestSettings>()
            .build();
        let manager = SettingsManager::new(config).expect("Failed to create manager");

        // Register sub-settings manually
        manager.register_sub_settings(SubSettingsConfig::new("remotes")).unwrap();
        manager.register_sub_settings(SubSettingsConfig::singlefile("backends")).unwrap();

        Self { temp_dir, manager }
    }

    /// Create a fixture with environment variable prefix
    pub fn with_env_prefix(prefix: &str) -> Self {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let config = SettingsConfig::builder("test-app", "1.0.0")
            .with_config_dir(temp_dir.path())
            .with_schema::<TestSettings>()
            .with_env_prefix(prefix)
            .build();
        let manager = SettingsManager::new(config).expect("Failed to create manager");

        Self { temp_dir, manager }
    }

    /// Get the config directory path
    pub fn config_dir(&self) -> PathBuf {
        self.temp_dir.path().to_path_buf()
    }

    /// Get the settings file path
    pub fn settings_path(&self) -> PathBuf {
        self.temp_dir.path().join("settings.json")
    }
}

impl Default for TestFixture {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Read the raw settings JSON file content
pub fn read_settings_file(fixture: &TestFixture) -> Option<serde_json::Value> {
    let path = fixture.settings_path();
    if path.exists() {
        let content = std::fs::read_to_string(&path).ok()?;
        serde_json::from_str(&content).ok()
    } else {
        None
    }
}

/// Check if a key exists in the settings JSON file
pub fn key_exists_in_file(fixture: &TestFixture, key: &str) -> bool {
    read_settings_file(fixture)
        .map(|json| json.get(key).is_some())
        .unwrap_or(false)
}
