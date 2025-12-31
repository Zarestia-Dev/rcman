//! Integration tests for rcman-derive macro
//!
//! Tests the `#[derive(DeriveSettingsSchema)]` macro with various attribute combinations.

use rcman::{DeriveSettingsSchema, SettingsSchema};
use serde::{Deserialize, Serialize};

// =============================================================================
// Basic Derive Tests
// =============================================================================

#[derive(Default, Serialize, Deserialize, DeriveSettingsSchema)]
#[schema(category = "general")]
struct BasicSettings {
    #[setting(label = "Enable Feature")]
    enabled: bool,

    #[setting(label = "User Name", description = "The display name")]
    name: String,

    #[setting(label = "Max Count", min = 0, max = 100)]
    count: u32,
}

#[test]
fn test_basic_derive() {
    let metadata = BasicSettings::get_metadata();

    assert!(metadata.contains_key("general.enabled"));
    assert!(metadata.contains_key("general.name"));
    assert!(metadata.contains_key("general.count"));

    // Check label
    let enabled = metadata.get("general.enabled").unwrap();
    assert_eq!(enabled.label, "Enable Feature");

    // Check description
    let name = metadata.get("general.name").unwrap();
    assert_eq!(name.description.as_deref(), Some("The display name"));

    // Check min/max
    let count = metadata.get("general.count").unwrap();
    assert_eq!(count.min, Some(0.0));
    assert_eq!(count.max, Some(100.0));
}

// =============================================================================
// Nested Struct Tests
// =============================================================================

#[derive(Default, Serialize, Deserialize, DeriveSettingsSchema)]
#[schema(category = "ui")]
struct UiSettings {
    #[setting(label = "Theme")]
    theme: String,

    #[setting(label = "Dark Mode")]
    dark_mode: bool,
}

#[derive(Default, Serialize, Deserialize, DeriveSettingsSchema)]
struct AppSettings {
    ui: UiSettings,

    #[setting(label = "Language", category = "general")]
    language: String,
}

#[test]
fn test_nested_structs() {
    let metadata = AppSettings::get_metadata();

    // Nested ui settings should have "ui." prefix
    assert!(metadata.contains_key("ui.theme"));
    assert!(metadata.contains_key("ui.dark_mode"));

    // Top-level setting with explicit category
    assert!(metadata.contains_key("general.language"));
}

// =============================================================================
// Select Options Tests
// =============================================================================

#[derive(Default, Serialize, Deserialize, DeriveSettingsSchema)]
#[schema(category = "config")]
struct SelectSettings {
    #[setting(
        label = "Log Level",
        options(("debug", "Debug"), ("info", "Info"), ("error", "Error"))
    )]
    log_level: String,
}

#[test]
fn test_select_options() {
    let metadata = SelectSettings::get_metadata();

    let log_level = metadata.get("config.log_level").unwrap();
    assert!(log_level.options.is_some());

    let options = log_level.options.as_ref().unwrap();
    assert_eq!(options.len(), 3);
    assert_eq!(options[0].value, "debug");
    assert_eq!(options[0].label, "Debug");
}

// =============================================================================
// Skip Field Tests
// =============================================================================

#[derive(Default, Serialize, Deserialize, DeriveSettingsSchema)]
#[schema(category = "test")]
struct SkipSettings {
    #[setting(label = "Visible")]
    visible: bool,

    #[setting(skip)]
    internal_state: u32,
}

#[test]
fn test_skip_field() {
    let metadata = SkipSettings::get_metadata();

    assert!(metadata.contains_key("test.visible"));
    assert!(!metadata.contains_key("test.internal_state"));
}

// =============================================================================
// Advanced Attributes Tests
// =============================================================================

#[derive(Default, Serialize, Deserialize, DeriveSettingsSchema)]
#[schema(category = "advanced")]
struct AdvancedSettings {
    #[setting(label = "API Key", secret)]
    api_key: String,

    #[setting(label = "Debug Mode", advanced)]
    debug_mode: bool,

    #[setting(label = "Port", requires_restart)]
    port: u16,
}

#[test]
fn test_advanced_attributes() {
    let metadata = AdvancedSettings::get_metadata();

    let api_key = metadata.get("advanced.api_key").unwrap();
    assert!(api_key.secret);

    let debug_mode = metadata.get("advanced.debug_mode").unwrap();
    assert!(debug_mode.advanced);

    let port = metadata.get("advanced.port").unwrap();
    assert!(port.requires_restart);
}

// =============================================================================
// Auto-Generated Labels Tests
// =============================================================================

#[derive(Default, Serialize, Deserialize, DeriveSettingsSchema)]
#[schema(category = "auto")]
struct AutoLabelSettings {
    // No label attribute - should auto-generate from field name
    enable_notifications: bool,
    max_retry_count: u32,
}

#[test]
fn test_auto_generated_labels() {
    let metadata = AutoLabelSettings::get_metadata();

    let notifications = metadata.get("auto.enable_notifications").unwrap();
    assert_eq!(notifications.label, "Enable Notifications");

    let retry = metadata.get("auto.max_retry_count").unwrap();
    assert_eq!(retry.label, "Max Retry Count");
}

// =============================================================================
// Type Detection Tests
// =============================================================================

#[derive(Default, Serialize, Deserialize, DeriveSettingsSchema)]
#[schema(category = "types")]
struct TypeSettings {
    flag: bool,
    text: String,
    small_int: i16,
    big_int: u64,
    decimal: f64,
    tags: Vec<String>,
}

#[test]
fn test_type_detection() {
    let metadata = TypeSettings::get_metadata();

    // All fields should be detected with correct types
    assert!(metadata.contains_key("types.flag"));
    assert!(metadata.contains_key("types.text"));
    assert!(metadata.contains_key("types.small_int"));
    assert!(metadata.contains_key("types.big_int"));
    assert!(metadata.contains_key("types.decimal"));
    assert!(metadata.contains_key("types.tags"));
}
