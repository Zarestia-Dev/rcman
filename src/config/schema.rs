//! Settings schema trait and metadata types

use crate::credentials::SecretStorage;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;

/// Type of setting for UI rendering
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SettingType {
    /// Boolean toggle
    Toggle,
    /// Text input
    #[default]
    Text,
    /// Numeric input
    Number,
    /// Dropdown/select with predefined options
    Select,
    /// Color picker
    Color,
    /// Directory path selector
    Path,
    /// File path selector
    File,
    /// Multi-line text
    Textarea,
    /// Password/sensitive input
    Password,
    /// Read-only display
    Info,
    /// List of strings
    List,
}

/// Metadata for a single setting
///
/// # Example
///
/// ```
/// use rcman::{SettingMetadata, opt};
///
/// // Toggle setting
/// let dark_mode = SettingMetadata::toggle("Dark Mode", false)
///     .description("Enable dark theme")
///     .category("appearance");
///
/// // Number with range
/// let font_size = SettingMetadata::number("Font Size", 14.0)
///     .min(8.0).max(32.0).step(1.0);
///
/// // Select with options
/// let theme = SettingMetadata::select("Theme", "dark", vec![
///     opt("light", "Light"),
///     opt("dark", "Dark"),
/// ]);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettingMetadata {
    /// Type of setting (for UI rendering)
    #[serde(rename = "type")]
    pub setting_type: SettingType,

    /// Default value
    pub default: Value,

    /// Current value (populated at runtime)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,

    /// Human-readable label
    pub label: String,

    /// Description/help text
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Available options (for Select type)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<SettingOption>>,

    /// Minimum value (for Number type)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,

    /// Maximum value (for Number type)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,

    /// Step increment (for Number type)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub step: Option<f64>,

    /// Placeholder text
    #[serde(skip_serializing_if = "Option::is_none")]
    pub placeholder: Option<String>,

    /// Whether this setting requires app restart
    #[serde(default)]
    pub requires_restart: bool,

    /// Category for grouping in UI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,

    /// Order within category (lower = higher priority)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order: Option<i32>,

    /// Whether this setting is experimental/advanced
    #[serde(default)]
    pub advanced: bool,

    /// Whether this setting should be disabled
    #[serde(default)]
    pub disabled: bool,

    /// Whether this is a secret/sensitive value (stored in credential manager)
    #[serde(default)]
    pub secret: bool,

    /// Where to store secret values (only used if secret=true)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_storage: Option<SecretStorage>,

    /// Regex pattern for validation (for Text type)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,

    /// Error message for pattern validation failure
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern_error: Option<String>,

    /// Whether the value is overridden by an environment variable
    /// (populated at runtime for UI display)
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub env_override: bool,
}

impl Default for SettingMetadata {
    fn default() -> Self {
        Self {
            setting_type: SettingType::Text,
            default: Value::Null,
            value: None,
            label: String::new(),
            description: None,
            options: None,
            min: None,
            max: None,
            step: None,
            placeholder: None,
            requires_restart: false,
            category: None,
            order: None,
            advanced: false,
            disabled: false,
            secret: false,
            secret_storage: None,
            pattern: None,
            pattern_error: None,
            env_override: false,
        }
    }
}

impl SettingMetadata {
    // =========================================================================
    // Type-specific constructors (for easier creation)
    // =========================================================================

    /// Create a text input setting
    pub fn text(label: impl Into<String>, default: impl Into<String>) -> Self {
        Self {
            setting_type: SettingType::Text,
            label: label.into(),
            default: Value::String(default.into()),
            ..Default::default()
        }
    }

    /// Create a password/secret input setting
    pub fn password(label: impl Into<String>, default: impl Into<String>) -> Self {
        Self {
            setting_type: SettingType::Password,
            label: label.into(),
            default: Value::String(default.into()),
            ..Default::default()
        }
    }

    /// Create a number input setting
    pub fn number(label: impl Into<String>, default: impl Into<f64>) -> Self {
        Self {
            setting_type: SettingType::Number,
            label: label.into(),
            default: json!(default.into()),
            ..Default::default()
        }
    }

    /// Create a toggle/boolean setting
    pub fn toggle(label: impl Into<String>, default: bool) -> Self {
        Self {
            setting_type: SettingType::Toggle,
            label: label.into(),
            default: Value::Bool(default),
            ..Default::default()
        }
    }

    /// Create a select/dropdown setting
    pub fn select(
        label: impl Into<String>,
        default: impl Into<String>,
        options: Vec<SettingOption>,
    ) -> Self {
        Self {
            setting_type: SettingType::Select,
            label: label.into(),
            default: Value::String(default.into()),
            options: Some(options),
            ..Default::default()
        }
    }

    /// Create a color picker setting
    pub fn color(label: impl Into<String>, default: impl Into<String>) -> Self {
        Self {
            setting_type: SettingType::Color,
            label: label.into(),
            default: Value::String(default.into()),
            ..Default::default()
        }
    }

    /// Create a directory path selector setting
    pub fn path(label: impl Into<String>, default: impl Into<String>) -> Self {
        Self {
            setting_type: SettingType::Path,
            label: label.into(),
            default: Value::String(default.into()),
            ..Default::default()
        }
    }

    /// Create a file path selector setting
    pub fn file(label: impl Into<String>, default: impl Into<String>) -> Self {
        Self {
            setting_type: SettingType::File,
            label: label.into(),
            default: Value::String(default.into()),
            ..Default::default()
        }
    }

    /// Create an info/read-only setting
    pub fn info(label: impl Into<String>, default: Value) -> Self {
        Self {
            setting_type: SettingType::Info,
            label: label.into(),
            default,
            ..Default::default()
        }
    }

    /// Create a list setting (`Vec<String>`)
    pub fn list(label: impl Into<String>, default: Vec<String>) -> Self {
        Self {
            setting_type: SettingType::List,
            label: label.into(),
            default: json!(default),
            ..Default::default()
        }
    }

    // =========================================================================
    // Chainable setters (builder pattern)
    // =========================================================================

    /// Set description
    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Set options for Select type
    #[must_use] 
    pub fn options(mut self, opts: Vec<SettingOption>) -> Self {
        self.options = Some(opts);
        self
    }

    /// Set minimum value for Number type
    #[must_use] 
    pub fn min(mut self, val: f64) -> Self {
        self.min = Some(val);
        self
    }

    /// Set maximum value for Number type
    #[must_use] 
    pub fn max(mut self, val: f64) -> Self {
        self.max = Some(val);
        self
    }

    /// Set step for Number type
    #[must_use] 
    pub fn step(mut self, val: f64) -> Self {
        self.step = Some(val);
        self
    }

    /// Set placeholder text
    pub fn placeholder(mut self, text: impl Into<String>) -> Self {
        self.placeholder = Some(text.into());
        self
    }

    /// Mark as requiring restart
    #[must_use] 
    pub fn requires_restart(mut self) -> Self {
        self.requires_restart = true;
        self
    }

    /// Set category for grouping
    pub fn category(mut self, cat: impl Into<String>) -> Self {
        self.category = Some(cat.into());
        self
    }

    /// Set display order
    #[must_use] 
    pub fn order(mut self, ord: i32) -> Self {
        self.order = Some(ord);
        self
    }

    /// Mark as advanced setting
    #[must_use] 
    pub fn advanced(mut self) -> Self {
        self.advanced = true;
        self
    }

    /// Mark as disabled
    #[must_use] 
    pub fn disabled(mut self) -> Self {
        self.disabled = true;
        self
    }

    /// Mark as secret (stored in keychain when credentials enabled)
    #[must_use] 
    pub fn secret(mut self) -> Self {
        self.secret = true;
        self
    }

    /// Set regex pattern for validation
    pub fn pattern(mut self, pattern: impl Into<String>) -> Self {
        self.pattern = Some(pattern.into());
        self
    }

    /// Set pattern validation error message
    pub fn pattern_error(mut self, msg: impl Into<String>) -> Self {
        self.pattern_error = Some(msg.into());
        self
    }

    // =========================================================================
    // Validation
    // =========================================================================

    /// Validate a value against this setting's constraints
    ///
    /// Checks:
    /// - Number range (min/max)
    /// - Regex pattern for text
    /// - Valid option for select type
    pub fn validate(&self, value: &Value) -> Result<(), String> {
        match self.setting_type {
            SettingType::Number => {
                let num = value
                    .as_f64()
                    .ok_or_else(|| "Value must be a number".to_string())?;

                if let Some(min) = self.min {
                    if num < min {
                        return Err(format!("Value must be at least {min}"));
                    }
                }
                if let Some(max) = self.max {
                    if num > max {
                        return Err(format!("Value must be at most {max}"));
                    }
                }
            }
            SettingType::Text | SettingType::Password | SettingType::Textarea => {
                if let Some(ref pattern) = self.pattern {
                    let text = value.as_str().unwrap_or_default();
                    let re = regex::Regex::new(pattern)
                        .map_err(|e| format!("Invalid regex pattern: {e}"))?;

                    if !re.is_match(text) {
                        return Err(self.pattern_error.clone().unwrap_or_else(|| {
                            format!("Value does not match pattern: {pattern}")
                        }));
                    }
                }
            }
            SettingType::Select => {
                if let Some(ref options) = self.options {
                    let is_valid = options.iter().any(|opt| opt.value == *value);
                    if !is_valid {
                        return Err("Value must be one of the available options".to_string());
                    }
                }
            }
            _ => {} // Toggle, Color, Path, File, Info don't need special validation
        }
        Ok(())
    }
}

/// Option for Select type settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettingOption {
    /// Value to store
    pub value: Value,
    /// Display label
    pub label: String,
    /// Optional description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl SettingOption {
    /// Create a simple string option
    pub fn new(value: impl Into<String>, label: impl Into<String>) -> Self {
        let value_str = value.into();
        Self {
            value: Value::String(value_str),
            label: label.into(),
            description: None,
        }
    }

    /// Create an option with description
    pub fn with_description(
        value: impl Into<String>,
        label: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        let value_str = value.into();
        Self {
            value: Value::String(value_str),
            label: label.into(),
            description: Some(description.into()),
        }
    }
}

/// Trait for types that define a settings schema
///
/// Implement this trait for your application's settings struct to provide
/// metadata about available settings.
pub trait SettingsSchema: Default + Serialize + for<'de> Deserialize<'de> {
    /// Get metadata for all settings
    ///
    /// The key format should be "`category.setting_name`" (e.g., "general.language")
    fn get_metadata() -> HashMap<String, SettingMetadata>;

    /// Get list of categories in display order
    #[must_use] 
    fn get_categories() -> Vec<String> {
        let metadata = Self::get_metadata();
        let mut categories: Vec<String> = metadata
            .values()
            .filter_map(|m| m.category.clone())
            .collect();
        categories.sort();
        categories.dedup();
        categories
    }
}

// Default implementation for () to allow DynamicManager (no schema)
impl SettingsSchema for () {
    fn get_metadata() -> HashMap<String, SettingMetadata> {
        HashMap::new()
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Shorthand for creating a `SettingOption`
///
/// # Example
/// ```rust
/// use rcman::opt;
/// let options = vec![opt("light", "Light Mode"), opt("dark", "Dark Mode")];
/// ```
pub fn opt(value: impl Into<String>, label: impl Into<String>) -> SettingOption {
    SettingOption::new(value, label)
}

/// Macro for building settings metadata `HashMap` more cleanly
///
/// # Example
/// ```rust,compile_fail
/// use rcman::{settings, SettingsSchema, SettingMetadata, opt};
/// use std::collections::HashMap;
///
/// impl SettingsSchema for MySettings {
///     fn get_metadata() -> HashMap<String, SettingMetadata> {
///         settings! {
///             "ui.theme" => SettingMetadata::select("Theme", "dark", vec![
///                 opt("light", "Light"),
///                 opt("dark", "Dark"),
///             ]),
///             "ui.font_size" => SettingMetadata::number("Font Size", 14.0)
///                 .min(8.0).max(32.0),
///             "api.key" => SettingMetadata::password("API Key", "")
///                 .secret(),
///         }
///     }
/// }
/// ```
#[macro_export]
macro_rules! settings {
    ($($key:expr => $value:expr),* $(,)?) => {{
        let mut map = std::collections::HashMap::new();
        $(
            map.insert($key.to_string(), $value);
        )*
        map
    }};
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_setting_metadata_builder() {
        let setting = SettingMetadata::toggle("Dark Mode", true)
            .description("Enable dark theme")
            .category("appearance")
            .order(1);

        assert_eq!(setting.setting_type, SettingType::Toggle);
        assert_eq!(setting.default, Value::Bool(true));
        assert_eq!(setting.label, "Dark Mode");
        assert_eq!(setting.description, Some("Enable dark theme".into()));
        assert_eq!(setting.category, Some("appearance".into()));
        assert_eq!(setting.order, Some(1));
    }

    #[test]
    fn test_select_setting() {
        let options = vec![
            SettingOption::new("en", "English"),
            SettingOption::new("tr", "Turkish"),
            SettingOption::new("de", "German"),
        ];

        let setting = SettingMetadata::select("Language", "en", options);

        assert_eq!(setting.setting_type, SettingType::Select);
        assert_eq!(setting.options.as_ref().unwrap().len(), 3);
    }

    #[test]
    fn test_number_setting_with_range() {
        let setting = SettingMetadata::number("Volume", 50.0)
            .min(0.0)
            .max(100.0)
            .step(5.0);

        assert_eq!(setting.min, Some(0.0));
        assert_eq!(setting.max, Some(100.0));
        assert_eq!(setting.step, Some(5.0));
    }

    #[test]
    fn test_number_validation() {
        let setting = SettingMetadata::number("Port", 8080.0)
            .min(1.0)
            .max(65535.0);

        // Valid values
        assert!(setting.validate(&Value::from(8080)).is_ok());
        assert!(setting.validate(&Value::from(1)).is_ok());
        assert!(setting.validate(&Value::from(65535)).is_ok());

        // Invalid values
        assert!(setting.validate(&Value::from(0)).is_err());
        assert!(setting.validate(&Value::from(70000)).is_err());
        assert!(setting.validate(&Value::from("not a number")).is_err());
    }

    #[test]
    fn test_text_pattern_validation() {
        let setting = SettingMetadata::text("Email", "")
            .pattern(r"^[\w.-]+@[\w.-]+\.\w+$")
            .pattern_error("Invalid email format");

        // Valid emails
        assert!(setting.validate(&Value::from("user@example.com")).is_ok());
        assert!(setting
            .validate(&Value::from("test.user@domain.org"))
            .is_ok());

        // Invalid emails
        let result = setting.validate(&Value::from("not-an-email"));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid email format");
    }

    #[test]
    fn test_select_validation() {
        let options = vec![
            SettingOption::new("en", "English"),
            SettingOption::new("tr", "Turkish"),
        ];
        let setting = SettingMetadata::select("Language", "en", options);

        // Valid options
        assert!(setting.validate(&Value::from("en")).is_ok());
        assert!(setting.validate(&Value::from("tr")).is_ok());

        // Invalid option
        assert!(setting.validate(&Value::from("invalid")).is_err());
    }

    #[test]
    fn test_path_setting() {
        let setting = SettingMetadata::path("Config Directory", "/home/user/.config")
            .description("Directory for configuration files");

        assert_eq!(setting.setting_type, SettingType::Path);
        assert_eq!(setting.default, Value::String("/home/user/.config".into()));
        assert_eq!(setting.label, "Config Directory");
        assert_eq!(
            setting.description,
            Some("Directory for configuration files".into())
        );
        // Path type doesn't need special validation
        assert!(setting.validate(&Value::from("/any/path")).is_ok());
    }

    #[test]
    fn test_file_setting() {
        let setting = SettingMetadata::file("Config File", "/etc/app/config.json")
            .description("Path to the configuration file");

        assert_eq!(setting.setting_type, SettingType::File);
        assert_eq!(
            setting.default,
            Value::String("/etc/app/config.json".into())
        );
        assert_eq!(setting.label, "Config File");
        assert_eq!(
            setting.description,
            Some("Path to the configuration file".into())
        );
        // File type doesn't need special validation
        assert!(setting.validate(&Value::from("/any/file.txt")).is_ok());
    }

    #[test]
    fn test_list_setting() {
        let default_items = vec!["item1".to_string(), "item2".to_string()];
        let setting = SettingMetadata::list("Tags", default_items.clone())
            .description("List of tags")
            .category("metadata");

        assert_eq!(setting.setting_type, SettingType::List);
        assert_eq!(setting.default, json!(default_items));
        assert_eq!(setting.label, "Tags");
        assert_eq!(setting.description, Some("List of tags".into()));
        assert_eq!(setting.category, Some("metadata".into()));
    }

    #[test]
    fn test_list_setting_empty() {
        let setting = SettingMetadata::list("Empty List", vec![]);

        assert_eq!(setting.setting_type, SettingType::List);
        assert_eq!(setting.default, json!(Vec::<String>::new()));
    }

    #[test]
    fn test_list_validation() {
        let setting = SettingMetadata::list("Items", vec!["default".to_string()]);

        // Valid list values
        assert!(setting
            .validate(&json!(vec!["one".to_string(), "two".to_string()]))
            .is_ok());
        assert!(setting.validate(&json!(Vec::<String>::new())).is_ok());
        assert!(setting.validate(&json!(vec!["single"])).is_ok());

        // List type doesn't enforce specific validation beyond JSON structure
        // (arrays of strings are the expected format)
    }
}
