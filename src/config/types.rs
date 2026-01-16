//! Core types for rcman library

use std::marker::PhantomData;
use std::path::PathBuf;

use crate::config::SettingsSchema;
use crate::storage::{JsonStorage, StorageBackend};

#[cfg(feature = "backup")]
use crate::backup::ExternalConfig;

/// Trait for retrieving environment variables
///
/// This allows mocking environment variables in tests without
/// using unsafe `std::env::set_var`.
pub trait EnvSource: Send + Sync {
    /// Retrieve an environment variable
    ///
    /// # Errors
    ///
    /// Returns `VarError` if the variable is not present or invalid unicode.
    fn var(&self, key: &str) -> std::result::Result<String, std::env::VarError>;
}

/// Default implementation using `std::env`
#[derive(Clone, Default)]
pub struct DefaultEnvSource;

impl EnvSource for DefaultEnvSource {
    fn var(&self, key: &str) -> std::result::Result<String, std::env::VarError> {
        std::env::var(key)
    }
}

/// Configuration for initializing the `SettingsManager`
pub struct SettingsConfig<S: StorageBackend = JsonStorage, Schema: SettingsSchema = ()> {
    /// Directory where settings files will be stored
    pub config_dir: PathBuf,

    /// Filename for the main settings file (e.g., "settings.json")
    pub settings_file: String,

    /// Application name (used in backup manifests)
    pub app_name: String,

    /// Application version (used for backup compatibility checks)
    pub app_version: String,

    /// Storage backend (defaults to `JsonStorage`)
    pub(crate) storage: S,

    /// Enable credential management for secret settings
    pub enable_credentials: bool,

    /// Environment variable prefix for setting overrides (e.g., "MYAPP" -> `MYAPP_UI_THEME`)
    /// If None, env var overrides are disabled
    pub env_prefix: Option<String>,

    /// Allow environment variables to override secret settings (stored in keychain)
    /// Default: false (secrets are never overridden by env vars)
    pub env_overrides_secrets: bool,

    /// External configuration files registered for backup
    #[cfg(feature = "backup")]
    pub external_configs: Vec<ExternalConfig>,

    /// Optional migration function for schema changes (lazy migration)
    /// The migrator function is called automatically when loading settings.
    /// If the function modifies the value, the migrated version is saved back.
    pub migrator:
        Option<std::sync::Arc<dyn Fn(serde_json::Value) -> serde_json::Value + Send + Sync>>,

    /// Enable profiles for main settings (stores settings per-profile)
    #[cfg(feature = "profiles")]
    pub profiles_enabled: bool,

    /// Profile migration strategy (defaults to Auto)
    #[cfg(feature = "profiles")]
    pub profile_migrator: crate::profiles::ProfileMigrator,

    /// Marker for schema type (internal use)
    #[doc(hidden)]
    pub _schema: PhantomData<Schema>,

    /// Source for environment variables (defaults to `std::env`)
    pub env_source: std::sync::Arc<dyn EnvSource>,
}

impl Default for SettingsConfig {
    fn default() -> Self {
        let storage = JsonStorage::new();
        let settings_file = format!("settings.{}", storage.extension());
        Self {
            config_dir: PathBuf::from("."),
            settings_file,
            app_name: "app".into(),
            app_version: "0.1.0".into(),
            storage,
            enable_credentials: false,
            env_prefix: None,
            env_overrides_secrets: false,
            #[cfg(feature = "backup")]
            external_configs: Vec::new(),
            migrator: None,
            #[cfg(feature = "profiles")]
            profiles_enabled: false,
            #[cfg(feature = "profiles")]
            profile_migrator: crate::profiles::ProfileMigrator::default(),
            _schema: PhantomData,
            env_source: std::sync::Arc::new(DefaultEnvSource),
        }
    }
}

impl<S: StorageBackend, Schema: SettingsSchema> SettingsConfig<S, Schema> {
    /// Get the full path to the main settings file
    pub fn settings_path(&self) -> PathBuf {
        self.config_dir.join(&self.settings_file)
    }
}

impl SettingsConfig {
    /// Create a new builder for `SettingsConfig`
    ///
    /// # Example
    /// ```rust
    /// use rcman::SettingsConfig;
    ///
    /// let config = SettingsConfig::builder("my-app", "1.0.0")
    ///     .with_config_dir("~/.config/my-app")
    ///     .build();
    /// ```
    pub fn builder(
        app_name: impl Into<String>,
        app_version: impl Into<String>,
    ) -> SettingsConfigBuilder {
        SettingsConfigBuilder::new(app_name, app_version)
    }
}

/// Builder for creating `SettingsConfig` with a fluent API.
///
/// This is the recommended way to create a settings manager.
///
/// # Type Parameters
///
/// - `Schema`: Settings schema type (defaults to `()` for dynamic usage)
///
/// # Examples
///
/// **Type-Safe (With Schema):**
/// ```no_run
/// use rcman::{SettingsConfig, SettingsSchema, SettingMetadata, settings};
/// use serde::{Serialize, Deserialize};
/// use std::collections::HashMap;
///
/// #[derive(Default, Serialize, Deserialize)]
/// struct MySettings { theme: String }
///
/// impl SettingsSchema for MySettings {
///     fn get_metadata() -> HashMap<String, SettingMetadata> {
///         settings! { "ui.theme" => SettingMetadata::text("dark").meta_str("label", "Theme") }
///     }
/// }
///
/// let config = SettingsConfig::builder("my-app", "1.0.0")
///     .with_schema::<MySettings>()
///     .with_config_dir("~/.config/my-app")
///     .build();
/// ```
///
/// **Dynamic (Without Schema):**
/// ```no_run
/// use rcman::SettingsConfig;
///
/// let config = SettingsConfig::builder("my-app", "1.0.0")
///     .with_config_dir("~/.config/my-app")
///     .build();
/// ```
#[derive(Clone)]
pub struct SettingsConfigBuilder<S: StorageBackend = JsonStorage, Schema: SettingsSchema = ()> {
    config_dir: Option<PathBuf>,
    settings_file: Option<String>,
    app_name: String,
    app_version: String,
    options: BuilderOptions,
    env_prefix: Option<String>,
    #[cfg(feature = "backup")]
    external_configs: Vec<ExternalConfig>,
    migrator: Option<std::sync::Arc<dyn Fn(serde_json::Value) -> serde_json::Value + Send + Sync>>,
    #[cfg(feature = "profiles")]
    profile_migrator: Option<crate::profiles::ProfileMigrator>,

    env_source: Option<std::sync::Arc<dyn EnvSource>>,

    _schema: PhantomData<Schema>,
    _storage: PhantomData<S>,
}

#[derive(Clone, Debug, Default)]
struct BuilderConfigFlags {
    pretty_json: bool,
    #[cfg(feature = "profiles")]
    profiles_enabled: bool,
}

#[derive(Clone, Debug, Default)]
struct BuilderSecurityFlags {
    enable_credentials: bool,
    env_overrides_secrets: bool,
}

#[derive(Clone, Debug, Default)]
struct BuilderOptions {
    config: BuilderConfigFlags,
    security: BuilderSecurityFlags,
}

impl<S: StorageBackend, Schema: SettingsSchema> std::fmt::Debug
    for SettingsConfigBuilder<S, Schema>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = f.debug_struct("SettingsConfigBuilder");
        debug
            .field("config_dir", &self.config_dir)
            .field("settings_file", &self.settings_file)
            .field("app_name", &self.app_name)
            .field("app_version", &self.app_version)
            .field("pretty_json", &self.options.config.pretty_json)
            .field(
                "enable_credentials",
                &self.options.security.enable_credentials,
            )
            .field("env_prefix", &self.env_prefix)
            .field(
                "env_overrides_secrets",
                &self.options.security.env_overrides_secrets,
            );

        #[cfg(feature = "backup")]
        debug.field("external_configs", &self.external_configs);

        #[cfg(feature = "profiles")]
        debug.field("profiles_enabled", &self.options.config.profiles_enabled);
        #[cfg(feature = "profiles")]
        debug.field("profile_migrator", &self.profile_migrator);

        debug.field("migrator", &self.migrator.as_ref().map(|_| "Some(Fn)"));
        debug.finish_non_exhaustive()
    }
}

impl SettingsConfigBuilder {
    /// Create a new builder with required app name and version
    pub fn new(app_name: impl Into<String>, app_version: impl Into<String>) -> Self {
        Self {
            config_dir: None,
            settings_file: None,
            app_name: app_name.into(),
            app_version: app_version.into(),
            options: BuilderOptions::default(),
            env_prefix: None,
            #[cfg(feature = "backup")]
            external_configs: Vec::new(),
            migrator: None,
            #[cfg(feature = "profiles")]
            profile_migrator: None,
            env_source: None,
            _schema: PhantomData,
            _storage: PhantomData,
        }
    }
}

impl<S: StorageBackend, Schema: SettingsSchema> SettingsConfigBuilder<S, Schema> {
    /// Use compact JSON (no pretty printing)
    ///
    /// Note: This method is only available when using `JsonStorage`.
    ///
    /// # Example
    /// ```
    /// use rcman::SettingsConfig;
    ///
    /// let config = SettingsConfig::builder("my-app", "1.0.0")
    ///     .build();
    /// ```
    #[must_use]
    pub fn with_pretty_json(mut self, pretty: bool) -> Self {
        self.options.config.pretty_json = pretty;
        self
    }
    /// Set the configuration directory
    ///
    /// Supports `~` expansion for home directory.
    #[must_use]
    pub fn with_config_dir(mut self, path: impl Into<PathBuf>) -> Self {
        let path: PathBuf = path.into();
        // Expand ~ to home directory
        let expanded = if path.starts_with("~") {
            if let Some(home) = dirs::home_dir() {
                home.join(path.strip_prefix("~").unwrap_or(&path))
            } else {
                path
            }
        } else {
            path
        };
        self.config_dir = Some(expanded);
        self
    }

    /// Set the settings filename (default: "settings.{ext}")
    #[must_use]
    pub fn settings_file(mut self, filename: impl Into<String>) -> Self {
        self.settings_file = Some(filename.into());
        self
    }

    /// When enabled, settings marked as `secret: true` in metadata
    /// will be stored in the OS keychain instead of the settings file.
    #[must_use]
    pub fn with_credentials(mut self) -> Self {
        self.options.security.enable_credentials = true;
        self
    }

    /// Register an external configuration file for backup
    ///
    /// External configs are files managed outside of rcman (like rclone.conf)
    /// that can be included in backups.
    ///
    /// # Example
    /// ```rust
    /// use rcman::SettingsConfig;
    /// use rcman::backup::ExternalConfig;
    ///
    /// let config = SettingsConfig::builder("my-app", "1.0.0")
    ///     .with_external_config(ExternalConfig::new("rclone", "/path/to/rclone.conf")
    ///         .display_name("Rclone Configuration"))
    ///     .build();
    /// ```
    #[cfg(feature = "backup")]
    #[must_use]
    pub fn with_external_config(mut self, config: ExternalConfig) -> Self {
        self.external_configs.push(config);
        self
    }

    /// Enable environment variable overrides
    ///
    /// When set, settings can be overridden by environment variables.
    /// The format is: `{PREFIX}_{CATEGORY}_{KEY}` (all uppercase, dots become underscores)
    ///
    /// # Example
    /// ```rust
    /// use rcman::SettingsConfig;
    ///
    /// let config = SettingsConfig::builder("my-app", "1.0.0")
    ///     .with_env_prefix("MYAPP")
    ///     .build();
    ///
    /// // Now MYAPP_UI_THEME=dark will override the "ui.theme" setting
    /// ```
    #[must_use]
    pub fn with_env_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.env_prefix = Some(prefix.into());
        self
    }

    /// Allow environment variables to override secret settings
    ///
    /// By default, secrets stored in the OS keychain are NOT affected by env vars.
    /// Enable this for Docker/CI environments where secrets are passed via env.
    ///
    /// # Example
    /// ```rust
    /// use rcman::SettingsConfig;
    ///
    /// let config = SettingsConfig::builder("my-app", "1.0.0")
    ///     .with_env_prefix("MYAPP")
    ///     .env_overrides_secrets(true)  // MYAPP_API_KEY will override keychain
    ///     .build();
    /// ```
    #[must_use]
    pub fn env_overrides_secrets(mut self, allow: bool) -> Self {
        self.options.security.env_overrides_secrets = allow;
        self
    }

    /// Set a custom environment variable source
    ///
    /// Useful for testing or injecting env vars procedurally.
    #[must_use]
    pub fn with_env_source(mut self, source: std::sync::Arc<dyn EnvSource>) -> Self {
        self.env_source = Some(source);
        self
    }

    /// Set a migration function for schema changes (lazy migration)
    ///
    /// The migrator function is called automatically when loading settings.
    /// If the function modifies the value, the migrated version is saved back.
    ///
    /// Use this to upgrade old data formats to new ones transparently.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rcman::SettingsConfig;
    /// use serde_json::json;
    ///
    /// let config = SettingsConfig::builder("my-app", "1.0.0")
    ///     .with_migrator(|mut value| {
    ///         // Migrate v1 to v2: rename "color" to "theme"
    ///         if let Some(obj) = value.as_object_mut() {
    ///             if let Some(ui) = obj.get_mut("ui").and_then(|v| v.as_object_mut()) {
    ///                 if let Some(color) = ui.remove("color") {
    ///                     ui.insert("theme".to_string(), color);
    ///                 }
    ///             }
    ///         }
    ///         value
    ///     })
    ///     .build();
    /// ```
    #[must_use]
    pub fn with_migrator<F>(mut self, migrator: F) -> Self
    where
        F: Fn(serde_json::Value) -> serde_json::Value + Send + Sync + 'static,
    {
        self.migrator = Some(std::sync::Arc::new(migrator));
        self
    }

    /// Enable profiles for main settings
    ///
    /// When enabled, the main settings file is stored per-profile, allowing
    /// completely different configurations (e.g., "work" vs "personal").
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use rcman::SettingsManager;
    ///
    /// let manager = SettingsManager::builder("my-app", "1.0.0")
    ///     .with_profiles()  // Enable profiles for main settings
    ///     .build()?;
    ///
    /// // Now you can switch profiles
    /// manager.switch_profile("work")?;
    /// ```
    #[cfg(feature = "profiles")]
    #[must_use]
    pub fn with_profiles(mut self) -> Self {
        self.options.config.profiles_enabled = true;
        self
    }

    /// Specify the schema type for compile-time type safety.
    ///
    /// This binds your settings struct to the manager, enabling:
    /// - Type-safe `settings()` method returning your struct
    /// - Compile-time validation of setting keys
    /// - Better IDE autocomplete and refactoring support
    ///
    /// # Example
    /// ```no_run
    /// use rcman::{SettingsConfig, SettingsSchema, SettingMetadata, settings};
    /// use serde::{Serialize, Deserialize};
    /// use std::collections::HashMap;
    ///
    /// #[derive(Default, Serialize, Deserialize)]
    /// struct AppSettings {
    ///     theme: String,
    ///     font_size: f64,
    /// }
    ///
    /// impl SettingsSchema for AppSettings {
    ///     fn get_metadata() -> HashMap<String, SettingMetadata> {
    ///         settings! {
    ///             "ui.theme" => SettingMetadata::text("dark").meta_str("label", "Theme"),
    ///             "ui.font_size" => SettingMetadata::number(14.0).meta_str("label", "Font Size")
    ///         }
    ///     }
    /// }
    ///
    /// let config = SettingsConfig::builder("my-app", "1.0.0")
    ///     .with_schema::<AppSettings>()  // Bind the schema
    ///     .build();
    /// ```
    #[must_use]
    pub fn with_schema<NewSchema: SettingsSchema>(self) -> SettingsConfigBuilder<S, NewSchema> {
        SettingsConfigBuilder {
            config_dir: self.config_dir,
            settings_file: self.settings_file,
            app_name: self.app_name,
            app_version: self.app_version,
            options: self.options,
            env_prefix: self.env_prefix,
            #[cfg(feature = "backup")]
            external_configs: self.external_configs,
            migrator: self.migrator,
            #[cfg(feature = "profiles")]
            profile_migrator: self.profile_migrator,
            env_source: self.env_source,
            _schema: PhantomData,
            _storage: PhantomData,
        }
    }

    /// Specify the storage backend type.
    ///
    /// This transforms the builder to use the specified storage backend.
    /// The settings filename will automatically be updated to match the format.
    ///
    /// # Example
    /// ```no_run
    /// use rcman::{SettingsConfig, JsonStorage};
    ///
    /// let config = SettingsConfig::builder("my-app", "1.0.0")
    ///     .with_storage::<JsonStorage>()
    ///     .build();
    /// ```
    #[must_use]
    pub fn with_storage<NewS: StorageBackend + Default>(
        self,
    ) -> SettingsConfigBuilder<NewS, Schema> {
        SettingsConfigBuilder {
            config_dir: self.config_dir,
            settings_file: self.settings_file,
            app_name: self.app_name,
            app_version: self.app_version,
            options: self.options,
            env_prefix: self.env_prefix,
            #[cfg(feature = "backup")]
            external_configs: self.external_configs,
            migrator: self.migrator,
            #[cfg(feature = "profiles")]
            profile_migrator: self.profile_migrator,
            env_source: self.env_source,
            _schema: PhantomData,
            _storage: PhantomData,
        }
    }

    /// Build the `SettingsConfig`
    ///
    /// If `config_dir` is not set, uses the system config directory for the app.
    #[must_use]
    pub fn build(self) -> SettingsConfig<S, Schema>
    where
        S: Default,
    {
        let config_dir = self.config_dir.unwrap_or_else(|| {
            // Use system config dir if available, otherwise current dir
            dirs::config_dir().map_or_else(|| PathBuf::from("."), |d| d.join(&self.app_name))
        });

        let storage = S::default();

        let settings_file = self
            .settings_file
            .unwrap_or_else(|| format!("settings.{}", storage.extension()));

        SettingsConfig {
            config_dir,
            settings_file,
            app_name: self.app_name,
            app_version: self.app_version,
            storage,
            enable_credentials: self.options.security.enable_credentials,
            env_prefix: self.env_prefix,
            env_overrides_secrets: self.options.security.env_overrides_secrets,
            #[cfg(feature = "backup")]
            external_configs: self.external_configs,
            migrator: self.migrator,
            #[cfg(feature = "profiles")]
            profiles_enabled: self.options.config.profiles_enabled,
            #[cfg(feature = "profiles")]
            profile_migrator: self.profile_migrator.unwrap_or_default(),
            _schema: PhantomData,
            env_source: self
                .env_source
                .unwrap_or_else(|| std::sync::Arc::new(DefaultEnvSource)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_basic() {
        let config = SettingsConfig::builder("test-app", "1.0.0").build();

        assert_eq!(config.app_name, "test-app");
        assert_eq!(config.app_version, "1.0.0");
        assert_eq!(config.settings_file, "settings.json");
    }

    #[test]
    fn test_builder_with_options() {
        let config = SettingsConfig::builder("my-app", "2.0.0")
            .with_config_dir("/tmp/my-app")
            .settings_file("config.json")
            .build();

        assert_eq!(config.config_dir, PathBuf::from("/tmp/my-app"));
        assert_eq!(config.settings_file, "config.json");
    }
}
