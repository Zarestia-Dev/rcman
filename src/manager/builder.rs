//! Builder for SettingsManager
//!
//! This module contains [`SettingsManagerBuilder`] which provides a fluent API
//! for creating a [`SettingsManager`](super::SettingsManager).

use crate::config::SettingsConfigBuilder;
use crate::error::Result;
use crate::storage::JsonStorage;
use crate::sub_settings::SubSettingsConfig;
use std::path::PathBuf;

use super::SettingsManager;

/// Builder for creating a [`SettingsManager`] with a fluent API.
///
/// This is the recommended way to create a `SettingsManager`. It allows you to
/// configure all options and register sub-settings in a single chain of calls.
///
/// # Example
///
/// ```rust,no_run
/// use rcman::{SettingsManager, SubSettingsConfig};
///
/// let manager = SettingsManager::builder("my-app", "1.0.0")
///     .config_dir("~/.config/my-app")
///     .with_credentials()
///     .with_sub_settings(SubSettingsConfig::new("remotes"))
///     .with_sub_settings(SubSettingsConfig::new("backends").single_file())
///     .build()
///     .unwrap();
/// ```
pub struct SettingsManagerBuilder {
    config_builder: SettingsConfigBuilder,
    sub_settings: Vec<SubSettingsConfig>,
}

impl SettingsManagerBuilder {
    /// Create a new builder with required app name and version.
    pub fn new(app_name: impl Into<String>, app_version: impl Into<String>) -> Self {
        Self {
            config_builder: SettingsConfigBuilder::new(app_name, app_version),
            sub_settings: Vec::new(),
        }
    }

    /// Set the configuration directory.
    ///
    /// Supports `~` expansion for home directory.
    pub fn config_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.config_builder = self.config_builder.config_dir(path);
        self
    }

    /// Set the settings filename (default: "settings.json").
    pub fn settings_file(mut self, filename: impl Into<String>) -> Self {
        self.config_builder = self.config_builder.settings_file(filename);
        self
    }

    /// Use compact JSON (no pretty printing).
    pub fn compact_json(mut self) -> Self {
        self.config_builder = self.config_builder.compact_json();
        self
    }

    /// Enable credential management for secret settings.
    ///
    /// When enabled, settings marked as `secret: true` in metadata
    /// will be stored in the OS keychain instead of the settings file.
    pub fn with_credentials(mut self) -> Self {
        self.config_builder = self.config_builder.with_credentials();
        self
    }

    /// Enable environment variable overrides.
    ///
    /// When set, settings can be overridden by environment variables.
    /// The format is: `{PREFIX}_{CATEGORY}_{KEY}` (all uppercase)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let manager = SettingsManager::builder("my-app", "1.0.0")
    ///     .with_env_prefix("MYAPP")
    ///     .build()?;
    ///
    /// // Now MYAPP_UI_THEME=dark will override the "ui.theme" setting
    /// ```
    pub fn with_env_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.config_builder = self.config_builder.with_env_prefix(prefix);
        self
    }

    /// Allow environment variables to override secret settings.
    ///
    /// By default, secrets stored in the OS keychain are NOT affected by env vars.
    /// Enable this for Docker/CI environments where secrets are passed via env.
    pub fn env_overrides_secrets(mut self, allow: bool) -> Self {
        self.config_builder = self.config_builder.env_overrides_secrets(allow);
        self
    }

    /// Register an external configuration file for backup.
    ///
    /// External configs are files managed outside of rcman (like rclone.conf)
    /// that can be included in backups.
    #[cfg(feature = "backup")]
    pub fn with_external_config(mut self, config: crate::backup::ExternalConfig) -> Self {
        self.config_builder = self.config_builder.with_external_config(config);
        self
    }

    /// Register a sub-settings type for per-entity configuration.
    ///
    /// Sub-settings allow you to manage separate config files for each entity
    /// (e.g., one file per remote, per profile, etc.).
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let manager = SettingsManager::builder("my-app", "1.0.0")
    ///     .with_sub_settings(SubSettingsConfig::new("remotes"))
    ///     .with_sub_settings(SubSettingsConfig::new("backends").single_file())
    ///     .build()?;
    /// ```
    pub fn with_sub_settings(mut self, config: SubSettingsConfig) -> Self {
        self.sub_settings.push(config);
        self
    }

    /// Build the [`SettingsManager`].
    ///
    /// This creates the config directory if it doesn't exist, initializes
    /// the manager, and registers all sub-settings.
    ///
    /// # Errors
    ///
    /// Returns an error if the config directory cannot be created.
    pub fn build(self) -> Result<SettingsManager<JsonStorage>> {
        let config = self.config_builder.build();
        let manager = SettingsManager::new(config)?;

        // Register all sub-settings
        for sub_config in self.sub_settings {
            manager.register_sub_settings(sub_config);
        }

        Ok(manager)
    }
}
