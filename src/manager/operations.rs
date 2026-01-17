use crate::config::{SettingMetadata, SettingsSchema};
use crate::error::{Error, Result};
use crate::manager::core::SettingsManager;
use crate::storage::StorageBackend;
use crate::sub_settings::{SubSettings, SubSettingsConfig};
use crate::sync::RwLockExt;

#[cfg(feature = "backup")]
use crate::backup::{BackupManager, ExternalConfigProvider};

use log::{debug, info};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;

impl<S: StorageBackend + 'static, Schema: SettingsSchema> SettingsManager<S, Schema> {
    /// Check if a setting value is overridden by an environment variable
    ///
    /// Returns the parsed value if env var is set and successfully parsed.
    pub(crate) fn get_env_override(&self, key: &str) -> Option<Value> {
        self.env_handler.get_env_override(key)
    }

    /// Get all setting metadata with current values populated.
    ///
    /// Returns a `HashMap` of all settings with their metadata (type, label, default, current value).
    /// Useful for rendering settings UI.
    ///
    /// Returns metadata map with current values populated.
    /// Uses in-memory cache when available.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Storage read fails
    /// - Data is corrupted
    pub fn metadata(&self) -> Result<HashMap<String, SettingMetadata>> {
        // Ensure cache is populated
        self.ensure_cache_populated()?;

        // Get stored settings from cache
        let stored = self
            .settings_cache
            .get_stored()?
            .unwrap_or_else(|| json!({}));

        // Get metadata and populate values
        let mut metadata = Schema::get_metadata();

        for (key, option) in &mut metadata {
            let parts: Vec<&str> = key.split('.').collect();
            if parts.len() == 2 {
                let category = parts[0];
                let setting_name = parts[1];

                // Handle secret settings - fetch from credential manager
                #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
                if option.is_secret() {
                    // Check env var override for secrets if enabled
                    if self.config.env_overrides_secrets {
                        if let Some(env_value) = self.get_env_override(key) {
                            option.value = Some(env_value);
                            option
                                .metadata
                                .insert("env_override".to_string(), Value::Bool(true));
                            debug!("Secret {key} overridden by env var");
                            continue;
                        }
                    }

                    if let Ok(Some(secret_value)) = self.get_credential_with_profile(key) {
                        option.value = Some(Value::String(secret_value));
                        continue;
                    }
                    // Secret not found in keychain, use default
                    option.value = Some(option.default.clone());
                    continue;
                }

                // Priority: env var override > stored value > default
                // Check for environment variable override first
                if let Some(env_value) = self.get_env_override(key) {
                    option.value = Some(env_value);
                    option
                        .metadata
                        .insert("env_override".to_string(), Value::Bool(true)); // Mark as env-overridden for UI
                    debug!("Setting {key} overridden by env var");
                    continue;
                }

                // Get effective value (stored or default)
                let effective_value = stored
                    .get(category)
                    .and_then(|cat| cat.get(setting_name))
                    .cloned()
                    .unwrap_or_else(|| option.default.clone());

                option.value = Some(effective_value);
            }
        }

        info!("Settings loaded successfully");
        Ok(metadata)
    }

    /// Get a single setting value by key path.
    ///
    /// # Type Parameters
    ///
    /// * `T` - The type to deserialize the value into
    ///
    /// # Arguments
    ///
    /// * `key` - Setting key in "category.name" format (e.g., "general.restrict")
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The setting doesn't exist (and no default)
    /// - The value cannot be deserialized to type `T`
    /// - Storage read fails
    pub fn get<T>(&self, key: &str) -> Result<T>
    where
        T: serde::de::DeserializeOwned,
    {
        let value = self.get_value(key)?;
        serde_json::from_value(value).map_err(|e| Error::Parse(e.to_string()))
    }

    /// Get raw JSON value for a setting key.
    ///
    /// Returns the value from merged settings cache.
    ///
    /// # Arguments
    ///
    /// * `key` - Setting key in "category.name" format
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The setting key format is invalid
    /// - The setting doesn't exist
    /// - Storage read fails
    pub fn get_value(&self, key: &str) -> Result<Value> {
        let parts: Vec<&str> = key.split('.').collect();
        if parts.len() != 2 {
            return Err(Error::Config(
                "Key must be in format 'category.setting'".into(),
            ));
        }
        let category = parts[0];
        let setting_name = parts[1];

        // Ensure cache is populated with schema defaults
        self.ensure_cache_populated()?;

        // Use cache helper
        if let Some(value) = self.settings_cache.get_value(category, setting_name, key)? {
            return Ok(value);
        }

        Err(Error::SettingNotFound(format!("{category}.{setting_name}")))
    }

    /// Get merged settings struct with caching.
    ///
    /// # Errors
    ///
    /// Returns an error if settings cannot be read or parsed.
    ///
    /// # Panics
    ///
    /// Panics if the internal cache lock is poisoned or if the `OnceLock` fails to initialize (should never happen).
    pub fn get_all(&self) -> Result<Schema> {
        // Ensure cache is populated
        self.ensure_cache_populated()?;

        let merged = self
            .settings_cache
            .get_or_compute_merged(|stored| Self::merge_with_defaults(stored))?;

        // Deserialize to concrete type
        serde_json::from_value(merged).map_err(|e| Error::Parse(e.to_string()))
    }

    /// Internal helper to merge stored settings with schema defaults.
    pub(crate) fn merge_with_defaults(stored: &Value) -> Result<Value> {
        let default = Schema::default();
        let mut merged = serde_json::to_value(&default)?;

        // Merge stored on top of defaults
        if let (Some(merged_obj), Some(stored_obj)) = (merged.as_object_mut(), stored.as_object()) {
            for (category, values) in stored_obj {
                if let Some(merged_cat) = merged_obj.get_mut(category) {
                    if let (Some(merged_cat_obj), Some(values_obj)) =
                        (merged_cat.as_object_mut(), values.as_object())
                    {
                        for (key, val) in values_obj {
                            merged_cat_obj.insert(key.clone(), val.clone());
                        }
                    }
                }
            }
        }

        Ok(merged)
    }

    // =========================================================================
    // Sub-Settings Management
    // =========================================================================

    /// Register a sub-settings type for per-entity configuration.
    ///
    /// Sub-settings allow you to manage separate config files for each entity
    /// (e.g., one file per remote, per profile, etc.).
    ///
    /// # Errors
    ///
    /// Returns an error if the sub-settings handler cannot be initialized (e.g. invalid path).
    pub fn register_sub_settings(&self, config: SubSettingsConfig) -> Result<()> {
        let name = config.name.clone();
        let handler = Arc::new(SubSettings::new(
            &self.config.config_dir,
            config,
            self.storage.clone(),
        )?);

        let mut guard = self.sub_settings.write_recovered()?;
        guard.insert(name.clone(), handler);

        info!("Registered sub-settings type: {name}");
        Ok(())
    }

    /// Get a registered sub-settings handler.
    ///
    /// Returns the handler for the specified sub-settings type, which can be used
    /// to read, write, and manage individual entries.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the sub-settings type to get
    ///
    /// # Errors
    ///
    /// Returns `Error::SubSettingsNotFound` if the sub-settings type is not registered.
    pub fn sub_settings(&self, name: &str) -> Result<Arc<SubSettings<S>>> {
        let guard = self.sub_settings.read_recovered()?;
        guard
            .get(name)
            .cloned()
            .ok_or_else(|| Error::SubSettingsNotRegistered(name.to_string()))
    }

    /// Check if a sub-settings type exists
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    pub fn has_sub_settings(&self, name: &str) -> bool {
        self.sub_settings
            .read_recovered()
            .map(|guard| guard.contains_key(name))
            .unwrap_or(false)
    }

    /// List all registered sub-settings types
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    pub fn sub_settings_types(&self) -> Vec<String> {
        self.sub_settings
            .read_recovered()
            .map(|guard| guard.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// List all entries in a sub-settings type (convenience method)
    ///
    /// This is a shorthand for `manager.sub_settings(name)?.list()?`
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the sub-settings type to list
    ///
    /// # Errors
    ///
    /// Returns `Error::SubSettingsNotFound` if the type is not registered, or I/O errors from the handler.
    pub fn list_sub_settings(&self, name: &str) -> Result<Vec<String>> {
        let sub = self.sub_settings(name)?;
        sub.list()
    }

    // =========================================================================
    // Backup & External Configs
    // =========================================================================

    /// Register an external config provider for backups.
    ///
    /// This allows dynamic registration of external files to be included in backups.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    #[cfg(feature = "backup")]
    pub fn register_external_provider(&self, provider: Box<dyn ExternalConfigProvider>) {
        if let Ok(mut providers) = self.external_providers.write_recovered() {
            providers.push(provider);
        }
    }

    /// Get the backup manager
    #[cfg(feature = "backup")]
    pub fn backup(&self) -> BackupManager<'_, S, Schema> {
        BackupManager::new(self)
    }

    /// Get all registered external configs
    ///
    /// Returns the external config files that were registered via
    /// `SettingsConfig::builder().with_external_config(...)`.
    #[cfg(feature = "backup")]
    pub fn external_configs(&self) -> &[crate::backup::ExternalConfig] {
        &self.config.external_configs
    }

    /// Get all export categories for backup UI
    ///
    /// Returns a list of all exportable categories:
    /// - Settings (main settings.json)
    /// - Sub-settings (each registered sub-settings type)
    /// - External configs (each registered external file)
    #[cfg(feature = "backup")]
    pub fn get_export_categories(&self) -> Vec<crate::backup::ExportCategory> {
        use crate::backup::{ExportCategory, ExportCategoryType};

        let mut categories = Vec::new();

        // 1. Main settings
        categories.push(ExportCategory {
            id: "settings".to_string(),
            name: "Application Settings".to_string(),
            category_type: ExportCategoryType::Settings,
            optional: false,
            description: Some("Main application settings".to_string()),
        });

        // 2. Sub-settings
        let sub_types = self.sub_settings_types();
        for sub_type in sub_types {
            categories.push(ExportCategory {
                id: sub_type.clone(),
                name: sub_type.clone(), // Could be enhanced with display names
                category_type: ExportCategoryType::SubSettings,
                optional: false,
                description: None,
            });
        }

        // 3. External configs
        for ext in &self.config.external_configs {
            categories.push(ExportCategory {
                id: ext.id.clone(),
                name: ext.display_name.clone(),
                category_type: ExportCategoryType::External,
                optional: ext.optional,
                description: ext.description.clone(),
            });
        }

        categories
    }
}
