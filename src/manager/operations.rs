use crate::config::{SettingMetadata, SettingsSchema};
use crate::error::{Error, Result};
use crate::manager::core::SettingsManager;
use crate::storage::StorageBackend;
use crate::sub_settings::{SubSettings, SubSettingsConfig};
use crate::utils::sync::RwLockExt;

#[cfg(feature = "backup")]
use crate::backup::{BackupManager, ExternalConfigProvider};

use indexmap::IndexMap;
use log::{debug, info};
use serde_json::Value;
use std::sync::Arc;

impl<S: StorageBackend + 'static, Schema: SettingsSchema> SettingsManager<S, Schema> {
    /// Split `category.name` into its category and the rest of the key.
    ///
    /// The name may itself contain dots (`net.proxy.host`) for settings nested
    /// deeper in the model; both parts must be non-empty.
    pub(crate) fn parse_setting_key(key: &str) -> Option<(&str, &str)> {
        key.split_once('.')
            .filter(|(category, name)| !category.is_empty() && !name.is_empty())
    }

    /// Helper to get a setting value, checking keyring if it's a secret (when feature is enabled).
    ///
    /// This centralizes the logic for retrieving values that may be stored in
    /// the keyring (for secrets) or in the file cache (for normal settings).
    fn get_value_with_secret_support(
        &self,
        key: &str,
        metadata: &SettingMetadata,
    ) -> Result<(Value, bool)> {
        if let Some(value) = self.env_override(key, metadata) {
            return Ok((value, true));
        }
        Ok((self.persisted_value(key, metadata)?, false))
    }

    pub(super) fn persisted_value(&self, key: &str, metadata: &SettingMetadata) -> Result<Value> {
        if metadata.is_secret() {
            #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
            if self.credentials.is_some()
                && let Some(secret) = self.get_credential_with_profile(key)?
            {
                return crate::credentials::decode_setting(&secret, metadata);
            }
            return Ok(metadata.default.clone());
        }
        self.settings_cache
            .get_value(key)?
            .ok_or_else(|| Error::SettingNotFound(key.to_owned()))
    }

    /// The environment override for a setting, if one is set and valid.
    ///
    /// Overrides pass the same validation as saved values, including pattern and
    /// reserved-value constraints. An invalid override is ignored with a warning,
    /// so one bad variable cannot make every settings read fail.
    pub(crate) fn env_override(&self, key: &str, metadata: &SettingMetadata) -> Option<Value> {
        if metadata.is_secret() && !self.config.env_overrides_secrets {
            return None;
        }
        let mut value = self
            .env_handler
            .get_env_override(key, &metadata.setting_type)?;
        metadata.normalize(&mut value);
        match metadata.validate(&value) {
            Ok(()) => Some(value),
            Err(reason) => {
                log::warn!("Ignoring invalid environment override for '{key}': {reason}");
                None
            }
        }
    }

    /// Get all setting metadata with current values populated.
    ///
    /// Returns an `IndexMap` of all settings with their metadata (type, label, default, current value).
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
    pub fn metadata(&self) -> Result<IndexMap<String, SettingMetadata>> {
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter(&self.config.config_dir)?;
        #[cfg(feature = "vault")]
        if self.is_locked() {
            return Err(Error::ConfigLocked);
        }

        let _guard = self.read_gate();
        // Ensure cache is populated
        self.ensure_cache_populated_inner()?;

        // Get metadata and populate values
        let mut metadata = (*self.schema_metadata).clone();

        for (key, option) in &mut metadata {
            if Self::parse_setting_key(key).is_some() {
                let (value, env_overridden) = self.get_value_with_secret_support(key, option)?;
                option.value = Some(value);
                if env_overridden {
                    option
                        .metadata
                        .insert("env_override".to_string(), Value::Bool(true));
                }
            }
        }

        debug!("Settings loaded successfully");
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
        serde_json::from_value(value).map_err(|source| Error::Deserialize {
            key: key.to_owned(),
            source,
        })
    }

    /// Get raw JSON value for a setting key.
    ///
    /// Returns the value from merged settings cache, or from keyring if it's a secret.
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
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter(&self.config.config_dir)?;
        #[cfg(feature = "vault")]
        if self.is_locked() {
            return Err(Error::ConfigLocked);
        }

        if Self::parse_setting_key(key).is_none() {
            return Err(Error::InvalidKey(key.to_owned()));
        }

        let _guard = self.read_gate();
        // Ensure cache is populated with schema defaults
        self.ensure_cache_populated_inner()?;

        // Get metadata to check if this is a secret
        let setting_metadata = self
            .schema_metadata
            .get(key)
            .ok_or_else(|| Error::SettingNotFound(key.to_owned()))?;

        // Use the helper that handles both secrets and regular settings.
        Ok(self.get_value_with_secret_support(key, setting_metadata)?.0)
    }

    /// Get merged settings as raw JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if settings cannot be read.
    pub fn get_all_data(&self) -> Result<Value> {
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter(&self.config.config_dir)?;
        #[cfg(feature = "vault")]
        if self.is_locked() {
            return Err(Error::ConfigLocked);
        }

        let _guard = self.read_gate();
        self.read_all_data(true)
    }

    pub(super) fn read_all_data(&self, include_env: bool) -> Result<Value> {
        self.ensure_cache_populated_inner()?;
        let mut merged = self
            .settings_cache
            .get_or_compute_merged(|stored| self.merge_with_defaults(stored))?;
        for (key, metadata) in self.schema_metadata.iter() {
            if metadata.is_secret() {
                let value = self.persisted_value(key, metadata)?;
                crate::utils::value::set_path(&mut merged, key, value);
            }
            if include_env && let Some(value) = self.env_override(key, metadata) {
                crate::utils::value::set_path(&mut merged, key, value);
            }
        }
        Ok(merged)
    }

    /// Get merged settings struct with caching.
    ///
    /// # Errors
    ///
    /// Returns an error if settings cannot be read or parsed.
    pub fn get_all(&self) -> Result<Schema> {
        let merged = self.get_all_data()?;

        // Deserialize to concrete type
        serde_json::from_value(merged).map_err(|source| Error::Deserialize {
            key: "*".to_owned(),
            source,
        })
    }

    /// Merge stored settings over the defaults.
    ///
    /// The schema metadata defaults win over `Schema::default()`, so every read
    /// path agrees on a setting's default; the struct's `Default` only fills
    /// fields the schema does not describe.
    fn merge_with_defaults(&self, stored: &Value) -> Result<Value> {
        let mut merged = serde_json::to_value(Schema::default())?;
        for (key, metadata) in self.schema_metadata.iter() {
            crate::utils::value::set_path(&mut merged, key, metadata.default.clone());
        }
        if stored.is_object() {
            crate::utils::value::deep_merge(&mut merged, stored);
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
        self.register_sub_settings_inner(config, true)
    }

    pub(super) fn register_sub_settings_inner(
        &self,
        config: SubSettingsConfig,
        initialize: bool,
    ) -> Result<()> {
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter(&self.config.config_dir)?;
        let name = config.name.clone();

        #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
        let credentials = self.credentials.clone();

        #[cfg(feature = "vault")]
        let vault = Arc::clone(&self.vault);

        let handler = Arc::new(SubSettings::new(
            &self.config.config_dir,
            config,
            self.storage.clone(),
            #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
            credentials,
            #[cfg(feature = "vault")]
            vault,
        )?);

        if initialize {
            #[cfg(feature = "vault")]
            if !self.is_locked() && (self.config.vault_requested || self.is_vault_enabled()) {
                for directory in handler.vault_directories()? {
                    handler.read_entries(&directory)?;
                }
            }
            #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
            {
                #[cfg(feature = "vault")]
                if !self.is_locked() {
                    self.finish_sub_settings_secret_migration(&handler)?;
                }
                #[cfg(not(feature = "vault"))]
                self.migrate_sub_settings_secret_keys(&handler)?;
            }
        }

        self.sub_settings
            .write_recovered()?
            .insert(name.clone(), handler);

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
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter(&self.config.config_dir)?;
        let guard = self.sub_settings.read_recovered()?;
        guard
            .get(name)
            .cloned()
            .ok_or_else(|| Error::SubSettingsNotRegistered(name.to_string()))
    }

    /// Check if a sub-settings type exists
    ///
    pub fn has_sub_settings(&self, name: &str) -> bool {
        match self.sub_settings.read_recovered() {
            Ok(guard) => guard.contains_key(name),
            Err(err) => {
                debug!("Failed to check sub-settings existence for {name}: {err}");
                false
            }
        }
    }

    /// List all registered sub-settings types
    pub fn sub_settings_types(&self) -> Vec<String> {
        match self.sub_settings.read_recovered() {
            Ok(guard) => guard.keys().cloned().collect(),
            Err(err) => {
                debug!("Failed to list sub-settings types: {err}");
                Vec::new()
            }
        }
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
    #[cfg(feature = "backup")]
    pub fn register_external_provider(&self, provider: Box<dyn ExternalConfigProvider>) {
        if let Ok(mut providers) = self.external_providers.write_recovered() {
            providers.push(Arc::from(provider));
        } else {
            debug!("Failed to register external config provider due to lock recovery error");
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

        // Main settings
        categories.push(ExportCategory {
            id: "settings".to_string(),
            name: "settings".to_string(),
            category_type: ExportCategoryType::Settings,
            optional: false,
            description: None,
        });

        // Sub-settings
        let sub_types = self.sub_settings_types();
        for sub_type in sub_types {
            categories.push(ExportCategory {
                id: sub_type.clone(),
                name: sub_type.clone(),
                category_type: ExportCategoryType::SubSettings,
                optional: false,
                description: None,
            });
        }

        // External configs
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
