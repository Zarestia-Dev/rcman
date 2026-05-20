#[cfg(any(feature = "keychain", feature = "encrypted-file"))]
use crate::config::SettingMetadata;
use crate::config::SettingsSchema;
use crate::error::{Error, Result};
use crate::manager::cache::CachedSettings;
use crate::manager::core::SettingsManager;
use crate::storage::StorageBackend;
use crate::utils::sync::RwLockExt;

use log::debug;
use serde_json::{Value, json};

impl<S: StorageBackend + 'static, Schema: SettingsSchema> SettingsManager<S, Schema> {
    /// Resolve the active profile name, or `None` if profiles are disabled.
    #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
    fn active_profile_name(&self) -> Option<String> {
        #[cfg(feature = "profiles")]
        {
            self.profile_manager
                .as_ref()
                .and_then(|pm| pm.active().ok())
        }
        #[cfg(not(feature = "profiles"))]
        {
            None
        }
    }

    #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
    fn require_credentials(&self) -> Result<&crate::credentials::CredentialManager> {
        self.credentials
            .as_ref()
            .ok_or(Error::Credential("Credentials not enabled".to_string()))
    }

    #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
    fn save_secret_setting(
        &self,
        full_key: &str,
        value: &Value,
        metadata: &SettingMetadata,
    ) -> Result<()> {
        let default_value = metadata.default.clone();

        let old_value = if self.credentials.is_some() {
            match self.get_credential_with_profile(full_key) {
                Ok(Some(secret_value)) => Value::String(secret_value),
                Ok(None) => default_value.clone(),
                Err(err) => {
                    debug!("Failed to read current secret value for {full_key} before save: {err}");
                    default_value.clone()
                }
            }
        } else {
            default_value.clone()
        };

        if *value == default_value {
            if self.credentials.is_some() {
                self.remove_credential_with_profile(full_key)?;
            }
            debug!("Secret {full_key} set to default, removed from keychain");

            if old_value != *value {
                self.events.notify(full_key, &old_value, value);
            }

            return Ok(());
        }

        let value_str = match value {
            Value::String(s) => s.clone(),
            _ => value.to_string(),
        };
        self.store_credential_with_profile(full_key, &value_str)?;
        debug!("Secret setting {full_key} stored in keychain");

        if old_value != *value {
            self.events.notify(full_key, &old_value, value);
        }

        Ok(())
    }

    /// Get the current settings file path.
    ///
    /// If profiles are enabled, this points to the active profile's directory.
    pub(crate) fn settings_path(&self) -> Result<std::path::PathBuf> {
        let dir = self.settings_dir.read_recovered()?;
        Ok(dir.join(&self.config.settings_file))
    }

    #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
    pub(crate) fn get_credential_with_profile(&self, key: &str) -> Result<Option<String>> {
        let creds = self.require_credentials()?;
        let profile = self.active_profile_name();
        creds.get_with_profile(key, profile.as_deref())
    }

    #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
    pub(crate) fn store_credential_with_profile(&self, key: &str, value: &str) -> Result<()> {
        let creds = self.require_credentials()?;
        let profile = self.active_profile_name();
        creds.store_with_profile(key, value, profile.as_deref())
    }

    #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
    pub(crate) fn remove_credential_with_profile(&self, key: &str) -> Result<()> {
        let creds = self.require_credentials()?;
        let profile = self.active_profile_name();
        creds.remove_with_profile(key, profile.as_deref())
    }

    /// Invalidate the settings cache.
    ///
    /// Call this if the settings file was modified externally.
    pub fn invalidate_cache(&self) {
        self.settings_cache.invalidate();

        #[cfg(feature = "profiles")]
        if let Some(pm) = &self.profile_manager {
            pm.invalidate_manifest();
        }

        if let Ok(sub_settings) = self.sub_settings.read_recovered() {
            for sub in sub_settings.values() {
                sub.invalidate_cache();
            }
        } else {
            debug!("Failed to invalidate sub-settings cache due to lock recovery error");
        }

        debug!("Settings cache invalidated");
    }

    /// Save a single setting value.
    ///
    /// Validates the value, updates the cache, and writes to disk.
    /// Secret settings (when credentials are enabled) are routed to the OS
    /// keychain instead. Values equal to the default are removed from storage.
    /// Unchanged values produce no I/O.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Validation fails
    /// - Keyring storage or file writing fails
    /// - Serialization or parsing fails
    pub fn save_setting(&self, category: &str, key: &str, value: &Value) -> Result<()> {
        let path = self.settings_path()?;
        let full_key = format!("{category}.{key}");

        // Run user-registered validators
        self.events
            .validate(&full_key, value)
            .map_err(|msg| Error::InvalidSettingValue {
                key: full_key.clone(),
                reason: msg,
            })?;

        let metadata = &self.schema_metadata;

        // Route secret settings to the credential backend
        #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
        if let Some(setting_meta) = metadata.get(&full_key).filter(|m| m.is_secret()) {
            self.save_secret_setting(&full_key, value, setting_meta)?;
            return Ok(());
        }

        self.ensure_cache_populated()?;

        let _write_guard = self
            .settings_write_lock
            .lock()
            .map_err(|_| Error::Config("Settings write lock poisoned".into()))?;

        let mut stored = self
            .settings_cache
            .get_stored()?
            .unwrap_or_else(|| json!({}));

        // Validate against schema and get metadata
        let setting_meta = metadata
            .get(&full_key)
            .ok_or_else(|| Error::SettingNotFound(full_key.clone()))?;

        if let Err(e) = setting_meta.validate(value) {
            return Err(Error::Config(format!(
                "Validation failed for {full_key}: {e}"
            )));
        }

        let default_value = setting_meta.default.clone();

        let old_value = stored
            .get(category)
            .and_then(|cat| cat.get(key))
            .cloned()
            .unwrap_or_else(|| default_value.clone());

        if old_value == *value {
            debug!("Setting {full_key} unchanged, skipping save");
            return Ok(());
        }

        let stored_obj = stored
            .as_object_mut()
            .ok_or_else(|| Error::Parse("Settings root is not an object".into()))?;

        {
            let category_obj = stored_obj
                .entry(category.to_string())
                .or_insert_with(|| json!({}))
                .as_object_mut()
                .ok_or_else(|| Error::Parse(format!("Category {category} is not an object")))?;

            // If value equals default, remove it to keep the file minimal
            if *value == default_value {
                category_obj.remove(key);
                debug!("Setting {full_key} set to default, removed from store");
            } else {
                category_obj.insert(key.to_string(), value.clone());
            }
        } // category_obj borrow ends

        // Remove empty categories
        if stored_obj
            .get(category)
            .and_then(|v| v.as_object())
            .is_some_and(serde_json::Map::is_empty)
        {
            stored_obj.remove(category);
        }

        self.storage.write(&path, &stored)?;
        self.settings_cache.update_stored(stored)?;

        debug!("Setting {full_key} saved");
        self.events.notify(&full_key, &old_value, value);

        Ok(())
    }

    /// Reset a single setting to its schema default.
    ///
    /// # Errors
    ///
    /// Returns an error if the setting key is not found in the schema,
    /// or if saving the default value fails.
    pub fn reset_setting(&self, category: &str, key: &str) -> Result<Value> {
        let metadata_key = format!("{category}.{key}");
        let default_value = self
            .schema_metadata
            .get(&metadata_key)
            .map(|m| m.default.clone())
            .ok_or_else(|| Error::SettingNotFound(format!("{category}.{key}")))?;

        self.save_setting(category, key, &default_value)?;

        debug!("Setting {category}.{key} reset to default");
        Ok(default_value)
    }

    /// Reset all settings to defaults.
    ///
    /// # Errors
    ///
    /// Returns an error if writing to storage fails or credential clearing fails.
    pub fn reset_all(&self) -> Result<()> {
        let path = self.settings_path()?;

        self.ensure_cache_populated()?;

        let stored = self
            .settings_cache
            .get_stored()?
            .unwrap_or_else(|| json!({}));

        let mut changed_events = Vec::new();
        for (full_key, metadata) in self.schema_metadata.iter() {
            let mut key_parts = full_key.split('.');
            let (Some(category), Some(setting), None) =
                (key_parts.next(), key_parts.next(), key_parts.next())
            else {
                debug!("Skipping invalid schema key format during reset_all: {full_key}");
                continue;
            };

            let default_value = metadata.default.clone();

            #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
            let old_value = if metadata.is_secret() && self.credentials.is_some() {
                match self.get_credential_with_profile(full_key) {
                    Ok(Some(secret_value)) => Value::String(secret_value),
                    Ok(None) => default_value.clone(),
                    Err(err) => {
                        debug!(
                            "Failed to read secret value for {full_key} during reset_all: {err}"
                        );
                        default_value.clone()
                    }
                }
            } else {
                stored
                    .get(category)
                    .and_then(|cat| cat.get(setting))
                    .cloned()
                    .unwrap_or_else(|| default_value.clone())
            };

            #[cfg(not(any(feature = "keychain", feature = "encrypted-file")))]
            let old_value = stored
                .get(category)
                .and_then(|cat| cat.get(setting))
                .cloned()
                .unwrap_or_else(|| default_value.clone());

            if old_value != default_value {
                changed_events.push((full_key.clone(), old_value, default_value));
            }
        }

        // Write empty object
        self.storage.write(&path, &json!({}))?;

        #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
        if let Some(ref creds) = self.credentials {
            creds.clear()?;
            debug!("All credentials cleared");
        }

        debug!("All settings reset to defaults");

        self.invalidate_cache();

        for (full_key, old_value, new_value) in changed_events {
            self.events.notify(&full_key, &old_value, &new_value);
        }

        Ok(())
    }

    /// Load settings from disk, applying migrations if needed.
    pub(crate) fn load_from_disk(&self) -> Result<CachedSettings> {
        let settings_path = self.settings_path()?;
        let mut value: Value = match self.storage.read(&settings_path) {
            Ok(v) => v,
            Err(Error::FileRead { .. } | Error::PathNotFound(_) | Error::Parse(_)) => {
                // Start empty if not found or corrupted/invalid JSON
                json!({})
            }
            Err(e) => return Err(e),
        };

        // Apply migrations
        if let Some(migrator) = &self.config.migrator {
            let original = value.clone();
            value = migrator(value);
            if value != original {
                debug!("Migrated settings file");
                self.storage.write(&settings_path, &value)?;
            }
        }

        // Strip null values: null in a settings file is a legacy artifact from
        // older code that used Option<T> fields (serialized as null when None).
        // rcman never writes null — it removes keys equal to the default instead.
        // Stripping here keeps deep_merge a pure function and prevents null from
        // clobbering schema defaults.
        crate::utils::value::strip_nulls(&mut value);

        Ok(CachedSettings {
            stored: value,
            merged: None,
            defaults: self.schema_defaults.clone(),
            generation: 0,
        })
    }

    /// Ensure the settings cache is populated.
    ///
    /// Thread-safe — `populate()` acquires a write lock internally and
    /// double-checks, so redundant calls are cheap.
    ///
    /// # Errors
    ///
    /// Returns an error if loading from disk or parsing fails.
    pub fn ensure_cache_populated(&self) -> Result<()> {
        self.settings_cache.populate(|| self.load_from_disk())
    }
}
