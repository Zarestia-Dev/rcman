use crate::config::SettingsSchema;
#[cfg(any(feature = "keychain", feature = "encrypted-file"))]
use crate::config::SettingMetadata;
use crate::error::{Error, Result};
use crate::manager::cache::CachedSettings;
use crate::manager::core::SettingsManager;
use crate::storage::StorageBackend;
use crate::sync::RwLockExt;

use log::{debug, info};
use serde_json::{json, Value};

impl<S: StorageBackend + 'static, Schema: SettingsSchema> SettingsManager<S, Schema> {
    /// Get the current settings file path
    ///
    /// This returns the path where settings.json is stored.
    /// If profiles are enabled, this points to the active profile's directory.
    pub(crate) fn settings_path(&self) -> std::path::PathBuf {
        let dir = self
            .settings_dir
            .read_recovered()
            .expect("Settings dir lock unrecoverable");
        dir.join(&self.config.settings_file)
    }

    /// Get the credential manager, potentially with profile context
    #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
    pub(crate) fn get_credential_with_profile(&self, key: &str) -> Result<Option<String>> {
        let creds = self
            .credentials
            .as_ref()
            .ok_or(Error::Credential("Credentials not enabled".to_string()))?;

        #[cfg(feature = "profiles")]
        let profile = self
            .profile_manager
            .as_ref()
            .and_then(|pm| pm.active().ok());

        #[cfg(not(feature = "profiles"))]
        let profile: Option<String> = None;

        creds.get_with_profile(key, profile.as_deref())
    }

    /// Store credential with profile context
    #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
    pub(crate) fn store_credential_with_profile(&self, key: &str, value: &str) -> Result<()> {
        let creds = self
            .credentials
            .as_ref()
            .ok_or(Error::Credential("Credentials not enabled".to_string()))?;

        #[cfg(feature = "profiles")]
        let profile = self
            .profile_manager
            .as_ref()
            .and_then(|pm| pm.active().ok());

        #[cfg(not(feature = "profiles"))]
        let profile: Option<String> = None;

        creds.store_with_profile(key, value, profile.as_deref())
    }

    /// Invalidate the settings cache
    ///
    /// Call this if the settings file was modified externally.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
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
        }

        debug!("Settings cache invalidated");
    }

    /// Save a single setting value.
    ///
    /// This method validates the value, updates the cache, and writes to disk.
    /// If the setting is marked as `secret: true` and credentials are enabled,
    /// the value will be stored in the OS keychain instead of the settings file.
    /// If the value equals the default, it will be removed from storage.
    /// If the value is unchanged, no I/O occurs.
    ///
    /// # Arguments
    ///
    /// * `category` - Category name (e.g., "ui", "general")
    /// * `key` - Setting key within the category (e.g., "theme", "language")
    /// * `value` - New value as JSON
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// * Validation fails
    /// * Saving to storage fails
    /// * Parsing the existing settings fails
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    pub fn save_setting(&self, category: &str, key: &str, value: &Value) -> Result<()> {
        let path = self.settings_path();
        let full_key = format!("{category}.{key}");

        // Validate the value before saving
        self.events
            .validate(&full_key, value)
            .map_err(|msg| Error::InvalidSettingValue {
                key: key.to_string(),
                reason: msg,
            })?;

        // Get metadata for this schema (needed for secret checking and validation)
        // Note: For performance-critical apps with many settings, consider implementing
        // a caching layer in your SettingsSchema implementation
        let metadata = Schema::get_metadata();

        // Handle secret settings separately
        #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
        if metadata
            .get(&full_key)
            .is_some_and(SettingMetadata::is_secret)
        {
            // Get default value from metadata
            let default_value = metadata
                .get(&full_key)
                .map_or(Value::Null, |m| m.default.clone());

            // If value equals default, remove from keychain (keep storage minimal)
            if *value == default_value {
                if let Some(ref creds) = self.credentials {
                    creds.remove(&full_key)?;
                }
                info!("Secret {full_key} set to default, removed from keychain");
                return Ok(());
            }

            let value_str = match value {
                Value::String(s) => s.clone(),
                _ => value.to_string(),
            };
            self.store_credential_with_profile(&full_key, &value_str)?;
            info!("Secret setting {full_key} stored in keychain");
            return Ok(());
        }

        // Load current settings from cache or disk
        self.ensure_cache_populated()?;

        let mut stored = self
            .settings_cache
            .get_stored()?
            .unwrap_or_else(|| json!({}));

        // Get default value from metadata
        let metadata_key = format!("{category}.{key}");
        let validator = metadata.get(&metadata_key);

        // Ensure setting exists in schema
        if validator.is_none() {
            return Err(Error::SettingNotFound(format!("{category}.{key}")));
        }

        let default_value = validator.map_or(Value::Null, |m| m.default.clone());

        // Validate value
        if let Some(m) = validator {
            if let Err(e) = m.validate(value) {
                return Err(Error::Config(format!(
                    "Validation failed for {category}.{key}: {e}"
                )));
            }
        }

        // Get old value for change notification
        let old_value = stored
            .get(category)
            .and_then(|cat| cat.get(key))
            .cloned()
            .unwrap_or_else(|| default_value.clone());

        // Skip if value unchanged
        if old_value == *value {
            debug!("Setting {category}.{key} unchanged, skipping save");
            return Ok(());
        }

        // Ensure stored is an object
        let stored_obj = stored
            .as_object_mut()
            .ok_or_else(|| Error::Parse("Settings root is not an object".into()))?;

        // Ensure category exists
        if !stored_obj.contains_key(category) {
            stored_obj.insert(category.to_string(), json!({}));
        }

        let category_obj = stored_obj
            .get_mut(category)
            .and_then(|v| v.as_object_mut())
            .ok_or_else(|| Error::Parse(format!("Category {category} is not an object")))?;

        // If value equals default, remove it (keep settings file minimal)
        if *value == default_value {
            category_obj.remove(key);
            debug!("Setting {category}.{key} set to default, removed from store");
        } else {
            category_obj.insert(key.to_string(), value.clone());
            debug!("Saved setting {category}.{key}");
        }

        // Remove empty categories
        if category_obj.is_empty() {
            stored_obj.remove(category);
        }

        // Save to file
        self.storage.write(&path, &stored)?;

        // Update cache
        self.settings_cache.update_stored(stored)?;

        info!("Setting {category}.{key} saved");

        // Notify change listeners
        self.events.notify(&full_key, &old_value, value);

        Ok(())
    }

    /// Reset a single setting to default
    ///
    /// # Arguments
    ///
    /// * `category` - Category of the setting
    /// * `key` - Key of the setting
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The setting doesn't exist
    /// - Writing to storage fails
    pub fn reset_setting(&self, category: &str, key: &str) -> Result<Value> {
        let metadata_key = format!("{category}.{key}");
        let default_value = Schema::get_metadata()
            .get(&metadata_key)
            .map(|m| m.default.clone())
            .ok_or_else(|| Error::SettingNotFound(format!("{category}.{key}")))?;

        self.save_setting(category, key, &default_value)?;

        info!("Setting {category}.{key} reset to default");
        Ok(default_value)
    }

    /// Reset all settings to defaults
    /// # Errors
    ///
    /// Returns an error if writing to storage fails or credential clearing fails.
    pub fn reset_all(&self) -> Result<()> {
        let path = self.settings_path();

        // Write empty object
        self.storage.write(&path, &json!({}))?;

        #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
        if let Some(ref creds) = self.credentials {
            creds.clear()?;
            info!("All credentials cleared");
        }

        info!("All settings reset to defaults");

        self.invalidate_cache();

        Ok(())
    }

    /// Load settings from disk, applying migrations if needed
    pub(crate) fn load_from_disk(&self) -> Result<CachedSettings> {
        // Read from file
        let settings_path = self.settings_path();
        let mut value: Value = match self.storage.read(&settings_path) {
            Ok(v) => v,
            Err(Error::FileRead { .. } | Error::PathNotFound(_)) => {
                // Start empty if not found
                json!({})
            }
            Err(e) => return Err(e),
        };

        // Apply migrations
        if let Some(migrator) = &self.config.migrator {
            let original = value.clone();
            value = migrator(value);
            if value != original {
                info!("Migrated settings file");
                self.storage.write(&settings_path, &value)?;
            }
        }

        Ok(CachedSettings {
            stored: value,
            merged: std::sync::OnceLock::new(),
            defaults: self.schema_defaults.clone(),
            generation: 0,
        })
    }

    /// Ensure the settings cache is populated
    ///
    /// This method is thread-safe and safe to call multiple times.
    /// It uses double-checked locking to avoid unnecessary locks.
    ///
    /// # Errors
    ///
    /// Returns an error if the settings cannot be loaded from disk.
    pub fn ensure_cache_populated(&self) -> Result<()> {
        if self.settings_cache.is_populated() {
            return Ok(());
        }

        self.settings_cache.populate(|| self.load_from_disk())?;

        Ok(())
    }
}
