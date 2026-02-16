//! Sub-settings management for per-entity configuration files
//!
//! Sub-settings allow storing multiple related configuration entities separately
//! from the main settings file. Two storage modes are available:
//!
//! - `MultiFile`: One file per entity (e.g., `config/remotes/gdrive.json`)
//! - `SingleFile`: All entities in one file (e.g., `config/backends.json`)

mod multi_file;
mod single_file;
mod store;

use crate::error::{Error, Result};
use crate::storage::StorageBackend;
use crate::sync::RwLockExt;
use crate::{SettingMetadata, SettingsSchema};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use self::multi_file::MultiFileStore;
use self::single_file::SingleFileStore;
use self::store::SubSettingsStore;

/// Mode of storage for sub-settings
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SubSettingsMode {
    /// Store each entry in a separate file within a directory (default)
    #[default]
    MultiFile,
    /// Store all entries in a single file
    SingleFile,
}

/// Configuration for a sub-settings type.
#[derive(Clone)]
pub struct SubSettingsConfig {
    /// Name of this sub-settings type
    pub name: String,

    /// File extension for entries (default: derived from storage backend)
    pub extension: Option<String>,

    /// Optional migration function for schema changes
    pub migrator: Option<Arc<dyn Fn(Value) -> Value + Send + Sync>>,

    /// Optional schema metadata for validating sub-settings entries
    pub schema: Option<Arc<HashMap<String, SettingMetadata>>>,

    /// Storage mode (`MultiFile` or `SingleFile`)
    pub mode: SubSettingsMode,

    /// Cache strategy for this sub-settings type
    pub cache_strategy: crate::CacheStrategy,

    /// Whether profiles are enabled for this sub-settings type
    #[cfg(feature = "profiles")]
    pub profiles_enabled: bool,

    /// Profile migration strategy (defaults to Auto)
    #[cfg(feature = "profiles")]
    pub profile_migrator: crate::ProfileMigrator,
}

impl Default for SubSettingsConfig {
    fn default() -> Self {
        Self {
            name: "items".into(),
            extension: None,
            migrator: None,
            schema: None,
            mode: SubSettingsMode::MultiFile,
            cache_strategy: crate::CacheStrategy::default(),
            #[cfg(feature = "profiles")]
            profiles_enabled: false,
            #[cfg(feature = "profiles")]
            profile_migrator: crate::ProfileMigrator::default(),
        }
    }
}
impl SubSettingsConfig {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Default::default()
        }
    }

    pub fn singlefile(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            mode: SubSettingsMode::SingleFile,
            ..Default::default()
        }
    }

    #[must_use]
    pub fn with_cache(mut self, strategy: crate::CacheStrategy) -> Self {
        self.cache_strategy = strategy;
        self
    }

    #[must_use]
    pub fn with_lru_cache(self, max_entries: usize) -> Self {
        self.with_cache(crate::CacheStrategy::Lru(max_entries))
    }

    #[must_use]
    pub fn with_no_cache(self) -> Self {
        self.with_cache(crate::CacheStrategy::None)
    }

    #[must_use]
    pub fn with_extension(mut self, ext: impl Into<String>) -> Self {
        self.extension = Some(ext.into());
        self
    }

    #[must_use]
    pub fn with_migrator<F>(mut self, migrator: F) -> Self
    where
        F: Fn(Value) -> Value + Send + Sync + 'static,
    {
        self.migrator = Some(Arc::new(migrator));
        self
    }

    #[must_use]
    pub fn with_metadata(mut self, metadata: HashMap<String, SettingMetadata>) -> Self {
        self.schema = Some(Arc::new(metadata));
        self
    }

    #[must_use]
    pub fn with_schema<Schema: SettingsSchema>(self) -> Self {
        self.with_metadata(Schema::get_metadata())
    }

    #[cfg(feature = "profiles")]
    #[must_use]
    pub fn with_profiles(mut self) -> Self {
        self.profiles_enabled = true;
        self
    }

    #[cfg(feature = "profiles")]
    #[must_use]
    pub fn with_profile_migrator(mut self, migrator: crate::profiles::ProfileMigrator) -> Self {
        self.profile_migrator = migrator;
        self
    }
}

/// Callback for change notifications
pub type ChangeCallback = Arc<dyn Fn(&str, SubSettingsAction) + Send + Sync>;

/// Handler for a single sub-settings type
pub struct SubSettings<S: StorageBackend = crate::storage::JsonStorage> {
    config: SubSettingsConfig,

    #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
    credential_manager: Option<crate::credentials::CredentialManager>,

    /// The active store implementation
    store: RwLock<Box<dyn SubSettingsStore>>,

    /// We keep storage around mostly for profiles logic if needed,
    /// or simple ref storage.
    /// The storage backend instance (kept for recreating stores)
    #[cfg(feature = "profiles")]
    storage: S,

    #[cfg(not(feature = "profiles"))]
    _marker: std::marker::PhantomData<S>,

    /// Callback for change notifications
    on_change: RwLock<Option<ChangeCallback>>,

    /// Profile manager (when profiles are enabled)
    #[cfg(feature = "profiles")]
    profile_manager: Option<crate::profiles::ProfileManager<S>>,

    #[cfg(feature = "profiles")]
    root_dir: PathBuf,
}

/// Action type for change callbacks
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubSettingsAction {
    Created,
    Updated,
    Deleted,
}

impl<S: StorageBackend + Clone + 'static> SubSettings<S> {
    /// Create a new `SubSettings` instance
    ///
    /// # Arguments
    ///
    /// * `config_dir` - The directory where the configuration files are stored
    /// * `config` - The configuration for the sub-settings
    /// * `storage` - The storage backend to use
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The cache strategy is invalid
    /// - Profile migration fails
    /// - File operations fail
    pub fn new(
        config_dir: &std::path::Path,
        mut config: SubSettingsConfig,
        storage: S,
        #[cfg(any(feature = "keychain", feature = "encrypted-file"))] credential_manager: Option<
            crate::credentials::CredentialManager,
        >,
    ) -> Result<Self> {
        if config.extension.is_none() {
            config.extension = Some(storage.extension().to_string());
        }

        if let Err(e) = config.cache_strategy.validate() {
            return Err(Error::InvalidCacheStrategy(e.to_string()));
        }

        if let Some(schema) = &config.schema {
            for (key, metadata) in schema.iter() {
                if let Err(reason) = metadata.validate_schema() {
                    return Err(Error::InvalidSettingMetadata {
                        key: format!("{}.{}", config.name, key),
                        reason,
                    });
                }
            }
        }

        #[cfg(feature = "profiles")]
        let root_dir = if config.profiles_enabled {
            config_dir.join(&config.name)
        } else if matches!(config.mode, SubSettingsMode::SingleFile) {
            config_dir.to_path_buf()
        } else {
            config_dir.join(&config.name)
        };

        #[cfg(not(feature = "profiles"))]
        let root_dir = if matches!(config.mode, SubSettingsMode::SingleFile) {
            config_dir.to_path_buf()
        } else {
            config_dir.join(&config.name)
        };

        // Determine initial base_dir (active profile or root)
        #[cfg(feature = "profiles")]
        let (base_dir, profile_manager) = if config.profiles_enabled {
            let is_single_file = matches!(config.mode, SubSettingsMode::SingleFile);
            crate::profiles::migrate(
                &root_dir,
                &config.name,
                is_single_file,
                &storage,
                &config.profile_migrator,
            )
            .map_err(|e| Error::ProfileMigrationFailed(e.to_string()))?;

            let pm = crate::profiles::ProfileManager::new(&root_dir, &config.name, storage.clone());
            let active_path = pm.profile_path(crate::profiles::DEFAULT_PROFILE);
            (active_path, Some(pm))
        } else {
            (root_dir.clone(), None)
        };

        #[cfg(not(feature = "profiles"))]
        let base_dir = root_dir.clone();

        let extension = config.extension.as_deref().unwrap_or("json").to_string();

        let store: Box<dyn SubSettingsStore> = match config.mode {
            SubSettingsMode::MultiFile => Box::new(MultiFileStore::new(
                config.name.clone(),
                base_dir,
                extension,
                storage.clone(),
                config.migrator.clone(),
                config.cache_strategy,
            )),
            SubSettingsMode::SingleFile => Box::new(SingleFileStore::new(
                config.name.clone(),
                base_dir,
                extension,
                storage.clone(),
                config.migrator.clone(),
            )),
        };

        Ok(Self {
            config,
            #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
            credential_manager,
            store: RwLock::new(store),
            #[cfg(feature = "profiles")]
            storage,
            #[cfg(not(feature = "profiles"))]
            _marker: std::marker::PhantomData,
            on_change: RwLock::new(None),
            #[cfg(feature = "profiles")]
            profile_manager,
            #[cfg(feature = "profiles")]
            root_dir,
        })
    }

    #[cfg(feature = "profiles")]
    pub fn root_path(&self) -> PathBuf {
        self.root_dir.clone()
    }

    pub fn is_single_file(&self) -> bool {
        matches!(self.config.mode, SubSettingsMode::SingleFile)
    }

    #[cfg(feature = "profiles")]
    pub fn profiles_enabled(&self) -> bool {
        self.config.profiles_enabled
    }

    pub fn extension(&self) -> &str {
        self.config.extension.as_deref().unwrap_or("json")
    }

    #[cfg(feature = "profiles")]
    pub fn storage(&self) -> &S {
        &self.storage
    }

    pub fn invalidate_cache(&self) {
        if let Ok(store) = self.store.read_recovered() {
            store.invalidate_cache();
        }
    }

    /// Get the profile manager if enabled
    ///
    /// # Errors
    ///
    /// Returns an error if profiles are not enabled for this sub-settings type.
    #[cfg(feature = "profiles")]
    pub fn profiles(&self) -> Result<&crate::profiles::ProfileManager<S>> {
        self.profile_manager
            .as_ref()
            .ok_or(Error::ProfilesNotEnabled)
    }

    /// Switch to a different profile
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the profile to switch to
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Profiles are not enabled
    /// - Profile switch fails
    /// - Store re-creation fails
    #[cfg(feature = "profiles")]
    pub fn switch_profile(&self, name: &str) -> Result<()> {
        let pm = self.profiles()?;
        pm.switch(name)?;

        // Re-create store pointing to new path
        let new_path = pm.profile_path(name);
        let extension = self
            .config
            .extension
            .as_deref()
            .unwrap_or("json")
            .to_string();

        let new_store: Box<dyn SubSettingsStore> = match self.config.mode {
            SubSettingsMode::MultiFile => Box::new(MultiFileStore::new(
                self.config.name.clone(),
                new_path,
                extension,
                self.storage.clone(),
                self.config.migrator.clone(),
                self.config.cache_strategy,
            )),
            SubSettingsMode::SingleFile => Box::new(SingleFileStore::new(
                self.config.name.clone(),
                new_path,
                extension,
                self.storage.clone(),
                self.config.migrator.clone(),
            )),
        };

        let mut store_guard = self.store.write_recovered()?;
        *store_guard = new_store;

        Ok(())
    }

    /// Set the change callback
    ///
    /// # Arguments
    ///
    /// * `callback` - The callback to set
    ///
    /// # Errors
    ///
    /// Returns an error if the internal lock is poisoned.
    pub fn set_on_change<F>(&self, callback: F) -> Result<()>
    where
        F: Fn(&str, SubSettingsAction) + Send + Sync + 'static,
    {
        let mut guard = self.on_change.write_recovered()?;
        *guard = Some(Arc::new(callback));
        Ok(())
    }

    fn notify_change(&self, name: &str, action: SubSettingsAction) {
        if let Ok(guard) = self.on_change.read_recovered() {
            if let Some(callback) = guard.as_ref() {
                callback(name, action);
            }
        }
    }

    /// Update a single field in a sub-settings entry.
    ///
    /// This performs a read-modify-write on one entry:
    /// - Loads existing entry (or `{}` if missing)
    /// - Sets the provided field path (supports dot notation)
    /// - Saves through `set()`, so schema validation and secret handling still apply
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails, schema validation fails,
    /// or store write fails.
    pub fn set_field<T: Serialize + Sync>(
        &self,
        name: &str,
        field_path: &str,
        value: &T,
    ) -> Result<()> {
        let mut entry = self
            .get_value(name)
            .unwrap_or_else(|_| Value::Object(serde_json::Map::new()));

        if !entry.is_object() {
            entry = Value::Object(serde_json::Map::new());
        }

        let new_value = serde_json::to_value(value).map_err(|e| Error::Parse(e.to_string()))?;
        Self::set_value_at_path(&mut entry, field_path, new_value);

        self.set(name, &entry)
    }

    fn value_at_path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
        let mut current = value;
        if path.is_empty() {
            return Some(current);
        }

        for segment in path.split('.') {
            current = current.as_object()?.get(segment)?;
        }

        Some(current)
    }

    fn validate_against_schema(&self, entry_name: &str, value: &Value) -> Result<()> {
        let Some(schema) = self.config.schema.as_ref() else {
            return Ok(());
        };

        if let Some(obj) = value.as_object() {
            let allowed_roots: std::collections::HashSet<&str> = schema
                .keys()
                .map(|key| key.split('.').next().unwrap_or(key.as_str()))
                .collect();

            for key in obj.keys() {
                if !allowed_roots.contains(key.as_str()) {
                    return Err(Error::InvalidSettingValue {
                        key: format!("{}.{}.{}", self.config.name, entry_name, key),
                        reason: "Field is not defined in sub-settings schema".to_string(),
                    });
                }
            }
        }

        for (path, metadata) in schema.iter() {
            if let Some(field_value) = Self::value_at_path(value, path) {
                if let Err(reason) = metadata.validate(field_value) {
                    return Err(Error::InvalidSettingValue {
                        key: format!("{}.{}.{}", self.config.name, entry_name, path),
                        reason,
                    });
                }
            }
        }

        Ok(())
    }

    #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
    fn remove_value_at_path(value: &mut Value, path: &str) -> Option<Value> {
        fn remove_nested(
            obj: &mut serde_json::Map<String, Value>,
            parts: &[&str],
        ) -> Option<Value> {
            match parts {
                [] => None,
                [last] => obj.remove(*last),
                [head, rest @ ..] => {
                    let child = obj.get_mut(*head)?;
                    let child_obj = child.as_object_mut()?;
                    let removed = remove_nested(child_obj, rest);
                    if child_obj.is_empty() {
                        obj.remove(*head);
                    }
                    removed
                }
            }
        }

        let parts: Vec<&str> = path.split('.').collect();
        let obj = value.as_object_mut()?;
        remove_nested(obj, &parts)
    }

    fn set_value_at_path(value: &mut Value, path: &str, new_value: Value) {
        if path.is_empty() {
            *value = new_value;
            return;
        }

        if !value.is_object() {
            *value = Value::Object(serde_json::Map::new());
        }

        let mut current = value;
        let mut parts = path.split('.').peekable();

        while let Some(part) = parts.next() {
            if parts.peek().is_none() {
                if let Some(obj) = current.as_object_mut() {
                    obj.insert(part.to_string(), new_value);
                }
                return;
            }

            if let Some(obj) = current.as_object_mut() {
                let entry = obj
                    .entry(part.to_string())
                    .or_insert_with(|| Value::Object(serde_json::Map::new()));

                if !entry.is_object() {
                    *entry = Value::Object(serde_json::Map::new());
                }

                current = entry;
            } else {
                return;
            }
        }
    }

    #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
    fn secret_credential_key(&self, entry_name: &str, field_path: &str) -> String {
        format!("sub.{}.{}.{}", self.config.name, entry_name, field_path)
    }

    #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
    fn active_secret_profile(&self) -> Option<String> {
        #[cfg(feature = "profiles")]
        {
            if self.config.profiles_enabled {
                return self
                    .profile_manager
                    .as_ref()
                    .and_then(|pm| pm.active().ok());
            }
        }

        None
    }

    #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
    fn extract_and_store_secrets(&self, entry_name: &str, value: &mut Value) -> Result<()> {
        let Some(schema) = self.config.schema.as_ref() else {
            return Ok(());
        };

        let secret_fields: Vec<_> = schema
            .iter()
            .filter(|(_, metadata)| metadata.is_secret())
            .collect();

        if secret_fields.is_empty() {
            return Ok(());
        }

        let creds = self
            .credential_manager
            .as_ref()
            .ok_or_else(|| Error::Credential("Credentials not enabled".to_string()))?;

        let profile = self.active_secret_profile();

        for (path, metadata) in secret_fields {
            let Some(secret_value) = Self::remove_value_at_path(value, path) else {
                continue;
            };

            let credential_key = self.secret_credential_key(entry_name, path);

            if secret_value == metadata.default {
                creds.remove(&credential_key)?;
                continue;
            }

            let value_str = match secret_value {
                Value::String(s) => s,
                v => v.to_string(),
            };

            creds.store_with_profile(&credential_key, &value_str, profile.as_deref())?;
        }

        Ok(())
    }

    #[cfg(not(any(feature = "keychain", feature = "encrypted-file")))]
    fn extract_and_store_secrets(&self, _entry_name: &str, _value: &mut Value) -> Result<()> {
        Ok(())
    }

    #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
    fn inject_secrets_from_store(&self, entry_name: &str, value: &mut Value) -> Result<()> {
        let Some(schema) = self.config.schema.as_ref() else {
            return Ok(());
        };

        let Some(creds) = self.credential_manager.as_ref() else {
            return Ok(());
        };

        let profile = self.active_secret_profile();

        for (path, metadata) in schema.iter().filter(|(_, metadata)| metadata.is_secret()) {
            let credential_key = self.secret_credential_key(entry_name, path);
            let secret = creds.get_with_profile(&credential_key, profile.as_deref())?;
            let resolved = secret.map_or_else(|| metadata.default.clone(), Value::String);
            Self::set_value_at_path(value, path, resolved);
        }

        Ok(())
    }

    #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
    fn has_stored_secret_for_entry(&self, entry_name: &str) -> Result<bool> {
        let Some(schema) = self.config.schema.as_ref() else {
            return Ok(false);
        };

        let Some(creds) = self.credential_manager.as_ref() else {
            return Ok(false);
        };

        let profile = self.active_secret_profile();

        for (path, metadata) in schema.iter().filter(|(_, metadata)| metadata.is_secret()) {
            let credential_key = self.secret_credential_key(entry_name, path);
            if creds
                .get_with_profile(&credential_key, profile.as_deref())?
                .is_some()
            {
                let _ = metadata;
                return Ok(true);
            }
        }

        Ok(false)
    }

    #[cfg(not(any(feature = "keychain", feature = "encrypted-file")))]
    fn has_stored_secret_for_entry(&self, _entry_name: &str) -> Result<bool> {
        Ok(false)
    }

    #[cfg(not(any(feature = "keychain", feature = "encrypted-file")))]
    fn inject_secrets_from_store(&self, _entry_name: &str, _value: &mut Value) -> Result<()> {
        Ok(())
    }

    #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
    fn clear_secret_fields(&self, entry_name: &str) -> Result<()> {
        let Some(schema) = self.config.schema.as_ref() else {
            return Ok(());
        };

        let Some(creds) = self.credential_manager.as_ref() else {
            return Ok(());
        };

        for (path, _) in schema.iter().filter(|(_, metadata)| metadata.is_secret()) {
            let credential_key = self.secret_credential_key(entry_name, path);
            creds.remove(&credential_key)?;
        }

        Ok(())
    }

    #[cfg(not(any(feature = "keychain", feature = "encrypted-file")))]
    fn clear_secret_fields(&self, _entry_name: &str) -> Result<()> {
        Ok(())
    }

    // Delegation methods

    /// Get a raw Value from the store
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the setting to retrieve
    ///
    /// # Errors
    ///
    /// Returns an error if the setting is not found or store access fails.
    pub fn get_value(&self, name: &str) -> Result<Value> {
        let store = self.store.read_recovered()?;

        // Try to get the entry from the store
        let mut value = match store.get(name) {
            Ok(v) => v,
            Err(Error::SubSettingsEntryNotFound(_)) => {
                // Entry not found in file, but might have secrets in keyring
                // If at least one secret exists in keyring, reconstruct from keyring + defaults
                if self.has_stored_secret_for_entry(name)? {
                    let mut empty_value = serde_json::json!({});
                    self.inject_secrets_from_store(name, &mut empty_value)?;
                    return Ok(empty_value);
                }
                // No schema or no secrets found, return original error
                return Err(Error::SubSettingsEntryNotFound(format!(
                    "Sub-setting entry '{name}' not found"
                )));
            }
            Err(e) => return Err(e),
        };

        // Inject secrets into the existing value
        self.inject_secrets_from_store(name, &mut value)?;
        Ok(value)
    }

    /// Get and deserialize a value from the store
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the setting to retrieve
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The setting is not found
    /// - Deserialization fails
    /// - Store access fails
    pub fn get<T: DeserializeOwned>(&self, name: &str) -> Result<T> {
        let value = self.get_value(name)?;
        serde_json::from_value(value).map_err(|e| Error::Parse(e.to_string()))
    }

    /// Serialize and set a value in the store
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the setting to set
    /// * `value` - The value to set
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Serialization fails
    /// - Store write fails
    pub fn set<T: Serialize + Sync>(&self, name: &str, value: &T) -> Result<()> {
        let mut json_value =
            serde_json::to_value(value).map_err(|e| Error::Parse(e.to_string()))?;

        self.validate_against_schema(name, &json_value)?;
        self.extract_and_store_secrets(name, &mut json_value)?;

        let store = self.store.read_recovered()?;
        let exists = store.get(name).is_ok();

        store.set(name, json_value)?;

        let action = if exists {
            SubSettingsAction::Updated
        } else {
            SubSettingsAction::Created
        };

        self.notify_change(name, action);
        Ok(())
    }

    /// Delete a value from the store
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the setting to delete
    ///
    /// # Errors
    ///
    /// Returns an error if store write fails.
    pub fn delete(&self, name: &str) -> Result<()> {
        let store = self.store.read_recovered()?;

        // Check if exists first for strict notification accuracy?
        // Store.remove handles "not found" gracefully usually.
        store.remove(name)?;
        self.clear_secret_fields(name)?;

        self.notify_change(name, SubSettingsAction::Deleted);
        Ok(())
    }

    /// List all sub-setting keys
    ///
    /// # Errors
    ///
    /// Returns an error if the store cannot be read.
    pub fn list(&self) -> Result<Vec<String>> {
        let store = self.store.read_recovered()?;
        store.list()
    }

    /// Check if a sub-setting key exists
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the setting to check
    ///
    /// # Errors
    ///
    /// Returns an error if the store cannot be read or if an unexpected error occurs during lookup.
    pub fn exists(&self, name: &str) -> Result<bool> {
        let store = self.store.read_recovered()?;
        match store.get(name) {
            Ok(_) => Ok(true),
            Err(Error::SubSettingsEntryNotFound(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    // Legacy support methods that might need to remain or be refactored differently
    pub fn directory(&self) -> PathBuf {
        self.store
            .read_recovered()
            .map(|s| s.get_base_path())
            .unwrap_or_default()
    }

    pub fn file_path(&self) -> Option<PathBuf> {
        self.store
            .read_recovered()
            .ok()
            .and_then(|s| s.get_single_file_path())
    }
}
