//! Sub-settings management for per-entity configuration files
//!
//! Sub-settings allow storing multiple related configuration entities separately
//! from the main settings file. Two storage modes are available:
//!
//! - `MultiFile`: One file per entity (e.g., `config/remotes/gdrive.json`)
//! - `SingleFile`: All entities in one file (e.g., `config/backends.json`)

pub mod multi_file;
pub mod single_file;
pub mod store;

use crate::error::{Error, Result};
use crate::storage::StorageBackend;
use crate::sync::RwLockExt;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
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

    /// Storage mode (`MultiFile` or `SingleFile`)
    pub mode: SubSettingsMode,

    /// Cache strategy for this sub-settings type
    pub(crate) cache_strategy: crate::CacheStrategy,

    /// Whether profiles are enabled for this sub-settings type
    #[cfg(feature = "profiles")]
    pub profiles_enabled: bool,

    /// Profile migration strategy (defaults to Auto)
    #[cfg(feature = "profiles")]
    pub profile_migrator: crate::profiles::ProfileMigrator,
}

impl Default for SubSettingsConfig {
    fn default() -> Self {
        Self {
            name: "items".into(),
            extension: None,
            migrator: None,
            mode: SubSettingsMode::MultiFile,
            cache_strategy: crate::CacheStrategy::default(),
            #[cfg(feature = "profiles")]
            profiles_enabled: false,
            #[cfg(feature = "profiles")]
            profile_migrator: crate::profiles::ProfileMigrator::default(),
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
    ) -> Result<Self> {
        if config.extension.is_none() {
            config.extension = Some(storage.extension().to_string());
        }

        if let Err(e) = config.cache_strategy.validate() {
            return Err(Error::InvalidCacheStrategy(e.to_string()));
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
        store.get(name)
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
        let json_value = serde_json::to_value(value).map_err(|e| Error::Parse(e.to_string()))?;

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
