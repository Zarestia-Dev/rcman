//! Sub-settings management for per-entity configuration files

use crate::error::{Error, Result};
use crate::storage::StorageBackend;
use crate::sync::{MutexExt, RwLockExt};
use log::{debug, info, warn};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

/// Mode of storage for sub-settings
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SubSettingsMode {
    /// Store each entry in a separate file within a directory (default)
    #[default]
    MultiFile,
    /// Store all entries in a single JSON file
    SingleFile,
}

/// Configuration for a sub-settings type.
///
/// Sub-settings allow storing multiple related configuration entities separately
/// from the main settings file. Two storage modes are available:
///
/// # Storage Modes
///
/// ## `MultiFile` Mode (Default)
/// **Best for**: Dynamic entity lists (remotes, profiles, connections)
///
/// - Each entity stored in separate file: `config/remotes/gdrive.json`
/// - Easy to add/remove entities
/// - Git-friendly: each change is isolated
/// - Performance: O(1) for single entity operations
///
/// ## `SingleFile` Mode
/// **Best for**: Fixed configuration groups (backends, plugins, themes)
///
/// - All entities in one file: `config/backends.json`
/// - Atomic updates to all entities
/// - Better for small, related configs
/// - Performance: O(n) for operations, but entire file is cached
///
/// # Example Comparison
/// ```no_run
/// use rcman::{SubSettingsConfig, SettingsManager};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let manager = SettingsManager::builder("app", "1.0")
///     // MultiFile: one file per remote (remotes/gdrive.json, remotes/s3.json, ...)
///     .with_sub_settings(SubSettingsConfig::new("remotes"))
///     
///     // SingleFile: all backends in one file (backends.json)
///     .with_sub_settings(SubSettingsConfig::singlefile("backends"))
///     .build()?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct SubSettingsConfig {
    /// Name of this sub-settings type
    /// - Multi-file mode: used as directory name (e.g., "remotes" → config/remotes/)
    /// - Single-file mode: used as file name (e.g., "backends" → config/backends.json)
    pub name: String,

    /// File extension for entries (default: "json")
    pub extension: String,

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
            extension: "json".into(),
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
    /// Set cache strategy for this sub-settings type
    ///
    /// # Example
    /// ```
    /// use rcman::{SubSettingsConfig, CacheStrategy};
    /// let config = SubSettingsConfig::new("backends").with_cache(CacheStrategy::Full);
    /// ```
    #[must_use]
    pub fn with_cache(mut self, strategy: crate::CacheStrategy) -> Self {
        self.cache_strategy = strategy;
        self
    }

    /// Use LRU cache with maximum number of entries
    ///
    /// Good for large collections where only some entries are accessed frequently.
    ///
    /// # Example
    /// ```
    /// use rcman::SubSettingsConfig;
    /// // Keep only 20 most recently used entries in memory
    /// let config = SubSettingsConfig::new("remotes").with_lru_cache(20);
    /// ```
    #[must_use]
    pub fn with_lru_cache(self, max_entries: usize) -> Self {
        self.with_cache(crate::CacheStrategy::Lru(max_entries))
    }

    /// Disable caching - always read from disk
    ///
    /// **Warning:** High I/O overhead! Only use for write-once-read-once patterns.
    ///
    /// # Example
    /// ```
    /// use rcman::SubSettingsConfig;
    /// let config = SubSettingsConfig::new("logs").with_no_cache();
    /// ```
    #[must_use]
    pub fn with_no_cache(self) -> Self {
        self.with_cache(crate::CacheStrategy::None)
    }
    /// Create a new sub-settings config
    ///
    /// # Arguments
    /// * `name` - Name of this sub-settings type (used as directory or file name)
    ///
    /// By default, creates a directory with separate files for each entity.
    /// Use `singlefile()` constructor to store all entities in one JSON file instead.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Default::default()
        }
    }

    /// Create a single-file sub-settings config
    ///
    /// Convenience constructor for single-file mode where all entities are stored
    /// in one JSON file with entity names as keys.
    ///
    /// # Storage Mode Comparison
    ///
    /// **Multi-file (default)** - Use `new()`:
    /// ```text
    /// config/remotes/
    ///   gdrive.json
    ///   s3.json
    ///   dropbox.json
    /// ```
    ///
    /// **Single-file** - Use `singlefile()`:
    /// ```text
    /// config/backends.json  # {"local": {...}, "remote": {...}}
    /// ```
    ///
    /// # When to Use Single-File
    ///
    /// - **Few entities** (< 10)
    /// - **Atomic updates** to all entities
    /// - **Simpler structure** (one file vs directory)
    ///
    /// # Example
    ///
    /// ```rust
    /// use rcman::SubSettingsConfig;
    ///
    /// // Multi-file mode (default)
    /// let remotes = SubSettingsConfig::new("remotes");
    ///
    /// // Single-file mode
    /// let backends = SubSettingsConfig::singlefile("backends");
    /// ```
    #[must_use]
    pub fn singlefile(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            mode: SubSettingsMode::SingleFile,
            ..Default::default()
        }
    }

    /// Set a custom file extension
    #[must_use]
    pub fn with_extension(mut self, ext: impl Into<String>) -> Self {
        self.extension = ext.into();
        self
    }

    /// Set a migration function for schema changes (lazy migration)
    ///
    /// The migrator function is called automatically when loading.
    ///
    /// # `MultiFile` Mode
    /// The migrator is called for each entry when loaded.
    /// `value` is the content of the entry.
    ///
    /// # `SingleFile` Mode
    /// The migrator is called for the ENTIRE file when loaded.
    /// `value` is the root JSON object containing all entries.
    /// Use this to migrate the file structure or iterate over entries to migrate them.
    ///
    /// # Example (`MultiFile` Mode)
    ///
    /// ```rust
    /// use rcman::SubSettingsConfig;
    /// use serde_json::json;
    ///
    /// // Migrate individual remote configs
    /// let config = SubSettingsConfig::new("remotes")
    ///     .with_migrator(|mut value| {
    ///         // Add version field if missing
    ///         if let Some(obj) = value.as_object_mut() {
    ///             if !obj.contains_key("version") {
    ///                 obj.insert("version".into(), json!(2));
    ///             }
    ///         }
    ///         value
    ///     });
    /// ```
    ///
    /// # Example (`SingleFile` Mode)
    ///
    /// ```rust
    /// use rcman::SubSettingsConfig;
    /// use serde_json::json;
    ///
    /// // Migrate the entire backends file
    /// let config = SubSettingsConfig::singlefile("backends")
    ///     .with_migrator(|mut value| {
    ///         // Iterate and update each backend
    ///         if let Some(obj) = value.as_object_mut() {
    ///             for (_name, backend) in obj.iter_mut() {
    ///                 if let Some(b) = backend.as_object_mut() {
    ///                     b.insert("migrated".into(), json!(true));
    ///                 }
    ///             }
    ///         }
    ///         value
    ///     });
    /// ```
    #[must_use]
    pub fn with_migrator<F>(mut self, migrator: F) -> Self
    where
        F: Fn(Value) -> Value + Send + Sync + 'static,
    {
        self.migrator = Some(Arc::new(migrator));
        self
    }

    /// Enable profiles for this sub-settings type
    ///
    /// When profiles are enabled, entries are stored under named profile directories,
    /// allowing users to maintain multiple configurations.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use rcman::SubSettingsConfig;
    ///
    /// // Enable profiles: creates remotes/profiles/default/gdrive.json, etc.
    /// let config = SubSettingsConfig::new("remotes").with_profiles();
    /// ```
    #[cfg(feature = "profiles")]
    #[must_use]
    pub fn with_profiles(mut self) -> Self {
        self.profiles_enabled = true;
        self
    }

    /// Set a custom profile migration strategy (default: Auto)
    #[cfg(feature = "profiles")]
    #[must_use]
    pub fn with_profile_migrator(mut self, migrator: crate::profiles::ProfileMigrator) -> Self {
        self.profile_migrator = migrator;
        self
    }
}

use std::collections::HashMap;

/// Internal state protected by a single lock
#[derive(Debug)]
/// Cache storage for sub-settings
enum SubSettingsCache {
    /// Full cache - all entities in HashMap
    Full(HashMap<String, Value>),
    /// LRU cache - bounded size
    Lru(lru::LruCache<String, Value>),
    /// No cache - always read from disk
    None,
}

impl SubSettingsCache {
    /// Get a value from cache
    fn get(&self, key: &str) -> Option<&Value> {
        match self {
            SubSettingsCache::Full(map) => map.get(key),
            SubSettingsCache::Lru(lru) => lru.peek(key),
            SubSettingsCache::None => None,
        }
    }

    /// Insert a value into cache
    fn insert(&mut self, key: String, value: Value) -> Option<Value> {
        match self {
            SubSettingsCache::Full(map) => map.insert(key, value),
            SubSettingsCache::Lru(lru) => lru.put(key, value),
            SubSettingsCache::None => None,
        }
    }

    /// Remove a value from cache
    fn remove(&mut self, key: &str) -> Option<Value> {
        match self {
            SubSettingsCache::Full(map) => map.remove(key),
            SubSettingsCache::Lru(lru) => lru.pop(key),
            SubSettingsCache::None => None,
        }
    }

    /// Check if cache contains a key
    fn contains(&self, key: &str) -> bool {
        match self {
            SubSettingsCache::Full(map) => map.contains_key(key),
            SubSettingsCache::Lru(lru) => lru.contains(key),
            SubSettingsCache::None => false,
        }
    }

    /// Get all keys from cache
    fn keys(&self) -> Vec<String> {
        match self {
            SubSettingsCache::Full(map) => map.keys().cloned().collect(),
            SubSettingsCache::Lru(lru) => lru.iter().map(|(k, _)| k.clone()).collect(),
            SubSettingsCache::None => Vec::new(),
        }
    }

    /// Convert cache to HashMap (for single-file writes)
    fn to_hashmap(&self) -> HashMap<String, Value> {
        match self {
            SubSettingsCache::Full(map) => map.clone(),
            SubSettingsCache::Lru(lru) => lru.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            SubSettingsCache::None => HashMap::new(),
        }
    }
}
struct SubSettingsState {
    /// Base directory for this sub-settings type
    /// When profiles are enabled, this updates dynamically on profile switch
    base_dir: PathBuf,

    /// Cache storage based on strategy
    /// - None: not initialized yet (lazy load)
    /// - Some(SubSettingsCache::Full): full cache populated
    /// - Some(SubSettingsCache::Lru): LRU cache populated  
    /// - Some(SubSettingsCache::None): no-cache strategy (always reads from disk)
    cache: Option<SubSettingsCache>,
}

/// Handler for a single sub-settings type
pub struct SubSettings<S: StorageBackend = crate::storage::JsonStorage> {
    /// Configuration
    config: SubSettingsConfig,

    /// Internal state (base_dir + cache)
    state: RwLock<SubSettingsState>,

    /// Root directory (before profile path is applied)
    /// Reserved for future use (e.g., profile migration)
    #[cfg(feature = "profiles")]
    #[allow(dead_code)]
    root_dir: PathBuf,

    /// Storage backend (defaults to JsonStorage)
    storage: S,

    /// Mutex to serialize save operations (prevents race conditions)
    save_mutex: Mutex<()>,

    /// Callback for change notifications
    #[allow(clippy::type_complexity)]
    on_change: RwLock<Option<Arc<dyn Fn(&str, SubSettingsAction) + Send + Sync>>>,

    /// Profile manager (when profiles are enabled)
    #[cfg(feature = "profiles")]
    profile_manager: Option<crate::profiles::ProfileManager>,
}

/// Action type for change callbacks
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubSettingsAction {
    Created,
    Updated,
    Deleted,
}

impl<S: StorageBackend> SubSettings<S> {
    /// Create a new sub-settings handler
    pub fn new(config_dir: &std::path::Path, config: SubSettingsConfig, storage: S) -> Result<Self> {
        // Validate cache strategy configuration (prevents LRU(0) panic)
        if let Err(e) = config.cache_strategy.validate() {
            return Err(Error::InvalidCacheStrategy(e.to_string()));
        }

        // Determine the root directory for this sub-settings type
        // For multi-file mode: config_dir/name/
        // For single-file mode without profiles: config_dir (file will be name.json)
        // For single-file mode with profiles: config_dir/name/ (to hold .profiles.json and profiles/)
        #[cfg(feature = "profiles")]
        let root_dir = if config.profiles_enabled {
            // With profiles, always use a dedicated directory
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

        // When profiles are enabled, base_dir points to the active profile's directory
        // Otherwise, base_dir is the same as root_dir
        #[cfg(feature = "profiles")]
        let (base_dir, profile_manager) = if config.profiles_enabled {
            // Run migration if needed
            let is_single_file = matches!(config.mode, SubSettingsMode::SingleFile);
            crate::profiles::migrate(
                &root_dir,
                &config.name,
                is_single_file,
                &config.profile_migrator,
            )
            .map_err(|e| Error::ProfileMigrationFailed(e.to_string()))?;

            let pm = crate::profiles::ProfileManager::new(&root_dir, &config.name);
            // Get active profile path (defaults to "default" on first access)
            let active_path = pm.profile_path(crate::profiles::DEFAULT_PROFILE);
            (active_path, Some(pm))
        } else {
            (root_dir.clone(), None)
        };

        #[cfg(not(feature = "profiles"))]
        let base_dir = root_dir.clone();

        let state = SubSettingsState {
            base_dir,
            cache: None,
        };

        Ok(Self {
            config,
            state: RwLock::new(state),
            #[cfg(feature = "profiles")]
            root_dir,
            storage,
            save_mutex: Mutex::new(()),
            on_change: RwLock::new(None),
            #[cfg(feature = "profiles")]
            profile_manager,
        })
    }

    /// Get the root directory (useful for backups)
    #[cfg(feature = "profiles")]
    pub fn root_path(&self) -> PathBuf {
        self.root_dir.clone()
    }

    /// Get the single-file path (for single-file mode)
    fn single_file_path(base_dir: &std::path::Path, name: &str, ext: &str) -> PathBuf {
        base_dir.join(format!("{}.{}", name, ext))
    }

    /// Check if we're in single-file mode
    pub fn is_single_file(&self) -> bool {
        matches!(self.config.mode, SubSettingsMode::SingleFile)
    }

    /// Check if profiles are enabled
    #[cfg(feature = "profiles")]
    pub fn profiles_enabled(&self) -> bool {
        self.config.profiles_enabled
    }

    /// Invalidate the internal cache
    ///
    /// This forces the next read operation to reload from disk.
    /// Useful if external processes might modify the files.
    pub fn invalidate_cache(&self) {
        if let Ok(mut state) = self.state.write_recovered() {
            state.cache = None;
        }
    }

    /// Check if profiles are enabled for this sub-settings type
    #[cfg(feature = "profiles")]
    pub fn is_profiles_enabled(&self) -> bool {
        self.profile_manager.is_some()
    }

    /// Get the profile manager for this sub-settings type
    #[cfg(feature = "profiles")]
    pub fn profiles(&self) -> Result<&crate::profiles::ProfileManager> {
        self.profile_manager
            .as_ref()
            .ok_or(Error::ProfilesNotEnabled)
    }

    /// Switch to a different profile
    #[cfg(feature = "profiles")]
    pub fn switch_profile(&self, name: &str) -> Result<()> {
        let pm = self.profiles()?;
        pm.switch(name)?;

        let new_path = pm.profile_path(name);

        // Critical: Update state atomically
        let mut state = self.state.write_recovered()?;
        state.base_dir = new_path;
        state.cache = None;

        Ok(())
    }

    /// Set a callback for change notifications
    pub fn set_on_change<F>(&self, callback: F) -> Result<()>
    where
        F: Fn(&str, SubSettingsAction) + Send + Sync + 'static,
    {
        let mut guard = self.on_change.write_recovered()?;
        *guard = Some(Arc::new(callback));
        Ok(())
    }

    /// Notify about a change
    fn notify_change(&self, name: &str, action: SubSettingsAction) {
        if let Ok(guard) = self.on_change.read_recovered() {
            if let Some(callback) = guard.as_ref() {
                callback(name, action);
            }
        }
    }

    /// Ensure cache is populated (loads from disk if needed)
    fn ensure_cache_populated(&self) -> Result<()> {
        // Fast path: check if cache exists with read lock
        if self.state.read_recovered()?.cache.is_some() {
            return Ok(());
        }

        // Upgrade to write lock
        let mut state = self.state.write_recovered()?;
        if state.cache.is_some() {
            return Ok(());
        }

        let base_dir = state.base_dir.clone();

        if self.is_single_file() {
            let path = Self::single_file_path(&base_dir, &self.config.name, &self.config.extension);
            let mut file_data = match std::fs::metadata(&path) {
                Ok(_) => self.storage.read::<Value>(&path)?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // Start with empty cache based on strategy
                    state.cache = Some(match &self.config.cache_strategy {
                        crate::CacheStrategy::Full => SubSettingsCache::Full(HashMap::new()),
                        crate::CacheStrategy::Lru(max_size) => SubSettingsCache::Lru(
                            lru::LruCache::new(std::num::NonZeroUsize::new(*max_size).ok_or_else(
                                || Error::InvalidCacheStrategy("LRU size must be > 0".into()),
                            )?),
                        ),
                        crate::CacheStrategy::None => SubSettingsCache::None,
                    });
                    return Ok(());
                }
                Err(e) => {
                    return Err(Error::FileRead {
                        path: path.to_path_buf(),
                        source: e,
                    })
                }
            };

            // Apply migration and persist if changed
            if let Some(migrator) = &self.config.migrator {
                let original = file_data.clone();
                file_data = migrator(file_data);

                if file_data != original {
                    debug!("Migrated sub-settings file: {}", self.config.name);
                    // We hold state write lock, but we also need save_mutex for file I/O safety?
                    // Ideally yes, but here we are in a "load" phase.
                    // If we write back, we should lock save_mutex.
                    let _save_guard = self.save_mutex.lock_recovered()?;
                    self.storage.write(&path, &file_data)?;
                }
            }

            let obj = file_data.as_object().ok_or_else(|| {
                Error::InvalidBackup(format!(
                    "{}: Single-file sub-settings is not a JSON object",
                    path.display()
                ))
            })?;

            // Initialize cache based on strategy
            state.cache = Some(match &self.config.cache_strategy {
                crate::CacheStrategy::Full => SubSettingsCache::Full(
                    obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
                ),
                crate::CacheStrategy::Lru(max_size) => {
                    let mut lru =
                        lru::LruCache::new(std::num::NonZeroUsize::new(*max_size).ok_or_else(
                            || Error::InvalidCacheStrategy("LRU size must be > 0".into()),
                        )?);
                    for (k, v) in obj.iter() {
                        lru.put(k.clone(), v.clone());
                    }
                    SubSettingsCache::Lru(lru)
                }
                crate::CacheStrategy::None => SubSettingsCache::None,
            });
        } else {
            // MultiFile: init based on strategy
            state.cache = Some(match &self.config.cache_strategy {
                crate::CacheStrategy::Full => SubSettingsCache::Full(HashMap::new()),
                crate::CacheStrategy::Lru(max_size) => SubSettingsCache::Lru(lru::LruCache::new(
                    std::num::NonZeroUsize::new(*max_size).ok_or_else(|| {
                        Error::InvalidCacheStrategy("LRU size must be > 0".into())
                    })?,
                )),
                crate::CacheStrategy::None => SubSettingsCache::None,
            });
        }

        Ok(())
    }

    /// Load an entry (returns raw JSON Value)
    pub fn get_value(&self, name: &str) -> Result<Value> {
        self.ensure_cache_populated()?;

        // 1. Try to get from cache (Read Lock)
        let state = self.state.read_recovered()?;
        if let Some(cache) = &state.cache {
            if let Some(v) = cache.get(name) {
                return Ok(v.clone());
            }
        }

        // 2. Cache miss handling
        if self.is_single_file() {
            // In SingleFile mode, cache is authoritative if loaded
            return Err(Error::SubSettingsEntryNotFound(format!(
                "{}/{}",
                self.config.name, name
            )));
        }

        // 3. Multi-file mode: read from individual file
        // We capture base_dir to read from the correct location
        let base_dir = state.base_dir.clone();
        drop(state); // DROP LOCK to allow other readers/writers/profile switches

        let path = base_dir.join(format!("{}.{}", name, self.config.extension));

        if let Err(e) = std::fs::metadata(&path) {
            if e.kind() == std::io::ErrorKind::NotFound {
                return Err(Error::SubSettingsEntryNotFound(format!(
                    "{}/{}",
                    self.config.name, name
                )));
            }
            return Err(Error::FileRead {
                path: path.to_path_buf(),
                source: e,
            });
        }

        let mut value: Value = self.storage.read(&path)?;

        // 4. Apply migration
        if let Some(migrator) = &self.config.migrator {
            let original = value.clone();
            value = migrator(value);

            if value != original {
                debug!("Migrated sub-settings entry: {name}");

                // We need to persist the migration.
                // We lock save_mutex for I/O serialization.
                let _save_guard = self.save_mutex.lock_recovered()?;

                // We write to the path we just read from.
                // Note: we don't re-check base_dir here because we just want to update the file we read.
                self.storage.write(&path, &value)?;

                // We will update cache below, but need to be careful about base_dir.
            }
        }

        // 5. Update cache (Write Lock)
        // We must verify that base_dir hasn't changed.
        let mut state = self.state.write_recovered()?;
        if state.base_dir != base_dir {
            // Profile switched during our I/O!
            // The value we read belongs to the OLD profile.
            // We return it (it was valid when we started), but we DO NOT cache it in the NEW profile.
            return Ok(value);
        }

        // Update cache based on strategy
        if let Some(cache) = &mut state.cache {
            cache.insert(name.to_string(), value.clone());
        }

        Ok(value)
    }

    /// Load a typed entry
    pub fn get<T: DeserializeOwned>(&self, name: &str) -> Result<T> {
        let value = self.get_value(name)?;
        serde_json::from_value(value).map_err(|e| Error::Parse(e.to_string()))
    }

    /// Save an entry
    pub fn set<T: Serialize + Sync>(&self, name: &str, value: &T) -> Result<()> {
        self.ensure_cache_populated()?;
        let json_value = serde_json::to_value(value).map_err(|e| Error::Parse(e.to_string()))?;

        // Lock save_mutex to serialize I/O
        let _save_guard = self.save_mutex.lock_recovered()?;

        // Lock state (Write) for consistency
        let mut state = self.state.write_recovered()?;

        let exists = if let Some(cache) = &mut state.cache {
            cache.insert(name.to_string(), json_value.clone()).is_some()
        } else {
            false
        };

        if self.is_single_file() {
            // Write full object from cache
            let full_obj = if let Some(cache) = &state.cache {
                Value::Object(cache.to_hashmap().into_iter().collect())
            } else {
                Value::Object(serde_json::Map::new())
            };

            let base_dir = &state.base_dir; // use current base dir
                                            // Ensure dir exists
            if !base_dir.exists() {
                std::fs::create_dir_all(base_dir).map_err(|e| Error::DirectoryCreate {
                    path: base_dir.clone(),
                    source: e,
                })?;
                crate::security::set_secure_dir_permissions(base_dir)?;
            }

            let path = Self::single_file_path(base_dir, &self.config.name, &self.config.extension);
            self.storage.write(&path, &full_obj)?;
        } else {
            // Multi-file: write individual file
            let base_dir = &state.base_dir;
            std::fs::create_dir_all(base_dir).map_err(|e| Error::DirectoryCreate {
                path: base_dir.clone(),
                source: e,
            })?;
            crate::security::set_secure_dir_permissions(base_dir)?;

            let path = base_dir.join(format!("{}.{}", name, self.config.extension));
            self.storage.write(&path, &json_value)?;
        }

        let action = if exists {
            SubSettingsAction::Updated
        } else {
            SubSettingsAction::Created
        };

        info!(
            "Sub-settings '{}' {} in {}",
            name,
            match action {
                SubSettingsAction::Created => "created",
                SubSettingsAction::Updated => "updated",
                SubSettingsAction::Deleted => "deleted",
            },
            self.config.name
        );

        // Notify handling requires dropping locks ideally, but `notify_change` uses its own ReadLock on `on_change`.
        // We currently hold `state` write lock.
        // `notify_change` locks `on_change`.
        // If expectation is `on_change` callback might call back into `SubSettings`... deadlock risk?
        // Callbacks should generally be async or not call back into same lock.
        // But here we are safe from `state` deadlock if callback calls `get_value` (Read state), since RwLock allows recursion?
        // No, RwLock does NOT allow `read` if `write` is held by same thread (typically deadlocks).
        // `parking_lot::RwLock` will DEADLOCK if we try to read while holding write.

        // FIX: Drop state lock before notifying.
        drop(state); // Ensure state lock is dropped.

        self.notify_change(name, action);
        Ok(())
    }

    /// Delete an entry
    pub fn delete(&self, name: &str) -> Result<()> {
        self.ensure_cache_populated()?;

        let _save_guard = self.save_mutex.lock_recovered()?;
        let mut state = self.state.write_recovered()?;

        // Update cache
        let existed = if let Some(cache) = &mut state.cache {
            cache.remove(name).is_some()
        } else {
            false
        };

        if self.is_single_file() {
            if !existed {
                warn!("Sub-settings entry '{}' not found, nothing to delete", name);
                return Ok(());
            }

            let full_obj = if let Some(cache) = &state.cache {
                Value::Object(cache.to_hashmap().into_iter().collect())
            } else {
                Value::Object(serde_json::Map::new())
            };

            let base_dir = &state.base_dir;
            let path = Self::single_file_path(base_dir, &self.config.name, &self.config.extension);
            self.storage.write(&path, &full_obj)?;
        } else {
            let base_dir = &state.base_dir;
            let path = base_dir.join(format!("{}.{}", name, self.config.extension));

            if let Err(e) = std::fs::metadata(&path) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    return Err(Error::FileRead {
                        path: path.to_path_buf(),
                        source: e,
                    });
                }
                // If not found, that's fine from deletion perspective
            } else {
                std::fs::remove_file(&path).map_err(|e| Error::FileDelete {
                    path: path.to_path_buf(),
                    source: e,
                })?;
            }
        }

        info!("Sub-settings '{}' deleted", name);
        drop(state); // Drop lock before notify

        self.notify_change(name, SubSettingsAction::Deleted);
        Ok(())
    }

    /// List all entries
    pub fn list(&self) -> Result<Vec<String>> {
        self.ensure_cache_populated()?;

        let state = self.state.read_recovered()?;

        if self.is_single_file() {
            if let Some(cache) = &state.cache {
                let mut entries = cache.keys();
                entries.sort();
                Ok(entries)
            } else {
                Ok(Vec::new())
            }
        } else {
            // Multi-file: list files in directory
            // We use state.base_dir
            let base_dir = state.base_dir.clone();
            drop(state); // Drop lock for I/O

            if let Err(e) = std::fs::metadata(&base_dir) {
                if e.kind() == std::io::ErrorKind::NotFound {
                    return Ok(Vec::new());
                }
                return Err(Error::FileRead {
                    path: base_dir,
                    source: e,
                });
            }

            let mut entries = Vec::new();
            let ext = format!(".{}", self.config.extension);

            let read_dir = std::fs::read_dir(&base_dir).map_err(|e| Error::FileRead {
                path: base_dir.clone(),
                source: e,
            })?;

            for entry in read_dir {
                let entry = entry.map_err(|e| Error::FileRead {
                    path: base_dir.clone(),
                    source: e,
                })?;
                let name = entry.file_name().to_string_lossy().to_string();
                if name.ends_with(&ext) {
                    entries.push(name.trim_end_matches(&ext).to_string());
                }
            }
            entries.sort();
            Ok(entries)
        }
    }

    /// Check if an entry exists
    pub fn exists(&self, name: &str) -> Result<bool> {
        self.ensure_cache_populated()?;

        let state = self.state.read_recovered()?;

        if let Some(cache) = &state.cache {
            if cache.contains(name) {
                return Ok(true);
            }
        }

        if self.is_single_file() {
            Ok(false)
        } else {
            let base_dir = state.base_dir.clone();
            drop(state); // Drop lock for I/O

            let path = base_dir.join(format!("{}.{}", name, self.config.extension));
            match std::fs::metadata(&path) {
                Ok(_) => Ok(true),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(e) => Err(Error::FileRead {
                    path: path.to_path_buf(),
                    source: e,
                }),
            }
        }
    }

    /// Get the directory path for this sub-settings type
    pub fn directory(&self) -> PathBuf {
        self.state.read_recovered().map(|s| s.base_dir.clone()).unwrap_or_default()
    }

    /// Get the single file path (only applicable in single-file mode)
    pub fn file_path(&self) -> Option<PathBuf> {
        if self.is_single_file() {
            self.state.read_recovered().ok().map(|state| {
                Self::single_file_path(
                    &state.base_dir,
                    &self.config.name,
                    &self.config.extension,
                )
            })
        } else {
            None
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::JsonStorage;
    use serde_json::json;
    use tempfile::tempdir;

    #[test]
    fn test_sub_settings_crud() {
        let dir = tempdir().unwrap();
        let config = SubSettingsConfig::new("remotes");
        let storage = JsonStorage::new();
        let sub = SubSettings::new(dir.path(), config, storage).unwrap();

        // Initially empty
        let list = sub.list().unwrap();
        assert!(list.is_empty());

        // Save an entry
        let data = json!({"type": "drive", "path": "/mount/gdrive"});
        sub.set("gdrive", &data).unwrap();

        // Verify it exists
        assert!(sub.exists("gdrive").unwrap());

        // Load it back
        let loaded = sub.get_value("gdrive").unwrap();
        assert_eq!(loaded, data);

        // List should show it
        let list = sub.list().unwrap();
        assert_eq!(list, vec!["gdrive"]);

        // Delete it
        sub.delete("gdrive").unwrap();
        assert!(!sub.exists("gdrive").unwrap());
    }

    #[test]
    fn test_sub_settings_migration() {
        let dir = tempdir().unwrap();

        // Create config with migrator that adds a field
        let config = SubSettingsConfig::new("items").with_migrator(|mut v| {
            if let Some(obj) = v.as_object_mut() {
                if !obj.contains_key("version") {
                    obj.insert("version".into(), json!(2));
                }
            }
            v
        });

        let storage = JsonStorage::new();
        let sub = SubSettings::new(dir.path(), config, storage).unwrap();

        // Save old format (without version)
        let old_data = json!({"name": "test"});
        sub.set("item1", &old_data).unwrap();

        // Invalidate cache to force reload and migration
        sub.invalidate_cache();

        // Load should apply migration
        let loaded = sub.get_value("item1").unwrap();
        assert_eq!(loaded["version"], json!(2));
        assert_eq!(loaded["name"], json!("test"));
    }

    #[test]
    fn test_sub_settings_not_found() {
        let dir = tempdir().unwrap();
        let config = SubSettingsConfig::new("items");
        let storage = JsonStorage::new();
        let sub = SubSettings::new(dir.path(), config, storage).unwrap();

        let result = sub.get_value("nonexistent");
        assert!(matches!(
            result,
            Err(Error::SubSettingsEntryNotFound { .. })
        ));
    }

    #[test]
    fn test_sub_settings_single_file_mode() {
        let dir = tempdir().unwrap();

        // Create single-file config
        let config = SubSettingsConfig::singlefile("backends");
        let storage = JsonStorage::new();
        let sub = SubSettings::new(dir.path(), config, storage).unwrap();

        // Test create
        sub.set("gdrive", &json!({"type": "drive", "client_id": "123"}))
            .unwrap();
        sub.set("s3", &json!({"type": "s3", "region": "us-east-1"}))
            .unwrap();

        // Verify single file was created (not a directory)
        let file_path = dir.path().join("backends.json");
        assert!(file_path.exists());
        assert!(file_path.is_file());

        // Test list
        let list = sub.list().unwrap();
        assert_eq!(list, vec!["gdrive", "s3"]);

        // Test get
        let gdrive = sub.get::<serde_json::Value>("gdrive").unwrap();
        assert_eq!(gdrive["type"], json!("drive"));
        assert_eq!(gdrive["client_id"], json!("123"));

        // Test update
        sub.set("gdrive", &json!({"type": "drive", "client_id": "456"}))
            .unwrap();
        let gdrive = sub.get::<serde_json::Value>("gdrive").unwrap();
        assert_eq!(gdrive["client_id"], json!("456"));

        // Test exists
        assert!(sub.exists("gdrive").unwrap());
        assert!(sub.exists("s3").unwrap());
        assert!(!sub.exists("dropbox").unwrap());

        // Test delete
        sub.delete("s3").unwrap();
        let list = sub.list().unwrap();
        assert_eq!(list, vec!["gdrive"]);
        assert!(!sub.exists("s3").unwrap());

        // Test file_path()
        assert!(sub.file_path().is_some());
        assert_eq!(sub.file_path().unwrap(), file_path);
    }

    #[test]
    fn test_invalid_cache_strategy() {
        let dir = tempdir().unwrap();
        // Create config with invalid LRU size (0)
        let config = SubSettingsConfig::new("items")
            .with_cache(crate::CacheStrategy::Lru(0));
        let storage = JsonStorage::new();

        // Should return error instead of panicking
        let result = SubSettings::new(dir.path(), config, storage);
        assert!(result.is_err());
        match result {
            Err(Error::InvalidCacheStrategy(msg)) => {
                assert_eq!(msg, "Configuration error: LRU cache size must be greater than 0");
            }
            _ => panic!("Expected InvalidCacheStrategy error"),
        }
    }
}
