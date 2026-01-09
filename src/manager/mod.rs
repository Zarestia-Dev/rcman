//! Main settings manager module
//!
//! This module contains the [`SettingsManager`] struct which is the primary entry point
//! for managing application settings.

#[cfg(feature = "backup")]
use crate::backup::BackupManager;
#[cfg(feature = "backup")]
use crate::backup::ExternalConfigProvider;
use crate::config::SettingsConfig;
use crate::config::{SettingMetadata, SettingsSchema};
use std::marker::PhantomData;
#[cfg(any(feature = "keychain", feature = "encrypted-file"))]
use crate::credentials::CredentialManager;
use crate::error::{Error, Result};
use crate::events::EventManager;
use crate::storage::StorageBackend;
use crate::sub_settings::{SubSettings, SubSettingsConfig};

#[cfg(feature = "profiles")]
use log::warn;
use log::{debug, info};
use parking_lot::RwLock;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

/// Main settings manager for loading, saving, and managing application settings.
///
/// The `SettingsManager` provides a complete solution for application configuration:
///
/// - **Load/Save Settings**: Read and write settings with schema validation
/// - **Sub-Settings**: Manage per-entity configuration files (e.g., per-remote configs)
/// - **Change Events**: Register callbacks for setting changes
/// - **Backup/Restore**: Create and restore encrypted backups
/// - **Caching**: In-memory caching for fast access
/// - **Secret Settings**: Automatic keychain storage for sensitive values
///
/// # Example
///
/// ```rust,no_run
/// use rcman::{SettingsManager, SettingsConfig};
///
/// // Create with builder
/// let config = SettingsConfig::builder("my-app", "1.0.0")
///     .with_config_dir("~/.config/my-app")
///     .with_credentials()  // Enable secret storage
///     .build();
///
/// let manager = SettingsManager::new(config).unwrap();
/// ```
///
/// # Complete workflow
///
/// ```rust,no_run
/// use rcman::{SettingsManager, SettingsSchema, SettingMetadata, settings};
/// use serde::{Deserialize, Serialize};
/// use serde_json::json;
/// use std::collections::HashMap;
///
/// #[derive(Default, Serialize, Deserialize)]
/// struct AppSettings {
///     theme: String,
/// }
///
/// impl SettingsSchema for AppSettings {
///     fn get_metadata() -> HashMap<String, SettingMetadata> {
///         settings! {
///             "ui.theme" => SettingMetadata::text("Theme", "dark")
///         }
///     }
/// }
///
/// let manager = SettingsManager::builder("my-app", "1.0.0")
///     .with_config_dir("/tmp/my-app-config")
///     .build()
///     .unwrap();
///
/// // Load settings (creates file with defaults if missing)
/// manager.metadata().unwrap();
///
/// // Save a setting
/// manager.save_setting("ui", "theme", json!("light")).unwrap();
///
/// // Load settings again to verify
/// let metadata = manager.metadata().unwrap();
/// let theme_value = metadata.get("ui.theme").unwrap().value.as_ref().unwrap();
/// assert_eq!(theme_value.as_str(), Some("light"));
/// ```
///
/// # Type Parameters
///
/// * `Schema`: The settings schema type (defaults to `()` for dynamic usage).
pub struct SettingsManager<S: StorageBackend = crate::storage::JsonStorage, Schema: SettingsSchema = ()> {
    /// Configuration
    config: SettingsConfig<S, Schema>,

    /// Storage backend (defaults to JsonStorage)
    storage: S,

    /// Directory where settings file is located (may change if profiles enabled)
    settings_dir: RwLock<std::path::PathBuf>,

    /// Registered sub-settings handlers
    sub_settings: RwLock<HashMap<String, Arc<SubSettings<S>>>>,

    /// Event manager for change callbacks and validation
    events: Arc<EventManager>,

    /// Unified settings cache with generation counter for race-free invalidation
    settings_cache: RwLock<Option<CachedSettings>>,

    /// Mutex to serialize save operations (prevents race conditions)
    save_mutex: parking_lot::Mutex<()>,

    /// Credential manager for secret settings (optional, requires keychain or encrypted-file feature)
    #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
    credentials: Option<CredentialManager>,

    /// External config providers for backups
    #[cfg(feature = "backup")]
    pub(crate) external_providers: RwLock<Vec<Box<dyn ExternalConfigProvider>>>,

    /// Profile manager for main settings (when profiles are enabled)
    #[cfg(feature = "profiles")]
    profile_manager: Option<crate::profiles::ProfileManager>,

    /// Marker for schema type
    _schema: PhantomData<Schema>,
}

/// Unified cache structure holding all settings data
struct CachedSettings {
    /// Stored settings (from disk)
    stored: Value,
    /// Merged settings (defaults + stored)
    merged: Value,
    /// Default values for quick lookup
    defaults: HashMap<String, Value>,
    /// Generation counter (incremented on invalidation)
    generation: u64,
}

// =============================================================================
// Builder Module
// =============================================================================

mod builder;
pub use builder::SettingsManagerBuilder;

impl SettingsManager {
    /// Create a builder for `SettingsManager` with a fluent API.
    ///
    /// This is the recommended way to create a `SettingsManager`.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use rcman::{SettingsManager, SubSettingsConfig};
    ///
    /// let manager = SettingsManager::builder("my-app", "1.0.0")
    ///     .with_config_dir("~/.config/my-app")
    ///     .with_credentials()
    ///     .with_sub_settings(SubSettingsConfig::new("remotes"))
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn builder(
        app_name: impl Into<String>,
        app_version: impl Into<String>,
    ) -> SettingsManagerBuilder {
        SettingsManagerBuilder::<crate::storage::JsonStorage, ()>::new(app_name, app_version)
    }
}

impl<S: StorageBackend + 'static, Schema: SettingsSchema> SettingsManager<S, Schema> {
    /// Create a new settings manager with the given configuration.
    ///
    /// This will create the config directory if it doesn't exist.
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration specifying paths, app info, and storage backend
    ///
    /// # Errors
    ///
    /// Returns an error if the config directory cannot be created.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use rcman::{SettingsManager, SettingsConfig};
    ///
    /// let config = SettingsConfig::builder("my-app", "1.0.0").build();
    /// let manager = SettingsManager::new(config)?;
    /// # Ok::<(), rcman::Error>(())
    /// ```
    pub fn new(config: SettingsConfig<S, Schema>) -> Result<Self> {
        // Ensure config directory exists with secure permissions
        if !config.config_dir.exists() {
            std::fs::create_dir_all(&config.config_dir).map_err(|e| Error::DirectoryCreate {
                path: config.config_dir.clone(),
                source: e,
            })?;
            crate::security::set_secure_dir_permissions(&config.config_dir)?;
        }

        let storage = config.storage.clone();

        // Initialize credential manager if enabled and feature is available
        #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
        let credentials = if config.enable_credentials {
            info!("Credential management enabled for secret settings");
            Some(CredentialManager::new(&config.app_name))
        } else {
            None
        };

        // Initialize profile manager if profiles are enabled
        #[cfg(feature = "profiles")]
        let (settings_dir, profile_manager) = if config.profiles_enabled {
            // Run migration if needed
            crate::profiles::migrate(
                &config.config_dir,
                "settings",
                false, // Main settings is always multi-file logic (creates settings.json inside)
                &config.profile_migrator,
            )?;

            let pm = crate::profiles::ProfileManager::new(&config.config_dir, "settings");
            let active_path = pm.profile_path(crate::profiles::DEFAULT_PROFILE);
            info!("Main settings profiles enabled");
            (active_path, Some(pm))
        } else {
            (config.config_dir.clone(), None)
        };

        #[cfg(not(feature = "profiles"))]
        let settings_dir = config.config_dir.clone();

        info!(
            "Initialized rcman SettingsManager at: {:?}",
            config.config_dir
        );

        Ok(Self {
            config,
            storage,
            settings_dir: RwLock::new(settings_dir),
            sub_settings: RwLock::new(HashMap::new()),
            events: Arc::new(EventManager::new()),
            settings_cache: RwLock::new(None),
            save_mutex: parking_lot::Mutex::new(()),
            #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
            credentials,
            #[cfg(feature = "backup")]
            external_providers: RwLock::new(Vec::new()),
            #[cfg(feature = "profiles")]
            profile_manager,
            _schema: PhantomData,
        })
    }

    /// Get the configuration
    pub fn config(&self) -> &SettingsConfig<S, Schema> {
        &self.config
    }

    /// Get the current settings file path
    ///
    /// This returns the path where settings.json is stored.
    /// If profiles are enabled, this points to the active profile's directory.
    fn settings_path(&self) -> std::path::PathBuf {
        let dir = self.settings_dir.read();
        dir.join(&self.config.settings_file)
    }

    /// Get the profile manager for main settings
    ///
    /// Returns None if profiles are not enabled for main settings.
    #[cfg(feature = "profiles")]
    pub fn profiles(&self) -> Option<&crate::profiles::ProfileManager> {
        self.profile_manager.as_ref()
    }

    /// Get the credential manager, potentially with profile context
    #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
    fn get_credential_with_profile(&self, key: &str) -> Result<Option<String>> {
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
    fn store_credential_with_profile(&self, key: &str, value: &str) -> Result<()> {
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

    /// Check if profiles are enabled for main settings
    #[cfg(feature = "profiles")]
    pub fn is_profiles_enabled(&self) -> bool {
        self.profile_manager.is_some()
    }

    /// Switch to a different profile
    ///
    /// This switches the active profile for main settings and updates internal paths.
    /// All subsequent operations will use the new profile's settings.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let manager = SettingsManager::builder("my-app", "1.0.0")
    ///     .with_profiles()
    ///     .build()?;
    ///
    /// manager.switch_profile("work")?;
    /// // Now all settings operations use the work profile
    /// ```
    #[cfg(feature = "profiles")]
    pub fn switch_profile(&self, name: &str) -> Result<()> {
        let pm = self
            .profile_manager
            .as_ref()
            .ok_or(Error::ProfilesNotEnabled)?;

        // Step 1: Switch the profile in ProfileManager (this handles manifest updates)
        // This must be done first to ensure the profile exists and is valid
        pm.switch(name)?;

        // Step 2: Get the new path (without holding any locks)
        let new_path = pm.profile_path(name);

        // Step 3: Update settings_dir atomically
        {
            let mut settings_dir = self.settings_dir.write();
            *settings_dir = new_path;
        } // Lock released immediately

        // Step 4: Invalidate cache (after lock is released)
        self.invalidate_cache();

        // Step 5: Propagate to sub-settings
        // Clone the Arc references to avoid holding the lock during profile switches
        let sub_settings_list: Vec<_> = {
            let sub_settings = self.sub_settings.read();
            sub_settings
                .iter()
                .map(|(key, sub)| (key.clone(), Arc::clone(sub)))
                .collect()
        }; // Lock released immediately

        // Now switch each sub-settings without holding the main lock
        for (key, sub) in sub_settings_list {
            if let Ok(pm) = sub.profiles() {
                match pm.switch(name) {
                    Ok(()) => {
                        debug!("Switched sub-settings '{key}' to profile '{name}'");
                        sub.invalidate_cache();
                    }
                    Err(e) => warn!(
                        "Failed to switch sub-settings '{key}' to profile '{name}': {e}"
                    ),
                }
            }
        }

        Ok(())
    }

    /// Create a new profile for main settings
    #[cfg(feature = "profiles")]
    pub fn create_profile(&self, name: &str) -> Result<()> {
        let pm = self
            .profile_manager
            .as_ref()
            .ok_or(Error::ProfilesNotEnabled)?;
        pm.create(name)?;

        // Propagate to sub-settings
        let sub_settings = self.sub_settings.read();
        for (key, sub) in sub_settings.iter() {
            if let Ok(pm) = sub.profiles() {
                match pm.create(name) {
                    Ok(()) => debug!("Created profile '{name}' in sub-settings '{key}'"),
                    Err(e) => warn!(
                        "Failed to create profile '{name}' in sub-settings '{key}': {e}"
                    ),
                }
            }
        }
        Ok(())
    }

    /// List all available profiles
    #[cfg(feature = "profiles")]
    pub fn list_profiles(&self) -> Result<Vec<String>> {
        let pm = self
            .profile_manager
            .as_ref()
            .ok_or(Error::ProfilesNotEnabled)?;
        pm.list()
    }

    /// Get the active profile name
    #[cfg(feature = "profiles")]
    pub fn active_profile(&self) -> Result<String> {
        let pm = self
            .profile_manager
            .as_ref()
            .ok_or(Error::ProfilesNotEnabled)?;
        pm.active()
    }

    /// Get the environment variable name for a setting key
    ///
    /// Returns None if env var overrides are disabled.
    /// Format: {PREFIX}_{CATEGORY}_{KEY} (all uppercase)
    ///
    /// Example: with prefix "MYAPP" and key "ui.theme" -> "`MYAPP_UI_THEME`"
    #[inline]
    fn get_env_var_name(&self, key: &str) -> Option<String> {
        self.config.env_prefix.as_ref().map(|prefix| {
            let env_key = key.replace('.', "_").to_uppercase();
            format!("{}_{}", prefix.to_uppercase(), env_key)
        })
    }

    /// Check if a setting value is overridden by an environment variable
    ///
    /// Returns the parsed value if env var is set and successfully parsed.
    fn get_env_override(&self, key: &str) -> Option<Value> {
        let env_var_name = self.get_env_var_name(key)?;
        std::env::var(&env_var_name).ok().map(|env_value| {
            // Try to parse as JSON first, fallback to string
            serde_json::from_str(&env_value).unwrap_or_else(|_| {
                // If not valid JSON, treat as string
                // But also try to parse booleans and numbers
                if env_value.eq_ignore_ascii_case("true") {
                    Value::Bool(true)
                } else if env_value.eq_ignore_ascii_case("false") {
                    Value::Bool(false)
                } else if let Ok(n) = env_value.parse::<i64>() {
                    Value::Number(n.into())
                } else if let Ok(n) = env_value.parse::<f64>() {
                    serde_json::Number::from_f64(n).map_or_else(|| Value::String(env_value.clone()), Value::Number)
                } else {
                    Value::String(env_value)
                }
            })
        })
    }

    /// Get the event manager for registering change listeners and validators
    ///
    /// # Example
    ///
    /// ```
    /// # use rcman::*;
    /// # use std::sync::Arc;
    /// # use serde_json::Value;
    /// # let temp = tempfile::tempdir().unwrap();
    /// # let manager = SettingsManager::builder("test", "1.0")
    /// #     .with_config_dir(temp.path())
    /// #     .build()
    /// #     .unwrap();
    /// // Watch all changes
    /// manager.events().on_change(|key, old, new| {
    ///     println!("Changed {}: {:?} -> {:?}", key, old, new);
    /// });
    ///
    /// // Watch specific key
    /// manager.events().watch("theme", |key, _old, new| {
    ///     println!("Theme changed to: {:?}", new);
    /// });
    ///
    /// // Add validator
    /// manager.events().add_validator("port", |v: &Value| {
    ///     if v.as_i64().map(|n| n > 0 && n <= 65535).unwrap_or(false) {
    ///         Ok(())
    ///     } else {
    ///         Err("Invalid port".into())
    ///     }
    /// });
    /// ```
    pub fn events(&self) -> &Arc<EventManager> {
        &self.events
    }

    /// Get reference to credential manager (if configured)
    #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
    pub fn credentials(&self) -> Option<&crate::credentials::CredentialManager> {
        self.credentials.as_ref()
    }

    /// Invalidate the settings cache
    ///
    /// Call this if the settings file was modified externally.
    pub fn invalidate_cache(&self) {
        {
            let mut cache = self.settings_cache.write();
            *cache = None;
        }
        debug!("Settings cache invalidated");
    }

    // =========================================================================
    // Fast Value Access Methods
    // =========================================================================

    /// Get a single setting value by key path.
    ///
    /// This method automatically populates the cache using schema defaults if needed,
    /// so you don't need to call `load_settings()` first.
    ///
    /// # Type Parameters
    ///
    /// * `T` - The type to deserialize the value into
    /// * `S` - The settings schema type that provides defaults
    ///
    /// # Arguments
    ///
    /// * `key` - Setting key in "category.name" format (e.g., "general.restrict")
    ///
    /// # Example
    ///
    /// ```
    /// # use rcman::*;
    /// # use serde::{Serialize, Deserialize};
    /// # use std::collections::HashMap;
    /// # use serde_json::json;
    /// # #[derive(Default, Serialize, Deserialize)]
    /// # struct UiSettings { theme: String }
    /// # #[derive(Default, Serialize, Deserialize)]
    /// # struct GeneralSettings { restrict: bool }
    /// # #[derive(Default, Serialize, Deserialize)]
    /// # struct MySettings { ui: UiSettings, general: GeneralSettings }
    /// # impl SettingsSchema for MySettings {
    /// #     fn get_metadata() -> HashMap<String, SettingMetadata> {
    /// #         let mut m = HashMap::new();
    /// #         m.insert("ui.theme".into(), SettingMetadata::text("Theme", "dark"));
    /// #         m.insert("general.restrict".into(), SettingMetadata::toggle("Restrict", false));
    /// #         m
    /// #     }
    /// # }
    /// # let temp = tempfile::tempdir().unwrap();
    /// # let config = SettingsConfig::builder("test", "1.0").with_config_dir(temp.path()).with_schema::<MySettings>().build();
    /// # let manager = SettingsManager::new(config).unwrap();
    /// // Get a setting value with automatic default fallback
    /// let theme: String = manager.get("ui.theme")?;;
    ///
    /// // With type inference for the return type
    /// let restrict: bool = manager.get("general.restrict")?;
    /// # Ok::<(), rcman::Error>(())
    /// ```
    pub fn get<T>(&self, key: &str) -> Result<T>
    where
        T: serde::de::DeserializeOwned,
        Schema: SettingsSchema,
    {
        let value = self.get_value(key)?;
        serde_json::from_value(value).map_err(|e| Error::Parse(e.to_string()))
    }

    /// Get raw JSON value for a setting key.
    ///
    /// Returns the value from merged settings cache (stored value merged with defaults).
    /// Automatically populates the cache using schema defaults if needed.
    ///
    /// # Type Parameters
    ///
    /// * `Schema` - The settings schema type that provides defaults
    ///
    /// # Arguments
    ///
    /// * `key` - Setting key in "category.name" format
    ///
    /// # Example
    ///
    /// ```
    /// # use rcman::*;
    /// # use serde::{Serialize, Deserialize};
    /// # use std::collections::HashMap;
    /// # use serde_json::Value;
    /// # #[derive(Default, Serialize, Deserialize)]
    /// # struct CoreSettings { rclone_path: String }
    /// # #[derive(Default, Serialize, Deserialize)]
    /// # struct MySettings { core: CoreSettings }
    /// # impl SettingsSchema for MySettings {
    /// #     fn get_metadata() -> HashMap<String, SettingMetadata> {
    /// #         let mut m = HashMap::new();
    /// #         m.insert("core.rclone_path".into(), SettingMetadata::text("Path", "/usr/bin/rclone"));
    /// #         m
    /// #     }
    /// # }
    /// # let temp = tempfile::tempdir().unwrap();
    /// # let config = SettingsConfig::builder("test", "1.0").with_config_dir(temp.path()).with_schema::<MySettings>().build();
    /// # let manager = SettingsManager::new(config).unwrap();
    /// let value: Value = manager.get_value("core.rclone_path")?;
    /// # Ok::<(), rcman::Error>(())
    /// ```
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
        self.ensure_cache_populated::<Schema>()?;

        // Now read from cache (guaranteed to be populated)
        {
            let cache = self.settings_cache.read();
            if let Some(cached) = cache.as_ref() {
                // Check merged settings first
                if let Some(value) = cached
                    .merged
                    .get(category)
                    .and_then(|cat| cat.get(setting_name))
                {
                    return Ok(value.clone());
                }
                // Fall back to default
                if let Some(value) = cached.defaults.get(key) {
                    return Ok(value.clone());
                }
            }
        }

        Err(Error::SettingNotFound(format!("{category}.{setting_name}")))
    }

    /// Get merged settings struct with caching.
    ///
    /// This method caches the merged result and skips re-merging on subsequent calls,
    /// making it efficient for repeated access.
    ///
    /// # Example
    ///
    /// ```
    /// # use rcman::*;
    /// # use serde::{Serialize, Deserialize};
    /// # use std::collections::HashMap;
    /// # #[derive(Default, Serialize, Deserialize)]
    /// # struct UiSettings { theme: String }
    /// # #[derive(Default, Serialize, Deserialize)]
    /// # struct MySettings { ui: UiSettings }
    /// # impl SettingsSchema for MySettings {
    /// #     fn get_metadata() -> HashMap<String, SettingMetadata> {
    /// #         let mut m = HashMap::new();
    /// #         m.insert("ui.theme".into(), SettingMetadata::text("Theme", "dark"));
    /// #         m
    /// #     }
    /// # }
    /// # let temp = tempfile::tempdir().unwrap();
    /// # let config = SettingsConfig::builder("test", "1.0").with_config_dir(temp.path()).with_schema::<MySettings>().build();
    /// # let manager = SettingsManager::new(config).unwrap();
    /// let settings: MySettings = manager.get_all()?;
    /// println!("Theme: {}", settings.ui.theme);
    /// # Ok::<(), rcman::Error>(())
    /// ```
    pub fn get_all(&self) -> Result<Schema> {
        // Try cache first
        {
            let cache = self.settings_cache.read();
            if let Some(cached) = cache.as_ref() {
                return serde_json::from_value(cached.merged.clone())
                    .map_err(|e| Error::Parse(e.to_string()));
            }
        }

        // Cache miss - populate it
        self.ensure_cache_populated::<Schema>()?;

        // Retry with populated cache
        let cache = self.settings_cache.read();
        if let Some(cached) = cache.as_ref() {
            return serde_json::from_value(cached.merged.clone())
                .map_err(|e| Error::Parse(e.to_string()));
        }

        // Should never happen since ensure_cache_populated just populated it
        Err(Error::Config("Cache was not populated".into()))
    }

    /// Internal helper to merge stored settings with schema defaults.
    fn merge_with_defaults<T: SettingsSchema>(stored: &Value) -> Result<Value> {
        let default = T::default();
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

    /// Internal helper to ensure cache is populated.
    /// Uses double-checked locking for thread safety.
    fn ensure_cache_populated<T: SettingsSchema>(&self) -> Result<Value> {
        // 1. Fast path: Check if already cached
        {
            let cache = self.settings_cache.read();
            if let Some(cached) = cache.as_ref() {
                return Ok(cached.stored.clone());
            }
        } // Drop read lock

        // 2. Slow path: Acquire write lock
        let mut cache = self.settings_cache.write();

        // 3. Double-check: Another thread may have populated it
        if let Some(cached) = cache.as_ref() {
            return Ok(cached.stored.clone());
        }

        // 4. Load from disk
        let path = self.settings_path();
        let stored = match self.storage.read(&path) {
            Ok(v) => v,
            Err(Error::FileRead { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                json!({})
            }
            Err(e) => return Err(e),
        };

        // 5. Apply migration if configured
        let stored = if let Some(migrator) = &self.config.migrator {
            let original = stored.clone();
            let migrated = migrator(stored);

            if migrated != original {
                debug!("Migrated main settings structure");
                let _save_guard = self.save_mutex.lock();
                self.storage.write(&path, &migrated)?;
                info!("Saved migrated main settings to disk");
            }
            migrated
        } else {
            stored
        };

        // 6. Build merged and defaults
        let merged = Self::merge_with_defaults::<Schema>(&stored)?;

        let metadata = T::get_metadata();
        let defaults: HashMap<String, Value> = metadata
            .iter()
            .map(|(key, meta)| (key.clone(), meta.default.clone()))
            .collect();

        // 7. Populate unified cache
        *cache = Some(CachedSettings {
            stored: stored.clone(),
            merged,
            defaults,
            generation: 0,
        });

        debug!("Settings cache populated from disk");

        Ok(stored)
    }

    /// Get all setting metadata with current values populated.
    ///
    /// Returns a HashMap of all settings with their metadata (type, label, default, current value).
    /// Useful for rendering settings UI.
    ///
    /// Returns metadata map with current values populated.
    /// Uses in-memory cache when available.
    pub fn metadata(&self) -> Result<HashMap<String, SettingMetadata>> {
        // Ensure cache is populated
        self.ensure_cache_populated::<Schema>()?;

        // Get stored settings from cache
        let stored = {
            let cache = self.settings_cache.read();
            cache
                .as_ref().map_or_else(|| json!({}), |c| c.stored.clone())
        };

        // Get metadata and populate values
        let mut metadata = Schema::get_metadata();

        for (key, option) in &mut metadata {
            let parts: Vec<&str> = key.split('.').collect();
            if parts.len() == 2 {
                let category = parts[0];
                let setting_name = parts[1];

                // Handle secret settings - fetch from credential manager
                #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
                if option.secret {
                    // Check env var override for secrets if enabled
                    if self.config.env_overrides_secrets {
                        if let Some(env_value) = self.get_env_override(key) {
                            option.value = Some(env_value);
                            option.env_override = true;
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
                    option.env_override = true; // Mark as env-overridden for UI
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
    /// # Example
    ///
    /// ```
    /// # use rcman::*;
    /// # use serde::{Serialize, Deserialize};
    /// # use serde_json::json;
    /// # use std::collections::HashMap;
    /// # #[derive(Default, Serialize, Deserialize)]
    /// # struct UiSettings { theme: String }
    /// # #[derive(Default, Serialize, Deserialize)]
    /// # struct MySettings { ui: UiSettings }
    /// # impl SettingsSchema for MySettings {
    /// #     fn get_metadata() -> HashMap<String, SettingMetadata> { let mut m = HashMap::new(); m.insert("ui.theme".into(), SettingMetadata::text("T", "d")); m }
    /// # }
    /// # let temp = tempfile::tempdir().unwrap();
    /// # let config = SettingsConfig::builder("test", "1.0").with_config_dir(temp.path()).with_schema::<MySettings>().build();
    /// # let manager = SettingsManager::new(config).unwrap();
    /// manager.save_setting("ui", "theme", json!("dark"))?;
    /// # Ok::<(), rcman::Error>(())
    /// ```
    pub fn save_setting(
        &self,
        category: &str,
        key: &str,
        value: Value,
    ) -> Result<()> {
        // Acquire save mutex to prevent race conditions
        let _save_guard = self.save_mutex.lock();

        let path = self.settings_path();
        let full_key = format!("{category}.{key}");

        // Validate the value before saving
        self.events
            .validate(&full_key, &value)
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
        if metadata.get(&full_key).is_some_and(|m| m.secret) {
            // Get default value from metadata
            let default_value = metadata
                .get(&full_key)
                .map_or(Value::Null, |m| m.default.clone());

            // If value equals default, remove from keychain (keep storage minimal)
            if value == default_value {
                if let Some(ref creds) = self.credentials {
                    creds.remove(&full_key)?;
                }
                info!("Secret {full_key} set to default, removed from keychain");
                return Ok(());
            }

            let value_str = match &value {
                Value::String(s) => s.clone(),
                _ => value.to_string(),
            };
            self.store_credential_with_profile(&full_key, &value_str)?;
            info!("Secret setting {full_key} stored in keychain");
            return Ok(());
        }

        // Load current settings from cache or disk
        self.ensure_cache_populated::<Schema>()?;

        let mut stored: Value = {
            let cache = self.settings_cache.read();
            cache
                .as_ref().map_or_else(|| json!({}), |c| c.stored.clone())
        };

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
            if let Err(e) = m.validate(&value) {
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
        if old_value == value {
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
        if value == default_value {
            category_obj.remove(key);
            debug!(
                "Setting {category}.{key} set to default, removed from store"
            );
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

        // Update unified cache (both stored and merged)
        {
            let merged = Self::merge_with_defaults::<Schema>(&stored)?;

            let mut cache = self.settings_cache.write();
            if let Some(ref mut cached) = *cache {
                cached.stored = stored;
                cached.merged = merged;
                cached.generation += 1;
            }
        }

        info!("Setting {category}.{key} saved");

        // Notify change listeners
        self.events.notify(&full_key, &old_value, &value);

        Ok(())
    }

    /// Reset a single setting to default
    pub fn reset_setting(&self, category: &str, key: &str) -> Result<Value> {
        let metadata_key = format!("{category}.{key}");
        let default_value = Schema::get_metadata()
            .get(&metadata_key)
            .map(|m| m.default.clone())
            .ok_or_else(|| Error::SettingNotFound(format!("{category}.{key}")))?;

        self.save_setting(category, key, default_value.clone())?;

        info!("Setting {category}.{key} reset to default");
        Ok(default_value)
    }

    /// Reset all settings to defaults
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

    // =========================================================================
    // Sub-Settings Management
    // =========================================================================

    /// Register a sub-settings type for per-entity configuration.
    ///
    /// Sub-settings allow you to manage separate config files for each entity
    /// (e.g., one file per remote, per profile, etc.).
    ///
    /// # Example
    ///
    /// ```
    /// # use rcman::*;
    /// # let temp = tempfile::tempdir().unwrap();
    /// # let manager = SettingsManager::builder("test", "1.0").with_config_dir(temp.path()).build().unwrap();
    /// manager.register_sub_settings(SubSettingsConfig::new("remotes"));
    /// manager.register_sub_settings(SubSettingsConfig::new("profiles"));
    /// ```
    pub fn register_sub_settings(&self, config: SubSettingsConfig) {
        let name = config.name.clone();
        let handler = Arc::new(SubSettings::new(
            &self.config.config_dir,
            config,
            self.storage.clone(),
        ));

        let mut guard = self.sub_settings.write();
        guard.insert(name.clone(), handler);

        info!("Registered sub-settings type: {name}");
    }

    /// Get a registered sub-settings handler.
    ///
    /// Returns the handler for the specified sub-settings type, which can be used
    /// to read, write, and manage individual entries.
    ///
    /// # Example
    ///
    /// ```
    /// # use rcman::*;
    /// # use serde_json::json;
    /// # let temp = tempfile::tempdir().unwrap();
    /// # let manager = SettingsManager::builder("test", "1.0").with_config_dir(temp.path()).build().unwrap();
    /// # manager.register_sub_settings(SubSettingsConfig::new("remotes"));
    /// let remotes = manager.sub_settings("remotes")?;
    /// remotes.set("gdrive", &json!({"type": "drive"}))?;
    /// let config = remotes.get_value("gdrive")?;
    /// # Ok::<(), rcman::Error>(())
    /// ```
    pub fn sub_settings(&self, name: &str) -> Result<Arc<SubSettings<S>>> {
        let guard = self.sub_settings.read();
        guard
            .get(name)
            .cloned()
            .ok_or_else(|| Error::SubSettingsNotRegistered(name.to_string()))
    }

    /// Check if a sub-settings type is registered
    pub fn has_sub_settings(&self, name: &str) -> bool {
        self.sub_settings.read().contains_key(name)
    }

    /// Get all registered sub-settings types
    pub fn sub_settings_types(&self) -> Vec<String> {
        self.sub_settings.read().keys().cloned().collect()
    }

    /// List all entries in a sub-settings type (convenience method)
    ///
    /// This is a shorthand for `manager.sub_settings(name)?.list()?`
    ///
    /// # Example
    ///
    /// ```
    /// # use rcman::*;
    /// # let temp = tempfile::tempdir().unwrap();
    /// # let manager = SettingsManager::builder("test", "1.0").with_config_dir(temp.path()).build().unwrap();
    /// # manager.register_sub_settings(SubSettingsConfig::new("remotes"));
    /// // Instead of:
    /// let items = manager.sub_settings("remotes")?.list()?;
    ///
    /// // Use:
    /// let items = manager.list_sub_settings("remotes")?;
    /// # Ok::<(), rcman::Error>(())
    /// ```
    pub fn list_sub_settings(&self, name: &str) -> Result<Vec<String>> {
        let sub = self.sub_settings(name)?;
        sub.list()
    }

    /// Register an external config provider for backups.
    ///
    /// This allows dynamic registration of external files to be included in backups.
    #[cfg(feature = "backup")]
    pub fn register_external_provider(&self, provider: Box<dyn ExternalConfigProvider>) {
        let mut providers = self.external_providers.write();
        providers.push(provider);
    }

    // =========================================================================
    // Backup Manager Access
    // =========================================================================

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
    ///
    /// # Example
    ///
    /// ```
    /// # use rcman::*;
    /// # let temp = tempfile::tempdir().unwrap();
    /// # let manager = SettingsManager::builder("test", "1.0").with_config_dir(temp.path()).build().unwrap();
    /// let categories = manager.get_export_categories();
    /// for cat in categories {
    ///     println!("{}: {:?}", cat.name, cat.category_type);
    /// }
    /// ```
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

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SettingsConfig;
    use crate::config::{SettingMetadata, SettingType, SettingsSchema};
    use crate::storage::JsonStorage;
    use serde::{Deserialize, Serialize};
    use tempfile::tempdir;

    #[derive(Debug, Default, Serialize, Deserialize)]
    struct TestSettings {
        general: GeneralSettings,
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct GeneralSettings {
        language: String,
        dark_mode: bool,
    }

    impl Default for GeneralSettings {
        fn default() -> Self {
            Self {
                language: "en".into(),
                dark_mode: false,
            }
        }
    }

    impl SettingsSchema for TestSettings {
        fn get_metadata() -> HashMap<String, SettingMetadata> {
            let mut map = HashMap::new();
            map.insert(
                "general.language".into(),
                SettingMetadata {
                    setting_type: SettingType::Select,
                    default: json!("en"),
                    label: "Language".into(),
                    ..Default::default()
                },
            );
            map.insert(
                "general.dark_mode".into(),
                SettingMetadata {
                    setting_type: SettingType::Toggle,
                    default: json!(false),
                    label: "Dark Mode".into(),
                    ..Default::default()
                },
            );
            map
        }
    }

    #[test]
    fn test_settings_defaults() {
        let dir = tempdir().unwrap();
        let config = SettingsConfig {
            config_dir: dir.path().to_path_buf(),
            settings_file: "settings.json".into(),
            app_name: "test".into(),
            app_version: "1.0.0".into(),
            storage: JsonStorage::new(),
            enable_credentials: false,
            external_configs: Vec::new(),
            env_prefix: None,
            env_overrides_secrets: false,
            migrator: None,
            #[cfg(feature = "profiles")]
            profiles_enabled: false,
            #[cfg(feature = "profiles")]
            profile_migrator: crate::profiles::ProfileMigrator::None,
            _schema: std::marker::PhantomData::<TestSettings>,
        };

        let manager = SettingsManager::new(config).unwrap();
        let settings: TestSettings = manager.get_all().unwrap();

        assert_eq!(settings.general.language, "en");
        assert!(!settings.general.dark_mode);
    }

    #[test]
    fn test_settings_with_stored() {
        let dir = tempdir().unwrap();

        // Write some stored settings
        std::fs::write(
            dir.path().join("settings.json"),
            r#"{"general": {"language": "tr"}}"#,
        )
        .unwrap();

        let config = SettingsConfig {
            config_dir: dir.path().to_path_buf(),
            settings_file: "settings.json".into(),
            app_name: "test".into(),
            app_version: "1.0.0".into(),
            storage: JsonStorage::new(),
            enable_credentials: false,
            external_configs: Vec::new(),
            env_prefix: None,
            env_overrides_secrets: false,
            migrator: None,
            #[cfg(feature = "profiles")]
            profiles_enabled: false,
            #[cfg(feature = "profiles")]
            profile_migrator: crate::profiles::ProfileMigrator::None,
            _schema: std::marker::PhantomData::<TestSettings>,
        };

        let manager = SettingsManager::new(config).unwrap();
        let settings: TestSettings = manager.get_all().unwrap();

        // Stored value should override default
        assert_eq!(settings.general.language, "tr");
        // Non-stored value should use default
        assert!(!settings.general.dark_mode);
    }

    #[test]
    fn test_save_and_load_setting() {
        let dir = tempdir().unwrap();
        let config = SettingsConfig {
            config_dir: dir.path().to_path_buf(),
            settings_file: "settings.json".into(),
            app_name: "test".into(),
            app_version: "1.0.0".into(),
            storage: JsonStorage::new(),
            enable_credentials: false,
            external_configs: Vec::new(),
            env_prefix: None,
            env_overrides_secrets: false,
            migrator: None,
            #[cfg(feature = "profiles")]
            profiles_enabled: false,
            #[cfg(feature = "profiles")]
            profile_migrator: crate::profiles::ProfileMigrator::None,
            _schema: std::marker::PhantomData::<TestSettings>,
        };

        let manager = SettingsManager::new(config).unwrap();

        // Save a setting
        manager
            .save_setting("general", "language", json!("de"))
            .unwrap();

        // Load settings
        let metadata = manager.metadata().unwrap();
        let lang = metadata.get("general.language").unwrap();

        assert_eq!(lang.value, Some(json!("de")));
    }

    #[test]
    fn test_reset_setting() {
        let dir = tempdir().unwrap();
        let config = SettingsConfig {
            config_dir: dir.path().to_path_buf(),
            settings_file: "settings.json".into(),
            app_name: "test".into(),
            app_version: "1.0.0".into(),
            storage: JsonStorage::new(),
            enable_credentials: false,
            external_configs: Vec::new(),
            env_prefix: None,
            env_overrides_secrets: false,
            migrator: None,
            #[cfg(feature = "profiles")]
            profiles_enabled: false,
            #[cfg(feature = "profiles")]
            profile_migrator: crate::profiles::ProfileMigrator::None,
            _schema: std::marker::PhantomData::<TestSettings>,
        };

        let manager = SettingsManager::new(config).unwrap();

        // Save a non-default value
        manager
            .save_setting("general", "dark_mode", json!(true))
            .unwrap();

        // Reset it
        let default = manager
            .reset_setting("general", "dark_mode")
            .unwrap();

        assert_eq!(default, json!(false));
    }

    #[test]
    fn test_sub_settings_registration() {
        let dir = tempdir().unwrap();
        let config = SettingsConfig {
            config_dir: dir.path().to_path_buf(),
            settings_file: "settings.json".into(),
            app_name: "test".into(),
            app_version: "1.0.0".into(),
            storage: JsonStorage::new(),
            enable_credentials: false,
            external_configs: Vec::new(),
            env_prefix: None,
            env_overrides_secrets: false,
            migrator: None,
            #[cfg(feature = "profiles")]
            profiles_enabled: false,
            #[cfg(feature = "profiles")]
            profile_migrator: crate::profiles::ProfileMigrator::None,
            _schema: std::marker::PhantomData::<TestSettings>,
        };

        let manager = SettingsManager::new(config).unwrap();

        // Register sub-settings
        manager.register_sub_settings(SubSettingsConfig::new("remotes"));

        assert!(manager.has_sub_settings("remotes"));
        assert!(!manager.has_sub_settings("nonexistent"));

        // Use sub-settings
        let remotes = manager.sub_settings("remotes").unwrap();
        remotes.set("gdrive", &json!({"type": "drive"})).unwrap();

        let loaded = remotes.get_value("gdrive").unwrap();
        assert_eq!(loaded["type"], json!("drive"));
    }

    #[test]
    fn test_env_var_override() {
        let dir = tempdir().unwrap();
        let config = SettingsConfig {
            config_dir: dir.path().to_path_buf(),
            settings_file: "settings.json".into(),
            app_name: "test".into(),
            app_version: "1.0.0".into(),
            storage: JsonStorage::new(),
            enable_credentials: false,
            env_prefix: Some("RCMAN_TEST".to_string()),
            env_overrides_secrets: false,
            external_configs: Vec::new(),
            migrator: None,
            #[cfg(feature = "profiles")]
            profiles_enabled: false,
            #[cfg(feature = "profiles")]
            profile_migrator: crate::profiles::ProfileMigrator::None,
            _schema: std::marker::PhantomData::<TestSettings>,
        };

        let manager = SettingsManager::new(config).unwrap();

        // Set an environment variable for testing
        std::env::set_var("RCMAN_TEST_GENERAL_LANGUAGE", "fr");

        // Load settings - should get value from env var
        let metadata = manager.metadata().unwrap();
        let lang = metadata.get("general.language").unwrap();

        // Value should be from env var, not default
        assert_eq!(lang.value, Some(json!("fr")));
        // Should be marked as env override
        assert!(
            lang.env_override,
            "Setting should be marked as env-overridden"
        );

        // Clean up
        std::env::remove_var("RCMAN_TEST_GENERAL_LANGUAGE");
    }

    #[test]
    fn test_env_var_priority_over_stored() {
        let dir = tempdir().unwrap();

        // First, store a value in the settings file
        let stored = json!({
            "general": {
                "language": "de"
            }
        });
        std::fs::write(
            dir.path().join("settings.json"),
            serde_json::to_string_pretty(&stored).unwrap(),
        )
        .unwrap();

        let config = SettingsConfig {
            config_dir: dir.path().to_path_buf(),
            settings_file: "settings.json".into(),
            app_name: "test".into(),
            app_version: "1.0.0".into(),
            storage: JsonStorage::new(),
            enable_credentials: false,
            env_prefix: Some("RCMAN_TEST2".to_string()),
            env_overrides_secrets: false,
            external_configs: Vec::new(),
            migrator: None,
            #[cfg(feature = "profiles")]
            profiles_enabled: false,
            #[cfg(feature = "profiles")]
            profile_migrator: crate::profiles::ProfileMigrator::None,
            _schema: std::marker::PhantomData::<TestSettings>,
        };

        let manager = SettingsManager::new(config).unwrap();

        // Set env var - should take priority over stored value
        std::env::set_var("RCMAN_TEST2_GENERAL_LANGUAGE", "es");

        let metadata = manager.metadata().unwrap();
        let lang = metadata.get("general.language").unwrap();

        // Env var should win over stored value
        assert_eq!(lang.value, Some(json!("es")));
        assert!(lang.env_override);

        std::env::remove_var("RCMAN_TEST2_GENERAL_LANGUAGE");
    }

    #[test]
    fn test_env_var_type_parsing() {
        let dir = tempdir().unwrap();
        let config = SettingsConfig {
            config_dir: dir.path().to_path_buf(),
            settings_file: "settings.json".into(),
            app_name: "test".into(),
            app_version: "1.0.0".into(),
            storage: JsonStorage::new(),
            enable_credentials: false,
            env_prefix: Some("RCMAN_TEST3".to_string()),
            env_overrides_secrets: false,
            external_configs: Vec::new(),
            migrator: None,
            #[cfg(feature = "profiles")]
            profiles_enabled: false,
            #[cfg(feature = "profiles")]
            profile_migrator: crate::profiles::ProfileMigrator::None,
            _schema: std::marker::PhantomData::<TestSettings>,
        };

        let manager = SettingsManager::new(config).unwrap();

        // Test boolean parsing
        std::env::set_var("RCMAN_TEST3_GENERAL_DARK_MODE", "true");

        let metadata = manager.metadata().unwrap();
        let dark_mode = metadata.get("general.dark_mode").unwrap();

        // Should parse "true" as boolean true
        assert_eq!(dark_mode.value, Some(json!(true)));

        std::env::remove_var("RCMAN_TEST3_GENERAL_DARK_MODE");
    }
}
