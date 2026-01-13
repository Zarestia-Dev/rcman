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
#[cfg(any(feature = "keychain", feature = "encrypted-file"))]
use crate::credentials::CredentialManager;
use crate::error::{Error, Result};
use crate::events::EventManager;
use crate::storage::StorageBackend;
use crate::sub_settings::{SubSettings, SubSettingsConfig};
use std::marker::PhantomData;

use crate::sync::RwLockExt;
#[cfg(feature = "profiles")]
use log::warn;
use log::{debug, info};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

pub mod cache;
pub mod env;

use self::cache::{CachedSettings, SettingsCache};
use self::env::EnvironmentHandler;

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
/// manager.save_setting("ui", "theme", &json!("light")).unwrap();
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
pub struct SettingsManager<
    S: StorageBackend = crate::storage::JsonStorage,
    Schema: SettingsSchema = (),
> {
    /// Configuration
    config: SettingsConfig<S, Schema>,

    /// Storage backend (defaults to `JsonStorage`)
    storage: S,

    /// Directory where settings file is located (may change if profiles enabled)
    settings_dir: RwLock<std::path::PathBuf>,

    /// Registered sub-settings handlers
    sub_settings: RwLock<HashMap<String, Arc<SubSettings<S>>>>,

    /// Event manager for change callbacks and validation
    events: Arc<EventManager>,

    /// Unified settings cache
    settings_cache: SettingsCache,

    /// Environment variable handler
    env_handler: EnvironmentHandler,

    /// Pre-computed schema defaults (shared across cache operations)
    schema_defaults: Arc<HashMap<String, Value>>,

    /// Credential manager for secret settings (optional, requires keychain or encrypted-file feature)
    #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
    credentials: Option<CredentialManager>,

    /// External config providers for backups
    #[cfg(feature = "backup")]
    pub(crate) external_providers: RwLock<Vec<Box<dyn ExternalConfigProvider>>>,

    /// Profile manager for main settings (when profiles are enabled)
    #[cfg(feature = "profiles")]
    profile_manager: Option<crate::profiles::ProfileManager<S>>,

    /// Marker for schema type
    _schema: PhantomData<Schema>,
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
            crate::security::ensure_secure_dir(&config.config_dir)?;
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
        let (settings_dir, profile_manager) = crate::profiles::ProfileManager::initialize(
            &config.config_dir,
            "settings",
            storage.clone(),
            config.profiles_enabled,
            &config.profile_migrator,
        )?;

        #[cfg(not(feature = "profiles"))]
        let settings_dir = config.config_dir.clone();

        // Pre-compute schema defaults ONCE (memory optimization)
        let metadata = Schema::get_metadata();
        let schema_defaults = Arc::new(
            metadata
                .iter()
                .map(|(k, m)| (k.clone(), m.default.clone()))
                .collect(),
        );

        let env_handler =
            EnvironmentHandler::new(config.env_prefix.clone(), config.env_source.clone());

        info!(
            "Initialized rcman SettingsManager at: {:?}",
            config.config_dir.display()
        );

        Ok(Self {
            config,
            storage,
            settings_dir: RwLock::new(settings_dir),
            sub_settings: RwLock::new(HashMap::new()),
            events: Arc::new(EventManager::new()),
            settings_cache: SettingsCache::new(),
            env_handler,
            schema_defaults,
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

    /// Get the storage backend
    pub fn storage(&self) -> &S {
        &self.storage
    }

    /// Get the current settings file path
    ///
    /// This returns the path where settings.json is stored.
    /// If profiles are enabled, this points to the active profile's directory.
    fn settings_path(&self) -> std::path::PathBuf {
        let dir = self.settings_dir.read().expect("Lock poisoned");
        dir.join(&self.config.settings_file)
    }

    /// Get the profile manager for main settings
    ///
    /// Returns None if profiles are not enabled for main settings.
    #[cfg(feature = "profiles")]
    pub fn profiles(&self) -> Option<&crate::profiles::ProfileManager<S>> {
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
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the profile to switch to
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Profiles are not enabled for this manager
    /// - The profile does not exist
    /// - The profile switch fails (e.g. IO error)
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
            let mut settings_dir = self.settings_dir.write_recovered()?;
            *settings_dir = new_path;
        } // Lock released immediately

        // Step 4: Invalidate cache (after lock is released)
        self.invalidate_cache();

        // Step 5: Propagate to sub-settings
        // Clone the Arc references to avoid holding the lock during profile switches
        let sub_settings_list: Vec<_> = {
            let sub_settings = self.sub_settings.read_recovered()?;
            sub_settings
                .iter()
                .map(|(key, sub)| (key.clone(), Arc::clone(sub)))
                .collect()
        }; // Lock released immediately

        // Now switch each sub-settings without holding the main lock
        for (key, sub) in sub_settings_list {
            match sub.switch_profile(name) {
                Ok(()) => {
                    debug!("Switched sub-settings '{key}' to profile '{name}'");
                }
                Err(Error::ProfilesNotEnabled) => {
                    // Ignore sub-settings that don't support profiles
                    // They will continue to operate in their default mode
                }
                Err(e) => warn!("Failed to switch sub-settings '{key}' to profile '{name}': {e}"),
            }
        }

        Ok(())
    }

    /// Create a new profile for main settings
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the profile to create
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Profiles are not enabled
    /// - The profile already exists
    /// - Creation fails (e.g. IO error)
    #[cfg(feature = "profiles")]
    pub fn create_profile(&self, name: &str) -> Result<()> {
        let pm = self
            .profile_manager
            .as_ref()
            .ok_or(Error::ProfilesNotEnabled)?;
        pm.create(name)?;

        // Propagate to sub-settings
        let sub_settings = self.sub_settings.read_recovered()?;
        for (key, sub) in sub_settings.iter() {
            if let Ok(pm) = sub.profiles() {
                match pm.create(name) {
                    Ok(()) => debug!("Created profile '{name}' in sub-settings '{key}'"),
                    Err(e) => {
                        warn!("Failed to create profile '{name}' in sub-settings '{key}': {e}");
                    }
                }
            }
        }
        Ok(())
    }

    /// List all available profiles
    /// # Errors
    ///
    /// Returns an error if profiles are not enabled or reading the profile list fails.
    #[cfg(feature = "profiles")]
    pub fn list_profiles(&self) -> Result<Vec<String>> {
        let pm = self
            .profile_manager
            .as_ref()
            .ok_or(Error::ProfilesNotEnabled)?;
        pm.list()
    }

    /// Get the active profile name
    /// # Errors
    ///
    /// Returns an error if profiles are not enabled or determining the active profile fails.
    #[cfg(feature = "profiles")]
    pub fn active_profile(&self) -> Result<String> {
        let pm = self
            .profile_manager
            .as_ref()
            .ok_or(Error::ProfilesNotEnabled)?;
        pm.active()
    }

    /// Check if a setting value is overridden by an environment variable
    ///
    /// Returns the parsed value if env var is set and successfully parsed.
    fn get_env_override(&self, key: &str) -> Option<Value> {
        self.env_handler.get_env_override(key)
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

        let sub_settings = self.sub_settings.read().expect("Lock poisoned");
        for sub in sub_settings.values() {
            sub.invalidate_cache();
        }

        debug!("Settings cache invalidated");
    }

    // =========================================================================
    // Fast Value Access Methods
    // =========================================================================

    /// Get a single setting value by key path.
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
        Schema: SettingsSchema,
    {
        let value = self.get_value(key)?;
        serde_json::from_value(value).map_err(|e| Error::Parse(e.to_string()))
    }

    /// Get raw JSON value for a setting key.
    ///
    /// Returns the value from merged settings cache.
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
            .get_or_compute_merged(|stored| Self::merge_with_defaults::<Schema>(stored))?;

        // Deserialize to concrete type
        serde_json::from_value(merged).map_err(|e| Error::Parse(e.to_string()))
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

    /// Load settings from disk, applying migrations if needed
    fn load_from_disk(&self) -> Result<CachedSettings> {
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
                if option.flags.system.secret {
                    // Check env var override for secrets if enabled
                    if self.config.env_overrides_secrets {
                        if let Some(env_value) = self.get_env_override(key) {
                            option.value = Some(env_value);
                            option.flags.system.env_override = true;
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
                    option.flags.system.env_override = true; // Mark as env-overridden for UI
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
    /// # fn main() {
    /// # let temp = tempfile::tempdir().unwrap();
    /// # let config = SettingsConfig::builder("test", "1.0").with_config_dir(temp.path()).with_schema::<MySettings>().build();
    /// # let manager = SettingsManager::new(config).unwrap();
    /// # manager.save_setting("ui", "theme", &serde_json::json!("d")).unwrap();
    /// # }
    /// ```
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
            .is_some_and(|m| m.flags.system.secret)
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
    /// manager.register_sub_settings(SubSettingsConfig::new("remotes")).unwrap();
    /// manager.register_sub_settings(SubSettingsConfig::new("profiles")).unwrap();
    /// ```
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
            .read()
            .expect("Lock poisoned")
            .contains_key(name)
    }

    /// List all registered sub-settings types
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    pub fn sub_settings_types(&self) -> Vec<String> {
        self.sub_settings
            .read()
            .expect("Lock poisoned")
            .keys()
            .cloned()
            .collect()
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

    /// Register an external config provider for backups.
    ///
    /// This allows dynamic registration of external files to be included in backups.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    #[cfg(feature = "backup")]
    pub fn register_external_provider(&self, provider: Box<dyn ExternalConfigProvider>) {
        let mut providers = self.external_providers.write().expect("Lock poisoned");
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
    use crate::config::{
        DefaultEnvSource, EnvSource, SettingMetadata, SettingType, SettingsSchema,
    };
    use crate::storage::JsonStorage;
    use serde::{Deserialize, Serialize};
    use std::sync::{Arc, Mutex};
    use tempfile::tempdir;

    struct MockEnvSource {
        vars: Mutex<HashMap<String, String>>,
    }

    impl MockEnvSource {
        fn new() -> Self {
            Self {
                vars: Mutex::new(HashMap::new()),
            }
        }

        fn set(&self, key: &str, value: &str) {
            self.vars
                .lock()
                .unwrap()
                .insert(key.to_string(), value.to_string());
        }
    }

    impl EnvSource for MockEnvSource {
        fn var(&self, key: &str) -> std::result::Result<String, std::env::VarError> {
            self.vars
                .lock()
                .unwrap()
                .get(key)
                .cloned()
                .ok_or(std::env::VarError::NotPresent)
        }
    }

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
            env_source: Arc::new(DefaultEnvSource),
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
            env_source: Arc::new(DefaultEnvSource),
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
            env_source: Arc::new(DefaultEnvSource),
        };

        let manager = SettingsManager::new(config).unwrap();

        // Save a setting
        manager
            .save_setting("general", "language", &json!("de"))
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
            env_source: Arc::new(DefaultEnvSource),
        };

        let manager = SettingsManager::new(config).unwrap();

        // Save a non-default value
        manager
            .save_setting("general", "dark_mode", &json!(true))
            .unwrap();

        // Reset it
        let default = manager.reset_setting("general", "dark_mode").unwrap();

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
            env_source: Arc::new(DefaultEnvSource),
        };

        let manager = SettingsManager::new(config).unwrap();

        // Register sub-settings
        manager
            .register_sub_settings(SubSettingsConfig::new("remotes"))
            .unwrap();

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
        let env_source = Arc::new(MockEnvSource::new());
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
            env_source: env_source.clone(),
        };

        let manager = SettingsManager::new(config).unwrap();

        // Set an environment variable for testing through mock
        env_source.set("RCMAN_TEST_GENERAL_LANGUAGE", "fr");

        // Load settings - should get value from env var
        let metadata = manager.metadata().unwrap();
        let lang = metadata.get("general.language").unwrap();

        // Value should be from env var, not default
        assert_eq!(lang.value, Some(json!("fr")));
        // Should be marked as env override
        assert!(
            lang.flags.system.env_override,
            "Setting should be marked as env-overridden"
        );
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

        let env_source = Arc::new(MockEnvSource::new());

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
            env_source: env_source.clone(),
        };

        let manager = SettingsManager::new(config).unwrap();

        // Set env var - should take priority over stored value
        env_source.set("RCMAN_TEST2_GENERAL_LANGUAGE", "es");

        let metadata = manager.metadata().unwrap();
        let lang = metadata.get("general.language").unwrap();

        // Env var should win over stored value
        assert_eq!(lang.value, Some(json!("es")));
        assert!(lang.flags.system.env_override);
    }

    #[test]
    fn test_env_var_type_parsing() {
        let dir = tempdir().unwrap();
        let env_source = Arc::new(MockEnvSource::new());

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
            env_source: env_source.clone(),
        };

        let manager = SettingsManager::new(config).unwrap();

        // Test boolean parsing
        env_source.set("RCMAN_TEST3_GENERAL_DARK_MODE", "true");

        let metadata = manager.metadata().unwrap();
        let dark_mode = metadata.get("general.dark_mode").unwrap();

        // Should parse "true" as boolean true
        assert_eq!(dark_mode.value, Some(json!(true)));
    }
}
