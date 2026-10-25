#[cfg(feature = "backup")]
use crate::backup::ExternalConfigProvider;
#[cfg(any(feature = "keychain", feature = "encrypted-file"))]
use crate::config::CredentialConfig;
use crate::config::{SettingMetadata, SettingsConfig, SettingsSchema};
#[cfg(any(feature = "keychain", feature = "encrypted-file"))]
use crate::credentials::CredentialManager;
use crate::error::Result;
use crate::manager::EventManager;
use crate::manager::cache::SettingsCache;
use crate::manager::env::EnvironmentHandler;
use crate::storage::StorageBackend;
use crate::sub_settings::SubSettings;

use indexmap::IndexMap;
use serde_json::Value;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::{Arc, RwLock};

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
/// # Type Parameters
///
/// * `Schema`: The settings schema type (defaults to `()` for dynamic usage).
pub struct SettingsManager<
    S: StorageBackend = crate::storage::JsonStorage,
    Schema: SettingsSchema = (),
> {
    /// Configuration
    pub(super) config: SettingsConfig<S, Schema>,

    /// Storage backend (defaults to `JsonStorage`)
    pub(super) storage: S,

    /// Registered sub-settings handlers
    pub(super) sub_settings: RwLock<HashMap<String, Arc<SubSettings<S>>>>,

    /// Event manager for change callbacks and validation
    pub(super) events: Arc<EventManager>,

    /// Unified settings cache
    pub(super) settings_cache: Arc<SettingsCache>,

    /// Isolates managed reads from in-progress settings and credential commits.
    pub(super) settings_write_lock: Arc<RwLock<()>>,

    /// Environment variable handler
    pub(super) env_handler: EnvironmentHandler,

    /// Pre-computed schema defaults (shared across cache operations)
    pub(super) schema_defaults: Arc<HashMap<String, Value>>,

    /// Cached schema metadata (shared across read paths)
    pub(super) schema_metadata: Arc<IndexMap<String, SettingMetadata>>,

    /// Credential manager for secret settings (optional, requires keychain or encrypted-file feature)
    #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
    pub(super) credentials: Option<CredentialManager>,

    /// Flag indicating if the credential store was upgraded (missing `__rcman_secrets__`)
    #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
    pub(super) is_upgraded: Arc<std::sync::atomic::AtomicBool>,

    /// External config providers for backups
    #[cfg(feature = "backup")]
    pub(crate) external_providers: RwLock<Vec<Arc<dyn ExternalConfigProvider>>>,

    /// Profile manager for main settings (when profiles are enabled)
    #[cfg(feature = "profiles")]
    pub(super) profile_manager: Option<crate::profiles::ProfileManager<S>>,

    /// Configuration vault state (when vault feature is enabled)
    #[cfg(feature = "vault")]
    pub(crate) vault: crate::vault::SharedVault,

    /// Marker for schema type
    pub(super) _schema: PhantomData<Schema>,
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
        Self::new_with_sub_settings(config, Vec::new())
    }

    pub(super) fn new_with_sub_settings(
        config: SettingsConfig<S, Schema>,
        sub_settings: Vec<crate::sub_settings::SubSettingsConfig>,
    ) -> Result<Self> {
        #[cfg(feature = "vault")]
        let mut config = config;
        #[cfg(feature = "vault")]
        let password = config
            .vault_password
            .take()
            .map(crate::credentials::SecretPasswordSource::resolve_vault)
            .transpose()?;
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter(&config.config_dir)?;
        // Ensure config directory exists with secure permissions
        if !config.config_dir.exists() {
            crate::utils::security::ensure_secure_dir(&config.config_dir)?;
        }

        let storage = config.storage.clone();

        #[cfg(feature = "vault")]
        let initial_vault =
            Self::initialize_vault(&config, password.as_deref().map(String::as_str))?;
        #[cfg(feature = "vault")]
        let _startup_pin = initial_vault
            .as_ref()
            .filter(|_| password.is_some())
            .map(|vault| vault.begin_migration())
            .transpose()?;
        #[cfg(feature = "vault")]
        let vault = Arc::new(RwLock::new(initial_vault.clone()));
        #[cfg(all(feature = "vault", feature = "profiles"))]
        Self::check_profile_initialization(&config, &storage, &vault)?;

        #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
        let credentials = Self::initialize_credentials(&config)?;

        let settings_write_lock = Arc::new(RwLock::new(()));
        let settings_cache = Arc::new(SettingsCache::new());
        // Initialize profile manager if profiles are enabled
        #[cfg(feature = "profiles")]
        let (_, profile_manager) = crate::profiles::ProfileManager::initialize_file(
            &config.config_dir,
            "settings",
            &config.settings_file,
            storage.clone(),
            config.profiles_enabled,
            &config.profile_migrator,
        )?;
        // Compute schema metadata once for cache defaults and credential ownership.
        let metadata = Arc::new(Schema::get_metadata());
        #[cfg(feature = "profiles")]
        let profile_manager = profile_manager.map(|profiles| {
            let profiles = profiles.with_owner(
                Arc::clone(&settings_write_lock),
                settings_cache.invalidator(),
            );
            #[cfg(feature = "vault")]
            let profiles = profiles.with_vault(Arc::clone(&vault));
            #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
            let profiles = profiles.with_credentials(
                credentials.clone(),
                crate::credentials::ProfileSecretScope::Keys(metadata.keys().cloned().collect()),
            );
            profiles
        });
        let schema_defaults = Arc::new(
            metadata
                .iter()
                .map(|(k, m)| (k.clone(), m.default.clone()))
                .collect(),
        );

        let manager = Self {
            env_handler: EnvironmentHandler::new(
                config.env_prefix.clone(),
                config.env_source.clone(),
            ),
            config,
            storage,
            sub_settings: RwLock::new(HashMap::new()),
            events: Arc::new(EventManager::new()),
            settings_cache,
            settings_write_lock,
            schema_defaults,
            schema_metadata: metadata,
            #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
            credentials,

            #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
            is_upgraded: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            #[cfg(feature = "backup")]
            external_providers: RwLock::new(Vec::new()),
            #[cfg(feature = "profiles")]
            profile_manager,
            #[cfg(feature = "vault")]
            vault,
            _schema: PhantomData,
        };

        for config in sub_settings {
            manager.register_sub_settings_inner(config, !cfg!(feature = "vault"))?;
        }
        #[cfg(feature = "vault")]
        manager.finish_vault_initialization(password.as_ref().map(|p| p.as_str()))?;
        #[cfg(all(
            any(feature = "keychain", feature = "encrypted-file"),
            not(feature = "vault")
        ))]
        manager.migrate_secret_keys()?;

        Ok(manager)
    }
    #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
    fn initialize_credentials(
        config: &SettingsConfig<S, Schema>,
    ) -> Result<Option<CredentialManager>> {
        match &config.credential_config {
            CredentialConfig::Disabled => Ok(None),
            CredentialConfig::Default => {
                log::debug!("Credential management enabled with default backend");
                Ok(Some(CredentialManager::new(&config.app_name)))
            }
            #[cfg(all(feature = "keychain", feature = "encrypted-file"))]
            CredentialConfig::WithFallback {
                fallback_path,
                password,
            } => {
                log::debug!(
                    "Credential management enabled with keychain and encrypted file fallback"
                );
                let resolved;
                let mut password = password;
                if let crate::credentials::SecretPasswordSource::Environment(var) = password {
                    match config.env_source.var(var) {
                        Ok(value) if !value.is_empty() => {
                            resolved = crate::credentials::SecretPasswordSource::Provided(value);
                            password = &resolved;
                        }
                        _ => {
                            log::warn!(
                                "Environment variable '{var}' is not set; encrypted file fallback is disabled. \
                                 Secrets use the keychain, or volatile memory if it is unavailable."
                            );
                            return Ok(Some(CredentialManager::new(&config.app_name)));
                        }
                    }
                }
                let path = fallback_path
                    .clone()
                    .unwrap_or_else(|| config.config_dir.join("secrets.enc"));
                Ok(Some(CredentialManager::with_fallback(
                    &config.app_name,
                    path,
                    password,
                )?))
            }
            CredentialConfig::Custom(backend) => {
                log::debug!("Credential management enabled with custom backend");
                Ok(Some(CredentialManager::with_backend(
                    &config.app_name,
                    backend.clone(),
                )))
            }
        }
    }

    /// Get the configuration
    pub fn config(&self) -> &SettingsConfig<S, Schema> {
        &self.config
    }

    /// Get the storage backend
    pub fn storage(&self) -> &S {
        &self.storage
    }

    /// Get the event manager for registering change listeners and validators
    ///
    /// Callback semantics:
    /// - `save_setting()` emits callbacks only when the effective value changes.
    /// - `reset_setting()` delegates to `save_setting()`, so unchanged resets emit nothing.
    /// - `reset_all()` emits one callback per changed key (no callbacks for already-default values).
    /// - With profiles enabled, `switch_profile()` emits callbacks for keys whose effective
    ///   values differ between the old and new profiles.
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
    /// manager.events().watch("ui.theme", |key, _old, new| {
    ///     println!("Theme changed to: {:?}", new);
    /// });
    ///
    /// // Add validator
    /// manager.events().add_validator("network.port", |v: &Value| {
    ///     if v.as_i64().map(|n| n > 0 && n <= 65535).unwrap_or(false) {
    ///         Ok(())
    ///     } else {
    ///         Err("Invalid port".into())
    ///     }
    /// });
    /// ```
    pub fn events(&self) -> &EventManager {
        &self.events
    }

    /// Get reference to credential manager (if configured)
    #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
    pub fn credentials(&self) -> Option<&crate::credentials::CredentialManager> {
        self.credentials.as_ref()
    }

    /// Get reference to the schema metadata map
    #[cfg(feature = "backup")]
    pub(crate) fn schema_metadata(&self) -> &IndexMap<String, SettingMetadata> {
        &self.schema_metadata
    }
}

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
    ) -> crate::manager::SettingsManagerBuilder {
        crate::manager::SettingsManagerBuilder::<crate::storage::JsonStorage, ()>::new(
            app_name,
            app_version,
        )
    }
}
