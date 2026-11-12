//! Core types for rcman library

use std::marker::PhantomData;
use std::path::PathBuf;

use crate::config::SettingsSchema;
use crate::storage::{JsonStorage, StorageBackend};

#[cfg(feature = "backup")]
use crate::backup::ExternalConfig;
use crate::credentials::CredentialBackend;
use std::sync::Arc;

/// Configuration for how credentials should be stored.
#[derive(Clone)]
pub enum CredentialConfig {
    /// Credentials are disabled (default behavior when not configured)
    Disabled,
    /// Use the default backend (Keychain if enabled, otherwise Memory)
    Default,
    /// Use Keychain with an `EncryptedFile` fallback (requires password source for encryption)
    /// This is useful for environments where the OS keychain might be unavailable (e.g., CI/Docker).
    #[cfg(all(feature = "keychain", feature = "encrypted-file"))]
    WithFallback {
        /// Path to the encrypted JSON file (None = use default in `config_dir`)
        fallback_path: Option<std::path::PathBuf>,
        /// Source for the master password to unlock the file
        password: crate::credentials::SecretPasswordSource,
    },
    /// Provide a custom backend implementation
    Custom(Arc<dyn CredentialBackend>),
}

// Custom Debug impl since CredentialBackend and keys might not be Debug
impl std::fmt::Debug for CredentialConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disabled => write!(f, "Disabled"),
            Self::Default => write!(f, "Default"),
            #[cfg(all(feature = "keychain", feature = "encrypted-file"))]
            Self::WithFallback {
                fallback_path,
                password,
            } => f
                .debug_struct("WithFallback")
                .field("fallback_path", fallback_path)
                .field("password", password)
                .finish(),
            Self::Custom(_) => f
                .debug_tuple("Custom")
                .field(&"<dyn CredentialBackend>")
                .finish(),
        }
    }
}

/// Trait for retrieving environment variables
///
/// This allows mocking environment variables in tests without
/// using unsafe `std::env::set_var`.
pub trait EnvSource: Send + Sync {
    /// Retrieve an environment variable
    ///
    /// # Errors
    ///
    /// Returns `VarError` if the variable is not present or invalid unicode.
    fn var(&self, key: &str) -> std::result::Result<String, std::env::VarError>;
}

/// Default implementation using `std::env`
#[derive(Clone, Default)]
pub struct DefaultEnvSource;

impl EnvSource for DefaultEnvSource {
    fn var(&self, key: &str) -> std::result::Result<String, std::env::VarError> {
        std::env::var(key)
    }
}

/// Backend strategy for file watching in hot-reload mode.
#[cfg(feature = "hot-reload")]
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum HotReloadBackend {
    /// Use the OS-native watcher backend when available.
    #[default]
    Auto,
    /// Force polling mode with `poll_interval_ms`.
    Poll,
}

/// Configuration for hot-reload behavior.
#[cfg(feature = "hot-reload")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HotReloadConfig {
    /// Debounce window for coalescing bursty filesystem events.
    pub debounce_ms: u64,
    /// Polling interval used when backend is `Poll`.
    pub poll_interval_ms: u64,
    /// Filesystem watching backend strategy.
    pub backend: HotReloadBackend,
}

#[cfg(feature = "hot-reload")]
impl Default for HotReloadConfig {
    fn default() -> Self {
        Self {
            debounce_ms: 200,
            poll_interval_ms: 1000,
            backend: HotReloadBackend::Auto,
        }
    }
}

/// Configuration for initializing the `SettingsManager`
pub struct SettingsConfig<S: StorageBackend = JsonStorage, Schema: SettingsSchema = ()> {
    /// Directory where settings files will be stored
    pub config_dir: PathBuf,

    /// Filename for the main settings file (e.g., "settings.json")
    pub settings_file: String,

    /// Application name (used in backup manifests)
    pub app_name: String,

    /// Application version (used for backup compatibility checks)
    pub app_version: String,

    /// Storage backend (defaults to `JsonStorage`)
    pub(crate) storage: S,

    /// Configuration for how credential secrets should be stored
    pub credential_config: CredentialConfig,

    /// Environment variable prefix for setting overrides (e.g., "MYAPP" -> `MYAPP_UI_THEME`)
    /// If None, env var overrides are disabled
    pub env_prefix: Option<String>,

    /// Allow environment variables to override secret settings (stored in keychain)
    /// Default: false (secrets are never overridden by env vars)
    pub env_overrides_secrets: bool,

    /// External configuration files registered for backup
    #[cfg(feature = "backup")]
    pub external_configs: Vec<ExternalConfig>,

    /// Optional migration function for schema changes (lazy migration)
    /// The migrator function is called automatically when loading settings.
    /// If the function modifies the value, the migrated version is saved back.
    pub migrator:
        Option<std::sync::Arc<dyn Fn(serde_json::Value) -> serde_json::Value + Send + Sync>>,

    /// Enable profiles for main settings (stores settings per-profile)
    #[cfg(feature = "profiles")]
    pub profiles_enabled: bool,

    /// Profile migration strategy (defaults to Auto)
    #[cfg(feature = "profiles")]
    pub profile_migrator: crate::profiles::ProfileMigrator,

    /// Marker for schema type (internal use)
    #[doc(hidden)]
    pub _schema: PhantomData<Schema>,

    /// Source for environment variables (defaults to `std::env`)
    pub env_source: std::sync::Arc<dyn EnvSource>,

    /// Hot-reload configuration (when enabled).
    #[cfg(feature = "hot-reload")]
    pub hot_reload: Option<HotReloadConfig>,

    /// Request vault startup checks for registered stores, including missing metadata.
    /// Existing vault metadata is always detected; a password opts into encryption.
    #[cfg(feature = "vault")]
    pub vault_requested: bool,

    /// Startup password source, resolved once during manager construction. Consumed by
    /// `SettingsManager::new`; the manager's configuration retains `None`.
    #[cfg(feature = "vault")]
    pub vault_password: Option<crate::credentials::SecretPasswordSource>,

    /// Auto-lock timeout after inactivity
    #[cfg(feature = "vault")]
    pub vault_lock_timeout: Option<std::time::Duration>,

    /// Custom Argon2 KDF parameters (when vault is enabled)
    #[cfg(feature = "vault")]
    pub vault_kdf_params: Option<crate::vault::Argon2Params>,
}

impl Default for SettingsConfig {
    fn default() -> Self {
        let storage = JsonStorage::new();
        let settings_file = format!("settings.{}", storage.extension());
        Self {
            config_dir: PathBuf::from("."),
            settings_file,
            app_name: "app".into(),
            app_version: "0.1.0".into(),
            storage,
            credential_config: CredentialConfig::Disabled,
            env_prefix: None,
            env_overrides_secrets: false,
            #[cfg(feature = "backup")]
            external_configs: Vec::new(),
            migrator: None,
            #[cfg(feature = "profiles")]
            profiles_enabled: false,
            #[cfg(feature = "profiles")]
            profile_migrator: crate::profiles::ProfileMigrator::default(),
            _schema: PhantomData,
            env_source: std::sync::Arc::new(DefaultEnvSource),
            #[cfg(feature = "hot-reload")]
            hot_reload: None,
            #[cfg(feature = "vault")]
            vault_requested: false,
            #[cfg(feature = "vault")]
            vault_password: None,
            #[cfg(feature = "vault")]
            vault_lock_timeout: None,
            #[cfg(feature = "vault")]
            vault_kdf_params: None,
        }
    }
}

impl<S: StorageBackend, Schema: SettingsSchema> SettingsConfig<S, Schema> {
    /// The main settings file in `config_dir`.
    ///
    /// With profiles enabled each profile has its own file; use
    /// [`SettingsManager::settings_path`](crate::SettingsManager::settings_path)
    /// for the file the manager currently reads and writes.
    pub fn settings_path(&self) -> PathBuf {
        self.config_dir.join(&self.settings_file)
    }

    /// Get a reference to the storage backend
    pub fn storage(&self) -> &S {
        &self.storage
    }
}

impl SettingsConfig {
    /// Create a new builder for `SettingsConfig`
    ///
    /// # Example
    /// ```rust
    /// use rcman::SettingsConfig;
    ///
    /// let config = SettingsConfig::builder("my-app", "1.0.0")
    ///     .with_config_dir("~/.config/my-app")
    ///     .build();
    /// ```
    pub fn builder(
        app_name: impl Into<String>,
        app_version: impl Into<String>,
    ) -> SettingsConfigBuilder {
        SettingsConfigBuilder::new(app_name, app_version)
    }
}

#[cfg(feature = "vault")]
#[derive(Clone, Default)]
struct VaultConfig {
    requested: bool,
    password: Option<crate::credentials::SecretPasswordSource>,
    lock_timeout: Option<std::time::Duration>,
    kdf_params: Option<crate::vault::Argon2Params>,
}

/// Builder for creating `SettingsConfig` with a fluent API.
///
/// This is the recommended way to create a settings manager.
///
/// # Type Parameters
///
/// - `Schema`: Settings schema type (defaults to `()` for dynamic usage)
///
/// # Examples
///
/// **Type-Safe (With Schema):**
/// ```no_run
/// use rcman::{IndexMap, SettingMetadata, SettingsConfig, SettingsSchema, settings};
/// use serde::{Serialize, Deserialize};
///
/// #[derive(Default, Serialize, Deserialize)]
/// struct MySettings { theme: String }
///
/// impl SettingsSchema for MySettings {
///     fn get_metadata() -> IndexMap<String, SettingMetadata> {
///         settings! { "ui.theme" => SettingMetadata::text("dark").meta_str("label", "Theme") }
///     }
/// }
///
/// let config = SettingsConfig::builder("my-app", "1.0.0")
///     .with_schema::<MySettings>()
///     .with_config_dir("~/.config/my-app")
///     .build();
/// ```
///
/// **Dynamic (Without Schema):**
/// ```no_run
/// use rcman::SettingsConfig;
///
/// let config = SettingsConfig::builder("my-app", "1.0.0")
///     .with_config_dir("~/.config/my-app")
///     .build();
/// ```
#[derive(Clone)]
pub struct SettingsConfigBuilder<S: StorageBackend = JsonStorage, Schema: SettingsSchema = ()> {
    options: BuilderOptions,
    storage: S,
    _schema: PhantomData<Schema>,
}

/// Builder settings that do not depend on the storage or schema type, so
/// [`SettingsConfigBuilder::with_schema`] and `with_storage_instance` move them as one value.
#[derive(Clone)]
struct BuilderOptions {
    config_dir: Option<PathBuf>,
    settings_file: Option<String>,
    app_name: String,
    app_version: String,
    env_prefix: Option<String>,
    #[cfg(feature = "backup")]
    external_configs: Vec<ExternalConfig>,
    migrator: Option<std::sync::Arc<dyn Fn(serde_json::Value) -> serde_json::Value + Send + Sync>>,
    #[cfg(feature = "profiles")]
    profile_migrator: Option<crate::profiles::ProfileMigrator>,
    env_source: Option<std::sync::Arc<dyn EnvSource>>,
    #[cfg(feature = "profiles")]
    profiles_enabled: bool,
    #[cfg(feature = "hot-reload")]
    hot_reload: Option<HotReloadConfig>,
    #[cfg(feature = "vault")]
    vault: VaultConfig,
    credential_config: CredentialConfig,
    env_overrides_secrets: bool,
    resolve_env_credentials: bool,
}

impl<S: StorageBackend, Schema: SettingsSchema> std::fmt::Debug
    for SettingsConfigBuilder<S, Schema>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = f.debug_struct("SettingsConfigBuilder");
        debug
            .field("config_dir", &self.options.config_dir)
            .field("settings_file", &self.options.settings_file)
            .field("app_name", &self.options.app_name)
            .field("app_version", &self.options.app_version)
            .field("credential_config", &self.options.credential_config)
            .field("env_prefix", &self.options.env_prefix)
            .field("env_overrides_secrets", &self.options.env_overrides_secrets)
            .field(
                "resolve_env_credentials",
                &self.options.resolve_env_credentials,
            );

        #[cfg(feature = "backup")]
        debug.field("external_configs", &self.options.external_configs);

        #[cfg(feature = "profiles")]
        debug.field("profiles_enabled", &self.options.profiles_enabled);
        #[cfg(feature = "profiles")]
        debug.field("profile_migrator", &self.options.profile_migrator);

        #[cfg(feature = "vault")]
        debug.field("vault_kdf_params", &self.options.vault.kdf_params);

        debug.field(
            "migrator",
            &self.options.migrator.as_ref().map(|_| "Some(Fn)"),
        );
        debug.finish_non_exhaustive()
    }
}

impl SettingsConfigBuilder {
    /// Create a new builder with required app name and version
    pub fn new(app_name: impl Into<String>, app_version: impl Into<String>) -> Self {
        Self {
            options: BuilderOptions {
                config_dir: None,
                settings_file: None,
                app_name: app_name.into(),
                app_version: app_version.into(),
                env_prefix: None,
                #[cfg(feature = "backup")]
                external_configs: Vec::new(),
                migrator: None,
                #[cfg(feature = "profiles")]
                profile_migrator: None,
                env_source: None,
                #[cfg(feature = "profiles")]
                profiles_enabled: false,
                #[cfg(feature = "hot-reload")]
                hot_reload: None,
                #[cfg(feature = "vault")]
                vault: VaultConfig::default(),
                credential_config: CredentialConfig::Disabled,
                env_overrides_secrets: false,
                resolve_env_credentials: false,
            },
            storage: JsonStorage::new(),
            _schema: PhantomData,
        }
    }
}

impl<Schema: SettingsSchema> SettingsConfigBuilder<JsonStorage, Schema> {
    /// Use compact JSON (no pretty printing)
    ///
    /// Note: This method is only available when using `JsonStorage`.
    ///
    /// # Example
    /// ```
    /// use rcman::SettingsConfig;
    ///
    /// let config = SettingsConfig::builder("my-app", "1.0.0")
    ///     .with_pretty_json(false)
    ///     .build();
    /// ```
    #[must_use]
    pub fn with_pretty_json(mut self, pretty: bool) -> Self {
        self.storage.set_pretty(pretty);
        self
    }
}

impl<S: StorageBackend, Schema: SettingsSchema> SettingsConfigBuilder<S, Schema> {
    /// Set the configuration directory
    ///
    /// Supports `~` expansion for home directory.
    #[must_use]
    pub fn with_config_dir(mut self, path: impl Into<PathBuf>) -> Self {
        let path: PathBuf = path.into();
        // Expand ~ to home directory
        let expanded = if path.starts_with("~") {
            if let Some(home) = dirs::home_dir() {
                home.join(path.strip_prefix("~").unwrap_or(&path))
            } else {
                path
            }
        } else {
            path
        };
        self.options.config_dir = Some(expanded);
        self
    }

    /// Set the settings filename (default: "settings.{ext}")
    #[must_use]
    pub fn with_settings_file(mut self, filename: impl Into<String>) -> Self {
        self.options.settings_file = Some(filename.into());
        self
    }

    /// Enable credential management for secret settings with default behavior.
    ///
    /// When enabled, settings marked as `secret: true` in metadata
    /// will be stored in the primary OS keychain instead of the settings file.
    #[must_use]
    pub fn with_credentials(mut self) -> Self {
        self.options.credential_config = CredentialConfig::Default;
        self
    }

    /// Choose how secret settings are stored: a custom [`CredentialBackend`],
    /// or the keychain with an encrypted-file fallback.
    ///
    /// # Example
    /// ```rust
    /// # #[cfg(all(feature = "keychain", feature = "encrypted-file"))]
    /// # {
    /// use rcman::{CredentialConfig, SecretPasswordSource, SettingsConfig};
    ///
    /// let config = SettingsConfig::builder("my-app", "1.0.0")
    ///     .with_credential_config(CredentialConfig::WithFallback {
    ///         fallback_path: Some("/tmp/secrets.enc".into()),
    ///         password: SecretPasswordSource::Environment("APP_KEY".into()),
    ///     })
    ///     .build();
    /// # }
    /// ```
    #[must_use]
    pub fn with_credential_config(mut self, config: CredentialConfig) -> Self {
        self.options.credential_config = config;
        self
    }

    /// Enable credential management with an encrypted file fallback triggered by a password source.
    ///
    /// This is the recommended way to support CI/Docker environments securely.
    #[cfg(all(feature = "keychain", feature = "encrypted-file"))]
    #[must_use]
    pub fn with_encrypted_fallback(
        mut self,
        path: impl Into<std::path::PathBuf>,
        password_source: crate::credentials::SecretPasswordSource,
    ) -> Self {
        self.options.credential_config = CredentialConfig::WithFallback {
            fallback_path: Some(path.into()),
            password: password_source,
        };
        self
    }

    /// Enable credentials with a default environment variable password source (Keychain + Encrypted File fallback).
    ///
    /// The environment variable name is automatically derived from the app name
    /// (e.g., "my-app" -> "`MY_APP_SECRET`").
    #[cfg(all(feature = "keychain", feature = "encrypted-file"))]
    #[must_use]
    pub fn with_env_credentials(mut self) -> Self {
        self.options.resolve_env_credentials = true;
        self
    }

    /// Enable credentials with a custom environment variable password source (Keychain + Encrypted File fallback).
    ///
    /// The fallback file will be stored at the default path in the config directory.
    #[cfg(all(feature = "keychain", feature = "encrypted-file"))]
    #[must_use]
    pub fn with_custom_env_credentials(mut self, var_name: impl Into<String>) -> Self {
        self.options.credential_config = CredentialConfig::WithFallback {
            fallback_path: None,
            password: crate::credentials::SecretPasswordSource::Environment(var_name.into()),
        };
        self
    }

    /// Enable credentials with file password source (Keychain + Encrypted File fallback).
    ///
    /// The fallback file will be stored at the default path in the config directory.
    #[cfg(all(feature = "keychain", feature = "encrypted-file"))]
    #[must_use]
    pub fn with_file_credentials(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.options.credential_config = CredentialConfig::WithFallback {
            fallback_path: None,
            password: crate::credentials::SecretPasswordSource::File(path.into()),
        };
        self
    }

    /// Enable credentials with provided password string (Keychain + Encrypted File fallback).
    ///
    /// The fallback file will be stored at the default path in the config directory.
    #[cfg(all(feature = "keychain", feature = "encrypted-file"))]
    #[must_use]
    pub fn with_password_credentials(mut self, password: impl Into<String>) -> Self {
        self.options.credential_config = CredentialConfig::WithFallback {
            fallback_path: None,
            password: crate::credentials::SecretPasswordSource::Provided(password.into()),
        };
        self
    }

    /// Enable automatic vault startup handling for registered settings.
    ///
    /// Existing metadata starts locked unless a password is supplied. Without
    /// metadata or a password, plaintext remains usable; orphaned encrypted files
    /// are rejected. Supply a password to create or unlock the shared vault.
    #[cfg(feature = "vault")]
    #[must_use]
    pub fn with_vault(mut self) -> Self {
        self.options.vault.requested = true;
        self
    }

    /// Unlock an existing vault, or encrypt registered settings on first startup.
    ///
    /// Manager construction consumes and zeroizes its password buffer, including
    /// on failure. The resulting manager's configuration holds `None`; caller-owned
    /// copies are unaffected.
    #[cfg(feature = "vault")]
    #[must_use]
    pub fn with_vault_password(mut self, password: impl Into<String>) -> Self {
        self.options.vault.requested = true;
        self.options.vault.password =
            Some(crate::credentials::SecretPasswordSource::provided(password));
        self
    }

    /// Read a vault startup password from a file, environment variable, or supplied value.
    ///
    /// Resolution happens during manager construction; missing or empty sources
    /// fail construction instead of silently using plaintext. File sources strip
    /// trailing line endings while preserving spaces in the password. Manager
    /// construction consumes and zeroizes the resolved password buffer.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # #[cfg(feature = "vault")]
    /// # fn example() -> rcman::Result<()> {
    /// let manager = rcman::SettingsManager::builder("my-app", "1.0")
    ///     .with_vault_password_source(rcman::SecretPasswordSource::file(
    ///         "/run/secrets/settings-password",
    ///     ))
    ///     .build()?;
    /// assert!(!manager.is_locked());
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "vault")]
    #[must_use]
    pub fn with_vault_password_source(
        mut self,
        source: crate::credentials::SecretPasswordSource,
    ) -> Self {
        self.options.vault.requested = true;
        self.options.vault.password = Some(source);
        self
    }

    /// Set an auto-lock inactivity timeout for the vault
    #[cfg(feature = "vault")]
    #[must_use]
    pub fn with_vault_lock_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.options.vault.requested = true;
        self.options.vault.lock_timeout = Some(timeout);
        self
    }

    /// Configure custom Argon2 KDF tuning parameters for the vault
    #[cfg(feature = "vault")]
    #[must_use]
    pub fn with_vault_kdf_params(mut self, params: crate::vault::Argon2Params) -> Self {
        self.options.vault.requested = true;
        self.options.vault.kdf_params = Some(params);
        self
    }

    /// Configure a predefined Argon2 KDF preset for the vault
    #[cfg(feature = "vault")]
    #[must_use]
    pub fn with_vault_preset(self, preset: crate::vault::Argon2Preset) -> Self {
        self.with_vault_kdf_params(preset.params())
    }

    /// Register an external configuration file for backup
    ///
    /// External configs are files managed outside of rcman (like rclone.conf)
    /// that can be included in backups.
    ///
    /// # Example
    /// ```rust
    /// use rcman::SettingsConfig;
    /// use rcman::backup::ExternalConfig;
    ///
    /// let config = SettingsConfig::builder("my-app", "1.0.0")
    ///     .with_external_config(ExternalConfig::new("rclone", "/path/to/rclone.conf")
    ///         .display_name("Rclone Configuration"))
    ///     .build();
    /// ```
    #[cfg(feature = "backup")]
    #[must_use]
    pub fn with_external_config(mut self, config: ExternalConfig) -> Self {
        self.options.external_configs.push(config);
        self
    }

    /// Enable environment variable overrides
    ///
    /// When set, settings can be overridden by environment variables.
    /// The format is: `{PREFIX}_{CATEGORY}_{KEY}` (all uppercase, dots become underscores)
    ///
    /// # Example
    /// ```rust
    /// use rcman::SettingsConfig;
    ///
    /// let config = SettingsConfig::builder("my-app", "1.0.0")
    ///     .with_env_prefix("MYAPP")
    ///     .build();
    ///
    /// // Now MYAPP_UI_THEME=dark will override the "ui.theme" setting
    /// ```
    #[must_use]
    pub fn with_env_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.options.env_prefix = Some(prefix.into());
        self
    }

    /// Allow environment variables to override secret settings
    ///
    /// By default, secrets stored in the OS keychain are NOT affected by env vars.
    /// Enable this for Docker/CI environments where secrets are passed via env.
    ///
    /// # Example
    /// ```rust
    /// use rcman::SettingsConfig;
    ///
    /// let config = SettingsConfig::builder("my-app", "1.0.0")
    ///     .with_env_prefix("MYAPP")
    ///     .env_overrides_secrets(true)  // MYAPP_API_KEY will override keychain
    ///     .build();
    /// ```
    #[must_use]
    pub fn env_overrides_secrets(mut self, allow: bool) -> Self {
        self.options.env_overrides_secrets = allow;
        self
    }

    /// Set a custom environment variable source
    ///
    /// Useful for testing or injecting env vars procedurally.
    #[must_use]
    pub fn with_env_source(mut self, source: std::sync::Arc<dyn EnvSource>) -> Self {
        self.options.env_source = Some(source);
        self
    }

    /// Set a migration function for schema changes (lazy migration)
    ///
    /// The migrator function is called automatically when loading settings.
    /// If the function modifies the value, the migrated version is saved back.
    ///
    /// Use this to upgrade old data formats to new ones transparently.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rcman::SettingsConfig;
    /// use serde_json::json;
    ///
    /// let config = SettingsConfig::builder("my-app", "1.0.0")
    ///     .with_migrator(|mut value| {
    ///         // Migrate v1 to v2: rename "color" to "theme"
    ///         if let Some(obj) = value.as_object_mut() {
    ///             if let Some(ui) = obj.get_mut("ui").and_then(|v| v.as_object_mut()) {
    ///                 if let Some(color) = ui.remove("color") {
    ///                     ui.insert("theme".to_string(), color);
    ///                 }
    ///             }
    ///         }
    ///         value
    ///     })
    ///     .build();
    /// ```
    #[must_use]
    pub fn with_migrator<F>(mut self, migrator: F) -> Self
    where
        F: Fn(serde_json::Value) -> serde_json::Value + Send + Sync + 'static,
    {
        self.options.migrator = Some(std::sync::Arc::new(migrator));
        self
    }

    /// Enable hot-reload with default configuration.
    #[cfg(feature = "hot-reload")]
    #[must_use]
    pub fn with_hot_reload(mut self) -> Self {
        self.options.hot_reload = Some(HotReloadConfig::default());
        self
    }

    /// Enable hot-reload with a custom configuration.
    #[cfg(feature = "hot-reload")]
    #[must_use]
    pub fn with_hot_reload_config(mut self, config: HotReloadConfig) -> Self {
        self.options.hot_reload = Some(config);
        self
    }

    /// Enable profiles for main settings
    ///
    /// When enabled, the main settings file is stored per-profile, allowing
    /// completely different configurations (e.g., "work" vs "personal").
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use rcman::SettingsManager;
    ///
    /// let manager = SettingsManager::builder("my-app", "1.0.0")
    ///     .with_profiles()  // Enable profiles for main settings
    ///     .build()?;
    ///
    /// // Now you can switch profiles
    /// manager.switch_profile("work")?;
    /// ```
    #[cfg(feature = "profiles")]
    #[must_use]
    pub fn with_profiles(mut self) -> Self {
        self.options.profiles_enabled = true;
        self
    }

    /// Specify the schema type for compile-time type safety.
    ///
    /// This binds your settings struct to the manager, enabling:
    /// - Type-safe `get_all()` method returning your struct
    /// - Compile-time validation of setting keys
    /// - Better IDE autocomplete and refactoring support
    ///
    /// # Example
    /// ```no_run
    /// use rcman::{IndexMap, SettingMetadata, SettingsConfig, SettingsSchema, settings};
    /// use serde::{Serialize, Deserialize};
    ///
    /// #[derive(Default, Serialize, Deserialize)]
    /// struct AppSettings {
    ///     theme: String,
    ///     font_size: f64,
    /// }
    ///
    /// impl SettingsSchema for AppSettings {
    ///     fn get_metadata() -> IndexMap<String, SettingMetadata> {
    ///         settings! {
    ///             "ui.theme" => SettingMetadata::text("dark").meta_str("label", "Theme"),
    ///             "ui.font_size" => SettingMetadata::number(14.0).meta_str("label", "Font Size")
    ///         }
    ///     }
    /// }
    ///
    /// let config = SettingsConfig::builder("my-app", "1.0.0")
    ///     .with_schema::<AppSettings>()  // Bind the schema
    ///     .build();
    /// ```
    #[must_use]
    pub fn with_schema<NewSchema: SettingsSchema>(self) -> SettingsConfigBuilder<S, NewSchema> {
        SettingsConfigBuilder {
            options: self.options,
            storage: self.storage,
            _schema: PhantomData,
        }
    }

    /// Specify the storage backend instance.
    ///
    /// This transforms the builder to use the specified storage backend instance.
    /// The settings filename will automatically be updated to match the format.
    ///
    /// # Example
    /// ```no_run
    /// use rcman::{SettingsConfig, JsonStorage};
    ///
    /// let storage = JsonStorage::compact();
    /// let config = SettingsConfig::builder("my-app", "1.0.0")
    ///     .with_storage_instance(storage)
    ///     .build();
    /// ```
    #[must_use]
    pub fn with_storage_instance<NewS: StorageBackend>(
        self,
        storage: NewS,
    ) -> SettingsConfigBuilder<NewS, Schema> {
        SettingsConfigBuilder {
            options: self.options,
            storage,
            _schema: PhantomData,
        }
    }

    /// Specify the storage backend type.
    ///
    /// This transforms the builder to use the specified storage backend.
    /// The settings filename will automatically be updated to match the format.
    ///
    /// # Example
    /// ```no_run
    /// use rcman::{SettingsConfig, JsonStorage};
    ///
    /// let config = SettingsConfig::builder("my-app", "1.0.0")
    ///     .with_storage::<JsonStorage>()
    ///     .build();
    /// ```
    #[must_use]
    pub fn with_storage<NewS: StorageBackend + Default>(
        self,
    ) -> SettingsConfigBuilder<NewS, Schema> {
        self.with_storage_instance(NewS::default())
    }

    /// Build the `SettingsConfig`
    ///
    /// If `config_dir` is not set, uses the system config directory for the app.
    #[must_use]
    pub fn build(self) -> SettingsConfig<S, Schema> {
        let options = self.options;
        let config_dir = options.config_dir.unwrap_or_else(|| {
            // Use system config dir if available, otherwise current dir
            dirs::config_dir().map_or_else(|| PathBuf::from("."), |d| d.join(&options.app_name))
        });

        let storage = self.storage;

        let settings_file = options
            .settings_file
            .unwrap_or_else(|| format!("settings.{}", storage.extension()));

        #[cfg(all(feature = "keychain", feature = "encrypted-file"))]
        let mut credential_config = options.credential_config;
        #[cfg(not(all(feature = "keychain", feature = "encrypted-file")))]
        let credential_config = options.credential_config;

        let env_source = options
            .env_source
            .unwrap_or_else(|| std::sync::Arc::new(DefaultEnvSource));

        #[cfg(all(feature = "keychain", feature = "encrypted-file"))]
        {
            if options.resolve_env_credentials {
                credential_config = env_credential_config(&options.app_name, &*env_source);
            }

            Self::set_default_credential_path(&mut credential_config, &config_dir);
        }

        SettingsConfig {
            config_dir,
            settings_file,
            app_name: options.app_name,
            app_version: options.app_version,
            storage,
            credential_config,
            env_prefix: options.env_prefix,
            env_overrides_secrets: options.env_overrides_secrets,
            #[cfg(feature = "backup")]
            external_configs: options.external_configs,
            migrator: options.migrator,
            #[cfg(feature = "profiles")]
            profiles_enabled: options.profiles_enabled,
            #[cfg(feature = "profiles")]
            profile_migrator: options.profile_migrator.unwrap_or_default(),
            _schema: PhantomData,
            env_source,
            #[cfg(feature = "hot-reload")]
            hot_reload: options.hot_reload,
            #[cfg(feature = "vault")]
            vault_requested: options.vault.requested,
            #[cfg(feature = "vault")]
            vault_password: options.vault.password,
            #[cfg(feature = "vault")]
            vault_lock_timeout: options.vault.lock_timeout,
            #[cfg(feature = "vault")]
            vault_kdf_params: options.vault.kdf_params,
        }
    }
    #[cfg(all(feature = "keychain", feature = "encrypted-file"))]
    fn set_default_credential_path(config: &mut CredentialConfig, config_dir: &std::path::Path) {
        if let CredentialConfig::WithFallback { fallback_path, .. } = config
            && fallback_path.is_none()
        {
            *fallback_path = Some(config_dir.join("secrets.enc"));
        }
    }
}

/// Resolve [`SettingsConfigBuilder::with_env_credentials`] from the environment.
///
/// The variables are named after the app (uppercased, `-` and `.` become `_`),
/// so `my-app` reads `MY_APP_SECRET`, `MY_APP_SECRET_FILE` and `MY_APP_SECRET_PATH`:
///
/// | Set                                                   | Password                  | Fallback file  |
/// |-------------------------------------------------------|---------------------------|----------------|
/// | `_SECRET_FILE`                                        | read from that file       | default        |
/// | `_SECRET_PATH` naming an existing file, no `_SECRET`  | read from that file       | default        |
/// | `_SECRET_PATH` otherwise                              | `_SECRET`                 | `_SECRET_PATH` |
/// | none of them                                          | `_SECRET`                 | default        |
///
/// An unset `_SECRET` is not an error: credentials then use the keychain, or
/// volatile memory when it is unavailable.
#[cfg(all(feature = "keychain", feature = "encrypted-file"))]
fn env_credential_config(app_name: &str, env: &dyn EnvSource) -> CredentialConfig {
    use crate::credentials::SecretPasswordSource;
    let base_name = app_name.to_uppercase().replace(['-', '.'], "_");
    let secret_var = format!("{base_name}_SECRET");
    let set = |name: String| env.var(&name).ok().filter(|value| !value.is_empty());

    if let Some(file) = set(format!("{base_name}_SECRET_FILE")) {
        return CredentialConfig::WithFallback {
            fallback_path: None,
            password: SecretPasswordSource::File(PathBuf::from(file)),
        };
    }
    let Some(path) = set(format!("{base_name}_SECRET_PATH")).map(PathBuf::from) else {
        return CredentialConfig::WithFallback {
            fallback_path: None,
            password: SecretPasswordSource::Environment(secret_var),
        };
    };
    // Container convenience: a secret file mounted at `_SECRET_PATH`.
    if set(secret_var.clone()).is_none() && path.is_file() {
        return CredentialConfig::WithFallback {
            fallback_path: None,
            password: SecretPasswordSource::File(path),
        };
    }
    CredentialConfig::WithFallback {
        fallback_path: Some(path),
        password: SecretPasswordSource::Environment(secret_var),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(all(feature = "keychain", feature = "encrypted-file"))]
    struct MockEnvSource(std::collections::HashMap<String, String>);
    #[cfg(all(feature = "keychain", feature = "encrypted-file"))]
    impl EnvSource for MockEnvSource {
        fn var(&self, key: &str) -> std::result::Result<String, std::env::VarError> {
            self.0
                .get(key)
                .cloned()
                .ok_or(std::env::VarError::NotPresent)
        }
    }

    #[test]
    fn test_builder_basic() {
        let config = SettingsConfig::builder("test-app", "1.0.0").build();

        assert_eq!(config.app_name, "test-app");
        assert_eq!(config.app_version, "1.0.0");
        assert_eq!(config.settings_file, "settings.json");
    }

    #[test]
    fn test_builder_with_options() {
        let config = SettingsConfig::builder("my-app", "2.0.0")
            .with_config_dir("/tmp/my-app")
            .with_settings_file("config.json")
            .build();

        assert_eq!(config.config_dir, PathBuf::from("/tmp/my-app"));
        assert_eq!(config.settings_file, "config.json");
    }

    #[test]
    #[cfg(all(feature = "keychain", feature = "encrypted-file"))]
    fn test_builder_credentials_auto_path() {
        let config = SettingsConfig::builder("my-app", "1.0.0")
            .with_config_dir("/tmp/my-app")
            .with_custom_env_credentials("MYAPP_KEY")
            .build();

        if let CredentialConfig::WithFallback {
            fallback_path,
            password,
        } = config.credential_config
        {
            assert_eq!(
                fallback_path,
                Some(PathBuf::from("/tmp/my-app/secrets.enc"))
            );
            assert_eq!(
                password,
                crate::credentials::SecretPasswordSource::Environment("MYAPP_KEY".into())
            );
        } else {
            panic!("Expected CredentialConfig::WithFallback");
        }
    }

    #[test]
    #[cfg(all(feature = "keychain", feature = "encrypted-file"))]
    fn test_builder_credentials_default_name() {
        let config = SettingsConfig::builder("my-app", "1.0.0")
            .with_env_credentials()
            .build();

        if let CredentialConfig::WithFallback { password, .. } = config.credential_config {
            assert_eq!(
                password,
                crate::credentials::SecretPasswordSource::Environment("MY_APP_SECRET".to_string())
            );
        } else {
            panic!("Expected CredentialConfig::WithFallback");
        }
    }

    #[test]
    #[cfg(all(feature = "keychain", feature = "encrypted-file"))]
    fn test_builder_credentials_automated_path() {
        let mut vars = std::collections::HashMap::new();
        vars.insert(
            "MY_APP_SECRET_PATH".to_string(),
            "/tmp/mystic_path.enc".to_string(),
        );
        let env_source = std::sync::Arc::new(MockEnvSource(vars));

        let config = SettingsConfig::builder("my-app", "1.0.0")
            .with_env_source(env_source)
            .with_env_credentials()
            .build();

        if let CredentialConfig::WithFallback {
            fallback_path,
            password,
        } = config.credential_config
        {
            assert_eq!(
                fallback_path,
                Some(std::path::PathBuf::from("/tmp/mystic_path.enc"))
            );
            assert_eq!(
                password,
                crate::credentials::SecretPasswordSource::Environment("MY_APP_SECRET".to_string())
            );
        } else {
            panic!("Expected CredentialConfig::WithFallback");
        }
    }
}
