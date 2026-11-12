//! Builder for `SettingsManager`
//!
//! This module contains [`SettingsManagerBuilder`] which provides a fluent API
//! for creating a [`SettingsManager`](super::SettingsManager).

use crate::config::SettingsConfigBuilder;
use crate::config::SettingsSchema;
use crate::error::Result;
use crate::storage::StorageBackend;
use crate::sub_settings::SubSettingsConfig;
use std::path::PathBuf;

use super::SettingsManager;

/// Builder for creating a [`SettingsManager`] with a fluent API.
///
/// This is the recommended way to create a `SettingsManager`. It allows you to
/// configure all options and register sub-settings in a single chain of calls.
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
///     .with_sub_settings(SubSettingsConfig::singlefile("backends"))
///     .build()
///     .unwrap();
/// ```
pub struct SettingsManagerBuilder<
    S: StorageBackend = crate::storage::JsonStorage,
    Schema: SettingsSchema = (),
> {
    config_builder: SettingsConfigBuilder<S, Schema>,
    sub_settings: Vec<SubSettingsConfig>,
}

impl<S: StorageBackend, Schema: SettingsSchema> SettingsManagerBuilder<S, Schema> {
    /// Create a new builder with required app name and version.
    pub fn new(
        app_name: impl Into<String>,
        app_version: impl Into<String>,
    ) -> SettingsManagerBuilder {
        SettingsManagerBuilder {
            config_builder: SettingsConfigBuilder::new(app_name, app_version),
            sub_settings: Vec::new(),
        }
    }
}

/// Forward builder options to [`SettingsConfigBuilder`], so each option is
/// implemented and documented once.
macro_rules! forward {
    ($( $(#[cfg($cfg:meta)])* $name:ident ( $($arg:ident : $ty:ty),* ); )*) => {
        $(
            $(#[cfg($cfg)])*
            #[doc = concat!("See [`SettingsConfigBuilder::", stringify!($name), "`].")]
            #[must_use]
            pub fn $name(mut self, $($arg: $ty),*) -> Self {
                self.config_builder = self.config_builder.$name($($arg),*);
                self
            }
        )*
    };
}

impl<S: StorageBackend, Schema: SettingsSchema> SettingsManagerBuilder<S, Schema> {
    forward! {
        with_config_dir(path: impl Into<PathBuf>);
        with_settings_file(filename: impl Into<String>);
        with_credentials();
        with_credential_config(config: crate::config::CredentialConfig);
        #[cfg(all(feature = "keychain", feature = "encrypted-file"))]
        with_encrypted_fallback(
            path: impl Into<PathBuf>,
            password_source: crate::credentials::SecretPasswordSource
        );
        #[cfg(all(feature = "keychain", feature = "encrypted-file"))]
        with_env_credentials();
        #[cfg(all(feature = "keychain", feature = "encrypted-file"))]
        with_custom_env_credentials(var_name: impl Into<String>);
        #[cfg(all(feature = "keychain", feature = "encrypted-file"))]
        with_file_credentials(path: impl Into<PathBuf>);
        #[cfg(all(feature = "keychain", feature = "encrypted-file"))]
        with_password_credentials(password: impl Into<String>);
        #[cfg(feature = "vault")]
        with_vault();
        #[cfg(feature = "vault")]
        with_vault_password(password: impl Into<String>);
        #[cfg(feature = "vault")]
        with_vault_password_source(source: crate::credentials::SecretPasswordSource);
        #[cfg(feature = "vault")]
        with_vault_lock_timeout(timeout: std::time::Duration);
        #[cfg(feature = "vault")]
        with_vault_kdf_params(params: crate::vault::Argon2Params);
        #[cfg(feature = "vault")]
        with_vault_preset(preset: crate::vault::Argon2Preset);
        with_env_prefix(prefix: impl Into<String>);
        env_overrides_secrets(allow: bool);
        with_env_source(source: std::sync::Arc<dyn crate::config::EnvSource>);
        #[cfg(feature = "hot-reload")]
        with_hot_reload();
        #[cfg(feature = "hot-reload")]
        with_hot_reload_config(config: crate::config::HotReloadConfig);
        #[cfg(feature = "backup")]
        with_external_config(config: crate::backup::ExternalConfig);
        #[cfg(feature = "profiles")]
        with_profiles();
    }

    /// See [`SettingsConfigBuilder::with_migrator`].
    #[must_use]
    pub fn with_migrator<F>(mut self, migrator: F) -> Self
    where
        F: Fn(serde_json::Value) -> serde_json::Value + Send + Sync + 'static,
    {
        self.config_builder = self.config_builder.with_migrator(migrator);
        self
    }

    /// Specify the schema type for the settings.
    ///
    /// This transforms the builder to use a typed schema instead of dynamic.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use rcman::{IndexMap, SettingMetadata, SettingsManager, SettingsSchema, settings};
    /// use serde::{Deserialize, Serialize};
    ///
    /// #[derive(Debug, Clone, Serialize, Deserialize, Default)]
    /// struct AppSettings {
    ///     theme: String,
    /// }
    ///
    /// impl SettingsSchema for AppSettings {
    ///     fn get_metadata() -> IndexMap<String, SettingMetadata> {
    ///         settings! {
    ///             "ui.theme" => SettingMetadata::text("dark").meta_str("label", "Theme")
    ///         }
    ///     }
    /// }
    ///
    /// let manager = SettingsManager::builder("my-app", "1.0.0")
    ///     .with_schema::<AppSettings>()
    ///     .build()
    ///     .unwrap();
    /// ```
    #[must_use]
    pub fn with_schema<NewSchema: SettingsSchema>(self) -> SettingsManagerBuilder<S, NewSchema> {
        SettingsManagerBuilder {
            config_builder: self.config_builder.with_schema::<NewSchema>(),
            sub_settings: self.sub_settings,
        }
    }

    /// Specify the storage backend instance.
    ///
    /// This transforms the builder to use the specified storage backend instance.
    ///
    /// # Example
    /// ```rust,no_run
    /// use rcman::{SettingsManager, JsonStorage};
    ///
    /// let storage = JsonStorage::compact();
    /// let manager = SettingsManager::builder("my-app", "1.0.0")
    ///     .with_storage_instance(storage)
    ///     .build()
    ///     .unwrap();
    /// ```
    #[must_use]
    pub fn with_storage_instance<NewS: StorageBackend>(
        self,
        storage: NewS,
    ) -> SettingsManagerBuilder<NewS, Schema> {
        SettingsManagerBuilder {
            config_builder: self.config_builder.with_storage_instance(storage),
            sub_settings: self.sub_settings,
        }
    }

    /// Specify the storage backend type.
    ///
    /// This transforms the builder to use the specified storage backend.
    ///
    /// # Example
    /// ```rust,no_run
    /// use rcman::{SettingsManager, JsonStorage};
    ///
    /// let manager = SettingsManager::builder("my-app", "1.0.0")
    ///     .with_storage::<JsonStorage>()
    ///     .build()
    ///     .unwrap();
    /// ```
    #[must_use]
    pub fn with_storage<NewS: StorageBackend + Default>(
        self,
    ) -> SettingsManagerBuilder<NewS, Schema> {
        self.with_storage_instance(NewS::default())
    }

    /// Register a sub-settings type for per-entity configuration.
    ///
    /// Sub-settings allow you to manage separate config files for each entity
    /// (e.g., one file per remote, per profile, etc.).
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use rcman::{SettingsManager, SubSettingsConfig};
    ///
    /// let manager = SettingsManager::builder("my-app", "1.0.0")
    ///     .with_sub_settings(SubSettingsConfig::new("remotes"))
    ///     .with_sub_settings(SubSettingsConfig::singlefile("backends"))
    ///     .build()
    ///     .unwrap();
    /// ```
    #[must_use]
    pub fn with_sub_settings(mut self, config: SubSettingsConfig) -> Self {
        self.sub_settings.push(config);
        self
    }

    /// Build the [`SettingsManager`].
    ///
    /// This creates the config directory if it doesn't exist, initializes
    /// the manager, and registers all sub-settings.
    ///
    /// # Errors
    ///
    /// Returns an error if the config directory cannot be created.
    pub fn build(self) -> Result<SettingsManager<S, Schema>>
    where
        S: 'static,
    {
        let config = self.config_builder.build();
        SettingsManager::new_with_sub_settings(config, self.sub_settings)
    }
}

impl<Schema: SettingsSchema> SettingsManagerBuilder<crate::storage::JsonStorage, Schema> {
    /// See [`SettingsConfigBuilder::with_pretty_json`].
    #[must_use]
    pub fn with_pretty_json(mut self, pretty: bool) -> Self {
        self.config_builder = self.config_builder.with_pretty_json(pretty);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_with_credentials_config() {
        let manager = SettingsManager::builder("my-app", "1.0.0")
            .with_config_dir("/tmp/my-app")
            .with_credential_config(crate::config::CredentialConfig::Default)
            .build()
            .unwrap();

        #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
        {
            assert!(manager.credentials.is_some());
        }

        #[cfg(not(any(feature = "keychain", feature = "encrypted-file")))]
        {
            let _ = manager;
        }
    }

    #[test]
    fn test_builder_with_storage_instance() {
        let storage = crate::storage::JsonStorage::compact();
        let manager = SettingsManager::builder("my-app", "1.0.0")
            .with_config_dir("/tmp/my-app-storage-test")
            .with_storage_instance(storage)
            .build()
            .unwrap();

        assert_eq!(manager.storage().extension(), "json");
    }
}
