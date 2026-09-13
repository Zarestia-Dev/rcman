use crate::config::{SettingMetadata, SettingsSchema};
use crate::error::{Error, Result};
use crate::manager::core::SettingsManager;
use crate::storage::StorageBackend;
use crate::sub_settings::{SubSettings, SubSettingsConfig};
use crate::utils::sync::RwLockExt;

#[cfg(feature = "backup")]
use crate::backup::{BackupManager, ExternalConfigProvider};

use indexmap::IndexMap;
use log::{debug, info};
use serde_json::Value;
#[cfg(feature = "vault")]
use serde_json::json;
use std::sync::Arc;

#[cfg(feature = "vault")]
type SubSettingsProfileEntries = (Option<String>, Vec<(String, Value)>);

#[cfg(feature = "vault")]
struct SubSettingsSnapshot<S: StorageBackend> {
    sub: Arc<SubSettings<S>>,
    profiles_data: Vec<SubSettingsProfileEntries>,
}

#[cfg(feature = "vault")]
struct VaultMigrationSnapshot<S: StorageBackend> {
    active_settings: (std::path::PathBuf, Value),
    other_profiles_settings: Vec<(String, std::path::PathBuf, Value)>,
    sub_settings_data: Vec<SubSettingsSnapshot<S>>,
}

impl<S: StorageBackend + 'static, Schema: SettingsSchema> SettingsManager<S, Schema> {
    pub(crate) fn parse_setting_key(key: &str) -> Option<(&str, &str)> {
        let mut parts = key.split('.');
        let category = parts.next()?;
        let setting = parts.next()?;

        if parts.next().is_some() {
            return None;
        }

        Some((category, setting))
    }

    /// Helper to get a setting value, checking keyring if it's a secret (when feature is enabled).
    ///
    /// This centralizes the logic for retrieving values that may be stored in
    /// the keyring (for secrets) or in the file cache (for normal settings).
    fn get_value_with_secret_support(
        &self,
        key: &str,
        metadata: &SettingMetadata,
    ) -> Result<Option<(Value, bool)>> {
        if cfg!(any(feature = "keychain", feature = "encrypted-file")) && metadata.is_secret() {
            // Check env var override for secrets if enabled
            if self.config.env_overrides_secrets
                && let Some(env_value) = self.get_env_override(key)
            {
                return Ok(Some((env_value, true)));
            }

            // Try retrieving from keyring
            #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
            if let Ok(Some(secret_value)) = self.get_credential_with_profile(key) {
                return Ok(Some((Value::String(secret_value), false)));
            }

            // Secret not found, use default
            return Ok(Some((metadata.default.clone(), false)));
        }

        // Not a secret (or feature disabled) - check cache (with env override support)
        if let Some(env_value) = self.get_env_override(key) {
            return Ok(Some((env_value, true)));
        }

        let Some((category, setting_name)) = Self::parse_setting_key(key) else {
            return Ok(None);
        };

        Ok(self
            .settings_cache
            .get_value(category, setting_name, key)?
            .map(|v| (v, false)))
    }

    /// Check if a setting value is overridden by an environment variable
    ///
    /// Returns the parsed value if env var is set and successfully parsed.
    pub(crate) fn get_env_override(&self, key: &str) -> Option<Value> {
        self.env_handler.get_env_override(key)
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
    pub fn metadata(&self) -> Result<IndexMap<String, SettingMetadata>> {
        #[cfg(feature = "vault")]
        if self.is_locked() {
            return Err(Error::ConfigLocked);
        }

        // Ensure cache is populated
        self.ensure_cache_populated()?;

        // Get metadata and populate values
        let mut metadata = (*self.schema_metadata).clone();

        for (key, option) in &mut metadata {
            if Self::parse_setting_key(key).is_some() {
                match self.get_value_with_secret_support(key, option) {
                    Ok(Some((value, env_overridden))) => {
                        option.value = Some(value);
                        if env_overridden {
                            option
                                .metadata
                                .insert("env_override".to_string(), Value::Bool(true));
                            debug!("Setting {key} overridden by env var");
                        }
                    }
                    Ok(None) => {
                        // Fallback to default if helper returns None
                        option.value = Some(option.default.clone());
                    }
                    Err(e) => {
                        debug!("Failed to read value for {key}: {e}");
                        option.value = Some(option.default.clone());
                    }
                }
            }
        }

        debug!("Settings loaded successfully");
        Ok(metadata)
    }

    /// Get a single setting value by key path.
    ///
    /// # Type Parameters
    ///
    /// * `T` - The type to deserialize the value into
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
    {
        let value = self.get_value(key)?;
        serde_json::from_value(value).map_err(|e| Error::Parse(e.to_string()))
    }

    /// Get raw JSON value for a setting key.
    ///
    /// Returns the value from merged settings cache, or from keyring if it's a secret.
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
        #[cfg(feature = "vault")]
        if self.is_locked() {
            return Err(Error::ConfigLocked);
        }

        let Some((category, setting_name)) = Self::parse_setting_key(key) else {
            return Err(Error::Config(
                "Key must be in format 'category.setting'".into(),
            ));
        };

        // Ensure cache is populated with schema defaults
        self.ensure_cache_populated()?;

        // Get metadata to check if this is a secret
        let setting_metadata = self
            .schema_metadata
            .get(key)
            .ok_or_else(|| Error::SettingNotFound(format!("{category}.{setting_name}")))?;

        // Use the helper that handles both secrets and regular settings.
        self.get_value_with_secret_support(key, setting_metadata)?
            .map(|(v, _)| v)
            .ok_or_else(|| Error::SettingNotFound(format!("{category}.{setting_name}")))
    }

    /// Get merged settings as raw JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if settings cannot be read.
    pub fn get_all_data(&self) -> Result<Value> {
        #[cfg(feature = "vault")]
        if self.is_locked() {
            return Err(Error::ConfigLocked);
        }

        self.ensure_cache_populated()?;
        self.settings_cache
            .get_or_compute_merged(|stored| Self::merge_with_defaults(stored))
    }

    /// Get merged settings struct with caching.
    ///
    /// # Errors
    ///
    /// Returns an error if settings cannot be read or parsed.
    pub fn get_all(&self) -> Result<Schema> {
        let merged = self.get_all_data()?;

        // Deserialize to concrete type
        serde_json::from_value(merged).map_err(|e| Error::Parse(e.to_string()))
    }

    /// Internal helper to merge stored settings with schema defaults.
    pub(crate) fn merge_with_defaults(stored: &Value) -> Result<Value> {
        let default = Schema::default();
        let mut merged = serde_json::to_value(&default)?;

        // Merge stored on top of defaults only if stored is an object
        if stored.is_object() {
            crate::utils::value::deep_merge(&mut merged, stored);
        }

        Ok(merged)
    }

    // =========================================================================
    // Sub-Settings Management
    // =========================================================================

    /// Register a sub-settings type for per-entity configuration.
    ///
    /// Sub-settings allow you to manage separate config files for each entity
    /// (e.g., one file per remote, per profile, etc.).
    ///
    /// # Errors
    ///
    /// Returns an error if the sub-settings handler cannot be initialized (e.g. invalid path).
    pub fn register_sub_settings(&self, config: SubSettingsConfig) -> Result<()> {
        let name = config.name.clone();

        #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
        let credentials = self.credentials.clone();

        #[cfg(feature = "vault")]
        let vault = Arc::clone(&self.vault);

        let handler = Arc::new(SubSettings::new(
            &self.config.config_dir,
            config,
            self.storage.clone(),
            #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
            credentials,
            #[cfg(feature = "vault")]
            vault,
        )?);

        let mut guard = self.sub_settings.write_recovered()?;
        guard.insert(name.clone(), handler.clone());

        #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
        self.migrate_sub_settings_secret_keys(&handler)?;

        info!("Registered sub-settings type: {name}");
        Ok(())
    }

    /// Get a registered sub-settings handler.
    ///
    /// Returns the handler for the specified sub-settings type, which can be used
    /// to read, write, and manage individual entries.
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
    pub fn has_sub_settings(&self, name: &str) -> bool {
        match self.sub_settings.read_recovered() {
            Ok(guard) => guard.contains_key(name),
            Err(err) => {
                debug!("Failed to check sub-settings existence for {name}: {err}");
                false
            }
        }
    }

    /// List all registered sub-settings types
    pub fn sub_settings_types(&self) -> Vec<String> {
        match self.sub_settings.read_recovered() {
            Ok(guard) => guard.keys().cloned().collect(),
            Err(err) => {
                debug!("Failed to list sub-settings types: {err}");
                Vec::new()
            }
        }
    }

    /// List all entries in a sub-settings type (convenience method)
    ///
    /// This is a shorthand for `manager.sub_settings(name)?.list()?`
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

    // =========================================================================
    // Backup & External Configs
    // =========================================================================

    /// Register an external config provider for backups.
    ///
    /// This allows dynamic registration of external files to be included in backups.
    ///
    #[cfg(feature = "backup")]
    pub fn register_external_provider(&self, provider: Box<dyn ExternalConfigProvider>) {
        if let Ok(mut providers) = self.external_providers.write_recovered() {
            providers.push(provider);
        } else {
            debug!("Failed to register external config provider due to lock recovery error");
        }
    }

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
    #[cfg(feature = "backup")]
    pub fn get_export_categories(&self) -> Vec<crate::backup::ExportCategory> {
        use crate::backup::{ExportCategory, ExportCategoryType};

        let mut categories = Vec::new();

        // Main settings
        categories.push(ExportCategory {
            id: "settings".to_string(),
            name: "Application Settings".to_string(),
            category_type: ExportCategoryType::Settings,
            optional: false,
            description: Some("Main application settings".to_string()),
        });

        // Sub-settings
        let sub_types = self.sub_settings_types();
        for sub_type in sub_types {
            categories.push(ExportCategory {
                id: sub_type.clone(),
                name: sub_type.clone(),
                category_type: ExportCategoryType::SubSettings,
                optional: false,
                description: None,
            });
        }

        // External configs
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

    // =========================================================================
    // Vault & Lock Operations (vault feature)
    // =========================================================================

    /// Check if the configuration manager is currently locked.
    ///
    /// Automatically applies inactivity timeouts if configured.
    /// When locked, all settings read/write operations return `Err(Error::ConfigLocked)`.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use rcman::SettingsManager;
    /// # fn check(manager: &SettingsManager) {
    /// if manager.is_locked() {
    ///     println!("Vault is locked");
    /// }
    /// # }
    /// ```
    #[cfg(feature = "vault")]
    #[must_use]
    pub fn is_locked(&self) -> bool {
        let guard = match self.vault.read() {
            Ok(g) => g,
            Err(_) => return false,
        };
        let Some(vault) = guard.as_ref() else {
            return false;
        };
        let (locked, did_transition) = vault.is_locked_transition();
        if did_transition {
            self.invalidate_cache();
        }
        locked
    }

    /// Check if the configuration vault feature is enabled for this settings manager.
    #[cfg(feature = "vault")]
    #[must_use]
    pub fn is_vault_enabled(&self) -> bool {
        self.vault.read().ok().is_some_and(|guard| guard.is_some())
    }

    /// Retrieve a snapshot of the current vault status, parameters, and activity.
    ///
    /// Returns `None` if the vault feature is not enabled for this manager.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use rcman::SettingsManager;
    /// # fn check(manager: &SettingsManager) {
    /// if let Some(info) = manager.vault_info() {
    ///     println!("Vault enabled: {}, locked: {}", info.enabled, info.is_locked);
    /// }
    /// # }
    /// ```
    #[cfg(feature = "vault")]
    #[must_use]
    pub fn vault_info(&self) -> Option<crate::vault::VaultInfo> {
        let guard = self.vault.read().ok()?;
        let vault = guard.as_ref()?;
        Some(vault.info())
    }

    /// Verify whether a password matches the configuration vault without altering lock state.
    ///
    /// This is useful for confirmation dialogs before sensitive operations (e.g. key rotation,
    /// deleting profiles, or exporting sensitive data).
    ///
    /// # Errors
    /// Returns `Error::VaultNotEnabled` if vault is not enabled, or `Error::Vault` if crypto derivation fails.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use rcman::SettingsManager;
    /// # fn confirm(manager: &SettingsManager, pwd: &str) -> rcman::Result<()> {
    /// if manager.verify_vault_password(pwd)? {
    ///     println!("Password confirmed");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "vault")]
    pub fn verify_vault_password(&self, password: &str) -> Result<bool> {
        let guard = self.vault.read().map_err(|_| Error::LockPoisoned)?;
        let vault = guard.as_ref().ok_or(Error::VaultNotEnabled)?;

        let settings_path = self.settings_path()?;
        let envelope = match self.storage.read::<Value>(&settings_path) {
            Ok(value) if crate::vault::is_vault_value(&value) => {
                serde_json::from_value::<crate::vault::VaultEnvelope>(value).ok()
            }
            _ => None,
        };

        vault.verify_password(password, envelope.as_ref())
    }

    /// Update the inactivity auto-lock timeout at runtime.
    ///
    /// Pass `None` to disable auto-locking on inactivity.
    ///
    /// # Errors
    /// Returns `Error::VaultNotEnabled` if vault is not enabled on this manager.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use rcman::SettingsManager;
    /// # use std::time::Duration;
    /// # fn config(manager: &SettingsManager) -> rcman::Result<()> {
    /// manager.set_vault_lock_timeout(Some(Duration::from_secs(300)))?;
    /// assert_eq!(manager.vault_lock_timeout(), Some(Duration::from_secs(300)));
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "vault")]
    pub fn set_vault_lock_timeout(&self, timeout: Option<std::time::Duration>) -> Result<()> {
        let guard = self.vault.read().map_err(|_| Error::LockPoisoned)?;
        let vault = guard.as_ref().ok_or(Error::VaultNotEnabled)?;
        vault.set_lock_timeout(timeout);
        Ok(())
    }

    /// Retrieve the configured inactivity auto-lock timeout, if configured.
    #[cfg(feature = "vault")]
    #[must_use]
    pub fn vault_lock_timeout(&self) -> Option<std::time::Duration> {
        self.vault
            .read()
            .ok()
            .and_then(|guard| guard.as_ref().and_then(|v| v.lock_timeout()))
    }

    /// Reset the inactivity auto-lock timer without performing file I/O.
    ///
    /// Call this when the user interacts with the UI (e.g. keyboard/mouse activity)
    /// to prevent auto-lock while actively working.
    ///
    /// # Errors
    /// Returns `Error::VaultNotEnabled` if vault is not enabled.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use rcman::SettingsManager;
    /// # fn on_user_activity(manager: &SettingsManager) -> rcman::Result<()> {
    /// manager.touch_vault()?;
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "vault")]
    pub fn touch_vault(&self) -> Result<()> {
        let guard = self.vault.read().map_err(|_| Error::LockPoisoned)?;
        let vault = guard.as_ref().ok_or(Error::VaultNotEnabled)?;
        vault.touch();
        Ok(())
    }

    /// Unlock the configuration vault using the master key or password.
    ///
    /// Once unlocked, settings and all registered sub-settings can be read and
    /// updated normally in memory.
    ///
    /// # Errors
    /// Returns:
    /// - `Error::VaultNotEnabled` if vault was not enabled on this manager
    /// - `Error::InvalidPassword` if the password cannot decrypt the on-disk envelope
    #[cfg(feature = "vault")]
    pub fn unlock(&self, password: &str) -> Result<()> {
        let guard = self.vault.read().map_err(|_| Error::LockPoisoned)?;
        let vault = guard.as_ref().ok_or(Error::VaultNotEnabled)?;

        if !vault.is_locked() {
            return Ok(());
        }

        let settings_path = self.settings_path()?;
        let envelope = match self.storage.read::<Value>(&settings_path) {
            Ok(value) if crate::vault::is_vault_value(&value) => {
                serde_json::from_value::<crate::vault::VaultEnvelope>(value).ok()
            }
            _ => None,
        };

        let _ = vault.unlock(password, envelope.as_ref())?;

        // Invalidate in-memory cache to force reading decrypted contents
        self.invalidate_cache();
        self.ensure_cache_populated()?;

        // Migrate secret keys now that vault is unlocked
        #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
        self.migrate_secret_keys()?;

        self.events.notify_vault(crate::vault::VaultEvent::Unlocked);
        info!("Configuration vault successfully unlocked");
        Ok(())
    }

    /// Lock the configuration vault immediately, wiping keys from memory.
    ///
    /// # Errors
    /// Returns `Error::VaultNotEnabled` if vault is not enabled.
    #[cfg(feature = "vault")]
    pub fn lock(&self) -> Result<()> {
        let guard = self.vault.read().map_err(|_| Error::LockPoisoned)?;
        let vault = guard.as_ref().ok_or(Error::VaultNotEnabled)?;
        vault.lock()?;
        self.invalidate_cache();
        self.events.notify_vault(crate::vault::VaultEvent::Locked);
        info!("Configuration vault locked");
        Ok(())
    }

    /// Unlock the configuration vault using the master key or password.
    ///
    /// Convenience alias for [`unlock`](Self::unlock).
    ///
    /// # Errors
    /// Returns `Error::VaultNotEnabled` if vault is not enabled, or `Error::InvalidPassword` if decryption fails.
    #[cfg(feature = "vault")]
    pub fn unlock_vault(&self, password: &str) -> Result<()> {
        self.unlock(password)
    }

    /// Lock the configuration vault immediately, wiping keys from memory.
    ///
    /// Convenience alias for [`lock`](Self::lock).
    ///
    /// # Errors
    /// Returns `Error::VaultNotEnabled` if vault is not enabled.
    #[cfg(feature = "vault")]
    pub fn lock_vault(&self) -> Result<()> {
        self.lock()
    }

    /// Snapshot all main settings (across all profiles) and sub-settings (across all profiles)
    /// into memory prior to enabling, disabling, or rotating vault keys.
    #[cfg(feature = "vault")]
    fn snapshot_for_vault_migration(&self) -> Result<VaultMigrationSnapshot<S>> {
        self.ensure_cache_populated()?;
        let active_value = self
            .settings_cache
            .get_stored()?
            .unwrap_or_else(|| json!({}));
        let active_path = self.settings_path()?;

        #[cfg(feature = "profiles")]
        let mut other_profiles = Vec::new();
        #[cfg(not(feature = "profiles"))]
        let other_profiles = Vec::new();

        #[cfg(feature = "profiles")]
        if let Some(ref pm) = self.profile_manager {
            let active_profile_name = pm.active().ok();
            if let Ok(all_profiles) = pm.list() {
                for p in all_profiles {
                    if Some(&p) != active_profile_name.as_ref() {
                        let profile_path = pm.profile_path(&p).join(&self.config.settings_file);
                        if profile_path.exists() {
                            let value = match self.read_settings_from_disk(&profile_path) {
                                Ok(v) => v,
                                Err(e) => {
                                    log::warn!("Failed to read settings for profile '{p}': {e}");
                                    json!({})
                                }
                            };
                            other_profiles.push((p, profile_path, value));
                        }
                    }
                }
            }
        }

        let mut sub_snapshots = Vec::new();
        if let Ok(sub_settings_map) = self.sub_settings.read_recovered() {
            for sub in sub_settings_map.values() {
                let mut profiles_data = Vec::new();

                #[cfg(feature = "profiles")]
                let orig_active = sub.profiles().ok().and_then(|pm| pm.active().ok());

                #[cfg(feature = "profiles")]
                if let Ok(pm) = sub.profiles()
                    && let Ok(profiles) = pm.list()
                {
                    for p in profiles {
                        let _ = sub.switch_profile(&p);
                        if let Ok(store) = sub.store.read_recovered()
                            && let Ok(all_entries) = store.get_all()
                        {
                            profiles_data.push((Some(p), all_entries.into_iter().collect()));
                        }
                    }
                }

                #[cfg(feature = "profiles")]
                if let Some(ref orig) = orig_active {
                    let _ = sub.switch_profile(orig);
                }

                if profiles_data.is_empty()
                    && let Ok(store) = sub.store.read_recovered()
                    && let Ok(all_entries) = store.get_all()
                {
                    profiles_data.push((None, all_entries.into_iter().collect()));
                }

                sub_snapshots.push(SubSettingsSnapshot {
                    sub: Arc::clone(sub),
                    profiles_data,
                });
            }
        }

        Ok(VaultMigrationSnapshot {
            active_settings: (active_path, active_value),
            other_profiles_settings: other_profiles,
            sub_settings_data: sub_snapshots,
        })
    }

    /// Re-apply a snapshot of settings and sub-settings to disk, either encrypted or decrypted.
    #[cfg(feature = "vault")]
    fn apply_vault_migration_snapshot(
        &self,
        snapshot: VaultMigrationSnapshot<S>,
        write_vault: bool,
    ) -> Result<()> {
        if write_vault {
            self.write_settings_to_disk(&snapshot.active_settings.0, &snapshot.active_settings.1)?;
            for (_name, path, value) in &snapshot.other_profiles_settings {
                self.write_settings_to_disk(path, value)?;
            }
        } else {
            self.storage
                .write(&snapshot.active_settings.0, &snapshot.active_settings.1)?;
            for (_name, path, value) in &snapshot.other_profiles_settings {
                self.storage.write(path, value)?;
            }
        }

        for item in snapshot.sub_settings_data {
            #[cfg(feature = "profiles")]
            let orig_profile = item.sub.profiles().ok().and_then(|pm| pm.active().ok());

            for (_opt_p, entries) in item.profiles_data {
                #[cfg(feature = "profiles")]
                if let Some(ref p) = _opt_p {
                    let _ = item.sub.switch_profile(p);
                }

                if let Ok(store) = item.sub.store.read_recovered() {
                    store.invalidate_cache();
                    for (key, value) in entries {
                        let _ = store.set(&key, value);
                    }
                }
            }

            #[cfg(feature = "profiles")]
            if let Some(ref orig) = orig_profile {
                let _ = item.sub.switch_profile(orig);
            }
            item.sub.invalidate_cache();
        }

        self.invalidate_cache();
        self.ensure_cache_populated()?;
        Ok(())
    }

    /// Set an initial vault password and encrypt current settings to disk across all profiles.
    ///
    /// # Errors
    /// Returns `Error::VaultNotEnabled` if vault is not enabled.
    #[cfg(feature = "vault")]
    pub fn set_vault_password(&self, password: &str) -> Result<()> {
        let guard = self.vault.read().map_err(|_| Error::LockPoisoned)?;
        let vault = guard.as_ref().ok_or(Error::VaultNotEnabled)?;
        let snapshot = self.snapshot_for_vault_migration()?;
        vault.unlock(password, None)?;

        self.apply_vault_migration_snapshot(snapshot, true)?;

        self.events
            .notify_vault(crate::vault::VaultEvent::PasswordChanged);
        info!("Configuration vault password set");
        Ok(())
    }

    /// Change the master password used to encrypt the configuration vault across all profiles.
    ///
    /// Generates a new salt, re-derives the key, re-encrypts all profile settings, and saves to disk.
    ///
    /// # Errors
    /// Returns:
    /// - `Error::VaultNotEnabled` if vault is not enabled
    /// - `Error::InvalidPassword` if `old_password` does not match
    #[cfg(feature = "vault")]
    pub fn change_vault_password(&self, old_password: &str, new_password: &str) -> Result<()> {
        if self.is_locked() {
            self.unlock(old_password)?;
        }

        let guard = self.vault.read().map_err(|_| Error::LockPoisoned)?;
        let vault = guard.as_ref().ok_or(Error::VaultNotEnabled)?;

        let snapshot = self.snapshot_for_vault_migration()?;

        vault.change_password(old_password, new_password)?;

        self.apply_vault_migration_snapshot(snapshot, true)?;

        self.events
            .notify_vault(crate::vault::VaultEvent::PasswordChanged);
        info!("Configuration vault password changed successfully");
        Ok(())
    }

    /// Enable vault encryption at runtime on an unencrypted configuration manager using default parameters.
    ///
    /// # Errors
    /// Returns error if encryption or saving fails.
    #[cfg(feature = "vault")]
    pub fn enable_vault(&self, password: &str) -> Result<()> {
        let params = self.config.vault_kdf_params.unwrap_or_default();
        self.enable_vault_with_params(password, params)
    }

    /// Enable vault encryption at runtime on an unencrypted configuration manager with custom KDF parameters.
    ///
    /// # Errors
    /// Returns error if encryption or saving fails.
    #[cfg(feature = "vault")]
    pub fn enable_vault_with_params(
        &self,
        password: &str,
        params: crate::vault::Argon2Params,
    ) -> Result<()> {
        let snapshot = self.snapshot_for_vault_migration()?;

        let new_vault = Arc::new(crate::vault::VaultState::new(
            None,
            self.config.vault_lock_timeout,
            Some(params),
        ));
        let events_clone = Arc::clone(&self.events);
        new_vault.set_event_callback(Some(Arc::new(move |event| {
            events_clone.notify_vault(event);
        })));

        new_vault.unlock(password, None)?;

        {
            let mut guard = self.vault.write().map_err(|_| Error::LockPoisoned)?;
            *guard = Some(new_vault);
        }

        self.apply_vault_migration_snapshot(snapshot, true)?;

        self.events.notify_vault(crate::vault::VaultEvent::Enabled);
        info!("Configuration vault enabled and encrypted across all profiles");
        Ok(())
    }

    /// Disable vault encryption, decrypting the configuration files across all profiles back to plain text.
    ///
    /// # Errors
    /// Returns `Error::InvalidPassword` if password is wrong, or `Error::VaultNotEnabled`.
    #[cfg(feature = "vault")]
    pub fn disable_vault(&self, password: &str) -> Result<()> {
        let vault = {
            let guard = self.vault.read().map_err(|_| Error::LockPoisoned)?;
            guard.clone().ok_or(Error::VaultNotEnabled)?
        };

        if vault.is_locked() {
            let settings_path = self.settings_path()?;
            let envelope = match self.storage.read::<Value>(&settings_path) {
                Ok(value) if crate::vault::is_vault_value(&value) => {
                    serde_json::from_value::<crate::vault::VaultEnvelope>(value).ok()
                }
                _ => None,
            };
            vault.unlock(password, envelope.as_ref())?;
        } else if !vault.verify_password(password, None)? {
            return Err(Error::InvalidPassword);
        }

        let snapshot = self.snapshot_for_vault_migration()?;

        {
            let mut guard = self.vault.write().map_err(|_| Error::LockPoisoned)?;
            *guard = None;
        }

        self.apply_vault_migration_snapshot(snapshot, false)?;

        self.events.notify_vault(crate::vault::VaultEvent::Disabled);
        info!("Configuration vault disabled; files stored as plaintext");
        Ok(())
    }
}
