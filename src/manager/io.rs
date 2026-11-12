#[cfg(any(feature = "keychain", feature = "encrypted-file"))]
use crate::config::SettingMetadata;
use crate::config::SettingsSchema;
use crate::error::{Error, Result};
use crate::manager::cache::CachedSettings;
use crate::manager::core::SettingsManager;
use crate::storage::StorageBackend;
use crate::utils::sync::RwLockExt;

use log::debug;
use serde_json::{Value, json};

/// One setting whose effective value a write changed.
#[derive(Debug, Clone, PartialEq)]
pub struct SettingChange {
    /// The full setting key, such as `"ui.theme"`.
    pub key: String,
    /// The value before the write.
    pub old: Value,
    /// The value after the write.
    pub new: Value,
}

impl<S: StorageBackend + 'static, Schema: SettingsSchema> SettingsManager<S, Schema> {
    /// Resolve the active profile name, or `None` if profiles are disabled.
    #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
    fn active_profile_name(&self) -> Result<Option<String>> {
        #[cfg(feature = "profiles")]
        {
            self.profile_manager
                .as_ref()
                .map(crate::profiles::ProfileManager::active)
                .transpose()
        }
        #[cfg(not(feature = "profiles"))]
        {
            Ok(None)
        }
    }

    #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
    fn require_credentials(&self) -> Result<&crate::credentials::CredentialManager> {
        self.credentials.as_ref().ok_or(Error::CredentialsDisabled)
    }

    /// The settings file the manager currently reads and writes.
    ///
    /// With profiles enabled this is the active profile's file.
    ///
    /// # Errors
    ///
    /// Returns an error if the active profile cannot be resolved.
    pub fn settings_path(&self) -> Result<std::path::PathBuf> {
        #[cfg(feature = "profiles")]
        if let Some(profiles) = &self.profile_manager {
            return Ok(profiles.active_path()?.join(&self.config.settings_file));
        }
        Ok(self.config.config_dir.join(&self.config.settings_file))
    }

    #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
    pub(crate) fn get_credential_with_profile(&self, key: &str) -> Result<Option<String>> {
        let creds = self.require_credentials()?;
        let profile = self.active_profile_name()?;
        creds.get_with_profile(key, profile.as_deref())
    }

    #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
    fn get_tracked_secrets(
        &self,
        profile: Option<&str>,
    ) -> Result<std::collections::HashSet<String>> {
        let creds = self.require_credentials()?;
        // Check if __rcman_secrets__ exists in credential store
        let (tracked_value, mut backend_unavailable) =
            creds.get_with_profile_status("__rcman_secrets__", profile)?;
        if tracked_value.is_none() {
            // Backward-compatible one-time fallback scan:
            // Scan all keys in the schema metadata to check what is in credentials
            let mut initial_tracked = std::collections::HashSet::new();
            for full_key in self.schema_metadata.keys() {
                let (value, unavailable) = creds.get_with_profile_status(full_key, profile)?;
                backend_unavailable |= unavailable;
                if value.is_some() {
                    initial_tracked.insert(full_key.clone());
                }
            }
            if !backend_unavailable {
                // Record the migration only after reads confirmed that the index is absent.
                self.is_upgraded
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                creds.save_tracked_secrets(&initial_tracked, profile)?;
            }
            return Ok(initial_tracked);
        }

        creds.get_tracked_secrets(profile)
    }

    /// Invalidate the settings cache.
    ///
    /// Call this if the settings file was modified externally.
    pub fn invalidate_cache(&self) {
        self.settings_cache.invalidate();

        #[cfg(feature = "profiles")]
        if let Some(pm) = &self.profile_manager {
            pm.invalidate_manifest();
        }

        #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
        if let Some(ref creds) = self.credentials
            && let Err(e) = creds.invalidate_tracked_secrets_cache()
        {
            debug!("Failed to invalidate tracked secrets cache: {e}");
        }

        if let Ok(sub_settings) = self.sub_settings.read_recovered() {
            for sub in sub_settings.values() {
                sub.invalidate_cache();
            }
        } else {
            debug!("Failed to invalidate sub-settings cache due to lock recovery error");
        }

        debug!("Settings cache invalidated");
    }

    /// Save a single setting value by its full key.
    ///
    /// Same as [`Self::set`], with the key given as category and name.
    ///
    /// # Errors
    ///
    /// See [`Self::set`].
    pub fn save_setting(&self, category: &str, key: &str, value: &Value) -> Result<()> {
        self.set(&format!("{category}.{key}"), value)
    }

    /// Save one setting by its full key, such as `"ui.theme"`.
    ///
    /// Validates the value, updates the cache, and writes to disk. Secret
    /// settings (when credentials are enabled) go to the credential store
    /// instead. Values equal to the default are removed from storage, and
    /// unchanged values produce no writes and no change events.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key is not in the schema, or the value cannot be serialized
    /// - Validation fails
    /// - Keyring storage or file writing fails
    ///
    /// # Examples
    ///
    /// ```
    /// # use rcman::*;
    /// # use serde::{Deserialize, Serialize};
    /// #[derive(Default, Serialize, Deserialize)]
    /// struct Model { ui: Ui }
    /// #[derive(Default, Serialize, Deserialize)]
    /// struct Ui { size: u32 }
    /// impl SettingsSchema for Model {
    ///     fn get_metadata() -> IndexMap<String, SettingMetadata> {
    ///         settings! { "ui.size" => SettingMetadata::integer(0_u32) }
    ///     }
    /// }
    /// # let dir = tempfile::tempdir().unwrap();
    /// let manager = SettingsManager::builder("app", "1.0")
    /// #   .with_config_dir(dir.path())
    ///     .with_schema::<Model>()
    ///     .build()?;
    /// manager.set("ui.size", &14_u32)?;
    /// assert_eq!(manager.get::<u32>("ui.size")?, 14);
    /// # Ok::<(), rcman::Error>(())
    /// ```
    pub fn set<T: serde::Serialize + ?Sized>(&self, key: &str, value: &T) -> Result<()> {
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter(&self.config.config_dir)?;
        #[cfg(feature = "vault")]
        if self.is_locked() {
            return Err(Error::ConfigLocked);
        }
        if Self::parse_setting_key(key).is_none() {
            return Err(Error::InvalidKey(key.to_owned()));
        }

        let mut value = serde_json::to_value(value)?;
        let metadata = self
            .schema_metadata
            .get(key)
            .ok_or_else(|| Error::SettingNotFound(key.to_owned()))?;
        metadata.normalize(&mut value);
        self.validate_value(key, metadata, &value)?;
        let guard = self.write_gate();
        self.ensure_cache_populated_inner()?;
        if crate::utils::value::same_value(&self.persisted_value(key, metadata)?, &value) {
            return Ok(());
        }
        let mut values = json!({});
        crate::utils::value::set_path(&mut values, key, value);
        let changes = self.commit_values(&values, Some(key), false)?;
        drop(guard);
        self.notify_changes(&changes);
        Ok(())
    }

    fn validate_value(
        &self,
        key: &str,
        metadata: &crate::SettingMetadata,
        value: &Value,
    ) -> Result<()> {
        #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
        let has_credentials = self.credentials.is_some();
        #[cfg(not(any(feature = "keychain", feature = "encrypted-file")))]
        let has_credentials = false;
        let is_default = crate::utils::value::same_value(value, &metadata.default);
        if metadata.is_secret() && !has_credentials && !is_default {
            return Err(Error::CredentialsDisabled);
        }
        // The default is always accepted: saving it removes the stored value,
        // so `reset_setting` works even for an "unset" default such as `""`.
        if !is_default {
            metadata
                .validate(value)
                .map_err(|reason| Error::InvalidSettingValue {
                    key: key.to_owned(),
                    reason,
                })?;
        }
        self.events
            .validate(key, value)
            .map_err(|reason| Error::InvalidSettingValue {
                key: key.to_owned(),
                reason: crate::config::ValidationError::Custom(reason),
            })
    }

    fn notify_changes(&self, changes: &[SettingChange]) {
        for change in changes {
            self.events.notify(&change.key, &change.old, &change.new);
        }
    }

    /// Validate every schema field before beginning bulk writes.
    fn validate_schema_values(&self, value: &Value) -> Result<()> {
        for (key, metadata) in self.schema_metadata.iter() {
            let new_value = crate::utils::value::get_path(value, key).unwrap_or(&metadata.default);
            self.validate_value(key, metadata, new_value)?;
        }
        Ok(())
    }

    /// Save all settings from a strongly-typed schema model instance.
    ///
    /// On an ordinary backend error, earlier credential writes are rolled back.
    /// Rollback failures are reported as `Error::TransactionFailed`. This is not
    /// crash-atomic across the filesystem and OS credential store. Direct access
    /// to the backends or other manager instances requires caller coordination.
    /// Credential writes use the first reachable persistent backend. When none is
    /// reachable, new values are held in volatile memory (see
    /// `CredentialManager::is_volatile_active`) and a warning is logged; removals
    /// and errors from a reachable backend are still returned.
    ///
    /// Performs pre-validation, updates stored settings, routes secret settings to keychain,
    /// removes default values to keep storage minimal, and dispatches change events.
    ///
    /// Returns the settings whose effective value changed, in schema order.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Validation fails for any setting
    /// - Storage write fails
    /// - Keyring storage fails
    pub fn save_all(&self, schema: &Schema) -> Result<Vec<SettingChange>> {
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter(&self.config.config_dir)?;
        let value = serde_json::to_value(schema)?;
        self.validate_schema_values(&value)?;
        let guard = self.write_gate();
        self.ensure_cache_populated_inner()?;
        let changes = self.commit_values(&value, None, false)?;
        drop(guard);
        self.notify_changes(&changes);
        Ok(changes)
    }

    // Caller holds settings_write_lock and has validated candidates. Stage every
    // value before mutating a backend, then commit credentials and the file.
    fn commit_values(
        &self,
        value: &Value,
        only_key: Option<&str>,
        clear_stored: bool,
    ) -> Result<Vec<SettingChange>> {
        #[cfg(feature = "vault")]
        if self.is_locked() {
            return Err(Error::ConfigLocked);
        }
        let mut stored = self
            .settings_cache
            .get_stored()?
            .ok_or(Error::NotInitialized)?;
        let mut notifications = Vec::new();
        let mut stored_modified = clear_stored && stored != json!({});
        if clear_stored {
            stored = json!({});
        }
        #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
        let mut secrets = Vec::new();
        let range = match only_key {
            Some(key) => {
                let index = self
                    .schema_metadata
                    .get_index_of(key)
                    .ok_or_else(|| Error::SettingNotFound(key.to_owned()))?;
                index..index + 1
            }
            None => 0..self.schema_metadata.len(),
        };
        for (key, metadata) in &self.schema_metadata[range] {
            let new = crate::utils::value::get_path(value, key).unwrap_or(&metadata.default);
            let old = self.persisted_value(key, metadata)?;
            if crate::utils::value::same_value(&old, new) {
                continue;
            }
            let is_default = crate::utils::value::same_value(new, &metadata.default);
            notifications.push(SettingChange {
                key: key.clone(),
                old,
                new: new.clone(),
            });
            if metadata.is_secret() {
                #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
                {
                    let encoded = if is_default {
                        None
                    } else {
                        Some(crate::credentials::encode_setting(new))
                    };
                    secrets.push((key.clone(), encoded));
                }
                #[cfg(not(any(feature = "keychain", feature = "encrypted-file")))]
                return Err(Error::CredentialsDisabled);
            } else {
                stored_modified = true;
                if is_default {
                    crate::utils::value::remove_path(&mut stored, key);
                } else {
                    crate::utils::value::set_path(&mut stored, key, new.clone());
                }
            }
        }
        if notifications.is_empty() && !stored_modified {
            return Ok(notifications);
        }
        crate::utils::value::prune_empty_objects(&mut stored);
        let finish = || -> Result<()> {
            if stored_modified {
                self.commit_file(&stored)?;
            }
            Ok(())
        };
        #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
        if secrets.is_empty() {
            finish()?;
        } else {
            let profile = self.active_profile_name()?;
            self.require_credentials()?
                .commit_settings(&secrets, profile.as_deref(), finish)?;
        }
        #[cfg(not(any(feature = "keychain", feature = "encrypted-file")))]
        finish()?;
        if stored_modified {
            self.settings_cache.update_stored(stored)?;
        }
        Ok(notifications)
    }

    // Preserve the raw envelope, including encryption, when undoing an I/O error.
    fn commit_file(&self, value: &Value) -> Result<()> {
        self.commit_file_at(&self.settings_path()?, value)
    }

    fn commit_file_at(&self, path: &std::path::Path, value: &Value) -> Result<()> {
        let original: Option<Value> = crate::error::optional(self.storage.read(path))?;
        // Refuse to replace a file the current vault key cannot read; the raw
        // copy kept for rollback serves for the check, so the file is read once.
        #[cfg(feature = "vault")]
        if let Some(raw) = &original {
            self.decode_settings(path, raw.clone())?;
        }
        if let Err(source) = self.write_settings_snapshot(path, value) {
            let restored = match original {
                Some(value) => self.storage.write(path, &value),
                None => self.storage.remove(path),
            };
            self.settings_cache.invalidate();
            return match restored {
                Ok(()) => Err(source),
                Err(error) => Err(Error::TransactionFailed {
                    source: Box::new(source),
                    rollback_errors: vec![error.to_string()],
                }),
            };
        }
        Ok(())
    }

    /// Mutate settings using a closure with full compile-time struct field type-safety.
    ///
    /// Loads current settings, applies the closure, validates, saves, routes secrets to keychain,
    /// and dispatches change events for modified fields. Environment overrides are
    /// excluded so unrelated edits do not persist transient environment values.
    /// The closure runs without internal locks; concurrent changes cause
    /// `Error::ConcurrentModification` instead of overwriting another writer.
    ///
    /// # Errors
    ///
    /// Returns an error if loading current settings fails, validation fails, or saving fails.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use rcman::{SettingsManager, SettingsSchema, SettingMetadata, settings};
    /// # use serde::{Serialize, Deserialize};
    /// # #[derive(Default, Serialize, Deserialize, Clone)] struct MySettings { theme: String }
    /// # impl SettingsSchema for MySettings {
    /// #     fn get_metadata() -> rcman::IndexMap<String, SettingMetadata> { rcman::IndexMap::new() }
    /// # }
    /// # let manager = SettingsManager::builder("app", "1.0").with_schema::<MySettings>().build().unwrap();
    /// manager.update(|settings| {
    ///     settings.theme = "dark".to_string();
    /// }).unwrap();
    /// ```
    pub fn update<F>(&self, f: F) -> Result<Schema>
    where
        F: FnOnce(&mut Schema),
    {
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter(&self.config.config_dir)?;
        // Keep arbitrary user code outside locks. Compare the persisted snapshot
        // at commit so reentrant/concurrent writes cannot silently be overwritten.
        let (snapshot, snapshot_path) = {
            let _guard = self.write_gate();
            (self.read_all_data(false)?, self.settings_path()?)
        };
        let mut current: Schema =
            serde_json::from_value(snapshot.clone()).map_err(|source| Error::Deserialize {
                key: "*".to_owned(),
                source,
            })?;
        f(&mut current);
        let value = serde_json::to_value(&current)?;
        self.validate_schema_values(&value)?;
        let guard = self.write_gate();
        if self.settings_path()? != snapshot_path || self.read_all_data(false)? != snapshot {
            return Err(Error::ConcurrentModification);
        }
        let changes = self.commit_values(&value, None, false)?;
        drop(guard);
        self.notify_changes(&changes);
        Ok(current)
    }

    /// Reset a single setting to its schema default.
    ///
    /// # Errors
    ///
    /// Returns an error if the setting key is not found in the schema,
    /// or if saving the default value fails.
    pub fn reset_setting(&self, category: &str, key: &str) -> Result<Value> {
        self.reset(&format!("{category}.{key}"))
    }

    /// Reset one setting, given by its full key, to its schema default.
    ///
    /// Returns the default. Like [`Self::set`], an unchanged value emits nothing.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is not in the schema or saving fails.
    pub fn reset(&self, key: &str) -> Result<Value> {
        let default_value = self
            .schema_metadata
            .get(key)
            .map(|m| m.default.clone())
            .ok_or_else(|| Error::SettingNotFound(key.to_owned()))?;
        self.set(key, &default_value)?;
        debug!("Setting {key} reset to default");
        Ok(default_value)
    }

    /// Reset the active main settings to defaults, including unknown file keys.
    ///
    /// Credentials belonging to sub-settings or other profiles are preserved.
    /// Uses the same rollback behavior as [`Self::save_all`].
    ///
    /// Returns the settings whose effective value changed, in schema order.
    ///
    /// # Errors
    ///
    /// Returns an error if writing to storage fails or credential clearing fails.
    pub fn reset_all(&self) -> Result<Vec<SettingChange>> {
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter(&self.config.config_dir)?;
        #[cfg(feature = "vault")]
        if self.is_locked() {
            return Err(Error::ConfigLocked);
        }

        let guard = self.write_gate();
        self.ensure_cache_populated_inner()?;
        let mut defaults = json!({});
        for (key, metadata) in self.schema_metadata.iter() {
            crate::utils::value::set_path(&mut defaults, key, metadata.default.clone());
        }
        let changes = self.commit_values(&defaults, None, true)?;
        drop(guard);
        self.notify_changes(&changes);
        Ok(changes)
    }

    /// Read settings from disk, automatically decrypting if the file is an rcman vault.
    pub(crate) fn read_settings_from_disk(&self, path: &std::path::Path) -> Result<Value> {
        let value = self.storage.read(path)?;
        #[cfg(feature = "vault")]
        let value = self.decode_settings(path, value)?;
        Ok(value)
    }

    /// Decrypt a raw settings value read from `path`, or reject a vault file
    /// when the vault is not enabled.
    #[cfg(feature = "vault")]
    fn decode_settings(&self, path: &std::path::Path, value: Value) -> Result<Value> {
        let guard = self.vault.read().map_err(|_| Error::LockPoisoned)?;
        if let Some(vault) = guard.as_ref() {
            let plaintext =
                vault.decrypt_managed(&value, path, self.storage.vault_entry_id().as_deref())?;
            return self.storage.deserialize(&plaintext);
        } else if value.get("__rcman_vault__").is_some() {
            return Err(Error::VaultNotFound);
        }
        Ok(value)
    }

    /// Write settings value to disk, automatically encrypting if vault is enabled.
    pub(crate) fn write_settings_to_disk(
        &self,
        path: &std::path::Path,
        value: &Value,
    ) -> Result<()> {
        #[cfg(feature = "vault")]
        crate::error::optional(self.read_settings_from_disk(path))?;
        self.write_settings_snapshot(path, value)
    }

    /// Persist a trusted snapshot without reading data encrypted with a previous key.
    pub(super) fn write_settings_snapshot(
        &self,
        path: &std::path::Path,
        value: &Value,
    ) -> Result<()> {
        #[cfg(feature = "backup")]
        crate::backup::transaction::capture_file(path)?;
        #[cfg(feature = "vault")]
        {
            let guard = self.vault.read().map_err(|_| Error::LockPoisoned)?;
            if let Some(ref vault) = *guard {
                if vault.is_locked() {
                    return Err(Error::ConfigLocked);
                }
                let serialized = self.storage.serialize(value)?;
                let envelope = vault.encrypt_managed(
                    serialized.as_bytes(),
                    path,
                    self.storage.vault_entry_id().as_deref(),
                )?;
                self.storage.write(path, &envelope)?;
                vault.touch();
                return Ok(());
            }
        }

        self.storage.write(path, value)
    }

    /// Load settings from disk, applying migrations if needed.
    pub(crate) fn load_from_disk(&self) -> Result<CachedSettings> {
        let settings_path = self.settings_path()?;
        let mut value = crate::error::optional(self.read_settings_from_disk(&settings_path))?
            .unwrap_or_else(|| json!({}));

        // Apply migrations
        if let Some(migrator) = &self.config.migrator {
            let original = value.clone();
            value = migrator(value);
            if value != original {
                debug!("Migrated settings file");
                self.write_settings_to_disk(&settings_path, &value)?;
            }
        }

        // Strip null values: null in a settings file is a legacy artifact from
        // older code that used Option<T> fields (serialized as null when None),
        // and would clobber schema defaults. A nullable setting saved as null
        // over a non-null default is a real value, so it is kept.
        let saved_nulls: Vec<&String> = self
            .schema_metadata
            .iter()
            .filter(|(key, metadata)| {
                metadata.nullable
                    && crate::utils::value::get_path(&value, key).is_some_and(Value::is_null)
            })
            .map(|(key, _)| key)
            .collect();
        crate::utils::value::strip_nulls(&mut value);
        for key in saved_nulls {
            crate::utils::value::set_path(&mut value, key, Value::Null);
        }

        Ok(CachedSettings {
            stored: value,
            merged: None,
            defaults: self.schema_defaults.clone(),
        })
    }

    /// Ensure the settings cache is populated.
    ///
    /// Thread-safe — `populate()` acquires a write lock internally and
    /// double-checks, so redundant calls are cheap.
    ///
    /// # Errors
    ///
    /// Returns an error if loading from disk or parsing fails.
    pub fn ensure_cache_populated(&self) -> Result<()> {
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter(&self.config.config_dir)?;
        let _guard = self.read_gate();
        self.ensure_cache_populated_inner()
    }

    pub(super) fn ensure_cache_populated_inner(&self) -> Result<()> {
        #[cfg(feature = "vault")]
        if self.is_locked() {
            return Err(Error::ConfigLocked);
        }

        self.settings_cache
            .populate(&self.settings_path()?, || self.load_from_disk())
    }

    /// Migrate settings between the settings file and credential store if their secret schema status has changed.
    #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
    pub(crate) fn migrate_secret_keys(&self) -> Result<()> {
        let _guard = self.write_gate();
        let profile = self.active_profile_name()?;
        self.migrate_secret_keys_locked(&self.settings_path()?, profile.as_deref())
    }

    #[cfg(all(
        feature = "vault",
        feature = "profiles",
        any(feature = "keychain", feature = "encrypted-file")
    ))]
    pub(super) fn migrate_secret_keys_in(
        &self,
        path: &std::path::Path,
        profile: Option<&str>,
    ) -> Result<()> {
        let _write_guard = self.write_gate();
        self.migrate_secret_keys_locked(path, profile)
    }

    #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
    fn migrate_secret_keys_locked(
        &self,
        path: &std::path::Path,
        profile: Option<&str>,
    ) -> Result<()> {
        if self.credentials.is_none() {
            return Ok(());
        }
        let mut stored = crate::error::optional(self.read_settings_from_disk(path))?
            .unwrap_or_else(|| json!({}));
        let original = stored.clone();
        if let Some(migrator) = &self.config.migrator {
            stored = migrator(stored);
        }
        let creds = self.require_credentials()?;
        let tracked = self.get_tracked_secrets(profile)?;
        let mut changes = Vec::new();
        for (key, metadata) in self.schema_metadata.iter() {
            if metadata.is_secret()
                && let Some(value) = crate::utils::value::remove_path(&mut stored, key)
            {
                // Normalizers can recreate absent secret defaults. The credential
                // store remains authoritative after an earlier extraction.
                if value == metadata.default && creds.get_with_profile(key, profile)?.is_some() {
                    continue;
                }
                changes.push((
                    key.clone(),
                    (value != metadata.default).then(|| crate::credentials::encode_setting(&value)),
                ));
            }
        }
        for key in tracked {
            if key.starts_with("sub.") && !self.schema_metadata.contains_key(&key) {
                continue;
            }
            let metadata = self.schema_metadata.get(&key);
            if let Some(value) =
                migrate_tracked_secret(creds, &key, metadata, profile, &mut changes)?
            {
                crate::utils::value::set_path(&mut stored, &key, value);
            }
        }
        crate::utils::value::prune_empty_objects(&mut stored);
        creds.commit_settings(&changes, profile, || {
            if stored != original {
                self.commit_file_at(path, &stored)?;
            }
            Ok(())
        })?;
        if stored != original {
            self.settings_cache.invalidate();
        }
        Ok(())
    }

    /// Migrate sub-settings secret keys between the sub-settings files and credential store if their secret schema status has changed.
    #[cfg(all(
        any(feature = "keychain", feature = "encrypted-file"),
        any(not(feature = "vault"), feature = "profiles")
    ))]
    pub(crate) fn migrate_sub_settings_secret_keys(
        &self,
        sub: &crate::sub_settings::SubSettings<S>,
    ) -> Result<()> {
        let _guard = sub.operation_lock.write_recovered()?;
        let profile = sub.active_secret_profile()?;
        let store = sub.active_store()?;
        self.migrate_sub_settings_secrets_in(sub, &**store, profile.as_deref())
    }

    #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
    pub(super) fn migrate_sub_settings_secrets_in(
        &self,
        sub: &crate::sub_settings::SubSettings<S>,
        store: &dyn crate::sub_settings::SubSettingsStore,
        profile: Option<&str>,
    ) -> Result<()> {
        if self.credentials.is_none() {
            return Ok(());
        }
        let Some(schema) = sub.config.schema.as_ref() else {
            return Ok(());
        };
        let creds = self.require_credentials()?;
        let tracked = creds.get_tracked_secrets(profile)?;
        let mut entries = indexmap::IndexMap::new();
        let mut changes = Vec::new();
        for name in store.list()? {
            let mut value = store.get(&name)?;
            let mut modified = false;
            for (path, metadata) in schema.iter().filter(|(_, metadata)| metadata.is_secret()) {
                let key = sub.secret_credential_key(&name, path);
                if let Some(secret) = crate::utils::value::remove_path(&mut value, path) {
                    modified = true;
                    if secret != metadata.default
                        || creds.get_with_profile(&key, profile)?.is_none()
                    {
                        changes.push((
                            key,
                            (secret != metadata.default)
                                .then(|| crate::credentials::encode_setting(&secret)),
                        ));
                    }
                } else if self.is_upgraded.load(std::sync::atomic::Ordering::Relaxed)
                    && let Some(secret) = creds.get_with_profile(&key, profile)?
                {
                    changes.push((key, Some(secret)));
                }
            }
            if modified {
                entries.insert(name, Some(value));
            }
        }
        let prefix = format!("sub.{}.", sub.config.name);
        for key in tracked {
            let Some(suffix) = key.strip_prefix(&prefix) else {
                continue;
            };
            let Some((name, path)) = suffix.split_once('.') else {
                continue;
            };
            let metadata = schema.get(path);
            if let Some(value) =
                migrate_tracked_secret(creds, &key, metadata, profile, &mut changes)?
            {
                if !entries.contains_key(name) {
                    let original = match store.get(name) {
                        Ok(value) => value,
                        Err(Error::SubSettingsEntryNotFound(_)) => json!({}),
                        Err(error) => return Err(error),
                    };
                    entries.insert(name.to_owned(), Some(original));
                }
                if let Some(Some(entry)) = entries.get_mut(name) {
                    crate::utils::value::set_path(entry, path, value);
                }
            }
        }
        let entries: Vec<_> = entries.into_iter().collect();
        creds.commit_settings(&changes, profile, || {
            crate::sub_settings::SubSettings::<S>::commit_entries(store, &entries)
        })
    }
}

/// Plan the migration of one credential the store tracks, after the schema
/// may have changed which settings are secret.
///
/// A key that is still secret is dropped only when its credential is confirmed
/// absent: unreadable credentials stay tracked, and a pending extraction in
/// `changes` is not overwritten. A key that is no longer secret is removed from
/// the credential store; its non-default value is returned so the caller moves
/// it back into the settings file.
#[cfg(any(feature = "keychain", feature = "encrypted-file"))]
fn migrate_tracked_secret(
    creds: &crate::credentials::CredentialManager,
    key: &str,
    metadata: Option<&SettingMetadata>,
    profile: Option<&str>,
    changes: &mut Vec<(String, Option<String>)>,
) -> Result<Option<Value>> {
    if metadata.is_some_and(SettingMetadata::is_secret) {
        if !changes.iter().any(|(changed, _)| changed == key)
            && matches!(creds.try_exists_with_profile(key, profile), Ok(false))
        {
            changes.push((key.to_owned(), None));
        }
        return Ok(None);
    }
    let value = match (creds.get_with_profile(key, profile)?, metadata) {
        (Some(secret), Some(metadata)) => {
            let value = crate::credentials::decode_setting(&secret, metadata)?;
            (value != metadata.default).then_some(value)
        }
        _ => None,
    };
    changes.push((key.to_owned(), None));
    Ok(value)
}
