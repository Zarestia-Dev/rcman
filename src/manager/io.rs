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
        self.credentials
            .as_ref()
            .ok_or(Error::Credential("Credentials not enabled".to_string()))
    }

    /// Get the current settings file path.
    ///
    /// If profiles are enabled, this points to the active profile's directory.
    pub(crate) fn settings_path(&self) -> Result<std::path::PathBuf> {
        let dir = self.settings_dir.read_recovered()?;
        Ok(dir.join(&self.config.settings_file))
    }

    #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
    pub(crate) fn get_credential_with_profile(&self, key: &str) -> Result<Option<String>> {
        let creds = self.require_credentials()?;
        let profile = self.active_profile_name()?;
        creds.get_with_profile(key, profile.as_deref())
    }

    #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
    fn get_tracked_secrets(&self) -> Result<std::collections::HashSet<String>> {
        let creds = self.require_credentials()?;
        let profile = self.active_profile_name()?;
        let profile_ref = profile.as_deref();

        // Check if __rcman_secrets__ exists in credential store
        if self
            .get_credential_with_profile("__rcman_secrets__")?
            .is_none()
        {
            // Set the is_upgraded flag to indicate we did a fallback scan
            self.is_upgraded
                .store(true, std::sync::atomic::Ordering::Relaxed);

            // Backward-compatible one-time fallback scan:
            // Scan all keys in the schema metadata to check what is in credentials
            let mut initial_tracked = std::collections::HashSet::new();
            for full_key in self.schema_metadata.keys() {
                if self.get_credential_with_profile(full_key)?.is_some() {
                    initial_tracked.insert(full_key.clone());
                }
            }
            creds.save_tracked_secrets(&initial_tracked, profile_ref)?;
            return Ok(initial_tracked);
        }

        creds.get_tracked_secrets(profile_ref)
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

    /// Save a single setting value.
    ///
    /// Validates the value, updates the cache, and writes to disk.
    /// Secret settings (when credentials are enabled) are routed to the OS
    /// keychain instead. Values equal to the default are removed from storage.
    /// Unchanged values produce no writes. Credential reads may still be required.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Validation fails
    /// - Keyring storage or file writing fails
    /// - Serialization or parsing fails
    pub fn save_setting(&self, category: &str, key: &str, value: &Value) -> Result<()> {
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter(&self.config.config_dir)?;
        #[cfg(feature = "vault")]
        if self.is_locked() {
            return Err(Error::ConfigLocked);
        }

        let full_key = format!("{category}.{key}");
        let metadata = self
            .schema_metadata
            .get(&full_key)
            .ok_or_else(|| Error::SettingNotFound(full_key.clone()))?;
        self.validate_value(&full_key, metadata, value)?;
        let guard = self
            .settings_write_lock
            .write()
            .map_err(|_| Error::LockPoisoned)?;
        self.ensure_cache_populated_inner()?;
        let old_value = self.persisted_value(&full_key, metadata)?;
        if old_value == *value {
            return Ok(());
        }
        let mut values = json!({});
        crate::utils::value::set_path(&mut values, &full_key, value.clone());
        let notifications = self.commit_values(&values, Some(&full_key), false)?;
        drop(guard);
        self.notify_changes(notifications);
        Ok(())
    }

    fn validate_value(
        &self,
        key: &str,
        metadata: &crate::SettingMetadata,
        value: &Value,
    ) -> Result<()> {
        if metadata.is_secret() {
            #[cfg(not(any(feature = "keychain", feature = "encrypted-file")))]
            if *value != metadata.default {
                return Err(Error::Credential(
                    "Secret storage requires keychain or encrypted-file".into(),
                ));
            }
            #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
            if self.credentials.is_none() && *value != metadata.default {
                return Err(Error::Credential("Credentials not enabled".into()));
            }
        }
        metadata
            .validate(value)
            .map_err(|reason| Error::InvalidSettingValue {
                key: key.to_owned(),
                reason,
            })?;
        self.events
            .validate(key, value)
            .map_err(|reason| Error::InvalidSettingValue {
                key: key.to_owned(),
                reason,
            })
    }

    fn notify_changes(&self, notifications: Vec<(String, Value, Value)>) {
        for (key, old, new) in notifications {
            self.events.notify(&key, &old, &new);
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
    /// Credential writes require a readable, writable primary backend; no silent
    /// fallback to volatile storage is performed by managed saves.
    ///
    /// Performs pre-validation, updates stored settings, routes secret settings to keychain,
    /// removes default values to keep storage minimal, and dispatches change events.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Validation fails for any setting
    /// - Storage write fails
    /// - Keyring storage fails
    pub fn save_all(&self, schema: &Schema) -> Result<()> {
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter(&self.config.config_dir)?;
        let value = serde_json::to_value(schema).map_err(|e| Error::Parse(e.to_string()))?;
        self.validate_schema_values(&value)?;
        let guard = self
            .settings_write_lock
            .write()
            .map_err(|_| Error::LockPoisoned)?;
        self.ensure_cache_populated_inner()?;
        let notifications = self.commit_values(&value, None, false)?;
        drop(guard);
        self.notify_changes(notifications);
        Ok(())
    }

    // Caller holds settings_write_lock and has validated candidates. Stage every
    // value before mutating a backend, then commit credentials and the file.
    fn commit_values(
        &self,
        value: &Value,
        only_key: Option<&str>,
        clear_stored: bool,
    ) -> Result<Vec<(String, Value, Value)>> {
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
            if old == *new {
                continue;
            }
            notifications.push((key.clone(), old, new.clone()));
            if metadata.is_secret() {
                #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
                {
                    let encoded = if *new == metadata.default {
                        None
                    } else {
                        Some(crate::credentials::encode_setting(new))
                    };
                    secrets.push((key.clone(), encoded));
                }
                #[cfg(not(any(feature = "keychain", feature = "encrypted-file")))]
                return Err(Error::Credential(
                    "Secret storage requires keychain or encrypted-file".into(),
                ));
            } else {
                stored_modified = true;
                if *new == metadata.default {
                    crate::utils::value::remove_path(&mut stored, key);
                } else {
                    crate::utils::value::set_path(&mut stored, key, new.clone());
                }
            }
        }
        if notifications.is_empty() && !stored_modified {
            return Ok(notifications);
        }
        if let Some(object) = stored.as_object_mut() {
            object.retain(|_, value| !value.as_object().is_some_and(serde_json::Map::is_empty));
        }
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
        let path = self.settings_path()?;
        let original: Option<Value> = match self.storage.read(&path) {
            Ok(value) => Some(value),
            Err(Error::PathNotFound(_)) => None,
            Err(Error::FileRead { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                None
            }
            Err(error) => return Err(error),
        };
        if let Err(source) = self.write_settings_to_disk(&path, value) {
            let restored = match original {
                Some(value) => self.storage.write(&path, &value),
                None => self.storage.remove(&path),
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
            let _guard = self
                .settings_write_lock
                .write()
                .map_err(|_| Error::LockPoisoned)?;
            (self.read_all_data(false)?, self.settings_path()?)
        };
        let mut current: Schema = serde_json::from_value(snapshot.clone())?;
        f(&mut current);
        let value = serde_json::to_value(&current)?;
        self.validate_schema_values(&value)?;
        let guard = self
            .settings_write_lock
            .write()
            .map_err(|_| Error::LockPoisoned)?;
        if self.settings_path()? != snapshot_path || self.read_all_data(false)? != snapshot {
            return Err(Error::ConcurrentModification);
        }
        let notifications = self.commit_values(&value, None, false)?;
        drop(guard);
        self.notify_changes(notifications);
        Ok(current)
    }

    /// Reset a single setting to its schema default.
    ///
    /// # Errors
    ///
    /// Returns an error if the setting key is not found in the schema,
    /// or if saving the default value fails.
    pub fn reset_setting(&self, category: &str, key: &str) -> Result<Value> {
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter(&self.config.config_dir)?;
        let metadata_key = format!("{category}.{key}");
        let default_value = self
            .schema_metadata
            .get(&metadata_key)
            .map(|m| m.default.clone())
            .ok_or_else(|| Error::SettingNotFound(format!("{category}.{key}")))?;

        self.save_setting(category, key, &default_value)?;

        debug!("Setting {category}.{key} reset to default");
        Ok(default_value)
    }

    /// Reset the active main settings to defaults, including unknown file keys.
    ///
    /// Credentials belonging to sub-settings or other profiles are preserved.
    /// Uses the same rollback behavior as [`Self::save_all`].
    ///
    /// # Errors
    ///
    /// Returns an error if writing to storage fails or credential clearing fails.
    pub fn reset_all(&self) -> Result<()> {
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter(&self.config.config_dir)?;
        #[cfg(feature = "vault")]
        if self.is_locked() {
            return Err(Error::ConfigLocked);
        }

        let guard = self
            .settings_write_lock
            .write()
            .map_err(|_| Error::LockPoisoned)?;
        self.ensure_cache_populated_inner()?;
        let mut defaults = json!({});
        for (key, metadata) in self.schema_metadata.iter() {
            crate::utils::value::set_path(&mut defaults, key, metadata.default.clone());
        }
        let notifications = self.commit_values(&defaults, None, true)?;
        drop(guard);
        self.notify_changes(notifications);
        Ok(())
    }

    /// Read settings from disk, automatically decrypting if the file is an rcman vault.
    pub(crate) fn read_settings_from_disk(&self, path: &std::path::Path) -> Result<Value> {
        let value: Value = self.storage.read(path)?;

        #[cfg(feature = "vault")]
        if crate::vault::is_vault_value(&value) {
            let envelope: crate::vault::VaultEnvelope = serde_json::from_value(value)
                .map_err(|e| Error::InvalidVaultEnvelope(format!("Invalid vault envelope: {e}")))?;
            let guard = self.vault.read().map_err(|_| Error::LockPoisoned)?;
            let Some(ref vault) = *guard else {
                return Err(Error::ConfigLocked);
            };
            if vault.is_locked() {
                return Err(Error::ConfigLocked);
            }
            let decrypted_bytes = vault.decrypt_envelope(&envelope)?;
            let decrypted_str = String::from_utf8(decrypted_bytes)
                .map_err(|e| Error::Vault(format!("Decrypted settings is not UTF-8: {e}")))?;
            return self.storage.deserialize(&decrypted_str);
        }

        Ok(value)
    }

    /// Write settings value to disk, automatically encrypting if vault is enabled.
    pub(crate) fn write_settings_to_disk(
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
                let envelope = vault.encrypt_payload(serialized.as_bytes())?;
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
        let mut value: Value = match self.read_settings_from_disk(&settings_path) {
            Ok(v) => v,
            #[cfg(feature = "vault")]
            Err(Error::ConfigLocked) => return Err(Error::ConfigLocked),
            Err(Error::PathNotFound(_)) => json!({}),
            Err(Error::FileRead { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                json!({})
            }
            Err(e) => return Err(e),
        };

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
        // older code that used Option<T> fields (serialized as null when None).
        // rcman never writes null — it removes keys equal to the default instead.
        // Stripping here keeps deep_merge a pure function and prevents null from
        // clobbering schema defaults.
        crate::utils::value::strip_nulls(&mut value);

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
        self.ensure_cache_populated_inner()
    }

    pub(super) fn ensure_cache_populated_inner(&self) -> Result<()> {
        #[cfg(feature = "vault")]
        if self.is_locked() {
            return Err(Error::ConfigLocked);
        }

        self.settings_cache.populate(|| self.load_from_disk())
    }

    /// Migrate settings between the settings file and credential store if their secret schema status has changed.
    #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
    pub(crate) fn migrate_secret_keys(&self) -> Result<()> {
        if self.credentials.is_none() {
            return Ok(());
        }

        let _write_guard = self
            .settings_write_lock
            .write()
            .map_err(|_| Error::Config("Settings write lock poisoned".into()))?;

        let path = self.settings_path()?;
        let mut stored: Value = match self.read_settings_from_disk(&path) {
            Ok(v) => v,
            Err(Error::PathNotFound(_)) => json!({}),
            Err(Error::FileRead { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                json!({})
            }
            Err(error) => return Err(error),
        };
        let original = stored.clone();
        let tracked = self.get_tracked_secrets()?;
        let mut changes = Vec::new();
        for (key, metadata) in self.schema_metadata.iter() {
            if metadata.is_secret()
                && let Some(value) = crate::utils::value::remove_path(&mut stored, key)
            {
                changes.push((
                    key.clone(),
                    (value != metadata.default).then(|| crate::credentials::encode_setting(&value)),
                ));
            }
        }
        for key in tracked {
            if key.starts_with("sub.") {
                continue;
            }
            let metadata = self.schema_metadata.get(&key);
            if metadata.is_some_and(SettingMetadata::is_secret) {
                continue;
            }
            if let Some(value) = self.get_credential_with_profile(&key)?
                && let Some(metadata) = metadata
            {
                let value = crate::credentials::decode_setting(&value, metadata)?;
                if value != metadata.default {
                    crate::utils::value::set_path(&mut stored, &key, value);
                }
            }
            changes.push((key, None));
        }
        if let Some(object) = stored.as_object_mut() {
            object.retain(|_, value| !value.as_object().is_some_and(serde_json::Map::is_empty));
        }
        let profile = self.active_profile_name()?;
        self.require_credentials()?
            .commit_settings(&changes, profile.as_deref(), || {
                if stored != original {
                    self.commit_file(&stored)?;
                }
                Ok(())
            })?;
        if stored != original {
            self.settings_cache.update_stored(stored)?;
        }
        Ok(())
    }

    /// Migrate sub-settings secret keys between the sub-settings files and credential store if their secret schema status has changed.
    #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
    pub(crate) fn migrate_sub_settings_secret_keys(
        &self,
        sub: &crate::sub_settings::SubSettings<S>,
    ) -> Result<()> {
        if self.credentials.is_none() {
            return Ok(());
        }

        let Some(schema) = sub.config.schema.as_ref() else {
            return Ok(());
        };

        let _guard = sub.operation_lock.write_recovered()?;
        let creds = self.require_credentials()?;
        let profile = sub.active_secret_profile()?;
        let tracked = creds.get_tracked_secrets(profile.as_deref())?;
        let store = sub.store.read_recovered()?;
        let mut entries = indexmap::IndexMap::new();
        let mut changes = Vec::new();
        for name in store.list()? {
            let mut value = store.get(&name)?;
            let mut modified = false;
            for (path, metadata) in schema.iter().filter(|(_, metadata)| metadata.is_secret()) {
                let key = sub.secret_credential_key(&name, path);
                if let Some(secret) = crate::utils::value::remove_path(&mut value, path) {
                    changes.push((
                        key,
                        (secret != metadata.default)
                            .then(|| crate::credentials::encode_setting(&secret)),
                    ));
                    modified = true;
                } else if self.is_upgraded.load(std::sync::atomic::Ordering::Relaxed)
                    && let Some(secret) = creds.get_with_profile(&key, profile.as_deref())?
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
            if metadata.is_some_and(SettingMetadata::is_secret) {
                continue;
            }
            if let Some(secret) = creds.get_with_profile(&key, profile.as_deref())?
                && let Some(metadata) = metadata
            {
                let value = crate::credentials::decode_setting(&secret, metadata)?;
                if value != metadata.default {
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
            changes.push((key, None));
        }
        let entries: Vec<_> = entries.into_iter().collect();
        creds.commit_settings(&changes, profile.as_deref(), || {
            crate::sub_settings::SubSettings::<S>::commit_entries(&**store, &entries)
        })
    }
}
