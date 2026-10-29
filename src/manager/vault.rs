//! Vault lifecycle and migration of registered settings stores.

use crate::config::SettingsSchema;
use crate::error::{Error, Result};
use crate::manager::core::SettingsManager;
use crate::storage::StorageBackend;
use crate::sub_settings::SubSettings;
use crate::utils::sync::RwLockExt;
use crate::vault::metadata;
use log::info;
use serde_json::Value;
use std::sync::Arc;

struct SubSettingsProfileEntries {
    directory: std::path::PathBuf,
    entries: std::collections::HashMap<String, Value>,
}

struct SubSettingsSnapshot<S: StorageBackend> {
    sub: Arc<SubSettings<S>>,
    profiles_data: Vec<SubSettingsProfileEntries>,
}

struct VaultMigrationSnapshot<S: StorageBackend> {
    settings: Vec<(std::path::PathBuf, Value)>,
    sub_settings_data: Vec<SubSettingsSnapshot<S>>,
}

impl<S: StorageBackend + 'static, Schema: SettingsSchema> SettingsManager<S, Schema> {
    pub(super) fn finish_vault_initialization(&self, password: Option<&str>) -> Result<()> {
        let creating = !self.is_vault_enabled() && password.is_some();
        if creating {
            self.enable_vault(password.ok_or(Error::VaultUnlockFailed)?)?;
        }
        let vault = self.vault.read_recovered()?.clone();
        let _pin = vault
            .as_ref()
            .filter(|vault| !vault.is_locked())
            .map(|vault| vault.begin_migration())
            .transpose()?;
        if !creating
            && !self.is_locked()
            && (self.config.vault_requested || self.is_vault_enabled())
        {
            self.validate_registered_vault()?;
        }
        #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
        if !self.is_locked() {
            self.migrate_vault_secrets()?;
        }
        if let Some(vault) = &vault {
            self.configure_vault_events(vault);
        }
        Ok(())
    }

    #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
    fn migrate_vault_secrets(&self) -> Result<()> {
        #[cfg(feature = "profiles")]
        if let Some(profiles) = &self.profile_manager {
            for name in profiles.list()? {
                self.migrate_secret_keys_in(
                    &profiles
                        .profile_path(&name)
                        .join(&self.config.settings_file),
                    Some(&name),
                )?;
            }
        } else {
            self.migrate_secret_keys()?;
        }
        #[cfg(not(feature = "profiles"))]
        self.migrate_secret_keys()?;
        for sub in self.sub_settings.read_recovered()?.values() {
            self.finish_sub_settings_secret_migration(sub)?;
        }
        Ok(())
    }

    #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
    pub(super) fn finish_sub_settings_secret_migration(
        &self,
        sub: &Arc<SubSettings<S>>,
    ) -> Result<()> {
        if self.credentials.is_none() || sub.config.schema.is_none() {
            return Ok(());
        }
        for directory in sub.vault_directories()? {
            let store = sub.secret_migration_store(&directory);
            #[cfg(feature = "profiles")]
            let profile = if sub.profiles_enabled() {
                directory.file_name().and_then(|name| name.to_str())
            } else {
                None
            };
            self.migrate_sub_settings_secrets_in(
                sub,
                &*store,
                #[cfg(feature = "profiles")]
                profile,
                #[cfg(not(feature = "profiles"))]
                None,
            )?;
        }
        sub.invalidate_cache();
        Ok(())
    }

    #[cfg(feature = "profiles")]
    pub(super) fn check_profile_initialization(
        config: &crate::config::SettingsConfig<S, Schema>,
        storage: &S,
        vault: &crate::vault::SharedVault,
    ) -> Result<()> {
        if !config.profiles_enabled
            || config
                .config_dir
                .join(format!(".profiles.{}", storage.extension()))
                .exists()
        {
            return Ok(());
        }
        if vault.read_recovered()?.is_some() {
            return Err(Error::Vault(
                "Disable the vault before changing the profile storage layout".into(),
            ));
        }
        let path = config.config_dir.join(&config.settings_file);
        match storage.read::<Value>(&path) {
            Ok(value) if value.get("__rcman_vault__").is_some() => {
                return Err(Error::VaultNotFound);
            }
            Ok(_) => {}
            Err(Error::FileRead { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        Ok(())
    }

    pub(super) fn initialize_vault(
        config: &crate::config::SettingsConfig<S, Schema>,
        password: Option<&str>,
    ) -> Result<Option<Arc<crate::vault::VaultState>>> {
        if std::path::Path::new(&config.settings_file)
            .file_name()
            .is_some_and(|name| name == crate::vault::metadata::FILE_NAME)
        {
            return Err(crate::Error::Config(
                "The vault metadata filename is reserved".into(),
            ));
        }

        let Some(envelope) = metadata::read(&config.config_dir)? else {
            return Ok(None);
        };
        let vault = Arc::new(crate::vault::VaultState::new(
            &config.config_dir,
            Some(envelope.decode_salt()?),
            config
                .vault_lock_timeout
                .or_else(|| envelope.lock_timeout()),
            Some(envelope.kdf_params()),
            Some(envelope.vault_id.clone()),
        ));
        if let Some(password) = password {
            metadata::unlock(&vault, password, &envelope)?;
        }
        Ok(Some(vault))
    }

    pub(super) fn configure_vault_events(&self, vault: &Arc<crate::vault::VaultState>) {
        let events = Arc::clone(&self.events);
        vault.set_event_callback(Some(Arc::new(move |event| events.notify_vault(event))));
        vault.start_watchdog();
    }

    fn read_vault_envelope(&self) -> Result<crate::vault::VaultEnvelope> {
        let envelope = metadata::read(&self.config.config_dir)?.ok_or(Error::VaultNotFound)?;
        if let Some(vault) = self.vault.read().map_err(|_| Error::LockPoisoned)?.as_ref()
            && envelope.vault_id != vault.identity()
        {
            return Err(Error::InvalidVaultMetadata(
                "Vault identity changed while open".into(),
            ));
        }
        Ok(envelope)
    }

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
    #[must_use]
    pub fn is_locked(&self) -> bool {
        let Ok(guard) = self.vault.read() else {
            return true;
        };
        let Some(vault) = guard.as_ref().cloned() else {
            return false;
        };
        drop(guard);
        let (locked, did_transition) = vault.is_locked_transition();
        if did_transition {
            self.invalidate_cache();
        }
        locked
    }

    /// Check if the configuration vault feature is enabled for this settings manager.
    #[must_use]
    pub fn is_vault_enabled(&self) -> bool {
        self.vault.read().is_ok_and(|guard| guard.is_some())
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
    #[must_use]
    pub fn vault_info(&self) -> Option<crate::vault::VaultInfo> {
        let guard = self.vault.read().ok()?;
        let vault = guard.as_ref()?.clone();
        drop(guard);
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
    pub fn verify_vault_password(&self, password: &str) -> Result<bool> {
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter(&self.config.config_dir)?;
        let guard = self.vault.read().map_err(|_| Error::LockPoisoned)?;
        let vault = guard.as_ref().cloned().ok_or(Error::VaultNotEnabled)?;
        drop(guard);

        let envelope = self.read_vault_envelope()?;

        vault.verify_password(password, Some(&envelope))
    }

    /// Update the inactivity auto-lock timeout at runtime.
    ///
    /// Pass `None` to disable auto-locking on inactivity. The new timeout is
    /// persisted before updating the running timer; the vault must be unlocked.
    ///
    /// # Errors
    /// Returns `Error::VaultNotEnabled` if vault is not enabled, `Error::ConfigLocked`
    /// if locked, or an error if the timeout cannot be represented or saved.
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
    pub fn set_vault_lock_timeout(&self, timeout: Option<std::time::Duration>) -> Result<()> {
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter(&self.config.config_dir)?;
        let guard = self.vault.read().map_err(|_| Error::LockPoisoned)?;
        let vault = guard.as_ref().cloned().ok_or(Error::VaultNotEnabled)?;
        drop(guard);
        if vault.is_locked() {
            return Err(Error::ConfigLocked);
        }
        let _write_guard = self
            .settings_write_lock
            .write()
            .map_err(|_| Error::LockPoisoned)?;
        let timeout_ms = timeout
            .map(|duration| u64::try_from(duration.as_millis()))
            .transpose()
            .map_err(|_| Error::Config("Vault timeout exceeds the supported duration".into()))?;
        let _pin = vault.begin_migration()?;
        let envelope = metadata::envelope(&self.config.config_dir, &vault, timeout)?;
        debug_assert_eq!(envelope.lock_timeout_ms, timeout_ms);
        metadata::write(&self.config.config_dir, &envelope)?;
        vault.set_lock_timeout(timeout);
        vault.start_watchdog();

        Ok(())
    }

    /// Retrieve the configured inactivity auto-lock timeout, if configured.
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
    pub fn touch_vault(&self) -> Result<()> {
        let guard = self.vault.read().map_err(|_| Error::LockPoisoned)?;
        let vault = guard.as_ref().cloned().ok_or(Error::VaultNotEnabled)?;
        drop(guard);
        vault.touch();
        Ok(())
    }

    /// Unlock the configuration vault using its password.
    ///
    /// Once unlocked, settings and all registered sub-settings can be read and
    /// updated normally. The root metadata verifies the password independently of
    /// main settings. All registered files are checked before credential migration;
    /// inserted plaintext or foreign vault files are rejected and preserved.
    ///
    /// # Errors
    /// Returns:
    /// - `Error::VaultNotEnabled` if vault was not enabled on this manager
    /// - `Error::VaultUnlockFailed` for an incorrect password or damaged authenticated metadata
    /// - A metadata, vault identity, or data authentication error for invalid files
    pub fn unlock(&self, password: &str) -> Result<()> {
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter(&self.config.config_dir)?;
        let guard = self.vault.read().map_err(|_| Error::LockPoisoned)?;
        let vault = guard.as_ref().cloned().ok_or(Error::VaultNotEnabled)?;
        drop(guard);

        if !vault.is_locked() {
            return Ok(());
        }

        let envelope = self.read_vault_envelope()?;

        metadata::unlock(&vault, password, &envelope)?;
        let initialized = (|| -> Result<()> {
            let _pin = vault.begin_migration()?;
            self.invalidate_cache();
            #[cfg(feature = "profiles")]
            for sub in self.sub_settings.read_recovered()?.values() {
                sub.finish_layout_migration(&self.config.config_dir)?;
            }
            self.validate_registered_vault()?;
            #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
            self.migrate_vault_secrets()?;
            Ok(())
        })();
        if let Err(error) = initialized {
            vault.lock()?;
            self.invalidate_cache();
            return Err(error);
        }
        vault.start_watchdog();

        self.events.notify_vault(crate::vault::VaultEvent::Unlocked);
        info!("Configuration vault successfully unlocked");
        Ok(())
    }

    /// Lock the vault, zeroize its active key buffer, and invalidate manager caches.
    ///
    /// # Errors
    /// Returns `Error::VaultNotEnabled` if vault is not enabled, or
    /// `Error::ConcurrentModification` while a migration needs the active key.
    pub fn lock(&self) -> Result<()> {
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter(&self.config.config_dir)?;
        let guard = self.vault.read().map_err(|_| Error::LockPoisoned)?;
        let vault = guard.as_ref().cloned().ok_or(Error::VaultNotEnabled)?;
        drop(guard);
        vault.lock()?;
        self.invalidate_cache();
        self.events.notify_vault(crate::vault::VaultEvent::Locked);
        info!("Configuration vault locked");
        Ok(())
    }

    fn vault_settings_paths(&self) -> Result<Vec<std::path::PathBuf>> {
        #[cfg(feature = "profiles")]
        if let Some(profiles) = &self.profile_manager {
            return Ok(profiles
                .list()?
                .iter()
                .map(|name| profiles.profile_path(name).join(&self.config.settings_file))
                .collect());
        }
        Ok(vec![self.settings_path()?])
    }

    fn validate_registered_vault(&self) -> Result<()> {
        for path in self.vault_settings_paths()? {
            match self.read_settings_from_disk(&path) {
                Ok(_) => {}
                Err(Error::FileRead { source, .. })
                    if source.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        for sub in self.sub_settings.read_recovered()?.values() {
            for directory in sub.vault_directories()? {
                sub.read_entries(&directory)?;
            }
        }
        Ok(())
    }

    // Apply migrations here only when credential preparation could not run.
    fn snapshot_for_vault_migration(
        &self,
        apply_migrations: bool,
    ) -> Result<VaultMigrationSnapshot<S>> {
        let mut settings = Vec::new();
        for path in self.vault_settings_paths()? {
            match self.read_settings_from_disk(&path) {
                Ok(mut value) => {
                    if apply_migrations && let Some(migrator) = &self.config.migrator {
                        value = migrator(value);
                    }
                    settings.push((path, value));
                }
                Err(Error::FileRead { source, .. })
                    if source.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        let mut sub_settings_data = Vec::new();
        for sub in self.sub_settings.read_recovered()?.values() {
            let mut profiles_data = Vec::new();
            for directory in sub.vault_directories()? {
                let entries = if apply_migrations && sub.config.migrator.is_some() {
                    sub.secret_migration_store(&directory).get_all()?
                } else {
                    sub.read_entries(&directory)?
                };
                profiles_data.push(SubSettingsProfileEntries { directory, entries });
            }
            sub_settings_data.push(SubSettingsSnapshot {
                sub: Arc::clone(sub),
                profiles_data,
            });
        }
        Ok(VaultMigrationSnapshot {
            settings,
            sub_settings_data,
        })
    }

    fn apply_vault_migration_snapshot(
        &self,
        snapshot: &VaultMigrationSnapshot<S>,
        write_vault: bool,
    ) -> Result<()> {
        for (path, value) in &snapshot.settings {
            if write_vault {
                self.write_settings_snapshot(path, value)?;
            } else {
                self.storage.write(path, value)?;
            }
        }
        for item in &snapshot.sub_settings_data {
            for data in &item.profiles_data {
                item.sub
                    .detached_store(&data.directory)
                    .rewrite(data.entries.clone())?;
            }
            item.sub.invalidate_cache();
        }
        self.invalidate_cache();
        Ok(())
    }

    fn migrate_vault(
        &self,
        snapshot: &VaultMigrationSnapshot<S>,
        new_vault: Option<&Arc<crate::vault::VaultState>>,
    ) -> Result<()> {
        let previous = self.vault.read().map_err(|_| Error::LockPoisoned)?.clone();
        let _previous_pin = previous.as_ref().map(|v| v.begin_migration()).transpose()?;
        let _replacement_pin = new_vault.map(|v| v.begin_migration()).transpose()?;
        let old_metadata = metadata::read(&self.config.config_dir)?;
        let new_metadata = new_vault
            .map(|v| metadata::envelope(&self.config.config_dir, v, v.lock_timeout()))
            .transpose()?;
        // Creation persists recovery information before the first encrypted data write.
        if old_metadata.is_none()
            && let Some(envelope) = &new_metadata
        {
            metadata::create(&self.config.config_dir, envelope)?;
        }
        *self.vault.write().map_err(|_| Error::LockPoisoned)? = new_vault.cloned();
        let result = self
            .apply_vault_migration_snapshot(snapshot, new_vault.is_some())
            .and_then(|()| {
                if let Some(envelope) = &new_metadata {
                    metadata::write(&self.config.config_dir, envelope)
                } else {
                    // Retain the verifier until every registered file is safely plaintext.
                    metadata::remove(&self.config.config_dir)
                }
            });
        if let Err(error) = result {
            self.vault
                .write()
                .map_err(|_| Error::LockPoisoned)?
                .clone_from(&previous);
            if let Err(rollback) = self.apply_vault_migration_snapshot(snapshot, previous.is_some())
            {
                return Err(Error::Vault(format!(
                    "Migration failed: {error}; restoring previous encryption also failed: {rollback}. Metadata and per-file derivation parameters were retained for recovery"
                )));
            }
            if let Some(envelope) = &old_metadata {
                metadata::write(&self.config.config_dir, envelope)?;
            } else {
                metadata::remove(&self.config.config_dir)?;
            }
            return Err(error);
        }
        if let Some(vault) = new_vault {
            self.configure_vault_events(vault);
        }
        Ok(())
    }

    /// Change the master password used to encrypt the configuration vault across all profiles.
    ///
    /// Generates a new salt and re-encrypts main settings and registered sub-settings
    /// across their profiles. Coordinate migration with application writes.
    /// Reported failures trigger best-effort rollback; this is not crash recovery.
    ///
    /// # Errors
    /// Returns:
    /// - `Error::VaultNotEnabled` if vault is not enabled
    /// - `Error::InvalidPassword` if `old_password` does not match an unlocked vault
    /// - `Error::VaultUnlockFailed` if a locked vault cannot authenticate its metadata
    pub fn change_vault_password(&self, old_password: &str, new_password: &str) -> Result<()> {
        if new_password.is_empty() {
            return Err(Error::Config("Vault password must not be empty".into()));
        }
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter(&self.config.config_dir)?;
        if self.is_locked() {
            self.unlock(old_password)?;
        }

        let guard = self.vault.read().map_err(|_| Error::LockPoisoned)?;
        let vault = guard.as_ref().cloned().ok_or(Error::VaultNotEnabled)?;
        drop(guard);

        let _pin = vault.begin_migration()?;
        if !vault.verify_password(old_password, None)? {
            return Err(Error::InvalidPassword);
        }
        let snapshot = self.snapshot_for_vault_migration(false)?;
        let replacement = Arc::new(crate::vault::VaultState::new(
            &self.config.config_dir,
            None,
            vault.lock_timeout(),
            Some(vault.kdf_params()),
            Some(vault.identity().to_owned()),
        ));
        replacement.unlock(new_password, None)?;
        self.migrate_vault(&snapshot, Some(&replacement))?;

        self.events
            .notify_vault(crate::vault::VaultEvent::PasswordChanged);
        info!("Configuration vault password changed successfully");
        Ok(())
    }

    /// Encrypt main settings and registered sub-settings using the configured KDF parameters.
    ///
    /// Uses default parameters when none were configured. Register every sub-settings
    /// store before migration and coordinate migration with application writes.
    /// Reported failures trigger best-effort rollback; this is not crash recovery.
    ///
    /// # Errors
    /// Returns error if encryption or saving fails.
    pub fn enable_vault(&self, password: &str) -> Result<()> {
        let params = self.config.vault_kdf_params.unwrap_or_default();
        self.enable_vault_with_params(password, params)
    }

    /// Enable vault encryption at runtime on an unencrypted configuration manager with custom KDF parameters.
    ///
    /// # Errors
    /// Returns error if encryption or saving fails.
    pub fn enable_vault_with_params(
        &self,
        password: &str,
        params: crate::vault::Argon2Params,
    ) -> Result<()> {
        if password.is_empty() {
            return Err(Error::Config("Vault password must not be empty".into()));
        }
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter(&self.config.config_dir)?;
        if self.is_vault_enabled() || metadata::read(&self.config.config_dir)?.is_some() {
            return Err(Error::Config(
                "Vault already exists; use password rotation".into(),
            ));
        }
        let snapshot = self.snapshot_for_vault_migration(false)?;

        let new_vault = Arc::new(crate::vault::VaultState::new(
            &self.config.config_dir,
            None,
            self.config.vault_lock_timeout,
            Some(params),
            None,
        ));
        new_vault.unlock(password, None)?;
        self.migrate_vault(&snapshot, Some(&new_vault))?;

        self.events.notify_vault(crate::vault::VaultEvent::Enabled);
        info!("Configuration vault enabled and encrypted across all profiles");
        Ok(())
    }

    /// Disable vault encryption, decrypting registered configuration files across all profiles.
    ///
    /// Schema migrations and credential extraction complete before plaintext is
    /// written. Secret fields remain in the credential backend. If this operation
    /// fails after unlocking a locked vault, the manager is locked again.
    ///
    /// # Errors
    /// Returns `Error::InvalidPassword` for an incorrect password while unlocked,
    /// `Error::VaultUnlockFailed` when locked metadata authentication fails, or
    /// `Error::VaultNotEnabled`. Returns `Error::Credential` if secret fields cannot
    /// be removed from the managed payloads before plaintext output.
    pub fn disable_vault(&self, password: &str) -> Result<()> {
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter(&self.config.config_dir)?;
        let vault = {
            let guard = self.vault.read().map_err(|_| Error::LockPoisoned)?;
            guard.clone().ok_or(Error::VaultNotEnabled)?
        };

        let was_locked = vault.is_locked();
        if was_locked {
            self.unlock(password)?;
        }

        let result = (|| {
            let _pin = vault.begin_migration()?;
            if !was_locked && !vault.verify_password(password, None)? {
                return Err(Error::InvalidPassword);
            }
            #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
            if !was_locked {
                self.migrate_vault_secrets()?;
            }
            let snapshot = self.snapshot_for_vault_migration(
                #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
                self.credentials.is_none(),
                #[cfg(not(any(feature = "keychain", feature = "encrypted-file")))]
                true,
            )?;
            // A disabled/unavailable credential backend must never make secret
            // fields eligible for plaintext output.
            let contains_secret =
                |value: &Value, schema: &indexmap::IndexMap<String, crate::SettingMetadata>| {
                    schema.iter().any(|(key, metadata)| {
                        metadata.is_secret() && crate::utils::value::get_path(value, key).is_some()
                    })
                };
            if snapshot
                .settings
                .iter()
                .any(|(_, value)| contains_secret(value, &self.schema_metadata))
                || snapshot.sub_settings_data.iter().any(|item| {
                    item.sub.config.schema.as_ref().is_some_and(|schema| {
                        item.profiles_data.iter().any(|data| {
                            data.entries
                                .values()
                                .any(|value| contains_secret(value, schema))
                        })
                    })
                })
            {
                return Err(Error::Credential(
                    "Secret fields must be migrated to a credential backend before disabling the vault".into(),
                ));
            }
            self.migrate_vault(&snapshot, None)
        })();
        if let Err(source) = result {
            if was_locked && let Err(rollback) = self.lock() {
                return Err(Error::TransactionFailed {
                    source: Box::new(source),
                    rollback_errors: vec![rollback.to_string()],
                });
            }
            return Err(source);
        }

        self.events.notify_vault(crate::vault::VaultEvent::Disabled);
        info!("Configuration vault disabled; files stored as plaintext");
        Ok(())
    }
}
