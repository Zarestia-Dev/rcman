//! Vault lifecycle and migration of registered settings stores.

use crate::config::SettingsSchema;
use crate::error::{Error, Result};
use crate::manager::core::SettingsManager;
use crate::storage::StorageBackend;
use crate::sub_settings::SubSettings;
use crate::utils::sync::RwLockExt;
use log::info;
use serde_json::{Value, json};
use std::sync::Arc;

struct SubSettingsProfileEntries {
    #[cfg(feature = "profiles")]
    profile: Option<String>,
    entries: std::collections::HashMap<String, Value>,
}

struct SubSettingsSnapshot<S: StorageBackend> {
    sub: Arc<SubSettings<S>>,
    profiles_data: Vec<SubSettingsProfileEntries>,
}

struct VaultMigrationSnapshot<S: StorageBackend> {
    active_settings: (std::path::PathBuf, Value),
    other_profiles_settings: Vec<(String, std::path::PathBuf, Value)>,
    sub_settings_data: Vec<SubSettingsSnapshot<S>>,
}

impl<S: StorageBackend + 'static, Schema: SettingsSchema> SettingsManager<S, Schema> {
    pub(super) fn initialize_vault(
        config: &crate::config::SettingsConfig<S, Schema>,
        storage: &S,
        settings_dir: &std::path::Path,
        password: Option<&str>,
    ) -> Result<Option<Arc<crate::vault::VaultState>>> {
        let detected_envelope = Self::find_vault_envelope(config, storage, settings_dir)?;
        let detected_salt = detected_envelope
            .as_ref()
            .map(crate::vault::VaultEnvelope::decode_salt)
            .transpose()?;
        let detected_kdf_params = detected_envelope
            .as_ref()
            .map(crate::vault::VaultEnvelope::kdf_params)
            .or(config.vault_kdf_params);

        let detected_lock_timeout = config.vault_lock_timeout.or_else(|| {
            detected_envelope
                .as_ref()
                .and_then(crate::vault::VaultEnvelope::lock_timeout)
        });

        if detected_envelope.is_some() || password.is_some() {
            let vault_state = Arc::new(crate::vault::VaultState::new(
                detected_salt,
                detected_lock_timeout,
                detected_kdf_params,
            ));

            if let Some(password) = password {
                vault_state.unlock(password, detected_envelope.as_ref())?;
            }

            Ok(Some(vault_state))
        } else {
            Ok(None)
        }
    }

    pub(super) fn configure_vault_events(&self, vault: &Arc<crate::vault::VaultState>) {
        let events = Arc::clone(&self.events);
        vault.set_event_callback(Some(Arc::new(move |event| events.notify_vault(event))));
        vault.start_watchdog();
    }

    // Older versions could leave the active profile empty. Find an existing
    // envelope before deciding that the configuration is unencrypted.
    fn find_vault_envelope(
        config: &crate::config::SettingsConfig<S, Schema>,
        storage: &S,
        settings_dir: &std::path::Path,
    ) -> Result<Option<crate::vault::VaultEnvelope>> {
        let paths = vec![settings_dir.join(&config.settings_file)];
        #[cfg(feature = "profiles")]
        let paths = {
            let mut paths = paths;
            let profiles_dir = config.config_dir.join(crate::profiles::PROFILES_DIR);
            if config.profiles_enabled && profiles_dir.exists() {
                let mut profiles = crate::error::read_dir(&profiles_dir)?
                    .map(|entry| entry.map(|entry| entry.path().join(&config.settings_file)))
                    .collect::<std::io::Result<Vec<_>>>()
                    .map_err(|source| Error::DirectoryRead {
                        path: profiles_dir,
                        source,
                    })?;
                profiles.sort();
                paths.extend(profiles);
            }
            paths
        };
        for path in paths {
            let value: Value = match storage.read(&path) {
                Ok(value) => value,
                Err(Error::FileRead { source, .. })
                    if source.kind() == std::io::ErrorKind::NotFound =>
                {
                    continue;
                }
                Err(error) => return Err(error),
            };
            if crate::vault::is_vault_value(&value) {
                return serde_json::from_value(value)
                    .map(Some)
                    .map_err(|error| Error::InvalidVaultEnvelope(error.to_string()));
            }
        }
        Ok(None)
    }

    fn read_vault_envelope(&self) -> Result<crate::vault::VaultEnvelope> {
        Self::find_vault_envelope(
            &self.config,
            &self.storage,
            &self.settings_dir.read_recovered()?,
        )?
        .ok_or_else(|| Error::InvalidVaultEnvelope("Expected encrypted settings".into()))
    }

    pub(super) fn persist_vault(&self) -> Result<()> {
        let snapshot = self.snapshot_for_vault_migration()?;
        self.apply_vault_migration_snapshot(&snapshot, true)
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
        let timeout_ms = timeout
            .map(|duration| u64::try_from(duration.as_millis()))
            .transpose()
            .map_err(|_| Error::Config("Vault timeout exceeds the supported duration".into()))?;
        self.ensure_cache_populated()?;
        let value = self
            .settings_cache
            .get_stored()?
            .unwrap_or_else(|| json!({}));
        let serialized = self.storage.serialize(&value)?;
        let mut envelope = vault.encrypt_payload(serialized.as_bytes())?;
        envelope.lock_timeout_ms = timeout_ms;
        self.storage.write(&self.settings_path()?, &envelope)?;
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
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter(&self.config.config_dir)?;
        let guard = self.vault.read().map_err(|_| Error::LockPoisoned)?;
        let vault = guard.as_ref().cloned().ok_or(Error::VaultNotEnabled)?;
        drop(guard);
        vault.touch();
        Ok(())
    }

    /// Unlock the configuration vault using its password.
    ///
    /// Once unlocked, settings and all registered sub-settings can be read and
    /// updated normally. If an older configuration has an empty active profile,
    /// another main-settings profile's envelope is used to verify the password.
    ///
    /// # Errors
    /// Returns:
    /// - `Error::VaultNotEnabled` if vault was not enabled on this manager
    /// - `Error::InvalidPassword` if the password cannot decrypt the on-disk envelope
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

        let _ = vault.unlock(password, Some(&envelope))?;
        vault.start_watchdog();

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

    /// Lock the vault, zeroize its active key buffer, and invalidate manager caches.
    ///
    /// # Errors
    /// Returns `Error::VaultNotEnabled` if vault is not enabled.
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

    /// Unlock the configuration vault using its password.
    ///
    /// Convenience alias for [`unlock`](Self::unlock).
    ///
    /// # Errors
    /// Returns `Error::VaultNotEnabled` if vault is not enabled, or `Error::InvalidPassword` if decryption fails.
    pub fn unlock_vault(&self, password: &str) -> Result<()> {
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter(&self.config.config_dir)?;
        self.unlock(password)
    }

    /// Lock the configuration vault immediately, wiping keys from memory.
    ///
    /// Convenience alias for [`lock`](Self::lock).
    ///
    /// # Errors
    /// Returns `Error::VaultNotEnabled` if vault is not enabled.
    pub fn lock_vault(&self) -> Result<()> {
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter(&self.config.config_dir)?;
        self.lock()
    }

    fn snapshot_sub_settings(sub: &Arc<SubSettings<S>>) -> Result<SubSettingsSnapshot<S>> {
        let mut profiles_data = Vec::new();

        #[cfg(feature = "profiles")]
        if sub.profiles_enabled() {
            let pm = sub.profiles()?;
            let original = pm.active()?;
            let result = (|| -> Result<()> {
                for profile in pm.list()? {
                    sub.switch_profile(&profile)?;
                    let entries = sub.store.read_recovered()?.get_all()?;
                    profiles_data.push(SubSettingsProfileEntries {
                        profile: Some(profile),
                        entries,
                    });
                }
                Ok(())
            })();
            let restored = sub.switch_profile(&original);
            result?;
            restored?;
        }

        if profiles_data.is_empty() {
            let entries = sub.store.read_recovered()?.get_all()?;
            profiles_data.push(SubSettingsProfileEntries {
                #[cfg(feature = "profiles")]
                profile: None,
                entries,
            });
        }

        Ok(SubSettingsSnapshot {
            sub: Arc::clone(sub),
            profiles_data,
        })
    }

    fn write_sub_settings_snapshot(item: &SubSettingsSnapshot<S>) -> Result<()> {
        #[cfg(feature = "profiles")]
        let orig_profile = item.sub.profiles().ok().and_then(|pm| pm.active().ok());

        let result = (|| -> Result<()> {
            for data in &item.profiles_data {
                #[cfg(feature = "profiles")]
                if let Some(ref profile) = data.profile {
                    item.sub.switch_profile(profile)?;
                }
                item.sub
                    .store
                    .read_recovered()?
                    .rewrite(data.entries.clone())?;
            }
            Ok(())
        })();

        #[cfg(feature = "profiles")]
        let restored = orig_profile
            .map(|profile| item.sub.switch_profile(&profile))
            .transpose();
        result?;
        #[cfg(feature = "profiles")]
        restored?;
        item.sub.invalidate_cache();
        Ok(())
    }

    pub(super) fn persist_sub_settings(sub: &Arc<SubSettings<S>>) -> Result<()> {
        let snapshot = Self::snapshot_sub_settings(sub)?;
        Self::write_sub_settings_snapshot(&snapshot)
    }

    /// Snapshot all main settings (across all profiles) and sub-settings (across all profiles)
    /// into memory prior to enabling, disabling, or rotating vault keys.
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
            {
                for p in pm.list()? {
                    if Some(&p) != active_profile_name.as_ref() {
                        let profile_path = pm.profile_path(&p).join(&self.config.settings_file);
                        if profile_path.exists() {
                            let value = self.read_settings_from_disk(&profile_path)?;
                            other_profiles.push((p, profile_path, value));
                        }
                    }
                }
            }
        }

        let mut sub_snapshots = Vec::new();
        for sub in self.sub_settings.read_recovered()?.values() {
            sub_snapshots.push(Self::snapshot_sub_settings(sub)?);
        }

        Ok(VaultMigrationSnapshot {
            active_settings: (active_path, active_value),
            other_profiles_settings: other_profiles,
            sub_settings_data: sub_snapshots,
        })
    }

    /// Re-apply a snapshot of settings and sub-settings to disk, either encrypted or decrypted.
    fn apply_vault_migration_snapshot(
        &self,
        snapshot: &VaultMigrationSnapshot<S>,
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

        for item in &snapshot.sub_settings_data {
            Self::write_sub_settings_snapshot(item)?;
        }

        self.invalidate_cache();
        self.ensure_cache_populated()?;
        Ok(())
    }

    fn migrate_vault(
        &self,
        snapshot: &VaultMigrationSnapshot<S>,
        new_vault: Option<Arc<crate::vault::VaultState>>,
    ) -> Result<()> {
        let previous = {
            let mut guard = self.vault.write().map_err(|_| Error::LockPoisoned)?;
            std::mem::replace(&mut *guard, new_vault.clone())
        };
        if let Err(error) = self.apply_vault_migration_snapshot(snapshot, new_vault.is_some()) {
            self.vault
                .write()
                .map_err(|_| Error::LockPoisoned)?
                .clone_from(&previous);
            if let Err(rollback) = self.apply_vault_migration_snapshot(snapshot, previous.is_some())
            {
                return Err(Error::Vault(format!(
                    "Migration failed: {error}; restoring previous encryption also failed: {rollback}"
                )));
            }
            return Err(error);
        }
        if let Some(vault) = new_vault {
            self.configure_vault_events(&vault);
        }
        Ok(())
    }

    /// Replace the password of an unlocked vault without verifying the old password.
    ///
    /// Re-encrypts main settings and registered sub-settings across their profiles.
    /// Use [`Self::enable_vault`] for a plaintext configuration, or
    /// [`Self::change_vault_password`] when old-password verification is required.
    /// Coordinate migration with application writes; recovery from reported errors
    /// is best-effort and does not provide crash recovery across files.
    ///
    /// # Errors
    /// Returns `Error::VaultNotEnabled` if no vault exists, `Error::ConfigLocked`
    /// if locked, or an error if encryption, writing, or rollback fails.
    pub fn set_vault_password(&self, password: &str) -> Result<()> {
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter(&self.config.config_dir)?;
        let guard = self.vault.read().map_err(|_| Error::LockPoisoned)?;
        let vault = guard.as_ref().cloned().ok_or(Error::VaultNotEnabled)?;
        drop(guard);
        let snapshot = self.snapshot_for_vault_migration()?;
        let replacement = Arc::new(crate::vault::VaultState::new(
            None,
            vault.lock_timeout(),
            Some(vault.kdf_params()),
        ));
        replacement.unlock(password, None)?;
        self.migrate_vault(&snapshot, Some(replacement))?;

        self.events
            .notify_vault(crate::vault::VaultEvent::PasswordChanged);
        info!("Configuration vault password set");
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
    /// - `Error::InvalidPassword` if `old_password` does not match
    pub fn change_vault_password(&self, old_password: &str, new_password: &str) -> Result<()> {
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter(&self.config.config_dir)?;
        if self.is_locked() {
            self.unlock(old_password)?;
        }

        let guard = self.vault.read().map_err(|_| Error::LockPoisoned)?;
        let vault = guard.as_ref().cloned().ok_or(Error::VaultNotEnabled)?;
        drop(guard);

        let snapshot = self.snapshot_for_vault_migration()?;

        if !vault.verify_password(old_password, None)? {
            return Err(Error::InvalidPassword);
        }
        let replacement = Arc::new(crate::vault::VaultState::new(
            None,
            vault.lock_timeout(),
            Some(vault.kdf_params()),
        ));
        replacement.unlock(new_password, None)?;
        self.migrate_vault(&snapshot, Some(replacement))?;

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
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter(&self.config.config_dir)?;
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
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter(&self.config.config_dir)?;
        let snapshot = self.snapshot_for_vault_migration()?;

        let new_vault = Arc::new(crate::vault::VaultState::new(
            None,
            self.config.vault_lock_timeout,
            Some(params),
        ));
        new_vault.unlock(password, None)?;
        self.migrate_vault(&snapshot, Some(new_vault))?;

        self.events.notify_vault(crate::vault::VaultEvent::Enabled);
        info!("Configuration vault enabled and encrypted across all profiles");
        Ok(())
    }

    /// Disable vault encryption, decrypting the configuration files across all profiles back to plain text.
    ///
    /// # Errors
    /// Returns `Error::InvalidPassword` if password is wrong, or `Error::VaultNotEnabled`.
    pub fn disable_vault(&self, password: &str) -> Result<()> {
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter(&self.config.config_dir)?;
        let vault = {
            let guard = self.vault.read().map_err(|_| Error::LockPoisoned)?;
            guard.clone().ok_or(Error::VaultNotEnabled)?
        };

        if vault.is_locked() {
            let envelope = self.read_vault_envelope()?;
            vault.unlock(password, Some(&envelope))?;
        } else if !vault.verify_password(password, None)? {
            return Err(Error::InvalidPassword);
        }

        let snapshot = self.snapshot_for_vault_migration()?;

        self.migrate_vault(&snapshot, None)?;

        self.events.notify_vault(crate::vault::VaultEvent::Disabled);
        info!("Configuration vault disabled; files stored as plaintext");
        Ok(())
    }
}
