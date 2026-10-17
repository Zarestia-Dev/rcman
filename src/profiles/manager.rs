//! Profile manager implementation
//!
//! Handles profile lifecycle: create, switch, delete, rename, duplicate.

use crate::error::{Error, Result};
use crate::profiles::{DEFAULT_PROFILE, PROFILES_DIR, validate_profile_name};
use crate::utils::sync::RwLockExt;

use log::{debug, info};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

/// Type alias for cache invalidation callback
pub type InvalidateCallback = Arc<dyn Fn() + Send + Sync>;

// =============================================================================
// Profile Manifest
// =============================================================================

/// Profile manifest stored in `.profiles.json`
///
/// Tracks which profiles exist and which is currently active.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileManifest {
    /// Currently active profile name
    pub active: String,

    /// List of all profile names
    pub profiles: Vec<String>,
}

impl Default for ProfileManifest {
    fn default() -> Self {
        Self {
            active: DEFAULT_PROFILE.to_string(),
            profiles: vec![DEFAULT_PROFILE.to_string()],
        }
    }
}

impl ProfileManifest {
    /// Create a new manifest with a single default profile
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if a profile exists
    #[must_use]
    pub fn has_profile(&self, name: &str) -> bool {
        self.profiles.iter().any(|p| p == name)
    }

    /// Add a profile to the manifest
    pub fn add_profile(&mut self, name: String) {
        if !self.has_profile(&name) {
            self.profiles.push(name);
        }
    }

    /// Remove a profile from the manifest
    pub fn remove_profile(&mut self, name: &str) -> bool {
        if let Some(pos) = self.profiles.iter().position(|p| p == name) {
            self.profiles.remove(pos);
            true
        } else {
            false
        }
    }

    /// Rename a profile in the manifest
    pub fn rename_profile(&mut self, from: &str, to: String) -> bool {
        if let Some(pos) = self.profiles.iter().position(|p| p == from) {
            self.profiles[pos].clone_from(&to);
            if self.active == from {
                self.active = to;
            }
            true
        } else {
            false
        }
    }

    /// Set the active profile
    pub fn set_active(&mut self, name: &str) -> bool {
        if self.has_profile(name) {
            self.active = name.to_string();
            true
        } else {
            false
        }
    }
}

// =============================================================================
// Profile Event
// =============================================================================

/// Events emitted when profiles change
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileEvent {
    /// Profile was switched
    Switched {
        /// Previous active profile
        from: String,
        /// New active profile
        to: String,
    },
    /// New profile was created
    Created {
        /// Name of the created profile
        name: String,
    },
    /// Profile was deleted
    Deleted {
        /// Name of the deleted profile
        name: String,
    },
    /// Profile was renamed
    Renamed {
        /// Original name
        from: String,
        /// New name
        to: String,
    },
    /// Profile was duplicated
    Duplicated {
        /// Source profile
        source: String,
        /// New profile name
        target: String,
    },
}

// =============================================================================
// Profile Manager
// =============================================================================

use crate::storage::StorageBackend;

/// Type alias for profile event callback
pub type ProfileEventCallback = Arc<dyn Fn(ProfileEvent) + Send + Sync>;

/// Manages profiles for a specific target (settings or sub-settings)
///
/// The `ProfileManager` handles:
/// - Creating, deleting, renaming, and duplicating profiles
/// - Switching the active profile
/// - Persisting the profile manifest
/// - Emitting events on profile changes
pub struct ProfileManager<S: StorageBackend = crate::storage::JsonStorage> {
    /// Path to the manifest file (e.g., .profiles.json or .profiles.toml)
    manifest_path: PathBuf,

    /// Path to the profiles directory
    profiles_dir: PathBuf,

    /// Name of this profile target (for logging/errors)
    target_name: String,

    /// Storage backend for reading/writing manifest
    storage: S,

    /// Cached manifest (loaded on first access)
    manifest: RwLock<Option<ProfileManifest>>,

    /// Event callback
    on_event: RwLock<Option<ProfileEventCallback>>,

    /// Callback to invalidate caches when profile switches
    on_invalidate: RwLock<Option<InvalidateCallback>>,

    #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
    credentials: Option<(
        crate::credentials::CredentialManager,
        crate::credentials::ProfileSecretScope,
    )>,

    // Shared with the owning settings store, including direct profile mutations.
    operation_lock: Arc<RwLock<()>>,
    on_store_change: Option<InvalidateCallback>,

    #[cfg(feature = "vault")]
    vault: crate::vault::SharedVault,
}

impl<S: StorageBackend> ProfileManager<S> {
    /// Create a new profile manager for a given base directory
    ///
    /// # Arguments
    ///
    /// * `base_dir` - The directory containing the profiles
    /// * `target_name` - Name of this profile target (e.g., "remotes", "settings")
    /// * `storage` - Storage backend to use for manifest
    pub fn new(base_dir: &Path, target_name: impl Into<String>, storage: S) -> Self {
        // Manifest filename depends on storage extension
        let filename = format!(".profiles.{}", storage.extension());

        Self {
            manifest_path: base_dir.join(filename),
            profiles_dir: base_dir.join(PROFILES_DIR),
            target_name: target_name.into(),
            storage,
            manifest: RwLock::new(None),
            on_event: RwLock::new(None),
            on_invalidate: RwLock::new(None),
            #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
            credentials: None,
            operation_lock: Arc::new(RwLock::new(())),
            on_store_change: None,
            #[cfg(feature = "vault")]
            vault: Arc::new(RwLock::new(None)),
        }
    }

    #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
    pub(crate) fn with_credentials(
        mut self,
        credentials: Option<crate::credentials::CredentialManager>,
        scope: crate::credentials::ProfileSecretScope,
    ) -> Self {
        self.credentials = credentials.map(|manager| (manager, scope));
        self
    }

    pub(crate) fn with_owner(
        mut self,
        lock: Arc<RwLock<()>>,
        invalidate: InvalidateCallback,
    ) -> Self {
        self.operation_lock = lock;
        self.on_store_change = Some(invalidate);
        self
    }

    fn invalidate_store(&self) {
        if let Some(invalidate) = &self.on_store_change {
            invalidate();
        }
    }

    #[cfg(feature = "vault")]
    pub(crate) fn with_vault(mut self, vault: crate::vault::SharedVault) -> Self {
        self.vault = vault;
        self
    }

    #[cfg(feature = "vault")]
    fn copy_vault_profile(&self, source: &Path, target: &Path) -> Result<bool> {
        let vault = self.vault.read_recovered()?.clone();
        let Some(vault) = vault else {
            return Ok(false);
        };
        if vault.is_locked() {
            return Err(Error::ConfigLocked);
        }
        crate::vault::relocate::copy_profile(&self.storage, &vault, source, target)?;
        Ok(true)
    }

    fn copy_profile(&self, source: &Path, target: &Path) -> Result<()> {
        if target.exists() {
            return Err(Error::Config(
                "Profile destination already exists on disk".into(),
            ));
        }
        #[cfg(feature = "vault")]
        if self.copy_vault_profile(source, target)? {
            return Ok(());
        }
        let result = if source.exists() {
            copy_dir_recursive(source, target)
        } else {
            crate::utils::security::ensure_secure_dir(target)
        };
        result.map_err(|error| discard_copy(target, error))
    }

    // Returns true when vault rebinding kept the source for cleanup after commit.
    fn move_profile(&self, source: &Path, target: &Path) -> Result<bool> {
        if std::fs::symlink_metadata(target).is_ok() {
            return Err(Error::Config(
                "Profile destination already exists on disk".into(),
            ));
        }
        #[cfg(feature = "vault")]
        if self.copy_vault_profile(source, target)? {
            return Ok(true);
        }
        if source.exists() {
            std::fs::rename(source, target).map_err(|source| Error::FileWrite {
                path: target.to_path_buf(),
                source,
            })?;
        } else {
            crate::utils::security::ensure_secure_dir(target)?;
        }
        Ok(false)
    }

    /// Initialize the profile manager, running migrations if enabled
    ///
    /// Automatic migration moves only the main settings file into the default
    /// profile. Independent sub-settings and credential files stay at the root.
    ///
    /// # Arguments
    ///
    /// * `config_dir` - The root configuration directory
    /// * `target_name` - Main settings filename stem (e.g. "settings")
    /// * `storage` - Storage backend
    /// * `enabled` - Whether profiles are enabled
    /// * `migrator` - Migration strategy
    ///
    /// # Returns
    ///
    /// Returns a tuple of `(active_settings_dir, Option<ProfileManager>)`.
    /// If profiles are disabled, returns `(config_dir, None)`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Migration fails
    /// - Profile manager initialization fails
    /// - Active profile path cannot be resolved
    pub fn initialize(
        config_dir: &Path,
        target_name: &str,
        storage: S,
        enabled: bool,
        migrator: &crate::profiles::ProfileMigrator,
    ) -> Result<(PathBuf, Option<Self>)> {
        let filename = format!("{target_name}.{}", storage.extension());
        Self::initialize_file(
            config_dir,
            target_name,
            &filename,
            storage,
            enabled,
            migrator,
        )
    }

    pub(crate) fn initialize_file(
        config_dir: &Path,
        target_name: &str,
        filename: &str,
        storage: S,
        enabled: bool,
        migrator: &crate::profiles::ProfileMigrator,
    ) -> Result<(PathBuf, Option<Self>)> {
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter(config_dir)?;
        if enabled {
            crate::profiles::migrator::migrate_settings(config_dir, filename, &storage, migrator)?;

            let pm = Self::new(config_dir, target_name, storage);
            // Use active path from manifest (defaults to "default")
            let active = pm.active_path()?;

            info!(
                "Profiles initialized for '{target_name}' (active: {})",
                active.display()
            );
            Ok((active, Some(pm)))
        } else {
            Ok((config_dir.to_path_buf(), None))
        }
    }

    /// Set the event callback
    ///
    /// # Arguments
    ///
    /// * `callback` - The callback function to be called when a profile event occurs
    pub fn set_on_event<F>(&self, callback: F)
    where
        F: Fn(ProfileEvent) + Send + Sync + 'static,
    {
        if let Ok(mut guard) = self.on_event.write_recovered() {
            *guard = Some(Arc::new(callback));
        } else {
            debug!(
                "Failed to register profile event callback for '{}' due to lock recovery error",
                self.target_name
            );
        }
    }

    /// Set the cache invalidation callback
    ///
    /// # Arguments
    ///
    /// * `callback` - The callback function to be called when a profile switch occurs
    pub fn set_on_invalidate<F>(&self, callback: F)
    where
        F: Fn() + Send + Sync + 'static,
    {
        if let Ok(mut guard) = self.on_invalidate.write_recovered() {
            *guard = Some(Arc::new(callback));
        } else {
            debug!(
                "Failed to register profile invalidation callback for '{}' due to lock recovery error",
                self.target_name
            );
        }
    }

    /// Emit a profile event
    fn emit_event(&self, event: ProfileEvent) {
        let callback = self
            .on_event
            .read_recovered()
            .ok()
            .and_then(|guard| guard.clone());
        if let Some(callback) = callback {
            callback(event);
        }
    }

    /// Invalidate caches
    fn invalidate_caches(&self) {
        let callback = self
            .on_invalidate
            .read_recovered()
            .ok()
            .and_then(|guard| guard.clone());
        if let Some(callback) = callback {
            callback();
        }
    }

    /// Invalidate the internal manifest cache
    ///
    /// This forces the manifest to be re-read from disk on the next access.
    pub fn invalidate_manifest(&self) {
        if let Ok(mut guard) = self.manifest.write_recovered() {
            *guard = None;
        } else {
            debug!(
                "Failed to invalidate profile manifest cache for '{}' due to lock recovery error",
                self.target_name
            );
        }
    }

    /// Get the path to a specific profile's directory
    pub fn profile_path(&self, name: &str) -> PathBuf {
        self.profiles_dir.join(name)
    }

    /// Get the path to the active profile's directory
    ///
    /// # Returns
    ///
    /// Returns the path to the active profile's directory.
    ///
    /// # Errors
    ///
    /// Returns an error if the manifest cannot be read.
    pub fn active_path(&self) -> Result<PathBuf> {
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter(
            self.profiles_dir.parent().ok_or(Error::NotInitialized)?,
        )?;
        let active = self.active()?;
        Ok(self.profile_path(&active))
    }

    /// Ensure the manifest is loaded
    fn ensure_manifest(&self) -> Result<()> {
        {
            let guard = self.manifest.read_recovered()?;
            if guard.is_some() {
                return Ok(());
            }
        }

        let mut guard = self.manifest.write_recovered()?;
        if guard.is_some() {
            return Ok(());
        }

        // Try to load existing manifest
        let load_result = if self.manifest_path.exists() {
            // Normal case: load from current manifest path
            self.storage.read(&self.manifest_path).map(Some)
        } else {
            Ok(None)
        };

        match load_result {
            Ok(Some(manifest)) => {
                *guard = Some(manifest);
            }
            Ok(None) => {
                // Create default manifest
                *guard = Some(ProfileManifest::default());
            }
            Err(e) => return Err(e),
        }

        Ok(())
    }

    /// Save the manifest to disk
    fn save_manifest(&self) -> Result<()> {
        let manifest_clone = {
            let guard = self.manifest.read_recovered()?;
            let manifest = guard.as_ref().ok_or(Error::NotInitialized)?;
            manifest.clone()
        };
        // The read lock is now dropped, so concurrent operations are not blocked
        // while we wait for the (potentially slow) disk I/O to complete.

        self.storage.write(&self.manifest_path, &manifest_clone)?;

        debug!(
            "Saved profile manifest for '{}': active={}",
            self.target_name, manifest_clone.active
        );

        Ok(())
    }

    // Publish the new active profile only after its manifest is persisted.
    fn update_manifest(&self, update: impl FnOnce(&mut ProfileManifest)) -> Result<()> {
        let mut guard = self.manifest.write_recovered()?;
        let mut manifest = guard.as_ref().ok_or(Error::NotInitialized)?.clone();
        update(&mut manifest);
        self.storage.write(&self.manifest_path, &manifest)?;
        *guard = Some(manifest);
        Ok(())
    }

    // =========================================================================
    // Public API
    // =========================================================================

    /// Get the currently active profile name
    ///
    /// # Returns
    ///
    /// Returns the name of the currently active profile.
    ///
    /// # Errors
    ///
    /// Returns an error if the manifest cannot be read.
    pub fn active(&self) -> Result<String> {
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter(
            self.profiles_dir.parent().ok_or(Error::NotInitialized)?,
        )?;
        self.ensure_manifest()?;
        let guard = self.manifest.read_recovered()?;
        Ok(guard.as_ref().ok_or(Error::NotInitialized)?.active.clone())
    }

    /// List all profile names
    ///
    /// # Returns
    ///
    /// Returns a vector of profile names.
    ///
    /// # Errors
    ///
    /// Returns an error if the manifest cannot be read.
    pub fn list(&self) -> Result<Vec<String>> {
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter(
            self.profiles_dir.parent().ok_or(Error::NotInitialized)?,
        )?;
        self.ensure_manifest()?;
        let guard = self.manifest.read_recovered()?;
        Ok(guard
            .as_ref()
            .ok_or(Error::NotInitialized)?
            .profiles
            .clone())
    }

    /// Check if a profile exists
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the profile to check
    ///
    /// # Returns
    ///
    /// Returns `true` if the profile exists, `false` otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if the manifest cannot be read.
    pub fn exists(&self, name: &str) -> Result<bool> {
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter(
            self.profiles_dir.parent().ok_or(Error::NotInitialized)?,
        )?;
        self.ensure_manifest()?;
        let guard = self.manifest.read_recovered()?;
        Ok(guard
            .as_ref()
            .ok_or(Error::NotInitialized)?
            .has_profile(name))
    }

    /// Create a new profile
    ///
    /// Creates an empty profile directory and updates the manifest.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the profile to create
    ///
    /// # Errors
    ///
    /// Returns an error if the profile cannot be created.
    pub fn create(&self, name: &str) -> Result<()> {
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter(
            self.profiles_dir.parent().ok_or(Error::NotInitialized)?,
        )?;
        validate_profile_name(name)?;
        let operation_guard = self.operation_lock.write_recovered()?;
        self.ensure_manifest()?;

        // Check if already exists
        {
            let guard = self.manifest.read_recovered()?;
            if guard
                .as_ref()
                .ok_or(Error::NotInitialized)?
                .has_profile(name)
            {
                return Err(Error::ProfileAlreadyExists(name.to_string()));
            }
        }

        // Create profile directory
        let profile_dir = self.profile_path(name);
        crate::utils::security::ensure_secure_dir(&profile_dir)?;

        self.update_manifest(|manifest| manifest.add_profile(name.to_string()))?;

        self.invalidate_store();
        drop(operation_guard);
        info!("Created profile '{}' for '{}'", name, self.target_name);
        self.emit_event(ProfileEvent::Created {
            name: name.to_string(),
        });

        Ok(())
    }

    /// Switch to a different profile
    ///
    /// Updates the active profile in the manifest and invalidates caches.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the profile to switch to
    ///
    /// # Errors
    ///
    /// Returns an error if the profile cannot be switched.
    pub fn switch(&self, name: &str) -> Result<()> {
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter(
            self.profiles_dir.parent().ok_or(Error::NotInitialized)?,
        )?;
        let operation_guard = self.operation_lock.write_recovered()?;
        self.ensure_manifest()?;

        let from = {
            let guard = self.manifest.read_recovered()?;
            let manifest = guard.as_ref().ok_or(Error::NotInitialized)?;
            if !manifest.has_profile(name) {
                return Err(Error::ProfileNotFound(name.to_string()));
            }
            manifest.active.clone()
        };

        if from == name {
            debug!("Profile '{name}' is already active");
            return Ok(());
        }

        self.update_manifest(|manifest| {
            manifest.set_active(name);
        })?;

        self.invalidate_store();
        drop(operation_guard);
        info!(
            "Switched profile for '{}': {} -> {}",
            self.target_name, from, name
        );

        // Invalidate caches
        self.invalidate_caches();

        self.emit_event(ProfileEvent::Switched {
            from,
            to: name.to_string(),
        });

        Ok(())
    }

    /// Delete a profile
    ///
    /// Removes the profile directory, this target's secret credentials, and its
    /// manifest entry. Other settings groups retain their credentials.
    /// Cannot delete the active profile or the last remaining profile.
    /// Credential or manifest failures attempt to restore the directory; incomplete
    /// rollback is reported. This operation does not provide crash recovery.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the profile to delete
    ///
    /// # Errors
    ///
    /// Returns an error if the profile cannot be deleted.
    pub fn delete(&self, name: &str) -> Result<()> {
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter(
            self.profiles_dir.parent().ok_or(Error::NotInitialized)?,
        )?;
        let operation_guard = self.operation_lock.write_recovered()?;
        self.ensure_manifest()?;

        {
            let guard = self.manifest.read_recovered()?;
            let manifest = guard.as_ref().ok_or(Error::NotInitialized)?;

            if !manifest.has_profile(name) {
                return Err(Error::ProfileNotFound(name.to_string()));
            }

            if manifest.active == name {
                return Err(Error::CannotDeleteActiveProfile(name.to_string()));
            }

            if manifest.profiles.len() <= 1 {
                return Err(Error::CannotDeleteLastProfile);
            }
        }

        let profile_dir = self.profile_path(name);
        let pending = self.profiles_dir.join(format!(".rcman-delete-{name}"));
        let moved = if profile_dir.exists() {
            if std::fs::symlink_metadata(&pending).is_ok() {
                return Err(Error::Config(
                    "Pending profile deletion already exists".into(),
                ));
            }
            std::fs::rename(&profile_dir, &pending).map_err(|source| Error::FileWrite {
                path: pending.clone(),
                source,
            })?;
            true
        } else {
            false
        };
        let finish = || {
            self.update_manifest(|manifest| {
                manifest.remove_profile(name);
            })
        };
        #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
        let result = if let Some((credentials, scope)) = &self.credentials {
            credentials.remove_profile_secrets(name, scope, finish)
        } else {
            finish()
        };
        #[cfg(not(any(feature = "keychain", feature = "encrypted-file")))]
        let result = finish();
        if let Err(error) = result {
            return Err(if moved {
                rollback_move(&profile_dir, &pending, false, error)
            } else {
                error
            });
        }
        if moved {
            std::fs::remove_dir_all(&pending).map_err(|source| Error::FileDelete {
                path: pending,
                source,
            })?;
        }

        self.invalidate_store();
        drop(operation_guard);
        info!("Deleted profile '{}' from '{}'", name, self.target_name);
        self.emit_event(ProfileEvent::Deleted {
            name: name.to_string(),
        });

        Ok(())
    }

    /// Rename a profile
    ///
    /// Managed settings follow the new name, including when this is the active
    /// profile. Credential-backed secrets for this target move to the new namespace.
    /// Unencrypted directories are moved; encrypted files are rebound to their
    /// new authenticated paths before the source directory is removed.
    ///
    /// # Arguments
    ///
    /// * `from` - The name of the profile to rename
    /// * `to` - The new name for the profile
    ///
    /// # Errors
    ///
    /// Returns an error if the profile cannot be renamed.
    pub fn rename(&self, from: &str, to: &str) -> Result<()> {
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter(
            self.profiles_dir.parent().ok_or(Error::NotInitialized)?,
        )?;
        validate_profile_name(to)?;
        let operation_guard = self.operation_lock.write_recovered()?;
        self.ensure_manifest()?;

        {
            let guard = self.manifest.read_recovered()?;
            let manifest = guard.as_ref().ok_or(Error::NotInitialized)?;

            if !manifest.has_profile(from) {
                return Err(Error::ProfileNotFound(from.to_string()));
            }

            if manifest.has_profile(to) {
                return Err(Error::ProfileAlreadyExists(to.to_string()));
            }
        }

        // Rename directory
        let from_dir = self.profile_path(from);
        let to_dir = self.profile_path(to);

        let copied = self.move_profile(&from_dir, &to_dir)?;
        let finish = || {
            self.update_manifest(|manifest| {
                manifest.rename_profile(from, to.to_string());
            })
        };
        #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
        let result = if let Some((credentials, scope)) = &self.credentials {
            credentials.transfer_profile(from, to, scope, true, finish)
        } else {
            finish()
        };
        #[cfg(not(any(feature = "keychain", feature = "encrypted-file")))]
        let result = finish();
        if let Err(error) = result {
            return Err(rollback_move(&from_dir, &to_dir, copied, error));
        }
        if copied && from_dir.exists() {
            std::fs::remove_dir_all(&from_dir).map_err(|source| Error::FileDelete {
                path: from_dir,
                source,
            })?;
        }
        self.invalidate_store();
        drop(operation_guard);
        self.invalidate_caches();

        info!(
            "Renamed profile '{}' -> '{}' in '{}'",
            from, to, self.target_name
        );

        self.emit_event(ProfileEvent::Renamed {
            from: from.to_string(),
            to: to.to_string(),
        });

        Ok(())
    }

    /// Duplicate a profile
    ///
    /// Copies all contents from the source profile to a new profile.
    /// When obtained from a settings manager, also copies this target's secret
    /// credentials; other settings groups keep their own credential namespaces.
    ///
    /// # Arguments
    ///
    /// * `source` - The name of the source profile
    /// * `target` - The name of the target profile
    ///
    /// # Errors
    ///
    /// Returns an error if the profile cannot be duplicated.
    pub fn duplicate(&self, source: &str, target: &str) -> Result<()> {
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter(
            self.profiles_dir.parent().ok_or(Error::NotInitialized)?,
        )?;
        validate_profile_name(target)?;
        let operation_guard = self.operation_lock.write_recovered()?;
        self.ensure_manifest()?;

        {
            let guard = self.manifest.read_recovered()?;
            let manifest = guard.as_ref().ok_or(Error::NotInitialized)?;

            if !manifest.has_profile(source) {
                return Err(Error::ProfileNotFound(source.to_string()));
            }

            if manifest.has_profile(target) {
                return Err(Error::ProfileAlreadyExists(target.to_string()));
            }
        }

        let source_dir = self.profile_path(source);
        let target_dir = self.profile_path(target);

        self.copy_profile(&source_dir, &target_dir)?;

        let finish = || self.update_manifest(|manifest| manifest.add_profile(target.to_string()));
        #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
        let result = if let Some((credentials, scope)) = &self.credentials {
            credentials.transfer_profile(source, target, scope, false, finish)
        } else {
            finish()
        };
        #[cfg(not(any(feature = "keychain", feature = "encrypted-file")))]
        let result = finish();
        if let Err(error) = result {
            return Err(discard_copy(&target_dir, error));
        }

        self.invalidate_store();
        drop(operation_guard);
        info!(
            "Duplicated profile '{}' -> '{}' in '{}'",
            source, target, self.target_name
        );

        self.emit_event(ProfileEvent::Duplicated {
            source: source.to_string(),
            target: target.to_string(),
        });

        Ok(())
    }

    /// Rollback to flat structure (removes all profiles except active)
    ///
    /// # ⚠️ Warning
    ///
    /// This operation is **irreversible** and will:
    /// - Keep only the **active profile's** data
    /// - **Permanently delete** all other profiles
    /// - Remove the profile structure entirely
    ///
    /// # Example
    ///
    /// ```ignore
    /// use rcman::{SettingsManager, SubSettingsConfig};
    ///
    /// let manager = SettingsManager::builder("my-app", "1.0.0")
    ///     .with_sub_settings(SubSettingsConfig::new("remotes").with_profiles())
    ///     .build()?;
    ///
    /// let remotes = manager.sub_settings("remotes")?;
    ///
    /// // Remove profile support, keeping only active profile data
    /// remotes.profiles()?.rollback_to_flat()?;
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the rollback fails
    /// or a vault is enabled. Disable vault encryption before changing storage layout.
    pub fn rollback_to_flat(&self) -> Result<()> {
        use crate::profiles::rollback_migration;

        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter(
            self.profiles_dir.parent().ok_or(Error::NotInitialized)?,
        )?;

        let operation_guard = self.operation_lock.write_recovered()?;
        #[cfg(feature = "vault")]
        if self.vault.read_recovered()?.is_some() {
            return Err(Error::Vault(
                "Disable the vault before changing the profile storage layout".into(),
            ));
        }

        // Need to construct the root_dir from profiles_dir parent
        let root_dir = self
            .profiles_dir
            .parent()
            .ok_or_else(|| Error::Config("Invalid profiles directory structure".to_string()))?;

        // Determine single_file_mode by checking if root_dir is a file path
        // In single file mode, root_dir is like "config/backends" (no extension)
        // In multi file mode, root_dir is like "config/remotes" (directory)
        let single_file_mode = root_dir.with_extension(self.storage.extension()).is_file();

        rollback_migration(root_dir, &self.target_name, single_file_mode, &self.storage)?;

        self.invalidate_store();
        drop(operation_guard);
        // Invalidate caches
        self.invalidate_caches();

        Ok(())
    }

    /// Initialize profiles with auto-migration from flat structure
    ///
    /// If files exist in the base directory but no manifest exists,
    /// moves them into a "default" profile.
    ///
    /// # Arguments
    ///
    /// * `detect_existing` - A function that returns `true` if there are existing files to migrate
    ///
    /// # Returns
    ///
    /// Returns `true` if migration was needed, `false` otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if the manifest cannot be read or saved.
    pub fn initialize_with_migration<F>(&self, detect_existing: F) -> Result<bool>
    where
        F: FnOnce() -> bool,
    {
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter(
            self.profiles_dir.parent().ok_or(Error::NotInitialized)?,
        )?;
        // If manifest exists, nothing to migrate
        if self.manifest_path.exists() {
            self.ensure_manifest()?;
            return Ok(false);
        }

        // Detection is application code and may read through the owning store.
        let existing = detect_existing();
        let _profile_guard = self.operation_lock.write_recovered()?;
        if self.manifest_path.exists() {
            self.ensure_manifest()?;
            return Ok(false);
        }
        if !existing {
            // No existing files, just initialize fresh
            self.ensure_manifest()?;

            // Create default profile directory
            let default_dir = self.profile_path(DEFAULT_PROFILE);
            if !default_dir.exists() {
                std::fs::create_dir_all(&default_dir).map_err(|e| Error::DirectoryCreate {
                    path: default_dir.clone(),
                    source: e,
                })?;
            }

            self.save_manifest()?;
            return Ok(false);
        }

        // Migration will be handled by the caller
        // Just initialize the manifest
        let mut guard = self.manifest.write_recovered()?;
        *guard = Some(ProfileManifest::default());
        drop(guard);

        // Create profiles directory
        if !self.profiles_dir.exists() {
            std::fs::create_dir_all(&self.profiles_dir).map_err(|e| Error::DirectoryCreate {
                path: self.profiles_dir.clone(),
                source: e,
            })?;
        }

        info!(
            "Initialized profiles for '{}', migration needed",
            self.target_name
        );

        Ok(true) // Migration needed
    }

    /// Mark migration as complete and save manifest
    ///
    /// # Errors
    ///
    /// Returns an error if the manifest cannot be saved.
    pub fn complete_migration(&self) -> Result<()> {
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter(
            self.profiles_dir.parent().ok_or(Error::NotInitialized)?,
        )?;
        let _profile_guard = self.operation_lock.write_recovered()?;
        self.save_manifest()?;
        info!("Profile migration complete for '{}'", self.target_name);
        Ok(())
    }

    /// Get the manifest (for advanced use cases)
    ///
    /// # Errors
    ///
    /// Returns an error if the manifest cannot be read.
    pub fn manifest(&self) -> Result<ProfileManifest> {
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter(
            self.profiles_dir.parent().ok_or(Error::NotInitialized)?,
        )?;
        self.ensure_manifest()?;
        let guard = self.manifest.read_recovered()?;
        Ok(guard.as_ref().ok_or(Error::NotInitialized)?.clone())
    }

    /// Get the profiles directory path
    pub fn profiles_dir(&self) -> &Path {
        &self.profiles_dir
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Recursively copy a directory
fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    if !dst.exists() {
        std::fs::create_dir_all(dst).map_err(|e| Error::DirectoryCreate {
            path: dst.to_path_buf(),
            source: e,
        })?;
    }

    for entry in std::fs::read_dir(src).map_err(|e| Error::FileRead {
        path: src.to_path_buf(),
        source: e,
    })? {
        let entry = entry.map_err(|e| Error::FileRead {
            path: src.to_path_buf(),
            source: e,
        })?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if src_path.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            std::fs::copy(&src_path, &dst_path).map_err(|e| Error::FileWrite {
                path: dst_path.clone(),
                source: e,
            })?;
        }
    }

    Ok(())
}

fn rollback_move(source: &Path, target: &Path, copied: bool, error: Error) -> Error {
    if copied {
        return discard_copy(target, error);
    }
    match std::fs::rename(target, source) {
        Ok(()) => error,
        Err(rollback) => Error::TransactionFailed {
            source: Box::new(error),
            rollback_errors: vec![rollback.to_string()],
        },
    }
}

fn discard_copy(path: &Path, source: Error) -> Error {
    match std::fs::remove_dir_all(path) {
        Ok(()) => source,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => source,
        Err(error) => Error::TransactionFailed {
            source: Box::new(source),
            rollback_errors: vec![error.to_string()],
        },
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn create_test_manager() -> (
        tempfile::TempDir,
        ProfileManager<crate::storage::JsonStorage>,
    ) {
        let dir = tempdir().unwrap();
        let storage = crate::storage::JsonStorage::compact();
        let manager = ProfileManager::new(dir.path(), "test", storage);
        (dir, manager)
    }

    #[test]
    fn test_create_profile() {
        let (_dir, manager) = create_test_manager();

        manager.create("work").unwrap();

        let profiles = manager.list().unwrap();
        assert!(profiles.contains(&"default".to_string()));
        assert!(profiles.contains(&"work".to_string()));
    }

    #[test]
    fn test_switch_profile() {
        let (_dir, manager) = create_test_manager();

        manager.create("work").unwrap();
        manager.switch("work").unwrap();

        assert_eq!(manager.active().unwrap(), "work");
    }

    #[test]
    fn test_switch_nonexistent_profile() {
        let (_dir, manager) = create_test_manager();

        let result = manager.switch("nonexistent");
        assert!(matches!(result, Err(Error::ProfileNotFound(_))));
    }

    #[test]
    fn test_delete_profile() {
        let (_dir, manager) = create_test_manager();

        manager.create("work").unwrap();
        manager.delete("work").unwrap();

        let profiles = manager.list().unwrap();
        assert!(!profiles.contains(&"work".to_string()));
    }

    #[test]
    fn test_cannot_delete_active_profile() {
        let (_dir, manager) = create_test_manager();

        let result = manager.delete("default");
        assert!(matches!(result, Err(Error::CannotDeleteActiveProfile(_))));
    }

    #[test]
    fn test_cannot_delete_last_profile() {
        let (_dir, manager) = create_test_manager();

        manager.create("work").unwrap();
        manager.switch("work").unwrap();
        manager.delete("default").unwrap();

        // Now only "work" remains
        let result = manager.delete("work");
        assert!(matches!(result, Err(Error::CannotDeleteActiveProfile(_))));
    }

    #[test]
    fn test_rename_profile() {
        let (_dir, manager) = create_test_manager();

        manager.create("old").unwrap();
        manager.rename("old", "new").unwrap();

        let profiles = manager.list().unwrap();
        assert!(!profiles.contains(&"old".to_string()));
        assert!(profiles.contains(&"new".to_string()));
    }

    #[test]
    fn test_duplicate_profile() {
        let (dir, manager) = create_test_manager();

        manager.create("original").unwrap();

        // Create a file in the original profile
        let original_dir = dir.path().join("profiles").join("original");
        std::fs::write(original_dir.join("test.json"), r#"{"key": "value"}"#).unwrap();

        manager.duplicate("original", "copy").unwrap();

        // Verify copy has the file
        let copy_dir = dir.path().join("profiles").join("copy");
        assert!(copy_dir.join("test.json").exists());
    }

    #[test]
    fn test_profile_already_exists() {
        let (_dir, manager) = create_test_manager();

        manager.create("work").unwrap();
        let result = manager.create("work");
        assert!(matches!(result, Err(Error::ProfileAlreadyExists(_))));
    }

    #[test]
    fn test_event_callback() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let (_dir, manager) = create_test_manager();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();

        manager.set_on_event(move |_event| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });

        manager.create("work").unwrap();
        manager.switch("work").unwrap();
        manager.rename("work", "job").unwrap();

        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn test_callback_paths_recover_from_poisoned_locks() {
        use std::panic::{AssertUnwindSafe, catch_unwind};
        use std::sync::atomic::{AtomicUsize, Ordering};

        let (_dir, manager) = create_test_manager();

        let _ = catch_unwind(AssertUnwindSafe(|| {
            let _guard = manager.on_event.write().unwrap();
            panic!("poison on_event lock");
        }));

        let _ = catch_unwind(AssertUnwindSafe(|| {
            let _guard = manager.on_invalidate.write().unwrap();
            panic!("poison on_invalidate lock");
        }));

        let event_count = Arc::new(AtomicUsize::new(0));
        let event_count_clone = Arc::clone(&event_count);
        manager.set_on_event(move |_event| {
            event_count_clone.fetch_add(1, Ordering::SeqCst);
        });

        let invalidate_count = Arc::new(AtomicUsize::new(0));
        let invalidate_count_clone = Arc::clone(&invalidate_count);
        manager.set_on_invalidate(move || {
            invalidate_count_clone.fetch_add(1, Ordering::SeqCst);
        });

        manager.create("work").unwrap();
        manager.switch("work").unwrap();

        assert_eq!(event_count.load(Ordering::SeqCst), 2);
        assert_eq!(invalidate_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_manifest_persistence() {
        let dir = tempdir().unwrap();

        // Create manager and add profile
        {
            let storage = crate::storage::JsonStorage::compact();
            let manager = ProfileManager::new(dir.path(), "test", storage);
            manager.create("persistent").unwrap();
        }

        // Create new manager instance
        {
            let storage = crate::storage::JsonStorage::compact();
            let manager = ProfileManager::new(dir.path(), "test", storage);
            let profiles = manager.list().unwrap();
            assert!(profiles.contains(&"persistent".to_string()));
        }
    }
}
