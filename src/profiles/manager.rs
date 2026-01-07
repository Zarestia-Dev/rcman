//! Profile manager implementation
//!
//! Handles profile lifecycle: create, switch, delete, rename, duplicate.

use crate::error::{Error, Result};
use crate::profiles::{validate_profile_name, DEFAULT_PROFILE, MANIFEST_FILE, PROFILES_DIR};

use log::{debug, info};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;

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
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if a profile exists
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
            self.profiles[pos] = to.clone();
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

/// Type alias for profile event callback
pub type ProfileEventCallback = Arc<dyn Fn(ProfileEvent) + Send + Sync>;

/// Manages profiles for a specific target (settings or sub-settings)
///
/// The `ProfileManager` handles:
/// - Creating, deleting, renaming, and duplicating profiles
/// - Switching the active profile
/// - Persisting the profile manifest
/// - Emitting events on profile changes
pub struct ProfileManager {
    /// Path to the manifest file (.profiles.json)
    manifest_path: PathBuf,

    /// Path to the profiles directory
    profiles_dir: PathBuf,

    /// Name of this profile target (for logging/errors)
    target_name: String,

    /// Cached manifest (loaded on first access)
    manifest: RwLock<Option<ProfileManifest>>,

    /// Event callback
    on_event: RwLock<Option<ProfileEventCallback>>,

    /// Callback to invalidate caches when profile switches
    on_invalidate: RwLock<Option<InvalidateCallback>>,
}

impl ProfileManager {
    /// Create a new profile manager for a given base directory
    ///
    /// # Arguments
    ///
    /// * `base_dir` - The directory containing the profiles
    /// * `target_name` - Name of this profile target (e.g., "remotes", "settings")
    pub fn new(base_dir: &Path, target_name: impl Into<String>) -> Self {
        Self {
            manifest_path: base_dir.join(MANIFEST_FILE),
            profiles_dir: base_dir.join(PROFILES_DIR),
            target_name: target_name.into(),
            manifest: RwLock::new(None),
            on_event: RwLock::new(None),
            on_invalidate: RwLock::new(None),
        }
    }

    /// Set the event callback
    pub fn set_on_event<F>(&self, callback: F)
    where
        F: Fn(ProfileEvent) + Send + Sync + 'static,
    {
        let mut guard = self.on_event.write();
        *guard = Some(Arc::new(callback));
    }

    /// Set the cache invalidation callback
    pub fn set_on_invalidate<F>(&self, callback: F)
    where
        F: Fn() + Send + Sync + 'static,
    {
        let mut guard = self.on_invalidate.write();
        *guard = Some(Arc::new(callback));
    }

    /// Emit a profile event
    fn emit_event(&self, event: ProfileEvent) {
        let guard = self.on_event.read();
        if let Some(callback) = guard.as_ref() {
            callback(event);
        }
    }

    /// Invalidate caches
    fn invalidate_caches(&self) {
        let guard = self.on_invalidate.read();
        if let Some(callback) = guard.as_ref() {
            callback();
        }
    }

    /// Get the path to a specific profile's directory
    pub fn profile_path(&self, name: &str) -> PathBuf {
        self.profiles_dir.join(name)
    }

    /// Get the path to the active profile's directory
    pub fn active_path(&self) -> Result<PathBuf> {
        let active = self.active()?;
        Ok(self.profile_path(&active))
    }

    /// Ensure the manifest is loaded
    fn ensure_manifest(&self) -> Result<()> {
        {
            let guard = self.manifest.read();
            if guard.is_some() {
                return Ok(());
            }
        }

        let mut guard = self.manifest.write();
        if guard.is_some() {
            return Ok(());
        }

        // Try to load existing manifest
        if self.manifest_path.exists() {
            let content =
                std::fs::read_to_string(&self.manifest_path).map_err(|e| Error::FileRead {
                    path: self.manifest_path.display().to_string(),
                    source: e,
                })?;
            let manifest: ProfileManifest =
                serde_json::from_str(&content).map_err(|e| Error::Parse(e.to_string()))?;
            *guard = Some(manifest);
        } else {
            // Create default manifest
            *guard = Some(ProfileManifest::default());
        }

        Ok(())
    }

    /// Save the manifest to disk
    fn save_manifest(&self) -> Result<()> {
        let guard = self.manifest.read();
        let manifest = guard.as_ref().ok_or(Error::NotInitialized)?;

        // Ensure parent directory exists
        if let Some(parent) = self.manifest_path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent).map_err(|e| Error::DirectoryCreate {
                    path: parent.display().to_string(),
                    source: e,
                })?;
            }
        }

        let content =
            serde_json::to_string_pretty(manifest).map_err(|e| Error::Parse(e.to_string()))?;
        std::fs::write(&self.manifest_path, content).map_err(|e| Error::FileWrite {
            path: self.manifest_path.display().to_string(),
            source: e,
        })?;

        debug!(
            "Saved profile manifest for '{}': active={}",
            self.target_name, manifest.active
        );

        Ok(())
    }

    // =========================================================================
    // Public API
    // =========================================================================

    /// Get the currently active profile name
    pub fn active(&self) -> Result<String> {
        self.ensure_manifest()?;
        let guard = self.manifest.read();
        Ok(guard.as_ref().unwrap().active.clone())
    }

    /// List all profile names
    pub fn list(&self) -> Result<Vec<String>> {
        self.ensure_manifest()?;
        let guard = self.manifest.read();
        Ok(guard.as_ref().unwrap().profiles.clone())
    }

    /// Check if a profile exists
    pub fn exists(&self, name: &str) -> Result<bool> {
        self.ensure_manifest()?;
        let guard = self.manifest.read();
        Ok(guard.as_ref().unwrap().has_profile(name))
    }

    /// Create a new profile
    ///
    /// Creates an empty profile directory and updates the manifest.
    pub fn create(&self, name: &str) -> Result<()> {
        validate_profile_name(name)?;
        self.ensure_manifest()?;

        // Check if already exists
        {
            let guard = self.manifest.read();
            if guard.as_ref().unwrap().has_profile(name) {
                return Err(Error::ProfileAlreadyExists(name.to_string()));
            }
        }

        // Create profile directory
        let profile_dir = self.profile_path(name);
        std::fs::create_dir_all(&profile_dir).map_err(|e| Error::DirectoryCreate {
            path: profile_dir.display().to_string(),
            source: e,
        })?;
        crate::security::set_secure_dir_permissions(&profile_dir)?;

        // Update manifest
        {
            let mut guard = self.manifest.write();
            guard.as_mut().unwrap().add_profile(name.to_string());
        }
        self.save_manifest()?;

        info!("Created profile '{}' for '{}'", name, self.target_name);
        self.emit_event(ProfileEvent::Created {
            name: name.to_string(),
        });

        Ok(())
    }

    /// Switch to a different profile
    ///
    /// Updates the active profile in the manifest and invalidates caches.
    pub fn switch(&self, name: &str) -> Result<()> {
        self.ensure_manifest()?;

        let from = {
            let guard = self.manifest.read();
            let manifest = guard.as_ref().unwrap();
            if !manifest.has_profile(name) {
                return Err(Error::ProfileNotFound(name.to_string()));
            }
            manifest.active.clone()
        };

        if from == name {
            debug!("Profile '{}' is already active", name);
            return Ok(());
        }

        // Update manifest
        {
            let mut guard = self.manifest.write();
            guard.as_mut().unwrap().set_active(name);
        }
        self.save_manifest()?;

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
    /// Removes the profile directory and updates the manifest.
    /// Cannot delete the active profile or the last remaining profile.
    pub fn delete(&self, name: &str) -> Result<()> {
        self.ensure_manifest()?;

        {
            let guard = self.manifest.read();
            let manifest = guard.as_ref().unwrap();

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

        // Delete profile directory
        let profile_dir = self.profile_path(name);
        if profile_dir.exists() {
            std::fs::remove_dir_all(&profile_dir).map_err(|e| Error::FileDelete {
                path: profile_dir.display().to_string(),
                source: e,
            })?;
        }

        // Update manifest
        {
            let mut guard = self.manifest.write();
            guard.as_mut().unwrap().remove_profile(name);
        }
        self.save_manifest()?;

        info!("Deleted profile '{}' from '{}'", name, self.target_name);
        self.emit_event(ProfileEvent::Deleted {
            name: name.to_string(),
        });

        Ok(())
    }

    /// Rename a profile
    pub fn rename(&self, from: &str, to: &str) -> Result<()> {
        validate_profile_name(to)?;
        self.ensure_manifest()?;

        {
            let guard = self.manifest.read();
            let manifest = guard.as_ref().unwrap();

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

        if from_dir.exists() {
            std::fs::rename(&from_dir, &to_dir).map_err(|e| Error::FileWrite {
                path: format!("{} -> {}", from_dir.display(), to_dir.display()),
                source: e,
            })?;
        } else {
            // Create the new directory if old didn't exist
            std::fs::create_dir_all(&to_dir).map_err(|e| Error::DirectoryCreate {
                path: to_dir.display().to_string(),
                source: e,
            })?;
        }

        // Update manifest
        {
            let mut guard = self.manifest.write();
            guard.as_mut().unwrap().rename_profile(from, to.to_string());
        }
        self.save_manifest()?;

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
    pub fn duplicate(&self, source: &str, target: &str) -> Result<()> {
        validate_profile_name(target)?;
        self.ensure_manifest()?;

        {
            let guard = self.manifest.read();
            let manifest = guard.as_ref().unwrap();

            if !manifest.has_profile(source) {
                return Err(Error::ProfileNotFound(source.to_string()));
            }

            if manifest.has_profile(target) {
                return Err(Error::ProfileAlreadyExists(target.to_string()));
            }
        }

        let source_dir = self.profile_path(source);
        let target_dir = self.profile_path(target);

        // Copy directory contents
        if source_dir.exists() {
            copy_dir_recursive(&source_dir, &target_dir)?;
        } else {
            std::fs::create_dir_all(&target_dir).map_err(|e| Error::DirectoryCreate {
                path: target_dir.display().to_string(),
                source: e,
            })?;
        }

        // Update manifest
        {
            let mut guard = self.manifest.write();
            guard.as_mut().unwrap().add_profile(target.to_string());
        }
        self.save_manifest()?;

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

    /// Initialize profiles with auto-migration from flat structure
    ///
    /// If files exist in the base directory but no manifest exists,
    /// moves them into a "default" profile.
    pub fn initialize_with_migration<F>(&self, detect_existing: F) -> Result<bool>
    where
        F: FnOnce() -> bool,
    {
        // If manifest exists, nothing to migrate
        if self.manifest_path.exists() {
            self.ensure_manifest()?;
            return Ok(false);
        }

        // Check if there are existing files to migrate
        if !detect_existing() {
            // No existing files, just initialize fresh
            self.ensure_manifest()?;

            // Create default profile directory
            let default_dir = self.profile_path(DEFAULT_PROFILE);
            if !default_dir.exists() {
                std::fs::create_dir_all(&default_dir).map_err(|e| Error::DirectoryCreate {
                    path: default_dir.display().to_string(),
                    source: e,
                })?;
            }

            self.save_manifest()?;
            return Ok(false);
        }

        // Migration will be handled by the caller
        // Just initialize the manifest
        let mut guard = self.manifest.write();
        *guard = Some(ProfileManifest::default());
        drop(guard);

        // Create profiles directory
        if !self.profiles_dir.exists() {
            std::fs::create_dir_all(&self.profiles_dir).map_err(|e| Error::DirectoryCreate {
                path: self.profiles_dir.display().to_string(),
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
    pub fn complete_migration(&self) -> Result<()> {
        self.save_manifest()?;
        info!("Profile migration complete for '{}'", self.target_name);
        Ok(())
    }

    /// Get the manifest (for advanced use cases)
    pub fn manifest(&self) -> Result<ProfileManifest> {
        self.ensure_manifest()?;
        let guard = self.manifest.read();
        Ok(guard.as_ref().unwrap().clone())
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
            path: dst.display().to_string(),
            source: e,
        })?;
    }

    for entry in std::fs::read_dir(src).map_err(|e| Error::FileRead {
        path: src.display().to_string(),
        source: e,
    })? {
        let entry = entry.map_err(|e| Error::FileRead {
            path: src.display().to_string(),
            source: e,
        })?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if src_path.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            std::fs::copy(&src_path, &dst_path).map_err(|e| Error::FileWrite {
                path: dst_path.display().to_string(),
                source: e,
            })?;
        }
    }

    Ok(())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn create_test_manager() -> (tempfile::TempDir, ProfileManager) {
        let dir = tempdir().unwrap();
        let manager = ProfileManager::new(dir.path(), "test");
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
        let (_dir, manager) = create_test_manager();

        use std::sync::atomic::{AtomicUsize, Ordering};
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
    fn test_manifest_persistence() {
        let dir = tempdir().unwrap();

        // Create manager and add profile
        {
            let manager = ProfileManager::new(dir.path(), "test");
            manager.create("persistent").unwrap();
        }

        // Create new manager instance
        {
            let manager = ProfileManager::new(dir.path(), "test");
            let profiles = manager.list().unwrap();
            assert!(profiles.contains(&"persistent".to_string()));
        }
    }
}
