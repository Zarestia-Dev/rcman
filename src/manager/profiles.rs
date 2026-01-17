use crate::config::SettingsSchema;
use crate::error::{Error, Result};
use crate::manager::core::SettingsManager;
use crate::storage::StorageBackend;
use crate::sync::RwLockExt; // Import the trait for read_recovered/write_recovered
use log::{debug, warn};
use std::sync::Arc;

#[cfg(feature = "profiles")]
impl<S: StorageBackend + 'static, Schema: SettingsSchema> SettingsManager<S, Schema> {
    /// Check if profiles are enabled for main settings
    pub fn is_profiles_enabled(&self) -> bool {
        self.profile_manager.is_some()
    }

    /// Get the profile manager for main settings
    ///
    /// Returns None if profiles are not enabled for main settings.
    pub fn profiles(&self) -> Option<&crate::profiles::ProfileManager<S>> {
        self.profile_manager.as_ref()
    }

    /// Switch to a different profile
    ///
    /// This switches the active profile for main settings and updates internal paths.
    /// All subsequent operations will use the new profile's settings.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the profile to switch to
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Profiles are not enabled for this manager
    /// - The profile does not exist
    /// - The profile switch fails (e.g. IO error)
    pub fn switch_profile(&self, name: &str) -> Result<()> {
        let pm = self
            .profile_manager
            .as_ref()
            .ok_or(Error::ProfilesNotEnabled)?;

        // Step 1: Switch the profile in ProfileManager (this handles manifest updates)
        // This must be done first to ensure the profile exists and is valid
        pm.switch(name)?;

        // Step 2: Get the new path (without holding any locks)
        let new_path = pm.profile_path(name);

        // Step 3: Update settings_dir atomically
        {
            let mut settings_dir = self.settings_dir.write_recovered()?;
            *settings_dir = new_path;
        } // Lock released immediately

        // Step 4: Invalidate cache (after lock is released)
        self.invalidate_cache();

        // Step 5: Propagate to sub-settings
        // Clone the Arc references to avoid holding the lock during profile switches
        let sub_settings_list: Vec<_> = {
            let sub_settings = self.sub_settings.read_recovered()?;
            sub_settings
                .iter()
                .map(|(key, sub)| (key.clone(), Arc::clone(sub)))
                .collect()
        }; // Lock released immediately

        // Now switch each sub-settings without holding the main lock
        for (key, sub) in sub_settings_list {
            match sub.switch_profile(name) {
                Ok(()) => {
                    debug!("Switched sub-settings '{key}' to profile '{name}'");
                }
                Err(Error::ProfilesNotEnabled) => {
                    // Ignore sub-settings that don't support profiles
                    // They will continue to operate in their default mode
                }
                Err(e) => warn!("Failed to switch sub-settings '{key}' to profile '{name}': {e}"),
            }
        }

        Ok(())
    }

    /// Create a new profile for main settings
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the profile to create
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Profiles are not enabled
    /// - The profile already exists
    /// - Creation fails (e.g. IO error)
    pub fn create_profile(&self, name: &str) -> Result<()> {
        let pm = self
            .profile_manager
            .as_ref()
            .ok_or(Error::ProfilesNotEnabled)?;
        pm.create(name)?;

        // Propagate to sub-settings
        let sub_settings = self.sub_settings.read_recovered()?;
        for (key, sub) in sub_settings.iter() {
            if let Ok(pm) = sub.profiles() {
                match pm.create(name) {
                    Ok(()) => debug!("Created profile '{name}' in sub-settings '{key}'"),
                    Err(e) => {
                        warn!("Failed to create profile '{name}' in sub-settings '{key}': {e}");
                    }
                }
            }
        }
        Ok(())
    }

    /// List all available profiles
    /// # Errors
    ///
    /// Returns an error if profiles are not enabled or reading the profile list fails.
    pub fn list_profiles(&self) -> Result<Vec<String>> {
        let pm = self
            .profile_manager
            .as_ref()
            .ok_or(Error::ProfilesNotEnabled)?;
        pm.list()
    }

    /// Get the active profile name
    /// # Errors
    ///
    /// Returns an error if profiles are not enabled or determining the active profile fails.
    pub fn active_profile(&self) -> Result<String> {
        let pm = self
            .profile_manager
            .as_ref()
            .ok_or(Error::ProfilesNotEnabled)?;
        pm.active()
    }
}
