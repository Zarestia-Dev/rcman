//! Profile management for rcman
//!
//! This module provides profile support for settings and sub-settings,
//! allowing multiple named configurations that can be switched at runtime.
//!
//! # Overview
//!
//! Profiles allow users to maintain multiple configurations (e.g., "work", "personal", "testing")
//! and switch between them dynamically. Profiles can be scoped to:
//!
//! - **Main settings** - Different `settings.json` per profile
//! - **Sub-settings** - Different entity sets per profile (e.g., different remotes)
//! - **Full app** - Everything profiled together
//!
//! # Example
//!
//! ```rust,ignore
//! use rcman::{SettingsManager, SubSettingsConfig};
//!
//! // Enable profiles for remotes sub-settings
//! let manager = SettingsManager::builder("my-app", "1.0.0")
//!     .with_sub_settings(SubSettingsConfig::new("remotes").with_profiles())
//!     .build()?;
//!
//! // Manage profiles
//! let remotes = manager.sub_settings("remotes")?;
//! remotes.profiles()?.create("work")?;
//! remotes.profiles()?.switch("work")?;
//!
//! // CRUD now operates on "work" profile
//! remotes.set("company-drive", &json!({...}))?;
//! ```

mod manager;
mod migrator;

pub use manager::{ProfileEvent, ProfileManager, ProfileManifest};
pub use migrator::{migrate, ProfileMigrator};

/// Default profile name used when migrating or initializing
pub const DEFAULT_PROFILE: &str = "default";

/// Manifest file name stored in profiled directories
pub const MANIFEST_FILE: &str = ".profiles.json";

/// Directory name containing profile subdirectories
pub const PROFILES_DIR: &str = "profiles";

/// Validate a profile name
///
/// Valid names contain only alphanumeric characters, underscores, and hyphens.
/// Names cannot be empty, start with a dot, or contain path separators.
/// 
/// # Errors
/// 
/// Returns an error if the name is invalid.
pub fn validate_profile_name(name: &str) -> crate::Result<()> {
    use crate::Error;

    if name.is_empty() {
        return Err(Error::InvalidProfileName(format!(
            "{name}: Profile name cannot be empty",
        )));
    }

    if name.starts_with('.') {
        return Err(Error::InvalidProfileName(format!(
            "{name}: Profile name cannot start with a dot",
        )));
    }

    if name.contains('/') || name.contains('\\') || name.contains("..") {
        return Err(Error::InvalidProfileName(format!(
            "{name}: Profile name cannot contain path separators",
        )));
    }

    // Allow only alphanumeric, underscore, hyphen
    if !name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
    {
        return Err(Error::InvalidProfileName(format!(
            "{name}: Profile name can only contain alphanumeric characters, underscores, and hyphens"
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_profile_names() {
        assert!(validate_profile_name("default").is_ok());
        assert!(validate_profile_name("work").is_ok());
        assert!(validate_profile_name("my-profile").is_ok());
        assert!(validate_profile_name("profile_123").is_ok());
        assert!(validate_profile_name("Work").is_ok());
        assert!(validate_profile_name("PROD").is_ok());
    }

    #[test]
    fn test_invalid_profile_names() {
        assert!(validate_profile_name("").is_err());
        assert!(validate_profile_name(".hidden").is_err());
        assert!(validate_profile_name("path/to").is_err());
        assert!(validate_profile_name("..").is_err());
        assert!(validate_profile_name("has space").is_err());
        assert!(validate_profile_name("special@char").is_err());
    }
}
