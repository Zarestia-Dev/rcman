//! Profile Migration Logic
//!
//! Handles migration from flat configuration structure to profile-based structure.
//!
//! The migration strategy is:
//! 1. Check if the target directory/file exists and is NOT already profiled (no .profiles.json)
//! 2. Create the "profiles/default" directory structure
//! 3. Move existing files/contents to the default profile location
//! 4. Create .profiles.json manifest pointing to "default"

use crate::error::{Error, Result};
use crate::profiles::{DEFAULT_PROFILE, MANIFEST_FILE, PROFILES_DIR};
use log::{debug, info, warn};
use std::path::Path;

/// Type alias for custom migration closure
type MigrationFn = std::sync::Arc<dyn Fn(&Path) -> Result<()> + Send + Sync>;

/// Migration strategy
#[derive(Clone, Default)]
pub enum ProfileMigrator {
    /// Auto-migrate flat structure to profiles/default/
    #[default]
    Auto,
    /// Custom migration logic
    /// Arguments: (root_dir) -> Result<()>
    Custom(MigrationFn),
    /// No migration (error if flat structure found but profiles enabled)
    None,
}

impl std::fmt::Debug for ProfileMigrator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auto => write!(f, "Auto"),
            Self::None => write!(f, "None"),
            Self::Custom(_) => write!(f, "Custom(<closure>)"),
        }
    }
}

/// Execute migration if needed
pub fn migrate(
    root_dir: &Path,
    target_name: &str,
    single_file_mode: bool,
    strategy: &ProfileMigrator,
) -> Result<()> {
    let manifest_path = root_dir.join(MANIFEST_FILE);
    let _profiles_dir = root_dir.join(PROFILES_DIR); // Used in check? No, check uses manifest.

    // If manifest exists, we are already profiled
    if manifest_path.exists() {
        debug!("Profiles already initialized for '{}'", target_name);
        return Ok(());
    }

    // Determine if there's anything to migrate
    let needs_migration = if single_file_mode {
        true
    } else {
        root_dir.exists()
            && root_dir
                .read_dir()
                .map_err(|e| Error::DirectoryRead {
                    path: root_dir.display().to_string(),
                    source: e,
                })?
                .count()
                > 0
    };

    if !needs_migration {
        return Ok(());
    }

    info!("Migrating '{}' to profile structure...", target_name);

    match strategy {
        ProfileMigrator::None => {
            warn!(
                "Profiles enabled for '{}' but flat structure detected and migration is disabled.",
                target_name
            );
            Ok(())
        }
        ProfileMigrator::Custom(func) => func(root_dir),
        ProfileMigrator::Auto => run_auto_migration(root_dir, target_name, single_file_mode),
    }
}

fn run_auto_migration(root_dir: &Path, target_name: &str, _single_file_mode: bool) -> Result<()> {
    // 1. Create profiles/default directory
    let default_profile_dir = root_dir.join(PROFILES_DIR).join(DEFAULT_PROFILE);
    std::fs::create_dir_all(&default_profile_dir).map_err(|e| Error::DirectoryCreate {
        path: default_profile_dir.display().to_string(),
        source: e,
    })?;

    // 2. Move files
    if root_dir.is_dir() {
        for entry in std::fs::read_dir(root_dir).map_err(|e| Error::DirectoryRead {
            path: root_dir.display().to_string(),
            source: e,
        })? {
            let entry = entry.map_err(|e| Error::DirectoryRead {
                path: root_dir.display().to_string(),
                source: e,
            })?;
            let path = entry.path();

            // Skip .profiles.json and profiles/ dir
            if path.ends_with(MANIFEST_FILE) || path.ends_with(PROFILES_DIR) {
                continue;
            }

            if let Some(name) = path.file_name() {
                let dest = default_profile_dir.join(name);
                debug!("Moving {:?} -> {:?}", path, dest);
                std::fs::rename(&path, &dest).map_err(|e| Error::FileWrite {
                    path: dest.display().to_string(),
                    source: e,
                })?;
            }
        }
    }

    // 3. Create manifest
    let manifest = crate::profiles::ProfileManifest::default();
    let manifest_path = root_dir.join(MANIFEST_FILE);
    let content = serde_json::to_string_pretty(&manifest)
        .map_err(|e| Error::Parse(format!("Failed to serialize profile manifest: {}", e)))?;
    std::fs::write(&manifest_path, content).map_err(|e| Error::FileWrite {
        path: manifest_path.display().to_string(),
        source: e,
    })?;

    info!("Successfully migrated '{}' to profiles", target_name);
    Ok(())
}
