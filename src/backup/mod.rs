//! Portable backup and restore for rcman settings and opaque external content.
//!
//! Managed settings are exported as serialized values, without their source vault
//! envelopes. An enabled vault must be unlocked; export does not disable it, change
//! profiles, or run source migrations. Use [`BackupOptions::password`] to encrypt
//! the backup independently of the vault. Managed plaintext is written directly
//! into ZIP entries instead of a temporary export directory.
//!
//! External files and provider output are opaque bytes: vault conversion and
//! schema secret filtering do not apply to their contents. Their registered
//! import targets control restore behavior.
//!
//! Restore validates selected payloads before writing, then uses the destination
//! vault and credential stores. Legacy managed payloads containing raw vault
//! envelopes are rejected; re-export them from the unlocked source installation.
//! Managed restore writes are journaled: an application error restores previous
//! files and credentials and discards change notifications. Rollback failures are
//! reported with the original error; recoverable file snapshots are retained.
//! This is error recovery, not crash recovery or a distributed transaction.
//!
//! With `backup` enabled, managed API calls coordinate in-process. Export's managed
//! snapshot and restore's managed transaction exclude concurrent managed operations
//! on overlapping configuration directories or the same credential namespace,
//! including access through other manager instances or directory aliases. Unrelated
//! managers remain available. Nested backup/restore on the same resources is
//! rejected. Conflicting calls fail immediately with
//! `Error::Config` and can be retried; resource claims never wait across
//! application callbacks. Direct storage/backend access, external
//! processes, and vault auto-lock remain outside this coordination; callers must
//! quiesce independent writers. External imports run after managed commit and
//! cannot roll it back; their failures explicitly report that managed data committed.
//! Custom storage backends must persist to the supplied path for file rollback.
//!
//! Restore decrypts archive entries into a temporary directory that is cleaned up
//! when the operation returns. Restoring secret fields requires a configured
//! credential store, even when the destination uses a vault.
//!
//! # Examples
//!
//! Export a registered store and restore it into a separate configuration:
//!
//! ```
//! use rcman::{BackupOptions, RestoreOptions, SettingsManager, SubSettingsConfig};
//! use serde_json::json;
//!
//! let directory = tempfile::tempdir()?;
//! let source = SettingsManager::builder("backup-example", "1.0")
//!     .with_config_dir(directory.path().join("source"))
//!     .with_sub_settings(SubSettingsConfig::singlefile("connections"))
//!     .build()?;
//! source.sub_settings("connections")?
//!     .set("primary", &json!({"host": "storage.internal"}))?;
//! let backup = source.backup().create(
//!     &BackupOptions::new()
//!         .output_dir(directory.path().join("backups"))
//!         .password("archive-password"),
//! )?;
//!
//! let target = SettingsManager::builder("backup-example", "1.0")
//!     .with_config_dir(directory.path().join("target"))
//!     .with_sub_settings(SubSettingsConfig::singlefile("connections"))
//!     .build()?;
//! let options = RestoreOptions::from_path(backup)
//!     .password("archive-password")
//!     .overwrite(true);
//! let preview = target.backup().restore(&options.clone().dry_run(true))?;
//! assert!(!preview.has_conflicts());
//! target.backup().restore(&options)?;
//! assert_eq!(target.sub_settings("connections")?
//!     .get_value("primary")?["host"], "storage.internal");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use crate::error::{Error, Result};

mod archive;
mod operations;
mod restore;
pub(crate) mod transaction;
mod types;

pub use operations::BackupManager;
pub use restore::{
    RestorePendingItem, RestorePendingReason, RestoreResult, RestoreSkipReason, RestoreSkippedItem,
};

pub use types::{
    BackupAnalysis, BackupContents, BackupInfo, BackupIntegrity, BackupManifest, BackupOptions,
    ExportCategory, ExportCategoryType, ExportSource, ExportType, ExternalConfig,
    ExternalConfigProvider, ImportTarget, MANIFEST_VERSION_CURRENT, MANIFEST_VERSION_MAX_SUPPORTED,
    MANIFEST_VERSION_MIN_SUPPORTED, ProfileEntry, ProgressCallback, RestoreControl, RestoreFlags,
    RestoreOptions, RestoreScope, SubSettingsManifestEntry, is_manifest_version_supported,
};

// Archive encryption is handled during extraction. A managed payload must not
// contain an independently encrypted vault file, even in builds without vault support.
pub(super) fn validate_backup_value(value: &serde_json::Value) -> Result<()> {
    if value.get("__rcman_vault__").is_some() {
        return Err(Error::InvalidBackup(
            "Backup contains a raw vault file. Export it from an unlocked source vault with a version that supports portable profile backups.".into(),
        ));
    }
    Ok(())
}
