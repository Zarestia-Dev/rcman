//! Error types for rcman library

use std::path::PathBuf;
use thiserror::Error;

/// Result type alias for rcman operations
pub type Result<T> = std::result::Result<T, Error>;

/// Main error type for rcman library
///
/// New variants may be added in minor releases; match with a wildcard arm.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    // -------------------------------------------------------------------------
    // I/O Errors
    // -------------------------------------------------------------------------
    #[error("Failed to read file '{path}': {source}")]
    FileRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to write file '{path}': {source}")]
    FileWrite {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to create directory '{path}': {source}")]
    DirectoryCreate {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to read directory '{path}': {source}")]
    DirectoryRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to delete file '{path}': {source}")]
    FileDelete {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Path not found: {0}")]
    PathNotFound(String),

    // -------------------------------------------------------------------------
    // Serialization Errors
    // -------------------------------------------------------------------------
    #[error("Failed to serialize data: {0}")]
    Serialize(#[from] serde_json::Error),

    #[error("Failed to parse settings: {0}")]
    Parse(String),

    /// A stored value could not be read into the requested Rust type.
    #[error("Failed to read '{key}' as the requested type: {source}")]
    Deserialize {
        /// The setting key, sub-settings entry name, or `*` for the whole settings model.
        key: String,
        #[source]
        source: serde_json::Error,
    },

    // -------------------------------------------------------------------------
    // Settings Errors
    // -------------------------------------------------------------------------
    #[error("Setting not found: {0}")]
    SettingNotFound(String),

    #[error("Invalid setting value for {key}: {reason}")]
    InvalidSettingValue {
        key: String,
        reason: crate::config::ValidationError,
    },

    /// A setting key is not in `category.name` form.
    #[error("Invalid setting key '{0}': expected 'category.name'")]
    InvalidKey(String),

    #[error("Invalid setting metadata for {key}: {reason}")]
    InvalidSettingMetadata { key: String, reason: String },

    // -------------------------------------------------------------------------
    // Sub-Settings Errors
    // -------------------------------------------------------------------------
    #[error("Sub-settings type '{0}' not registered")]
    SubSettingsNotRegistered(String),

    #[error("Sub-settings entry '{0}' not found")]
    SubSettingsEntryNotFound(String),

    /// A multi-file sub-settings entry name cannot be a file name in its store
    /// directory: an empty name, or one with a path separator.
    #[error("Invalid sub-settings entry name '{0}'")]
    InvalidEntryName(String),

    // -------------------------------------------------------------------------
    // Backup Errors
    // -------------------------------------------------------------------------
    #[error("Backup failed: {0}")]
    BackupFailed(String),

    #[error("Restore failed: {0}")]
    RestoreFailed(String),

    #[error("Invalid backup: {0}")]
    InvalidBackup(String),

    #[error("Backup password required")]
    PasswordRequired,

    #[error("Invalid backup password")]
    InvalidPassword,

    // -------------------------------------------------------------------------
    // Archive Errors (backup feature)
    // -------------------------------------------------------------------------
    #[cfg(feature = "backup")]
    #[error("Archive error: {0}")]
    Archive(String),

    #[cfg(feature = "backup")]
    #[error("Zip error: {0}")]
    Zip(#[from] zip::result::ZipError),

    // -------------------------------------------------------------------------
    // Configuration Errors
    // -------------------------------------------------------------------------
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Manager not initialized")]
    NotInitialized,

    // -------------------------------------------------------------------------
    // Credential Errors
    // -------------------------------------------------------------------------
    #[error("Credential error: {0}")]
    Credential(String),

    /// A credential password environment variable is not set.
    ///
    /// Distinct from [`Error::Credential`], which reports unreadable or corrupt
    /// stored data, so callers can degrade instead of aborting startup.
    #[error("Credential password source is not set: {0}")]
    CredentialSourceMissing(String),

    /// A secret setting received a non-default value, but the manager has no
    /// credential storage (enable it with `with_credentials()` and the
    /// `keychain` or `encrypted-file` feature).
    #[error("Secret settings need credential storage, which is not enabled")]
    CredentialsDisabled,

    /// A credential backend could not be accessed, so no result about this key is available.
    #[error("Credential backend unavailable: {0}")]
    CredentialBackendUnavailable(String),

    // -------------------------------------------------------------------------
    // Profile Errors (profiles feature)
    // -------------------------------------------------------------------------
    #[cfg(feature = "profiles")]
    #[error("Profile '{0}' not found")]
    ProfileNotFound(String),

    #[cfg(feature = "profiles")]
    #[error("Profile '{0}' already exists")]
    ProfileAlreadyExists(String),

    #[cfg(feature = "profiles")]
    #[error("Cannot delete active profile '{0}'")]
    CannotDeleteActiveProfile(String),

    #[cfg(feature = "profiles")]
    #[error("Cannot delete the last remaining profile")]
    CannotDeleteLastProfile,

    #[cfg(feature = "profiles")]
    #[error("Invalid profile name: {0}")]
    InvalidProfileName(String),

    #[cfg(feature = "profiles")]
    #[error("Profiles not enabled")]
    ProfilesNotEnabled,

    #[cfg(feature = "profiles")]
    #[error("Profile migration failed: {0}")]
    ProfileMigrationFailed(String),

    // -------------------------------------------------------------------------
    // Cache Errors
    // -------------------------------------------------------------------------
    #[error("Invalid cache strategy: {0}")]
    InvalidCacheStrategy(String),

    // -------------------------------------------------------------------------
    // Concurrency Errors
    // -------------------------------------------------------------------------
    #[error(
        "Internal lock was poisoned - possible thread panic. The operation may have left data in an inconsistent state."
    )]
    LockPoisoned,

    /// The model changed after an update closure read its snapshot. Reload and retry.
    #[error("Settings changed concurrently; reload and retry the update")]
    ConcurrentModification,

    /// A write failed and one or more attempts to restore its previous state also failed.
    #[error("{source}; rollback incomplete: {rollback_errors:?}")]
    TransactionFailed {
        /// The error that caused rollback.
        #[source]
        source: Box<Error>,
        /// Backend failures encountered while restoring the previous state.
        rollback_errors: Vec<String>,
    },

    /// A backup, restore or vault operation holds these settings; retry after it finishes.
    #[error("Another settings operation is in progress; retry after it finishes")]
    Busy,

    // -------------------------------------------------------------------------
    // Vault Errors (vault feature)
    // -------------------------------------------------------------------------
    #[cfg(feature = "vault")]
    #[error("Configuration is locked. Key or password required to unlock")]
    ConfigLocked,

    #[cfg(feature = "vault")]
    #[error("Configuration vault is not enabled")]
    VaultNotEnabled,

    /// Required root metadata is absent; encrypted files must not be enrolled again.
    #[cfg(feature = "vault")]
    #[error("Vault metadata was not found")]
    VaultNotFound,

    /// Root metadata cannot be parsed or violates the supported format.
    #[cfg(feature = "vault")]
    #[error("Invalid vault metadata: {0}")]
    InvalidVaultMetadata(String),

    /// The password or authenticated metadata is invalid; these cannot be distinguished.
    #[cfg(feature = "vault")]
    #[error("Vault unlock failed: incorrect password or damaged metadata")]
    VaultUnlockFailed,

    /// An encrypted file claims an identity different from the active vault.
    #[cfg(feature = "vault")]
    #[error("Vault identity mismatch at {0}")]
    VaultMismatch(String),

    /// File authentication failed under the already validated shared key.
    #[cfg(feature = "vault")]
    #[error("Vault data authentication failed at {0}")]
    VaultDataAuthenticationFailed(String),

    #[cfg(feature = "vault")]
    #[error("Invalid vault envelope: {0}")]
    InvalidVaultEnvelope(String),

    #[cfg(feature = "vault")]
    #[error("Vault error: {0}")]
    Vault(String),
}

impl Error {
    /// Check if this is a "not found" type error, including a file read that
    /// failed because the file does not exist
    #[must_use]
    pub fn is_not_found(&self) -> bool {
        match self {
            Error::PathNotFound(_)
            | Error::SettingNotFound(_)
            | Error::SubSettingsEntryNotFound(_) => true,
            Error::FileRead { source, .. } => source.kind() == std::io::ErrorKind::NotFound,
            _ => false,
        }
    }

    /// Check if a credential password source (env var) was not provided
    #[must_use]
    pub fn is_credential_source_missing(&self) -> bool {
        matches!(self, Error::CredentialSourceMissing(_))
    }

    /// Check if this is a backup-related error
    #[cfg(feature = "backup")]
    #[must_use]
    pub fn is_backup_error(&self) -> bool {
        matches!(
            self,
            Error::BackupFailed(_)
                | Error::RestoreFailed(_)
                | Error::InvalidBackup(_)
                | Error::PasswordRequired
                | Error::InvalidPassword
                | Error::Archive(_)
                | Error::Zip(_)
        )
    }

    /// Check if this is a vault-related error
    #[cfg(feature = "vault")]
    #[must_use]
    pub fn is_vault_error(&self) -> bool {
        matches!(
            self,
            Error::ConfigLocked
                | Error::VaultNotEnabled
                | Error::VaultNotFound
                | Error::InvalidVaultMetadata(_)
                | Error::VaultUnlockFailed
                | Error::VaultMismatch(_)
                | Error::VaultDataAuthenticationFailed(_)
                | Error::InvalidVaultEnvelope(_)
                | Error::Vault(_)
        )
    }

    /// Check if this error indicates that the configuration is locked
    #[cfg(feature = "vault")]
    #[must_use]
    pub fn is_locked(&self) -> bool {
        matches!(self, Error::ConfigLocked)
    }
}

/// Treat a missing file as absent and keep every other error.
pub(crate) fn optional<T>(result: Result<T>) -> Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(Error::PathNotFound(_)) => Ok(None),
        Err(Error::FileRead { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

// =============================================================================
// Filesystem Helper Functions (backup and vault features)
// =============================================================================
// These reduce repetitive map_err patterns in filesystem operations.

#[cfg(any(feature = "backup", all(feature = "vault", feature = "profiles")))]
use std::path::Path;

/// Read directory entries with proper error handling
#[cfg(any(feature = "backup", all(feature = "vault", feature = "profiles")))]
pub fn read_dir(path: &Path) -> Result<std::fs::ReadDir> {
    std::fs::read_dir(path).map_err(|e| Error::DirectoryRead {
        path: path.to_path_buf(),
        source: e,
    })
}
