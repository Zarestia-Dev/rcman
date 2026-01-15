//! Credential types

use serde::{Deserialize, Serialize};

/// Where to store secret values
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SecretStorage {
    /// Store in OS keychain (default, most secure)
    #[default]
    Keychain,

    /// Store encrypted in settings file (portable)
    EncryptedFile,

    /// Store in memory only (session-only, not persisted)
    /// Useful for testing or secrets that should not survive app restart.
    Memory,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SecretBackupPolicy {
    /// Never include secrets in backup (default)
    ///
    /// Secrets will be redacted (set to null) in the export.
    #[default]
    Exclude,

    /// Include secrets only if backup is encrypted
    ///
    /// Safe option: secrets are included but protected by the backup password.
    /// If no password is provided, this falls back to `Exclude`.
    EncryptedOnly,

    /// Always include secrets (Unsafe)
    ///
    /// Secrets will be included in plaintext if backup is not encrypted.
    /// Use with caution.
    Include,
}
