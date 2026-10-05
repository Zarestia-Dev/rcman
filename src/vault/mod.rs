//! Password-based encryption for managed configuration files.
//!
//! Enable the `vault` feature to encrypt main settings and registered sub-settings
//! with AES-256-GCM and Argon2id. Files remain encrypted while unlocked; locking
//! zeroizes the active key buffer and blocks managed settings reads and writes.
//!
//! # Startup and profiles
//!
//! `.with_vault()` configures support without encrypting plaintext settings.
//! Call `SettingsManager::enable_vault` to encrypt an existing configuration, or
//! supply `.with_vault_password(...)` to unlock or encrypt during construction.
//! The startup password buffer is consumed and zeroized, including on construction
//! failure; `manager.config().vault_password` is `None` afterward. Application-owned
//! password copies and values already returned to callers are unaffected.
//!
//! Existing main-settings vault envelopes are detected without a startup password,
//! leaving the manager locked. With `profiles`, switching to an empty profile writes
//! an encrypted settings envelope before activation. Older configurations with an
//! empty active profile can be detected using another main-settings profile.
//!
//! # Migration and backups
//!
//! Register all sub-settings before enabling, disabling, or rotating vault encryption.
//! These operations rewrite managed stores across their profiles and attempt to
//! restore the previous encryption state after a reported failure. Applications
//! must coordinate migration with settings writes; multi-file crash recovery is
//! not provided.
//!
//! When `backup` is enabled, export reads values from an unlocked vault and applies
//! the secret export policy. The backup needs its own password to be encrypted.
//! Restore writes values using the destination vault and credential configuration.
//!
//! # Examples
//!
//! Startup with a password, followed by an explicit lock and unlock:
//!
//! ```
//! use rcman::{SettingsManager, SubSettingsConfig};
//! use serde_json::json;
//!
//! let directory = tempfile::tempdir()?;
//! let manager = SettingsManager::builder("vault-example", "1.0")
//!     .with_config_dir(directory.path())
//!     .with_sub_settings(SubSettingsConfig::singlefile("connections"))
//!     .with_vault_password("example-password")
//!     .build()?;
//! assert!(manager.config().vault_password.is_none());
//!
//! let connections = manager.sub_settings("connections")?;
//! connections.set("primary", &json!({"host": "storage.internal"}))?;
//! manager.lock()?;
//! assert!(connections.get_value("primary").unwrap_err().is_locked());
//! manager.unlock("example-password")?;
//! assert_eq!(connections.get_value("primary")?["host"], "storage.internal");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

pub mod crypto;
pub mod envelope;
pub mod state;

pub use envelope::{
    Argon2Params, Argon2Preset, VAULT_ALGORITHM, VAULT_VERSION, VaultEnvelope, is_vault_content,
    is_vault_value, parse_envelope,
};
pub use state::{VaultEvent, VaultEventCallback, VaultInfo, VaultState};

/// Thread-safe shared handle to an optional active vault
pub(crate) type SharedVault = std::sync::Arc<std::sync::RwLock<Option<std::sync::Arc<VaultState>>>>;
