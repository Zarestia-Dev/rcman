//! Password-based encryption for managed configuration files.
//!
//! Enable the `vault` feature to encrypt main settings and registered sub-settings
//! with AES-256-GCM and Argon2id. Files remain encrypted while unlocked; locking
//! zeroizes the active key buffer and blocks managed settings reads and writes.
//!
//! # Startup and profiles
//!
//! `.with_vault()` enables startup handling for registered stores. Existing
//! `.rcman-vault.json` metadata is detected automatically; without a password
//! the manager starts locked. `.with_vault_password(...)` unlocks an existing
//! vault or creates one and encrypts registered stores on first startup.
//! No opening mode needs to be selected. Without metadata or a password,
//! plaintext remains usable and `SettingsManager::enable_vault` can encrypt it later.
//!
//! Root metadata authenticates a password verifier, vault identity, salt, KDF
//! parameters, and timeout. Main settings are optional: an empty vault or one
//! containing only sub-settings can lock, unlock, rotate passwords, and restart.
//! Every registered store shares the same vault identity, key, and lock state.
//! Reads, writes, and unlocked registration reject inserted plaintext or foreign
//! encrypted files. Locked startup defers data checks until unlock. Unlock
//! completes required credential migration before reporting
//! success; a validation or migration failure leaves the manager locked. Disabling
//! encryption completes secret migration across main and sub-settings profiles
//! before writing plaintext, and re-locks a previously locked vault on failure.
//!
//! Construction consumes and zeroizes its startup password buffer, including on
//! failure; `manager.config().vault_password` is `None` afterward. Application-owned
//! password copies and values already returned to callers are unaffected.
//!
//! Envelope headers and relative file identities are authenticated; SQLite records
//! also bind their table and row key. Profile
//! duplication and renaming re-encrypt managed data for the destination identity.
//! Moving the entire configuration directory preserves relative identities;
//! enabling profiles on existing flat sub-settings re-encrypts them into the
//! default profile (deferred until unlock while the vault is locked), and other
//! layout changes require disabling the vault first.
//! Managed filenames must be valid UTF-8. Older copies at the same logical identity
//! can still be replayed. Replacing all metadata and data clones a valid vault;
//! the vault does not maintain a trusted external counter.
//! Argon2 costs are limited to 256 `MiB`, 10 passes, and 16 lanes before derivation.
//!
//! # Migration and backups
//!
//! Register all sub-settings before enabling, disabling, or rotating vault encryption.
//! These operations rewrite managed stores across their profiles and attempt to
//! restore the previous encryption state after a reported failure. Applications
//! must coordinate migration with settings writes; multi-file crash recovery is
//! not provided. Per-file derivation parameters are retained for manual recovery.
//! Migration pins keep auto-lock from discarding keys needed for rollback.
//! SQLite migration scrubs freed pages and truncates WAL history; readers that
//! prevent cleanup cause an error. External backups and previously deleted
//! filesystem blocks are outside this cleanup guarantee.
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
//!     .with_vault()
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

mod crypto;
pub mod envelope;
pub(crate) mod metadata;
mod state;

#[cfg(feature = "profiles")]
pub(crate) mod relocate;

pub use envelope::{
    Argon2Params, Argon2Preset, VAULT_ALGORITHM, VAULT_VERSION, VaultContext, VaultEnvelope,
    is_vault_content, is_vault_value, parse_envelope,
};
pub(crate) use state::VaultState;
pub use state::{VaultEvent, VaultEventCallback, VaultInfo};

/// Thread-safe shared handle to an optional active vault
pub(crate) type SharedVault = std::sync::Arc<std::sync::RwLock<Option<std::sync::Arc<VaultState>>>>;
