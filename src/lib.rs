//! # rcman - Rust Config Manager
//!
//! A generic, framework-agnostic Rust library for managing application settings
//! with backup/restore, sub-settings, and automatic secret storage.
//!
//! ## Features
//!
//! - **Settings Management**: Load, save, and reset settings with schema metadata
//! - **Secret Settings**: Mark settings with `.secret()` to auto-store in OS keychain (requires `keychain` or `encrypted-file` feature)
//! - **Sub-Settings**: Per-entity configuration files (e.g., one file per "remote")
//! - **Backup & Restore**: Create and restore encrypted backups with AES-256
//! - **Profiles**: Named configurations for switching between different setups (e.g., "work", "home")
//! - **Schema Validation**: Regex patterns, numeric ranges, and option constraints
//! - **Performance**: In-memory caching for fast access
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use rcman::{SettingsConfig, SettingsManager, SubSettingsConfig};
//!
//! # use rcman::*;
//! # use serde::{Serialize, Deserialize};
//! # use std::collections::HashMap;
//! # #[derive(Default, Serialize, Deserialize)] struct MySettings;
//! # impl SettingsSchema for MySettings { fn get_metadata() -> HashMap<String, SettingMetadata> { HashMap::new() } }
//! let manager = SettingsManager::builder("my-app", "1.0.0")
//!     .with_config_dir("~/.config/my-app")
//!     .with_credentials()  // Enable automatic secret storage
//!     .with_sub_settings(SubSettingsConfig::new("remotes"))
//!     .with_schema::<MySettings>()
//!     .build()
//!     .unwrap();
//! ```
//!
//! ## Defining Settings Schema
//!
//! ```rust,no_run
//! use rcman::{settings, SettingsSchema, SettingMetadata, opt};
//! use serde::{Deserialize, Serialize};
//! use std::collections::HashMap;
//!
//! #[derive(Default, Serialize, Deserialize)]
//! struct MySettings {
//!     theme: String,
//!     font_size: f64,
//! }
//!
//! impl SettingsSchema for MySettings {
//!     fn get_metadata() -> HashMap<String, SettingMetadata> {
//!         settings! {
//!             "ui.theme" => SettingMetadata::select("dark", vec![
//!                 opt("light", "Light"),
//!                 opt("dark", "Dark"),
//!             ])
//!             .meta_str("label", "Theme")
//!             .meta_str("category", "appearance"),
//!
//!             "ui.font_size" => SettingMetadata::number(14.0)
//!                 .min(8.0).max(32.0).step(1.0)
//!                 .meta_str("label", "Font Size"),
//!
//!             "logging.output" => SettingMetadata::text("/var/log/app.log")
//!                 .meta_str("label", "Log File")
//!                 .meta_str("description", "Path to the log output file")
//!                 .meta_str("input_type", "file"),
//!
//!             "api.key" => SettingMetadata::text("")
//!                 .meta_str("label", "API Key")
//!                 .meta_str("input_type", "password")
//!                 .secret(),  // Auto-stored in OS keychain!
//!         }
//!     }
//! }
//! ```
//!
//! ## Default Value Behavior
//!
//! When you save a setting that equals its default value, rcman **removes it from storage**
//! to keep files minimal. This applies to both regular settings and secrets:
//!
//! - **Regular settings**: Removed from settings file
//! - **Secret settings**: Removed from keychain
//!
//! This means:
//! - Settings files only contain user customizations
//! - Changing defaults in code auto-applies to users who haven't customized
//! - Using `reset_setting()` removes the key from storage
//!
//! ## Sub-Settings (Per-Entity Config)
//!
//! ```rust,no_run
//! use rcman::{SettingsManager, SubSettingsConfig};
//! use serde_json::json;
//!
//! # fn example() -> rcman::Result<()> {
//! # use rcman::*;
//! # use serde::{Serialize, Deserialize};
//! # use std::collections::HashMap;
//! # #[derive(Default, Serialize, Deserialize)] struct MySettings;
//! # impl SettingsSchema for MySettings { fn get_metadata() -> HashMap<String, SettingMetadata> { HashMap::new() } }
//! // Register sub-settings via builder
//! let manager = SettingsManager::builder("my-app", "1.0.0")
//!     .with_sub_settings(SubSettingsConfig::new("remotes"))  // Multi-file mode
//!     .with_sub_settings(SubSettingsConfig::singlefile("backends"))  // Single-file mode
//!     .with_schema::<MySettings>()
//!     .build()?;
//!
//! // Access sub-settings
//! let remotes = manager.sub_settings("remotes")?;
//! remotes.set("gdrive", &json!({"type": "drive"}))?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Profiles (Named Configurations)
//!
//! rcman supports creating multiple profiles (e.g., "default", "work", "home") and switching between them.
//! Profiles are supported for both main settings and sub-settings.
//!
//! ```rust,no_run
//! use rcman::{SettingsManager, SubSettingsConfig};
//!
//! # fn example() -> rcman::Result<()> {
//! # #[cfg(feature = "profiles")]
//! # {
//! # use rcman::*;
//! # use serde::{Serialize, Deserialize};
//! # use std::collections::HashMap;
//! # #[derive(Default, Serialize, Deserialize)] struct MySettings;
//! # impl SettingsSchema for MySettings { fn get_metadata() -> HashMap<String, SettingMetadata> { HashMap::new() } }
//! let manager = SettingsManager::builder("my-app", "1.0.0")
//!     .with_profiles() // Enable profiles for main settings
//!     .with_sub_settings(SubSettingsConfig::new("remotes").with_profiles()) // Enable for sub-settings
//!     .with_schema::<MySettings>()
//!     .build()?;
//!
//! // Create and switch profiles
//! manager.create_profile("work")?;
//! manager.switch_profile("work")?;
//!
//! // Sub-settings automatically use the active profile
//! let remotes = manager.sub_settings("remotes")?;
//! // This will save to .../remotes/profiles/work/gdrive.<ext>
//! remotes.set("gdrive", &serde_json::json!({"type": "drive"}))?;
//! # }
//! # Ok(())
//! # }
//! ```
//!
//! ## Backup & Restore
//!
//! ```rust,no_run
//! use rcman::{SettingsManager, SettingsConfig, BackupOptions, RestoreOptions};
//!
//! # fn example() -> rcman::Result<()> {
//! # use rcman::*;
//! # use serde::{Serialize, Deserialize};
//! # use std::collections::HashMap;
//! # #[derive(Default, Serialize, Deserialize)] struct MySettings;
//! # impl SettingsSchema for MySettings { fn get_metadata() -> HashMap<String, SettingMetadata> { HashMap::new() } }
//! let config = SettingsConfig::builder("my-app", "1.0.0")
//!     .with_schema::<MySettings>()
//!     .build();
//! let manager = SettingsManager::new(config)?;
//!
//! // Create encrypted backup using builder pattern
//! let path = manager.backup()
//!     .create(&BackupOptions::new()
//!         .output_dir("backups/")
//!         .password("secret")
//!         .note("Weekly backup"))?;
//!
//! // Analyze a backup before restoring (inspect contents, check if encrypted)
//! let analysis = manager.backup().analyze(&path)?;
//! println!("Encrypted: {}", analysis.requires_password);
//! println!("Valid: {}", analysis.is_valid);
//! println!("App version: {}", analysis.manifest.backup.app_version);
//!
//! // Restore from backup
//! manager.backup()
//!     .restore(&RestoreOptions::from_path(&path)
//!         .password("secret")
//!         .overwrite(true))?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Credentials
//!
//! **Note**: `CredentialManager` is only available when the `keychain` or `encrypted-file` feature is enabled.
//!
//! ```rust,no_run
//! #[cfg(feature = "keychain")]
//! {
//!     use rcman::CredentialManager;
//!
//!     let creds = CredentialManager::new("my-app");
//!     creds.store("api-key", "secret-value").unwrap();
//!     let key = creds.get("api-key").unwrap();
//! }
//! ```
//!
//! ## Import Patterns
//!
//! All public types are re-exported at the crate root for convenience:
//!
//! ```rust,ignore
//! // Recommended: flat imports
//! use rcman::{SettingsManager, JsonStorage, SettingMetadata};
//!
//! // Alternative: prelude for common types
//! use rcman::prelude::*;
//! ```

// =============================================================================
// INTERNAL MODULES (private implementation details)
// =============================================================================

// Core modules
mod config;
mod docs;
mod error;
mod events;
mod manager;
mod security;
mod storage;
mod sub_settings;
mod sync;

// Cache module (always available - used by sub_settings)
mod cache;

// Feature-gated modules
#[cfg(feature = "backup")]
pub mod backup;

#[cfg(feature = "profiles")]
mod profiles;

mod credentials;

// =============================================================================
// PUBLIC API RE-EXPORTS
// =============================================================================

// -----------------------------------------------------------------------------
// Core Types (always available)
// -----------------------------------------------------------------------------

/// Core configuration types and traits for settings management.
pub use config::{
    DefaultEnvSource, EnvSource, NumberConstraints, SettingConstraints, SettingMetadata,
    SettingOption, SettingType, SettingsConfig, SettingsConfigBuilder, SettingsSchema,
    TextConstraints, meta, opt,
};

/// Documentation generation utilities.
pub use docs::{DocsConfig, generate_docs, generate_docs_from_metadata};

/// Error types for the library.
pub use error::{Error, Result};

/// Event system for reactive settings changes.
pub use events::EventManager;

/// Main settings manager and builder.
pub use manager::{SettingsManager, SettingsManagerBuilder};

/// Sub-settings for per-entity configuration.
pub use sub_settings::{SubSettings, SubSettingsAction, SubSettingsConfig, SubSettingsMode};

// -----------------------------------------------------------------------------
// Storage Backends
// -----------------------------------------------------------------------------

/// JSON storage backend (default).
pub use storage::{JsonStorage, StorageBackend};

/// TOML storage backend (requires `toml` feature).
#[cfg(feature = "toml")]
pub use storage::TomlStorage;

// -----------------------------------------------------------------------------
// Cache
// -----------------------------------------------------------------------------

/// Cache strategy for settings components.
pub use cache::CacheStrategy;

// -----------------------------------------------------------------------------
// Backup & Restore (requires backup feature)
// -----------------------------------------------------------------------------

#[cfg(feature = "backup")]
pub use backup::{
    BackupInfo, BackupManager, BackupOptions, ExportType, ProfileEntry, ProgressCallback,
    RestoreOptions, RestoreResult, SubSettingsManifestEntry,
};

// -----------------------------------------------------------------------------
// Profiles (requires profiles feature)
// -----------------------------------------------------------------------------

#[cfg(feature = "profiles")]
pub use profiles::{
    DEFAULT_PROFILE, PROFILES_DIR, ProfileEvent, ProfileManager, ProfileManifest, ProfileMigrator,
    migrate, validate_profile_name,
};

// -----------------------------------------------------------------------------
// Credentials
// -----------------------------------------------------------------------------

/// Credential storage backend trait and types.
pub use credentials::{CredentialBackend, MemoryBackend, SecretBackupPolicy, SecretStorage};

/// Keychain backend (requires `keychain` feature).
#[cfg(feature = "keychain")]
pub use credentials::KeychainBackend;

/// Encrypted file backend (requires `encrypted-file` feature).
#[cfg(feature = "encrypted-file")]
pub use credentials::EncryptedFileBackend;

/// Credential manager for secure secret storage.
/// Requires `keychain` or `encrypted-file` feature.
#[cfg(any(feature = "keychain", feature = "encrypted-file"))]
pub use credentials::CredentialManager;

// -----------------------------------------------------------------------------
// Derive Macro (requires derive feature)
// -----------------------------------------------------------------------------

/// Derive macro for auto-generating `SettingsSchema` implementations.
///
/// Use this to reduce boilerplate when defining settings structs.
///
/// # Example
///
/// ```rust,ignore
/// use rcman::DeriveSettingsSchema;
/// use serde::{Deserialize, Serialize};
///
/// #[derive(Default, Serialize, Deserialize, DeriveSettingsSchema)]
/// #[schema(category = "general")]
/// struct GeneralSettings {
///     #[setting(label = "Enable Tray")]
///     tray_enabled: bool,
/// }
/// ```
#[cfg(feature = "derive")]
pub use rcman_derive::SettingsSchema as DeriveSettingsSchema;

// =============================================================================
// PRELUDE MODULE (convenient glob import)
// =============================================================================

/// Prelude module for convenient glob imports.
///
/// Import all commonly-used types with a single line:
///
/// ```rust
/// use rcman::prelude::*;
/// ```
///
/// This includes the core types needed for most use cases:
/// - `SettingsManager`, `SettingsConfig`, `SettingsSchema`
/// - `SettingMetadata`, `SettingOption`, `opt`
/// - `SubSettingsConfig`
/// - `JsonStorage`, `StorageBackend`
/// - `Error`, `Result`
///
/// Feature-gated types are also included when their features are enabled.
pub mod prelude {
    // Core types users need for basic usage
    pub use super::{
        Error, NumberConstraints, Result, SettingConstraints, SettingMetadata, SettingOption,
        SettingType, SettingsConfig, SettingsManager, SettingsSchema, SubSettingsConfig,
        TextConstraints, opt,
    };

    // Storage
    pub use super::{JsonStorage, StorageBackend};

    #[cfg(feature = "toml")]
    pub use super::TomlStorage;

    // Cache
    pub use super::CacheStrategy;

    // Backup types
    #[cfg(feature = "backup")]
    pub use super::{BackupOptions, RestoreOptions};

    // Derive
    #[cfg(feature = "derive")]
    pub use super::DeriveSettingsSchema;
}
