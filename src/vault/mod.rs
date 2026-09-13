//! Vault module for locked/encrypted configuration storage
//!
//! Provides native AES-256-GCM encryption with Argon2id key derivation,
//! on-disk envelope formatting, and stateful lifecycle controls (`unlock()`, `lock()`).

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
