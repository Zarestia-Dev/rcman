//! Credential management module
//!
//! Provides secure storage for sensitive values with multiple backends:
//! - **Keychain**: OS-level secure storage (recommended) - requires `keychain` feature
//! - **Encrypted File**: Encrypted JSON fallback for CI/Docker - requires `encrypted-file` feature
//! - **Memory**: In-memory only for testing

#[cfg(feature = "encrypted-file")]
mod encrypted;
#[cfg(feature = "keychain")]
mod keychain;
mod memory;
mod types;

#[cfg(feature = "encrypted-file")]
pub use encrypted::EncryptedFileBackend;
#[cfg(feature = "keychain")]
pub use keychain::KeychainBackend;
pub use memory::MemoryBackend;

pub use types::{SecretBackupPolicy, SecretStorage};

use crate::error::Result;
#[cfg(any(feature = "keychain", feature = "encrypted-file"))]
use std::sync::Arc;

/// Trait for credential storage backends
pub trait CredentialBackend: Send + Sync {
    /// Store a credential
    ///
    /// # Errors
    ///
    /// Returns an error if the backend fails to store the key.
    fn store(&self, key: &str, value: &str) -> Result<()>;

    /// Retrieve a credential
    ///
    /// # Errors
    ///
    /// Returns an error if the backend fails to retrieve the key.
    fn get(&self, key: &str) -> Result<Option<String>>;

    /// Remove a credential
    ///
    /// # Errors
    ///
    /// Returns an error if the backend fails to remove the key.
    fn remove(&self, key: &str) -> Result<()>;

    /// Check if a credential exists
    ///
    /// # Errors
    ///
    /// Returns an error if the backend fails to check if the key exists.
    fn exists(&self, key: &str) -> Result<bool> {
        Ok(self.get(key)?.is_some())
    }

    /// List all stored credential keys
    ///
    /// # Errors
    ///
    /// Returns an error if the backend fails to list keys.
    fn list_keys(&self) -> Result<Vec<String>>;

    /// Backend name for logging/debugging
    fn backend_name(&self) -> &'static str;
}

/// Credential manager with configurable backend and fallback
#[cfg(any(feature = "keychain", feature = "encrypted-file"))]
#[derive(Clone)]
pub struct CredentialManager {
    /// Primary backend (typically keychain)
    primary: Arc<dyn CredentialBackend>,

    /// Fallback backend (typically encrypted file)
    fallback: Option<Arc<dyn CredentialBackend>>,

    /// Service name for keychain
    service_name: String,

    /// Profile context (if any)
    #[cfg(feature = "profiles")]
    profile_context: Option<String>,
}

#[cfg(any(feature = "keychain", feature = "encrypted-file"))]
impl CredentialManager {
    /// Create a new credential manager with keychain backend
    #[cfg(feature = "keychain")]
    pub fn new(service_name: impl Into<String>) -> Self {
        let service = service_name.into();
        Self {
            primary: Arc::new(KeychainBackend::new(service.clone())),
            fallback: None,
            service_name: service,
            #[cfg(feature = "profiles")]
            profile_context: None,
        }
    }

    /// Create a new credential manager with memory backend (when keychain feature is disabled)
    #[cfg(not(feature = "keychain"))]
    pub fn new(service_name: impl Into<String>) -> Self {
        Self::memory_only(service_name)
    }

    /// Create with automatic fallback to encrypted file
    #[cfg(all(feature = "keychain", feature = "encrypted-file"))]
    pub fn with_fallback(
        service_name: impl Into<String>,
        fallback_path: std::path::PathBuf,
        encryption_key: &[u8; 32],
    ) -> Self {
        let service = service_name.into();

        // For fallback, we need to handle salt manually since we already have the key
        let salt = EncryptedFileBackend::read_salt(&fallback_path)
            .ok()
            .flatten()
            .unwrap_or_else(EncryptedFileBackend::generate_salt);

        let fallback = EncryptedFileBackend::new(fallback_path, encryption_key, salt).ok();

        Self {
            primary: Arc::new(KeychainBackend::new(service.clone())),
            fallback: fallback.map(|f| Arc::new(f) as Arc<dyn CredentialBackend>),
            service_name: service,
            #[cfg(feature = "profiles")]
            profile_context: None,
        }
    }

    /// Create with only memory backend (for testing)
    pub fn memory_only(service_name: impl Into<String>) -> Self {
        Self {
            primary: Arc::new(MemoryBackend::new()),
            fallback: None,
            service_name: service_name.into(),
            #[cfg(feature = "profiles")]
            profile_context: None,
        }
    }

    /// Create with custom backend
    pub fn with_backend(
        service_name: impl Into<String>,
        backend: Arc<dyn CredentialBackend>,
    ) -> Self {
        Self {
            primary: backend,
            fallback: None,
            service_name: service_name.into(),
            #[cfg(feature = "profiles")]
            profile_context: None,
        }
    }

    /// Create a clone of this manager with a profile context
    ///
    /// This causes all operations to be namespaced under the profile.
    /// Key format becomes: `service:profiles:profile_name:key`
    #[cfg(feature = "profiles")]
    #[must_use]
    pub fn with_profile_context(&self, profile_name: &str) -> Self {
        Self {
            primary: self.primary.clone(),
            fallback: self.fallback.clone(),
            service_name: self.service_name.clone(),
            profile_context: Some(profile_name.to_string()),
        }
    }

    /// Store a credential
    ///
    /// # Errors
    ///
    /// Returns an error if the primary backend fails to store the key or if the fallback backend fails to store the key.
    pub fn store(&self, key: &str, value: &str) -> Result<()> {
        self.store_with_profile(key, value, None)
    }

    /// Store a credential with optional profile context
    ///
    /// # Errors
    ///
    /// Returns an error if the primary backend fails to store the key or if the fallback backend fails to store the key.
    /// # Panics
    ///
    /// This function will not panic under normal circumstances. The `.unwrap()` call
    /// on `self.fallback` is safe because it only executes within an `if let Some(...)`
    /// block that has already confirmed the fallback exists.
    pub fn store_with_profile(&self, key: &str, value: &str, profile: Option<&str>) -> Result<()> {
        let full_key = self.make_key_with_profile(key, profile);

        match self.primary.store(&full_key, value) {
            Ok(()) => {
                log::debug!(
                    "Stored credential '{}' in {}",
                    key,
                    self.primary.backend_name()
                );
                Ok(())
            }
            Err(e) => {
                if let Some(ref fallback) = self.fallback {
                    log::warn!(
                        "Primary backend failed, using fallback: {}",
                        self.fallback.as_ref().unwrap().backend_name()
                    );
                    fallback.store(&full_key, value)
                } else {
                    Err(e)
                }
            }
        }
    }

    /// Retrieve a credential
    ///
    /// # Errors
    ///
    /// Returns an error if the primary backend fails to retrieve the key or if the fallback backend fails to retrieve the key.
    pub fn get(&self, key: &str) -> Result<Option<String>> {
        self.get_with_profile(key, None)
    }

    /// Retrieve a credential with optional profile context
    ///
    /// # Errors
    ///
    /// Returns an error if the primary backend fails to retrieve the key or if the fallback backend fails to retrieve the key.
    pub fn get_with_profile(&self, key: &str, profile: Option<&str>) -> Result<Option<String>> {
        let full_key = self.make_key_with_profile(key, profile);

        // Try primary first
        match self.primary.get(&full_key) {
            Ok(Some(value)) => return Ok(Some(value)),
            Ok(None) => {}
            Err(e) => {
                log::debug!("Primary backend error: {e}");
            }
        }

        // Try fallback if available
        if let Some(ref fallback) = self.fallback {
            return fallback.get(&full_key);
        }

        Ok(None)
    }

    /// Remove a credential
    ///
    /// # Errors
    ///
    /// Returns an error if the primary backend fails to remove the key or if the fallback backend fails to remove the key.
    pub fn remove(&self, key: &str) -> Result<()> {
        let full_key = self.make_key(key);

        // Remove from both backends
        let _ = self.primary.remove(&full_key);
        if let Some(ref fallback) = self.fallback {
            let _ = fallback.remove(&full_key);
        }

        Ok(())
    }

    /// Check if a credential exists
    #[must_use]
    pub fn exists(&self, key: &str) -> bool {
        let full_key = self.make_key(key);

        if self.primary.exists(&full_key).unwrap_or(false) {
            return true;
        }

        if let Some(ref fallback) = self.fallback {
            return fallback.exists(&full_key).unwrap_or(false);
        }

        false
    }

    /// Clear all credentials for this service
    ///
    /// # Errors
    /// Returns an error if the primary backend fails to list keys or if the fallback backend fails to remove keys.
    pub fn clear(&self) -> Result<()> {
        // Warning: clear() operates on the service level, ignores profile context for now
        // to avoid accidentally deleting everything if context logic is wrong.
        // TODO: Implement scoped clear for profiles
        let prefix = format!("{}:", self.service_name);
        let mut keys_to_remove = std::collections::HashSet::new();

        if let Ok(keys) = self.primary.list_keys() {
            for key in keys {
                if key.starts_with(&prefix) {
                    keys_to_remove.insert(key);
                }
            }
        }

        if let Some(ref fallback) = self.fallback {
            if let Ok(keys) = fallback.list_keys() {
                for key in keys {
                    if key.starts_with(&prefix) {
                        keys_to_remove.insert(key);
                    }
                }
            }
        }

        for full_key in keys_to_remove {
            // Remove directly from backends using full key to avoid reconstruction overhead
            let _ = self.primary.remove(&full_key);
            if let Some(ref fallback) = self.fallback {
                let _ = fallback.remove(&full_key);
            }
        }

        Ok(())
    }

    /// Get service name
    #[must_use]
    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    /// Get active backend name
    #[must_use]
    pub fn backend_name(&self) -> &'static str {
        self.primary.backend_name()
    }

    fn make_key(&self, key: &str) -> String {
        self.make_key_with_profile(key, None)
    }

    fn make_key_with_profile(&self, key: &str, profile: Option<&str>) -> String {
        #[cfg(feature = "profiles")]
        {
            // Check explicit profile parameter first
            if let Some(profile) = profile {
                return format!("{}:profiles:{}:{}", self.service_name, profile, key);
            }
            // Fall back to stored context
            if let Some(ref profile_ctx) = self.profile_context {
                return format!("{}:profiles:{}:{}", self.service_name, profile_ctx, key);
            }
        }
        #[cfg(not(feature = "profiles"))]
        let _ = profile;
        format!("{}:{}", self.service_name, key)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(all(test, any(feature = "keychain", feature = "encrypted-file")))]
mod tests {
    use super::*;

    #[test]
    fn test_memory_backend_crud() {
        let manager = CredentialManager::memory_only("test-app");

        // Store
        manager.store("api_key", "secret123").unwrap();
        assert!(manager.exists("api_key"));

        // Get
        let value = manager.get("api_key").unwrap();
        assert_eq!(value, Some("secret123".to_string()));

        // Remove
        manager.remove("api_key").unwrap();
        assert!(!manager.exists("api_key"));
    }

    #[test]
    fn test_credential_not_found() {
        let manager = CredentialManager::memory_only("test-app");
        let value = manager.get("nonexistent").unwrap();
        assert_eq!(value, None);
    }
}
