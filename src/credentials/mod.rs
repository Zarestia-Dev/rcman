//! Credential management module
//!
//! Provides secure storage for sensitive values with multiple backends:
//! - **Keychain**: OS-level secure storage (recommended) - requires `keychain` feature
//!   - macOS/iOS: native keychain via `keyring` apple-native
//!   - Windows: Windows Credential Manager via `keyring`
//!   - Linux: Secret Service via `keyring`
//!   - Android: native credential store via `keyring` v4 / `keyring-core` (`android-native-keyring-store`, requires `ndk_context` setup)
//! - **Encrypted File**: Encrypted JSON fallback for CI/Docker and unsupported platforms - requires `encrypted-file` feature
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

pub use types::{SecretBackupPolicy, SecretPasswordSource, SecretStorage};

use crate::error::Result;
#[cfg(any(feature = "keychain", feature = "encrypted-file"))]
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

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

    /// Whether the primary backend has failed permanently in this session
    is_primary_failed: Arc<AtomicBool>,

    /// Service name for keychain
    service_name: String,

    /// Profile context (if any)
    #[cfg(feature = "profiles")]
    profile_context: Option<String>,

    /// Volatile emergency fallback (always available, lost on restart)
    volatile: Arc<MemoryBackend>,

    /// In-memory cache of keys stored in the credential store to optimize lookup and migration, keyed by profile context
    tracked_secrets_cache: Arc<
        std::sync::RwLock<
            std::collections::HashMap<Option<String>, std::collections::HashSet<String>>,
        >,
    >,

    /// In-memory cache of tracked profile names to optimize profile lookups
    #[cfg(feature = "profiles")]
    tracked_profiles_cache: Arc<std::sync::RwLock<Option<std::collections::HashSet<String>>>>,
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
            is_primary_failed: Arc::new(AtomicBool::new(false)),
            service_name: service,
            #[cfg(feature = "profiles")]
            profile_context: None,
            volatile: Arc::new(MemoryBackend::new()),
            tracked_secrets_cache: Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
            #[cfg(feature = "profiles")]
            tracked_profiles_cache: Arc::new(std::sync::RwLock::new(None)),
        }
    }

    /// Create a new credential manager with memory backend (when keychain feature is disabled)
    #[cfg(not(feature = "keychain"))]
    pub fn new(service_name: impl Into<String>) -> Self {
        let service = service_name.into();
        Self {
            primary: Arc::new(MemoryBackend::new()),
            fallback: None,
            is_primary_failed: Arc::new(AtomicBool::new(false)),
            service_name: service,
            #[cfg(feature = "profiles")]
            profile_context: None,
            volatile: Arc::new(MemoryBackend::new()),
            tracked_secrets_cache: Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
            #[cfg(feature = "profiles")]
            tracked_profiles_cache: Arc::new(std::sync::RwLock::new(None)),
        }
    }

    /// Create with automatic fallback to encrypted file using a password source
    #[cfg(all(feature = "keychain", feature = "encrypted-file"))]
    pub fn with_fallback(
        service_name: impl Into<String>,
        fallback_path: std::path::PathBuf,
        password_source: &SecretPasswordSource,
    ) -> Self {
        let service = service_name.into();

        let fallback = EncryptedFileBackend::with_source(fallback_path, password_source).ok();

        Self {
            primary: Arc::new(KeychainBackend::new(service.clone())),
            fallback: fallback.map(|f| Arc::new(f) as Arc<dyn CredentialBackend>),
            is_primary_failed: Arc::new(AtomicBool::new(false)),
            service_name: service,
            #[cfg(feature = "profiles")]
            profile_context: None,
            volatile: Arc::new(MemoryBackend::new()),
            tracked_secrets_cache: Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
            #[cfg(feature = "profiles")]
            tracked_profiles_cache: Arc::new(std::sync::RwLock::new(None)),
        }
    }

    /// Create with only memory backend (for testing)
    pub fn memory_only(service_name: impl Into<String>) -> Self {
        Self {
            primary: Arc::new(MemoryBackend::new()),
            fallback: None,
            is_primary_failed: Arc::new(AtomicBool::new(false)),
            service_name: service_name.into(),
            #[cfg(feature = "profiles")]
            profile_context: None,
            volatile: Arc::new(MemoryBackend::new()),
            tracked_secrets_cache: Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
            #[cfg(feature = "profiles")]
            tracked_profiles_cache: Arc::new(std::sync::RwLock::new(None)),
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
            is_primary_failed: Arc::new(AtomicBool::new(false)),
            service_name: service_name.into(),
            #[cfg(feature = "profiles")]
            profile_context: None,
            volatile: Arc::new(MemoryBackend::new()),
            tracked_secrets_cache: Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
            #[cfg(feature = "profiles")]
            tracked_profiles_cache: Arc::new(std::sync::RwLock::new(None)),
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
            is_primary_failed: self.is_primary_failed.clone(),
            service_name: self.service_name.clone(),
            profile_context: Some(profile_name.to_string()),
            volatile: self.volatile.clone(),
            tracked_secrets_cache: self.tracked_secrets_cache.clone(),
            tracked_profiles_cache: self.tracked_profiles_cache.clone(),
        }
    }

    /// Returns true if the primary backend has failed and we are now using fallback.
    #[must_use]
    pub fn is_primary_failed(&self) -> bool {
        self.is_primary_failed.load(Ordering::Relaxed)
    }

    /// Returns true if the volatile emergency fallback is currently holding any data.
    #[must_use]
    pub fn is_volatile_active(&self) -> bool {
        self.volatile.list_keys().is_ok_and(|keys| !keys.is_empty())
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
    pub fn store_with_profile(&self, key: &str, value: &str, profile: Option<&str>) -> Result<()> {
        let full_key = self.make_key_with_profile(key, profile);

        // Always attempt primary backend first
        match self.primary.store(&full_key, value) {
            Ok(()) => {
                log::debug!(
                    "Stored credential '{key}' in {}",
                    self.primary.backend_name()
                );
                self.is_primary_failed.store(false, Ordering::Relaxed);
                let _ = self.volatile.store(&full_key, value);
                return Ok(());
            }
            Err(e) => {
                log::debug!("Primary backend store for '{key}' failed: {e:?}");
                self.is_primary_failed.store(true, Ordering::Relaxed);
            }
        }

        // Try persistent fallback if available
        if let Some(ref fallback) = self.fallback {
            match fallback.store(&full_key, value) {
                Ok(()) => {
                    log::debug!("Stored credential '{key}' in persistent fallback");
                    let _ = self.volatile.store(&full_key, value);
                    return Ok(());
                }
                Err(e) => {
                    log::error!(
                        "Persistent fallback failed for '{key}': {e}. Falling back to VOLATILE memory."
                    );
                }
            }
        }

        // Final attempt: Volatile memory (won't persist across restarts)
        log::warn!("Using volatile fallback for '{key}' - secret will NOT persist across restarts");
        self.volatile.store(&full_key, value)
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
            Ok(Some(val)) => {
                self.is_primary_failed.store(false, Ordering::Relaxed);
                let _ = self.volatile.store(&full_key, &val);
                return Ok(Some(val));
            }
            Ok(None) => {
                self.is_primary_failed.store(false, Ordering::Relaxed);
            }
            Err(e) => {
                log::debug!("Primary backend get for '{key}' failed: {e:?}");
                self.is_primary_failed.store(true, Ordering::Relaxed);
            }
        }

        // Try fallback
        if let Some(ref fallback) = self.fallback {
            match fallback.get(&full_key) {
                Ok(Some(val)) => {
                    let _ = self.volatile.store(&full_key, &val);
                    return Ok(Some(val));
                }
                Ok(None) => {}
                Err(e) => {
                    log::error!(
                        "Persistent fallback failed for '{key}': {e}. Trying VOLATILE memory."
                    );
                }
            }
        }

        // Final attempt: Volatile memory
        self.volatile.get(&full_key)
    }

    /// Remove a credential
    ///
    /// # Errors
    ///
    /// Returns an error if the primary backend fails to remove the key or if the fallback backend fails to remove the key.
    pub fn remove(&self, key: &str) -> Result<()> {
        self.remove_with_profile(key, None)
    }

    /// Remove a credential with optional profile context
    ///
    /// # Errors
    ///
    /// Returns an error if the primary backend fails to remove the key or if the fallback backend fails to remove the key.
    pub fn remove_with_profile(&self, key: &str, profile: Option<&str>) -> Result<()> {
        let full_key = self.make_key_with_profile(key, profile);

        // Remove from all backends
        let _ = self.primary.remove(&full_key);
        if let Some(ref fallback) = self.fallback {
            let _ = fallback.remove(&full_key);
        }
        let _ = self.volatile.remove(&full_key);

        Ok(())
    }

    /// Check if a credential exists
    #[must_use]
    pub fn exists(&self, key: &str) -> bool {
        self.exists_with_profile(key, None)
    }

    /// Check if a credential exists with optional profile context
    #[must_use]
    pub fn exists_with_profile(&self, key: &str, profile: Option<&str>) -> bool {
        let full_key = self.make_key_with_profile(key, profile);

        if self.primary.exists(&full_key).unwrap_or(false) {
            return true;
        }

        if let Some(ref fallback) = self.fallback
            && fallback.exists(&full_key).unwrap_or(false)
        {
            return true;
        }

        self.volatile.exists(&full_key).unwrap_or(false)
    }

    /// Clear all credentials for this service.
    ///
    /// # Errors
    ///
    /// Returns an error if the cache invalidation fails.
    pub fn clear(&self) -> Result<()> {
        #[cfg(feature = "profiles")]
        let profile = self.profile_context.as_deref();
        #[cfg(not(feature = "profiles"))]
        let profile: Option<&str> = None;

        let mut keys_to_remove = std::collections::HashSet::new();

        // 1. Fetch tracked secrets from the credential store (__rcman_secrets__)
        if let Ok(tracked) = self.get_tracked_secrets(profile) {
            for key in tracked {
                let full_key = self.make_key_with_profile(&key, profile);
                keys_to_remove.insert(full_key);
            }
        }

        // 2. Also query list_keys on backends
        #[cfg(feature = "profiles")]
        let prefix = if let Some(profile_ctx) = &self.profile_context {
            format!("{}:profiles:{}:", self.service_name, profile_ctx)
        } else {
            format!("{}:", self.service_name)
        };

        #[cfg(not(feature = "profiles"))]
        let prefix = format!("{}:", self.service_name);

        if let Ok(keys) = self.primary.list_keys() {
            for key in keys {
                if key.starts_with(&prefix) {
                    keys_to_remove.insert(key);
                }
            }
        }

        if let Some(ref fallback) = self.fallback
            && let Ok(keys) = fallback.list_keys()
        {
            for key in keys {
                if key.starts_with(&prefix) {
                    keys_to_remove.insert(key);
                }
            }
        }

        if let Ok(keys) = self.volatile.list_keys() {
            for key in keys {
                if key.starts_with(&prefix) {
                    keys_to_remove.insert(key);
                }
            }
        }

        // 3. Always include __rcman_secrets__ itself in keys_to_remove
        let rcman_secrets_key = self.make_key_with_profile("__rcman_secrets__", profile);
        keys_to_remove.insert(rcman_secrets_key);

        // Track per-key failures so we can log a useful aggregate without
        // aborting the loop on the first error.
        let mut failure_count: usize = 0;
        let total = keys_to_remove.len();

        for full_key in &keys_to_remove {
            // Remove directly from backends using full key to avoid
            // reconstruction overhead.  Each backend's `remove()` is
            // idempotent — a `NoEntry` result is treated as success.
            if let Err(e) = self.primary.remove(full_key) {
                log::debug!("clear: primary.remove({full_key}) failed: {e}");
                failure_count += 1;
            }
            if let Some(ref fallback) = self.fallback
                && let Err(e) = fallback.remove(full_key)
            {
                log::debug!("clear: fallback.remove({full_key}) failed: {e}");
                failure_count += 1;
            }
            if let Err(e) = self.volatile.remove(full_key) {
                log::debug!("clear: volatile.remove({full_key}) failed: {e}");
                failure_count += 1;
            }
        }

        if let Err(e) = self.invalidate_tracked_secrets_cache() {
            log::warn!("clear: failed to invalidate tracked_secrets_cache: {e}");
            return Err(e);
        }

        #[cfg(feature = "profiles")]
        if self.profile_context.is_none() {
            if let Ok(profiles) = self.get_tracked_profiles() {
                for p in profiles {
                    let profile_creds = self.with_profile_context(&p);
                    let _ = profile_creds.clear();
                }
            }
            let _ = self.remove("__rcman_profiles__");
        }

        if failure_count > 0 {
            log::warn!(
                "clear: {failure_count} of {} removals failed (see debug log for details)",
                total * 3 // each key tried against up to 3 backends
            );
        } else {
            log::debug!("clear: removed {total} keys");
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
        if self.is_primary_failed.load(Ordering::Relaxed) {
            if let Some(ref fallback) = self.fallback {
                fallback.backend_name()
            } else {
                self.volatile.backend_name()
            }
        } else {
            self.primary.backend_name()
        }
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

    /// Load tracked secrets, utilizing the in-memory cache if available.
    ///
    /// # Errors
    ///
    /// Returns an error if the tracked secrets cache lock is poisoned,
    /// or if reading the credential store or parsing the credential list fails.
    pub fn get_tracked_secrets(
        &self,
        profile: Option<&str>,
    ) -> Result<std::collections::HashSet<String>> {
        let profile_key = profile.map(ToString::to_string);
        {
            let cache_guard = self
                .tracked_secrets_cache
                .read()
                .map_err(|_| crate::error::Error::LockPoisoned)?;
            if let Some(cache) = cache_guard.get(&profile_key) {
                return Ok(cache.clone());
            }
        }

        // Perform I/O outside of the write lock to prevent blocking concurrent readers/writers
        let secrets = match self.get_with_profile("__rcman_secrets__", profile)? {
            Some(value_str) => {
                let list: Vec<String> = serde_json::from_str(&value_str).map_err(|e| {
                    crate::error::Error::Credential(format!(
                        "Failed to parse tracked secrets list: {e}"
                    ))
                })?;
                list.into_iter().collect()
            }
            None => std::collections::HashSet::new(),
        };

        let mut cache_guard = self
            .tracked_secrets_cache
            .write()
            .map_err(|_| crate::error::Error::LockPoisoned)?;
        cache_guard.insert(profile_key, secrets.clone());
        Ok(secrets)
    }

    /// Save tracked secrets to the credential store and update the in-memory cache.
    ///
    /// # Errors
    ///
    /// Returns an error if serializing the tracked secrets fails, if storing the
    /// credential fails, or if the tracked secrets cache lock is poisoned.
    pub fn save_tracked_secrets(
        &self,
        secrets: &std::collections::HashSet<String>,
        profile: Option<&str>,
    ) -> Result<()> {
        let profile_key = profile.map(ToString::to_string);
        let list: Vec<&String> = secrets.iter().collect();
        let value_str = serde_json::to_string(&list).map_err(|e| {
            crate::error::Error::Credential(format!(
                "Failed to serialize tracked secrets list: {e}"
            ))
        })?;
        self.store_with_profile("__rcman_secrets__", &value_str, profile)?;

        #[cfg(feature = "profiles")]
        if let Some(profile_name) = profile {
            let _ = self.add_tracked_profile(profile_name);
        }

        let mut cache_guard = self
            .tracked_secrets_cache
            .write()
            .map_err(|_| crate::error::Error::LockPoisoned)?;
        cache_guard.insert(profile_key, secrets.clone());
        Ok(())
    }

    /// Load the list of tracked profile names with stored credentials, utilizing the in-memory cache if available.
    ///
    /// # Errors
    ///
    /// Returns an error if reading the credential store or parsing fails.
    #[cfg(feature = "profiles")]
    pub fn get_tracked_profiles(&self) -> Result<std::collections::HashSet<String>> {
        {
            let cache_guard = self
                .tracked_profiles_cache
                .read()
                .map_err(|_| crate::error::Error::LockPoisoned)?;
            if let Some(ref cache) = *cache_guard {
                return Ok(cache.clone());
            }
        }

        // Perform I/O outside of the write lock
        let profiles: std::collections::HashSet<String> = match self.get("__rcman_profiles__")? {
            Some(value_str) => {
                let list: Vec<String> = serde_json::from_str(&value_str).map_err(|e| {
                    crate::error::Error::Credential(format!(
                        "Failed to parse tracked profiles list: {e}"
                    ))
                })?;
                list.into_iter().collect()
            }
            None => std::collections::HashSet::new(),
        };

        let mut cache_guard = self
            .tracked_profiles_cache
            .write()
            .map_err(|_| crate::error::Error::LockPoisoned)?;
        *cache_guard = Some(profiles.clone());
        Ok(profiles)
    }

    /// Register a profile name in the tracked profiles list and update the in-memory cache.
    ///
    /// # Errors
    ///
    /// Returns an error if storing the profile list in credentials fails.
    #[cfg(feature = "profiles")]
    pub fn add_tracked_profile(&self, profile: &str) -> Result<()> {
        let mut profiles = self.get_tracked_profiles()?;
        if profiles.insert(profile.to_string()) {
            let list: Vec<&String> = profiles.iter().collect();
            let value_str = serde_json::to_string(&list).map_err(|e| {
                crate::error::Error::Credential(format!(
                    "Failed to serialize tracked profiles list: {e}"
                ))
            })?;
            self.store("__rcman_profiles__", &value_str)?;

            let mut cache_guard = self
                .tracked_profiles_cache
                .write()
                .map_err(|_| crate::error::Error::LockPoisoned)?;
            *cache_guard = Some(profiles);
        }
        Ok(())
    }

    /// Add a key to the tracked secrets list
    ///
    /// # Errors
    ///
    /// Returns an error if loading or saving the tracked secrets fails.
    pub fn add_tracked_secret(&self, key: &str, profile: Option<&str>) -> Result<()> {
        let mut tracked = self.get_tracked_secrets(profile)?;
        if tracked.insert(key.to_string()) {
            self.save_tracked_secrets(&tracked, profile)?;
        }
        Ok(())
    }

    /// Remove a key from the tracked secrets list
    ///
    /// # Errors
    ///
    /// Returns an error if loading or saving the tracked secrets fails.
    pub fn remove_tracked_secret(&self, key: &str, profile: Option<&str>) -> Result<()> {
        let mut tracked = self.get_tracked_secrets(profile)?;
        if tracked.remove(key) {
            self.save_tracked_secrets(&tracked, profile)?;
        }
        Ok(())
    }

    /// Invalidate the tracked secrets cache and profile cache (clears all in-memory caches)
    ///
    /// # Errors
    ///
    /// Returns an error if the cache lock is poisoned.
    pub fn invalidate_tracked_secrets_cache(&self) -> Result<()> {
        {
            let mut cache_guard = self
                .tracked_secrets_cache
                .write()
                .map_err(|_| crate::error::Error::LockPoisoned)?;
            cache_guard.clear();
        }

        #[cfg(feature = "profiles")]
        {
            let mut profile_cache_guard = self
                .tracked_profiles_cache
                .write()
                .map_err(|_| crate::error::Error::LockPoisoned)?;
            *profile_cache_guard = None;
        }

        Ok(())
    }

    /// Reset/clear the tracked secrets cache to an empty set for a specific profile
    ///
    /// # Errors
    ///
    /// Returns an error if the tracked secrets cache lock is poisoned.
    pub fn clear_tracked_secrets_cache(&self, profile: Option<&str>) -> Result<()> {
        let profile_key = profile.map(ToString::to_string);
        let mut cache_guard = self
            .tracked_secrets_cache
            .write()
            .map_err(|_| crate::error::Error::LockPoisoned)?;
        cache_guard.insert(profile_key, std::collections::HashSet::new());
        Ok(())
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(all(test, any(feature = "keychain", feature = "encrypted-file")))]
mod tests {
    use super::*;

    struct FailingBackend;

    impl CredentialBackend for FailingBackend {
        fn store(&self, _key: &str, _value: &str) -> Result<()> {
            Err(crate::error::Error::Credential(
                "primary store failed".to_string(),
            ))
        }

        fn get(&self, _key: &str) -> Result<Option<String>> {
            Err(crate::error::Error::Credential(
                "primary get failed".to_string(),
            ))
        }

        fn remove(&self, _key: &str) -> Result<()> {
            Err(crate::error::Error::Credential(
                "primary remove failed".to_string(),
            ))
        }

        fn list_keys(&self) -> Result<Vec<String>> {
            Ok(Vec::new())
        }

        fn backend_name(&self) -> &'static str {
            "failing"
        }
    }

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

    #[test]
    fn test_fallback_used_when_primary_backend_fails() {
        let manager = CredentialManager {
            primary: std::sync::Arc::new(FailingBackend),
            fallback: Some(std::sync::Arc::new(MemoryBackend::new())),
            is_primary_failed: Arc::new(AtomicBool::new(false)),
            service_name: "test-app".to_string(),
            #[cfg(feature = "profiles")]
            profile_context: None,
            volatile: Arc::new(MemoryBackend::new()),
            tracked_secrets_cache: Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
            #[cfg(feature = "profiles")]
            tracked_profiles_cache: Arc::new(std::sync::RwLock::new(None)),
        };

        manager.remove("api_key").unwrap();
        assert_eq!(manager.get("api_key").unwrap(), None);
    }

    #[test]
    fn test_sticky_fallback_is_remembered() {
        let manager = CredentialManager {
            primary: std::sync::Arc::new(FailingBackend),
            fallback: Some(std::sync::Arc::new(MemoryBackend::new())),
            is_primary_failed: Arc::new(AtomicBool::new(false)),
            service_name: "test-app".to_string(),
            #[cfg(feature = "profiles")]
            profile_context: None,
            volatile: Arc::new(MemoryBackend::new()),
            tracked_secrets_cache: Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
            #[cfg(feature = "profiles")]
            tracked_profiles_cache: Arc::new(std::sync::RwLock::new(None)),
        };

        // Initially not failed
        assert!(!manager.is_primary_failed.load(Ordering::Relaxed));

        // Operation triggers failure and sticky flag
        manager.store("key1", "val1").unwrap();
        assert!(manager.is_primary_failed.load(Ordering::Relaxed));

        // Subsequent operation doesn't even call primary (already marked as failed)
        manager.get("key1").unwrap();
        assert!(manager.is_primary_failed.load(Ordering::Relaxed));
    }

    #[cfg(feature = "profiles")]
    #[test]
    fn test_clear_with_profile_context_is_scoped() {
        let manager = CredentialManager::memory_only("test-app");

        manager
            .store_with_profile("api_key", "default-secret", Some("default"))
            .unwrap();
        manager
            .store_with_profile("api_key", "work-secret", Some("work"))
            .unwrap();
        manager.store("global_key", "global-secret").unwrap();

        let work_manager = manager.with_profile_context("work");
        work_manager.clear().unwrap();

        assert_eq!(
            manager.get_with_profile("api_key", Some("work")).unwrap(),
            None
        );
        assert_eq!(
            manager
                .get_with_profile("api_key", Some("default"))
                .unwrap(),
            Some("default-secret".to_string())
        );
        assert_eq!(
            manager.get("global_key").unwrap(),
            Some("global-secret".to_string())
        );
    }

    #[cfg(feature = "profiles")]
    #[test]
    fn test_clear_without_profile_context_removes_all_scopes() {
        let manager = CredentialManager::memory_only("test-app");

        manager
            .store_with_profile("api_key", "default-secret", Some("default"))
            .unwrap();
        manager
            .store_with_profile("api_key", "work-secret", Some("work"))
            .unwrap();
        manager.store("global_key", "global-secret").unwrap();

        manager.clear().unwrap();

        assert_eq!(
            manager
                .get_with_profile("api_key", Some("default"))
                .unwrap(),
            None
        );
        assert_eq!(
            manager.get_with_profile("api_key", Some("work")).unwrap(),
            None
        );
        assert_eq!(manager.get("global_key").unwrap(), None);
    }

    #[cfg(feature = "profiles")]
    #[test]
    fn test_profile_context_isolation_under_concurrency() {
        use std::sync::Arc;
        use std::thread;

        let manager = Arc::new(CredentialManager::memory_only("test-app"));

        let work_manager = Arc::new(manager.with_profile_context("work"));
        let default_manager = Arc::new(manager.with_profile_context("default"));

        let work = {
            let work_manager = Arc::clone(&work_manager);
            thread::spawn(move || {
                for _ in 0..100 {
                    work_manager.store("api_key", "work-secret").unwrap();
                }
            })
        };

        let default = {
            let default_manager = Arc::clone(&default_manager);
            thread::spawn(move || {
                for _ in 0..100 {
                    default_manager.store("api_key", "default-secret").unwrap();
                }
            })
        };

        work.join().unwrap();
        default.join().unwrap();

        assert_eq!(
            work_manager.get("api_key").unwrap(),
            Some("work-secret".to_string())
        );
        assert_eq!(
            default_manager.get("api_key").unwrap(),
            Some("default-secret".to_string())
        );
        assert_eq!(manager.get("api_key").unwrap(), None);
    }

    #[test]
    fn test_ultimate_memory_fallback() {
        let manager = CredentialManager {
            primary: Arc::new(FailingBackend),
            fallback: Some(Arc::new(FailingBackend)),
            is_primary_failed: Arc::new(AtomicBool::new(false)),
            service_name: "test-app".to_string(),
            #[cfg(feature = "profiles")]
            profile_context: None,
            volatile: Arc::new(MemoryBackend::new()),
            tracked_secrets_cache: Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
            #[cfg(feature = "profiles")]
            tracked_profiles_cache: Arc::new(std::sync::RwLock::new(None)),
        };

        // Even though persistent backends fail, store should succeed using volatile memory
        manager.store("api_key", "top-secret").unwrap();

        // Retrieve from volatile memory
        assert_eq!(
            manager.get("api_key").unwrap(),
            Some("top-secret".to_string())
        );

        // Cleanup should also pass
        manager.remove("api_key").unwrap();
        assert_eq!(manager.get("api_key").unwrap(), None);
    }

    struct StoreFailingBackend;

    impl CredentialBackend for StoreFailingBackend {
        fn store(&self, _key: &str, _value: &str) -> Result<()> {
            Err(crate::error::Error::Credential(
                "primary store failed".to_string(),
            ))
        }

        fn get(&self, _key: &str) -> Result<Option<String>> {
            // Emulates OS keychain behavior where unwritten entry returns Ok(None)
            Ok(None)
        }

        fn remove(&self, _key: &str) -> Result<()> {
            Ok(())
        }

        fn list_keys(&self) -> Result<Vec<String>> {
            Ok(Vec::new())
        }

        fn backend_name(&self) -> &'static str {
            "store_failing"
        }
    }

    #[test]
    fn test_volatile_fallback_when_primary_get_returns_none() {
        let manager = CredentialManager {
            primary: Arc::new(StoreFailingBackend),
            fallback: None,
            is_primary_failed: Arc::new(AtomicBool::new(false)),
            service_name: "test-app".to_string(),
            #[cfg(feature = "profiles")]
            profile_context: None,
            volatile: Arc::new(MemoryBackend::new()),
            tracked_secrets_cache: Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
            #[cfg(feature = "profiles")]
            tracked_profiles_cache: Arc::new(std::sync::RwLock::new(None)),
        };

        // Primary store fails, stored in volatile memory
        manager.store("api_key", "top-secret").unwrap();

        // Primary get returns Ok(None), but volatile fallback has it
        assert_eq!(
            manager.get("api_key").unwrap(),
            Some("top-secret".to_string())
        );

        // Cleanup
        manager.remove("api_key").unwrap();
        assert_eq!(manager.get("api_key").unwrap(), None);
    }

    #[cfg(feature = "profiles")]
    #[test]
    fn test_exists_with_profile() {
        let manager = CredentialManager::memory_only("test-app");
        manager
            .store_with_profile("token", "val-work", Some("work"))
            .unwrap();

        assert!(manager.exists_with_profile("token", Some("work")));
        assert!(!manager.exists_with_profile("token", Some("personal")));
        assert!(!manager.exists("token"));
    }

    #[test]
    fn test_read_through_cache_populates_volatile() {
        let primary = Arc::new(MemoryBackend::new());
        primary.store("test-app:cached_key", "secret-val").unwrap();

        let manager = CredentialManager {
            primary,
            fallback: None,
            is_primary_failed: Arc::new(AtomicBool::new(false)),
            service_name: "test-app".to_string(),
            #[cfg(feature = "profiles")]
            profile_context: None,
            volatile: Arc::new(MemoryBackend::new()),
            tracked_secrets_cache: Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
            #[cfg(feature = "profiles")]
            tracked_profiles_cache: Arc::new(std::sync::RwLock::new(None)),
        };

        // Before read, volatile is empty
        assert_eq!(manager.volatile.get("test-app:cached_key").unwrap(), None);

        // Read from primary through manager
        let val = manager.get("cached_key").unwrap();
        assert_eq!(val, Some("secret-val".to_string()));

        // After read, volatile is populated (read-through cache)
        assert_eq!(
            manager.volatile.get("test-app:cached_key").unwrap(),
            Some("secret-val".to_string())
        );
    }
}
