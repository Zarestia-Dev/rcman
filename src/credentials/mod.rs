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

#[cfg(any(feature = "keychain", feature = "encrypted-file"))]
mod cache;
#[cfg(feature = "encrypted-file")]
mod encrypted;
#[cfg(feature = "keychain")]
mod keychain;
mod memory;
#[cfg(any(feature = "keychain", feature = "encrypted-file"))]
mod transaction;
mod types;
#[cfg(all(
    feature = "profiles",
    any(feature = "keychain", feature = "encrypted-file")
))]
pub(crate) use transaction::ProfileSecretScope;
#[cfg(any(feature = "keychain", feature = "encrypted-file"))]
pub(crate) use transaction::{decode_setting, encode_setting};

#[cfg(feature = "encrypted-file")]
pub use encrypted::EncryptedFileBackend;
#[cfg(feature = "keychain")]
pub use keychain::KeychainBackend;
pub use memory::MemoryBackend;

pub use types::{SecretBackupPolicy, SecretPasswordSource, SecretStorage};

use crate::error::Result;
#[cfg(any(feature = "keychain", feature = "encrypted-file"))]
use cache::{CredentialMemory, MemoryEntry};
#[cfg(any(feature = "keychain", feature = "encrypted-file"))]
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

#[cfg(any(feature = "keychain", feature = "encrypted-file"))]
fn is_credential_backend_unavailable(error: &crate::error::Error) -> bool {
    matches!(error, crate::error::Error::CredentialBackendUnavailable(_))
}

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
    /// Returns an error if the backend fails to retrieve the key. Use
    /// [`crate::Error::CredentialBackendUnavailable`] when access to the backend
    /// is unavailable; reserve other errors for failures such as invalid data.
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

/// Operational state of the credential backends.
///
/// `primary_available` reflects the last observed primary backend operation,
/// not a live probe. A `false` value means the primary backend should be
/// considered degraded until a later operation succeeds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialStatus {
    /// Name of the configured primary backend.
    pub primary_backend: &'static str,
    /// Name of the configured persistent fallback, if any.
    pub fallback_backend: Option<&'static str>,
    /// Whether the primary backend has not recently reported an outage.
    pub primary_available: bool,
    /// Whether a write currently exists only in volatile memory.
    pub volatile_writes: bool,
}

/// Credential manager with configurable backend and fallback
#[cfg(any(feature = "keychain", feature = "encrypted-file"))]
#[derive(Clone)]
pub struct CredentialManager {
    /// Primary backend (typically keychain)
    primary: Arc<dyn CredentialBackend>,

    /// Fallback backend (typically encrypted file)
    fallback: Option<Arc<dyn CredentialBackend>>,

    /// Whether direct credential access last observed a primary backend failure.
    is_primary_failed: Arc<AtomicBool>,
    commit_lock: Arc<std::sync::Mutex<()>>,

    /// Service name for keychain
    service_name: String,

    /// Profile context (if any)
    #[cfg(feature = "profiles")]
    profile_context: Option<String>,

    /// Cached credentials and unpersisted writes retain distinct enum states.
    memory: Arc<CredentialMemory>,

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
            commit_lock: Arc::new(std::sync::Mutex::new(())),
            service_name: service,
            #[cfg(feature = "profiles")]
            profile_context: None,
            memory: Arc::new(CredentialMemory::default()),
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
            commit_lock: Arc::new(std::sync::Mutex::new(())),
            service_name: service,
            #[cfg(feature = "profiles")]
            profile_context: None,
            memory: Arc::new(CredentialMemory::default()),
            tracked_secrets_cache: Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
            #[cfg(feature = "profiles")]
            tracked_profiles_cache: Arc::new(std::sync::RwLock::new(None)),
        }
    }

    /// Create with automatic fallback to encrypted file using a password source
    ///
    /// # Errors
    ///
    /// Returns an error if the password source cannot be resolved or if the
    /// encrypted fallback file is invalid or cannot be read.
    #[cfg(all(feature = "keychain", feature = "encrypted-file"))]
    pub fn with_fallback(
        service_name: impl Into<String>,
        fallback_path: std::path::PathBuf,
        password_source: &SecretPasswordSource,
    ) -> Result<Self> {
        let service = service_name.into();

        let fallback = EncryptedFileBackend::with_source(fallback_path, password_source)?;

        Ok(Self {
            primary: Arc::new(KeychainBackend::new(service.clone())),
            fallback: Some(Arc::new(fallback)),
            is_primary_failed: Arc::new(AtomicBool::new(false)),
            commit_lock: Arc::new(std::sync::Mutex::new(())),
            service_name: service,
            #[cfg(feature = "profiles")]
            profile_context: None,
            memory: Arc::new(CredentialMemory::default()),
            tracked_secrets_cache: Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
            #[cfg(feature = "profiles")]
            tracked_profiles_cache: Arc::new(std::sync::RwLock::new(None)),
        })
    }

    /// Create with only memory backend (for testing)
    pub fn memory_only(service_name: impl Into<String>) -> Self {
        Self {
            primary: Arc::new(MemoryBackend::new()),
            fallback: None,
            is_primary_failed: Arc::new(AtomicBool::new(false)),
            commit_lock: Arc::new(std::sync::Mutex::new(())),
            service_name: service_name.into(),
            #[cfg(feature = "profiles")]
            profile_context: None,
            memory: Arc::new(CredentialMemory::default()),
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
            commit_lock: Arc::new(std::sync::Mutex::new(())),
            service_name: service_name.into(),
            #[cfg(feature = "profiles")]
            profile_context: None,
            memory: Arc::new(CredentialMemory::default()),
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
            commit_lock: self.commit_lock.clone(),
            service_name: self.service_name.clone(),
            profile_context: Some(profile_name.to_string()),
            memory: self.memory.clone(),
            tracked_secrets_cache: self.tracked_secrets_cache.clone(),
            tracked_profiles_cache: self.tracked_profiles_cache.clone(),
        }
    }

    /// Reports the most recently observed primary backend failure state.
    #[must_use]
    pub fn is_primary_failed(&self) -> bool {
        self.is_primary_failed.load(Ordering::Relaxed)
    }

    /// Returns true if the volatile emergency fallback is currently holding any data.
    #[must_use]
    pub fn is_volatile_active(&self) -> bool {
        self.memory.has_volatile_writes().unwrap_or(false)
    }

    /// Return the current operational status of the credential backends.
    ///
    /// The status does not perform network, keychain, or filesystem I/O. The
    /// primary availability flag is updated by credential operations.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::LockPoisoned`] if the in-memory credential
    /// state cannot be inspected.
    pub fn status(&self) -> Result<CredentialStatus> {
        Ok(CredentialStatus {
            primary_backend: self.primary.backend_name(),
            fallback_backend: self.fallback.as_ref().map(|backend| backend.backend_name()),
            primary_available: !self.is_primary_failed(),
            volatile_writes: self.memory.has_volatile_writes()?,
        })
    }

    /// Store a credential
    ///
    /// Successful writes use the primary backend, then the persistent fallback,
    /// then volatile memory. `is_volatile_active()` reports unpersisted writes.
    ///
    /// # Errors
    ///
    /// Returns an error if updating a selected backend or its cached state fails.
    pub fn store(&self, key: &str, value: &str) -> Result<()> {
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter_credentials(&self.service_name)?;
        self.store_with_profile(key, value, None)
    }

    /// Store a credential with optional profile context
    ///
    /// Successful writes use the primary backend, then the persistent fallback,
    /// then volatile memory. `is_volatile_active()` reports unpersisted writes.
    ///
    /// # Errors
    ///
    /// Returns an error if updating a selected backend or its cached state fails.
    pub fn store_with_profile(&self, key: &str, value: &str, profile: Option<&str>) -> Result<()> {
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter_credentials(&self.service_name)?;
        let full_key = self.make_key_with_profile(key, profile);
        #[cfg(feature = "backup")]
        {
            crate::backup::transaction::capture_credential(
                self.primary.clone(),
                &full_key,
                &self.service_name,
            )?;
            if let Some(fallback) = &self.fallback {
                crate::backup::transaction::capture_credential(
                    fallback.clone(),
                    &full_key,
                    &self.service_name,
                )?;
            }
            self.memory.capture(&full_key, &self.service_name)?;
        }

        #[cfg(feature = "backup")]
        if crate::backup::transaction::active(&self.service_name) {
            self.primary.store(&full_key, value)?;
            return self
                .memory
                .store(&full_key, MemoryEntry::Cached(value.to_owned()));
        }

        // Always attempt primary backend first
        match self.primary.store(&full_key, value) {
            Ok(()) => {
                log::debug!(
                    "Stored credential '{key}' in {}",
                    self.primary.backend_name()
                );
                if let Some(fallback) = &self.fallback {
                    fallback.remove(&full_key)?;
                }
                self.is_primary_failed.store(false, Ordering::Relaxed);
                self.memory
                    .store(&full_key, MemoryEntry::Cached(value.to_owned()))?;
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
                    self.memory
                        .store(&full_key, MemoryEntry::Cached(value.to_owned()))?;
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
        self.memory
            .store(&full_key, MemoryEntry::VolatileWrite(value.to_owned()))
    }

    /// Retrieve a credential
    ///
    /// # Errors
    ///
    /// Returns an error for backend read failures other than classified access
    /// outages, or if reading the in-memory cache fails.
    pub fn get(&self, key: &str) -> Result<Option<String>> {
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter_credentials(&self.service_name)?;
        self.get_with_profile(key, None)
    }

    /// Retrieve a credential with optional profile context.
    ///
    /// Cached persistent values are used during read failures, never after a
    /// confirmed absence. Writes accepted only in volatile memory remain readable
    /// until removed or superseded by a persistent value.
    ///
    /// # Errors
    ///
    /// Returns an error if a backend reports an internal read failure, or if reading
    /// the in-memory cache fails. An unavailable primary backend with no cached or
    /// fallback value is treated as an unknown credential and returns `Ok(None)`.
    pub fn get_with_profile(&self, key: &str, profile: Option<&str>) -> Result<Option<String>> {
        self.get_with_profile_status(key, profile)
            .map(|(value, _)| value)
    }

    pub(crate) fn get_with_profile_status(
        &self,
        key: &str,
        profile: Option<&str>,
    ) -> Result<(Option<String>, bool)> {
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter_credentials(&self.service_name)?;
        let full_key = self.make_key_with_profile(key, profile);
        #[cfg(feature = "backup")]
        self.memory.capture(&full_key, &self.service_name)?;

        let mut fallback_error = None;
        if let Some(fallback) = &self.fallback {
            match fallback.get(&full_key) {
                Ok(Some(value)) => {
                    self.memory
                        .store(&full_key, MemoryEntry::Cached(value.clone()))?;
                    return Ok((Some(value), false));
                }
                Ok(None) => {}
                Err(error) => fallback_error = Some(error),
            }
        }
        let primary_unavailable = match self.primary.get(&full_key) {
            Ok(Some(value)) => {
                self.is_primary_failed.store(false, Ordering::Relaxed);
                self.memory
                    .store(&full_key, MemoryEntry::Cached(value.clone()))?;
                return Ok((Some(value), false));
            }
            Ok(None) => {
                self.is_primary_failed.store(false, Ordering::Relaxed);
                false
            }
            Err(error) => {
                self.is_primary_failed.store(true, Ordering::Relaxed);
                if !is_credential_backend_unavailable(&error) {
                    return Err(error);
                }
                log::debug!(
                    "Credential read from primary backend '{}' is unavailable: {error}",
                    self.primary.backend_name()
                );
                true
            }
        };

        if let Some(error) = fallback_error.take() {
            if !is_credential_backend_unavailable(&error) {
                return Err(error);
            }
            fallback_error = Some(error);
        }

        let read_failed = primary_unavailable
            || fallback_error
                .as_ref()
                .is_some_and(is_credential_backend_unavailable);

        if let Some(value) = self.memory.read_fallback(&full_key, read_failed)? {
            return Ok((Some(value), read_failed));
        }

        if let Some(error) = fallback_error {
            return Err(error);
        }

        // An unavailable primary does not prove that the credential is absent.
        // With no fallback value, return an empty read while keeping
        // `is_primary_failed()` set so callers can distinguish the outage.
        Ok((None, read_failed))
    }

    /// Remove a credential
    ///
    /// # Errors
    ///
    /// Returns an error if the primary backend fails to remove the key or if the fallback backend fails to remove the key.
    pub fn remove(&self, key: &str) -> Result<()> {
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter_credentials(&self.service_name)?;
        self.remove_with_profile(key, None)
    }

    /// Remove a credential with optional profile context
    ///
    /// # Errors
    ///
    /// Returns an error if the primary backend fails to remove the key or if the fallback backend fails to remove the key.
    pub fn remove_with_profile(&self, key: &str, profile: Option<&str>) -> Result<()> {
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter_credentials(&self.service_name)?;
        let full_key = self.make_key_with_profile(key, profile);
        #[cfg(feature = "backup")]
        {
            crate::backup::transaction::capture_credential(
                self.primary.clone(),
                &full_key,
                &self.service_name,
            )?;
            if let Some(fallback) = &self.fallback {
                crate::backup::transaction::capture_credential(
                    fallback.clone(),
                    &full_key,
                    &self.service_name,
                )?;
            }
            self.memory.capture(&full_key, &self.service_name)?;
        }

        #[cfg(feature = "backup")]
        if crate::backup::transaction::active(&self.service_name) {
            self.primary.remove(&full_key)?;
            if let Some(fallback) = &self.fallback {
                fallback.remove(&full_key)?;
            }
            return self.memory.remove(&full_key);
        }

        // Attempt every backend, but never report a failed deletion as success.
        let mut failure = None;
        for backend in std::iter::once(&self.primary).chain(self.fallback.iter()) {
            if let Err(error) = backend.remove(&full_key) {
                failure.get_or_insert(error);
            }
        }
        self.memory.remove(&full_key)?;
        self.invalidate_tracked_secrets_cache()?;
        failure.map_or(Ok(()), Err)
    }

    /// Check if a credential exists
    ///
    /// Returns `false` when a backend cannot be checked. Use
    /// [`Self::try_exists`] when the caller needs to distinguish that case from
    /// confirmed absence.
    #[must_use]
    pub fn exists(&self, key: &str) -> bool {
        self.exists_with_profile(key, None)
    }

    /// Check if a credential exists with optional profile context
    ///
    /// Returns `false` when a backend cannot be checked. Use
    /// [`Self::try_exists_with_profile`] when the caller needs to distinguish
    /// that case from confirmed absence.
    #[must_use]
    pub fn exists_with_profile(&self, key: &str, profile: Option<&str>) -> bool {
        self.try_exists_with_profile(key, profile).unwrap_or(false)
    }

    /// Check whether a credential exists while preserving backend errors.
    pub fn try_exists(&self, key: &str) -> Result<bool> {
        self.try_exists_with_profile(key, None)
    }

    /// Check whether a credential exists in the selected profile while preserving errors.
    ///
    /// # Errors
    ///
    /// Returns an error if a backend reports an internal failure, all configured
    /// backends are unavailable, or an in-memory lock is poisoned.
    pub fn try_exists_with_profile(&self, key: &str, profile: Option<&str>) -> Result<bool> {
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter_credentials(&self.service_name)?;
        let full_key = self.make_key_with_profile(key, profile);
        let mut failure = None;
        for backend in std::iter::once(&self.primary).chain(self.fallback.iter()) {
            match backend.exists(&full_key) {
                Ok(true) => return Ok(true),
                Ok(false) => {}
                Err(error) => {
                    if !is_credential_backend_unavailable(&error) {
                        return Err(error);
                    }
                    failure.get_or_insert(error);
                }
            }
        }
        #[cfg(feature = "backup")]
        self.memory.capture(&full_key, &self.service_name)?;
        if self
            .memory
            .read_fallback(&full_key, failure.is_some())?
            .is_some()
        {
            return Ok(true);
        }
        failure.map_or(Ok(false), Err)
    }

    /// Clear all credentials for this service or the current profile.
    ///
    /// Tracking entries are removed only after all discovered secrets have been
    /// deleted. On failure they remain available for a later cleanup attempt.
    ///
    /// # Errors
    ///
    /// Returns an error if enumeration, deletion, or cache invalidation fails.
    pub fn clear(&self) -> Result<()> {
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter_credentials(&self.service_name)?;
        self.invalidate_tracked_secrets_cache()?;
        #[cfg(feature = "profiles")]
        let profile = self.profile_context.as_deref();
        #[cfg(not(feature = "profiles"))]
        let profile: Option<&str> = None;

        #[cfg(feature = "profiles")]
        if profile.is_none() {
            for name in self.get_tracked_profiles()? {
                self.with_profile_context(&name).clear()?;
            }
        }

        let marker = self.make_key_with_profile("__rcman_secrets__", profile);
        let prefix = self.make_key_with_profile("", profile);
        let mut keys: std::collections::HashSet<_> = self
            .get_tracked_secrets(profile)?
            .into_iter()
            .map(|key| self.make_key_with_profile(&key, profile))
            .collect();
        let mut failure = None;
        for backend in std::iter::once(&self.primary)
            .chain(self.fallback.iter())
            .map(AsRef::as_ref)
        {
            match backend.list_keys() {
                Ok(found) => keys.extend(found.into_iter().filter(|key| key.starts_with(&prefix))),
                Err(error) => {
                    failure.get_or_insert(error);
                }
            }
        }
        keys.extend(
            self.memory
                .list_keys()?
                .into_iter()
                .filter(|key| key.starts_with(&prefix)),
        );
        keys.insert(marker);
        #[cfg(feature = "profiles")]
        if profile.is_none() {
            keys.insert(self.make_key_with_profile("__rcman_profiles__", None));
        }

        let (markers, secrets): (Vec<_>, Vec<_>) = keys.into_iter().partition(|key| {
            key.ends_with(":__rcman_secrets__") || key.ends_with(":__rcman_profiles__")
        });
        for full_key in secrets {
            if let Err(error) = self.remove_with_profile(&full_key[prefix.len()..], profile) {
                failure.get_or_insert(error);
            }
        }
        self.invalidate_tracked_secrets_cache()?;
        if let Some(error) = failure {
            return Err(error);
        }
        for full_key in markers {
            self.remove_with_profile(&full_key[prefix.len()..], profile)?;
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
                "memory"
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
        self.get_tracked_secrets_with_status(profile)
            .map(|(secrets, _)| secrets)
    }

    fn get_tracked_secrets_with_status(
        &self,
        profile: Option<&str>,
    ) -> Result<(std::collections::HashSet<String>, bool)> {
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter_credentials(&self.service_name)?;
        #[cfg(feature = "profiles")]
        let profile = profile.or(self.profile_context.as_deref());
        let profile_key = profile.map(ToString::to_string);
        {
            let cache_guard = self
                .tracked_secrets_cache
                .read()
                .map_err(|_| crate::error::Error::LockPoisoned)?;
            if let Some(cache) = cache_guard.get(&profile_key) {
                return Ok((cache.clone(), false));
            }
        }

        // Perform I/O outside of the write lock to prevent blocking concurrent readers/writers
        let (tracked_value, backend_unavailable) =
            self.get_with_profile_status("__rcman_secrets__", profile)?;
        let secrets = match tracked_value {
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

        if !backend_unavailable {
            let mut cache_guard = self
                .tracked_secrets_cache
                .write()
                .map_err(|_| crate::error::Error::LockPoisoned)?;
            cache_guard.insert(profile_key, secrets.clone());
        }
        Ok((secrets, backend_unavailable))
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
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter_credentials(&self.service_name)?;
        #[cfg(feature = "profiles")]
        let profile = profile.or(self.profile_context.as_deref());
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
            self.add_tracked_profile(profile_name)?;
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
        self.get_tracked_profiles_with_status()
            .map(|(profiles, _)| profiles)
    }

    #[cfg(feature = "profiles")]
    fn get_tracked_profiles_with_status(
        &self,
    ) -> Result<(std::collections::HashSet<String>, bool)> {
        if self.profile_context.is_some() {
            let mut root = self.clone();
            root.profile_context = None;
            return root.get_tracked_profiles_with_status();
        }
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter_credentials(&self.service_name)?;
        {
            let cache_guard = self
                .tracked_profiles_cache
                .read()
                .map_err(|_| crate::error::Error::LockPoisoned)?;
            if let Some(ref cache) = *cache_guard {
                return Ok((cache.clone(), false));
            }
        }

        // Perform I/O outside of the write lock
        let (tracked_value, backend_unavailable) =
            self.get_with_profile_status("__rcman_profiles__", None)?;
        let profiles: std::collections::HashSet<String> = match tracked_value {
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

        if !backend_unavailable {
            let mut cache_guard = self
                .tracked_profiles_cache
                .write()
                .map_err(|_| crate::error::Error::LockPoisoned)?;
            *cache_guard = Some(profiles.clone());
        }
        Ok((profiles, backend_unavailable))
    }

    /// Register a profile name in the tracked profiles list and update the in-memory cache.
    ///
    /// # Errors
    ///
    /// Returns an error if storing the profile list in credentials fails.
    #[cfg(feature = "profiles")]
    pub fn add_tracked_profile(&self, profile: &str) -> Result<()> {
        if self.profile_context.is_some() {
            let mut root = self.clone();
            root.profile_context = None;
            return root.add_tracked_profile(profile);
        }
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter_credentials(&self.service_name)?;
        let (mut profiles, backend_unavailable) = self.get_tracked_profiles_with_status()?;
        if backend_unavailable {
            return Err(crate::error::Error::CredentialBackendUnavailable(
                "Cannot update tracked profiles while the credential backend is unavailable".into(),
            ));
        }
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
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter_credentials(&self.service_name)?;
        let (mut tracked, backend_unavailable) = self.get_tracked_secrets_with_status(profile)?;
        if backend_unavailable {
            return Err(crate::error::Error::CredentialBackendUnavailable(
                "Cannot update tracked secrets while the credential backend is unavailable".into(),
            ));
        }
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
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter_credentials(&self.service_name)?;
        let (mut tracked, backend_unavailable) = self.get_tracked_secrets_with_status(profile)?;
        if backend_unavailable {
            return Err(crate::error::Error::CredentialBackendUnavailable(
                "Cannot update tracked secrets while the credential backend is unavailable".into(),
            ));
        }
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
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter_credentials(&self.service_name)?;
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
        #[cfg(feature = "backup")]
        let _operation_guard = crate::backup::transaction::enter_credentials(&self.service_name)?;
        #[cfg(feature = "profiles")]
        let profile = profile.or(self.profile_context.as_deref());
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

    fn manager_with_backends(
        primary: Arc<dyn CredentialBackend>,
        fallback: Option<Arc<dyn CredentialBackend>>,
    ) -> CredentialManager {
        CredentialManager {
            primary,
            fallback,
            is_primary_failed: Arc::new(AtomicBool::new(false)),
            commit_lock: Arc::new(std::sync::Mutex::new(())),
            service_name: "test-app".to_string(),
            #[cfg(feature = "profiles")]
            profile_context: None,
            memory: Arc::new(CredentialMemory::default()),
            tracked_secrets_cache: Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
            #[cfg(feature = "profiles")]
            tracked_profiles_cache: Arc::new(std::sync::RwLock::new(None)),
        }
    }

    struct UnavailableBackend;

    impl CredentialBackend for UnavailableBackend {
        fn store(&self, _key: &str, _value: &str) -> Result<()> {
            Err(crate::Error::CredentialBackendUnavailable(
                "test backend unavailable".into(),
            ))
        }

        fn get(&self, _key: &str) -> Result<Option<String>> {
            Err(crate::Error::CredentialBackendUnavailable(
                "test backend unavailable".into(),
            ))
        }

        fn remove(&self, _key: &str) -> Result<()> {
            Err(crate::Error::CredentialBackendUnavailable(
                "test backend unavailable".into(),
            ))
        }

        fn list_keys(&self) -> Result<Vec<String>> {
            Ok(Vec::new())
        }

        fn backend_name(&self) -> &'static str {
            "unavailable"
        }
    }

    struct InternalErrorBackend;

    impl CredentialBackend for InternalErrorBackend {
        fn store(&self, _key: &str, _value: &str) -> Result<()> {
            Ok(())
        }

        fn get(&self, _key: &str) -> Result<Option<String>> {
            Err(crate::Error::LockPoisoned)
        }

        fn remove(&self, _key: &str) -> Result<()> {
            Ok(())
        }

        fn list_keys(&self) -> Result<Vec<String>> {
            Ok(Vec::new())
        }

        fn backend_name(&self) -> &'static str {
            "internal_error"
        }
    }

    #[test]
    fn unavailable_primary_without_memory_returns_none() {
        let manager = manager_with_backends(Arc::new(UnavailableBackend), None);

        assert_eq!(manager.get_with_profile("token", None).unwrap(), None);
        assert!(matches!(
            manager.try_exists("token"),
            Err(crate::Error::CredentialBackendUnavailable(_))
        ));
        assert!(!manager.exists("token"));
        assert!(manager.get_tracked_secrets(None).unwrap().is_empty());
        assert!(manager.tracked_secrets_cache.read().unwrap().is_empty());
        assert!(manager.add_tracked_secret("token", None).is_err());
        #[cfg(feature = "profiles")]
        {
            assert!(manager.get_tracked_profiles().unwrap().is_empty());
            assert!(manager.tracked_profiles_cache.read().unwrap().is_none());
            assert!(manager.add_tracked_profile("work").is_err());
        }
        assert!(manager.is_primary_failed());
        assert!(!manager.is_volatile_active());
    }

    #[test]
    fn unavailable_primary_returns_volatile_write() {
        let manager = manager_with_backends(Arc::new(UnavailableBackend), None);
        manager
            .memory
            .store(
                "test-app:token",
                MemoryEntry::VolatileWrite("volatile".into()),
            )
            .unwrap();

        assert_eq!(
            manager.get_with_profile("token", None).unwrap().as_deref(),
            Some("volatile")
        );
        assert!(manager.is_primary_failed());
        assert!(manager.is_volatile_active());
    }

    #[test]
    fn unavailable_primary_returns_cached_persistent_value() {
        let manager = manager_with_backends(Arc::new(UnavailableBackend), None);
        manager
            .memory
            .store("test-app:token", MemoryEntry::Cached("cached".into()))
            .unwrap();

        assert_eq!(
            manager.get_with_profile("token", None).unwrap().as_deref(),
            Some("cached")
        );
        assert!(manager.is_primary_failed());
        assert!(!manager.is_volatile_active());
    }

    #[cfg(feature = "encrypted-file")]
    #[test]
    fn unavailable_primary_reads_encrypted_fallback_value() {
        let directory = tempfile::tempdir().unwrap();
        let fallback = crate::credentials::EncryptedFileBackend::with_password(
            directory.path().join("credentials.enc.json"),
            "test-password",
        )
        .unwrap();
        fallback.store("test-app:token", "encrypted").unwrap();
        let manager = manager_with_backends(Arc::new(UnavailableBackend), Some(Arc::new(fallback)));

        assert_eq!(
            manager.get_with_profile("token", None).unwrap().as_deref(),
            Some("encrypted")
        );
        assert!(!manager.is_volatile_active());
    }

    #[test]
    fn confirmed_primary_miss_discards_stale_cached_value() {
        let primary = Arc::new(MemoryBackend::new());
        let manager = manager_with_backends(primary, None);
        manager
            .memory
            .store("test-app:token", MemoryEntry::Cached("stale".into()))
            .unwrap();

        assert_eq!(manager.get_with_profile("token", None).unwrap(), None);
        assert_eq!(
            manager
                .memory
                .read_fallback("test-app:token", true)
                .unwrap(),
            None
        );
        assert!(!manager.is_primary_failed());
    }

    #[test]
    fn internal_primary_and_fallback_errors_are_not_hidden_by_memory() {
        let primary = manager_with_backends(Arc::new(InternalErrorBackend), None);
        assert!(matches!(
            primary.get_with_profile("token", None),
            Err(crate::Error::LockPoisoned)
        ));
        primary
            .memory
            .store(
                "test-app:token",
                MemoryEntry::VolatileWrite("volatile".into()),
            )
            .unwrap();
        assert!(matches!(
            primary.try_exists_with_profile("token", None),
            Err(crate::Error::LockPoisoned)
        ));

        let manager =
            manager_with_backends(Arc::new(UnavailableBackend), Some(Arc::new(FailingBackend)));
        manager
            .memory
            .store("test-app:token", MemoryEntry::Cached("stale".into()))
            .unwrap();
        assert!(matches!(
            manager.get_with_profile("token", None),
            Err(crate::Error::Credential(_))
        ));
    }

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
            primary: std::sync::Arc::new(UnavailableBackend),
            fallback: Some(std::sync::Arc::new(MemoryBackend::new())),
            is_primary_failed: Arc::new(AtomicBool::new(false)),
            commit_lock: Arc::new(std::sync::Mutex::new(())),
            service_name: "test-app".to_string(),
            #[cfg(feature = "profiles")]
            profile_context: None,
            memory: Arc::new(CredentialMemory::default()),
            tracked_secrets_cache: Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
            #[cfg(feature = "profiles")]
            tracked_profiles_cache: Arc::new(std::sync::RwLock::new(None)),
        };

        manager.store("api_key", "fallback-value").unwrap();
        assert_eq!(
            manager.get("api_key").unwrap().as_deref(),
            Some("fallback-value")
        );
        assert!(manager.remove("api_key").is_err());
        assert_eq!(manager.get("api_key").unwrap(), None);
    }

    #[test]
    fn test_sticky_fallback_is_remembered() {
        let manager = CredentialManager {
            primary: std::sync::Arc::new(FailingBackend),
            fallback: Some(std::sync::Arc::new(MemoryBackend::new())),
            is_primary_failed: Arc::new(AtomicBool::new(false)),
            commit_lock: Arc::new(std::sync::Mutex::new(())),
            service_name: "test-app".to_string(),
            #[cfg(feature = "profiles")]
            profile_context: None,
            memory: Arc::new(CredentialMemory::default()),
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
            primary: Arc::new(UnavailableBackend),
            fallback: Some(Arc::new(UnavailableBackend)),
            is_primary_failed: Arc::new(AtomicBool::new(false)),
            commit_lock: Arc::new(std::sync::Mutex::new(())),
            service_name: "test-app".to_string(),
            #[cfg(feature = "profiles")]
            profile_context: None,
            memory: Arc::new(CredentialMemory::default()),
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

        // Persistent deletion cannot be confirmed, even though volatile data clears.
        assert!(manager.remove("api_key").is_err());
        // An unavailable persistent backend cannot confirm that the key is absent.
        assert!(matches!(
            manager.get("api_key"),
            Err(crate::Error::CredentialBackendUnavailable(_))
        ));
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
            commit_lock: Arc::new(std::sync::Mutex::new(())),
            service_name: "test-app".to_string(),
            #[cfg(feature = "profiles")]
            profile_context: None,
            memory: Arc::new(CredentialMemory::default()),
            tracked_secrets_cache: Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
            #[cfg(feature = "profiles")]
            tracked_profiles_cache: Arc::new(std::sync::RwLock::new(None)),
        };

        // Primary store fails, stored in volatile memory
        manager.store("api_key", "top-secret").unwrap();

        assert!(manager.exists("api_key"));
        assert!(manager.is_volatile_active());

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
    fn test_read_through_populates_cached_memory() {
        let primary = Arc::new(MemoryBackend::new());
        primary.store("test-app:cached_key", "secret-val").unwrap();

        let manager = CredentialManager {
            primary,
            fallback: None,
            is_primary_failed: Arc::new(AtomicBool::new(false)),
            commit_lock: Arc::new(std::sync::Mutex::new(())),
            service_name: "test-app".to_string(),
            #[cfg(feature = "profiles")]
            profile_context: None,
            memory: Arc::new(CredentialMemory::default()),
            tracked_secrets_cache: Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
            #[cfg(feature = "profiles")]
            tracked_profiles_cache: Arc::new(std::sync::RwLock::new(None)),
        };

        // Before read, memory is empty
        assert_eq!(
            manager
                .memory
                .read_fallback("test-app:cached_key", true)
                .unwrap(),
            None
        );

        // Read from primary through manager
        let val = manager.get("cached_key").unwrap();
        assert_eq!(val, Some("secret-val".to_string()));

        // After read, memory holds a cached persistent value
        assert_eq!(
            manager
                .memory
                .read_fallback("test-app:cached_key", true)
                .unwrap(),
            Some("secret-val".to_string())
        );
    }
}

#[cfg(all(test, any(feature = "keychain", feature = "encrypted-file")))]
mod consistency_tests {
    use super::*;
    use std::collections::HashSet;

    struct InterruptedBackend {
        memory: MemoryBackend,
        read_fails: AtomicBool,
        delete_fails: AtomicBool,
    }

    impl InterruptedBackend {
        fn new() -> Self {
            Self {
                memory: MemoryBackend::new(),
                read_fails: AtomicBool::new(false),
                delete_fails: AtomicBool::new(false),
            }
        }
    }

    impl CredentialBackend for InterruptedBackend {
        fn store(&self, key: &str, value: &str) -> Result<()> {
            self.memory.store(key, value)
        }
        fn get(&self, key: &str) -> Result<Option<String>> {
            if self.read_fails.load(Ordering::Relaxed) {
                return Err(crate::Error::CredentialBackendUnavailable(
                    "read unavailable".into(),
                ));
            }
            self.memory.get(key)
        }
        fn remove(&self, key: &str) -> Result<()> {
            if self.delete_fails.load(Ordering::Relaxed) && key.ends_with(":secret") {
                return Err(crate::Error::Credential("delete unavailable".into()));
            }
            self.memory.remove(key)
        }
        fn list_keys(&self) -> Result<Vec<String>> {
            self.memory.list_keys()
        }
        fn backend_name(&self) -> &'static str {
            "interrupted"
        }
    }

    #[test]
    fn persistent_deletion_invalidates_cached_values_and_exists() {
        let primary = Arc::new(MemoryBackend::new());
        let manager = CredentialManager::with_backend("deletion", primary.clone());
        manager.store("secret", "value").unwrap();
        assert_eq!(manager.get("secret").unwrap().as_deref(), Some("value"));
        assert!(!manager.is_volatile_active());
        primary.remove("deletion:secret").unwrap();
        assert!(!manager.exists("secret"));
        assert_eq!(manager.get("secret").unwrap(), None);
        assert_eq!(
            manager
                .memory
                .read_fallback("deletion:secret", true)
                .unwrap(),
            None
        );
    }

    #[test]
    fn cached_values_survive_read_failure_with_an_empty_persistent_fallback() {
        let primary = Arc::new(InterruptedBackend::new());
        let mut manager = CredentialManager::with_backend("outage", primary.clone());
        manager.fallback = Some(Arc::new(MemoryBackend::new()));
        manager.store("secret", "value").unwrap();
        primary.read_fails.store(true, Ordering::Relaxed);
        assert!(manager.exists("secret"));
        assert_eq!(manager.get("secret").unwrap().as_deref(), Some("value"));
        primary.read_fails.store(false, Ordering::Relaxed);
        primary.remove("outage:secret").unwrap();
        assert_eq!(manager.get("secret").unwrap(), None);
    }

    #[test]
    fn failed_delete_reports_error_and_still_clears_other_backends() {
        let primary = Arc::new(InterruptedBackend::new());
        let fallback = Arc::new(MemoryBackend::new());
        let mut manager = CredentialManager::with_backend("delete", primary.clone());
        manager.fallback = Some(fallback.clone());
        manager.store("secret", "value").unwrap();
        fallback.store("delete:secret", "stale").unwrap();
        primary.delete_fails.store(true, Ordering::Relaxed);
        assert!(manager.remove("secret").is_err());
        assert!(primary.get("delete:secret").unwrap().is_some());
        assert_eq!(fallback.get("delete:secret").unwrap(), None);
        assert_eq!(
            manager.memory.read_fallback("delete:secret", true).unwrap(),
            None
        );
    }

    #[test]
    fn failed_clear_preserves_tracking_for_retry() {
        let primary = Arc::new(InterruptedBackend::new());
        let manager = CredentialManager::with_backend("clear", primary.clone());
        manager.store("secret", "value").unwrap();
        manager
            .save_tracked_secrets(&HashSet::from(["secret".into()]), None)
            .unwrap();
        primary.delete_fails.store(true, Ordering::Relaxed);
        assert!(manager.clear().is_err());
        assert!(primary.get("clear:secret").unwrap().is_some());
        assert!(primary.get("clear:__rcman_secrets__").unwrap().is_some());
        primary.delete_fails.store(false, Ordering::Relaxed);
        manager.clear().unwrap();
        assert!(primary.list_keys().unwrap().is_empty());
    }

    #[cfg(feature = "profiles")]
    #[test]
    fn tracking_caches_and_global_registry_respect_scoped_managers() {
        let manager = CredentialManager::memory_only("scopes");
        let root_keys = HashSet::from(["root-token".into()]);
        let work_keys = HashSet::from(["work-token".into()]);
        let personal_keys = HashSet::from(["personal-token".into()]);
        manager.save_tracked_secrets(&root_keys, None).unwrap();
        let work = manager.with_profile_context("work");
        work.save_tracked_secrets(&work_keys, None).unwrap();
        work.save_tracked_secrets(&personal_keys, Some("personal"))
            .unwrap();
        assert_eq!(manager.get_tracked_secrets(None).unwrap(), root_keys);
        assert_eq!(work.get_tracked_secrets(None).unwrap(), work_keys);
        assert_eq!(
            manager.get_tracked_secrets(Some("work")).unwrap(),
            work_keys
        );
        assert_eq!(
            work.get_tracked_secrets(Some("personal")).unwrap(),
            personal_keys
        );
        assert_eq!(
            manager.get_tracked_profiles().unwrap(),
            HashSet::from(["work".into(), "personal".into()])
        );
        work.clear_tracked_secrets_cache(None).unwrap();
        assert!(work.get_tracked_secrets(None).unwrap().is_empty());
        assert_eq!(manager.get_tracked_secrets(None).unwrap(), root_keys);
        work.invalidate_tracked_secrets_cache().unwrap();
        assert_eq!(work.get_tracked_secrets(None).unwrap(), work_keys);
    }
}
