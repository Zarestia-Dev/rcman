//! OS Keychain backend.
//!
//! ## Architecture
//!
//! **macOS**: uses `security-framework` v2.x directly. This crate only
//! references Security framework symbols available since macOS 10.7 (Lion)
//! — it does NOT reference `_kSecUseDataProtectionKeychain` (added in
//! macOS 10.15 Catalina), so the binary launches cleanly on macOS 10.14
//! Mojave and earlier.
//!
//! **Linux/Windows**: uses `keyring` v4.x. The macOS 10.14 dyld issue is
//! macOS-specific (caused by `security-framework` v3.x); `keyring` v4
//! works fine on Linux and Windows.
//!
//! ## Why not use `keyring` on macOS too?
//!
//! `keyring` v4 on macOS pulls in `apple-native-keyring-store` v1, which
//! requires `security-framework` v3.x — and that crate references
//! `_kSecUseDataProtectionKeychain`. On macOS 10.14 the dynamic linker
//! aborts the process at load time because that symbol doesn't exist.
//! By using `security-framework` v2.x directly, we bypass the broken
//! transitive dependency entirely.

use super::CredentialBackend;
use crate::error::{Error, Result};
use log::{debug, warn};
use std::collections::HashSet;
use std::sync::RwLock;

/// OS Keychain backend for secure credential storage
pub struct KeychainBackend {
    service_name: String,
    /// Cache of known keys (keychain doesn't support listing).
    known_keys: RwLock<HashSet<String>>,
    /// Global lock to serialize keychain access on Linux to prevent zbus panics
    #[cfg(target_os = "linux")]
    lock: std::sync::Mutex<()>,
}

impl KeychainBackend {
    /// Create a new keychain backend
    #[must_use]
    pub fn new(service_name: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
            known_keys: RwLock::new(HashSet::new()),
            #[cfg(target_os = "linux")]
            lock: std::sync::Mutex::new(()),
        }
    }

    fn track_key(&self, key: &str) {
        if let Ok(mut keys) = self.known_keys.write() {
            keys.insert(key.to_string());
        }
    }

    fn untrack_key(&self, key: &str) {
        if let Ok(mut keys) = self.known_keys.write() {
            keys.remove(key);
        }
    }

    // ── macOS: security-framework v2.x ──────────────────────────────────

    #[cfg(target_os = "macos")]
    fn store_impl(&self, key: &str, value: &str) -> Result<()> {
        use security_framework::passwords::set_generic_password;
        set_generic_password(&self.service_name, key, value.as_bytes()).map_err(|e| {
            Error::Credential(format!("Failed to store credential {key} in keychain: {e}"))
        })?;
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn get_impl(&self, key: &str) -> Result<Option<String>> {
        use security_framework::passwords::get_generic_password;

        match get_generic_password(&self.service_name, key) {
            Ok(bytes) => {
                let password = String::from_utf8(bytes).map_err(|e| {
                    Error::Credential(format!("Keychain password is not valid UTF-8: {e}"))
                })?;
                Ok(Some(password))
            }
            // -25300 is Apple's errSecItemNotFound error code
            Err(e) if e.code() == -25300 => Ok(None),
            Err(e) => Err(Error::Credential(format!(
                "Failed to retrieve credential {key}: {e}"
            ))),
        }
    }

    #[cfg(target_os = "macos")]
    fn remove_impl(&self, key: &str) -> Result<()> {
        use security_framework::passwords::delete_generic_password;

        match delete_generic_password(&self.service_name, key) {
            Ok(()) => Ok(()),
            // -25300 is Apple's errSecItemNotFound error code
            Err(e) if e.code() == -25300 => Ok(()),
            Err(e) => Err(Error::Credential(format!(
                "Failed to remove credential {key}: {e}"
            ))),
        }
    }

    // ── Linux + Windows: keyring v4.x ───────────────────────────────────

    #[cfg(not(target_os = "macos"))]
    fn store_impl(&self, key: &str, value: &str) -> Result<()> {
        use keyring::Entry;

        #[cfg(target_os = "linux")]
        let _guard = self.lock.lock().map_err(|_| Error::LockPoisoned)?;

        let entry = Entry::new(&self.service_name, key).map_err(|e| {
            Error::Credential(format!("Failed to create keychain entry for {key}: {e}"))
        })?;
        entry.set_password(value).map_err(|e| {
            Error::Credential(format!("Failed to store credential {key} in keychain: {e}"))
        })?;
        Ok(())
    }

    #[cfg(not(target_os = "macos"))]
    fn get_impl(&self, key: &str) -> Result<Option<String>> {
        use keyring::{Entry, Error as KeyringError};

        #[cfg(target_os = "linux")]
        let _guard = self.lock.lock().map_err(|_| Error::LockPoisoned)?;

        let entry = Entry::new(&self.service_name, key).map_err(|e| {
            Error::Credential(format!("Failed to create keychain entry for {key}: {e}"))
        })?;
        match entry.get_password() {
            Ok(password) => Ok(Some(password)),
            Err(KeyringError::NoEntry) => Ok(None),
            Err(e) => Err(Error::Credential(format!(
                "Failed to retrieve credential {key}: {e}"
            ))),
        }
    }

    #[cfg(not(target_os = "macos"))]
    fn remove_impl(&self, key: &str) -> Result<()> {
        use keyring::{Entry, Error as KeyringError};

        #[cfg(target_os = "linux")]
        let _guard = self.lock.lock().map_err(|_| Error::LockPoisoned)?;

        let entry = Entry::new(&self.service_name, key).map_err(|e| {
            Error::Credential(format!("Failed to create keychain entry for {key}: {e}"))
        })?;
        match entry.delete_credential() {
            Ok(()) | Err(KeyringError::NoEntry) => Ok(()),
            Err(e) => Err(Error::Credential(format!(
                "Failed to remove credential {key}: {e}"
            ))),
        }
    }
}

impl CredentialBackend for KeychainBackend {
    fn store(&self, key: &str, value: &str) -> Result<()> {
        self.store_impl(key, value)?;
        self.track_key(key);
        debug!("Credential stored in keychain: {key}");
        Ok(())
    }

    fn get(&self, key: &str) -> Result<Option<String>> {
        match self.get_impl(key) {
            Ok(Some(password)) => {
                self.track_key(key);
                debug!("Credential retrieved from keychain: {key}");
                Ok(Some(password))
            }
            Ok(None) => Ok(None),
            Err(e) => {
                warn!("Failed to retrieve credential {key} from keychain: {e}");
                Err(e)
            }
        }
    }

    fn remove(&self, key: &str) -> Result<()> {
        match self.remove_impl(key) {
            Ok(()) => {
                self.untrack_key(key);
                debug!("Credential removed from keychain: {key}");
                Ok(())
            }
            // ItemNotFound / NoEntry is already handled as Ok(()) inside remove_impl
            Err(e) => Err(e),
        }
    }

    /// List all stored credential keys tracked in the current session.
    ///
    /// # Warning
    ///
    /// Since the OS keychain does not support listing/enumerating keys,
    /// this backend only returns keys that have been tracked (created or accessed)
    /// during the lifetime of this `KeychainBackend` instance.
    fn list_keys(&self) -> Result<Vec<String>> {
        self.known_keys
            .read()
            .map(|keys| keys.iter().cloned().collect())
            .map_err(|_| Error::LockPoisoned)
    }

    fn backend_name(&self) -> &'static str {
        "keychain"
    }
}
