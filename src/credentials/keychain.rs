//! OS Keychain backend using `keyring` (v4+)
//!
//! Supports native secure credential storage across desktop and mobile platforms:
//! - **Linux**: Secret Service (D-Bus / Seahorse / KWallet)
//! - **macOS / iOS**: Native Apple Keychain & Protected Data store
//! - **Windows**: Windows Credential Manager
//! - **Android**: Android KeyStore & SharedPreferences (requires `ndk_context` initialization)

use super::CredentialBackend;
use crate::error::{Error, Result};
use keyring_core::{Entry, Error as KeyringError};
use log::{debug, warn};
use std::collections::HashSet;
#[cfg(not(target_os = "android"))]
use std::sync::OnceLock;
use std::sync::RwLock;

/// Ensures the platform-native keyring store is initialized.
///
/// On Android, initialization waits until `ndk_context::android_context()` is initialized by the host application (e.g., Tauri v2) to prevent panic or lock poisoning.
/// On desktop and iOS, initialization is performed lazily once via `OnceLock`.
fn ensure_native_store_initialized() {
    #[cfg(target_os = "android")]
    {
        static IS_INIT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        if !IS_INIT.load(std::sync::atomic::Ordering::Relaxed) {
            let context_ready = std::panic::catch_unwind(|| {
                let _ = ndk_context::android_context();
            })
            .is_ok();

            if context_ready {
                let config: std::collections::HashMap<&str, &str> =
                    std::collections::HashMap::new();
                match android_native_keyring_store::Store::new_with_configuration(&config) {
                    Ok(store) => {
                        keyring_core::set_default_store(store);
                        IS_INIT.store(true, std::sync::atomic::Ordering::Relaxed);
                        log::info!("Android KeyStore keyring store initialized successfully");
                    }
                    Err(e) => warn!("Failed to initialize Android KeyStore keyring store: {e}"),
                }
            } else {
                log::debug!("Android KeyStore initialization waiting for ndk_context");
            }
        }
    }

    #[cfg(not(target_os = "android"))]
    {
        static NATIVE_STORE_INIT: OnceLock<()> = OnceLock::new();
        NATIVE_STORE_INIT.get_or_init(|| {
            // Force Secret Service (Seahorse/KWallet) on Linux
            #[cfg(target_os = "linux")]
            {
                let config: std::collections::HashMap<&str, &str> =
                    std::collections::HashMap::new();
                match dbus_secret_service_keyring_store::Store::new_with_configuration(&config) {
                    Ok(store) => keyring_core::set_default_store(store),
                    Err(e) => warn!("Failed to initialize Linux Secret Service keyring store: {e}"),
                }
            }

            // Native Apple Keychain on macOS / iOS
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            {
                let config: std::collections::HashMap<&str, &str> =
                    std::collections::HashMap::new();
                #[cfg(target_os = "ios")]
                let store_res =
                    apple_native_keyring_store::protected::Store::new_with_configuration(&config);
                #[cfg(target_os = "macos")]
                let store_res =
                    apple_native_keyring_store::keychain::Store::new_with_configuration(&config);

                match store_res {
                    Ok(store) => keyring_core::set_default_store(store),
                    Err(e) => warn!("Failed to initialize Apple Keychain store: {e}"),
                }
            }

            // Native Windows Credential Manager on Windows
            #[cfg(target_os = "windows")]
            {
                let config: std::collections::HashMap<&str, &str> =
                    std::collections::HashMap::new();
                match windows_native_keyring_store::Store::new_with_configuration(&config) {
                    Ok(store) => keyring_core::set_default_store(store),
                    Err(e) => warn!("Failed to initialize Windows native store: {e}"),
                }
            }
        });
    }
}

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
    pub fn new(service_name: impl Into<String>) -> Self {
        ensure_native_store_initialized();

        Self {
            service_name: service_name.into(),
            known_keys: RwLock::new(HashSet::new()),
            #[cfg(target_os = "linux")]
            lock: std::sync::Mutex::new(()),
        }
    }

    fn get_entry(&self, key: &str) -> Result<Entry> {
        ensure_native_store_initialized();
        Entry::new(&self.service_name, key).map_err(|e| {
            Error::Credential(format!("Failed to create keychain entry for {key}: {e}"))
        })
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
}

impl CredentialBackend for KeychainBackend {
    fn store(&self, key: &str, value: &str) -> Result<()> {
        #[cfg(target_os = "linux")]
        let _guard = self.lock.lock().map_err(|_| Error::LockPoisoned)?;

        self.get_entry(key)?.set_password(value).map_err(|e| {
            Error::Credential(format!("Failed to store credential {key} in keychain: {e}"))
        })?;

        self.track_key(key);
        debug!("Credential stored in keychain: {key}");
        Ok(())
    }

    fn get(&self, key: &str) -> Result<Option<String>> {
        #[cfg(target_os = "linux")]
        let _guard = self.lock.lock().map_err(|_| Error::LockPoisoned)?;

        match self.get_entry(key)?.get_password() {
            Ok(password) => {
                self.track_key(key);
                debug!("Credential retrieved from keychain: {key}");
                Ok(Some(password))
            }
            Err(KeyringError::NoEntry) => Ok(None),
            Err(e) => {
                warn!("Failed to retrieve credential {key} from keychain: {e}");
                Err(Error::Credential(format!(
                    "Failed to retrieve credential {key}: {e}"
                )))
            }
        }
    }

    fn remove(&self, key: &str) -> Result<()> {
        #[cfg(target_os = "linux")]
        let _guard = self.lock.lock().map_err(|_| Error::LockPoisoned)?;

        match self.get_entry(key)?.delete_credential() {
            Ok(()) => {
                self.untrack_key(key);
                debug!("Credential removed from keychain: {key}");
                Ok(())
            }
            Err(KeyringError::NoEntry) => {
                self.untrack_key(key);
                Ok(())
            }
            Err(e) => Err(Error::Credential(format!(
                "Failed to remove credential {key}: {e}"
            ))),
        }
    }

    /// List all stored credential keys tracked in the current session.
    ///
    /// # Warning
    ///
    /// Since the OS keychain does not support listing/enumerating keys,
    /// this backend only returns keys that have been tracked (created or accessed)
    /// during the lifetime of this `KeychainBackend` instance.
    /// Consequently, keys created in previous runs of the application will not
    /// be returned by this method until they are accessed again.
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
