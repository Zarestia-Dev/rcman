//! OS Keychain backend using keyring (v4+)

use super::CredentialBackend;
use crate::error::{Error, Result};
use keyring_core::{Entry, Error as KeyringError};
use log::{debug, warn};
use std::collections::HashSet;
use std::sync::{OnceLock, RwLock};

static NATIVE_STORE_INIT: OnceLock<()> = OnceLock::new();

/// OS Keychain backend for secure credential storage
pub struct KeychainBackend {
    service_name: String,
    /// Cache of known keys (keychain doesn't support listing).
    known_keys: RwLock<HashSet<String>>,
}

impl KeychainBackend {
    /// Create a new keychain backend
    pub fn new(service_name: impl Into<String>) -> Self {
        NATIVE_STORE_INIT.get_or_init(|| {
            // v4 requires a config HashMap for initialization, even if empty
            let config: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();

            // Force Secret Service (Seahorse/KWallet) on Linux
            #[cfg(target_os = "linux")]
            {
                if let Err(e) = keyring::use_dbus_secret_service_store(&config) {
                    warn!("Failed to initialize Linux Secret Service keyring store: {e}");
                }
            }

            // Native Apple Keychain on macOS
            #[cfg(target_os = "macos")]
            {
                if let Err(e) = keyring::use_apple_keychain_store(&config) {
                    warn!("Failed to initialize macOS Keychain store: {e}");
                }
            }

            // Native Windows Credential Manager on Windows
            #[cfg(target_os = "windows")]
            {
                if let Err(e) = keyring::use_windows_native_store(&config) {
                    warn!("Failed to initialize Windows native store: {e}");
                }
            }
        });

        Self {
            service_name: service_name.into(),
            known_keys: RwLock::new(HashSet::new()),
        }
    }

    fn get_entry(&self, key: &str) -> Result<Entry> {
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
        self.get_entry(key)?.set_password(value).map_err(|e| {
            Error::Credential(format!("Failed to store credential {key} in keychain: {e}"))
        })?;

        self.track_key(key);
        debug!("Credential stored in keychain: {key}");
        Ok(())
    }

    fn get(&self, key: &str) -> Result<Option<String>> {
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
