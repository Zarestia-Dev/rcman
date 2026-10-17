//! State management and lifecycle control for the configuration vault

use crate::error::{Error, Result};
use crate::vault::crypto::{
    constant_time_eq, decrypt_authenticated, derive_key, encrypt_authenticated, generate_nonce,
    generate_salt, zeroize_bytes,
};
use crate::vault::envelope::{Argon2Params, VaultEnvelope};
use base64::Engine as _;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Secure wrapper around a 32-byte cryptographic key that zeroizes memory on drop
#[derive(Debug)]
pub(crate) struct VaultKey(pub(crate) [u8; 32]);

impl Drop for VaultKey {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.0);
    }
}

/// Lifecycle event emitted by the configuration vault
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultEvent {
    /// Vault has been unlocked with master password
    Unlocked,
    /// Vault has been explicitly locked
    Locked,
    /// Inactivity timeout triggered auto-lock
    AutoLocked,
    /// Vault master password was changed / rotated
    PasswordChanged,
    /// Vault encryption was enabled on the manager
    Enabled,
    /// Vault encryption was disabled on the manager
    Disabled,
}

impl std::fmt::Display for VaultEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unlocked => write!(f, "unlocked"),
            Self::Locked => write!(f, "locked"),
            Self::AutoLocked => write!(f, "auto_locked"),
            Self::PasswordChanged => write!(f, "password_changed"),
            Self::Enabled => write!(f, "enabled"),
            Self::Disabled => write!(f, "disabled"),
        }
    }
}

/// Callback type for receiving vault lifecycle events
pub type VaultEventCallback = std::sync::Arc<dyn Fn(VaultEvent) + Send + Sync>;

/// Snapshot of configuration vault state and parameters
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VaultInfo {
    /// Whether vault encryption is enabled on the manager
    pub enabled: bool,
    /// Whether the vault is currently locked
    pub is_locked: bool,
    /// Configured inactivity auto-lock timeout, if any
    pub lock_timeout: Option<Duration>,
    /// Active Argon2 KDF parameters used for key derivation
    pub kdf_params: Argon2Params,
    /// Time elapsed since the last activity, if currently unlocked
    pub time_since_last_activity: Option<Duration>,
}

/// Internal status of the configuration vault
#[derive(Debug)]
pub(crate) enum VaultStatus {
    /// Vault is locked; keys are not held in memory.
    Locked {
        /// Salt from existing vault file (if discovered)
        salt: Option<[u8; 16]>,
    },
    /// Vault is unlocked with an active AES key in memory.
    Unlocked {
        /// Active key
        key: VaultKey,
        /// Salt associated with key
        salt: [u8; 16],
    },
}

/// Thread-safe controller for vault locking and unlocking lifecycle
pub struct VaultState {
    status: RwLock<VaultStatus>,
    lock_timeout: RwLock<Option<Duration>>,
    last_activity: RwLock<Instant>,
    kdf_params: RwLock<Argon2Params>,
    event_callback: RwLock<Option<VaultEventCallback>>,
    watchdog_running: Arc<AtomicBool>,
    migration_pins: AtomicUsize,
    root: std::path::PathBuf,
    identity: String,
}

/// Keeps the active key available throughout a managed migration and rollback.
pub(crate) struct MigrationGuard<'a> {
    vault: &'a VaultState,
}

impl Drop for MigrationGuard<'_> {
    fn drop(&mut self) {
        self.vault.touch();
        self.vault.migration_pins.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Drop for VaultState {
    fn drop(&mut self) {
        self.watchdog_running.store(false, Ordering::Release);
    }
}

impl VaultState {
    /// Create a new vault state
    #[must_use]
    pub(crate) fn new(
        root: &std::path::Path,
        salt: Option<[u8; 16]>,
        lock_timeout: Option<Duration>,
        kdf_params: Option<Argon2Params>,
        identity: Option<String>,
    ) -> Self {
        Self {
            status: RwLock::new(VaultStatus::Locked { salt }),
            lock_timeout: RwLock::new(lock_timeout),
            last_activity: RwLock::new(Instant::now()),
            kdf_params: RwLock::new(kdf_params.unwrap_or_default()),
            event_callback: RwLock::new(None),
            watchdog_running: Arc::new(AtomicBool::new(false)),
            migration_pins: AtomicUsize::new(0),
            root: root.to_path_buf(),
            identity: identity.unwrap_or_else(|| {
                base64::engine::general_purpose::STANDARD.encode(generate_salt())
            }),
        }
    }

    pub(crate) fn identity(&self) -> &str {
        &self.identity
    }

    pub(crate) fn begin_migration(&self) -> Result<MigrationGuard<'_>> {
        // Serialize pin acquisition with the watchdog's decision to destroy a key.
        let status = self.status.write().map_err(|_| Error::LockPoisoned)?;
        if matches!(*status, VaultStatus::Locked { .. }) {
            return Err(Error::ConfigLocked);
        }
        self.migration_pins.fetch_add(1, Ordering::SeqCst);
        Ok(MigrationGuard { vault: self })
    }

    fn context_for(
        &self,
        path: &std::path::Path,
        entry: Option<&str>,
    ) -> Result<super::envelope::VaultContext> {
        let relative = path
            .strip_prefix(&self.root)
            .map_err(|_| Error::Vault("Managed path is outside the vault root".into()))?;
        let parts = relative
            .components()
            .map(|part| {
                if let std::path::Component::Normal(name) = part {
                    name.to_str().ok_or_else(|| {
                        Error::Vault("Vault identities require UTF-8 filenames".into())
                    })
                } else {
                    Err(Error::Vault("Invalid managed vault path".into()))
                }
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(super::envelope::VaultContext {
            path: parts.join("/"),
            entry: entry.map(str::to_owned),
        })
    }

    pub(crate) fn encrypt_managed(
        &self,
        plaintext: &[u8],
        path: &std::path::Path,
        entry: Option<&str>,
    ) -> Result<VaultEnvelope> {
        self.encrypt_with_context(plaintext, Some(self.context_for(path, entry)?), None)
    }

    pub(crate) fn encrypt_managed_with_timeout(
        &self,
        plaintext: &[u8],
        path: &std::path::Path,
        timeout: Option<Duration>,
    ) -> Result<VaultEnvelope> {
        self.encrypt_with_context(plaintext, Some(self.context_for(path, None)?), timeout)
    }

    pub(crate) fn decrypt_managed(
        &self,
        value: &serde_json::Value,
        path: &std::path::Path,
        entry: Option<&str>,
    ) -> Result<String> {
        if !crate::vault::is_vault_value(value) {
            if value.get("__rcman_vault__").is_some() {
                return Err(Error::InvalidVaultEnvelope("Invalid vault marker".into()));
            }
            return Err(Error::InvalidVaultEnvelope(
                "Expected encrypted managed settings".into(),
            ));
        }
        let envelope: VaultEnvelope = serde_json::from_value(value.clone())?;
        self.validate_context(&envelope, path, entry)?;
        self.decrypt_envelope_to_str(&envelope).map_err(|error| {
            if matches!(error, Error::InvalidPassword) {
                Error::VaultDataAuthenticationFailed(format!(
                    "{} (entry {entry:?})",
                    path.display()
                ))
            } else {
                error
            }
        })
    }

    pub(crate) fn validate_context(
        &self,
        envelope: &VaultEnvelope,
        path: &std::path::Path,
        entry: Option<&str>,
    ) -> Result<()> {
        envelope.validate()?;
        if envelope.vault_id != self.identity() {
            return Err(Error::VaultMismatch(format!(
                "{} (entry {entry:?})",
                path.display()
            )));
        }
        if envelope.context.as_ref() != Some(&self.context_for(path, entry)?) {
            return Err(Error::VaultDataAuthenticationFailed(format!(
                "{} (entry {entry:?})",
                path.display()
            )));
        }
        Ok(())
    }

    /// Start the background auto-lock watchdog thread if not already running.
    ///
    /// The watchdog periodically inspects elapsed inactivity time and triggers
    /// auto-lock when `elapsed > lock_timeout`, emitting `VaultEvent::AutoLocked`.
    pub fn start_watchdog(self: &Arc<Self>) {
        if self.lock_timeout().is_none() || self.watchdog_running.swap(true, Ordering::SeqCst) {
            return;
        }

        let weak = Arc::downgrade(self);
        let is_running = Arc::clone(&self.watchdog_running);

        let spawned = std::thread::Builder::new()
            .name("rcman-vault-watchdog".to_string())
            .spawn(move || {
                while is_running.load(Ordering::Relaxed) {
                    let Some(vault) = weak.upgrade() else {
                        break;
                    };

                    let (is_locked, did_auto_lock) = vault.is_locked_transition();
                    if did_auto_lock {
                        log::debug!("rcman: vault auto-locked due to inactivity timeout");
                    }

                    let sleep_dur = if let Some(timeout) = vault.lock_timeout() {
                        if is_locked {
                            Duration::from_millis(500)
                        } else {
                            let elapsed = vault
                                .last_activity
                                .read()
                                .map_or(Duration::MAX, |t| t.elapsed());
                            if elapsed >= timeout {
                                Duration::from_millis(50)
                            } else {
                                let rem = timeout.saturating_sub(elapsed);
                                rem.min(Duration::from_millis(500))
                                    .max(Duration::from_millis(50))
                            }
                        }
                    } else {
                        Duration::from_millis(500)
                    };

                    drop(vault);
                    std::thread::sleep(sleep_dur);
                }
                is_running.store(false, Ordering::Release);
            });
        if let Err(error) = spawned {
            self.watchdog_running.store(false, Ordering::Release);
            log::error!("Failed to start vault auto-lock watchdog: {error}");
        }
    }

    /// Register a callback to receive vault lifecycle events
    pub fn set_event_callback(&self, cb: Option<VaultEventCallback>) {
        if let Ok(mut guard) = self.event_callback.write() {
            *guard = cb;
        }
    }

    /// Dispatch a vault event to the registered callback (if any)
    pub(crate) fn dispatch_event(&self, event: VaultEvent) {
        let cb = self.event_callback.read().ok().and_then(|g| g.clone());
        if let Some(cb) = cb {
            cb(event);
        }
    }

    /// Retrieve the currently configured Argon2 KDF parameters
    #[must_use]
    pub fn kdf_params(&self) -> Argon2Params {
        self.kdf_params.read().map(|g| *g).unwrap_or_default()
    }

    /// Set or update the active Argon2 KDF parameters
    fn set_kdf_params(&self, params: Argon2Params) {
        if let Ok(mut guard) = self.kdf_params.write() {
            *guard = params;
        }
    }

    /// Check if the vault is currently locked, automatically applying inactivity timeout.
    ///
    /// Returns a tuple `(is_locked, did_auto_lock_transition)`.
    pub fn is_locked_transition(&self) -> (bool, bool) {
        let did_auto_lock = if let Some(timeout) = self.lock_timeout() {
            // Serialize the transition with encryption and explicit locking. Reading
            // activity under this guard prevents expiring a concurrent successful write.
            let Ok(mut status) = self.status.write() else {
                return (true, false);
            };
            let elapsed = self
                .last_activity
                .read()
                .map_or(Duration::MAX, |t| t.elapsed());
            if elapsed >= timeout && self.migration_pins.load(Ordering::SeqCst) == 0 {
                if let VaultStatus::Unlocked { salt, .. } = &*status {
                    let salt = *salt;
                    *status = VaultStatus::Locked { salt: Some(salt) };
                    true
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        };

        if did_auto_lock {
            self.dispatch_event(VaultEvent::AutoLocked);
            return (true, true);
        }

        let Ok(guard) = self.status.read() else {
            return (true, false);
        };

        (matches!(*guard, VaultStatus::Locked { .. }), false)
    }

    /// Check if the vault is currently locked, automatically applying inactivity timeout
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.is_locked_transition().0
    }

    /// Record activity to refresh the inactivity timer
    pub fn touch(&self) {
        if let Ok(mut guard) = self.last_activity.write() {
            *guard = Instant::now();
        }
    }

    /// Get the configured lock timeout
    #[must_use]
    pub fn lock_timeout(&self) -> Option<Duration> {
        self.lock_timeout.read().ok().and_then(|g| *g)
    }

    /// Set or update the inactivity lock timeout
    pub fn set_lock_timeout(&self, timeout: Option<Duration>) {
        if let Ok(mut guard) = self.lock_timeout.write() {
            *guard = timeout;
        }
    }

    /// Time elapsed since the last activity, or None if currently locked
    #[must_use]
    pub fn time_since_last_activity(&self) -> Option<Duration> {
        if self.is_locked() {
            None
        } else {
            self.last_activity.read().ok().map(|t| t.elapsed())
        }
    }

    /// Assemble a `VaultInfo` snapshot of current state
    #[must_use]
    pub fn info(&self) -> VaultInfo {
        let is_locked = self.is_locked();
        let time_since_last_activity = if is_locked {
            None
        } else {
            self.last_activity.read().ok().map(|t| t.elapsed())
        };

        VaultInfo {
            enabled: true,
            is_locked,
            lock_timeout: self.lock_timeout(),
            kdf_params: self.kdf_params(),
            time_since_last_activity,
        }
    }

    /// Explicitly lock the vault and scrub the encryption key from RAM
    ///
    /// # Errors
    /// Returns `Error::LockPoisoned` if the internal lock is poisoned, or
    /// `Error::ConcurrentModification` while a managed migration needs the key.
    pub fn lock(&self) -> Result<()> {
        let mut guard = self.status.write().map_err(|_| Error::LockPoisoned)?;
        if self.migration_pins.load(Ordering::SeqCst) != 0 {
            return Err(Error::ConcurrentModification);
        }
        let current_salt = match &*guard {
            VaultStatus::Locked { salt } => *salt,
            VaultStatus::Unlocked { salt, .. } => Some(*salt),
        };
        *guard = VaultStatus::Locked { salt: current_salt };
        Ok(())
    }

    /// Unlock the vault using a password and optional envelope to verify and decrypt
    ///
    /// # Errors
    /// Returns:
    /// - `Error::InvalidPassword` if decryption of the envelope fails
    /// - `Error::Vault` if key derivation fails
    /// - `Error::LockPoisoned` if internal synchronization fails
    pub fn unlock(
        &self,
        password: &str,
        envelope: Option<&VaultEnvelope>,
    ) -> Result<Option<Vec<u8>>> {
        let (salt, active_params, key_bytes, payload) = if let Some(env) = envelope {
            env.validate()?;
            if env.vault_id != self.identity {
                return Err(Error::VaultMismatch("vault metadata".into()));
            }
            let salt = env.decode_salt()?;
            let params = env.kdf_params();
            let key = zeroize::Zeroizing::new(derive_key(password, &salt, &params)?);
            let nonce = env.decode_nonce()?;
            let ciphertext = env.decode_ciphertext()?;
            let payload =
                decrypt_authenticated(&key, &nonce, &ciphertext, &env.authenticated_data()?)?;
            (salt, params, key, Some(payload))
        } else {
            let current_salt = {
                let guard = self.status.read().map_err(|_| Error::LockPoisoned)?;
                match &*guard {
                    VaultStatus::Locked { salt } => *salt,
                    VaultStatus::Unlocked { salt, .. } => Some(*salt),
                }
            };
            let salt = current_salt.unwrap_or_else(generate_salt);
            let params = self.kdf_params();
            let key = zeroize::Zeroizing::new(derive_key(password, &salt, &params)?);
            (salt, params, key, None)
        };

        // Keep parameters synchronized with the decrypted envelope
        self.set_kdf_params(active_params);

        let mut guard = self.status.write().map_err(|_| Error::LockPoisoned)?;
        *guard = VaultStatus::Unlocked {
            key: VaultKey(*key_bytes),
            salt,
        };
        self.touch();
        Ok(payload)
    }

    /// Encrypt a byte slice payload and pack into a `VaultEnvelope`
    ///
    /// # Errors
    /// Returns `Error::ConfigLocked` if locked, or `Error::Vault` if encryption fails.
    #[cfg(test)]
    fn encrypt_payload(&self, plaintext: &[u8]) -> Result<VaultEnvelope> {
        self.encrypt_with_context(plaintext, None, self.lock_timeout())
    }

    fn encrypt_with_context(
        &self,
        plaintext: &[u8],
        context: Option<super::envelope::VaultContext>,
        timeout: Option<Duration>,
    ) -> Result<VaultEnvelope> {
        if self.is_locked() {
            return Err(Error::ConfigLocked);
        }

        let guard = self.status.read().map_err(|_| Error::LockPoisoned)?;
        match &*guard {
            VaultStatus::Unlocked { key, salt } => {
                let nonce = generate_nonce();
                let params = self.kdf_params();
                let timeout_ms = timeout
                    .map(|d| u64::try_from(d.as_millis()))
                    .transpose()
                    .map_err(|_| {
                        Error::Config("Vault timeout exceeds the supported duration".into())
                    })?;
                let mut envelope = VaultEnvelope::with_params_and_timeout(
                    self.identity().to_owned(),
                    salt,
                    &nonce,
                    &[],
                    Some(params),
                    timeout_ms,
                );
                envelope.context = context;
                let ciphertext = encrypt_authenticated(
                    &key.0,
                    &nonce,
                    plaintext,
                    &envelope.authenticated_data()?,
                )?;
                envelope.ciphertext = base64::engine::general_purpose::STANDARD.encode(ciphertext);
                self.touch();
                Ok(envelope)
            }
            VaultStatus::Locked { .. } => Err(Error::ConfigLocked),
        }
    }

    /// Decrypt a `VaultEnvelope` using the active key
    ///
    /// # Errors
    /// Returns `Error::ConfigLocked` if locked, or `Error::InvalidPassword` if tag verification fails.
    pub fn decrypt_envelope(&self, envelope: &VaultEnvelope) -> Result<Vec<u8>> {
        if self.is_locked() {
            return Err(Error::ConfigLocked);
        }
        let key = {
            let status = self.status.read().map_err(|_| Error::LockPoisoned)?;
            let VaultStatus::Unlocked { key, .. } = &*status else {
                return Err(Error::ConfigLocked);
            };
            zeroize::Zeroizing::new(key.0)
        };
        let nonce = envelope.decode_nonce()?;
        let ciphertext = envelope.decode_ciphertext()?;
        decrypt_authenticated(&key, &nonce, &ciphertext, &envelope.authenticated_data()?)
    }

    /// Decrypt a `VaultEnvelope` and return the decrypted bytes as a UTF-8 string
    ///
    /// # Errors
    /// Returns `Error::ConfigLocked` if locked, `Error::InvalidPassword` if decryption fails,
    /// or `Error::Vault` if UTF-8 decoding fails.
    pub fn decrypt_envelope_to_str(&self, envelope: &VaultEnvelope) -> Result<String> {
        let bytes = self.decrypt_envelope(envelope)?;
        String::from_utf8(bytes)
            .map_err(|e| Error::Vault(format!("Decrypted data is not UTF-8: {e}")))
    }

    /// Verify whether a password matches the vault without altering lock state or active key.
    ///
    /// If `envelope` is provided, the candidate password is validated against the envelope's
    /// authentication tag regardless of whether the vault is locked or unlocked.
    ///
    /// # Errors
    /// Returns `Error::ConfigLocked` if locked and no envelope is provided, or `Error::Vault` on crypto error.
    pub fn verify_password(
        &self,
        candidate_password: &str,
        envelope: Option<&VaultEnvelope>,
    ) -> Result<bool> {
        if let Some(env) = envelope {
            env.validate()?;
            let salt = env.decode_salt()?;
            let params = env.kdf_params();
            let key = zeroize::Zeroizing::new(derive_key(candidate_password, &salt, &params)?);
            let nonce = env.decode_nonce()?;
            let ciphertext = env.decode_ciphertext()?;
            match decrypt_authenticated(&key, &nonce, &ciphertext, &env.authenticated_data()?) {
                Ok(_) => Ok(true),
                Err(Error::InvalidPassword) => Ok(false),
                Err(e) => Err(e),
            }
        } else {
            let guard = self.status.read().map_err(|_| Error::LockPoisoned)?;
            match &*guard {
                VaultStatus::Unlocked { key, salt } => {
                    let active_params = self.kdf_params();
                    let derived = zeroize::Zeroizing::new(derive_key(
                        candidate_password,
                        salt,
                        &active_params,
                    )?);
                    Ok(constant_time_eq(derived.as_ref(), &key.0))
                }
                VaultStatus::Locked { .. } => Err(Error::ConfigLocked),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_pins_prevent_auto_and_explicit_key_loss() {
        let state = VaultState::new(
            std::path::Path::new("test-root"),
            None,
            None,
            Some(Argon2Params::fast()),
            None,
        );
        state.unlock("password", None).unwrap();
        let pin = state.begin_migration().unwrap();
        state.set_lock_timeout(Some(Duration::ZERO));
        assert!(!state.is_locked());
        assert!(matches!(state.lock(), Err(Error::ConcurrentModification)));
        assert!(state.encrypt_payload(b"retained key").is_ok());
        drop(pin);
        assert!(state.is_locked());
    }

    #[test]
    fn test_vault_lifecycle() {
        let state = VaultState::new(
            std::path::Path::new("test-root"),
            None,
            None,
            Some(Argon2Params::fast()),
            None,
        );
        assert!(state.is_locked());

        // Unlock with password (new store)
        state.unlock("secret123", None).unwrap();
        assert!(!state.is_locked());

        // Encrypt payload
        let envelope = state.encrypt_payload(b"hello world").unwrap();
        let decrypted = state.decrypt_envelope(&envelope).unwrap();
        assert_eq!(decrypted, b"hello world");

        // Lock
        state.lock().unwrap();
        assert!(state.is_locked());

        // Unlock with wrong password against existing envelope
        let wrong_err = state.unlock("wrong_password", Some(&envelope)).unwrap_err();
        assert!(matches!(wrong_err, Error::InvalidPassword));
        assert!(state.is_locked());

        // Unlock with correct password
        let payload = state.unlock("secret123", Some(&envelope)).unwrap().unwrap();
        assert_eq!(payload, b"hello world");
        assert!(!state.is_locked());
    }

    #[test]
    fn test_lock_timeout() {
        let state = VaultState::new(
            std::path::Path::new("test-root"),
            None,
            Some(Duration::from_millis(50)),
            Some(Argon2Params::fast()),
            None,
        );
        state.unlock("pass", None).unwrap();
        assert!(!state.is_locked());

        // Wait past the timeout
        std::thread::sleep(Duration::from_millis(60));
        assert!(state.is_locked());
    }
}
