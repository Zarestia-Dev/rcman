//! Vault envelope definition and serialization
//!
//! Provides the on-disk storage format for encrypted configuration files.

use crate::error::{Error, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};

/// Current vault format version
pub const VAULT_VERSION: u32 = 1;

/// Standard algorithm identifier for rcman vaults
pub const VAULT_ALGORITHM: &str = "aes-256-gcm+argon2id";

/// Tuning parameters for Argon2id key derivation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Argon2Params {
    /// Memory size in `KiB` (default: 19,456 = 19 `MiB`)
    pub m_cost: u32,
    /// Number of iterations / passes (default: 2)
    pub t_cost: u32,
    /// Degree of parallelism / lane count (default: 1)
    pub p_cost: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Argon2Preset::Standard.params()
    }
}

impl Argon2Params {
    /// Validate parameters against the vault's resource budget before allocating memory.
    ///
    /// At most 256 `MiB`, 10 passes, and 16 lanes are accepted. These limits bound
    /// work requested by an unauthenticated file.
    ///
    /// # Errors
    /// Returns `Error::Vault` for invalid parameters or costs exceeding the budget.
    pub fn validate(&self) -> Result<()> {
        if self.m_cost > 262_144 || self.t_cost > 10 || self.p_cost > 16 {
            return Err(Error::Vault(
                "Argon2 parameters exceed the vault resource budget".into(),
            ));
        }
        argon2::Params::new(self.m_cost, self.t_cost, self.p_cost, Some(32))
            .map_err(|error| Error::Vault(format!("Invalid Argon2 parameters: {error}")))?;
        Ok(())
    }

    /// Create custom Argon2 parameters
    #[must_use]
    pub const fn new(m_cost: u32, t_cost: u32, p_cost: u32) -> Self {
        Self {
            m_cost,
            t_cost,
            p_cost,
        }
    }

    /// Low-cost preset for tests and demos, not production data (64 `KiB`, 1 pass, 1 lane)
    #[must_use]
    pub const fn fast() -> Self {
        Argon2Preset::Fast.params()
    }

    /// Standard OWASP-recommended preset (19 `MiB`, 2 passes, 1 lane)
    #[must_use]
    pub const fn standard() -> Self {
        Argon2Preset::Standard.params()
    }

    /// Memory-conscious preset for mobile/embedded targets (8 `MiB`, 1 pass, 1 lane)
    #[must_use]
    pub const fn mobile() -> Self {
        Argon2Preset::Mobile.params()
    }

    /// Hardened security preset for server/enterprise environments (64 `MiB`, 3 passes, 4 lanes)
    #[must_use]
    pub const fn high_security() -> Self {
        Argon2Preset::HighSecurity.params()
    }
}

/// Pre-configured security and performance presets for Argon2id key derivation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Argon2Preset {
    /// Standard OWASP recommendation (19,456 `KiB` / ~19 `MiB`, 2 iterations, 1 lane)
    #[default]
    Standard,
    /// Low-cost derivation for tests and demos, not production data (64 `KiB`, 1 iteration, 1 lane)
    Fast,
    /// Memory-conscious profile tailored for mobile (Android/iOS) and constrained environments (8,192 `KiB`, 1 iteration, 1 lane)
    Mobile,
    /// Hardened profile for maximum brute-force resistance (65,536 `KiB` / 64 `MiB`, 3 iterations, 4 lanes)
    HighSecurity,
}

impl Argon2Preset {
    /// Return the corresponding `Argon2Params` configuration
    #[must_use]
    pub const fn params(self) -> Argon2Params {
        match self {
            Self::Standard => Argon2Params::new(19_456, 2, 1),
            Self::Fast => Argon2Params::new(64, 1, 1),
            Self::Mobile => Argon2Params::new(8_192, 1, 1),
            Self::HighSecurity => Argon2Params::new(65_536, 3, 4),
        }
    }
}

/// Relative location authenticated by a managed vault envelope.
///
/// Paths use `/` separators on every platform and are relative to the vault root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultContext {
    /// Relative managed filename, including any profile and group directories.
    pub path: String,
    /// Logical record identity for storage backends that share a file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<String>,
}

/// On-disk envelope for encrypted settings
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultEnvelope {
    /// Magic identifier signaling an rcman vault envelope
    __rcman_vault__: u32,
    /// Format version
    pub version: u32,
    /// Cryptographic algorithm suite
    pub algorithm: String,
    /// Base64-encoded random 16-byte identity shared by every file in this vault.
    pub vault_id: String,
    /// Base64-encoded 16-byte Argon2id salt
    pub salt: String,
    /// Base64-encoded 12-byte AES-GCM nonce
    pub nonce: String,
    /// Base64-encoded ciphertext with authentication tag
    pub ciphertext: String,
    /// Key derivation parameters used to derive the AES key
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kdf_params: Option<Argon2Params>,
    /// Inactivity timeout in milliseconds, stored only in root vault metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lock_timeout_ms: Option<u64>,
    /// Authenticated logical file and optional row identity for managed envelopes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<VaultContext>,
}

impl VaultEnvelope {
    /// Create a new vault envelope with explicit KDF parameters and optional timeout
    #[must_use]
    pub(crate) fn with_params_and_timeout(
        vault_id: String,
        salt: &[u8; 16],
        nonce: &[u8; 12],
        ciphertext: &[u8],
        kdf_params: Option<Argon2Params>,
        lock_timeout_ms: Option<u64>,
    ) -> Self {
        Self {
            __rcman_vault__: 1,
            version: VAULT_VERSION,
            algorithm: VAULT_ALGORITHM.to_string(),
            vault_id,
            salt: BASE64.encode(salt),
            nonce: BASE64.encode(nonce),
            ciphertext: BASE64.encode(ciphertext),
            kdf_params,
            lock_timeout_ms,
            context: None,
        }
    }

    /// Validate the format and cheap structural properties before deriving a key.
    ///
    /// # Errors
    /// Returns an error for unsupported formats, invalid encodings, truncated tags,
    /// or Argon2 costs outside the supported resource budget.
    pub fn validate(&self) -> Result<()> {
        if self.__rcman_vault__ != 1
            || self.version != VAULT_VERSION
            || self.algorithm != VAULT_ALGORITHM
        {
            return Err(Error::InvalidVaultEnvelope(
                "Unsupported vault format or algorithm".into(),
            ));
        }
        self.kdf_params().validate()?;
        if BASE64
            .decode(&self.vault_id)
            .map_or(true, |id| id.len() != 16)
        {
            return Err(Error::InvalidVaultEnvelope("Invalid vault identity".into()));
        }
        self.decode_salt()?;
        self.decode_nonce()?;
        if self.decode_ciphertext()?.len() < 16 {
            return Err(Error::InvalidVaultEnvelope(
                "Ciphertext is missing its authentication tag".into(),
            ));
        }
        Ok(())
    }

    pub(crate) fn authenticated_data(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&(
            self.__rcman_vault__,
            self.version,
            &self.algorithm,
            &self.vault_id,
            &self.salt,
            self.kdf_params,
            self.lock_timeout_ms,
            &self.context,
        ))?)
    }

    /// Retrieve the configured auto-lock timeout, if present
    #[must_use]
    pub fn lock_timeout(&self) -> Option<std::time::Duration> {
        self.lock_timeout_ms.map(std::time::Duration::from_millis)
    }

    /// Retrieve the effective Argon2 parameters (falling back to standard defaults if absent)
    #[must_use]
    pub fn kdf_params(&self) -> Argon2Params {
        self.kdf_params.unwrap_or_default()
    }

    /// Decode the 16-byte salt from Base64
    ///
    /// # Errors
    /// Returns `Error::InvalidVaultEnvelope` if decoding fails or length != 16.
    pub fn decode_salt(&self) -> Result<[u8; 16]> {
        let vec = BASE64
            .decode(&self.salt)
            .map_err(|e| Error::InvalidVaultEnvelope(format!("Invalid salt base64: {e}")))?;
        if vec.len() != 16 {
            return Err(Error::InvalidVaultEnvelope(format!(
                "Invalid salt length: expected 16, got {}",
                vec.len()
            )));
        }
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&vec);
        Ok(salt)
    }

    /// Decode the 12-byte nonce from Base64
    ///
    /// # Errors
    /// Returns `Error::InvalidVaultEnvelope` if decoding fails or length != 12.
    pub fn decode_nonce(&self) -> Result<[u8; 12]> {
        let vec = BASE64
            .decode(&self.nonce)
            .map_err(|e| Error::InvalidVaultEnvelope(format!("Invalid nonce base64: {e}")))?;
        if vec.len() != 12 {
            return Err(Error::InvalidVaultEnvelope(format!(
                "Invalid nonce length: expected 12, got {}",
                vec.len()
            )));
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&vec);
        Ok(nonce)
    }

    /// Decode the ciphertext from Base64
    ///
    /// # Errors
    /// Returns `Error::InvalidVaultEnvelope` if decoding fails.
    pub fn decode_ciphertext(&self) -> Result<Vec<u8>> {
        BASE64
            .decode(&self.ciphertext)
            .map_err(|e| Error::InvalidVaultEnvelope(format!("Invalid ciphertext base64: {e}")))
    }
}

/// Check if a string content looks like an rcman vault envelope
#[must_use]
pub fn is_vault_content(content: &str) -> bool {
    content.contains("__rcman_vault__")
}

/// Check if a `serde_json::Value` looks like an rcman vault envelope
#[must_use]
pub fn is_vault_value(value: &serde_json::Value) -> bool {
    value
        .get("__rcman_vault__")
        .and_then(serde_json::Value::as_u64)
        == Some(1)
}

/// Parse a string content as a vault envelope if it matches the format
///
/// # Errors
/// Returns `Error::InvalidVaultEnvelope` if it has the vault marker but fails to parse.
pub fn parse_envelope(content: &str) -> Result<Option<VaultEnvelope>> {
    if !is_vault_content(content) {
        return Ok(None);
    }

    let envelope: VaultEnvelope = serde_json::from_str(content)
        .map_err(|e| Error::InvalidVaultEnvelope(format!("Failed to parse vault envelope: {e}")))?;

    envelope.validate()?;

    Ok(Some(envelope))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_envelope_roundtrip() {
        let salt = [1u8; 16];
        let nonce = [2u8; 12];
        let ciphertext = b"encrypted_payload";

        let env = VaultEnvelope::with_params_and_timeout(
            BASE64.encode([1; 16]),
            &salt,
            &nonce,
            ciphertext,
            None,
            None,
        );
        let serialized = serde_json::to_string_pretty(&env).unwrap();

        assert!(is_vault_content(&serialized));
        let parsed = parse_envelope(&serialized).unwrap().unwrap();

        assert_eq!(parsed.decode_salt().unwrap(), salt);
        assert_eq!(parsed.decode_nonce().unwrap(), nonce);
        assert_eq!(parsed.decode_ciphertext().unwrap(), ciphertext);
    }

    #[test]
    fn test_non_vault_content() {
        let normal_json = r#"{"ui": {"theme": "dark"}}"#;
        assert!(!is_vault_content(normal_json));
        assert!(parse_envelope(normal_json).unwrap().is_none());
    }
}
