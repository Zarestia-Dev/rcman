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
    /// Create custom Argon2 parameters
    #[must_use]
    pub const fn new(m_cost: u32, t_cost: u32, p_cost: u32) -> Self {
        Self {
            m_cost,
            t_cost,
            p_cost,
        }
    }

    /// Fast preset for unit testing and rapid local execution (64 `KiB`, 1 pass, 1 lane)
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
    /// Ultra-fast derivation for unit tests, CI pipelines, and high-frequency CLI workflows (64 `KiB`, 1 iteration, 1 lane)
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

/// On-disk envelope for encrypted settings
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultEnvelope {
    /// Magic identifier signaling an rcman vault envelope
    __rcman_vault__: u32,
    /// Format version
    pub version: u32,
    /// Cryptographic algorithm suite
    pub algorithm: String,
    /// Base64-encoded 16-byte Argon2id salt
    pub salt: String,
    /// Base64-encoded 12-byte AES-GCM nonce
    pub nonce: String,
    /// Base64-encoded ciphertext with authentication tag
    pub ciphertext: String,
    /// Key derivation parameters used to derive the AES key (optional for backwards compatibility)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kdf_params: Option<Argon2Params>,
    /// Inactivity auto-lock timeout in milliseconds (optional for backwards compatibility)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lock_timeout_ms: Option<u64>,
}

impl VaultEnvelope {
    /// Create a new vault envelope with default KDF parameters
    #[must_use]
    pub fn new(salt: &[u8; 16], nonce: &[u8; 12], ciphertext: &[u8]) -> Self {
        Self::with_params(salt, nonce, ciphertext, None)
    }

    /// Create a new vault envelope with explicit KDF parameters and optional timeout
    #[must_use]
    pub fn with_params_and_timeout(
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
            salt: BASE64.encode(salt),
            nonce: BASE64.encode(nonce),
            ciphertext: BASE64.encode(ciphertext),
            kdf_params,
            lock_timeout_ms,
        }
    }

    /// Create a new vault envelope with explicit KDF parameters
    #[must_use]
    pub fn with_params(
        salt: &[u8; 16],
        nonce: &[u8; 12],
        ciphertext: &[u8],
        kdf_params: Option<Argon2Params>,
    ) -> Self {
        Self::with_params_and_timeout(salt, nonce, ciphertext, kdf_params, None)
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

    if envelope.__rcman_vault__ != 1 {
        return Err(Error::InvalidVaultEnvelope(format!(
            "Unsupported vault magic marker: {}",
            envelope.__rcman_vault__
        )));
    }

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

        let env = VaultEnvelope::new(&salt, &nonce, ciphertext);
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
