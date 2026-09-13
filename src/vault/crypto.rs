//! Cryptographic primitives for rcman vault
//!
//! Provides AES-256-GCM authenticated encryption and Argon2id key derivation.

use crate::error::{Error, Result};
use crate::vault::envelope::Argon2Params;
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString},
};
use rand::RngExt;

/// Generate a cryptographically secure 16-byte random salt
#[must_use]
pub fn generate_salt() -> [u8; 16] {
    rand::rng().random()
}

/// Generate a cryptographically secure 12-byte random AES-GCM nonce
#[must_use]
pub fn generate_nonce() -> [u8; 12] {
    rand::rng().random()
}

/// Derive a 32-byte AES-256 encryption key from a password and salt using Argon2id
///
/// # Errors
/// Returns `Error::Vault` if hashing or encoding fails.
pub fn derive_key(password: &str, salt: &[u8; 16], params: &Argon2Params) -> Result<[u8; 32]> {
    let salt_string = SaltString::encode_b64(salt)
        .map_err(|e| Error::Vault(format!("Invalid salt bytes for Argon2: {e}")))?;

    let argon_params = argon2::Params::new(params.m_cost, params.t_cost, params.p_cost, Some(32))
        .map_err(|e| Error::Vault(format!("Invalid Argon2 parameters: {e}")))?;

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon_params,
    );

    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt_string)
        .map_err(|e| Error::Vault(format!("Argon2 key derivation failed: {e}")))?;

    let output = password_hash
        .hash
        .ok_or_else(|| Error::Vault("Argon2 hash output missing".into()))?;

    let bytes = output.as_bytes();
    if bytes.len() < 32 {
        return Err(Error::Vault(format!(
            "Argon2 output too short: expected >= 32, got {}",
            bytes.len()
        )));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes[..32]);
    Ok(key)
}

/// Encrypt plaintext using AES-256-GCM
///
/// # Errors
/// Returns `Error::Vault` if encryption fails.
pub fn encrypt(key: &[u8; 32], nonce_bytes: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| Error::Vault(format!("Invalid key length: {e}")))?;
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| Error::Vault(format!("AES-256-GCM encryption failed: {e}")))
}

/// Decrypt ciphertext using AES-256-GCM
///
/// # Errors
/// Returns `Error::InvalidPassword` if authentication fails, or `Error::Vault` for structural errors.
pub fn decrypt(key: &[u8; 32], nonce_bytes: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| Error::Vault(format!("Invalid key length: {e}")))?;
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| Error::InvalidPassword)
}

/// Securely zero out a byte buffer in memory using volatile writes and a compiler fence
pub fn zeroize_bytes(bytes: &mut [u8]) {
    for b in bytes.iter_mut() {
        // Safety: Pointer is valid as it comes from a mutable reference to an existing slice element.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// Compare two byte slices in constant time to mitigate timing attacks
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key_deterministic() {
        let params = Argon2Params::fast();
        let salt = [42u8; 16];
        let key1 = derive_key("my_password", &salt, &params).unwrap();
        let key2 = derive_key("my_password", &salt, &params).unwrap();
        assert_eq!(key1, key2);

        let key_diff_pass = derive_key("other_password", &salt, &params).unwrap();
        assert_ne!(key1, key_diff_pass);

        let other_salt = [43u8; 16];
        let key_diff_salt = derive_key("my_password", &other_salt, &params).unwrap();
        assert_ne!(key1, key_diff_salt);

        let standard_params = Argon2Params::standard();
        let key_standard = derive_key("my_password", &salt, &standard_params).unwrap();
        assert_ne!(key1, key_standard);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [7u8; 32];
        let nonce = [9u8; 12];
        let message = b"Hello, rcman secure vault!";

        let ciphertext = encrypt(&key, &nonce, message).unwrap();
        assert_ne!(ciphertext, message);

        let decrypted = decrypt(&key, &nonce, &ciphertext).unwrap();
        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let key = [7u8; 32];
        let wrong_key = [8u8; 32];
        let nonce = [9u8; 12];
        let message = b"Secret payload";

        let ciphertext = encrypt(&key, &nonce, message).unwrap();
        let err = decrypt(&wrong_key, &nonce, &ciphertext).unwrap_err();
        assert!(matches!(err, Error::InvalidPassword));
    }

    #[test]
    fn test_zeroize_bytes() {
        let mut key = [0xFFu8; 32];
        zeroize_bytes(&mut key);
        assert_eq!(key, [0u8; 32]);
    }

    #[test]
    fn test_constant_time_eq() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 4];
        let c = [1u8, 2, 3, 5];
        let d = [1u8, 2, 3];
        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
        assert!(!constant_time_eq(&a, &d));
    }
}
