//! Encrypted File Storage Example
//!
//! This example demonstrates how to use the encrypted file backend
//! for environments without OS keychain (Docker, CI, headless servers).
//!
//! The encrypted store saves secrets in a JSON file with:
//! - Argon2id (memory-hard, GPU-resistant) for key derivation
//! - AES-256-GCM for encryption
//! - Salt stored in plain text (safe) for key reconstruction
//!
//! Run with: cargo run --example `encrypted_storage` --features encrypted-file

use rcman::{CredentialBackend, EncryptedFileBackend};

fn main() {
    println!("🔐 Encrypted File Storage Demo (Argon2id)\n");
    println!("This demonstrates storing secrets WITHOUT using the OS keychain.");
    println!("Perfect for Docker, CI/CD, and headless environments.\n");

    // Create a temp directory for the example
    let temp_dir = std::env::temp_dir().join("rcman_encrypted_demo");
    std::fs::create_dir_all(&temp_dir).unwrap();
    let credentials_path = temp_dir.join("credentials.enc.json");

    // Clean up from previous runs
    if credentials_path.exists() {
        std::fs::remove_file(&credentials_path).unwrap();
    }

    // =========================================================================
    // STEP 1: Create encrypted store with a password
    // =========================================================================
    println!("📝 Step 1: Create encrypted store with password\n");

    let password = "my_secure_password";

    // with_password() is the recommended API:
    // - Generates random salt for new files
    // - Reads salt from existing files
    // - Derives key using Argon2id (state-of-the-art security)
    let backend = EncryptedFileBackend::with_password(credentials_path.clone(), password)
        .expect("Failed to create encrypted backend");

    println!(
        "   ✅ Encrypted backend created at: {}",
        credentials_path.display()
    );
    println!("   ⏱️  Key derivation uses Argon2id (memory-hard = GPU resistant)\n");

    // =========================================================================
    // STEP 2: Store some secrets
    // =========================================================================
    println!("📝 Step 2: Store secrets\n");

    backend.store("api_key", "sk-12345-secret-key").unwrap();
    backend
        .store("database_password", "super_secret_db_pass")
        .unwrap();
    backend
        .store("jwt_secret", "my-jwt-signing-secret")
        .unwrap();

    println!("   ✅ Stored: api_key, database_password, jwt_secret\n");

    // =========================================================================
    // STEP 3: Show the encrypted file format
    // =========================================================================
    println!("📄 Step 3: Encrypted file format (v3 - Argon2)\n");

    let file_content = std::fs::read_to_string(&credentials_path).unwrap();
    // Only show first part of entries to keep it readable
    let preview: serde_json::Value = serde_json::from_str(&file_content).unwrap();
    println!("   {{\n     \"version\": {},", preview["version"]);
    println!(
        "     \"salt\": \"{}\",",
        &preview["salt"].as_str().unwrap()[..24]
    );
    println!("     \"entries\": {{");
    if let Some(entries) = preview["entries"].as_object() {
        for key in entries.keys().take(1) {
            println!("       \"{key}\": {{ \"nonce\": \"...\", \"ciphertext\": \"...\" }}, ...");
        }
    }
    println!("     }}\n   }}\n");
    println!("   ℹ️  Salt is stored plaintext (safe - prevents rainbow tables)");
    println!("   ℹ️  Entries are AES-256-GCM encrypted\n");

    // =========================================================================
    // STEP 4: Simulate app restart - reopen with same password
    // =========================================================================
    println!("🔄 Step 4: Simulate app restart\n");

    // Drop the old backend (simulates app restart)
    drop(backend);

    // Reopen with the same password
    println!("   Opening encrypted store with password...");
    let backend2 = EncryptedFileBackend::with_password(credentials_path.clone(), password)
        .expect("Failed to reopen");

    // Read back the secrets
    let api_key = backend2.get("api_key").unwrap().unwrap();
    let db_pass = backend2.get("database_password").unwrap().unwrap();

    println!("   ✅ Retrieved api_key: {}...", &api_key[..10]);
    println!("   ✅ Retrieved database_password: {}...\n", &db_pass[..10]);

    // =========================================================================
    // STEP 5: Wrong password detection
    // =========================================================================
    println!("🔒 Step 5: Wrong password detection\n");

    // The password is checked when an existing file is opened.
    match EncryptedFileBackend::with_password(credentials_path.clone(), "wrong_password") {
        Ok(_) => println!("   ❌ This shouldn't happen!"),
        Err(e) => println!("   ✅ Correctly rejected wrong password: {e}"),
    }
    println!();

    // =========================================================================
    // STEP 6: List all keys
    // =========================================================================
    println!("📋 Step 6: List stored keys\n");

    let keys = backend2.list_keys().unwrap();
    println!("   Stored secrets:");
    for key in &keys {
        println!("     - {key}");
    }
    println!();

    // =========================================================================
    // Cleanup
    // =========================================================================
    println!("🧹 Cleanup\n");
    std::fs::remove_dir_all(&temp_dir).unwrap();
    println!("   ✅ Removed temp directory\n");

    // =========================================================================
    // Summary
    // =========================================================================
    println!("═══════════════════════════════════════════════════════════════════");
    println!("                        USAGE SUMMARY");
    println!("═══════════════════════════════════════════════════════════════════\n");
    println!("For new projects, use the recommended with_password() API:\n");
    println!("  use rcman::EncryptedFileBackend;");
    println!();
    println!("  let backend = EncryptedFileBackend::with_password(path, \"password\")?;");
    println!("  backend.store(\"api_key\", \"secret_value\")?;");
    println!("  let value = backend.get(\"api_key\")?;");
    println!();
    println!("The salt is automatically:");
    println!("  • Generated on first use");
    println!("  • Stored in the JSON file");
    println!("  • Read on subsequent opens");
    println!();
    println!("Security features:");
    println!("  • Argon2id (v3) for state-of-the-art key derivation");
    println!("  • AES-256-GCM authenticated encryption");
    println!("  • Random 16-byte salt per file");
    println!("  • Random 12-byte nonce per entry");
}
