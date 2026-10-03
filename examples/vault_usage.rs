//! Configuration Vault & Lock Example
//!
//! This example demonstrates using the native configuration vault:
//! - Encrypting main configuration and sub-settings on disk with AES-256-GCM + Argon2id
//! - Checking whether the config is locked on application startup
//! - Unlocking with a master key or password
//! - Transparently reading and saving settings and sub-settings while unlocked
//! - Verifying on-disk encrypted envelope structures (zero plaintext leakage)
//! - Locking on demand and protecting against unauthorized sub-settings access
//! - Rotating master passwords with automatic sub-settings re-encryption
//!
//! Run with: cargo run --example vault_usage --features vault

use rcman::vault::Argon2Preset;
use rcman::{Error, SettingMetadata, SettingsManager, SettingsSchema, SubSettingsConfig, settings};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct AppSettings;

impl SettingsSchema for AppSettings {
    fn get_metadata() -> rcman::IndexMap<String, SettingMetadata> {
        settings! {
            "api.endpoint" => SettingMetadata::text("https://api.default.internal")
                .meta_str("label", "API Endpoint")
                .meta_str("category", "API"),

            "api.rate_limit" => SettingMetadata::number(60.0)
                .meta_str("label", "Rate Limit")
                .meta_str("category", "API"),
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 rcman Configuration Vault & Lock Demo\n");
    println!("Encrypts configuration files at rest with AES-256-GCM and Argon2id.");
    println!("Enforces locked/unlocked state with zero-friction in-memory access.\n");

    let temp_dir = tempfile::tempdir()?;
    let config_dir = temp_dir.path();

    let password = "master_vault_password";

    // =========================================================================
    // STEP 1: Initialize SettingsManager with Vault enabled
    // =========================================================================
    println!("📝 Step 1: Initialize SettingsManager with .with_vault_preset(Argon2Preset::Fast)");
    let manager = SettingsManager::builder("secure-app", "1.0.0")
        .with_config_dir(config_dir)
        .with_schema::<AppSettings>()
        .with_vault_preset(Argon2Preset::Fast) // Fast preset for quick demo/testing; Standard for production
        .build()?;

    println!("   Vault enabled: {}", manager.is_vault_enabled());
    println!("   Initial locked state: {}\n", manager.is_locked());

    // Encrypt the existing configuration with a new vault
    println!("📝 Step 2: Enable vault and save sensitive configuration");
    manager.enable_vault(password)?;
    assert!(!manager.is_locked());

    manager.save_setting("api", "endpoint", &json!("https://api.secure.internal"))?;
    manager.save_setting("api", "rate_limit", &json!(100.0))?;
    println!("   ✅ Saved 'api.endpoint' and 'api.rate_limit'\n");

    // =========================================================================
    // STEP 3: Register and use Sub-Settings under the Vault
    // =========================================================================
    println!("📝 Step 3: Register Sub-Settings with Vault inheritance");
    let remotes_config = SubSettingsConfig::new("remotes");
    manager.register_sub_settings(remotes_config)?;
    let remotes = manager.sub_settings("remotes")?;

    let tokens_config = SubSettingsConfig::singlefile("tokens");
    manager.register_sub_settings(tokens_config)?;
    let tokens = manager.sub_settings("tokens")?;

    println!("   Saving entities into 'remotes' (MultiFile) and 'tokens' (SingleFile)...");
    remotes.set(
        "production_s3",
        &json!({
            "provider": "s3",
            "bucket": "customer-assets-vault",
            "access_key": "AKIA_PRODUCTION_KEY"
        }),
    )?;

    tokens.set(
        "oauth_github",
        &json!({
            "token": "ghp_secret_access_token_9999",
            "expires_in": 3600
        }),
    )?;
    println!("   ✅ Saved 'remotes/production_s3' and 'tokens/oauth_github'\n");

    // =========================================================================
    // STEP 4: Inspect raw files on disk (Encrypted Envelopes)
    // =========================================================================
    println!("📝 Step 4: Inspect raw files on disk");
    let settings_file = config_dir.join("settings.json");
    let raw_settings = std::fs::read_to_string(&settings_file)?;
    println!(
        "   Main settings envelope preview:\n   {}",
        raw_settings.trim()
    );
    assert!(raw_settings.contains("\"__rcman_vault__\": 1"));
    assert!(raw_settings.contains("\"algorithm\": \"aes-256-gcm+argon2id\""));
    assert!(!raw_settings.contains("https://api.secure.internal"));

    let remote_file = config_dir.join("remotes").join("production_s3.json");
    let raw_remote = std::fs::read_to_string(&remote_file)?;
    println!(
        "\n   Sub-settings (MultiFile) envelope preview:\n   {}",
        raw_remote.trim()
    );
    assert!(raw_remote.contains("\"__rcman_vault__\": 1"));
    assert!(!raw_remote.contains("AKIA_PRODUCTION_KEY"));

    let tokens_file = config_dir.join("tokens.json");
    let raw_tokens = std::fs::read_to_string(&tokens_file)?;
    println!(
        "\n   Sub-settings (SingleFile) envelope preview:\n   {}",
        raw_tokens.trim()
    );
    assert!(raw_tokens.contains("\"__rcman_vault__\": 1"));
    assert!(!raw_tokens.contains("ghp_secret_access_token_9999"));

    println!("\n   🔒 Verified: Main settings and all sub-settings are fully encrypted at rest!\n");

    // =========================================================================
    // STEP 5: Simulate application reboot & verify locked barriers
    // =========================================================================
    println!("📝 Step 5: Simulate application reboot");
    drop(remotes);
    drop(tokens);
    drop(manager);

    let reloaded_manager = SettingsManager::builder("secure-app", "1.0.0")
        .with_config_dir(config_dir)
        .with_schema::<AppSettings>()
        .with_vault()
        .build()?;

    reloaded_manager.register_sub_settings(SubSettingsConfig::new("remotes"))?;
    reloaded_manager.register_sub_settings(SubSettingsConfig::singlefile("tokens"))?;
    let reloaded_remotes = reloaded_manager.sub_settings("remotes")?;
    let reloaded_tokens = reloaded_manager.sub_settings("tokens")?;

    println!(
        "   Reloaded manager is_locked(): {}",
        reloaded_manager.is_locked()
    );
    assert!(reloaded_manager.is_locked());
    assert!(reloaded_remotes.is_locked());
    assert!(reloaded_tokens.is_locked());

    // Main settings access blocked while locked
    print!("   Attempting read main settings while locked... ");
    match reloaded_manager.metadata() {
        Err(Error::ConfigLocked) => println!("🛡️ Blocked with Error::ConfigLocked!"),
        other => panic!("Expected ConfigLocked, got: {:?}", other),
    }

    // Sub-settings access blocked while locked
    print!("   Attempting read 'remotes' sub-settings while locked... ");
    match reloaded_remotes.get::<serde_json::Value>("production_s3") {
        Err(Error::ConfigLocked) => println!("🛡️ Blocked with Error::ConfigLocked!"),
        other => panic!("Expected ConfigLocked, got: {:?}", other),
    }

    print!("   Attempting read 'tokens' sub-settings while locked... ");
    match reloaded_tokens.get::<serde_json::Value>("oauth_github") {
        Err(Error::ConfigLocked) => println!("🛡️ Blocked with Error::ConfigLocked!"),
        other => panic!("Expected ConfigLocked, got: {:?}", other),
    }

    // Unlock with correct password
    println!("\n   Unlocking manager with master password...");
    reloaded_manager.unlock(password)?;
    assert!(!reloaded_manager.is_locked());
    assert!(!reloaded_remotes.is_locked());
    assert!(!reloaded_tokens.is_locked());
    println!("   ✅ Successfully unlocked!");

    let remote_val: serde_json::Value = reloaded_remotes.get("production_s3")?;
    println!(
        "   Decrypted remote key: {}",
        remote_val["access_key"].as_str().unwrap_or_default()
    );

    let token_val: serde_json::Value = reloaded_tokens.get("oauth_github")?;
    println!(
        "   Decrypted oauth token: {}",
        token_val["token"].as_str().unwrap_or_default()
    );

    // =========================================================================
    // STEP 6: Rotate master password with sub-settings re-encryption
    // =========================================================================
    println!("\n📝 Step 6: Master password rotation");
    let new_password = "new_ultra_secure_password_2026";
    reloaded_manager.change_vault_password(password, new_password)?;
    println!("   ✅ Master password rotated!");

    // Verify disk envelopes re-encrypted with new salt and ciphertext
    let re_encrypted_remote = std::fs::read_to_string(&remote_file)?;
    assert_ne!(raw_remote, re_encrypted_remote);
    assert!(!re_encrypted_remote.contains("AKIA_PRODUCTION_KEY"));

    // =========================================================================
    // STEP 7: Lock on demand
    // =========================================================================
    println!("\n📝 Step 7: Lock on demand (e.g. app backgrounded)");
    reloaded_manager.lock()?;
    assert!(reloaded_manager.is_locked());
    assert!(reloaded_remotes.is_locked());
    println!("   🔒 Re-locked: RAM keys scrubbed.");

    println!("\n🎉 Vault & Sub-Settings demo completed successfully!");
    Ok(())
}
