//! Integration tests for rcman configuration locking and vault functionality.

#![cfg(feature = "vault")]

mod common;

use common::TestSettings;
use rcman::vault::{Argon2Preset, VaultEvent, is_vault_content};
use rcman::{Error, SettingsConfig, SettingsManager, SubSettingsConfig};
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;

#[test]
fn test_vault_encrypt_and_decrypt_settings() {
    let temp = TempDir::new().unwrap();
    let config = SettingsConfig::builder("vault-app", "1.0.0")
        .with_config_dir(temp.path())
        .with_schema::<TestSettings>()
        .with_vault()
        .with_vault_password("master_password_123")
        .build();

    let manager = SettingsManager::new(config).unwrap();
    assert!(manager.is_vault_enabled());
    assert!(!manager.is_locked());

    // Save a setting
    manager
        .save_setting("ui", "theme", &json!("light"))
        .unwrap();

    // Verify on-disk file exists and is encrypted in vault envelope format
    let file_path = temp.path().join("settings.json");
    assert!(file_path.exists());
    let raw_content = std::fs::read_to_string(&file_path).unwrap();
    assert!(
        is_vault_content(&raw_content),
        "Expected file to contain vault envelope marker"
    );
    assert!(!raw_content.contains("light"));

    // Verify read works transparently
    let settings = manager.get_all().unwrap();
    assert_eq!(settings.ui.theme, "light");
}

#[test]
fn test_vault_lock_lifecycle() {
    let temp = TempDir::new().unwrap();
    let config = SettingsConfig::builder("vault-app", "1.0.0")
        .with_config_dir(temp.path())
        .with_schema::<TestSettings>()
        .with_vault()
        .with_vault_password("correct_pass")
        .build();

    let manager = SettingsManager::new(config).unwrap();
    manager
        .save_setting("ui", "theme", &json!("light"))
        .unwrap();

    // Lock manager
    manager.lock().unwrap();
    assert!(manager.is_locked());

    // Reads and writes while locked must return ConfigLocked
    let read_err = manager.get_all().unwrap_err();
    assert!(read_err.is_locked());

    let write_err = manager
        .save_setting("ui", "theme", &json!("dark"))
        .unwrap_err();
    assert!(write_err.is_locked());

    // Unlocking with invalid password must fail and remain locked
    let bad_unlock = manager.unlock("wrong_pass").unwrap_err();
    assert!(matches!(bad_unlock, Error::InvalidPassword));
    assert!(manager.is_locked());

    // Unlocking with correct password succeeds
    manager.unlock("correct_pass").unwrap();
    assert!(!manager.is_locked());

    // Operations succeed again
    let settings = manager.get_all().unwrap();
    assert_eq!(settings.ui.theme, "light");
}

#[test]
fn test_vault_fresh_boot_locked() {
    let temp = TempDir::new().unwrap();

    // Session 1: Create vault and save setting
    {
        let config = SettingsConfig::builder("vault-app", "1.0.0")
            .with_config_dir(temp.path())
            .with_schema::<TestSettings>()
            .with_vault()
            .with_vault_password("session_key")
            .build();

        let manager = SettingsManager::new(config).unwrap();
        manager
            .save_setting("ui", "theme", &json!("light"))
            .unwrap();
    }

    // Session 2: Boot without password - must detect vault and boot locked
    {
        let config = SettingsConfig::builder("vault-app", "1.0.0")
            .with_config_dir(temp.path())
            .with_schema::<TestSettings>()
            .build();

        let manager = SettingsManager::new(config).unwrap();
        assert!(manager.is_vault_enabled());
        assert!(manager.is_locked());

        // Unlocking with password restores access
        manager.unlock("session_key").unwrap();
        assert!(!manager.is_locked());
        let settings = manager.get_all().unwrap();
        assert_eq!(settings.ui.theme, "light");
    }
}

#[test]
fn test_vault_change_password() {
    let temp = TempDir::new().unwrap();
    let config = SettingsConfig::builder("vault-app", "1.0.0")
        .with_config_dir(temp.path())
        .with_schema::<TestSettings>()
        .with_vault()
        .with_vault_password("old_pass")
        .build();

    let manager = SettingsManager::new(config).unwrap();
    manager
        .save_setting("ui", "theme", &json!("light"))
        .unwrap();

    // Wrong old password fails
    let err = manager
        .change_vault_password("wrong_old", "new_pass")
        .unwrap_err();
    assert!(matches!(err, Error::InvalidPassword));

    // Correct change succeeds
    manager
        .change_vault_password("old_pass", "new_pass")
        .unwrap();

    // Lock and verify new password works while old fails
    manager.lock().unwrap();
    assert!(manager.is_locked());

    let old_attempt = manager.unlock("old_pass").unwrap_err();
    assert!(matches!(old_attempt, Error::InvalidPassword));

    manager.unlock("new_pass").unwrap();
    assert!(!manager.is_locked());
    assert_eq!(manager.get_all().unwrap().ui.theme, "light");

    // Lock and test password rotation while locked
    manager.lock_vault().unwrap();
    assert!(manager.is_locked());

    // Wrong old password while locked fails
    let err = manager
        .change_vault_password("wrong_attempt", "third_pass")
        .unwrap_err();
    assert!(matches!(err, Error::InvalidPassword));

    // Correct old password while locked unlocks and rotates
    manager
        .change_vault_password("new_pass", "third_pass")
        .unwrap();
    assert!(!manager.is_locked());
    assert_eq!(manager.get_all().unwrap().ui.theme, "light");
}

#[test]
fn test_vault_enable_and_disable_at_runtime() {
    let temp = TempDir::new().unwrap();
    let config = SettingsConfig::builder("vault-app", "1.0.0")
        .with_config_dir(temp.path())
        .with_schema::<TestSettings>()
        .build();

    let manager = SettingsManager::new(config).unwrap();
    manager
        .save_setting("ui", "theme", &json!("light"))
        .unwrap();

    let file_path = temp.path().join("settings.json");
    let plain_content = std::fs::read_to_string(&file_path).unwrap();
    assert!(!is_vault_content(&plain_content));

    // Enable vault at runtime
    manager.enable_vault("vault_pwd_123").unwrap();
    assert!(manager.is_vault_enabled());
    assert!(!manager.is_locked());

    let encrypted_content = std::fs::read_to_string(&file_path).unwrap();
    assert!(is_vault_content(&encrypted_content));

    // Disable vault at runtime
    let bad_disable = manager.disable_vault("wrong").unwrap_err();
    assert!(matches!(bad_disable, Error::InvalidPassword));

    manager.disable_vault("vault_pwd_123").unwrap();
    assert!(!manager.is_vault_enabled());

    let decrypted_content = std::fs::read_to_string(&file_path).unwrap();
    assert!(!is_vault_content(&decrypted_content));
    assert_eq!(manager.get_all().unwrap().ui.theme, "light");
}

#[test]
fn test_vault_inactivity_auto_lock() {
    let temp = TempDir::new().unwrap();
    let config = SettingsConfig::builder("vault-app", "1.0.0")
        .with_config_dir(temp.path())
        .with_schema::<TestSettings>()
        .with_vault()
        .with_vault_preset(Argon2Preset::Fast)
        .with_vault_password("timeout_key")
        .with_vault_lock_timeout(Duration::from_millis(150))
        .build();

    let manager = SettingsManager::new(config).unwrap();
    assert!(!manager.is_locked());

    manager
        .save_setting("ui", "theme", &json!("light"))
        .unwrap();
    assert!(!manager.is_locked());

    // Sleep longer than timeout
    std::thread::sleep(Duration::from_millis(220));

    // Must have auto-locked
    assert!(manager.is_locked());
    assert!(manager.get_all().unwrap_err().is_locked());

    // Unlocking resets the inactivity clock
    manager.unlock("timeout_key").unwrap();
    assert!(!manager.is_locked());
    assert_eq!(manager.get_all().unwrap().ui.theme, "light");
}

#[test]
fn test_sub_settings_vault_inheritance() {
    let temp = TempDir::new().unwrap();
    let config = SettingsConfig::builder("vault-app", "1.0.0")
        .with_config_dir(temp.path())
        .with_schema::<TestSettings>()
        .with_vault()
        .with_vault_password("inherit_pwd")
        .build();

    let manager = SettingsManager::new(config).unwrap();
    let sub_config = SubSettingsConfig::new("remotes");
    manager.register_sub_settings(sub_config).unwrap();

    let remotes = manager.sub_settings("remotes").unwrap();
    assert!(!remotes.is_locked());

    remotes.set("drive", &json!({"type": "gdrive"})).unwrap();

    // Verify sub-settings file on disk is encrypted
    let sub_file = temp.path().join("remotes").join("drive.json");
    assert!(sub_file.exists());
    let raw = std::fs::read_to_string(&sub_file).unwrap();
    assert!(is_vault_content(&raw));

    // Lock manager -> sub-settings also locks
    manager.lock().unwrap();
    assert!(remotes.is_locked());

    assert!(
        remotes
            .get::<serde_json::Value>("drive")
            .unwrap_err()
            .is_locked()
    );
    assert!(
        remotes
            .set("s3", &json!({"type": "s3"}))
            .unwrap_err()
            .is_locked()
    );

    // Unlock manager -> sub-settings also unlocks
    manager.unlock("inherit_pwd").unwrap();
    assert!(!remotes.is_locked());

    let val = remotes.get::<serde_json::Value>("drive").unwrap();
    assert_eq!(val, json!({"type": "gdrive"}));
}

#[cfg(feature = "sqlite")]
#[test]
fn test_sub_settings_table_vault_inheritance() {
    let temp = TempDir::new().unwrap();
    let config = SettingsConfig::builder("vault-sqlite-app", "1.0.0")
        .with_config_dir(temp.path())
        .with_schema::<TestSettings>()
        .with_vault()
        .with_vault_password("table_pwd")
        .build();

    let manager = SettingsManager::new(config).unwrap();
    let sub_config = SubSettingsConfig::table("connections");
    manager.register_sub_settings(sub_config).unwrap();

    let conn = manager.sub_settings("connections").unwrap();
    assert!(!conn.is_locked());

    conn.set("primary", &json!({"host": "127.0.0.1", "port": 5432}))
        .unwrap();

    // Lock manager -> sub-settings also locks
    manager.lock().unwrap();
    assert!(conn.is_locked());
    assert!(
        conn.get::<serde_json::Value>("primary")
            .unwrap_err()
            .is_locked()
    );
    assert!(
        conn.set("secondary", &json!({"host": "10.0.0.1"}))
            .unwrap_err()
            .is_locked()
    );

    // Unlock manager -> sub-settings also unlocks
    manager.unlock("table_pwd").unwrap();
    assert!(!conn.is_locked());
    let val = conn.get::<serde_json::Value>("primary").unwrap();
    assert_eq!(val, json!({"host": "127.0.0.1", "port": 5432}));
}

#[cfg(feature = "backup")]
#[test]
fn test_vault_blocks_backup_when_locked() {
    let temp = TempDir::new().unwrap();
    let config = SettingsConfig::builder("vault-backup-app", "1.0.0")
        .with_config_dir(temp.path())
        .with_schema::<TestSettings>()
        .with_vault()
        .with_vault_password("backup_pwd")
        .build();

    let manager = SettingsManager::new(config).unwrap();
    manager.lock().unwrap();

    let backup_mgr = manager.backup();
    let options = rcman::BackupOptions::new();
    let err = backup_mgr.create(&options).unwrap_err();
    assert!(err.is_locked());
}

#[cfg(feature = "profiles")]
#[test]
fn test_vault_blocks_profile_switching_when_locked() {
    let temp = TempDir::new().unwrap();
    let config = SettingsConfig::builder("vault-profiles-app", "1.0.0")
        .with_config_dir(temp.path())
        .with_schema::<TestSettings>()
        .with_profiles()
        .with_vault()
        .with_vault_password("prof_pwd")
        .build();

    let manager = SettingsManager::new(config).unwrap();
    manager.create_profile("work").unwrap();

    manager.lock().unwrap();
    assert!(manager.switch_profile("work").unwrap_err().is_locked());
    assert!(manager.create_profile("home").unwrap_err().is_locked());

    manager.unlock("prof_pwd").unwrap();
    assert!(manager.switch_profile("work").is_ok());
}

#[test]
fn test_sub_settings_reencryption_on_vault_enable_disable() {
    let temp = TempDir::new().unwrap();
    let config = SettingsConfig::builder("sub-reenc-app", "1.0.0")
        .with_config_dir(temp.path())
        .with_schema::<TestSettings>()
        .build();

    let manager = SettingsManager::new(config).unwrap();
    let sub_config = SubSettingsConfig::new("items");
    manager.register_sub_settings(sub_config).unwrap();

    let items = manager.sub_settings("items").unwrap();
    items
        .set("item1", &json!({"secret_data": "plain_text_value"}))
        .unwrap();

    let item_file = temp.path().join("items").join("item1.json");
    let initial_content = std::fs::read_to_string(&item_file).unwrap();
    assert!(!is_vault_content(&initial_content));
    assert!(initial_content.contains("plain_text_value"));

    // Enable vault -> existing sub-setting item must be re-encrypted!
    manager.enable_vault("dynamic_pass").unwrap();
    let enc_content = std::fs::read_to_string(&item_file).unwrap();
    assert!(is_vault_content(&enc_content));
    assert!(!enc_content.contains("plain_text_value"));

    // Read back through sub-settings
    let val = items.get::<serde_json::Value>("item1").unwrap();
    assert_eq!(val, json!({"secret_data": "plain_text_value"}));

    // Disable vault -> existing sub-setting item must be decrypted!
    manager.disable_vault("dynamic_pass").unwrap();
    let dec_content = std::fs::read_to_string(&item_file).unwrap();
    assert!(!is_vault_content(&dec_content));
    assert!(dec_content.contains("plain_text_value"));
}

#[test]
fn test_vault_kdf_presets_and_envelope_detection() {
    let temp = TempDir::new().unwrap();

    // Session 1: Create vault using Fast preset
    {
        let config = SettingsConfig::builder("vault-preset-app", "1.0.0")
            .with_config_dir(temp.path())
            .with_schema::<TestSettings>()
            .with_vault_preset(Argon2Preset::Fast)
            .with_vault_password("preset_pwd")
            .build();

        let manager = SettingsManager::new(config).unwrap();
        manager
            .save_setting("ui", "theme", &json!("light"))
            .unwrap();

        // Verify on-disk envelope has kdf_params
        let file_path = temp.path().join("settings.json");
        let content = std::fs::read_to_string(&file_path).unwrap();
        let envelope: rcman::vault::VaultEnvelope = serde_json::from_str(&content).unwrap();
        assert_eq!(envelope.kdf_params, Some(Argon2Preset::Fast.params()));
    }

    // Session 2: Boot manager without explicit preset (defaults to Standard)
    // When unlocking, it must auto-detect Fast preset from the envelope and successfully unlock!
    {
        let config = SettingsConfig::builder("vault-preset-app", "1.0.0")
            .with_config_dir(temp.path())
            .with_schema::<TestSettings>()
            .with_vault()
            .build();

        let manager = SettingsManager::new(config).unwrap();
        assert!(manager.is_locked());

        // Unlock with password
        manager.unlock("preset_pwd").unwrap();
        assert!(!manager.is_locked());
        assert_eq!(manager.get_all().unwrap().ui.theme, "light");
    }
}

#[cfg(feature = "backup")]
#[test]
fn test_vault_backup_and_restore_roundtrip() {
    let temp_src = TempDir::new().unwrap();
    let temp_backup = TempDir::new().unwrap();
    let temp_dest = TempDir::new().unwrap();

    // Step 1: Initialize vaulted source manager with Fast preset for quick tests
    let src_config = SettingsConfig::builder("vault-backup-app", "1.0.0")
        .with_config_dir(temp_src.path())
        .with_schema::<TestSettings>()
        .with_vault_preset(Argon2Preset::Fast)
        .with_vault_password("src_vault_pwd")
        .build();

    let src_manager = SettingsManager::new(src_config).unwrap();
    src_manager
        .save_setting("ui", "theme", &json!("light"))
        .unwrap();

    // Register MultiFile and SingleFile sub-settings
    src_manager
        .register_sub_settings(SubSettingsConfig::new("remotes"))
        .unwrap();
    src_manager
        .register_sub_settings(SubSettingsConfig::singlefile("tokens"))
        .unwrap();

    let remotes = src_manager.sub_settings("remotes").unwrap();
    remotes
        .set(
            "my_gdrive",
            &json!({"type": "drive", "client_id": "cid123"}),
        )
        .unwrap();

    let tokens = src_manager.sub_settings("tokens").unwrap();
    tokens
        .set("github", &json!({"token": "gh_secret_token"}))
        .unwrap();

    // Verify source files are all encrypted envelopes on disk
    let src_settings_file = temp_src.path().join("settings.json");
    let src_remote_file = temp_src.path().join("remotes").join("my_gdrive.json");
    let src_tokens_file = temp_src.path().join("tokens.json");
    assert!(is_vault_content(
        &std::fs::read_to_string(&src_settings_file).unwrap()
    ));
    assert!(is_vault_content(
        &std::fs::read_to_string(&src_remote_file).unwrap()
    ));
    assert!(is_vault_content(
        &std::fs::read_to_string(&src_tokens_file).unwrap()
    ));

    // Step 2: Create a backup while unlocked
    let backup_mgr = src_manager.backup();
    let options = rcman::BackupOptions::new().output_dir(temp_backup.path());
    let backup_path = backup_mgr.create(&options).unwrap();
    assert!(backup_path.exists());

    // Step 3: Verify the inner backup archive contains decrypted settings (not vault envelopes)
    {
        let file = std::fs::File::open(&backup_path).unwrap();
        let mut outer_zip = zip::ZipArchive::new(file).unwrap();
        let mut data_zip_file = outer_zip.by_name("data.zip").unwrap();
        let mut data_bytes = Vec::new();
        std::io::Read::read_to_end(&mut data_zip_file, &mut data_bytes).unwrap();

        let mut inner_zip = zip::ZipArchive::new(std::io::Cursor::new(data_bytes)).unwrap();
        let mut inner_settings_file = inner_zip.by_name("settings.json").unwrap();
        let mut inner_content = String::new();
        std::io::Read::read_to_string(&mut inner_settings_file, &mut inner_content).unwrap();

        assert!(
            !is_vault_content(&inner_content),
            "Backup archive settings.json must contain decrypted data"
        );
        assert!(inner_content.contains("light"));
    }

    // Step 4: Initialize a NEW vaulted destination manager with its own vault password
    let dest_config = SettingsConfig::builder("vault-backup-app", "1.0.0")
        .with_config_dir(temp_dest.path())
        .with_schema::<TestSettings>()
        .with_vault_preset(Argon2Preset::Fast)
        .with_vault_password("dest_vault_pwd")
        .build();

    let dest_manager = SettingsManager::new(dest_config).unwrap();
    dest_manager
        .register_sub_settings(SubSettingsConfig::new("remotes"))
        .unwrap();
    dest_manager
        .register_sub_settings(SubSettingsConfig::singlefile("tokens"))
        .unwrap();

    // Step 5: Restore backup onto dest_manager
    let restore_mgr = dest_manager.backup();
    let restore_options = rcman::RestoreOptions::from_path(&backup_path).overwrite(true);
    let result = restore_mgr.restore(&restore_options).unwrap();
    assert!(!result.restored.is_empty());

    // Step 6: Verify restored files on disk are automatically encrypted with dest_manager's vault!
    let dest_settings_file = temp_dest.path().join("settings.json");
    let dest_remote_file = temp_dest.path().join("remotes").join("my_gdrive.json");
    let dest_tokens_file = temp_dest.path().join("tokens.json");

    assert!(dest_settings_file.exists());
    assert!(dest_remote_file.exists());
    assert!(dest_tokens_file.exists());

    let dest_raw_settings = std::fs::read_to_string(&dest_settings_file).unwrap();
    assert!(
        is_vault_content(&dest_raw_settings),
        "Restored main settings must be encrypted on disk"
    );
    assert!(!dest_raw_settings.contains("light"));

    let dest_raw_remote = std::fs::read_to_string(&dest_remote_file).unwrap();
    assert!(is_vault_content(&dest_raw_remote));
    assert!(!dest_raw_remote.contains("cid123"));

    let dest_raw_tokens = std::fs::read_to_string(&dest_tokens_file).unwrap();
    assert!(is_vault_content(&dest_raw_tokens));
    assert!(!dest_raw_tokens.contains("gh_secret_token"));

    // Step 7: Verify transparent reading while unlocked
    assert_eq!(dest_manager.get_all().unwrap().ui.theme, "light");
    let dest_remotes = dest_manager.sub_settings("remotes").unwrap();
    let remote_val: serde_json::Value = dest_remotes.get("my_gdrive").unwrap();
    assert_eq!(remote_val["client_id"], "cid123");

    let dest_tokens = dest_manager.sub_settings("tokens").unwrap();
    let token_val: serde_json::Value = dest_tokens.get("github").unwrap();
    assert_eq!(token_val["token"], "gh_secret_token");

    // Step 8: Lock dest_manager and verify locked access blocked
    dest_manager.lock().unwrap();
    assert!(dest_manager.is_locked());
    assert!(dest_manager.get_all().unwrap_err().is_locked());
    assert!(
        dest_remotes
            .get::<serde_json::Value>("my_gdrive")
            .unwrap_err()
            .is_locked()
    );
}

#[test]
#[cfg(feature = "profiles")]
fn test_vault_multi_profile_lifecycle() {
    let temp = TempDir::new().unwrap();
    let config = SettingsConfig::builder("multi-profile-vault", "1.0.0")
        .with_config_dir(temp.path())
        .with_schema::<TestSettings>()
        .with_profiles()
        .build();

    let manager = SettingsManager::new(config).unwrap();
    manager
        .register_sub_settings(SubSettingsConfig::new("remotes").with_profiles())
        .unwrap();

    // 1. Save settings in active "default" profile
    manager
        .save_setting("ui", "theme", &json!("light"))
        .unwrap();
    let remotes = manager.sub_settings("remotes").unwrap();
    remotes
        .set("gdrive", &json!({"client_id": "default_cid"}))
        .unwrap();

    // 2. Create and switch to "work" profile
    manager.create_profile("work").unwrap();
    manager.switch_profile("work").unwrap();

    manager
        .save_setting("ui", "theme", &json!("system"))
        .unwrap();
    remotes
        .set("gdrive", &json!({"client_id": "work_cid"}))
        .unwrap();

    // Switch back to "default"
    manager.switch_profile("default").unwrap();

    // Verify both profile files on disk exist and are currently plaintext
    let default_settings = temp
        .path()
        .join("profiles")
        .join("default")
        .join("settings.json");
    let work_settings = temp
        .path()
        .join("profiles")
        .join("work")
        .join("settings.json");
    assert!(default_settings.exists());
    assert!(work_settings.exists());
    assert!(!is_vault_content(
        &std::fs::read_to_string(&default_settings).unwrap()
    ));
    assert!(!is_vault_content(
        &std::fs::read_to_string(&work_settings).unwrap()
    ));

    // 3. Enable vault at runtime across all profiles
    manager
        .enable_vault_with_params("master_pwd_123", rcman::vault::Argon2Params::fast())
        .unwrap();

    // 4. Verify on-disk files for BOTH profiles are now encrypted envelopes
    let raw_default = std::fs::read_to_string(&default_settings).unwrap();
    let raw_work = std::fs::read_to_string(&work_settings).unwrap();
    assert!(
        is_vault_content(&raw_default),
        "Default profile must be encrypted"
    );
    assert!(
        is_vault_content(&raw_work),
        "Work profile must be encrypted"
    );
    assert!(!raw_default.contains("light"));
    assert!(!raw_work.contains("system"));

    // 5. Verify transparent reading across profiles while unlocked
    assert_eq!(manager.get_all().unwrap().ui.theme, "light");
    let default_remote: serde_json::Value = remotes.get("gdrive").unwrap();
    assert_eq!(default_remote["client_id"], "default_cid");

    manager.switch_profile("work").unwrap();
    assert_eq!(manager.get_all().unwrap().ui.theme, "system");
    let work_remote: serde_json::Value = remotes.get("gdrive").unwrap();
    assert_eq!(work_remote["client_id"], "work_cid");

    // 6. Rotate password across all profiles
    manager
        .change_vault_password("master_pwd_123", "new_pwd_456")
        .unwrap();

    // Verify reading works in work profile
    assert_eq!(manager.get_all().unwrap().ui.theme, "system");
    let work_remote2: serde_json::Value = remotes.get("gdrive").unwrap();
    assert_eq!(work_remote2["client_id"], "work_cid");

    // Switch to default profile and verify reading works
    manager.switch_profile("default").unwrap();
    assert_eq!(manager.get_all().unwrap().ui.theme, "light");
    let default_remote2: serde_json::Value = remotes.get("gdrive").unwrap();
    assert_eq!(default_remote2["client_id"], "default_cid");

    // 7. Lock and verify both profiles are protected
    manager.lock().unwrap();
    assert!(manager.is_locked());
    assert!(manager.get_all().unwrap_err().is_locked());
    assert!(manager.switch_profile("work").unwrap_err().is_locked());

    // 8. Unlock with new password
    manager.unlock("new_pwd_456").unwrap();
    assert!(!manager.is_locked());

    // 9. Disable vault across all profiles
    manager.disable_vault("new_pwd_456").unwrap();

    // Verify files on disk for BOTH profiles reverted to plaintext
    let final_default = std::fs::read_to_string(&default_settings).unwrap();
    let final_work = std::fs::read_to_string(&work_settings).unwrap();
    assert!(!is_vault_content(&final_default));
    assert!(!is_vault_content(&final_work));
    assert!(final_default.contains("light"));
    assert!(final_work.contains("system"));

    // Verify transparent access in both profiles
    assert_eq!(manager.get_all().unwrap().ui.theme, "light");
    manager.switch_profile("work").unwrap();
    assert_eq!(manager.get_all().unwrap().ui.theme, "system");
}

#[test]
fn test_vault_lifecycle_events() {
    let temp = TempDir::new().unwrap();
    let config = SettingsConfig::builder("events-app", "1.0.0")
        .with_config_dir(temp.path())
        .with_schema::<TestSettings>()
        .with_vault()
        .with_vault_preset(Argon2Preset::Fast)
        .with_vault_password("initial_pass")
        .build();

    let manager = SettingsManager::new(config).unwrap();

    let recorded_events = Arc::new(Mutex::new(Vec::new()));
    let events_clone = Arc::clone(&recorded_events);
    manager.events().on_vault_event(move |event| {
        events_clone.lock().unwrap().push(event);
    });

    let lock_count = Arc::new(AtomicUsize::new(0));
    let lock_count_clone = Arc::clone(&lock_count);
    manager.events().on_vault_lock(move || {
        lock_count_clone.fetch_add(1, Ordering::SeqCst);
    });

    let unlock_count = Arc::new(AtomicUsize::new(0));
    let unlock_count_clone = Arc::clone(&unlock_count);
    manager.events().on_vault_unlock(move || {
        unlock_count_clone.fetch_add(1, Ordering::SeqCst);
    });

    let (auto_lock_tx, auto_lock_rx) = std::sync::mpsc::channel();
    manager.events().on_vault_event(move |event| {
        if event == VaultEvent::AutoLocked {
            let _ = auto_lock_tx.send(());
        }
    });

    // 1. Lock vault explicitly
    manager.lock().unwrap();
    assert_eq!(lock_count.load(Ordering::SeqCst), 1);
    assert_eq!(unlock_count.load(Ordering::SeqCst), 0);
    assert_eq!(*recorded_events.lock().unwrap(), vec![VaultEvent::Locked]);

    // 2. Unlock vault
    manager.unlock("initial_pass").unwrap();
    assert_eq!(unlock_count.load(Ordering::SeqCst), 1);
    assert_eq!(
        *recorded_events.lock().unwrap(),
        vec![VaultEvent::Locked, VaultEvent::Unlocked]
    );

    // 3. Change password
    manager
        .change_vault_password("initial_pass", "new_pass_123")
        .unwrap();
    assert_eq!(
        *recorded_events.lock().unwrap(),
        vec![
            VaultEvent::Locked,
            VaultEvent::Unlocked,
            VaultEvent::PasswordChanged
        ]
    );

    // 4. Inactivity auto-lock
    manager
        .set_vault_lock_timeout(Some(Duration::from_millis(30)))
        .unwrap();
    auto_lock_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("auto-lock callbacks did not complete");
    assert!(manager.is_locked());
    assert_eq!(lock_count.load(Ordering::SeqCst), 2); // 1 manual + 1 auto-lock
    let history = recorded_events.lock().unwrap().clone();
    assert_eq!(
        history,
        vec![
            VaultEvent::Locked,
            VaultEvent::Unlocked,
            VaultEvent::PasswordChanged,
            VaultEvent::AutoLocked,
        ]
    );

    // 5. Unlock after auto-lock
    manager.unlock("new_pass_123").unwrap();
    manager.set_vault_lock_timeout(None).unwrap();
    assert_eq!(unlock_count.load(Ordering::SeqCst), 2);

    // 6. Disable vault
    manager.disable_vault("new_pass_123").unwrap();
    let history2 = recorded_events.lock().unwrap().clone();
    assert_eq!(history2.last(), Some(&VaultEvent::Disabled));

    // 7. Enable vault
    manager.enable_vault("re_enabled_pass").unwrap();
    let history3 = recorded_events.lock().unwrap().clone();
    assert_eq!(history3.last(), Some(&VaultEvent::Enabled));
}

#[test]
fn test_vault_password_verification() {
    let temp = TempDir::new().unwrap();
    let config = SettingsConfig::builder("vault-verify-app", "1.0.0")
        .with_config_dir(temp.path())
        .with_schema::<TestSettings>()
        .with_vault()
        .with_vault_password("correct_pass_123")
        .build();

    let manager = SettingsManager::new(config).unwrap();
    manager
        .save_setting("ui", "theme", &json!("light"))
        .unwrap();

    // 1. Verify while unlocked
    assert!(manager.verify_vault_password("correct_pass_123").unwrap());
    assert!(!manager.verify_vault_password("wrong_password").unwrap());
    assert!(!manager.is_locked()); // lock state was not mutated

    // 2. Verify while locked
    manager.lock().unwrap();
    assert!(manager.is_locked());

    assert!(manager.verify_vault_password("correct_pass_123").unwrap());
    assert!(!manager.verify_vault_password("wrong_password").unwrap());
    assert!(manager.is_locked()); // remains locked after verification
}

#[test]
fn test_vault_info_query() {
    let temp = TempDir::new().unwrap();
    let timeout = Duration::from_millis(150);
    let config = SettingsConfig::builder("vault-info-app", "1.0.0")
        .with_config_dir(temp.path())
        .with_schema::<TestSettings>()
        .with_vault()
        .with_vault_password("info_pass")
        .with_vault_lock_timeout(timeout)
        .build();

    let manager = SettingsManager::new(config).unwrap();
    let info = manager.vault_info().expect("VaultInfo should be present");

    assert!(info.enabled);
    assert!(!info.is_locked);
    assert_eq!(info.lock_timeout, Some(timeout));
    assert!(info.time_since_last_activity.is_some());

    // Touch vault refreshes activity
    manager.touch_vault().unwrap();

    // Lock and inspect info
    manager.lock().unwrap();
    let locked_info = manager.vault_info().unwrap();
    assert!(locked_info.is_locked);
    assert!(locked_info.time_since_last_activity.is_none());
}

#[test]
fn test_vault_runtime_lock_timeout_adjustment() {
    let temp = TempDir::new().unwrap();
    let config = SettingsConfig::builder("vault-timeout-app", "1.0.0")
        .with_config_dir(temp.path())
        .with_schema::<TestSettings>()
        .with_vault()
        .with_vault_preset(Argon2Preset::Fast)
        .with_vault_password("dyn_timeout_pass")
        .build();

    let manager = SettingsManager::new(config).unwrap();
    assert_eq!(manager.vault_lock_timeout(), None);

    // Set timeout at runtime
    let timeout = Duration::from_millis(150);
    manager.set_vault_lock_timeout(Some(timeout)).unwrap();
    assert_eq!(manager.vault_lock_timeout(), Some(timeout));

    manager
        .save_setting("ui", "theme", &json!("light"))
        .unwrap();

    // Wait past timeout
    std::thread::sleep(Duration::from_millis(220));
    assert!(manager.is_locked());

    // Unlock and remove timeout
    manager.unlock("dyn_timeout_pass").unwrap();
    assert!(!manager.is_locked());

    manager.set_vault_lock_timeout(None).unwrap();
    assert_eq!(manager.vault_lock_timeout(), None);

    std::thread::sleep(Duration::from_millis(150));
    assert!(!manager.is_locked()); // Remains unlocked
}

#[test]
fn test_vault_event_display() {
    assert_eq!(VaultEvent::Unlocked.to_string(), "unlocked");
    assert_eq!(VaultEvent::Locked.to_string(), "locked");
    assert_eq!(VaultEvent::AutoLocked.to_string(), "auto_locked");
    assert_eq!(VaultEvent::PasswordChanged.to_string(), "password_changed");
    assert_eq!(VaultEvent::Enabled.to_string(), "enabled");
    assert_eq!(VaultEvent::Disabled.to_string(), "disabled");
}

#[cfg(feature = "hot-reload")]
#[test]
fn test_vault_hot_reload_locked_coordination() {
    use rcman::{HotReloadConfig, HotReloadEvent, HotReloadRuntime};
    use std::sync::mpsc;

    let temp = TempDir::new().unwrap();
    let config = SettingsConfig::builder("vault-hot-reload-app", "1.0.0")
        .with_config_dir(temp.path())
        .with_schema::<TestSettings>()
        .with_vault()
        .with_vault_password("reload_pwd")
        .build();

    let manager = Arc::new(SettingsManager::new(config).unwrap());
    manager
        .save_setting("ui", "theme", &json!("light"))
        .unwrap();

    let (event_tx, event_rx) = mpsc::channel();
    let reload_config = HotReloadConfig {
        debounce_ms: 30,
        ..Default::default()
    };

    let _runtime = HotReloadRuntime::start(Arc::clone(&manager), reload_config, move |event| {
        let _ = event_tx.send(event);
    })
    .unwrap();

    // Lock manager
    manager.lock().unwrap();
    assert!(manager.is_locked());

    // External modification to file while locked
    // Re-encrypt a modified payload using a temporary manager with the same password
    {
        let helper_config = SettingsConfig::builder("vault-hot-reload-app", "1.0.0")
            .with_config_dir(temp.path())
            .with_schema::<TestSettings>()
            .with_vault()
            .with_vault_password("reload_pwd")
            .build();
        let helper = SettingsManager::new(helper_config).unwrap();
        helper
            .save_setting("ui", "theme", &json!("system"))
            .unwrap();
    }

    // Wait for event
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    let mut saw_skipped_locked = false;

    while std::time::Instant::now() < deadline {
        if let Ok(event) = event_rx.recv_timeout(Duration::from_millis(100))
            && matches!(event, HotReloadEvent::SkippedLocked { .. })
        {
            saw_skipped_locked = true;
            break;
        }
    }

    assert!(
        saw_skipped_locked,
        "Expected SkippedLocked event while locked"
    );

    // Unlocking must reload the updated settings seamlessly
    manager.unlock("reload_pwd").unwrap();
    assert_eq!(manager.get_all().unwrap().ui.theme, "system");
}

#[test]
fn test_vault_with_vault_without_password_on_plaintext_does_not_lock() {
    let temp = TempDir::new().unwrap();
    let config = SettingsConfig::builder("vault-plaintext-app", "1.0.0")
        .with_config_dir(temp.path())
        .with_schema::<TestSettings>()
        .with_vault()
        .build();

    let manager = SettingsManager::new(config).unwrap();
    assert!(!manager.is_vault_enabled());
    assert!(!manager.is_locked());

    // Settings can be saved and read normally in plaintext
    manager
        .save_setting("ui", "theme", &json!("light"))
        .unwrap();
    assert_eq!(manager.get_all().unwrap().ui.theme, "light");

    let file_path = temp.path().join("settings.json");
    let content = std::fs::read_to_string(&file_path).unwrap();
    assert!(!is_vault_content(&content));
}

#[test]
fn test_vault_active_auto_lock_watchdog_proactive_event() {
    let temp = TempDir::new().unwrap();
    let config = SettingsConfig::builder("vault-watchdog-app", "1.0.0")
        .with_config_dir(temp.path())
        .with_schema::<TestSettings>()
        .with_vault()
        .with_vault_password("watchdog_pwd")
        .with_vault_lock_timeout(Duration::from_millis(80))
        .build();

    let manager = SettingsManager::new(config).unwrap();
    let (tx, rx) = std::sync::mpsc::channel();

    manager.events().on_vault_event(move |event| {
        let _ = tx.send(event);
    });

    // Do NOT call manager.is_locked()!
    // The background watchdog must proactively detect inactivity and fire AutoLocked!
    let event = rx
        .recv_timeout(Duration::from_millis(600))
        .expect("Watchdog thread must proactively dispatch VaultEvent::AutoLocked without polling");

    assert_eq!(event, rcman::vault::VaultEvent::AutoLocked);
    assert!(manager.is_locked());
}

#[test]
fn test_vault_timeout_persisted_in_envelope_and_restored_on_reboot() {
    let temp = TempDir::new().unwrap();
    let timeout = Duration::from_millis(150);

    // Boot 1: Plaintext boot, runtime vault enable with timeout
    {
        let config = SettingsConfig::builder("vault-envelope-timeout-app", "1.0.0")
            .with_config_dir(temp.path())
            .with_schema::<TestSettings>()
            .with_vault()
            .build();
        let manager = SettingsManager::new(config).unwrap();
        manager.enable_vault("reboot_pass").unwrap();
        manager.set_vault_lock_timeout(Some(timeout)).unwrap();
        assert_eq!(manager.vault_lock_timeout(), Some(timeout));
    }

    // Boot 2: Restart without providing vault_lock_timeout in builder
    {
        let config = SettingsConfig::builder("vault-envelope-timeout-app", "1.0.0")
            .with_config_dir(temp.path())
            .with_schema::<TestSettings>()
            .with_vault()
            .build();
        let manager = SettingsManager::new(config).unwrap();
        assert!(manager.is_vault_enabled());
        assert!(manager.is_locked());
        // Timeout must have been restored from the on-disk envelope!
        assert_eq!(manager.vault_lock_timeout(), Some(timeout));
    }
}

#[test]
fn single_file_vault_migration_survives_rotation_and_restart() {
    let temp = TempDir::new().unwrap();
    let build = || {
        SettingsManager::builder("single-file-vault", "1.0")
            .with_config_dir(temp.path())
            .with_schema::<TestSettings>()
            .with_vault_preset(Argon2Preset::Fast)
            .with_sub_settings(SubSettingsConfig::singlefile("connections"))
            .build()
            .unwrap()
    };
    let manager = build();
    let sub = manager.sub_settings("connections").unwrap();
    sub.set("server", &json!({"host": "private.example"}))
        .unwrap();
    sub.set("_active", &json!("server")).unwrap();
    let path = temp.path().join("connections.json");

    manager.enable_vault("first").unwrap();
    let encrypted = std::fs::read_to_string(&path).unwrap();
    assert!(is_vault_content(&encrypted));
    assert!(!encrypted.contains("private.example"));

    manager.change_vault_password("first", "second").unwrap();
    assert_ne!(std::fs::read_to_string(&path).unwrap(), encrypted);
    drop(sub);
    drop(manager);

    let manager = build();
    assert!(manager.unlock("first").is_err());
    manager.unlock("second").unwrap();
    let sub = manager.sub_settings("connections").unwrap();
    assert_eq!(
        sub.get::<serde_json::Value>("_active").unwrap(),
        json!("server")
    );
    assert_eq!(
        sub.get::<serde_json::Value>("server").unwrap()["host"],
        "private.example"
    );
    manager.disable_vault("second").unwrap();
    assert!(!is_vault_content(&std::fs::read_to_string(&path).unwrap()));
    sub.invalidate_cache();
    assert_eq!(
        sub.get::<serde_json::Value>("_active").unwrap(),
        json!("server")
    );
}

#[test]
fn vault_migration_rejects_unreadable_sub_settings_before_encrypting() {
    let temp = TempDir::new().unwrap();
    let manager = SettingsManager::builder("broken-sub", "1.0")
        .with_config_dir(temp.path())
        .with_vault_preset(Argon2Preset::Fast)
        .with_sub_settings(SubSettingsConfig::new("remotes"))
        .build()
        .unwrap();
    let path = temp.path().join("remotes/broken.json");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, "{broken").unwrap();
    assert!(manager.enable_vault("password").is_err());
    assert!(!manager.is_vault_enabled());
    assert_eq!(std::fs::read_to_string(path).unwrap(), "{broken");
}

#[test]
fn empty_single_file_is_encrypted_during_vault_migration() {
    let temp = TempDir::new().unwrap();
    std::fs::write(temp.path().join("empty.json"), "{}").unwrap();
    let manager = SettingsManager::builder("empty-sub", "1.0")
        .with_config_dir(temp.path())
        .with_vault_preset(Argon2Preset::Fast)
        .with_sub_settings(SubSettingsConfig::singlefile("empty"))
        .build()
        .unwrap();
    manager.enable_vault("password").unwrap();
    assert!(is_vault_content(
        &std::fs::read_to_string(temp.path().join("empty.json")).unwrap()
    ));
    manager.change_vault_password("password", "new").unwrap();
    manager.disable_vault("new").unwrap();
    let value: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(temp.path().join("empty.json")).unwrap())
            .unwrap();
    assert_eq!(value, json!({}));
}

#[test]
fn startup_password_source_encrypts_existing_sub_settings_and_preserves_spaces() {
    let temp = TempDir::new().unwrap();
    let password_path = temp.path().join("password");
    std::fs::write(&password_path, " password with spaces \r\n").unwrap();
    std::fs::write(
        temp.path().join("connections.json"),
        r#"{"_active":"server"}"#,
    )
    .unwrap();
    let manager = SettingsManager::builder("startup-vault", "1.0")
        .with_config_dir(temp.path())
        .with_vault_preset(Argon2Preset::Fast)
        .with_vault_password_source(rcman::SecretPasswordSource::file(&password_path))
        .unwrap()
        .with_sub_settings(SubSettingsConfig::singlefile("connections"))
        .build()
        .unwrap();
    assert!(is_vault_content(
        &std::fs::read_to_string(temp.path().join("connections.json")).unwrap()
    ));
    manager.lock().unwrap();
    assert!(manager.unlock("password with spaces").is_err());
    manager.unlock(" password with spaces ").unwrap();
    assert_eq!(
        manager
            .sub_settings("connections")
            .unwrap()
            .get::<serde_json::Value>("_active")
            .unwrap(),
        json!("server")
    );
    assert!(
        SettingsManager::builder("missing", "1.0")
            .with_vault_password_source(rcman::SecretPasswordSource::file(
                temp.path().join("missing")
            ))
            .is_err()
    );
    assert!(
        SettingsManager::builder("empty", "1.0")
            .with_vault_password_source(rcman::SecretPasswordSource::provided(""))
            .is_err()
    );
}

#[test]
fn vault_migration_includes_entries_evicted_from_lru_cache() {
    let temp = TempDir::new().unwrap();
    let manager = SettingsManager::builder("lru-vault", "1.0")
        .with_config_dir(temp.path())
        .with_vault_preset(Argon2Preset::Fast)
        .with_sub_settings(
            SubSettingsConfig::new("remotes").with_cache(rcman::CacheStrategy::Lru(1)),
        )
        .build()
        .unwrap();
    let remotes = manager.sub_settings("remotes").unwrap();
    for name in ["one", "two", "three"] {
        remotes.set(name, &json!({"host": name})).unwrap();
    }
    manager.enable_vault("password").unwrap();
    manager.change_vault_password("password", "new").unwrap();
    for name in ["one", "two", "three"] {
        let content =
            std::fs::read_to_string(temp.path().join(format!("remotes/{name}.json"))).unwrap();
        assert!(is_vault_content(&content));
        assert_eq!(
            remotes.get::<serde_json::Value>(name).unwrap()["host"],
            name
        );
    }
}

#[cfg(feature = "profiles")]
#[test]
fn single_file_profiles_are_migrated_and_active_profile_is_preserved() {
    let temp = TempDir::new().unwrap();
    let manager = SettingsManager::builder("profiles-vault", "1.0")
        .with_config_dir(temp.path())
        .with_vault_preset(Argon2Preset::Fast)
        .with_sub_settings(SubSettingsConfig::singlefile("backend").with_profiles())
        .build()
        .unwrap();
    let backend = manager.sub_settings("backend").unwrap();
    let original = backend.profiles().unwrap().active().unwrap();
    backend.set("port", &json!(1234)).unwrap();
    backend.profiles().unwrap().create("work").unwrap();
    backend.switch_profile("work").unwrap();
    backend.set("port", &json!(5678)).unwrap();
    manager.enable_vault("password").unwrap();
    manager.change_vault_password("password", "new").unwrap();
    assert_eq!(backend.profiles().unwrap().active().unwrap(), "work");
    for (profile, port) in [(&original, 1234), (&String::from("work"), 5678)] {
        backend.switch_profile(profile).unwrap();
        assert_eq!(
            backend.get::<serde_json::Value>("port").unwrap(),
            json!(port)
        );
        let path = backend
            .profiles()
            .unwrap()
            .profile_path(profile)
            .join("backend.json");
        assert!(is_vault_content(&std::fs::read_to_string(path).unwrap()));
    }
    manager.disable_vault("new").unwrap();
    backend.switch_profile(&original).unwrap();
    assert_eq!(
        backend.get::<serde_json::Value>("port").unwrap(),
        json!(1234)
    );
}

#[test]
fn failed_vault_migrations_restore_previous_password_and_data() {
    use rcman::{JsonStorage, StorageBackend};
    use std::sync::atomic::AtomicBool;

    #[derive(Clone)]
    struct FailOnceStorage(Arc<AtomicBool>);

    impl StorageBackend for FailOnceStorage {
        fn extension(&self) -> &str {
            "json"
        }
        fn serialize<T: serde::Serialize>(&self, data: &T) -> rcman::Result<String> {
            JsonStorage::new().serialize(data)
        }
        fn deserialize<T: serde::de::DeserializeOwned>(&self, content: &str) -> rcman::Result<T> {
            JsonStorage::new().deserialize(content)
        }
        fn write<T: serde::Serialize>(
            &self,
            path: &std::path::Path,
            data: &T,
        ) -> rcman::Result<()> {
            if path.file_name().is_some_and(|name| name == "tokens.json")
                && self.0.swap(false, Ordering::SeqCst)
            {
                return Err(Error::FileWrite {
                    path: path.to_path_buf(),
                    source: std::io::Error::other("injected write failure"),
                });
            }
            JsonStorage::new().write(path, data)
        }
    }

    let temp = TempDir::new().unwrap();
    let fail = Arc::new(AtomicBool::new(false));
    let manager = SettingsManager::builder("rollback", "1.0")
        .with_config_dir(temp.path())
        .with_storage_instance(FailOnceStorage(Arc::clone(&fail)))
        .with_vault_preset(Argon2Preset::Fast)
        .with_sub_settings(SubSettingsConfig::singlefile("tokens"))
        .build()
        .unwrap();
    let tokens = manager.sub_settings("tokens").unwrap();
    tokens.set("token", &json!("secret")).unwrap();
    fail.store(true, Ordering::SeqCst);
    assert!(manager.enable_vault("old").is_err());
    assert!(!manager.is_vault_enabled());
    assert!(!is_vault_content(
        &std::fs::read_to_string(temp.path().join("tokens.json")).unwrap()
    ));

    manager.enable_vault("old").unwrap();
    fail.store(true, Ordering::SeqCst);
    assert!(manager.change_vault_password("old", "new").is_err());
    manager.lock().unwrap();
    assert!(manager.unlock("new").is_err());
    manager.unlock("old").unwrap();
    assert_eq!(
        tokens.get::<serde_json::Value>("token").unwrap(),
        json!("secret")
    );

    fail.store(true, Ordering::SeqCst);
    assert!(manager.disable_vault("old").is_err());
    assert!(manager.is_vault_enabled());
    manager.lock().unwrap();
    manager.unlock("old").unwrap();
    assert_eq!(
        tokens.get::<serde_json::Value>("token").unwrap(),
        json!("secret")
    );
}

#[test]
fn timeout_changes_require_unlock_and_zero_timeout_is_persisted() {
    let temp = TempDir::new().unwrap();
    let manager = SettingsManager::builder("timeout", "1.0")
        .with_config_dir(temp.path())
        .with_vault_preset(Argon2Preset::Fast)
        .with_vault_password("password")
        .build()
        .unwrap();
    manager.lock().unwrap();
    assert!(matches!(
        manager.set_vault_lock_timeout(Some(Duration::from_secs(10))),
        Err(Error::ConfigLocked)
    ));
    assert_eq!(manager.vault_lock_timeout(), None);
    manager.unlock("password").unwrap();
    manager
        .set_vault_lock_timeout(Some(Duration::ZERO))
        .unwrap();
    assert!(manager.is_locked());
    drop(manager);
    let manager = SettingsManager::builder("timeout", "1.0")
        .with_config_dir(temp.path())
        .build()
        .unwrap();
    assert_eq!(manager.vault_lock_timeout(), Some(Duration::ZERO));
}

#[test]
fn malformed_envelope_cannot_unlock_or_initialize_a_vault() {
    let temp = TempDir::new().unwrap();
    let manager = SettingsManager::builder("corrupt-envelope", "1.0")
        .with_config_dir(temp.path())
        .with_vault_preset(Argon2Preset::Fast)
        .with_vault_password("password")
        .build()
        .unwrap();
    manager.lock().unwrap();
    std::fs::write(
        temp.path().join("settings.json"),
        r#"{"__rcman_vault__":1}"#,
    )
    .unwrap();
    assert!(manager.unlock("anything").is_err());
    assert!(manager.is_locked());
    assert!(
        SettingsManager::builder("corrupt-envelope", "1.0")
            .with_config_dir(temp.path())
            .build()
            .is_err()
    );
}

#[cfg(feature = "profiles")]
#[test]
fn empty_profile_stays_encrypted_across_lock_and_restart() {
    let dir = TempDir::new().unwrap();
    let manager = SettingsManager::builder("empty-profile-vault", "1")
        .with_config_dir(dir.path())
        .with_schema::<TestSettings>()
        .with_profiles()
        .with_vault_preset(Argon2Preset::Fast)
        .with_vault_password("password")
        .build()
        .unwrap();
    manager.create_profile("empty").unwrap();
    manager.switch_profile("empty").unwrap();
    manager.lock().unwrap();
    assert!(matches!(
        manager.unlock("wrong"),
        Err(Error::InvalidPassword)
    ));
    manager.unlock("password").unwrap();
    drop(manager);

    let reopened = SettingsManager::builder("empty-profile-vault", "1")
        .with_config_dir(dir.path())
        .with_schema::<TestSettings>()
        .with_profiles()
        .with_vault()
        .build()
        .unwrap();
    assert!(reopened.is_vault_enabled());
    assert!(reopened.is_locked());
    reopened.unlock("password").unwrap();
    reopened
        .save_setting("ui", "theme", &json!("light"))
        .unwrap();
    let content = std::fs::read_to_string(dir.path().join("profiles/empty/settings.json")).unwrap();
    assert!(is_vault_content(&content));
}

#[cfg(feature = "profiles")]
#[test]
fn legacy_empty_active_profile_detects_existing_vault() {
    let dir = TempDir::new().unwrap();
    let manager = SettingsManager::builder("legacy-empty-vault", "1")
        .with_config_dir(dir.path())
        .with_profiles()
        .with_vault_preset(Argon2Preset::Fast)
        .with_vault_password("password")
        .build()
        .unwrap();
    manager.create_profile("empty").unwrap();
    // The old implementation switched the manifest without writing an envelope.
    manager.profiles().unwrap().switch("empty").unwrap();
    drop(manager);
    let reopened = SettingsManager::builder("legacy-empty-vault", "1")
        .with_config_dir(dir.path())
        .with_profiles()
        .with_vault()
        .build()
        .unwrap();
    assert!(reopened.is_vault_enabled());
    assert!(reopened.is_locked());
    assert!(matches!(
        reopened.unlock("wrong"),
        Err(Error::InvalidPassword)
    ));
    reopened.unlock("password").unwrap();
    reopened
        .change_vault_password("password", "rotated")
        .unwrap();
    reopened.lock().unwrap();
    reopened.unlock("rotated").unwrap();
}

#[test]
fn startup_password_is_consumed_before_exposing_manager() {
    let dir = TempDir::new().unwrap();
    let manager = SettingsManager::builder("startup-password", "1")
        .with_config_dir(dir.path())
        .with_vault_preset(Argon2Preset::Fast)
        .with_vault_password("password")
        .build()
        .unwrap();
    assert!(manager.config().vault_password.is_none());
    manager.lock().unwrap();
    assert!(manager.config().vault_password.is_none());
    assert!(matches!(
        manager.unlock("wrong"),
        Err(Error::InvalidPassword)
    ));
    manager.unlock("password").unwrap();
}
