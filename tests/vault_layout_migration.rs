//! Enabling profiles on stores that already hold vault-encrypted flat data.
//!
//! The ciphertext is bound to its file path, so the migration must re-encrypt
//! instead of moving files, and it needs the vault key. A locked vault therefore
//! starts normally and finishes the migration on unlock.
#![cfg(all(feature = "vault", feature = "profiles"))]

use rcman::{Argon2Preset, Error, SettingsManager, SubSettingsConfig};
use serde_json::{Value, json};
use std::path::Path;

const PASSWORD: &str = "password";

fn builder(dir: &Path) -> rcman::SettingsManagerBuilder {
    SettingsManager::builder("layout", "1")
        .with_config_dir(dir)
        .with_vault_preset(Argon2Preset::Fast)
}

/// A vault-encrypted install from before profiles were enabled.
fn legacy_install(dir: &Path) {
    let manager = builder(dir)
        .with_vault_password(PASSWORD)
        .with_sub_settings(SubSettingsConfig::singlefile("quick_runs"))
        .with_sub_settings(SubSettingsConfig::new("remotes"))
        .build()
        .unwrap();
    let quick_runs = manager.sub_settings("quick_runs").unwrap();
    quick_runs.set("one", &json!({"name": "first"})).unwrap();
    quick_runs.set("two", &json!({"name": "second"})).unwrap();
    let remotes = manager.sub_settings("remotes").unwrap();
    remotes.set("drive", &json!({"type": "drive"})).unwrap();
    assert!(dir.join("quick_runs.json").is_file());
    assert!(dir.join("remotes/drive.json").is_file());
}

fn profiled(dir: &Path) -> rcman::SettingsManagerBuilder {
    builder(dir)
        .with_sub_settings(SubSettingsConfig::singlefile("quick_runs").with_profiles())
        .with_sub_settings(SubSettingsConfig::new("remotes").with_profiles())
}

fn assert_migrated(manager: &SettingsManager) {
    let quick_runs = manager.sub_settings("quick_runs").unwrap();
    let mut names = quick_runs.list().unwrap();
    names.sort();
    assert_eq!(names, ["one", "two"]);
    assert_eq!(quick_runs.get_value("one").unwrap()["name"], "first");
    assert_eq!(quick_runs.profiles().unwrap().active().unwrap(), "default");

    let remotes = manager.sub_settings("remotes").unwrap();
    assert_eq!(remotes.get_value("drive").unwrap()["type"], "drive");
    assert_eq!(remotes.profiles().unwrap().active().unwrap(), "default");
}

fn assert_flat_files_gone(dir: &Path) {
    assert!(!dir.join("quick_runs.json").exists());
    assert!(!dir.join("remotes/drive.json").exists());
    assert!(
        dir.join("quick_runs/profiles/default/quick_runs.json")
            .is_file()
    );
    assert!(dir.join("remotes/profiles/default/drive.json").is_file());
}

fn is_encrypted(path: &Path) -> bool {
    let value: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    value.get("__rcman_vault__").is_some()
}

#[test]
fn unlocked_startup_re_encrypts_flat_data_into_the_default_profile() {
    let dir = tempfile::tempdir().unwrap();
    legacy_install(dir.path());

    let manager = profiled(dir.path())
        .with_vault_password(PASSWORD)
        .build()
        .unwrap();

    assert_migrated(&manager);
    assert_flat_files_gone(dir.path());
    assert!(is_encrypted(
        &dir.path()
            .join("quick_runs/profiles/default/quick_runs.json")
    ));
    assert!(is_encrypted(
        &dir.path().join("remotes/profiles/default/drive.json")
    ));
}

#[test]
fn locked_startup_succeeds_and_unlock_finishes_the_migration() {
    let dir = tempfile::tempdir().unwrap();
    legacy_install(dir.path());

    let manager = profiled(dir.path()).build().unwrap();
    let quick_runs = manager.sub_settings("quick_runs").unwrap();
    assert!(quick_runs.get_value("one").unwrap_err().is_locked());
    // Nothing is touched while the key is unavailable.
    assert!(dir.path().join("quick_runs.json").is_file());
    assert!(dir.path().join("remotes/drive.json").is_file());

    manager.unlock(PASSWORD).unwrap();

    assert_migrated(&manager);
    assert_flat_files_gone(dir.path());
}

#[test]
fn a_wrong_password_leaves_the_flat_data_untouched() {
    let dir = tempfile::tempdir().unwrap();
    legacy_install(dir.path());
    let original = std::fs::read(dir.path().join("quick_runs.json")).unwrap();

    let manager = profiled(dir.path()).build().unwrap();
    assert!(manager.unlock("wrong").is_err());

    assert_eq!(
        std::fs::read(dir.path().join("quick_runs.json")).unwrap(),
        original
    );
    assert!(!dir.path().join("quick_runs/.profiles.json").exists());

    manager.unlock(PASSWORD).unwrap();
    assert_migrated(&manager);
}

#[test]
fn the_migration_survives_restarts_before_and_after_unlock() {
    let dir = tempfile::tempdir().unwrap();
    legacy_install(dir.path());

    drop(profiled(dir.path()).build().unwrap());
    let manager = profiled(dir.path()).build().unwrap();
    manager.unlock(PASSWORD).unwrap();
    drop(manager);

    let manager = profiled(dir.path()).build().unwrap();
    manager.unlock(PASSWORD).unwrap();
    assert_migrated(&manager);
    assert_flat_files_gone(dir.path());
}

#[test]
fn migrated_data_is_writable_and_a_second_unlock_does_not_repeat_the_migration() {
    let dir = tempfile::tempdir().unwrap();
    legacy_install(dir.path());

    let manager = profiled(dir.path()).build().unwrap();
    manager.unlock(PASSWORD).unwrap();
    let quick_runs = manager.sub_settings("quick_runs").unwrap();
    quick_runs.set("three", &json!({"name": "third"})).unwrap();

    manager.lock().unwrap();
    manager.unlock(PASSWORD).unwrap();

    assert_eq!(quick_runs.get_value("three").unwrap()["name"], "third");
    assert_eq!(quick_runs.get_value("one").unwrap()["name"], "first");
}

#[test]
fn an_interrupted_migration_resumes_without_losing_the_flat_data() {
    let dir = tempfile::tempdir().unwrap();
    legacy_install(dir.path());
    let flat = [
        (
            "quick_runs.json",
            std::fs::read(dir.path().join("quick_runs.json")).unwrap(),
        ),
        (
            "remotes/drive.json",
            std::fs::read(dir.path().join("remotes/drive.json")).unwrap(),
        ),
    ];
    drop(
        profiled(dir.path())
            .with_vault_password(PASSWORD)
            .build()
            .unwrap(),
    );
    // A crash after the copy but before the flat data was removed leaves both
    // layouts on disk and no manifest.
    for (path, bytes) in &flat {
        std::fs::write(dir.path().join(path), bytes).unwrap();
    }
    std::fs::remove_file(dir.path().join("quick_runs/.profiles.json")).unwrap();
    std::fs::remove_file(dir.path().join("remotes/.profiles.json")).unwrap();

    let manager = profiled(dir.path()).build().unwrap();
    manager.unlock(PASSWORD).unwrap();

    assert_migrated(&manager);
    assert_flat_files_gone(dir.path());
}

#[test]
fn a_custom_migrator_cannot_move_encrypted_files() {
    let dir = tempfile::tempdir().unwrap();
    legacy_install(dir.path());

    let result = builder(dir.path())
        .with_vault_password(PASSWORD)
        .with_sub_settings(
            SubSettingsConfig::singlefile("quick_runs")
                .with_profiles()
                .with_profile_migrator(rcman::ProfileMigrator::Custom(std::sync::Arc::new(|_| {
                    Ok(())
                }))),
        )
        .build();

    assert!(matches!(result, Err(Error::Vault(_))));
    assert!(dir.path().join("quick_runs.json").is_file());
}

#[test]
fn profiles_cannot_change_while_the_migration_is_pending() {
    let dir = tempfile::tempdir().unwrap();
    legacy_install(dir.path());

    let manager = profiled(dir.path()).build().unwrap();
    for section in ["quick_runs", "remotes"] {
        let profiles_owner = manager.sub_settings(section).unwrap();
        let profiles = profiles_owner.profiles().unwrap();
        assert!(profiles.create("other").unwrap_err().is_locked());
        assert!(profiles.delete("default").unwrap_err().is_locked());
        assert!(!dir.path().join(section).join(".profiles.json").exists());
        assert!(!dir.path().join(section).join("profiles/other").exists());
    }

    manager.unlock(PASSWORD).unwrap();

    assert_migrated(&manager);
    let quick_runs = manager.sub_settings("quick_runs").unwrap();
    quick_runs.profiles().unwrap().create("other").unwrap();
    quick_runs.switch_profile("other").unwrap();
    assert!(quick_runs.list().unwrap().is_empty());
}

#[test]
fn plaintext_flat_data_migrates_before_a_new_vault_encrypts_it() {
    let dir = tempfile::tempdir().unwrap();
    let legacy = builder(dir.path())
        .with_sub_settings(SubSettingsConfig::singlefile("quick_runs"))
        .build()
        .unwrap();
    let quick_runs = legacy.sub_settings("quick_runs").unwrap();
    quick_runs.set("one", &json!({"name": "first"})).unwrap();
    drop(quick_runs);
    drop(legacy);

    let manager = builder(dir.path())
        .with_vault_password(PASSWORD)
        .with_sub_settings(SubSettingsConfig::singlefile("quick_runs").with_profiles())
        .build()
        .unwrap();

    let quick_runs = manager.sub_settings("quick_runs").unwrap();
    assert_eq!(quick_runs.get_value("one").unwrap()["name"], "first");
    assert!(!dir.path().join("quick_runs.json").exists());
    assert!(is_encrypted(
        &dir.path()
            .join("quick_runs/profiles/default/quick_runs.json")
    ));
}
