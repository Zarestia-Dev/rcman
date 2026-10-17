//! Root metadata, enrollment policy, and shared vault identity regressions.
#![cfg(feature = "vault")]

use rcman::{Error, SettingsManager, SubSettingsConfig, vault::Argon2Preset};
use serde_json::{Value, json};
use std::path::Path;

fn create(root: &Path) -> SettingsManager {
    SettingsManager::builder("metadata", "1")
        .with_config_dir(root)
        .with_vault_password("shared-password")
        .with_vault_preset(Argon2Preset::Fast)
        .with_sub_settings(SubSettingsConfig::new("remotes"))
        .build()
        .unwrap()
}

#[test]
fn subsettings_only_vault_survives_rotation_restart_and_disable() {
    let dir = tempfile::tempdir().unwrap();
    let manager = create(dir.path());
    let path = dir.path().join(".rcman-vault.json");
    let original: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    manager
        .sub_settings("remotes")
        .unwrap()
        .set("primary", &json!({"host":"example"}))
        .unwrap();
    assert!(!dir.path().join("settings.json").exists());
    manager
        .change_vault_password("shared-password", "changed")
        .unwrap();
    let rotated: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(original["vault_id"], rotated["vault_id"]);
    assert_ne!(original["salt"], rotated["salt"]);
    drop(manager);
    let manager = SettingsManager::builder("metadata", "1")
        .with_config_dir(dir.path())
        .with_sub_settings(SubSettingsConfig::new("remotes"))
        .build()
        .unwrap();
    assert!(manager.is_locked());
    assert!(!manager.verify_vault_password("shared-password").unwrap());
    manager.unlock("changed").unwrap();
    assert_eq!(
        manager
            .sub_settings("remotes")
            .unwrap()
            .get_value("primary")
            .unwrap()["host"],
        "example"
    );
    manager.disable_vault("changed").unwrap();
    assert!(!path.exists());
    assert!(!dir.path().join("settings.json").exists());
    let value: Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("remotes/primary.json")).unwrap())
            .unwrap();
    assert_eq!(value, json!({"host":"example"}));
}

#[test]
fn empty_vault_validates_password_without_a_settings_file() {
    let dir = tempfile::tempdir().unwrap();
    let manager = create(dir.path());
    manager.lock().unwrap();
    assert!(matches!(
        manager.unlock("wrong"),
        Err(Error::VaultUnlockFailed)
    ));
    assert!(manager.is_locked());
    manager.unlock("shared-password").unwrap();
    assert!(!dir.path().join("settings.json").exists());
    drop(manager);
    let manager = SettingsManager::builder("metadata", "1")
        .with_config_dir(dir.path())
        .build()
        .unwrap();
    assert!(manager.is_locked());
    manager.unlock("shared-password").unwrap();
    manager.disable_vault("shared-password").unwrap();
    assert!(!dir.path().join(".rcman-vault.json").exists());
}

#[test]
fn startup_password_creates_once_and_opens_on_subsequent_starts() {
    let dir = tempfile::tempdir().unwrap();
    let manager = create(dir.path());
    let path = dir.path().join(".rcman-vault.json");
    let before = std::fs::read(&path).unwrap();
    assert!(
        SettingsManager::builder("metadata", "1")
            .with_config_dir(dir.path())
            .with_vault_password("different")
            .build()
            .is_err()
    );
    assert!(manager.enable_vault("different").is_err());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    drop(manager);
    let manager = SettingsManager::builder("metadata", "1")
        .with_config_dir(dir.path())
        .with_vault_password("shared-password")
        .build()
        .unwrap();
    assert!(!manager.is_locked());
    assert_eq!(std::fs::read(path).unwrap(), before);
}

#[test]
fn explicit_creation_enrolls_all_builder_stores() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("remotes")).unwrap();
    std::fs::write(
        dir.path().join("remotes/primary.json"),
        br#"{"host":"secret"}"#,
    )
    .unwrap();
    std::fs::write(
        dir.path().join("connections.json"),
        br#"{"primary":{"port":1234}}"#,
    )
    .unwrap();
    let manager = SettingsManager::builder("metadata", "1")
        .with_config_dir(dir.path())
        .with_vault_password("password")
        .with_vault_preset(Argon2Preset::Fast)
        .with_sub_settings(SubSettingsConfig::new("remotes"))
        .with_sub_settings(SubSettingsConfig::singlefile("connections"))
        .build()
        .unwrap();
    for name in ["remotes/primary.json", "connections.json"] {
        let value: Value =
            serde_json::from_slice(&std::fs::read(dir.path().join(name)).unwrap()).unwrap();
        assert!(rcman::vault::is_vault_value(&value));
    }
    assert_eq!(
        manager
            .sub_settings("connections")
            .unwrap()
            .get_value("primary")
            .unwrap()["port"],
        1234
    );
    assert!(!dir.path().join("settings.json").exists());
}

#[test]
fn missing_metadata_rejects_orphaned_subsettings_without_modifying_them() {
    let dir = tempfile::tempdir().unwrap();
    let manager = create(dir.path());
    manager
        .sub_settings("remotes")
        .unwrap()
        .set("primary", &json!({"host":"example"}))
        .unwrap();
    drop(manager);
    std::fs::remove_file(dir.path().join(".rcman-vault.json")).unwrap();
    let path = dir.path().join("remotes/primary.json");
    let before = std::fs::read(&path).unwrap();
    for password in [None, Some("shared-password")] {
        let builder = SettingsManager::builder("metadata", "1")
            .with_config_dir(dir.path())
            .with_vault()
            .with_sub_settings(SubSettingsConfig::new("remotes"));
        let builder = if let Some(password) = password {
            builder.with_vault_password(password)
        } else {
            builder
        };
        assert!(matches!(builder.build(), Err(Error::VaultNotFound)));
    }
    assert_eq!(std::fs::read(path).unwrap(), before);
    assert!(!dir.path().join(".rcman-vault.json").exists());
}

#[test]
fn foreign_vault_and_forged_identity_have_distinct_errors_and_preserve_bytes() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    let manager = create(first.path());
    let foreign = create(second.path());
    let remotes = manager.sub_settings("remotes").unwrap();
    remotes.set("primary", &json!({"host":"local"})).unwrap();
    foreign
        .sub_settings("remotes")
        .unwrap()
        .set("primary", &json!({"host":"foreign"}))
        .unwrap();
    let path = first.path().join("remotes/primary.json");
    let local: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let mut injected: Value =
        serde_json::from_slice(&std::fs::read(second.path().join("remotes/primary.json")).unwrap())
            .unwrap();
    assert_ne!(local["vault_id"], injected["vault_id"]);
    for forged in [false, true] {
        if forged {
            injected["vault_id"] = local["vault_id"].clone();
        }
        let bytes = serde_json::to_vec(&injected).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        manager.invalidate_cache();
        let error = remotes.get_value("primary").unwrap_err();
        if forged {
            assert!(matches!(error, Error::VaultDataAuthenticationFailed(_)));
        } else {
            assert!(matches!(error, Error::VaultMismatch(_)));
        }
        assert!(error.to_string().contains("remotes/primary.json"));
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert!(
            manager
                .change_vault_password("shared-password", "new")
                .is_err()
        );
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }
}

#[test]
fn corrupted_metadata_is_never_recreated() {
    let dir = tempfile::tempdir().unwrap();
    let manager = create(dir.path());
    drop(manager);
    let path = dir.path().join(".rcman-vault.json");
    std::fs::write(&path, b"invalid metadata").unwrap();
    for password in [None, Some("password")] {
        let builder = SettingsManager::builder("metadata", "1").with_config_dir(dir.path());
        let builder = if let Some(password) = password {
            builder.with_vault_password(password)
        } else {
            builder
        };
        assert!(matches!(
            builder.build(),
            Err(Error::InvalidVaultMetadata(_))
        ));
        assert_eq!(std::fs::read(&path).unwrap(), b"invalid metadata");
    }
}

#[cfg(feature = "profiles")]
#[test]
fn invalid_metadata_failure_precedes_profile_migration() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = br#"{"ui":{"theme":"existing"}}"#;
    std::fs::write(dir.path().join("settings.json"), bytes).unwrap();
    std::fs::write(dir.path().join(".rcman-vault.json"), b"invalid metadata").unwrap();
    assert!(matches!(
        SettingsManager::builder("metadata", "1")
            .with_config_dir(dir.path())
            .with_profiles()
            .build(),
        Err(Error::InvalidVaultMetadata(_))
    ));
    assert_eq!(
        std::fs::read(dir.path().join("settings.json")).unwrap(),
        bytes
    );
    assert!(!dir.path().join("profiles").exists());
}
