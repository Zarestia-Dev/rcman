#![cfg(all(feature = "profiles", feature = "backup"))]

mod common;

#[cfg(all(feature = "encrypted-file", not(feature = "keychain")))]
use common::{TestCredentialsGuard, unique_app_name};
use rcman::{BackupOptions, RestoreOptions};
#[cfg(all(feature = "encrypted-file", not(feature = "keychain")))]
use rcman::{SettingMetadata, SettingsSchema, settings};
use rcman::{SettingsConfigBuilder, SettingsManager, SubSettingsConfig};
#[cfg(all(feature = "encrypted-file", not(feature = "keychain")))]
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_profile_backup_restore_full() {
    let temp = tempdir().unwrap();
    let config_dir = temp.path().join("config");
    fs::create_dir_all(&config_dir).unwrap();

    // 1. Setup Manager with Profiles Enabled
    let config = SettingsConfigBuilder::new("test-app", "1.0.0")
        .with_config_dir(&config_dir)
        .with_profiles()
        .build();

    let manager = SettingsManager::new(config).unwrap();
    manager
        .register_sub_settings(SubSettingsConfig::new("items").with_profiles())
        .unwrap();

    // 2. Create profiles
    if !manager.profiles().unwrap().exists("default").unwrap() {
        manager.create_profile("default").unwrap();
    }

    // Create 'work' profile
    manager.create_profile("work").unwrap();

    // 3. Add data to 'default'
    manager.switch_profile("default").unwrap();
    // Use sub-settings for data since SettingsManager requires schema
    let items = manager.sub_settings("items").unwrap();
    items.set("item1", &json!({"val": 1})).unwrap();

    // 4. Switch to 'work' and add data
    manager.switch_profile("work").unwrap();

    let items = manager.sub_settings("items").unwrap();
    items.set("item1", &json!({"val": 2})).unwrap();
    items.set("item2", &json!({"val": 3})).unwrap();

    // 5. Backup ALL profiles
    let backup_mgr = manager.backup();
    let backup_path = backup_mgr
        .create(&BackupOptions {
            output_dir: temp.path().join("backups"),
            include_settings: true,
            include_sub_settings: vec!["items".into()],
            include_profiles: vec![], // All
            ..Default::default()
        })
        .unwrap();

    // 6. Restore to fresh instance (profiled)
    let temp2 = tempdir().unwrap();
    let restore_config_dir = temp2.path().join("config");
    fs::create_dir_all(&restore_config_dir).unwrap();

    let config2 = SettingsConfigBuilder::new("test-app", "1.0.0")
        .with_config_dir(&restore_config_dir)
        .with_profiles()
        .build();

    let manager2 = SettingsManager::new(config2).unwrap();
    manager2
        .register_sub_settings(SubSettingsConfig::new("items").with_profiles())
        .unwrap();

    // Restore ALL
    let result = manager2
        .backup()
        .restore(&RestoreOptions {
            backup_path: backup_path.clone(),
            flags: rcman::backup::RestoreFlags {
                scope: rcman::backup::RestoreScope {
                    restore_settings: true,
                },
                ..Default::default()
            },
            restore_sub_settings: vec!["items".into()]
                .into_iter()
                .map(|s| (s, vec![]))
                .collect(),
            ..Default::default()
        })
        .unwrap();

    assert!(result.has_changes());

    // 7. Verify 'default' restore
    manager2.switch_profile("default").unwrap();

    let items2 = manager2.sub_settings("items").unwrap();
    let item1_def = items2.get_value("item1").unwrap();
    assert_eq!(item1_def["val"], 1);
    assert!(!items2.exists("item2").unwrap());

    // 8. Verify 'work' restore
    manager2.switch_profile("work").unwrap();

    let items2_work = manager2.sub_settings("items").unwrap();
    let item1_work = items2_work.get_value("item1").unwrap();
    assert_eq!(item1_work["val"], 2);
    let item2_work = items2_work.get_value("item2").unwrap();
    assert_eq!(item2_work["val"], 3);
}

#[test]
fn restore_refuses_a_profile_that_differs_from_an_existing_one_only_by_case() {
    let build = |dir: &std::path::Path| {
        let config = SettingsConfigBuilder::new("test-app", "1.0.0")
            .with_config_dir(dir)
            .with_profiles()
            .build();
        let manager = SettingsManager::new(config).unwrap();
        manager
            .register_sub_settings(SubSettingsConfig::new("items").with_profiles())
            .unwrap();
        manager
    };
    let source_dir = tempdir().unwrap();
    let source = build(&source_dir.path().join("config"));
    source.create_profile("Work").unwrap();
    source.switch_profile("Work").unwrap();
    source
        .sub_settings("items")
        .unwrap()
        .set("item", &json!({"val": 1}))
        .unwrap();
    let backup = source
        .backup()
        .create(&BackupOptions {
            output_dir: source_dir.path().join("backups"),
            include_settings: true,
            include_sub_settings: vec!["items".into()],
            include_profiles: vec![],
            ..Default::default()
        })
        .unwrap();

    let target_dir = tempdir().unwrap();
    let target = build(&target_dir.path().join("config"));
    target.create_profile("work").unwrap();
    let error = target
        .backup()
        .restore(&RestoreOptions {
            backup_path: backup,
            restore_sub_settings: vec![("items".to_string(), vec![])].into_iter().collect(),
            ..Default::default()
        })
        .unwrap_err();

    assert!(
        matches!(&error, rcman::Error::ProfileAlreadyExists(existing) if existing == "work"),
        "{error:?}"
    );
    // The existing profile and its manifest are untouched.
    assert_eq!(
        target
            .sub_settings("items")
            .unwrap()
            .profiles()
            .unwrap()
            .list()
            .unwrap(),
        ["default", "work"].map(String::from)
    );
}

#[cfg(all(feature = "encrypted-file", not(feature = "keychain")))]
#[derive(Default, Serialize, Deserialize)]
struct ProfileSecretSettings;

#[cfg(all(feature = "encrypted-file", not(feature = "keychain")))]
impl SettingsSchema for ProfileSecretSettings {
    fn get_metadata() -> rcman::IndexMap<String, SettingMetadata> {
        settings! {
            "secrets.api_key" => SettingMetadata::text("").secret(),
        }
    }
}

#[cfg(all(feature = "encrypted-file", not(feature = "keychain")))]
#[test]
fn test_profile_restore_rehydrates_main_secrets_with_credentials() {
    let temp = tempdir().unwrap();
    let app_name = unique_app_name();
    let _guard = TestCredentialsGuard::new(&app_name);
    let source_config_dir = temp.path().join("source");
    fs::create_dir_all(&source_config_dir).unwrap();

    let source_config = SettingsConfigBuilder::new(&app_name, "1.0.0")
        .with_config_dir(&source_config_dir)
        .with_schema::<ProfileSecretSettings>()
        .with_profiles()
        .with_credentials()
        .build();

    let source = SettingsManager::new(source_config).unwrap();

    source.create_profile("work").unwrap();
    source.switch_profile("work").unwrap();
    source
        .save_setting("secrets", "api_key", &json!("work-profile-secret"))
        .unwrap();

    let backup_path = source
        .backup()
        .create(
            &BackupOptions::new()
                .output_dir(temp.path().join("backups"))
                .include_profile("work")
                .secret_policy(rcman::SecretBackupPolicy::Include),
        )
        .unwrap();

    let target_config_dir = temp.path().join("target");
    fs::create_dir_all(&target_config_dir).unwrap();

    let target_config = SettingsConfigBuilder::new(&app_name, "1.0.0")
        .with_config_dir(&target_config_dir)
        .with_schema::<ProfileSecretSettings>()
        .with_profiles()
        .with_credentials()
        .build();

    let target = SettingsManager::new(target_config).unwrap();

    target
        .backup()
        .restore(
            &RestoreOptions::from_path(&backup_path)
                .overwrite(true)
                .restore_profile("work"),
        )
        .unwrap();

    let secret = target
        .credentials()
        .unwrap()
        .get_with_profile("secrets.api_key", Some("work"))
        .unwrap();
    assert_eq!(secret, Some("work-profile-secret".to_string()));

    let settings_path = target
        .config()
        .config_dir
        .join("profiles")
        .join("work")
        .join(&target.config().settings_file);
    let restored_settings: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(settings_path).unwrap()).unwrap();

    let persisted_key = restored_settings
        .get("secrets")
        .and_then(|secrets| secrets.get("api_key"));
    assert!(persisted_key.is_none() || persisted_key == Some(&serde_json::Value::Null));
}
