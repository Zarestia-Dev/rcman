//! Profile paths, migration conflicts, and credential namespace isolation.
#![cfg(feature = "profiles")]

use rcman::{SettingMetadata, SettingsManager, SettingsSchema, SubSettingsConfig};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Clone, Default)]
struct FailManifestStorage(std::sync::Arc<std::sync::atomic::AtomicBool>);

impl rcman::StorageBackend for FailManifestStorage {
    fn extension(&self) -> &str {
        "json"
    }
    fn serialize<T: Serialize>(&self, value: &T) -> rcman::Result<String> {
        rcman::JsonStorage::new().serialize(value)
    }
    fn deserialize<T: serde::de::DeserializeOwned>(&self, text: &str) -> rcman::Result<T> {
        rcman::JsonStorage::new().deserialize(text)
    }
    fn write<T: Serialize>(&self, path: &std::path::Path, value: &T) -> rcman::Result<()> {
        if path
            .file_name()
            .is_some_and(|name| name == ".profiles.json")
            && self.0.swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(rcman::Error::Config(
                "injected manifest write failure".into(),
            ));
        }
        rcman::JsonStorage::new().write(path, value)
    }
}

#[derive(Default, Serialize, Deserialize)]
struct Schema;

impl SettingsSchema for Schema {
    fn get_metadata() -> rcman::IndexMap<String, SettingMetadata> {
        rcman::settings! {
            "ui.theme" => SettingMetadata::text("dark"),
            "api.token" => SettingMetadata::text("").secret(),
            "sub.token" => SettingMetadata::text("").secret(),
        }
    }
}

#[test]
fn direct_main_profile_changes_refresh_paths_and_warm_caches() {
    let dir = tempfile::tempdir().unwrap();
    let builder = SettingsManager::builder("profiles", "1")
        .with_config_dir(dir.path())
        .with_schema::<Schema>()
        .with_profiles();
    #[cfg(feature = "vault")]
    let builder = builder
        .with_vault_password("password")
        .with_vault_preset(rcman::Argon2Preset::Fast);
    let manager = builder.build().unwrap();
    manager
        .save_setting("ui", "theme", &json!("light"))
        .unwrap();
    let profiles = manager.profiles().unwrap();
    profiles.create("work").unwrap();
    profiles.switch("work").unwrap();
    assert_eq!(manager.get_value("ui.theme").unwrap(), "dark");
    manager.save_setting("ui", "theme", &json!("work")).unwrap();
    profiles.rename("work", "renamed").unwrap();
    assert_eq!(manager.get_value("ui.theme").unwrap(), "work");
    manager.invalidate_cache();
    assert_eq!(manager.get_value("ui.theme").unwrap(), "work");
    manager
        .save_setting("ui", "theme", &json!("updated"))
        .unwrap();
    assert!(!dir.path().join("profiles/work").exists());
    profiles.switch("default").unwrap();
    assert_eq!(manager.get_value("ui.theme").unwrap(), "light");
}

#[test]
fn direct_sub_profile_changes_refresh_all_store_modes() {
    let mut configs = vec![
        SubSettingsConfig::new("multi"),
        SubSettingsConfig::singlefile("single"),
    ];
    #[cfg(feature = "sqlite")]
    configs.push(SubSettingsConfig::table("table"));
    for config in configs.drain(..) {
        let dir = tempfile::tempdir().unwrap();
        let name = config.name.clone();
        let builder = SettingsManager::builder("profiles", "1")
            .with_config_dir(dir.path())
            .with_sub_settings(config.with_profiles());
        #[cfg(feature = "vault")]
        let builder = builder
            .with_vault_password("password")
            .with_vault_preset(rcman::Argon2Preset::Fast);
        let manager = builder.build().unwrap();
        let sub = manager.sub_settings(&name).unwrap();
        sub.set("one", &json!({"value":"original"})).unwrap();
        let profiles = sub.profiles().unwrap();
        profiles.create("work").unwrap();
        profiles.switch("work").unwrap();
        assert!(!sub.exists("one").unwrap());
        sub.set("one", &json!({"value":"work"})).unwrap();
        profiles.rename("work", "renamed").unwrap();
        assert_eq!(sub.get_value("one").unwrap()["value"], "work");
        sub.invalidate_cache();
        assert_eq!(sub.get_value("one").unwrap()["value"], "work");
        sub.set("two", &json!({"value":"new"})).unwrap();
        assert!(!dir.path().join(&name).join("profiles/work").exists());
        assert!(sub.directory().ends_with("profiles/renamed"));
        profiles.switch("default").unwrap();
        assert_eq!(sub.get_value("one").unwrap()["value"], "original");
    }
}

#[test]
fn profile_migration_preserves_conflicting_data_and_retries_identical_copies() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("settings.json");
    let destination = dir.path().join("profiles/default/settings.json");
    std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
    std::fs::write(&source, r#"{"ui":{"theme":"source"}}"#).unwrap();
    std::fs::write(&destination, r#"{"ui":{"theme":"destination"}}"#).unwrap();
    let build = || {
        SettingsManager::builder("profiles", "1")
            .with_config_dir(dir.path())
            .with_profiles()
            .build()
    };
    let original = std::fs::read(&destination).unwrap();
    assert!(build().is_err());
    assert_eq!(std::fs::read(&destination).unwrap(), original);
    assert!(source.exists());
    assert!(!dir.path().join(".profiles.json").exists());
    std::fs::copy(&source, &destination).unwrap();
    assert!(build().is_ok());
    assert!(!source.exists());
}

#[test]
fn failed_profile_manifest_writes_preserve_active_data_and_remove_new_copies() {
    use std::sync::atomic::Ordering;
    let dir = tempfile::tempdir().unwrap();
    let storage = FailManifestStorage::default();
    let builder = SettingsManager::builder("failed-profile", "1")
        .with_config_dir(dir.path())
        .with_schema::<Schema>()
        .with_profiles()
        .with_storage_instance(storage.clone());
    #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
    let builder = builder.with_credential_config(rcman::CredentialConfig::Custom(
        std::sync::Arc::new(rcman::MemoryBackend::new()),
    ));
    let manager = builder.build().unwrap();
    manager
        .save_setting("ui", "theme", &json!("original"))
        .unwrap();
    #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
    manager
        .save_setting("api", "token", &json!("original-secret"))
        .unwrap();
    let profiles = manager.profiles().unwrap();
    profiles.create("work").unwrap();
    storage.0.store(true, Ordering::SeqCst);
    assert!(profiles.switch("work").is_err());
    assert_eq!(profiles.active().unwrap(), "default");
    for rename in [false, true] {
        storage.0.store(true, Ordering::SeqCst);
        let result = if rename {
            profiles.rename("default", "copy")
        } else {
            profiles.duplicate("default", "copy")
        };
        assert!(result.is_err());
        assert!(!dir.path().join("profiles/copy").exists());
        manager.invalidate_cache();
        assert_eq!(profiles.active().unwrap(), "default");
        assert_eq!(manager.get_value("ui.theme").unwrap(), "original");
        #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
        assert_eq!(manager.get_value("api.token").unwrap(), "original-secret");
    }
}

#[cfg(any(feature = "keychain", feature = "encrypted-file"))]
#[test]
fn profile_secret_transfers_preserve_other_targets_and_typed_values() {
    use rcman::{CredentialBackend, CredentialConfig, MemoryBackend};
    use std::sync::Arc;
    let dir = tempfile::tempdir().unwrap();
    let backend = Arc::new(MemoryBackend::new());
    let manager = SettingsManager::builder("profile-secrets", "1")
        .with_config_dir(dir.path())
        .with_schema::<Schema>()
        .with_profiles()
        .with_credential_config(CredentialConfig::Custom(backend.clone()))
        .with_sub_settings(
            SubSettingsConfig::singlefile("items")
                .with_profiles()
                .with_metadata(rcman::settings! {
                    "token" => SettingMetadata::number(0.0).secret(),
                }),
        )
        .build()
        .unwrap();
    manager
        .save_setting("api", "token", &json!("main-secret"))
        .unwrap();
    manager
        .save_setting("sub", "token", &json!("main-sub-category-secret"))
        .unwrap();
    let sub = manager.sub_settings("items").unwrap();
    sub.set("one", &json!({"token":42})).unwrap();
    let main_profiles = manager.profiles().unwrap();
    let sub_profiles = sub.profiles().unwrap();
    main_profiles.duplicate("default", "copy").unwrap();
    main_profiles.switch("copy").unwrap();
    assert_eq!(manager.get_value("api.token").unwrap(), "main-secret");
    assert_eq!(
        manager.get_value("sub.token").unwrap(),
        "main-sub-category-secret"
    );
    assert_eq!(sub.get_value("one").unwrap()["token"], 42);
    sub_profiles.duplicate("default", "copy").unwrap();
    sub_profiles.switch("copy").unwrap();
    assert_eq!(sub.get_value("one").unwrap()["token"], 42);
    manager
        .save_setting("api", "token", &json!("copy-main"))
        .unwrap();
    main_profiles.rename("copy", "renamed").unwrap();
    assert_eq!(
        manager.get_value("sub.token").unwrap(),
        "main-sub-category-secret"
    );
    assert_eq!(manager.get_value("api.token").unwrap(), "copy-main");
    assert_eq!(sub.get_value("one").unwrap()["token"], 42);
    sub_profiles.rename("copy", "renamed").unwrap();
    assert_eq!(sub.get_value("one").unwrap()["token"], 42);
    assert_eq!(manager.get_value("api.token").unwrap(), "copy-main");
    assert!(
        !backend
            .list_keys()
            .unwrap()
            .iter()
            .any(|key| key.contains(":copy:"))
    );
    main_profiles.switch("default").unwrap();
    assert_eq!(manager.get_value("api.token").unwrap(), "main-secret");
    main_profiles.delete("renamed").unwrap();
    assert_eq!(sub.get_value("one").unwrap()["token"], 42);
    main_profiles.create("renamed").unwrap();
    main_profiles.switch("renamed").unwrap();
    assert_eq!(manager.get_value("api.token").unwrap(), "");
    assert_eq!(manager.get_value("sub.token").unwrap(), "");
    manager
        .save_setting("api", "token", &json!("fresh-main"))
        .unwrap();
    sub_profiles.switch("default").unwrap();
    sub_profiles.delete("renamed").unwrap();
    sub_profiles.create("renamed").unwrap();
    sub_profiles.switch("renamed").unwrap();
    assert!(!sub.exists("one").unwrap());
    assert_eq!(manager.get_value("api.token").unwrap(), "fresh-main");
}

#[test]
fn failed_delete_restores_profile_directory_manifest_and_secrets() {
    use std::sync::atomic::Ordering;
    let dir = tempfile::tempdir().unwrap();
    let storage = FailManifestStorage::default();
    let builder = SettingsManager::builder("delete-rollback", "1")
        .with_config_dir(dir.path())
        .with_schema::<Schema>()
        .with_profiles()
        .with_storage_instance(storage.clone());
    #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
    let builder = builder.with_credential_config(rcman::CredentialConfig::Custom(
        std::sync::Arc::new(rcman::MemoryBackend::new()),
    ));
    let manager = builder.build().unwrap();
    manager.create_profile("work").unwrap();
    manager.switch_profile("work").unwrap();
    manager.save_setting("ui", "theme", &json!("work")).unwrap();
    #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
    manager
        .save_setting("api", "token", &json!("work-secret"))
        .unwrap();
    manager.switch_profile("default").unwrap();
    storage.0.store(true, Ordering::SeqCst);
    assert!(manager.profiles().unwrap().delete("work").is_err());
    assert!(dir.path().join("profiles/work/settings.json").exists());
    assert!(!dir.path().join("profiles/.rcman-delete-work").exists());
    manager.invalidate_cache();
    manager.switch_profile("work").unwrap();
    assert_eq!(manager.get_value("ui.theme").unwrap(), "work");
    #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
    assert_eq!(manager.get_value("api.token").unwrap(), "work-secret");
}

#[cfg(unix)]
#[test]
fn unencrypted_profile_rename_preserves_inodes_and_symlinks() {
    use std::os::unix::fs::MetadataExt;
    let dir = tempfile::tempdir().unwrap();
    let manager = SettingsManager::builder("move", "1")
        .with_config_dir(dir.path())
        .with_schema::<Schema>()
        .with_profiles()
        .build()
        .unwrap();
    manager
        .save_setting("ui", "theme", &json!("light"))
        .unwrap();
    let source = dir.path().join("profiles/default");
    let inode = std::fs::metadata(source.join("settings.json"))
        .unwrap()
        .ino();
    std::os::unix::fs::symlink("settings.json", source.join("alias")).unwrap();
    manager
        .profiles()
        .unwrap()
        .rename("default", "renamed")
        .unwrap();
    let target = dir.path().join("profiles/renamed");
    assert_eq!(
        std::fs::metadata(target.join("settings.json"))
            .unwrap()
            .ino(),
        inode
    );
    assert!(
        std::fs::symlink_metadata(target.join("alias"))
            .unwrap()
            .is_symlink()
    );
}

#[derive(Clone)]
struct BlockingRead {
    armed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    entered: std::sync::Arc<std::sync::Barrier>,
    release: std::sync::Arc<std::sync::Barrier>,
    suffix: &'static str,
}

impl BlockingRead {
    fn new(suffix: &'static str) -> Self {
        Self {
            armed: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            entered: std::sync::Arc::new(std::sync::Barrier::new(2)),
            release: std::sync::Arc::new(std::sync::Barrier::new(2)),
            suffix,
        }
    }
}

impl rcman::StorageBackend for BlockingRead {
    fn extension(&self) -> &str {
        "json"
    }
    fn serialize<T: Serialize>(&self, value: &T) -> rcman::Result<String> {
        rcman::JsonStorage::new().serialize(value)
    }
    fn deserialize<T: serde::de::DeserializeOwned>(&self, text: &str) -> rcman::Result<T> {
        rcman::JsonStorage::new().deserialize(text)
    }
    fn read<T: serde::de::DeserializeOwned>(&self, path: &std::path::Path) -> rcman::Result<T> {
        let value = rcman::JsonStorage::new().read(path)?;
        if path.ends_with(self.suffix)
            && self.armed.swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            self.entered.wait();
            self.release.wait();
        }
        Ok(value)
    }
}

#[test]
fn direct_main_switch_waits_for_the_current_write() {
    use std::{
        sync::{Arc, atomic::Ordering, mpsc},
        time::Duration,
    };
    let dir = tempfile::tempdir().unwrap();
    let storage = BlockingRead::new("profiles/default/settings.json");
    let manager = Arc::new(
        SettingsManager::builder("race", "1")
            .with_config_dir(dir.path())
            .with_schema::<Schema>()
            .with_storage_instance(storage.clone())
            .with_profiles()
            .build()
            .unwrap(),
    );
    manager.save_setting("ui", "theme", &json!("A")).unwrap();
    manager.create_profile("work").unwrap();
    manager.switch_profile("work").unwrap();
    manager.save_setting("ui", "theme", &json!("B")).unwrap();
    manager.switch_profile("default").unwrap();
    manager.invalidate_cache();
    storage.armed.store(true, Ordering::SeqCst);
    let writer = Arc::clone(&manager);
    let write = std::thread::spawn(move || writer.save_setting("ui", "theme", &json!("updated-A")));
    storage.entered.wait();
    let (started_tx, started_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let switcher = Arc::clone(&manager);
    let switch = std::thread::spawn(move || {
        started_tx.send(()).unwrap();
        switcher.profiles().unwrap().switch("work").unwrap();
        done_tx.send(()).unwrap();
    });
    started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    let switched_early = done_rx.recv_timeout(Duration::from_millis(50)).is_ok();
    storage.release.wait();
    write.join().unwrap().unwrap();
    switch.join().unwrap();
    assert!(!switched_early);
    assert_eq!(manager.get_value("ui.theme").unwrap(), "B");
    manager.profiles().unwrap().switch("default").unwrap();
    assert_eq!(manager.get_value("ui.theme").unwrap(), "updated-A");
}

#[test]
fn direct_sub_switch_waits_for_the_current_write() {
    use std::{
        sync::{Arc, atomic::Ordering, mpsc},
        time::Duration,
    };
    let dir = tempfile::tempdir().unwrap();
    let storage = BlockingRead::new("items/profiles/default/items.json");
    let manager = SettingsManager::builder("sub-race", "1")
        .with_config_dir(dir.path())
        .with_storage_instance(storage.clone())
        .with_sub_settings(SubSettingsConfig::singlefile("items").with_profiles())
        .build()
        .unwrap();
    let sub = manager.sub_settings("items").unwrap();
    sub.set("one", &json!({"value":"A"})).unwrap();
    sub.profiles().unwrap().create("work").unwrap();
    sub.switch_profile("work").unwrap();
    sub.set("one", &json!({"value":"B"})).unwrap();
    sub.switch_profile("default").unwrap();
    sub.invalidate_cache();
    storage.armed.store(true, Ordering::SeqCst);
    let writer = Arc::clone(&sub);
    let write = std::thread::spawn(move || writer.set("one", &json!({"value":"updated-A"})));
    storage.entered.wait();
    let (started_tx, started_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let switcher = Arc::clone(&sub);
    let switch = std::thread::spawn(move || {
        started_tx.send(()).unwrap();
        switcher.profiles().unwrap().switch("work").unwrap();
        done_tx.send(()).unwrap();
    });
    started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    let switched_early = done_rx.recv_timeout(Duration::from_millis(50)).is_ok();
    storage.release.wait();
    write.join().unwrap().unwrap();
    switch.join().unwrap();
    assert!(!switched_early);
    assert_eq!(sub.get_value("one").unwrap()["value"], "B");
    sub.profiles().unwrap().switch("default").unwrap();
    assert_eq!(sub.get_value("one").unwrap()["value"], "updated-A");
}

#[test]
fn profile_callbacks_can_read_settings_and_replace_themselves() {
    use std::{
        sync::{Arc, mpsc},
        time::Duration,
    };
    let dir = tempfile::tempdir().unwrap();
    let manager = Arc::new(
        SettingsManager::builder("callbacks", "1")
            .with_config_dir(dir.path())
            .with_schema::<Schema>()
            .with_profiles()
            .build()
            .unwrap(),
    );
    let weak = Arc::downgrade(&manager);
    manager.profiles().unwrap().set_on_event(move |_| {
        let manager = weak.upgrade().unwrap();
        manager.get_value("ui.theme").unwrap();
        manager.profiles().unwrap().set_on_event(|_| {});
    });
    let weak = Arc::downgrade(&manager);
    manager.profiles().unwrap().set_on_invalidate(move || {
        let manager = weak.upgrade().unwrap();
        manager.get_value("ui.theme").unwrap();
        manager.profiles().unwrap().set_on_invalidate(|| {});
    });
    let (tx, rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        manager.create_profile("work").unwrap();
        manager.switch_profile("work").unwrap();
        tx.send(()).unwrap();
    });
    rx.recv_timeout(Duration::from_secs(2))
        .expect("profile callback deadlocked");
    worker.join().unwrap();
}

#[test]
fn profile_migration_detection_can_read_the_owner() {
    use std::{
        sync::{Arc, mpsc},
        time::Duration,
    };
    let dir = tempfile::tempdir().unwrap();
    let mut config = rcman::SettingsConfig::builder("detection", "1")
        .with_config_dir(dir.path())
        .with_schema::<Schema>()
        .with_profiles()
        .build();
    config.profile_migrator = rcman::ProfileMigrator::None;
    let manager = Arc::new(SettingsManager::new(config).unwrap());
    let (tx, rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result = manager.profiles().unwrap().initialize_with_migration(|| {
            manager.get_value("ui.theme").unwrap();
            false
        });
        tx.send(result).unwrap();
    });
    assert!(
        !rx.recv_timeout(Duration::from_secs(2))
            .expect("detection callback deadlocked")
            .unwrap()
    );
    worker.join().unwrap();
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_profile_migration_checks_only_the_owned_record() {
    use rcman::{SqliteStorage, StorageBackend};
    let dir = tempfile::tempdir().unwrap();
    let storage = SqliteStorage::new().with_table("table");
    let source = dir.path().join("settings.db");
    let destination = dir.path().join("profiles/default/settings.db");
    storage.write(&source, &json!({"value":"source"})).unwrap();
    let other = storage.clone().with_key("other");
    other
        .write(&destination, &json!({"value":"other"}))
        .unwrap();
    SettingsManager::builder("profiles", "1")
        .with_config_dir(dir.path())
        .with_storage_instance(storage.clone())
        .with_profiles()
        .build()
        .unwrap();
    assert_eq!(
        storage.read::<serde_json::Value>(&destination).unwrap()["value"],
        "source"
    );
    assert_eq!(
        other.read::<serde_json::Value>(&destination).unwrap()["value"],
        "other"
    );
}
