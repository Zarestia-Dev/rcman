//! Automatic startup and regressions for store access during vault operations.
#![cfg(feature = "vault")]

use rcman::{
    Argon2Preset, JsonStorage, SettingsConfig, SettingsManager, StorageBackend, SubSettingsConfig,
};
use serde::{Serialize, de::DeserializeOwned};
#[cfg(feature = "sqlite")]
use serde_json::Value;
use serde_json::json;
use std::path::Path;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[test]
fn managed_context_is_structured_and_only_metadata_owns_timeout() {
    let dir = tempfile::tempdir().unwrap();
    let manager = SettingsManager::builder("context", "1")
        .with_config_dir(dir.path())
        .with_vault_password("password")
        .with_vault_preset(Argon2Preset::Fast)
        .with_vault_lock_timeout(std::time::Duration::from_secs(300))
        .with_sub_settings(SubSettingsConfig::new("items"))
        .build()
        .unwrap();
    manager
        .sub_settings("items")
        .unwrap()
        .set("one", &json!({"value":1}))
        .unwrap();
    manager
        .set_vault_lock_timeout(Some(std::time::Duration::from_secs(60)))
        .unwrap();
    let data: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("items/one.json")).unwrap()).unwrap();
    let metadata: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.path().join(".rcman-vault.json")).unwrap())
            .unwrap();
    assert_eq!(data["context"], json!({"path":"items/one.json"}));
    assert!(data.get("lock_timeout_ms").is_none());
    assert_eq!(metadata["context"], json!({"path":".rcman-vault.json"}));
    assert_eq!(metadata["lock_timeout_ms"], 60_000);
}

#[test]
fn password_sources_resolve_at_build_and_share_empty_password_validation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("password");
    let builder = SettingsManager::builder("password", "1")
        .with_config_dir(dir.path())
        .with_vault_preset(Argon2Preset::Fast)
        .with_vault_password_source(rcman::SecretPasswordSource::file(&path));
    std::fs::write(&path, " supplied later \r\n").unwrap();
    let manager = builder.build().unwrap();
    manager.lock().unwrap();
    manager.unlock(" supplied later ").unwrap();
    assert!(
        manager
            .change_vault_password(" supplied later ", "")
            .is_err()
    );
    manager.disable_vault(" supplied later ").unwrap();
    assert!(manager.enable_vault("").is_err());
    assert!(
        SettingsManager::builder("empty", "1")
            .with_config_dir(dir.path())
            .with_vault_password("")
            .build()
            .is_err()
    );
    assert!(
        SettingsManager::builder("empty", "1")
            .with_config_dir(dir.path())
            .with_vault_password_source(rcman::SecretPasswordSource::provided(""))
            .build()
            .is_err()
    );
    assert!(!dir.path().join(".rcman-vault.json").exists());
}

#[derive(Clone)]
struct SlowReadStorage(Arc<std::sync::atomic::AtomicBool>);

impl StorageBackend for SlowReadStorage {
    fn extension(&self) -> &str {
        "json"
    }
    fn serialize<T: Serialize>(&self, value: &T) -> rcman::Result<String> {
        JsonStorage::new().serialize(value)
    }
    fn deserialize<T: DeserializeOwned>(&self, value: &str) -> rcman::Result<T> {
        JsonStorage::new().deserialize(value)
    }
    fn read<T: DeserializeOwned>(&self, path: &Path) -> rcman::Result<T> {
        if path.file_name().is_some_and(|name| name == "one.json")
            && self.0.swap(false, Ordering::SeqCst)
        {
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        JsonStorage::new().read(path)
    }
}

#[test]
fn startup_validation_keeps_the_key_pinned_during_slow_io() {
    let dir = tempfile::tempdir().unwrap();
    let manager = SettingsManager::builder("slow", "1")
        .with_config_dir(dir.path())
        .with_vault_password("password")
        .with_vault_preset(Argon2Preset::Fast)
        .with_sub_settings(SubSettingsConfig::new("items"))
        .build()
        .unwrap();
    manager
        .sub_settings("items")
        .unwrap()
        .set("one", &json!({"value":1}))
        .unwrap();
    drop(manager);
    let manager = SettingsManager::builder("slow", "1")
        .with_config_dir(dir.path())
        .with_vault_password("password")
        .with_vault_lock_timeout(std::time::Duration::from_millis(10))
        .with_storage_instance(SlowReadStorage(Arc::new(
            std::sync::atomic::AtomicBool::new(true),
        )))
        .with_sub_settings(SubSettingsConfig::new("items"))
        .build()
        .unwrap();
    assert!(manager.config().vault_password.is_none());
}

#[test]
fn rotation_keeps_the_old_key_pinned_while_reading_a_slow_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let armed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let manager = SettingsManager::builder("rotation-pin", "1")
        .with_config_dir(dir.path())
        .with_storage_instance(SlowReadStorage(Arc::clone(&armed)))
        .with_vault_password("old")
        .with_vault_preset(Argon2Preset::Fast)
        .with_sub_settings(SubSettingsConfig::new("items"))
        .build()
        .unwrap();
    manager
        .sub_settings("items")
        .unwrap()
        .set("one", &json!({"value":1}))
        .unwrap();
    manager
        .set_vault_lock_timeout(Some(std::time::Duration::from_millis(10)))
        .unwrap();
    armed.store(true, Ordering::SeqCst);
    manager.change_vault_password("old", "new").unwrap();
    assert!(manager.verify_vault_password("new").unwrap());
    assert!(!manager.verify_vault_password("old").unwrap());
    drop(manager);
    let reopened = SettingsManager::builder("rotation-pin", "1")
        .with_config_dir(dir.path())
        .with_vault_password("new")
        .with_vault_lock_timeout(std::time::Duration::from_secs(60))
        .with_sub_settings(SubSettingsConfig::new("items"))
        .build()
        .unwrap();
    assert_eq!(
        reopened
            .sub_settings("items")
            .unwrap()
            .get_value("one")
            .unwrap()["value"],
        1
    );
}

#[cfg(feature = "profiles")]
#[test]
fn inactive_vault_keeps_independent_stores_lazy_during_main_profile_migration_and_registration() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("settings.json"), r#"{"value":1}"#).unwrap();
    std::fs::create_dir_all(dir.path().join("items")).unwrap();
    std::fs::write(dir.path().join("items/one.json"), "not json").unwrap();
    let manager = SettingsManager::builder("lazy", "1")
        .with_config_dir(dir.path())
        .with_profiles()
        .with_sub_settings(SubSettingsConfig::new("items"))
        .build()
        .unwrap();
    assert!(dir.path().join("profiles/default/settings.json").exists());
    assert!(
        manager
            .sub_settings("items")
            .unwrap()
            .get_value("one")
            .is_err()
    );
    manager
        .register_sub_settings(SubSettingsConfig::new("items"))
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(dir.path().join("items/one.json")).unwrap(),
        "not json"
    );
}

#[derive(Clone, Default)]
struct CountingStorage {
    entry_reads: Arc<AtomicUsize>,
    #[cfg(feature = "profiles")]
    manifest_writes: Arc<AtomicUsize>,
}
impl StorageBackend for CountingStorage {
    fn extension(&self) -> &str {
        "json"
    }
    fn serialize<T: Serialize>(&self, value: &T) -> rcman::Result<String> {
        JsonStorage::new().serialize(value)
    }
    fn deserialize<T: DeserializeOwned>(&self, text: &str) -> rcman::Result<T> {
        JsonStorage::new().deserialize(text)
    }
    fn read<T: DeserializeOwned>(&self, path: &Path) -> rcman::Result<T> {
        if path
            .parent()
            .and_then(Path::file_name)
            .is_some_and(|name| name == "items")
            && path.exists()
        {
            self.entry_reads.fetch_add(1, Ordering::Relaxed);
        }
        JsonStorage::new().read(path)
    }
    fn write<T: Serialize>(&self, path: &Path, value: &T) -> rcman::Result<()> {
        #[cfg(feature = "profiles")]
        if path
            .file_name()
            .is_some_and(|name| name == ".profiles.json")
        {
            self.manifest_writes.fetch_add(1, Ordering::Relaxed);
        }
        JsonStorage::new().write(path, value)
    }
}

#[test]
fn with_vault_stays_parameterless_and_does_not_require_a_password() {
    let dir = tempfile::tempdir().unwrap();
    let config = SettingsConfig::builder("simple", "1")
        .with_config_dir(dir.path())
        .with_vault()
        .build();
    assert!(config.vault_requested);
    let manager = SettingsManager::new(config).unwrap();
    assert!(!manager.is_locked());
    assert!(!manager.is_vault_enabled());
    assert!(!dir.path().join(".rcman-vault.json").exists());
}

#[test]
fn opted_in_startup_checks_registered_entries_once() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("items")).unwrap();
    for index in 0..10 {
        std::fs::write(
            dir.path().join(format!("items/{index}.json")),
            br#"{"value":1}"#,
        )
        .unwrap();
    }
    let storage = CountingStorage::default();
    let manager = SettingsManager::builder("simple", "1")
        .with_config_dir(dir.path())
        .with_storage_instance(storage.clone())
        .with_vault()
        .with_sub_settings(SubSettingsConfig::new("items"))
        .build()
        .unwrap();
    assert!(!manager.is_vault_enabled());
    assert_eq!(storage.entry_reads.load(Ordering::Relaxed), 10);
}

#[test]
fn inactive_vault_does_not_scan_plaintext_stores() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("items")).unwrap();
    std::fs::write(dir.path().join("items/one.json"), br#"{"value":1}"#).unwrap();
    let storage = CountingStorage::default();
    let manager = SettingsManager::builder("simple", "1")
        .with_config_dir(dir.path())
        .with_storage_instance(storage.clone())
        .with_sub_settings(SubSettingsConfig::new("items"))
        .build()
        .unwrap();
    assert_eq!(storage.entry_reads.load(Ordering::Relaxed), 0);
    assert_eq!(
        manager
            .sub_settings("items")
            .unwrap()
            .get_value("one")
            .unwrap()["value"],
        1
    );
}

#[cfg(feature = "profiles")]
#[test]
fn disabled_profiles_do_not_make_unused_data_a_startup_dependency() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("profiles/unused")).unwrap();
    std::fs::write(
        dir.path().join("profiles/unused/settings.json"),
        b"broken unused profile",
    )
    .unwrap();
    let manager = SettingsManager::builder("simple", "1")
        .with_config_dir(dir.path())
        .with_vault()
        .build()
        .unwrap();
    assert!(!manager.is_vault_enabled());
}

#[cfg(feature = "profiles")]
#[test]
fn vault_migrations_preserve_profile_selection_without_switch_events_or_manifest_writes() {
    let dir = tempfile::tempdir().unwrap();
    let storage = CountingStorage::default();
    let manager = SettingsManager::builder("simple", "1")
        .with_config_dir(dir.path())
        .with_storage_instance(storage.clone())
        .with_vault_preset(Argon2Preset::Fast)
        .with_sub_settings(SubSettingsConfig::singlefile("items").with_profiles())
        .build()
        .unwrap();
    let items = manager.sub_settings("items").unwrap();
    items.set("one", &json!({"value":1})).unwrap();
    items.profiles().unwrap().create("work").unwrap();
    items.switch_profile("work").unwrap();
    items.set("one", &json!({"value":2})).unwrap();
    let switches = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&switches);
    items.profiles().unwrap().set_on_event(move |event| {
        if matches!(event, rcman::ProfileEvent::Switched { .. }) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    });
    storage.manifest_writes.store(0, Ordering::Relaxed);
    manager.enable_vault("old").unwrap();
    manager.change_vault_password("old", "new").unwrap();
    manager.lock().unwrap();
    manager.unlock("new").unwrap();
    manager.disable_vault("new").unwrap();
    assert_eq!(items.profiles().unwrap().active().unwrap(), "work");
    assert_eq!(items.get_value("one").unwrap()["value"], 2);
    assert_eq!(storage.manifest_writes.load(Ordering::Relaxed), 0);
    assert_eq!(switches.load(Ordering::Relaxed), 0);
    items.switch_profile("default").unwrap();
    assert_eq!(items.get_value("one").unwrap()["value"], 1);
}

fn create(root: &Path, config: SubSettingsConfig) -> SettingsManager {
    SettingsManager::builder("simple", "1")
        .with_config_dir(root)
        .with_vault()
        .with_vault_password("same-password")
        .with_vault_preset(Argon2Preset::Fast)
        .with_sub_settings(config)
        .build()
        .unwrap()
}

fn protect_foreign_file(config: SubSettingsConfig, relative: &str) {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    let manager = create(first.path(), config.clone());
    let other = create(second.path(), config);
    let items = manager.sub_settings("items").unwrap();
    items.set("one", &json!({"value":"local"})).unwrap();
    other
        .sub_settings("items")
        .unwrap()
        .set("one", &json!({"value":"foreign"}))
        .unwrap();
    let path = first.path().join(relative);
    std::fs::copy(second.path().join(relative), &path).unwrap();
    let bytes = std::fs::read(&path).unwrap();
    // Keep the local entry cached: writes must inspect the destination on disk.
    assert!(items.set("one", &json!({"value":"replacement"})).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    assert!(items.delete("one").is_err());
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
}

#[test]
fn warm_multifile_cache_cannot_overwrite_or_delete_a_foreign_file() {
    protect_foreign_file(SubSettingsConfig::new("items"), "items/one.json");
}

#[test]
fn warm_singlefile_cache_cannot_overwrite_or_delete_a_foreign_file() {
    protect_foreign_file(SubSettingsConfig::singlefile("items"), "items.json");
}

#[cfg(feature = "sqlite")]
#[test]
fn warm_table_cache_cannot_overwrite_or_delete_foreign_rows() {
    protect_foreign_file(SubSettingsConfig::table("items"), "items.db");
}

#[cfg(feature = "sqlite")]
#[test]
fn ordinary_encrypted_updates_allow_existing_wal_readers() {
    let dir = tempfile::tempdir().unwrap();
    let manager = create(dir.path(), SubSettingsConfig::table("items"));
    let items = manager.sub_settings("items").unwrap();
    items.set("one", &json!({"value":1})).unwrap();
    let reader = rusqlite::Connection::open(dir.path().join("items.db")).unwrap();
    reader
        .execute_batch("PRAGMA journal_mode=WAL; BEGIN")
        .unwrap();
    let previous: String = reader
        .query_row("SELECT data FROM items WHERE key='one'", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert!(
        serde_json::from_str::<Value>(&previous)
            .unwrap()
            .get("__rcman_vault__")
            .is_some()
    );
    items.set("one", &json!({"value":2})).unwrap();
    items.invalidate_cache();
    assert_eq!(items.get_value("one").unwrap()["value"], 2);
    let snapshot: String = reader
        .query_row("SELECT data FROM items WHERE key='one'", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(snapshot, previous);
    reader.execute_batch("ROLLBACK").unwrap();
}

#[cfg(feature = "profiles")]
#[test]
fn missing_metadata_is_detected_before_main_profile_migration_moves_subsettings() {
    let dir = tempfile::tempdir().unwrap();
    let manager = create(dir.path(), SubSettingsConfig::new("items"));
    manager
        .sub_settings("items")
        .unwrap()
        .set("one", &json!({"value":1}))
        .unwrap();
    drop(manager);
    std::fs::remove_file(dir.path().join(".rcman-vault.json")).unwrap();
    let path = dir.path().join("items/one.json");
    let bytes = std::fs::read(&path).unwrap();
    assert!(
        SettingsManager::builder("simple", "1")
            .with_config_dir(dir.path())
            .with_profiles()
            .with_vault_password("password")
            .with_sub_settings(SubSettingsConfig::new("items"))
            .build()
            .is_err()
    );
    assert_eq!(std::fs::read(path).unwrap(), bytes);
    assert!(!dir.path().join("profiles").exists());
    assert!(!dir.path().join(".rcman-vault.json").exists());
}
