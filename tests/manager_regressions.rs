//! Regression coverage for managed writes, callback reentrancy and failed commits.

use rcman::{Error, JsonStorage, SettingMetadata, SettingsManager, SettingsSchema, StorageBackend};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::Path;
use std::sync::{
    Arc, Barrier,
    atomic::{AtomicBool, Ordering},
};

#[derive(Default, Serialize, Deserialize)]
struct Model {
    ui: Ui,
    auth: Auth,
}
#[derive(Default, Serialize, Deserialize)]
struct Ui {
    dark: bool,
    compact: bool,
}
#[derive(Default, Serialize, Deserialize)]
struct Auth {
    token: String,
    enabled: bool,
    optional: Option<String>,
}
impl SettingsSchema for Model {
    fn get_metadata() -> rcman::IndexMap<String, SettingMetadata> {
        let mut optional = SettingMetadata::text("").nullable(true).secret();
        optional.default = Value::Null;
        rcman::settings! {
            "ui.dark" => SettingMetadata::toggle(false),
            "ui.compact" => SettingMetadata::toggle(false),
            "auth.token" => SettingMetadata::text("").pattern("^[a-z]*$").secret(),
            "auth.enabled" => SettingMetadata::toggle(false).secret(),
            "auth.optional" => optional,
        }
    }
}

#[derive(Clone, Default)]
struct FailingStorage {
    fail: Arc<AtomicBool>,
    fail_before: Arc<AtomicBool>,
}
impl StorageBackend for FailingStorage {
    fn extension(&self) -> &str {
        "json"
    }
    fn serialize<T: Serialize>(&self, data: &T) -> rcman::Result<String> {
        JsonStorage::default().serialize(data)
    }
    fn deserialize<T: serde::de::DeserializeOwned>(&self, data: &str) -> rcman::Result<T> {
        JsonStorage::default().deserialize(data)
    }
    fn write<T: Serialize>(&self, path: &Path, data: &T) -> rcman::Result<()> {
        if self.fail_before.swap(false, Ordering::SeqCst) {
            return Err(Error::Config("injected failure before write".into()));
        }
        // Fail after mutation to exercise compensation, not just error propagation.
        JsonStorage::default().write(path, data)?;
        if self.fail.swap(false, Ordering::SeqCst) {
            return Err(Error::Config("injected failure after write".into()));
        }
        Ok(())
    }
}

#[test]
fn concurrent_updates_report_conflict_without_losing_the_winner() {
    let dir = tempfile::tempdir().unwrap();
    let manager = SettingsManager::builder("update-conflict", "1")
        .with_config_dir(dir.path())
        .with_schema::<Model>()
        .build()
        .unwrap();
    let barrier = Barrier::new(2);
    std::thread::scope(|scope| {
        let first = scope.spawn(|| {
            manager.update(|model| {
                barrier.wait();
                model.ui.dark = true;
            })
        });
        let second = scope.spawn(|| {
            manager.update(|model| {
                barrier.wait();
                model.ui.compact = true;
            })
        });
        let results = [first.join().unwrap(), second.join().unwrap()];
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|r| matches!(r, Err(Error::ConcurrentModification)))
                .count(),
            1
        );
    });
    let model = manager.get_all().unwrap();
    assert_ne!(model.ui.dark, model.ui.compact);
}

#[test]
fn failed_file_commit_restores_disk_and_cache() {
    let dir = tempfile::tempdir().unwrap();
    let storage = FailingStorage::default();
    let manager = SettingsManager::builder("file-rollback", "1")
        .with_config_dir(dir.path())
        .with_schema::<Model>()
        .with_storage_instance(storage.clone())
        .build()
        .unwrap();
    manager.save_setting("ui", "dark", &json!(true)).unwrap();
    let before = std::fs::read(dir.path().join("settings.json")).unwrap();
    storage.fail.store(true, Ordering::SeqCst);
    assert!(manager.save_setting("ui", "compact", &json!(true)).is_err());
    assert_eq!(
        std::fs::read(dir.path().join("settings.json")).unwrap(),
        before
    );
    assert!(!manager.get::<bool>("ui.compact").unwrap());
    manager.save_setting("ui", "compact", &json!(true)).unwrap();
    assert!(manager.get::<bool>("ui.compact").unwrap());
}

#[test]
fn secret_without_configured_backend_never_reaches_disk() {
    let dir = tempfile::tempdir().unwrap();
    let manager = SettingsManager::builder("missing-credentials", "1")
        .with_config_dir(dir.path())
        .with_schema::<Model>()
        .build()
        .unwrap();
    assert!(
        manager
            .save_setting("auth", "token", &json!("secret"))
            .is_err()
    );
    let mut model = manager.get_all().unwrap();
    model.auth.token = "secret".into();
    assert!(manager.save_all(&model).is_err());
    assert!(!dir.path().join("settings.json").exists());
}

#[test]
fn warmed_reads_do_not_require_the_configuration_directory() {
    let dir = tempfile::tempdir().unwrap();
    let manager = SettingsManager::builder("cached-read", "1")
        .with_config_dir(dir.path())
        .with_schema::<Model>()
        .build()
        .unwrap();
    assert!(!manager.get::<bool>("ui.dark").unwrap());
    std::fs::remove_dir(dir.path()).unwrap();
    assert!(!manager.get::<bool>("ui.dark").unwrap());
}

#[test]
fn regex_cache_respects_mutated_metadata() {
    let mut metadata = SettingMetadata::text("").pattern("^a+$");
    assert!(metadata.validate(&json!("aaa")).is_ok());
    metadata.constraints.text.pattern = Some("^b+$".into());
    assert!(metadata.validate(&json!("aaa")).is_err());
    assert!(metadata.validate(&json!("bbb")).is_ok());
}

#[test]
fn failed_sub_setting_write_can_be_retried_without_false_success() {
    let dir = tempfile::tempdir().unwrap();
    let storage = FailingStorage::default();
    let manager = SettingsManager::builder("sub-rollback", "1")
        .with_config_dir(dir.path())
        .with_storage_instance(storage.clone())
        .with_sub_settings(rcman::SubSettingsConfig::singlefile("items"))
        .build()
        .unwrap();
    let sub = manager.sub_settings("items").unwrap();
    sub.set("one", &json!({"value": 1})).unwrap();
    storage.fail_before.store(true, Ordering::SeqCst);
    assert!(sub.set("one", &json!({"value": 2})).is_err());
    assert_eq!(sub.get_value("one").unwrap(), json!({"value": 1}));
    sub.set("one", &json!({"value": 2})).unwrap();
    sub.invalidate_cache();
    assert_eq!(sub.get_value("one").unwrap(), json!({"value": 2}));
    storage.fail_before.store(true, Ordering::SeqCst);
    assert!(sub.delete("one").is_err());
    assert!(sub.exists("one").unwrap());
    sub.delete("one").unwrap();
    sub.invalidate_cache();
    assert!(!sub.exists("one").unwrap());
}

#[test]
fn update_does_not_persist_environment_overrides() {
    struct Env;
    impl rcman::EnvSource for Env {
        fn var(&self, key: &str) -> Result<String, std::env::VarError> {
            if key == "APP_UI_DARK" {
                Ok("true".into())
            } else {
                Err(std::env::VarError::NotPresent)
            }
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let config = rcman::SettingsConfig::builder("env-update", "1")
        .with_config_dir(dir.path())
        .with_schema::<Model>()
        .with_env_prefix("APP")
        .with_env_source(Arc::new(Env))
        .build();
    let manager = SettingsManager::new(config).unwrap();
    assert!(manager.get_all().unwrap().ui.dark);
    manager.update(|model| model.ui.compact = true).unwrap();
    let stored: Value =
        serde_json::from_str(&std::fs::read_to_string(dir.path().join("settings.json")).unwrap())
            .unwrap();
    assert_eq!(stored, json!({"ui": {"compact": true}}));
    assert!(manager.get::<bool>("ui.dark").unwrap());
}

#[cfg(any(feature = "keychain", feature = "encrypted-file"))]
mod credentials {
    use super::*;
    use rcman::{CredentialBackend, CredentialConfig, MemoryBackend};
    use std::sync::atomic::AtomicUsize;

    #[derive(Default)]
    struct FailingCredentials {
        memory: MemoryBackend,
        fail: AtomicBool,
        fail_read: AtomicBool,
    }
    impl CredentialBackend for FailingCredentials {
        fn store(&self, key: &str, value: &str) -> rcman::Result<()> {
            self.memory.store(key, value)?;
            if key.ends_with(":auth.enabled") && self.fail.swap(false, Ordering::SeqCst) {
                return Err(Error::Credential(
                    "injected failure after credential write".into(),
                ));
            }
            Ok(())
        }
        fn get(&self, key: &str) -> rcman::Result<Option<String>> {
            if key.ends_with(".token") && self.fail_read.load(Ordering::SeqCst) {
                return Err(Error::Credential("injected credential read failure".into()));
            }
            self.memory.get(key)
        }
        fn remove(&self, key: &str) -> rcman::Result<()> {
            self.memory.remove(key)
        }
        fn list_keys(&self) -> rcman::Result<Vec<String>> {
            self.memory.list_keys()
        }
        fn backend_name(&self) -> &'static str {
            "failure-injection"
        }
    }

    #[test]
    fn sub_settings_bulk_reads_propagate_secret_errors() {
        for config in [
            rcman::SubSettingsConfig::new("items"),
            rcman::SubSettingsConfig::singlefile("items"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let backend = Arc::new(FailingCredentials::default());
            let manager = SettingsManager::builder("bulk-secret-errors", "1")
                .with_config_dir(dir.path())
                .with_credential_config(CredentialConfig::Custom(backend.clone()))
                .with_sub_settings(config.with_metadata(rcman::settings! {
                    "host" => SettingMetadata::text("localhost"),
                    "token" => SettingMetadata::text("").secret(),
                }))
                .build()
                .unwrap();
            let sub = manager.sub_settings("items").unwrap();
            sub.set("one", &json!({"host": "first"})).unwrap();
            sub.set("two", &json!({"host": "second"})).unwrap();

            backend.fail_read.store(true, Ordering::SeqCst);
            assert!(
                matches!(sub.get_all_values(), Err(Error::Credential(message))
                if message == "injected credential read failure")
            );

            backend.fail_read.store(false, Ordering::SeqCst);
            let values = sub.get_all_values().unwrap();
            assert_eq!(values.len(), 2);
            assert_eq!(values["one"]["token"], json!(""));

            backend
                .store(
                    "bulk-secret-errors:sub.items.one.token",
                    "\u{1e}rcman:json:1:{",
                )
                .unwrap();
            assert!(matches!(sub.get_all_values(), Err(Error::Serialize(_))));
        }
    }

    #[test]
    fn typed_secrets_survive_update_and_emit_one_event() {
        let dir = tempfile::tempdir().unwrap();
        let manager = SettingsManager::builder("typed-secrets", "1")
            .with_config_dir(dir.path())
            .with_schema::<Model>()
            .with_credential_config(CredentialConfig::Custom(Arc::new(MemoryBackend::new())))
            .build()
            .unwrap();
        manager
            .save_setting("auth", "token", &json!("secret"))
            .unwrap();
        manager
            .save_setting("auth", "optional", &json!("null"))
            .unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&count);
        manager.events().watch("auth.enabled", move |_, _, _| {
            observed.fetch_add(1, Ordering::SeqCst);
        });
        manager
            .update(|model| {
                model.ui.dark = true;
                model.auth.enabled = true;
            })
            .unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert_eq!(manager.get::<String>("auth.token").unwrap(), "secret");
        assert!(manager.get::<bool>("auth.enabled").unwrap());
        assert_eq!(
            manager.get_all().unwrap().auth.optional.as_deref(),
            Some("null")
        );
        manager
            .save_setting("auth", "optional", &Value::Null)
            .unwrap();
        assert!(manager.get_all().unwrap().auth.optional.is_none());
        assert!(
            manager
                .save_setting("auth", "token", &json!("123"))
                .is_err()
        );
        assert!(
            !std::fs::read_to_string(dir.path().join("settings.json"))
                .unwrap()
                .contains("secret")
        );
    }

    #[test]
    fn later_credential_failure_rolls_back_earlier_secret_and_suppresses_events() {
        let dir = tempfile::tempdir().unwrap();
        let backend = Arc::new(FailingCredentials::default());
        let manager = SettingsManager::builder("credential-rollback", "1")
            .with_config_dir(dir.path())
            .with_schema::<Model>()
            .with_credential_config(CredentialConfig::Custom(backend.clone()))
            .build()
            .unwrap();
        manager
            .save_setting("auth", "token", &json!("before"))
            .unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&count);
        manager.events().on_change(move |_, _, _| {
            observed.fetch_add(1, Ordering::SeqCst);
        });
        backend.fail.store(true, Ordering::SeqCst);
        assert!(
            manager
                .update(|model| {
                    model.auth.token = "after".into();
                    model.auth.enabled = true;
                    model.ui.dark = true;
                })
                .is_err()
        );
        assert_eq!(manager.get::<String>("auth.token").unwrap(), "before");
        assert!(!manager.get::<bool>("auth.enabled").unwrap());
        assert!(!manager.get::<bool>("ui.dark").unwrap());
        assert_eq!(count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn file_failure_rolls_back_credentials_and_tracking() {
        let dir = tempfile::tempdir().unwrap();
        let backend = Arc::new(MemoryBackend::new());
        let storage = FailingStorage::default();
        let manager = SettingsManager::builder("combined-rollback", "1")
            .with_config_dir(dir.path())
            .with_schema::<Model>()
            .with_credential_config(CredentialConfig::Custom(backend.clone()))
            .with_storage_instance(storage.clone())
            .build()
            .unwrap();
        manager
            .save_setting("auth", "token", &json!("before"))
            .unwrap();
        storage.fail.store(true, Ordering::SeqCst);
        assert!(
            manager
                .update(|model| {
                    model.auth.token = "after".into();
                    model.ui.dark = true;
                })
                .is_err()
        );
        assert_eq!(manager.get::<String>("auth.token").unwrap(), "before");
        assert_eq!(
            backend
                .get("combined-rollback:auth.token")
                .unwrap()
                .as_deref(),
            Some("before")
        );
        assert!(!manager.get::<bool>("ui.dark").unwrap());
    }
}

#[test]
fn concurrent_sub_field_writes_preserve_both_fields() {
    let dir = tempfile::tempdir().unwrap();
    let manager = SettingsManager::builder("sub-concurrent", "1")
        .with_config_dir(dir.path())
        .with_sub_settings(rcman::SubSettingsConfig::singlefile("items"))
        .build()
        .unwrap();
    let sub = manager.sub_settings("items").unwrap();
    for _ in 0..20 {
        sub.set("one", &json!({})).unwrap();
        let barrier = Barrier::new(2);
        std::thread::scope(|scope| {
            let first = scope.spawn(|| {
                barrier.wait();
                sub.set_field("one", "a", &1).unwrap();
            });
            let second = scope.spawn(|| {
                barrier.wait();
                sub.set_field("one", "b", &2).unwrap();
            });
            first.join().unwrap();
            second.join().unwrap();
        });
        assert_eq!(sub.get_value("one").unwrap(), json!({"a": 1, "b": 2}));
    }
}

#[cfg(feature = "sqlite")]
#[test]
fn failed_sqlite_insert_preserves_other_namespaces() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.db");
    let other = rcman::SqliteStorage::new().with_key("other");
    other.write(&path, &json!({"keep": true})).unwrap();
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection.execute_batch("CREATE TRIGGER fail_main BEFORE INSERT ON rcman_settings WHEN NEW.key = 'main' BEGIN SELECT RAISE(FAIL, 'injected failure'); END;").unwrap();
    let manager = SettingsManager::builder("sqlite-rollback", "1")
        .with_config_dir(dir.path())
        .with_settings_file("settings.db")
        .with_storage_instance(rcman::SqliteStorage::new())
        .with_schema::<Model>()
        .build()
        .unwrap();
    assert!(manager.save_setting("ui", "dark", &json!(true)).is_err());
    assert_eq!(other.read::<Value>(&path).unwrap(), json!({"keep": true}));
}

#[cfg(any(feature = "keychain", feature = "encrypted-file"))]
#[test]
fn sub_secret_and_file_roll_back_together() {
    for config in [
        rcman::SubSettingsConfig::new("items"),
        rcman::SubSettingsConfig::singlefile("items"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let storage = FailingStorage::default();
        let backend = Arc::new(rcman::MemoryBackend::new());
        let manager = SettingsManager::builder("sub-secret-rollback", "1")
            .with_config_dir(dir.path())
            .with_storage_instance(storage.clone())
            .with_credential_config(rcman::CredentialConfig::Custom(backend))
            .with_sub_settings(config.with_metadata(rcman::settings! {
                "host" => SettingMetadata::text(""),
                "token" => SettingMetadata::text("").secret(),
            }))
            .build()
            .unwrap();
        let sub = manager.sub_settings("items").unwrap();
        let original = json!({"host": "before", "token": "original"});
        sub.set("one", &original).unwrap();
        storage.fail.store(true, Ordering::SeqCst);
        assert!(
            sub.set("one", &json!({"host": "after", "token": "changed"}))
                .is_err()
        );
        sub.invalidate_cache();
        assert_eq!(sub.get_value("one").unwrap(), original);
        if sub.is_single_file() {
            storage.fail.store(true, Ordering::SeqCst);
            assert!(sub.delete("one").is_err());
            sub.invalidate_cache();
            assert_eq!(sub.get_value("one").unwrap(), original);
        }
    }
}

#[cfg(any(feature = "keychain", feature = "encrypted-file"))]
#[test]
fn old_secret_outside_current_validation_can_be_replaced() {
    use rcman::CredentialBackend;
    let dir = tempfile::tempdir().unwrap();
    let backend = Arc::new(rcman::MemoryBackend::new());
    backend
        .store("secret-repair:auth.token", "OLD-INVALID")
        .unwrap();
    let manager = SettingsManager::builder("secret-repair", "1")
        .with_config_dir(dir.path())
        .with_schema::<Model>()
        .with_credential_config(rcman::CredentialConfig::Custom(backend))
        .build()
        .unwrap();
    manager
        .save_setting("auth", "token", &json!("valid"))
        .unwrap();
    assert_eq!(manager.get::<String>("auth.token").unwrap(), "valid");
}

#[cfg(any(feature = "keychain", feature = "encrypted-file"))]
#[test]
fn failed_secret_to_plain_migration_keeps_original_credential() {
    use rcman::CredentialBackend;
    let dir = tempfile::tempdir().unwrap();
    let backend = Arc::new(rcman::MemoryBackend::new());
    backend.store("migration-rollback:ui.dark", "true").unwrap();
    backend
        .store("migration-rollback:__rcman_secrets__", "[\"ui.dark\"]")
        .unwrap();
    let storage = FailingStorage::default();
    storage.fail.store(true, Ordering::SeqCst);
    let result = SettingsManager::builder("migration-rollback", "1")
        .with_config_dir(dir.path())
        .with_schema::<Model>()
        .with_storage_instance(storage)
        .with_credential_config(rcman::CredentialConfig::Custom(backend.clone()))
        .build();
    assert!(result.is_err());
    assert_eq!(
        backend
            .get("migration-rollback:ui.dark")
            .unwrap()
            .as_deref(),
        Some("true")
    );
    let manager = SettingsManager::builder("migration-rollback", "1")
        .with_config_dir(dir.path())
        .with_schema::<Model>()
        .with_credential_config(rcman::CredentialConfig::Custom(backend.clone()))
        .build()
        .unwrap();
    assert!(manager.get::<bool>("ui.dark").unwrap());
    assert!(backend.get("migration-rollback:ui.dark").unwrap().is_none());
}

#[cfg(all(feature = "hot-reload", feature = "profiles"))]
#[test]
fn hot_reload_follows_active_profile() {
    use std::time::{Duration, Instant};
    let dir = tempfile::tempdir().unwrap();
    let manager = Arc::new(
        SettingsManager::builder("reload-profile", "1")
            .with_config_dir(dir.path())
            .with_schema::<Model>()
            .with_profiles()
            .build()
            .unwrap(),
    );
    manager.profiles().unwrap().create("other").unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    let mut runtime = rcman::HotReloadRuntime::start(
        manager.clone(),
        rcman::HotReloadConfig {
            debounce_ms: 25,
            poll_interval_ms: 25,
            backend: rcman::HotReloadBackend::Poll,
        },
        move |event| {
            let _ = sender.send(event);
        },
    )
    .unwrap();
    manager.switch_profile("other").unwrap();
    let path = manager
        .profiles()
        .unwrap()
        .profile_path("other")
        .join("settings.json");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        assert!(
            Instant::now() < deadline,
            "watcher did not follow profile switch"
        );
        if let Ok(rcman::HotReloadEvent::Reloaded { path: observed }) =
            receiver.recv_timeout(Duration::from_millis(100))
            && observed == path
        {
            break;
        }
    }
    std::fs::write(&path, r#"{"ui":{"dark":true}}"#).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        assert!(Instant::now() < deadline, "new profile was not reloaded");
        let _ = receiver.recv_timeout(Duration::from_millis(100));
        if manager.get::<bool>("ui.dark").unwrap() {
            break;
        }
    }
    runtime.stop();
}
