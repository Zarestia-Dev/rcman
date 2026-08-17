//! SQLite storage integration tests
//!
//! Exercises the [`SqliteStorage`] backend through the full `SettingsManager`
//! stack: basic CRUD, sub-settings (multi-file and single-file modes), and
//! profile-aware reads/writes. The goal is to verify that the database backend
//! behaves identically to the file-based backends from the caller's
//! perspective.

#![cfg(feature = "sqlite")]

mod common;

use common::TestSettings;
use rcman::{SettingsConfig, SettingsManager, SqliteStorage, StorageBackend, SubSettingsConfig};
use serde_json::json;
use tempfile::TempDir;

// =============================================================================
// Basic CRUD via SettingsManager
// =============================================================================

#[test]
fn sqlite_settings_roundtrip() {
    let temp = TempDir::new().unwrap();
    let config = SettingsConfig::builder("sqlite-app", "1.0.0")
        .with_config_dir(temp.path())
        .with_schema::<TestSettings>()
        .with_storage::<SqliteStorage>()
        .build();

    let manager = SettingsManager::new(config).unwrap();

    // Defaults load successfully
    let _ = manager.get_all().unwrap();

    // Save a non-default setting
    manager
        .save_setting("ui", "theme", &json!("light"))
        .unwrap();
    manager
        .save_setting("ui", "font_size", &json!(18.0))
        .unwrap();

    // The on-disk file is a SQLite database
    let db_path = temp.path().join("settings.db");
    assert!(db_path.exists(), "expected database file at {db_path:?}");

    // SQLite magic header should be present
    let header = std::fs::read(&db_path).unwrap();
    assert!(
        header.starts_with(b"SQLite format 3\0"),
        "file is not a SQLite database"
    );

    // Reload into a fresh manager and verify
    let config2 = SettingsConfig::builder("sqlite-app", "1.0.0")
        .with_config_dir(temp.path())
        .with_schema::<TestSettings>()
        .with_storage::<SqliteStorage>()
        .build();
    let manager2 = SettingsManager::new(config2).unwrap();
    let settings = manager2.get_all().unwrap();
    assert_eq!(settings.ui.theme, "light");
    assert!((settings.ui.font_size - 18.0).abs() < f64::EPSILON);
}

#[test]
fn sqlite_reset_setting_removes_row_value() {
    let temp = TempDir::new().unwrap();
    let config = SettingsConfig::builder("sqlite-app", "1.0.0")
        .with_config_dir(temp.path())
        .with_schema::<TestSettings>()
        .with_storage::<SqliteStorage>()
        .build();
    let manager = SettingsManager::new(config).unwrap();

    manager
        .save_setting("ui", "theme", &json!("light"))
        .unwrap();
    manager.reset_setting("ui", "theme").unwrap();

    // After reset, the effective value should be the default.
    let settings = manager.get_all().unwrap();
    assert_eq!(settings.ui.theme, "dark");
}

// =============================================================================
// Sub-Settings (Multi-File Mode)
// =============================================================================

#[test]
fn sqlite_sub_settings_multi_file() {
    let temp = TempDir::new().unwrap();
    let config = SettingsConfig::builder("sqlite-app", "1.0.0")
        .with_config_dir(temp.path())
        .with_schema::<TestSettings>()
        .with_storage::<SqliteStorage>()
        .build();
    let manager = SettingsManager::new(config).unwrap();
    manager
        .register_sub_settings(SubSettingsConfig::new("remotes"))
        .unwrap();

    let remotes = manager.sub_settings("remotes").unwrap();
    remotes.set("gdrive", &json!({"type": "drive"})).unwrap();
    remotes.set("s3", &json!({"type": "s3"})).unwrap();

    // Each entry becomes its own SQLite file under remotes/
    let gdrive_path = temp.path().join("remotes").join("gdrive.db");
    let s3_path = temp.path().join("remotes").join("s3.db");
    assert!(gdrive_path.exists(), "missing {gdrive_path:?}");
    assert!(s3_path.exists(), "missing {s3_path:?}");

    // Reload and verify
    let config2 = SettingsConfig::builder("sqlite-app", "1.0.0")
        .with_config_dir(temp.path())
        .with_schema::<TestSettings>()
        .with_storage::<SqliteStorage>()
        .build();
    let manager2 = SettingsManager::new(config2).unwrap();
    manager2
        .register_sub_settings(SubSettingsConfig::new("remotes"))
        .unwrap();

    let remotes2 = manager2.sub_settings("remotes").unwrap();
    assert_eq!(remotes2.get_value("gdrive").unwrap()["type"], "drive");
    assert_eq!(remotes2.get_value("s3").unwrap()["type"], "s3");
    assert_eq!(remotes2.list().unwrap().len(), 2);
}

// =============================================================================
// Sub-Settings (Single-File Mode)
// =============================================================================

#[test]
fn sqlite_sub_settings_single_file() {
    let temp = TempDir::new().unwrap();
    let config = SettingsConfig::builder("sqlite-app", "1.0.0")
        .with_config_dir(temp.path())
        .with_schema::<TestSettings>()
        .with_storage::<SqliteStorage>()
        .build();
    let manager = SettingsManager::new(config).unwrap();
    manager
        .register_sub_settings(SubSettingsConfig::singlefile("backends"))
        .unwrap();

    let backends = manager.sub_settings("backends").unwrap();
    backends.set("fs", &json!({"path": "/tmp"})).unwrap();
    backends.set("s3", &json!({"bucket": "x"})).unwrap();

    // All entries live in a single `backends.db` file
    let db_path = temp.path().join("backends.db");
    assert!(db_path.exists(), "missing {db_path:?}");

    // Reload and verify
    let config2 = SettingsConfig::builder("sqlite-app", "1.0.0")
        .with_config_dir(temp.path())
        .with_schema::<TestSettings>()
        .with_storage::<SqliteStorage>()
        .build();
    let manager2 = SettingsManager::new(config2).unwrap();
    manager2
        .register_sub_settings(SubSettingsConfig::singlefile("backends"))
        .unwrap();

    let backends2 = manager2.sub_settings("backends").unwrap();
    assert_eq!(backends2.get_value("fs").unwrap()["path"], "/tmp");
    assert_eq!(backends2.get_value("s3").unwrap()["bucket"], "x");
    assert_eq!(backends2.list().unwrap().len(), 2);
}

// =============================================================================
// Direct StorageBackend usage (no SettingsManager)
// =============================================================================

#[test]
fn sqlite_backend_extension() {
    let storage = SqliteStorage::new();
    assert_eq!(storage.extension(), "db");
}

#[test]
fn sqlite_storage_getters() {
    let storage = SqliteStorage::new()
        .with_table("custom_table")
        .with_key("custom_key");

    assert_eq!(storage.table_name(), "custom_table");
    assert_eq!(storage.key(), "custom_key");
}

#[test]
fn sqlite_backend_custom_key_shares_database() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("shared.db");

    let alpha = SqliteStorage::new().with_key("alpha");
    let beta = SqliteStorage::new().with_key("beta");

    let payload_a = serde_json::json!({"who": "alpha", "n": 1});
    let payload_b = serde_json::json!({"who": "beta", "n": 2});

    alpha.write(&path, &payload_a).unwrap();
    beta.write(&path, &payload_b).unwrap();

    let a: serde_json::Value = alpha.read(&path).unwrap();
    let b: serde_json::Value = beta.read(&path).unwrap();
    assert_eq!(a["who"], "alpha");
    assert_eq!(b["who"], "beta");
}

#[test]
fn sqlite_settings_manager_custom_table_and_key() {
    let temp = TempDir::new().unwrap();
    let storage = SqliteStorage::new()
        .with_table("my_app_settings")
        .with_key("v1_config");

    let manager = SettingsManager::builder("sqlite-app", "1.0.0")
        .with_config_dir(temp.path())
        .with_schema::<TestSettings>()
        .with_storage_instance(storage)
        .build()
        .unwrap();

    manager
        .save_setting("ui", "theme", &json!("light"))
        .unwrap();

    // Verify settings via manager
    let settings = manager.get_all().unwrap();
    assert_eq!(settings.ui.theme, "light");

    let db_path = temp.path().join("settings.db");
    assert!(db_path.exists());

    // Inspect database directly using rusqlite
    let conn = rusqlite::Connection::open(&db_path).unwrap();

    // Table `my_app_settings` exists and contains row with key `v1_config`
    let data: String = conn
        .query_row(
            "SELECT data FROM my_app_settings WHERE key = ?1",
            rusqlite::params!["v1_config"],
            |row| row.get(0),
        )
        .unwrap();

    let parsed: serde_json::Value = serde_json::from_str(&data).unwrap();
    assert_eq!(parsed["ui"]["theme"], "light");

    // Ensure default table `rcman_settings` was NOT created
    let default_table_exists: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='rcman_settings'",
            [],
            |row| row.get::<_, i64>(0).map(|c| c > 0),
        )
        .unwrap();
    assert!(!default_table_exists);
}

#[test]
fn sqlite_settings_manager_database_sharing_different_keys() {
    let temp = TempDir::new().unwrap();

    let storage_auth = SqliteStorage::new().with_key("auth");
    let storage_ui = SqliteStorage::new().with_key("ui");

    let manager_auth = SettingsManager::builder("shared-app", "1.0.0")
        .with_config_dir(temp.path())
        .with_settings_file("shared_config.db")
        .with_schema::<TestSettings>()
        .with_storage_instance(storage_auth)
        .build()
        .unwrap();

    let manager_ui = SettingsManager::builder("shared-app", "1.0.0")
        .with_config_dir(temp.path())
        .with_settings_file("shared_config.db")
        .with_schema::<TestSettings>()
        .with_storage_instance(storage_ui)
        .build()
        .unwrap();

    manager_auth
        .save_setting("ui", "theme", &json!("light"))
        .unwrap();
    manager_ui
        .save_setting("ui", "theme", &json!("system"))
        .unwrap();

    // Verify both retain their respective values from the same database file
    assert_eq!(manager_auth.get_all().unwrap().ui.theme, "light");
    assert_eq!(manager_ui.get_all().unwrap().ui.theme, "system");

    // Re-instantiate both to verify persistence
    let storage_auth_reloaded = SqliteStorage::new().with_key("auth");
    let storage_ui_reloaded = SqliteStorage::new().with_key("ui");

    let manager_auth2 = SettingsManager::builder("shared-app", "1.0.0")
        .with_config_dir(temp.path())
        .with_settings_file("shared_config.db")
        .with_schema::<TestSettings>()
        .with_storage_instance(storage_auth_reloaded)
        .build()
        .unwrap();

    let manager_ui2 = SettingsManager::builder("shared-app", "1.0.0")
        .with_config_dir(temp.path())
        .with_settings_file("shared_config.db")
        .with_schema::<TestSettings>()
        .with_storage_instance(storage_ui_reloaded)
        .build()
        .unwrap();

    assert_eq!(manager_auth2.get_all().unwrap().ui.theme, "light");
    assert_eq!(manager_ui2.get_all().unwrap().ui.theme, "system");
}

#[test]
fn sqlite_settings_manager_database_sharing_different_tables() {
    let temp = TempDir::new().unwrap();

    let storage_a = SqliteStorage::new().with_table("table_a");
    let storage_b = SqliteStorage::new().with_table("table_b");

    let manager_a = SettingsManager::builder("shared-app", "1.0.0")
        .with_config_dir(temp.path())
        .with_settings_file("multi_table.db")
        .with_schema::<TestSettings>()
        .with_storage_instance(storage_a)
        .build()
        .unwrap();

    let manager_b = SettingsManager::builder("shared-app", "1.0.0")
        .with_config_dir(temp.path())
        .with_settings_file("multi_table.db")
        .with_schema::<TestSettings>()
        .with_storage_instance(storage_b)
        .build()
        .unwrap();

    manager_a
        .save_setting("ui", "font_size", &json!(18.0))
        .unwrap();
    manager_b
        .save_setting("ui", "font_size", &json!(22.0))
        .unwrap();

    assert_eq!(manager_a.get_all().unwrap().ui.font_size, 18.0);
    assert_eq!(manager_b.get_all().unwrap().ui.font_size, 22.0);

    // Direct SQLite check: both tables exist in multi_table.db
    let db_path = temp.path().join("multi_table.db");
    let conn = rusqlite::Connection::open(&db_path).unwrap();

    let count_a: i64 = conn
        .query_row("SELECT COUNT(*) FROM table_a", [], |row| row.get(0))
        .unwrap();
    let count_b: i64 = conn
        .query_row("SELECT COUNT(*) FROM table_b", [], |row| row.get(0))
        .unwrap();

    assert_eq!(count_a, 1);
    assert_eq!(count_b, 1);
}

// =============================================================================
// Sub-Settings (Table Mode)
// =============================================================================

#[test]
fn sqlite_sub_settings_table_mode_basic_crud() {
    let temp = TempDir::new().unwrap();
    let manager = SettingsManager::builder("sqlite-app", "1.0.0")
        .with_config_dir(temp.path())
        .with_schema::<TestSettings>()
        .with_storage::<SqliteStorage>()
        .with_sub_settings(SubSettingsConfig::table("remotes"))
        .build()
        .unwrap();

    let remotes = manager.sub_settings("remotes").unwrap();
    assert!(remotes.is_table());

    // Insert entries
    remotes
        .set("s3", &json!({"bucket": "my-bucket", "region": "us-east-1"}))
        .unwrap();
    remotes
        .set("gdrive", &json!({"client_id": "abc", "root": "/folder"}))
        .unwrap();
    remotes.set("dropbox", &json!({"token": "xyz"})).unwrap();

    // Verify get
    let s3 = remotes.get_value("s3").unwrap();
    assert_eq!(s3["bucket"], "my-bucket");

    // Verify exists
    assert!(remotes.exists("s3").unwrap());
    assert!(remotes.exists("gdrive").unwrap());
    assert!(!remotes.exists("ftp").unwrap());

    // Verify list
    let list = remotes.list().unwrap();
    assert_eq!(list, vec!["dropbox", "gdrive", "s3"]);

    // Verify get_all
    let all = remotes.get_all_values().unwrap();
    assert_eq!(all.len(), 3);
    assert_eq!(all["dropbox"]["token"], "xyz");

    // Update an entry
    remotes
        .set(
            "s3",
            &json!({"bucket": "updated-bucket", "region": "us-west-2"}),
        )
        .unwrap();
    assert_eq!(remotes.get_value("s3").unwrap()["bucket"], "updated-bucket");

    // Delete an entry
    remotes.delete("dropbox").unwrap();
    assert!(!remotes.exists("dropbox").unwrap());
    assert_eq!(remotes.list().unwrap().len(), 2);

    // Direct SQLite check on the generated `remotes.db` file
    let db_path = temp.path().join("remotes.db");
    assert!(db_path.exists());

    let conn = rusqlite::Connection::open(&db_path).unwrap();
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM remotes", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 2);

    // Reload in fresh manager
    let manager2 = SettingsManager::builder("sqlite-app", "1.0.0")
        .with_config_dir(temp.path())
        .with_schema::<TestSettings>()
        .with_storage::<SqliteStorage>()
        .with_sub_settings(SubSettingsConfig::table("remotes"))
        .build()
        .unwrap();

    let remotes2 = manager2.sub_settings("remotes").unwrap();
    assert_eq!(
        remotes2.get_value("s3").unwrap()["bucket"],
        "updated-bucket"
    );
    assert_eq!(remotes2.get_value("gdrive").unwrap()["root"], "/folder");
    assert_eq!(remotes2.list().unwrap().len(), 2);
}

#[test]
fn sqlite_sub_settings_table_mode_custom_table_name() {
    let temp = TempDir::new().unwrap();
    let manager = SettingsManager::builder("sqlite-app", "1.0.0")
        .with_config_dir(temp.path())
        .with_schema::<TestSettings>()
        .with_storage::<SqliteStorage>()
        .with_sub_settings(SubSettingsConfig::table("connections").with_table("active_connections"))
        .build()
        .unwrap();

    let connections = manager.sub_settings("connections").unwrap();
    connections
        .set("primary", &json!({"host": "10.0.0.1", "port": 5432}))
        .unwrap();

    assert_eq!(
        connections.get_value("primary").unwrap()["host"],
        "10.0.0.1"
    );

    // Check direct SQLite DB
    let db_path = temp.path().join("connections.db");
    let conn = rusqlite::Connection::open(&db_path).unwrap();

    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM active_connections", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(count, 1);

    // Default table name `connections` was not created
    let default_exists: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='connections'",
            [],
            |row| row.get::<_, i64>(0).map(|c| c > 0),
        )
        .unwrap();
    assert!(!default_exists);
}

#[test]
fn sqlite_sub_settings_table_mode_migrator() {
    let temp = TempDir::new().unwrap();
    let db_path = temp.path().join("services.db");

    // Pre-populate SQLite table with an older unmigrated record
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    conn.execute(
        "CREATE TABLE services (key TEXT PRIMARY KEY NOT NULL, data TEXT NOT NULL)",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO services (key, data) VALUES (?1, ?2)",
        rusqlite::params!["auth_service", r#"{"host": "auth.local"}"#],
    )
    .unwrap();
    drop(conn);

    let config = SubSettingsConfig::table("services").with_migrator(|mut val| {
        if let Some(obj) = val.as_object_mut()
            && !obj.contains_key("version")
        {
            obj.insert("version".to_string(), json!(1));
        }
        val
    });

    let manager = SettingsManager::builder("sqlite-app", "1.0.0")
        .with_config_dir(temp.path())
        .with_schema::<TestSettings>()
        .with_storage::<SqliteStorage>()
        .with_sub_settings(config)
        .build()
        .unwrap();

    let services = manager.sub_settings("services").unwrap();

    // On get, migration should be applied
    let val = services.get_value("auth_service").unwrap();
    assert_eq!(val["version"], 1);
    assert_eq!(val["host"], "auth.local");

    // Verify it was persisted back to SQLite
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    let raw: String = conn
        .query_row(
            "SELECT data FROM services WHERE key = 'auth_service'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(parsed["version"], 1);
}

#[test]
fn sqlite_sub_settings_table_mode_caching_strategies() {
    let temp = TempDir::new().unwrap();

    // LRU Cache
    let lru_sub = SubSettingsConfig::table("lru_items").with_lru_cache(2);
    // No Cache
    let no_cache_sub = SubSettingsConfig::table("no_cache_items").with_no_cache();

    let manager = SettingsManager::builder("sqlite-app", "1.0.0")
        .with_config_dir(temp.path())
        .with_schema::<TestSettings>()
        .with_storage::<SqliteStorage>()
        .with_sub_settings(lru_sub)
        .with_sub_settings(no_cache_sub)
        .build()
        .unwrap();

    let lru = manager.sub_settings("lru_items").unwrap();
    lru.set("item1", &json!({"val": 1})).unwrap();
    lru.set("item2", &json!({"val": 2})).unwrap();
    lru.set("item3", &json!({"val": 3})).unwrap();

    assert_eq!(lru.get_value("item1").unwrap()["val"], 1);
    assert_eq!(lru.get_value("item2").unwrap()["val"], 2);
    assert_eq!(lru.get_value("item3").unwrap()["val"], 3);

    let no_cache = manager.sub_settings("no_cache_items").unwrap();
    no_cache.set("item1", &json!({"val": 10})).unwrap();
    assert_eq!(no_cache.get_value("item1").unwrap()["val"], 10);
}

#[test]
fn sqlite_sub_settings_table_mode_profiles() {
    let temp = TempDir::new().unwrap();
    let sub = SubSettingsConfig::table("servers").with_profiles();

    let manager = SettingsManager::builder("sqlite-app", "1.0.0")
        .with_config_dir(temp.path())
        .with_schema::<TestSettings>()
        .with_storage::<SqliteStorage>()
        .with_sub_settings(sub)
        .build()
        .unwrap();

    let servers = manager.sub_settings("servers").unwrap();

    // Default profile
    servers
        .set("web", &json!({"host": "default.local"}))
        .unwrap();
    assert_eq!(servers.get_value("web").unwrap()["host"], "default.local");

    // Create and switch to work profile
    servers.profiles().unwrap().create("work").unwrap();
    servers.switch_profile("work").unwrap();
    assert!(!servers.exists("web").unwrap());
    servers.set("web", &json!({"host": "work.local"})).unwrap();
    assert_eq!(servers.get_value("web").unwrap()["host"], "work.local");

    // Switch back to default profile
    servers.switch_profile("default").unwrap();
    assert_eq!(servers.get_value("web").unwrap()["host"], "default.local");
}
