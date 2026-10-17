//! Regressions for secret preparation, profile migration, and SQLite identities.
#![cfg(feature = "vault")]

use rcman::{
    Argon2Preset, Error, IndexMap, SettingMetadata, SettingsManager, SettingsSchema,
    SubSettingsConfig,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Default, Serialize, Deserialize)]
struct Schema {
    ui: Ui,
}
#[derive(Default, Serialize, Deserialize)]
struct Ui {
    theme: String,
}
impl SettingsSchema for Schema {
    fn get_metadata() -> IndexMap<String, SettingMetadata> {
        [("ui.theme".into(), SettingMetadata::text(""))].into()
    }
}

#[derive(Default, Serialize, Deserialize)]
struct SecretSchema {
    ui: Ui,
}
impl SettingsSchema for SecretSchema {
    fn get_metadata() -> IndexMap<String, SettingMetadata> {
        [("ui.theme".into(), SettingMetadata::text("").secret())].into()
    }
}

#[derive(Default, Serialize, Deserialize)]
struct SecretEntry {
    token: String,
}
impl SettingsSchema for SecretEntry {
    fn get_metadata() -> IndexMap<String, SettingMetadata> {
        [("token".into(), SettingMetadata::text("").secret())].into()
    }
}

#[cfg(any(feature = "keychain", feature = "encrypted-file"))]
fn credentials() -> rcman::CredentialConfig {
    rcman::CredentialConfig::Custom(std::sync::Arc::new(rcman::MemoryBackend::new()))
}

#[cfg(any(feature = "keychain", feature = "encrypted-file"))]
#[test]
fn normalizers_cannot_erase_extracted_secrets_or_block_vault_disable() {
    let dir = tempfile::tempdir().unwrap();
    let initial = SettingsManager::builder("defaults", "1")
        .with_config_dir(dir.path())
        .with_schema::<Schema>()
        .with_vault_password("password")
        .with_vault_preset(Argon2Preset::Fast)
        .with_sub_settings(SubSettingsConfig::singlefile("items"))
        .build()
        .unwrap();
    initial
        .save_setting("ui", "theme", &json!("main-private"))
        .unwrap();
    initial
        .sub_settings("items")
        .unwrap()
        .set("one", &json!({"token":"sub-private", "host":"example"}))
        .unwrap();
    drop(initial);
    let manager = SettingsManager::builder("defaults", "1")
        .with_config_dir(dir.path())
        .with_schema::<SecretSchema>()
        .with_credential_config(credentials())
        .with_migrator(|mut value| {
            if value.get("ui").is_none() {
                value["ui"] = json!({"theme":""});
            }
            value
        })
        .with_sub_settings(
            SubSettingsConfig::singlefile("items")
                .with_schema::<SecretEntry>()
                .with_migrator(|mut value| {
                    if let Some(entries) = value.as_object_mut() {
                        for entry in entries.values_mut() {
                            if entry.get("token").is_none() {
                                entry["token"] = json!("");
                            }
                        }
                    }
                    value
                }),
        )
        .with_vault_password("password")
        .build()
        .unwrap();
    manager.disable_vault("password").unwrap();
    let main: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("settings.json")).unwrap()).unwrap();
    let sub: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("items.json")).unwrap()).unwrap();
    assert!(main.get("ui").is_none());
    assert!(sub["one"].get("token").is_none());
    assert_eq!(manager.get_value("ui.theme").unwrap(), "main-private");
    assert_eq!(
        manager
            .sub_settings("items")
            .unwrap()
            .get_value("one")
            .unwrap()["token"],
        "sub-private"
    );
}

#[cfg(all(feature = "sqlite", feature = "profiles"))]
#[test]
fn sqlite_profile_rebinding_preserves_unrelated_typed_rows() {
    let dir = tempfile::tempdir().unwrap();
    let manager = SettingsManager::builder("sqlite-copy", "1")
        .with_config_dir(dir.path())
        .with_schema::<Schema>()
        .with_storage::<rcman::SqliteStorage>()
        .with_profiles()
        .with_vault_password("password")
        .with_vault_preset(Argon2Preset::Fast)
        .build()
        .unwrap();
    manager
        .save_setting("ui", "theme", &json!("private"))
        .unwrap();
    let connection =
        rusqlite::Connection::open(dir.path().join("profiles/default/settings.db")).unwrap();
    connection.execute_batch("CREATE TABLE unrelated_cache (key INTEGER PRIMARY KEY, data BLOB); INSERT INTO unrelated_cache VALUES (1, X'01AB'), (2, 'plain text'), (3, '{\"value\":1}');").unwrap();
    drop(connection);
    let profiles = manager.profiles().unwrap();
    profiles.duplicate("default", "copy").unwrap();
    profiles.switch("copy").unwrap();
    assert_eq!(manager.get_value("ui.theme").unwrap(), "private");
    profiles.rename("copy", "renamed").unwrap();
    assert_eq!(manager.get_value("ui.theme").unwrap(), "private");
    let connection =
        rusqlite::Connection::open(dir.path().join("profiles/renamed/settings.db")).unwrap();
    let value: Vec<u8> = connection
        .query_row("SELECT data FROM unrelated_cache WHERE key=1", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(value, [1, 171]);
    let value: String = connection
        .query_row("SELECT data FROM unrelated_cache WHERE key=2", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(value, "plain text");
    assert_eq!(
        connection
            .query_row("SELECT count(*) FROM unrelated_cache", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        3
    );
}

#[cfg(feature = "profiles")]
#[test]
fn main_profile_migration_preserves_foreign_ciphertext_at_destination() {
    let source = tempfile::tempdir().unwrap();
    let foreign = tempfile::tempdir().unwrap();
    let other = SettingsManager::builder("foreign", "1")
        .with_config_dir(foreign.path())
        .with_schema::<Schema>()
        .with_profiles()
        .with_vault_password("password")
        .with_vault_preset(Argon2Preset::Fast)
        .build()
        .unwrap();
    other
        .save_setting("ui", "theme", &json!("foreign-private"))
        .unwrap();
    let original = std::fs::read(foreign.path().join("profiles/default/settings.json")).unwrap();
    let destination = source.path().join("profiles/default/settings.json");
    std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
    std::fs::write(&destination, &original).unwrap();
    std::fs::write(
        source.path().join("settings.json"),
        r#"{"ui":{"theme":"source"}}"#,
    )
    .unwrap();
    assert!(
        SettingsManager::builder("local", "1")
            .with_config_dir(source.path())
            .with_schema::<Schema>()
            .with_profiles()
            .with_vault_password("password")
            .with_vault_preset(Argon2Preset::Fast)
            .build()
            .is_err()
    );
    assert_eq!(std::fs::read(destination).unwrap(), original);
    assert!(source.path().join("settings.json").exists());
}

#[cfg(any(feature = "keychain", feature = "encrypted-file"))]
#[test]
fn locked_disable_migrates_new_secrets_before_writing_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    let first = SettingsManager::builder("audit", "1")
        .with_config_dir(dir.path())
        .with_schema::<Schema>()
        .with_vault_password("password")
        .with_vault_preset(Argon2Preset::Fast)
        .with_sub_settings(SubSettingsConfig::singlefile("connections"))
        .build()
        .unwrap();
    first
        .save_setting("ui", "theme", &json!("main-secret"))
        .unwrap();
    first
        .sub_settings("connections")
        .unwrap()
        .set("one", &json!({"token":"sub-secret", "host":"example"}))
        .unwrap();
    drop(first);

    let manager = SettingsManager::builder("audit", "2")
        .with_config_dir(dir.path())
        .with_schema::<SecretSchema>()
        .with_credential_config(credentials())
        .with_sub_settings(
            SubSettingsConfig::singlefile("connections").with_schema::<SecretEntry>(),
        )
        .build()
        .unwrap();
    assert!(manager.is_locked());
    manager.disable_vault("password").unwrap();
    assert!(!manager.is_vault_enabled());
    let main = std::fs::read_to_string(dir.path().join("settings.json")).unwrap();
    let sub = std::fs::read_to_string(dir.path().join("connections.json")).unwrap();
    assert!(!main.contains("main-secret"));
    assert!(!sub.contains("sub-secret"));
    assert_eq!(manager.get_value("ui.theme").unwrap(), "main-secret");
    assert_eq!(
        manager
            .sub_settings("connections")
            .unwrap()
            .get_value("one")
            .unwrap()["token"],
        "sub-secret"
    );
}

#[test]
fn failed_disable_preserves_lock_and_damaged_file() {
    let dir = tempfile::tempdir().unwrap();
    let manager = SettingsManager::builder("audit", "1")
        .with_config_dir(dir.path())
        .with_schema::<Schema>()
        .with_vault_password("password")
        .with_vault_preset(Argon2Preset::Fast)
        .with_sub_settings(SubSettingsConfig::new("connections"))
        .build()
        .unwrap();
    manager
        .save_setting("ui", "theme", &json!("private"))
        .unwrap();
    let sub = manager.sub_settings("connections").unwrap();
    sub.set("one", &json!({"host":"example"})).unwrap();
    manager.lock().unwrap();
    let path = dir.path().join("connections/one.json");
    std::fs::write(&path, b"{broken}").unwrap();
    assert!(manager.disable_vault("password").is_err());
    assert!(manager.is_locked());
    assert!(matches!(
        manager.get_value("ui.theme"),
        Err(Error::ConfigLocked)
    ));
    assert_eq!(std::fs::read(path).unwrap(), b"{broken}");
}

#[test]
fn disabled_credentials_cannot_expose_pending_main_or_sub_secrets() {
    for sub_secret in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let first = SettingsManager::builder("audit", "1")
            .with_config_dir(dir.path())
            .with_schema::<Schema>()
            .with_vault_password("password")
            .with_vault_preset(Argon2Preset::Fast)
            .with_sub_settings(SubSettingsConfig::singlefile("connections"))
            .build()
            .unwrap();
        if sub_secret {
            first
                .sub_settings("connections")
                .unwrap()
                .set("one", &json!({"token":"private"}))
                .unwrap();
        } else {
            first
                .save_setting("ui", "theme", &json!("private"))
                .unwrap();
        }
        drop(first);
        let manager = SettingsManager::builder("audit", "2")
            .with_config_dir(dir.path())
            .with_schema::<SecretSchema>()
            .with_sub_settings(
                SubSettingsConfig::singlefile("connections").with_schema::<SecretEntry>(),
            )
            .build()
            .unwrap();
        assert!(matches!(
            manager.disable_vault("password"),
            Err(Error::Credential(_))
        ));
        assert!(manager.is_locked());
        assert!(manager.is_vault_enabled());
        for file in ["settings.json", "connections.json"] {
            if let Ok(content) = std::fs::read_to_string(dir.path().join(file)) {
                assert!(!content.contains("private"));
                assert!(content.contains("__rcman_vault__"));
            }
        }
    }
}

#[cfg(any(feature = "keychain", feature = "encrypted-file"))]
#[test]
fn main_schema_migration_precedes_secret_extraction() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("settings.json"),
        br#"{"ui":{"old_theme":"private"}}"#,
    )
    .unwrap();
    let manager = SettingsManager::builder("audit", "2")
        .with_config_dir(dir.path())
        .with_schema::<SecretSchema>()
        .with_credential_config(credentials())
        .with_migrator(|mut value| {
            if let Some(old) = value["ui"]
                .as_object_mut()
                .and_then(|ui| ui.remove("old_theme"))
            {
                value["ui"]["theme"] = old;
            }
            value
        })
        .with_vault_password("password")
        .with_vault_preset(Argon2Preset::Fast)
        .build()
        .unwrap();
    assert_eq!(manager.get_value("ui.theme").unwrap(), "private");
    assert_eq!(
        manager.credentials().unwrap().get("ui.theme").unwrap(),
        Some("private".into())
    );
    manager.disable_vault("password").unwrap();
    assert!(
        !std::fs::read_to_string(dir.path().join("settings.json"))
            .unwrap()
            .contains("private")
    );
}

#[cfg(all(
    feature = "profiles",
    any(feature = "keychain", feature = "encrypted-file")
))]
#[test]
fn secret_migration_covers_inactive_main_profiles_without_switching() {
    let dir = tempfile::tempdir().unwrap();
    let first = SettingsManager::builder("audit", "1")
        .with_config_dir(dir.path())
        .with_schema::<Schema>()
        .with_profiles()
        .with_vault_password("password")
        .with_vault_preset(Argon2Preset::Fast)
        .build()
        .unwrap();
    first
        .save_setting("ui", "theme", &json!("default-private"))
        .unwrap();
    first.create_profile("work").unwrap();
    first.switch_profile("work").unwrap();
    first
        .save_setting("ui", "theme", &json!("work-private"))
        .unwrap();
    drop(first);
    let manager = SettingsManager::builder("audit", "2")
        .with_config_dir(dir.path())
        .with_schema::<SecretSchema>()
        .with_profiles()
        .with_credential_config(credentials())
        .with_vault_password("password")
        .build()
        .unwrap();
    manager.disable_vault("password").unwrap();
    assert_eq!(manager.active_profile().unwrap(), "work");
    for profile in ["default", "work"] {
        let raw =
            std::fs::read_to_string(dir.path().join(format!("profiles/{profile}/settings.json")))
                .unwrap();
        assert!(!raw.contains("private"));
        assert_eq!(
            manager
                .credentials()
                .unwrap()
                .get_with_profile("ui.theme", Some(profile))
                .unwrap(),
            Some(format!("{profile}-private"))
        );
    }
}

#[cfg(feature = "profiles")]
#[test]
fn main_profile_migration_preserves_independent_stores_and_custom_filename() {
    for filename in ["custom.json", "custom"] {
        let dir = tempfile::tempdir().unwrap();
        let first = SettingsManager::builder("audit", "1")
            .with_config_dir(dir.path())
            .with_settings_file(filename)
            .with_schema::<Schema>()
            .with_sub_settings(SubSettingsConfig::new("connections"))
            .with_sub_settings(SubSettingsConfig::singlefile("alerts/rules"))
            .build()
            .unwrap();
        first.save_setting("ui", "theme", &json!("dark")).unwrap();
        first
            .sub_settings("connections")
            .unwrap()
            .set("one", &json!({"host":"private-host"}))
            .unwrap();
        first
            .sub_settings("alerts/rules")
            .unwrap()
            .set("one", &json!({"enabled":true}))
            .unwrap();
        drop(first);
        let manager = SettingsManager::builder("audit", "2")
            .with_config_dir(dir.path())
            .with_settings_file(filename)
            .with_schema::<Schema>()
            .with_profiles()
            .with_vault_password("password")
            .with_vault_preset(Argon2Preset::Fast)
            .with_sub_settings(SubSettingsConfig::new("connections"))
            .with_sub_settings(SubSettingsConfig::singlefile("alerts/rules"))
            .build()
            .unwrap();
        assert_eq!(manager.get_value("ui.theme").unwrap(), "dark");
        assert_eq!(
            manager
                .sub_settings("connections")
                .unwrap()
                .get_value("one")
                .unwrap()["host"],
            "private-host"
        );
        assert_eq!(
            manager
                .sub_settings("alerts/rules")
                .unwrap()
                .get_value("one")
                .unwrap()["enabled"],
            true
        );
        for file in [
            format!("profiles/default/{filename}"),
            "connections/one.json".into(),
            "alerts/rules.json".into(),
        ] {
            let raw = std::fs::read_to_string(dir.path().join(file)).unwrap();
            assert!(raw.contains("__rcman_vault__"));
            assert!(!raw.contains("private-host"));
        }
        assert!(!dir.path().join("profiles/default/connections").exists());
        assert!(!dir.path().join("profiles/default/alerts").exists());
    }
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_rejects_ciphertext_transplanted_between_rows_or_tables() {
    for separate_table in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let a_storage = rcman::SqliteStorage::new()
            .with_table("alpha")
            .with_key("first");
        let b_table = if separate_table { "beta" } else { "alpha" };
        let b_key = if separate_table { "first" } else { "second" };
        let a = SettingsManager::builder("audit", "1")
            .with_config_dir(dir.path())
            .with_storage_instance(a_storage)
            .with_schema::<Schema>()
            .with_vault_password("password")
            .with_vault_preset(Argon2Preset::Fast)
            .build()
            .unwrap();
        a.save_setting("ui", "theme", &json!("alpha-theme"))
            .unwrap();
        let b = SettingsManager::builder("audit", "1")
            .with_config_dir(dir.path())
            .with_storage_instance(
                rcman::SqliteStorage::new()
                    .with_table(b_table)
                    .with_key(b_key),
            )
            .with_schema::<Schema>()
            .with_vault_password("password")
            .build()
            .unwrap();
        b.save_setting("ui", "theme", &json!("beta-theme")).unwrap();
        let conn = rusqlite::Connection::open(dir.path().join("settings.db")).unwrap();
        conn.execute(
            &format!(
                "UPDATE {b_table} SET data=(SELECT data FROM alpha WHERE key='first') WHERE key=?1"
            ),
            [b_key],
        )
        .unwrap();
        b.invalidate_cache();
        assert!(matches!(
            b.get_value("ui.theme"),
            Err(Error::VaultDataAuthenticationFailed(_))
        ));
    }
}

#[cfg(all(feature = "sqlite", feature = "profiles"))]
#[test]
fn sqlite_profile_migration_reads_wal_and_preserves_unrelated_rows() {
    use rcman::{SqliteStorage, StorageBackend};
    let dir = tempfile::tempdir().unwrap();
    let first = SettingsManager::builder("audit", "1")
        .with_config_dir(dir.path())
        .with_storage::<SqliteStorage>()
        .with_schema::<Schema>()
        .build()
        .unwrap();
    first
        .save_setting("ui", "theme", &json!("old-theme"))
        .unwrap();
    drop(first);
    let source = dir.path().join("settings.db");
    let conn = rusqlite::Connection::open(&source).unwrap();
    conn.execute_batch("PRAGMA journal_mode=WAL").unwrap();
    conn.execute(
        "UPDATE rcman_settings SET data=?1 WHERE key='main'",
        [json!({"ui":{"theme":"wal-theme"}}).to_string()],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO rcman_settings VALUES ('other', ?1)",
        [json!({"unrelated":true}).to_string()],
    )
    .unwrap();
    conn.execute_batch("BEGIN; SELECT * FROM rcman_settings")
        .unwrap();
    assert!(dir.path().join("settings.db-wal").exists());
    let manager = SettingsManager::builder("audit", "2")
        .with_config_dir(dir.path())
        .with_storage::<SqliteStorage>()
        .with_schema::<Schema>()
        .with_profiles()
        .with_vault_password("password")
        .with_vault_preset(Argon2Preset::Fast)
        .build()
        .unwrap();
    assert_eq!(manager.get_value("ui.theme").unwrap(), "wal-theme");
    let unrelated: serde_json::Value = SqliteStorage::new()
        .with_key("other")
        .read(&source)
        .unwrap();
    assert_eq!(unrelated, json!({"unrelated":true}));
}

#[test]
fn disabled_credentials_cannot_expose_secrets_renamed_by_migrators() {
    for sub_secret in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        if !sub_secret {
            std::fs::write(
                dir.path().join("settings.json"),
                br#"{"ui":{"old_theme":"private"}}"#,
            )
            .unwrap();
        }
        let first = SettingsManager::builder("audit", "1")
            .with_config_dir(dir.path())
            .with_vault_password("password")
            .with_vault_preset(Argon2Preset::Fast)
            .with_sub_settings(SubSettingsConfig::singlefile("connections"))
            .build()
            .unwrap();
        if sub_secret {
            first
                .sub_settings("connections")
                .unwrap()
                .set("one", &json!({"old_token":"private"}))
                .unwrap();
        }
        drop(first);
        let manager = SettingsManager::builder("audit", "2")
            .with_config_dir(dir.path())
            .with_schema::<SecretSchema>()
            .with_migrator(|mut value| {
                if let Some(old) = value["ui"]
                    .as_object_mut()
                    .and_then(|ui| ui.remove("old_theme"))
                {
                    value["ui"]["theme"] = old;
                }
                value
            })
            .with_sub_settings(
                SubSettingsConfig::singlefile("connections")
                    .with_schema::<SecretEntry>()
                    .with_migrator(|mut entries| {
                        // Single-file migrators transform the entry map as a whole.
                        if let Some(entry) = entries
                            .get_mut("one")
                            .and_then(serde_json::Value::as_object_mut)
                            && let Some(old) = entry.remove("old_token")
                        {
                            entry.insert("token".into(), old);
                        }
                        entries
                    }),
            )
            .build()
            .unwrap();
        assert!(matches!(
            manager.disable_vault("password"),
            Err(Error::Credential(_))
        ));
        assert!(manager.is_locked());
    }
}
