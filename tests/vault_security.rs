#![cfg(feature = "vault")]

mod tests {
    use rcman::vault::{Argon2Params, Argon2Preset};
    use rcman::{
        IndexMap, JsonStorage, SettingMetadata, SettingsManager, SettingsSchema, StorageBackend,
        SubSettingsConfig,
    };
    use serde::{Deserialize, Serialize};
    use serde_json::{Value, json};
    use std::path::Path;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use std::time::Duration;

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
            let mut metadata = IndexMap::new();
            metadata.insert("ui.theme".into(), SettingMetadata::text(""));
            metadata
        }
    }

    #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
    #[derive(Default, Serialize, Deserialize)]
    struct SecretSchema {
        token: String,
    }
    #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
    impl SettingsSchema for SecretSchema {
        fn get_metadata() -> IndexMap<String, SettingMetadata> {
            let mut metadata = IndexMap::new();
            metadata.insert("token".into(), SettingMetadata::text("").secret());
            metadata
        }
    }

    #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
    #[test]
    fn locked_startup_migrates_subsetting_secrets_before_reads() {
        let dir = tempfile::tempdir().unwrap();
        let manager = SettingsManager::builder("audit", "1")
            .with_config_dir(dir.path())
            .with_vault_password("password")
            .with_vault_preset(Argon2Preset::Fast)
            .with_sub_settings(SubSettingsConfig::singlefile("connections"))
            .build()
            .unwrap();
        manager
            .sub_settings("connections")
            .unwrap()
            .set(
                "primary",
                &json!({"token":"existing-token", "host":"example"}),
            )
            .unwrap();
        drop(manager);
        let manager = SettingsManager::builder("audit", "2")
            .with_config_dir(dir.path())
            .with_credential_config(rcman::CredentialConfig::Custom(Arc::new(
                rcman::MemoryBackend::new(),
            )))
            .with_sub_settings(
                SubSettingsConfig::singlefile("connections").with_schema::<SecretSchema>(),
            )
            .build()
            .unwrap();
        assert!(manager.is_locked());
        manager.unlock("password").unwrap();
        let connections = manager.sub_settings("connections").unwrap();
        let mut entry = connections.get_value("primary").unwrap();
        assert_eq!(
            entry["token"], "existing-token",
            "Token must be migrated before reads"
        );
        assert_eq!(
            manager
                .credentials()
                .unwrap()
                .get("sub.connections.primary.token")
                .unwrap(),
            Some("existing-token".into())
        );
        entry["host"] = json!("changed.example");
        connections.set("primary", &entry).unwrap();
        let reader = SettingsManager::builder("audit", "1")
            .with_config_dir(dir.path())
            .with_vault_password("password")
            .with_sub_settings(SubSettingsConfig::singlefile("connections"))
            .build()
            .unwrap();
        let stored = reader
            .sub_settings("connections")
            .unwrap()
            .get_value("primary")
            .unwrap();
        assert!(
            stored.get("token").is_none(),
            "Migrated secrets must be absent from the encrypted file payload"
        );
    }

    #[derive(Clone)]
    struct SlowFailStorage(Arc<AtomicBool>);
    impl StorageBackend for SlowFailStorage {
        fn extension(&self) -> &str {
            "json"
        }
        fn serialize<T: Serialize>(&self, data: &T) -> rcman::Result<String> {
            JsonStorage::new().serialize(data)
        }
        fn deserialize<T: serde::de::DeserializeOwned>(&self, content: &str) -> rcman::Result<T> {
            JsonStorage::new().deserialize(content)
        }
        fn write<T: Serialize>(&self, path: &Path, value: &T) -> rcman::Result<()> {
            if path.file_name().is_some_and(|n| n == "tokens.json")
                && self.0.swap(false, Ordering::SeqCst)
            {
                std::thread::sleep(Duration::from_millis(700));
                return Err(rcman::Error::FileWrite {
                    path: path.to_owned(),
                    source: std::io::Error::other("delayed failure"),
                });
            }
            JsonStorage::new().write(path, value)
        }
    }

    #[test]
    fn failed_disable_restores_encryption_despite_auto_lock_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let fail = Arc::new(AtomicBool::new(false));
        let manager = SettingsManager::builder("audit", "1")
            .with_schema::<Schema>()
            .with_config_dir(dir.path())
            .with_storage_instance(SlowFailStorage(fail.clone()))
            .with_vault_password("old")
            .with_vault_preset(Argon2Preset::Fast)
            .with_sub_settings(SubSettingsConfig::singlefile("tokens"))
            .build()
            .unwrap();
        manager
            .save_setting("ui", "theme", &json!("private-theme"))
            .unwrap();
        manager
            .sub_settings("tokens")
            .unwrap()
            .set("a", &json!("private-token"))
            .unwrap();
        manager
            .set_vault_lock_timeout(Some(Duration::from_millis(250)))
            .unwrap();
        fail.store(true, Ordering::SeqCst);
        let result = manager.disable_vault("old");
        assert!(result.is_err());
        assert!(manager.is_vault_enabled());
        let raw = std::fs::read_to_string(dir.path().join("settings.json")).unwrap();
        assert!(
            !raw.contains("private-theme"),
            "Failed disable must restore encryption"
        );
        manager.lock().unwrap();
        manager.unlock("old").unwrap();
        assert_eq!(
            manager.get_value("ui.theme").unwrap(),
            json!("private-theme")
        );
    }

    #[test]
    fn failed_rotation_preserves_the_old_password_across_stores() {
        let dir = tempfile::tempdir().unwrap();
        let fail = Arc::new(AtomicBool::new(false));
        let manager = SettingsManager::builder("audit", "1")
            .with_config_dir(dir.path())
            .with_storage_instance(SlowFailStorage(fail.clone()))
            .with_vault_password("old")
            .with_vault_preset(Argon2Preset::Fast)
            .with_sub_settings(SubSettingsConfig::singlefile("tokens"))
            .build()
            .unwrap();
        manager
            .sub_settings("tokens")
            .unwrap()
            .set("a", &json!("private-token"))
            .unwrap();
        manager
            .set_vault_lock_timeout(Some(Duration::from_millis(250)))
            .unwrap();
        fail.store(true, Ordering::SeqCst);
        let result = manager.change_vault_password("old", "new");
        assert!(result.is_err());
        assert!(
            SettingsManager::builder("audit", "1")
                .with_config_dir(dir.path())
                .with_vault_password("new")
                .build()
                .is_err()
        );
        let reader = SettingsManager::builder("audit", "1")
            .with_config_dir(dir.path())
            .with_vault_password("old")
            .with_sub_settings(SubSettingsConfig::singlefile("tokens"))
            .build()
            .unwrap();
        assert_eq!(
            reader
                .sub_settings("tokens")
                .unwrap()
                .get_value("a")
                .unwrap(),
            json!("private-token")
        );
    }

    #[test]
    fn enabled_and_required_vaults_reject_plaintext_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let manager = SettingsManager::builder("audit", "1")
            .with_schema::<Schema>()
            .with_config_dir(dir.path())
            .with_vault_password("password")
            .with_vault_preset(Argon2Preset::Fast)
            .build()
            .unwrap();
        std::fs::write(
            dir.path().join("settings.json"),
            r#"{"ui":{"theme":"injected"}}"#,
        )
        .unwrap();
        manager.invalidate_cache();
        assert!(manager.is_vault_enabled());
        assert!(manager.get_value("ui.theme").is_err());
        manager.lock().unwrap();
        drop(manager);
        for password in [None, Some("password")] {
            let builder = SettingsManager::builder("audit", "1").with_config_dir(dir.path());
            let builder = if let Some(password) = password {
                builder.with_vault_password(password)
            } else {
                builder
            };
            if password.is_some() {
                assert!(builder.build().is_err());
            } else {
                let manager = builder.build().unwrap();
                assert!(manager.unlock("password").is_err());
                assert!(manager.is_locked());
            }
        }
    }

    #[test]
    fn encrypted_entries_cannot_be_transplanted_between_names() {
        let dir = tempfile::tempdir().unwrap();
        let manager = SettingsManager::builder("audit", "1")
            .with_config_dir(dir.path())
            .with_vault_password("password")
            .with_vault_preset(Argon2Preset::Fast)
            .with_sub_settings(SubSettingsConfig::new("remotes"))
            .build()
            .unwrap();
        let remotes = manager.sub_settings("remotes").unwrap();
        remotes
            .set("production", &json!({"host":"production.example"}))
            .unwrap();
        remotes
            .set("untrusted", &json!({"host":"untrusted.example"}))
            .unwrap();
        std::fs::copy(
            dir.path().join("remotes/untrusted.json"),
            dir.path().join("remotes/production.json"),
        )
        .unwrap();
        manager.invalidate_cache();
        assert!(remotes.get_value("production").is_err());
        let mut forged: Value = serde_json::from_slice(
            &std::fs::read(dir.path().join("remotes/untrusted.json")).unwrap(),
        )
        .unwrap();
        forged["context"] = json!({"path": "remotes/production.json"});
        std::fs::write(
            dir.path().join("remotes/production.json"),
            serde_json::to_vec(&forged).unwrap(),
        )
        .unwrap();
        manager.invalidate_cache();
        assert!(remotes.get_value("production").is_err());
    }

    #[test]
    fn envelope_headers_and_timeout_are_authenticated() {
        let dir = tempfile::tempdir().unwrap();
        let manager = SettingsManager::builder("audit", "1")
            .with_config_dir(dir.path())
            .with_vault_password("password")
            .with_vault_preset(Argon2Preset::Fast)
            .build()
            .unwrap();
        manager
            .set_vault_lock_timeout(Some(Duration::from_secs(60)))
            .unwrap();
        drop(manager);
        let path = dir.path().join(".rcman-vault.json");
        let original: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        for field in ["lock_timeout_ms", "version", "algorithm", "context"] {
            let mut envelope = original.clone();
            envelope.as_object_mut().unwrap().remove(field);
            std::fs::write(&path, serde_json::to_vec(&envelope).unwrap()).unwrap();
            assert!(
                SettingsManager::builder("audit", "1")
                    .with_config_dir(dir.path())
                    .with_vault_password("password")
                    .build()
                    .is_err(),
                "Tampering with {field} must be rejected"
            );
        }
    }

    #[test]
    fn opening_or_registering_does_not_enroll_injected_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let manager = SettingsManager::builder("audit", "1")
            .with_config_dir(dir.path())
            .with_vault_password("password")
            .with_vault_preset(Argon2Preset::Fast)
            .build()
            .unwrap();
        let path = dir.path().join("connections.json");
        let original = br#"{"primary":{"token":"plaintext-token"}}"#;
        std::fs::write(&path, original).unwrap();
        assert!(
            manager
                .register_sub_settings(SubSettingsConfig::singlefile("connections"))
                .is_err()
        );
        drop(manager);
        let reopened = SettingsManager::builder("audit", "1")
            .with_config_dir(dir.path())
            .with_sub_settings(SubSettingsConfig::singlefile("connections"))
            .build()
            .unwrap();
        assert!(reopened.unlock("password").is_err());
        assert!(reopened.is_locked());
        assert_eq!(std::fs::read(path).unwrap(), original);
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_enable_removes_previous_plaintext_from_database_pages() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.db");
        let marker = "RCMAN_PLAINTEXT_REMANENCE_456789";
        let large = marker.repeat(1000);
        let manager = SettingsManager::builder("audit", "1")
            .with_config_dir(dir.path())
            .with_schema::<Schema>()
            .with_storage::<rcman::SqliteStorage>()
            .with_vault_preset(Argon2Preset::Fast)
            .build()
            .unwrap();
        manager.save_setting("ui", "theme", &json!(large)).unwrap();
        manager
            .enable_vault_with_params("password", Argon2Params::fast())
            .unwrap();
        let value: Value = manager.storage().read(&path).unwrap();
        assert!(rcman::vault::is_vault_value(&value));
        let raw = std::fs::read(path).unwrap();
        assert!(!raw.windows(marker.len()).any(|w| w == marker.as_bytes()));
    }

    #[test]
    fn excessive_kdf_costs_are_rejected_before_allocating() {
        let dir = tempfile::tempdir().unwrap();
        let manager = SettingsManager::builder("audit", "1")
            .with_config_dir(dir.path())
            .with_vault_password("password")
            .with_vault_preset(Argon2Preset::Fast)
            .build()
            .unwrap();
        drop(manager);
        let path = dir.path().join(".rcman-vault.json");
        let original: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        for params in [
            Argon2Params::new(1_048_576, 1, 1),
            Argon2Params::new(64, u32::MAX, 1),
            Argon2Params::new(256, 1, 17),
        ] {
            assert!(params.validate().is_err());
            let mut envelope = original.clone();
            envelope["kdf_params"] = serde_json::to_value(params).unwrap();
            std::fs::write(&path, serde_json::to_vec(&envelope).unwrap()).unwrap();
            assert!(
                SettingsManager::builder("audit", "1")
                    .with_config_dir(dir.path())
                    .with_vault_password("candidate")
                    .build()
                    .is_err()
            );
        }
    }

    #[cfg(feature = "profiles")]
    #[test]
    fn profile_copy_and_rename_rebind_encrypted_files() {
        let dir = tempfile::tempdir().unwrap();
        let manager = SettingsManager::builder("audit", "1")
            .with_config_dir(dir.path())
            .with_schema::<Schema>()
            .with_profiles()
            .with_vault_password("password")
            .with_vault_preset(Argon2Preset::Fast)
            .with_sub_settings(SubSettingsConfig::singlefile("connections").with_profiles())
            .build()
            .unwrap();
        manager
            .save_setting("ui", "theme", &json!("private-theme"))
            .unwrap();
        let sub = manager.sub_settings("connections").unwrap();
        sub.set("primary", &json!({"host":"private-host"})).unwrap();
        manager
            .profiles()
            .unwrap()
            .duplicate("default", "copy")
            .unwrap();
        sub.profiles()
            .unwrap()
            .duplicate("default", "copy")
            .unwrap();
        manager.switch_profile("copy").unwrap();
        assert_eq!(
            manager.get_value("ui.theme").unwrap(),
            json!("private-theme")
        );
        assert_eq!(sub.get_value("primary").unwrap()["host"], "private-host");
        manager.switch_profile("default").unwrap();
        manager
            .profiles()
            .unwrap()
            .rename("copy", "renamed")
            .unwrap();
        sub.profiles().unwrap().rename("copy", "renamed").unwrap();
        manager.switch_profile("renamed").unwrap();
        manager.lock().unwrap();
        manager.unlock("password").unwrap();
        assert_eq!(
            manager.get_value("ui.theme").unwrap(),
            json!("private-theme")
        );
        assert_eq!(sub.get_value("primary").unwrap()["host"], "private-host");
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_migration_scrubs_freelist_and_wal_history() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.db");
        let marker = "OLD_PLAINTEXT_HISTORY_12345";
        let manager = SettingsManager::builder("audit", "1")
            .with_config_dir(dir.path())
            .with_schema::<Schema>()
            .with_storage::<rcman::SqliteStorage>()
            .with_vault_preset(Argon2Preset::Fast)
            .build()
            .unwrap();
        manager
            .save_setting("ui", "theme", &json!(marker.repeat(2000)))
            .unwrap();
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA secure_delete=OFF;")
            .unwrap();
        conn.execute(
            "UPDATE rcman_settings SET data = ?1 WHERE key = 'main'",
            [r#"{"ui":{"theme":"short"}}"#],
        )
        .unwrap();
        manager.invalidate_cache();
        manager.enable_vault("password").unwrap();
        assert_eq!(manager.get_value("ui.theme").unwrap(), json!("short"));
        for path in [path.clone(), path.with_file_name("settings.db-wal")] {
            if path.exists() {
                let raw = std::fs::read(path).unwrap();
                assert!(
                    !raw.windows(marker.len())
                        .any(|bytes| bytes == marker.as_bytes())
                );
                assert!(!raw.windows(5).any(|bytes| bytes == b"short"));
            }
        }
    }

    #[cfg(all(feature = "sqlite", feature = "profiles"))]
    #[test]
    fn sqlite_profile_copies_rebind_main_and_table_rows() {
        let dir = tempfile::tempdir().unwrap();
        let manager = SettingsManager::builder("audit", "1")
            .with_config_dir(dir.path())
            .with_storage::<rcman::SqliteStorage>()
            .with_schema::<Schema>()
            .with_profiles()
            .with_vault_password("password")
            .with_vault_preset(Argon2Preset::Fast)
            .with_sub_settings(SubSettingsConfig::table("connections").with_profiles())
            .build()
            .unwrap();
        manager
            .save_setting("ui", "theme", &json!("private-theme"))
            .unwrap();
        let sub = manager.sub_settings("connections").unwrap();
        sub.set("primary", &json!({"host":"private-host"})).unwrap();
        let connection =
            rusqlite::Connection::open(dir.path().join("profiles/default/settings.db")).unwrap();
        connection.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE extra(value TEXT); INSERT INTO extra VALUES ('opaque');").unwrap();
        manager
            .profiles()
            .unwrap()
            .duplicate("default", "copy")
            .unwrap();
        sub.profiles()
            .unwrap()
            .duplicate("default", "copy")
            .unwrap();
        manager.switch_profile("copy").unwrap();
        manager.lock().unwrap();
        manager.unlock("password").unwrap();
        assert_eq!(
            manager.get_value("ui.theme").unwrap(),
            json!("private-theme")
        );
        assert_eq!(sub.get_value("primary").unwrap()["host"], "private-host");
        let copy =
            rusqlite::Connection::open(dir.path().join("profiles/copy/settings.db")).unwrap();
        let opaque: String = copy
            .query_row("SELECT value FROM extra", [], |row| row.get(0))
            .unwrap();
        assert_eq!(opaque, "opaque");
    }

    #[test]
    fn failed_unlock_validation_leaves_the_vault_locked() {
        let dir = tempfile::tempdir().unwrap();
        let manager = SettingsManager::builder("audit", "1")
            .with_config_dir(dir.path())
            .with_vault_preset(Argon2Preset::Fast)
            .with_vault_password("password")
            .build()
            .unwrap();
        drop(manager);
        let manager = SettingsManager::builder("audit", "1")
            .with_config_dir(dir.path())
            .with_sub_settings(SubSettingsConfig::singlefile("connections"))
            .build()
            .unwrap();
        std::fs::write(dir.path().join("connections.json"), b"broken JSON").unwrap();
        let notifications = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = Arc::clone(&notifications);
        manager.events().on_vault_unlock(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        });
        assert!(manager.unlock("password").is_err());
        assert!(manager.is_locked());
        assert_eq!(notifications.load(Ordering::SeqCst), 0);
        assert!(manager.get_all_data().is_err());
        assert_eq!(
            std::fs::read(dir.path().join("connections.json")).unwrap(),
            b"broken JSON"
        );
    }

    #[cfg(all(
        feature = "profiles",
        any(feature = "keychain", feature = "encrypted-file")
    ))]
    #[test]
    fn locked_startup_migrates_secrets_in_inactive_subsettings_profiles() {
        let dir = tempfile::tempdir().unwrap();
        let manager = SettingsManager::builder("audit", "1")
            .with_config_dir(dir.path())
            .with_vault_password("password")
            .with_vault_preset(Argon2Preset::Fast)
            .with_sub_settings(SubSettingsConfig::singlefile("connections").with_profiles())
            .build()
            .unwrap();
        let sub = manager.sub_settings("connections").unwrap();
        sub.profiles().unwrap().create("work").unwrap();
        sub.switch_profile("work").unwrap();
        sub.set("primary", &json!({"token":"work-token"})).unwrap();
        sub.switch_profile("default").unwrap();
        drop(sub);
        drop(manager);
        let manager = SettingsManager::builder("audit", "2")
            .with_config_dir(dir.path())
            .with_credential_config(rcman::CredentialConfig::Custom(Arc::new(
                rcman::MemoryBackend::new(),
            )))
            .with_sub_settings(
                SubSettingsConfig::singlefile("connections")
                    .with_profiles()
                    .with_schema::<SecretSchema>(),
            )
            .build()
            .unwrap();
        manager.unlock("password").unwrap();
        let sub = manager.sub_settings("connections").unwrap();
        assert_eq!(sub.profiles().unwrap().active().unwrap(), "default");
        sub.switch_profile("work").unwrap();
        assert_eq!(sub.get_value("primary").unwrap()["token"], "work-token");
    }
    #[cfg(all(
        feature = "profiles",
        any(feature = "keychain", feature = "encrypted-file")
    ))]
    #[test]
    fn unlock_runs_schema_migration_before_extracting_secrets_without_switching_profiles() {
        let dir = tempfile::tempdir().unwrap();
        let manager = SettingsManager::builder("audit", "1")
            .with_config_dir(dir.path())
            .with_vault_password("password")
            .with_vault_preset(Argon2Preset::Fast)
            .with_sub_settings(SubSettingsConfig::singlefile("connections").with_profiles())
            .build()
            .unwrap();
        let connections = manager.sub_settings("connections").unwrap();
        connections
            .set("one", &json!({"legacy_token":"default-token"}))
            .unwrap();
        connections.profiles().unwrap().create("work").unwrap();
        connections.switch_profile("work").unwrap();
        connections
            .set("one", &json!({"legacy_token":"work-token"}))
            .unwrap();
        drop(connections);
        drop(manager);
        let manager = SettingsManager::builder("audit", "2")
            .with_config_dir(dir.path())
            .with_credential_config(rcman::CredentialConfig::Custom(Arc::new(
                rcman::MemoryBackend::new(),
            )))
            .with_sub_settings(
                SubSettingsConfig::singlefile("connections")
                    .with_profiles()
                    .with_schema::<SecretSchema>()
                    .with_migrator(|mut value| {
                        if let Some(entries) = value.as_object_mut() {
                            for entry in entries.values_mut().filter_map(Value::as_object_mut) {
                                if let Some(token) = entry.remove("legacy_token") {
                                    entry.insert("token".into(), token);
                                }
                            }
                        }
                        value
                    }),
            )
            .build()
            .unwrap();
        manager.unlock("password").unwrap();
        let connections = manager.sub_settings("connections").unwrap();
        assert_eq!(connections.profiles().unwrap().active().unwrap(), "work");
        assert_eq!(connections.get_value("one").unwrap()["token"], "work-token");
        connections.switch_profile("default").unwrap();
        assert_eq!(
            connections.get_value("one").unwrap()["token"],
            "default-token"
        );
        let reader = SettingsManager::builder("audit", "2")
            .with_config_dir(dir.path())
            .with_vault_password("password")
            .with_sub_settings(SubSettingsConfig::singlefile("connections").with_profiles())
            .build()
            .unwrap();
        assert!(
            reader
                .sub_settings("connections")
                .unwrap()
                .get_value("one")
                .unwrap()
                .get("token")
                .is_none()
        );
    }
    #[test]
    fn failed_plaintext_write_relocks_a_previously_locked_vault() {
        let dir = tempfile::tempdir().unwrap();
        let fail = Arc::new(AtomicBool::new(false));
        let manager = SettingsManager::builder("audit", "1")
            .with_config_dir(dir.path())
            .with_storage_instance(SlowFailStorage(Arc::clone(&fail)))
            .with_vault_password("password")
            .with_vault_preset(Argon2Preset::Fast)
            .with_sub_settings(SubSettingsConfig::singlefile("tokens"))
            .build()
            .unwrap();
        let tokens = manager.sub_settings("tokens").unwrap();
        tokens.set("one", &json!({"value":"private"})).unwrap();
        manager.lock().unwrap();
        fail.store(true, Ordering::SeqCst);
        assert!(manager.disable_vault("password").is_err());
        assert!(manager.is_locked());
        let content = std::fs::read_to_string(dir.path().join("tokens.json")).unwrap();
        assert!(content.contains("__rcman_vault__"));
        assert!(!content.contains("private"));
        manager.unlock("password").unwrap();
        assert_eq!(tokens.get_value("one").unwrap()["value"], "private");
    }
}
