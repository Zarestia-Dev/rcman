//! Portable backups must not carry the source vault's encryption into the target.
#![cfg(all(feature = "backup", feature = "vault", feature = "profiles"))]

mod common;

use common::TestSettings;
use rcman::backup::ExternalConfig;
use rcman::vault::{Argon2Preset, is_vault_content};
use rcman::{BackupOptions, RestoreOptions, SettingsManager, SubSettingsConfig};
use serde_json::json;
use std::{
    fs,
    io::{Cursor, Read, Write},
    path::Path,
};
use tempfile::tempdir;
use zip::{ZipArchive, ZipWriter, write::SimpleFileOptions};

fn archive_entry(backup: &Path, name: &str, password: Option<&str>) -> Vec<u8> {
    let mut outer = ZipArchive::new(fs::File::open(backup).unwrap()).unwrap();
    let mut data = Vec::new();
    outer
        .by_name("data.zip")
        .unwrap()
        .read_to_end(&mut data)
        .unwrap();
    let mut inner = ZipArchive::new(Cursor::new(data)).unwrap();
    let mut file = match password {
        Some(password) => inner.by_name_decrypt(name, password.as_bytes()).unwrap(),
        None => inner.by_name(name).unwrap(),
    };
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    bytes
}

#[test]
fn profiled_backups_follow_target_vault_and_leave_sources_unchanged() {
    for source_encrypted in [false, true] {
        for target_encrypted in [false, true] {
            let source_dir = tempdir().unwrap();
            let target_dir = tempdir().unwrap();
            let output = tempdir().unwrap();
            let build = |path: &Path| {
                SettingsManager::builder("portable-vault", "1")
                    .with_config_dir(path)
                    .with_schema::<TestSettings>()
                    .with_vault_preset(Argon2Preset::Fast)
                    .with_sub_settings(SubSettingsConfig::new("remotes").with_profiles())
                    .with_sub_settings(SubSettingsConfig::singlefile("backend").with_profiles())
                    .build()
                    .unwrap()
            };
            let source = build(source_dir.path());
            source.save_setting("ui", "theme", &json!("light")).unwrap();
            for name in ["remotes", "backend"] {
                source
                    .sub_settings(name)
                    .unwrap()
                    .set("server", &json!({"host":"source"}))
                    .unwrap();
            }
            if source_encrypted {
                source.enable_vault("source-password").unwrap();
            }
            let paths = [
                "settings.json",
                "remotes/profiles/default/server.json",
                "backend/profiles/default/backend.json",
            ];
            let before: Vec<_> = paths
                .iter()
                .map(|p| fs::read(source_dir.path().join(p)).unwrap())
                .collect();
            let backup = source
                .backup()
                .create(
                    &BackupOptions::default()
                        .output_dir(output.path())
                        .password("archive-password"),
                )
                .unwrap();
            for (path, bytes) in paths.iter().zip(before) {
                assert_eq!(fs::read(source_dir.path().join(path)).unwrap(), bytes);
                let exported = archive_entry(&backup, path, Some("archive-password"));
                assert!(!is_vault_content(std::str::from_utf8(&exported).unwrap()));
            }
            let target = build(target_dir.path());
            if target_encrypted {
                target.enable_vault("different-target-password").unwrap();
            }
            target
                .backup()
                .restore(
                    &RestoreOptions::from_path(&backup)
                        .password("archive-password")
                        .overwrite(true),
                )
                .unwrap();
            for name in ["remotes", "backend"] {
                assert_eq!(
                    target
                        .sub_settings(name)
                        .unwrap()
                        .get_value("server")
                        .unwrap()["host"],
                    "source"
                );
            }
            for path in paths {
                assert_eq!(
                    is_vault_content(&fs::read_to_string(target_dir.path().join(path)).unwrap()),
                    target_encrypted
                );
            }
            if target_encrypted {
                target.lock().unwrap();
                target.unlock("different-target-password").unwrap();
                assert_eq!(
                    target
                        .sub_settings("backend")
                        .unwrap()
                        .get_value("server")
                        .unwrap()["host"],
                    "source"
                );
            }
        }
    }
}

#[test]
fn external_payloads_are_opaque_even_when_they_look_like_vault_files() {
    let root = tempdir().unwrap();
    let external = root.path().join("external.bin");
    let bytes = b"{\"__rcman_vault__\":1,\"payload\":\"keep these bytes\"}";
    fs::write(&external, bytes).unwrap();
    let manager = SettingsManager::builder("external-vault", "1")
        .with_config_dir(root.path().join("config"))
        .with_vault_preset(Argon2Preset::Fast)
        .with_external_config(ExternalConfig::new("external", &external))
        .build()
        .unwrap();
    manager.enable_vault("vault-password").unwrap();
    let backup = manager
        .backup()
        .create(&BackupOptions::default().output_dir(root.path().join("backups")))
        .unwrap();
    assert_eq!(archive_entry(&backup, "external/external.bin", None), bytes);
    fs::write(&external, b"changed").unwrap();
    manager
        .backup()
        .restore(&RestoreOptions::from_path(&backup).overwrite(true))
        .unwrap();
    assert_eq!(fs::read(external).unwrap(), bytes);
}

#[test]
fn invalid_profile_payload_is_rejected_before_main_settings_are_written() {
    for payload in [
        b"not json".as_slice(),
        b"{\"__rcman_vault__\":1}".as_slice(),
    ] {
        let root = tempdir().unwrap();
        let manager = SettingsManager::builder("preflight", "1")
            .with_config_dir(root.path().join("config"))
            .with_schema::<TestSettings>()
            .with_sub_settings(SubSettingsConfig::new("remotes").with_profiles())
            .build()
            .unwrap();
        manager
            .save_setting("ui", "theme", &json!("light"))
            .unwrap();
        manager
            .sub_settings("remotes")
            .unwrap()
            .set("server", &json!({"host":"original"}))
            .unwrap();
        let backup = manager
            .backup()
            .create(&BackupOptions::default().output_dir(root.path().join("backups")))
            .unwrap();
        let mut outer = ZipArchive::new(fs::File::open(&backup).unwrap()).unwrap();
        let mut manifest = Vec::new();
        outer
            .by_name("manifest.json")
            .unwrap()
            .read_to_end(&mut manifest)
            .unwrap();
        drop(outer);
        let mut inner = ZipWriter::new(Cursor::new(Vec::new()));
        for (name, bytes) in [
            ("settings.json", b"{\"ui\":{\"theme\":\"dark\"}}".as_slice()),
            ("remotes/profiles/default/server.json", payload),
        ] {
            inner
                .start_file(name, SimpleFileOptions::default())
                .unwrap();
            inner.write_all(bytes).unwrap();
        }
        let data = inner.finish().unwrap().into_inner();
        let mut outer = ZipWriter::new(fs::File::create(&backup).unwrap());
        for (name, bytes) in [("manifest.json", manifest), ("data.zip", data)] {
            outer
                .start_file(name, SimpleFileOptions::default())
                .unwrap();
            outer.write_all(&bytes).unwrap();
        }
        outer.finish().unwrap();
        let settings = root.path().join("config/settings.json");
        let original = fs::read(&settings).unwrap();
        let result = manager.backup().restore(
            &RestoreOptions::from_path(&backup)
                .verify_checksum(false)
                .overwrite(true),
        );
        assert!(result.is_err());
        assert_eq!(fs::read(settings).unwrap(), original);
    }
}

#[derive(Default, serde::Serialize, serde::Deserialize)]
struct SecretEntry;

impl rcman::SettingsSchema for SecretEntry {
    fn get_metadata() -> rcman::IndexMap<String, rcman::SettingMetadata> {
        rcman::settings! { "token" => rcman::SettingMetadata::text("").secret() }
    }
}

#[test]
fn single_and_profiled_exports_apply_secret_policy_without_migrating_sources() {
    let root = tempdir().unwrap();
    let manager = SettingsManager::builder("secret-backup", "1")
        .with_config_dir(root.path().join("config"))
        .with_sub_settings(
            SubSettingsConfig::new("remotes")
                .with_profiles()
                .with_schema::<SecretEntry>()
                .with_migrator(|mut value| {
                    value["migrated"] = json!(true);
                    value
                }),
        )
        .build()
        .unwrap();
    let path = root
        .path()
        .join("config/remotes/profiles/default/server.json");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let original = br#"{"token":"do-not-export","host":"example"}"#;
    fs::write(&path, original).unwrap();
    for export_type in [
        rcman::backup::ExportType::Full,
        rcman::backup::ExportType::Single {
            settings_type: "remotes".into(),
            name: "server".into(),
        },
    ] {
        let single = matches!(export_type, rcman::backup::ExportType::Single { .. });
        let backup = manager
            .backup()
            .create(
                &BackupOptions::default()
                    .output_dir(root.path().join("backups"))
                    .export_type(export_type)
                    .secret_policy(rcman::SecretBackupPolicy::Exclude),
            )
            .unwrap();
        let name = if single {
            "remotes/server.json"
        } else {
            "remotes/profiles/default/server.json"
        };
        let value: serde_json::Value =
            serde_json::from_slice(&archive_entry(&backup, name, None)).unwrap();
        assert!(value.get("token").is_none());
        assert!(value.get("migrated").is_none());
        assert_eq!(value["host"], "example");
        assert_eq!(fs::read(&path).unwrap(), original);
    }
}

#[derive(Clone)]
struct FailOnceStorage {
    writes_left: std::sync::Arc<std::sync::atomic::AtomicIsize>,
}

impl rcman::StorageBackend for FailOnceStorage {
    fn extension(&self) -> &str {
        "json"
    }
    fn serialize<T: serde::Serialize>(&self, value: &T) -> rcman::Result<String> {
        rcman::JsonStorage::new().serialize(value)
    }
    fn deserialize<T: serde::de::DeserializeOwned>(&self, content: &str) -> rcman::Result<T> {
        rcman::JsonStorage::new().deserialize(content)
    }
    fn write<T: serde::Serialize>(&self, path: &Path, value: &T) -> rcman::Result<()> {
        use std::sync::atomic::Ordering;
        if self.writes_left.fetch_sub(1, Ordering::SeqCst) == 0 {
            return Err(rcman::Error::Config("injected write failure".into()));
        }
        rcman::JsonStorage::new().write(path, value)
    }
}

#[test]
fn failed_restore_rolls_back_vault_files_and_does_not_notify() {
    use std::sync::{
        Arc,
        atomic::{AtomicIsize, AtomicUsize, Ordering},
    };
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();
    let output = tempdir().unwrap();
    let build = |path: &Path, writes_left: Arc<AtomicIsize>| {
        SettingsManager::builder("restore-rollback", "1")
            .with_config_dir(path)
            .with_schema::<TestSettings>()
            .with_storage_instance(FailOnceStorage { writes_left })
            .with_vault_preset(Argon2Preset::Fast)
            .with_sub_settings(SubSettingsConfig::singlefile("remotes"))
            .build()
            .unwrap()
    };
    let source = build(source_dir.path(), Arc::new(AtomicIsize::new(-1)));
    source.save_setting("ui", "theme", &json!("light")).unwrap();
    let remotes = source.sub_settings("remotes").unwrap();
    remotes.set("one", &json!({"host":"new-one"})).unwrap();
    remotes.set("two", &json!({"host":"new-two"})).unwrap();
    let backup = source
        .backup()
        .create(&BackupOptions::default().output_dir(output.path()))
        .unwrap();
    let writes_left = Arc::new(AtomicIsize::new(-1));
    let target = build(target_dir.path(), writes_left.clone());
    target
        .save_setting("ui", "theme", &json!("system"))
        .unwrap();
    let remotes = target.sub_settings("remotes").unwrap();
    remotes.set("one", &json!({"host":"old"})).unwrap();
    target.enable_vault("target-password").unwrap();
    let settings_path = target_dir.path().join("settings.json");
    let remote_path = remotes.file_path().unwrap();
    let before_settings = fs::read(&settings_path).unwrap();
    let before_remotes = fs::read(&remote_path).unwrap();
    let notifications = Arc::new(AtomicUsize::new(0));
    let observed = notifications.clone();
    remotes
        .set_on_change(move |_, _| {
            observed.fetch_add(1, Ordering::SeqCst);
        })
        .unwrap();
    // Main settings and one entry succeed; the second entry fails.
    writes_left.store(2, Ordering::SeqCst);
    let error = target
        .backup()
        .restore(&RestoreOptions::from_path(backup).overwrite(true))
        .unwrap_err();
    assert!(error.to_string().contains("injected write failure"));
    assert_eq!(fs::read(settings_path).unwrap(), before_settings);
    assert_eq!(fs::read(remote_path).unwrap(), before_remotes);
    assert_eq!(notifications.load(Ordering::SeqCst), 0);
    assert_eq!(remotes.get_value("one").unwrap()["host"], "old");
    assert!(!remotes.exists("two").unwrap());
    target.lock().unwrap();
    target.unlock("target-password").unwrap();
    assert_eq!(target.get_value("ui.theme").unwrap(), "system");
}
