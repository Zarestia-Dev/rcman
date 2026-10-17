//! Credential deletion and tracking contracts, independent of native keychains.
#![cfg(any(feature = "keychain", feature = "encrypted-file"))]

use rcman::{
    CredentialBackend, CredentialConfig, MemoryBackend, SettingMetadata, SettingsManager,
    SettingsSchema, SubSettingsConfig,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

#[derive(Default, Serialize, Deserialize)]
struct Settings;

impl SettingsSchema for Settings {
    fn get_metadata() -> rcman::IndexMap<String, SettingMetadata> {
        rcman::settings! { "auth.token" => SettingMetadata::text("").secret() }
    }
}

#[derive(Default, Serialize, Deserialize)]
struct Account;

impl SettingsSchema for Account {
    fn get_metadata() -> rcman::IndexMap<String, SettingMetadata> {
        rcman::settings! {
            "token" => SettingMetadata::text("").nullable(true).secret(),
            "host" => SettingMetadata::text("localhost"),
        }
    }
}

fn manager<B: CredentialBackend + 'static>(
    path: &Path,
    backend: &Arc<B>,
) -> rcman::JsonManager<Settings> {
    SettingsManager::builder("credentials-test", "1")
        .with_config_dir(path)
        .with_schema::<Settings>()
        .with_credential_config(CredentialConfig::Custom(backend.clone()))
        .with_sub_settings(SubSettingsConfig::singlefile("accounts").with_schema::<Account>())
        .build()
        .unwrap()
}

struct RestrictedBackend {
    memory: MemoryBackend,
    deny_secret_reads: AtomicBool,
    deny_presence_checks: AtomicBool,
    read_calls: AtomicUsize,
}

impl RestrictedBackend {
    fn new() -> Self {
        Self {
            memory: MemoryBackend::new(),
            deny_secret_reads: AtomicBool::new(false),
            deny_presence_checks: AtomicBool::new(false),
            read_calls: AtomicUsize::new(0),
        }
    }
}

impl CredentialBackend for RestrictedBackend {
    fn store(&self, key: &str, value: &str) -> rcman::Result<()> {
        self.memory.store(key, value)
    }
    fn get(&self, key: &str) -> rcman::Result<Option<String>> {
        self.read_calls.fetch_add(1, Ordering::Relaxed);
        if self.deny_secret_reads.load(Ordering::Relaxed) && key.ends_with(".token") {
            return Err(rcman::Error::Credential("secret read denied".into()));
        }
        self.memory.get(key)
    }
    fn remove(&self, key: &str) -> rcman::Result<()> {
        self.memory.remove(key)
    }
    fn exists(&self, key: &str) -> rcman::Result<bool> {
        if self.deny_presence_checks.load(Ordering::Relaxed) && key.ends_with(".token") {
            return Err(rcman::Error::Credential("presence check denied".into()));
        }
        self.memory.exists(key)
    }
    fn list_keys(&self) -> rcman::Result<Vec<String>> {
        self.memory.list_keys()
    }
    fn backend_name(&self) -> &'static str {
        "restricted"
    }
}

#[test]
fn existence_checks_respect_backend_metadata_without_reading_secrets() {
    let backend = Arc::new(RestrictedBackend::new());
    backend.store("metadata:auth.token", "secret").unwrap();
    backend.deny_secret_reads.store(true, Ordering::Relaxed);
    let credentials = rcman::CredentialManager::with_backend("metadata", backend.clone());
    assert!(credentials.exists("auth.token"));
    assert!(!credentials.exists("missing"));
    assert_eq!(backend.read_calls.load(Ordering::Relaxed), 0);
}

#[test]
fn startup_preserves_unreadable_tracked_secrets_without_blocking_settings() {
    let directory = tempfile::tempdir().unwrap();
    let backend = Arc::new(RestrictedBackend::new());
    let first = manager(directory.path(), &backend);
    first
        .save_setting("auth", "token", &json!("main-secret"))
        .unwrap();
    first
        .sub_settings("accounts")
        .unwrap()
        .set("main", &json!({"token": "sub-secret"}))
        .unwrap();
    backend.deny_secret_reads.store(true, Ordering::Relaxed);

    let restarted = manager(directory.path(), &backend);
    let credentials = restarted.credentials().unwrap();
    let tracked = credentials.get_tracked_secrets(None).unwrap();
    assert!(tracked.contains("auth.token"));
    assert!(tracked.contains("sub.accounts.main.token"));
    assert!(restarted.get_value("auth.token").is_err());
    assert!(
        restarted
            .sub_settings("accounts")
            .unwrap()
            .get_value("main")
            .is_err()
    );
    // Cleanup must also leave tracking intact when existence itself is unknown.
    backend.deny_presence_checks.store(true, Ordering::Relaxed);
    let restarted = manager(directory.path(), &backend);
    let tracked = restarted
        .credentials()
        .unwrap()
        .get_tracked_secrets(None)
        .unwrap();
    assert!(tracked.contains("auth.token"));
    assert!(tracked.contains("sub.accounts.main.token"));
    assert_eq!(
        backend
            .memory
            .get("credentials-test:auth.token")
            .unwrap()
            .as_deref(),
        Some("main-secret")
    );
    assert_eq!(
        backend
            .memory
            .get("credentials-test:sub.accounts.main.token")
            .unwrap()
            .as_deref(),
        Some("sub-secret")
    );
}

#[test]
fn omitted_secrets_are_preserved_and_only_the_schema_default_removes_them() {
    let dir = tempfile::tempdir().unwrap();
    let backend = Arc::new(MemoryBackend::new());
    let manager = manager(dir.path(), &backend);
    let accounts = manager.sub_settings("accounts").unwrap();
    let credentials = manager.credentials().unwrap();
    let key = "sub.accounts.main.token";
    accounts
        .set("main", &json!({"token": "secret", "host": "example.com"}))
        .unwrap();
    accounts
        .set("main", &json!({"host": "example.org"}))
        .unwrap();
    assert_eq!(credentials.get(key).unwrap().as_deref(), Some("secret"));
    accounts
        .set_field("main", "token", &Option::<String>::None)
        .unwrap();
    assert!(accounts.get_value("main").unwrap()["token"].is_null());
    assert!(credentials.get_tracked_secrets(None).unwrap().contains(key));
    accounts.set_field("main", "token", &"").unwrap();
    assert_eq!(credentials.get(key).unwrap(), None);
    assert!(!credentials.get_tracked_secrets(None).unwrap().contains(key));
    let disk = std::fs::read_to_string(dir.path().join("accounts.json")).unwrap();
    assert!(!disk.contains("secret"));
    assert!(!disk.contains("token"));
}

#[test]
fn another_manager_cannot_resurrect_deleted_secrets_or_lose_new_tracking() {
    let dir = tempfile::tempdir().unwrap();
    let backend = Arc::new(MemoryBackend::new());
    let first = manager(dir.path(), &backend);
    let accounts = first.sub_settings("accounts").unwrap();
    accounts.set("main", &json!({"token": "deleted"})).unwrap();
    let second = manager(dir.path(), &backend);
    let other = second.sub_settings("accounts").unwrap();
    other.set_field("main", "token", &"").unwrap();
    other.set("other", &json!({"token": "keep"})).unwrap();
    accounts.set_field("main", "host", &"example.org").unwrap();
    let credentials = first.credentials().unwrap();
    assert_eq!(credentials.get("sub.accounts.main.token").unwrap(), None);
    assert_eq!(
        credentials
            .get("sub.accounts.other.token")
            .unwrap()
            .as_deref(),
        Some("keep")
    );
    assert_eq!(
        credentials.get_tracked_secrets(None).unwrap(),
        std::collections::HashSet::from(["sub.accounts.other.token".into()])
    );
}

#[test]
fn startup_prunes_missing_credentials_from_main_and_sub_settings_tracking() {
    let dir = tempfile::tempdir().unwrap();
    let backend = Arc::new(MemoryBackend::new());
    let first = manager(dir.path(), &backend);
    first
        .save_setting("auth", "token", &json!("deleted-main"))
        .unwrap();
    let accounts = first.sub_settings("accounts").unwrap();
    accounts
        .set("main", &json!({"token": "deleted-sub"}))
        .unwrap();
    accounts.set("other", &json!({"token": "keep"})).unwrap();
    backend.remove("credentials-test:auth.token").unwrap();
    backend
        .remove("credentials-test:sub.accounts.main.token")
        .unwrap();
    let restarted = manager(dir.path(), &backend);
    let credentials = restarted.credentials().unwrap();
    assert_eq!(
        credentials.get_tracked_secrets(None).unwrap(),
        std::collections::HashSet::from(["sub.accounts.other.token".into()])
    );
    assert_eq!(
        credentials
            .get("sub.accounts.other.token")
            .unwrap()
            .as_deref(),
        Some("keep")
    );
}

#[test]
fn migration_extracts_new_values_despite_an_existing_orphan_tracking_entry() {
    let dir = tempfile::tempdir().unwrap();
    let backend = Arc::new(MemoryBackend::new());
    let first = manager(dir.path(), &backend);
    let credentials = first.credentials().unwrap();
    credentials
        .save_tracked_secrets(
            &std::collections::HashSet::from([
                "auth.token".into(),
                "sub.accounts.main.token".into(),
            ]),
            None,
        )
        .unwrap();
    std::fs::write(
        dir.path().join("settings.json"),
        r#"{"auth":{"token":"main-new"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.path().join("accounts.json"),
        r#"{"main":{"token":"sub-new"}}"#,
    )
    .unwrap();
    let restarted = manager(dir.path(), &backend);
    let credentials = restarted.credentials().unwrap();
    assert_eq!(
        credentials.get("auth.token").unwrap().as_deref(),
        Some("main-new")
    );
    assert_eq!(
        credentials
            .get("sub.accounts.main.token")
            .unwrap()
            .as_deref(),
        Some("sub-new")
    );
}
