//! Regressions for schema defaults, number types and key handling.

use rcman::{
    DeriveSettingsSchema, Error, IndexMap, SettingChange, SettingMetadata, SettingsManager,
    SettingsSchema, ValidationError, settings,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Serialize, Deserialize, DeriveSettingsSchema)]
#[schema(category = "ui")]
struct Ui {
    #[setting(min = 8, max = 32)]
    font_size: u32,
    scale: f64,
    zoom: Option<u8>,
    label: Option<String>,
    #[setting(min_length = 1, max_length = 8)]
    name: String,
    #[setting(max_items = 2)]
    ports: Vec<u16>,
}

impl Default for Ui {
    fn default() -> Self {
        Self {
            font_size: 14,
            scale: 1.0,
            zoom: Some(3),
            label: None,
            name: "main".into(),
            ports: vec![80],
        }
    }
}

#[derive(Default, Serialize, Deserialize, DeriveSettingsSchema)]
struct App {
    ui: Ui,
}

fn manager<Schema: SettingsSchema>(
    directory: &std::path::Path,
) -> SettingsManager<rcman::JsonStorage, Schema> {
    SettingsManager::builder("schema-regressions", "1")
        .with_config_dir(directory)
        .with_schema::<Schema>()
        .build()
        .unwrap()
}

#[test]
fn integer_fields_keep_integer_defaults_and_read_back_on_a_fresh_install() {
    let metadata = App::get_metadata();
    assert_eq!(metadata["ui.font_size"].default, json!(14));
    assert!(metadata["ui.font_size"].constraints.number.integer);
    assert!(!metadata["ui.scale"].constraints.number.integer);

    let directory = tempfile::tempdir().unwrap();
    let manager = manager::<App>(directory.path());
    assert_eq!(manager.get::<u32>("ui.font_size").unwrap(), 14);
    assert_eq!(manager.ui_font_size().unwrap(), 14);
}

#[test]
fn integer_fields_reject_fractions_so_the_model_stays_readable() {
    let directory = tempfile::tempdir().unwrap();
    let manager = manager::<App>(directory.path());
    let error = manager.set("ui.font_size", &12.5).unwrap_err();
    assert!(matches!(
        error,
        Error::InvalidSettingValue {
            reason: ValidationError::NotInteger,
            ..
        }
    ));
    manager.set_ui_font_size(12).unwrap();
    assert_eq!(manager.get_all().unwrap().ui.font_size, 12);
    // Fractional values are still fine for float fields.
    manager.set("ui.scale", &1.5).unwrap();
    assert!((manager.get_all().unwrap().ui.scale - 1.5).abs() < f64::EPSILON);
}

#[test]
fn option_fields_default_to_the_struct_default_including_none() {
    let metadata = App::get_metadata();
    assert_eq!(metadata["ui.zoom"].default, json!(3));
    assert_eq!(metadata["ui.label"].default, Value::Null);

    let directory = tempfile::tempdir().unwrap();
    let manager = manager::<App>(directory.path());
    assert_eq!(manager.get::<Option<String>>("ui.label").unwrap(), None);
    assert_eq!(manager.get_all().unwrap().ui.label, None);
    assert_eq!(manager.get::<Option<u8>>("ui.zoom").unwrap(), Some(3));
}

#[test]
fn a_nullable_setting_saved_as_null_stays_null_after_a_restart() {
    let directory = tempfile::tempdir().unwrap();
    manager::<App>(directory.path())
        .set("ui.zoom", &Value::Null)
        .unwrap();

    let reopened = manager::<App>(directory.path());
    assert_eq!(reopened.get::<Option<u8>>("ui.zoom").unwrap(), None);
    assert_eq!(reopened.get_all().unwrap().ui.zoom, None);
}

#[test]
fn list_defaults_keep_their_item_type_and_limits_apply() {
    assert_eq!(App::get_metadata()["ui.ports"].default, json!([80]));
    let directory = tempfile::tempdir().unwrap();
    let manager = manager::<App>(directory.path());
    assert_eq!(manager.get::<Vec<u16>>("ui.ports").unwrap(), [80]);
    assert!(matches!(
        manager.set("ui.ports", &[1, 2, 3]).unwrap_err(),
        Error::InvalidSettingValue {
            reason: ValidationError::TooManyItems { max: 2 },
            ..
        }
    ));
    assert!(matches!(
        manager.set("ui.name", "").unwrap_err(),
        Error::InvalidSettingValue {
            reason: ValidationError::TooShort { min: 1 },
            ..
        }
    ));
}

#[derive(Default, Serialize, Deserialize)]
struct BrokenDefault {
    ui: BrokenUi,
}
#[derive(Default, Serialize, Deserialize)]
struct BrokenUi {
    size: u32,
}
impl SettingsSchema for BrokenDefault {
    fn get_metadata() -> IndexMap<String, SettingMetadata> {
        settings! { "ui.size" => SettingMetadata::integer(0_u32).min(8.0) }
    }
}

#[test]
fn a_default_that_breaks_its_own_constraints_fails_at_startup() {
    let directory = tempfile::tempdir().unwrap();
    let error = SettingsManager::builder("broken-default", "1")
        .with_config_dir(directory.path())
        .with_schema::<BrokenDefault>()
        .build()
        .err()
        .unwrap();
    assert!(matches!(error, Error::InvalidSettingMetadata { ref key, .. } if key == "ui.size"));
}

#[derive(Default, Serialize, Deserialize)]
struct Themed {
    ui: ThemedUi,
}
#[derive(Default, Serialize, Deserialize)]
struct ThemedUi {
    theme: String,
}
impl SettingsSchema for Themed {
    fn get_metadata() -> IndexMap<String, SettingMetadata> {
        settings! { "ui.theme" => SettingMetadata::text("light") }
    }
}

#[test]
fn whole_model_and_single_reads_agree_on_metadata_defaults() {
    let directory = tempfile::tempdir().unwrap();
    let manager = manager::<Themed>(directory.path());
    assert_eq!(manager.get::<String>("ui.theme").unwrap(), "light");
    assert_eq!(manager.get_all().unwrap().ui.theme, "light");
}

#[derive(Serialize, Deserialize, DeriveSettingsSchema)]
struct Host {
    #[serde(rename = "address")]
    host: String,
}
impl Default for Host {
    fn default() -> Self {
        Self {
            host: "localhost".into(),
        }
    }
}
#[derive(Default, Serialize, Deserialize, DeriveSettingsSchema)]
struct Proxy {
    http: Host,
}
#[derive(Default, Serialize, Deserialize, DeriveSettingsSchema)]
struct Deep {
    net: Proxy,
}

#[test]
fn nested_structs_are_keyed_by_their_serialized_path_at_any_depth() {
    let metadata = Deep::get_metadata();
    assert_eq!(metadata.keys().collect::<Vec<_>>(), ["net.http.address"]);

    let directory = tempfile::tempdir().unwrap();
    let manager = manager::<Deep>(directory.path());
    assert_eq!(
        manager.get::<String>("net.http.address").unwrap(),
        "localhost"
    );
    manager.set("net.http.address", "proxy.local").unwrap();
    assert_eq!(manager.get_all().unwrap().net.http.host, "proxy.local");
    assert!(matches!(
        manager.get_value("net").unwrap_err(),
        Error::InvalidKey(_)
    ));
}

#[test]
fn bulk_writes_report_exactly_the_settings_they_changed() {
    let directory = tempfile::tempdir().unwrap();
    let manager = manager::<App>(directory.path());
    manager.set("ui.font_size", &20).unwrap();
    manager.set("ui.name", "other").unwrap();

    let changes = manager.reset_all().unwrap();
    assert_eq!(
        changes,
        [
            SettingChange {
                key: "ui.font_size".into(),
                old: json!(20),
                new: json!(14),
            },
            SettingChange {
                key: "ui.name".into(),
                old: json!("other"),
                new: json!("main"),
            },
        ]
    );
    assert!(manager.reset_all().unwrap().is_empty());
    assert_eq!(manager.reset("ui.font_size").unwrap(), json!(14));
}

#[test]
fn a_missing_file_is_a_not_found_error() {
    let error = Error::FileRead {
        path: "missing".into(),
        source: std::io::Error::from(std::io::ErrorKind::NotFound),
    };
    assert!(error.is_not_found());
    let denied = Error::FileRead {
        path: "denied".into(),
        source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
    };
    assert!(!denied.is_not_found());
}

#[test]
fn typed_reads_name_the_key_that_failed_to_deserialize() {
    let directory = tempfile::tempdir().unwrap();
    let manager = manager::<App>(directory.path());
    assert!(matches!(
        manager.get::<bool>("ui.name").unwrap_err(),
        Error::Deserialize { ref key, .. } if key == "ui.name"
    ));
}

#[test]
fn validation_errors_keep_their_english_messages() {
    let setting = SettingMetadata::integer(5_u8).min(1.0).max(9.0);
    assert_eq!(
        setting.validate(&json!(0)).unwrap_err().to_string(),
        "Value must be at least 1"
    );
    assert_eq!(
        setting.validate(&json!(2.5)).unwrap_err(),
        ValidationError::NotInteger
    );
    let select = SettingMetadata::select(1, vec![rcman::opt(1, "One"), rcman::opt(2, "Two")]);
    assert!(select.validate(&json!(2)).is_ok());
    assert_eq!(
        select.validate(&json!("2")).unwrap_err(),
        ValidationError::NotAnOption
    );
}

#[cfg(feature = "backup")]
#[test]
fn export_category_names_match_their_serialized_form() {
    use rcman::backup::ExportCategoryType;
    for kind in [
        ExportCategoryType::Settings,
        ExportCategoryType::SubSettings,
        ExportCategoryType::External,
    ] {
        assert_eq!(serde_json::to_value(kind).unwrap(), kind.as_str());
    }
}

#[derive(Default, Serialize, Deserialize)]
struct Account {
    user: AccountUser,
}
#[derive(Default, Serialize, Deserialize)]
struct AccountUser {
    name: String,
    scale: f64,
}
impl SettingsSchema for Account {
    fn get_metadata() -> IndexMap<String, SettingMetadata> {
        settings! {
            "user.name" => SettingMetadata::text("").pattern("^[a-z]{3,}$"),
            "user.scale" => SettingMetadata::number(1.0),
        }
    }
}

#[test]
fn an_unset_text_default_can_always_be_restored() {
    let directory = tempfile::tempdir().unwrap();
    let manager = manager::<Account>(directory.path());
    manager.set("user.name", "alice").unwrap();
    assert_eq!(manager.reset("user.name").unwrap(), json!(""));
    assert!(manager.set("user.name", "x").is_err());
}

#[test]
fn an_integer_for_a_float_default_is_the_same_value() {
    let directory = tempfile::tempdir().unwrap();
    let manager = manager::<Account>(directory.path());
    let changes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = std::sync::Arc::clone(&changes);
    manager.events().on_change(move |_, _, _| {
        counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    });
    // A UI sends `1` for the default `1.0`: nothing is stored or reported.
    manager.set("user.scale", &1).unwrap();
    assert_eq!(changes.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert!(!directory.path().join("settings.json").exists());
}

#[derive(Default, Serialize, Deserialize)]
struct Flat {
    theme: String,
}
impl SettingsSchema for Flat {
    fn get_metadata() -> IndexMap<String, SettingMetadata> {
        settings! { "theme" => SettingMetadata::text("dark") }
    }
}

#[test]
fn keys_without_a_category_still_serve_the_whole_model() {
    let directory = tempfile::tempdir().unwrap();
    let manager = manager::<Flat>(directory.path());
    assert_eq!(manager.get_all().unwrap().theme, "dark");
    manager.update(|flat| flat.theme = "light".into()).unwrap();
    assert_eq!(manager.get_all().unwrap().theme, "light");
}

#[derive(Default, Serialize, Deserialize, DeriveSettingsSchema)]
#[schema(category = "pair")]
struct Pair {
    left: u8,
}

/// Two fields nest the same schema under conditions that both hold; the
/// accessor marker must be implemented once, not twice.
#[derive(Default, Serialize, Deserialize, DeriveSettingsSchema)]
struct TwoPairs {
    #[cfg(feature = "derive")]
    pair: Pair,
    #[cfg(feature = "json")]
    other: Pair,
}

#[test]
fn a_schema_nested_twice_under_cfg_keeps_its_accessors() {
    let directory = tempfile::tempdir().unwrap();
    let manager = manager::<TwoPairs>(directory.path());
    manager.set_pair_left(7).unwrap();
    assert_eq!(manager.pair_left().unwrap(), 7);
}

#[cfg(unix)]
#[test]
fn a_non_utf8_path_default_does_not_panic() {
    use std::os::unix::ffi::OsStrExt;
    #[derive(Serialize, Deserialize, DeriveSettingsSchema)]
    #[schema(category = "files")]
    struct Files {
        root: std::path::PathBuf,
    }
    impl Default for Files {
        fn default() -> Self {
            Self {
                root: std::ffi::OsStr::from_bytes(b"/tmp/\xff").into(),
            }
        }
    }
    let default = &Files::get_metadata()["files.root"].default;
    assert!(
        default
            .as_str()
            .is_some_and(|path| path.starts_with("/tmp/"))
    );
}

#[test]
fn whole_numbers_sent_as_floats_are_stored_as_integers() {
    let directory = tempfile::tempdir().unwrap();
    let manager = manager::<App>(directory.path());
    manager.set("ui.font_size", &20.0).unwrap();
    assert_eq!(manager.get::<u32>("ui.font_size").unwrap(), 20);
    let file = std::fs::read_to_string(directory.path().join("settings.json")).unwrap();
    assert!(
        file.contains("\"font_size\": 20") && !file.contains("20.0"),
        "{file}"
    );
    assert!(manager.set("ui.font_size", &20.5).is_err());
}

#[derive(Default, Serialize, Deserialize, DeriveSettingsSchema)]
struct Endpoint {
    port: u16,
}

#[test]
fn sub_settings_store_whole_number_floats_as_integers() {
    let directory = tempfile::tempdir().unwrap();
    let manager = SettingsManager::builder("sub-integers", "1")
        .with_config_dir(directory.path())
        .with_sub_settings(rcman::SubSettingsConfig::new("endpoints").with_schema::<Endpoint>())
        .build()
        .unwrap();
    let endpoints = manager.sub_settings("endpoints").unwrap();
    endpoints.set("api", &json!({"port": 8080.0})).unwrap();
    assert_eq!(endpoints.get::<Endpoint>("api").unwrap().port, 8080);
}

#[cfg(feature = "backup")]
#[test]
fn a_backup_holding_an_unset_default_restores() {
    use rcman::{BackupOptions, RestoreOptions};
    let source = tempfile::tempdir().unwrap();
    let original = manager::<Account>(source.path());
    original.set("user.scale", &2.5).unwrap();
    // The settings file holds the unset name (`""` fails the pattern) as well.
    std::fs::write(
        source.path().join("settings.json"),
        r#"{"user":{"name":"","scale":2.5}}"#,
    )
    .unwrap();
    original.invalidate_cache();
    let backups = tempfile::tempdir().unwrap();
    let archive = original
        .backup()
        .create(&BackupOptions::new().output_dir(backups.path()))
        .unwrap();

    let target = tempfile::tempdir().unwrap();
    let restored = manager::<Account>(target.path());
    restored
        .backup()
        .restore(&RestoreOptions::from_path(&archive).overwrite(true))
        .unwrap();
    assert!((restored.get_all().unwrap().user.scale - 2.5).abs() < f64::EPSILON);
}

#[cfg(feature = "backup")]
#[test]
fn a_single_sub_settings_export_with_a_slash_in_its_name_works() {
    use rcman::{BackupOptions, ExportType};
    let directory = tempfile::tempdir().unwrap();
    let manager = SettingsManager::builder("slash-export", "1")
        .with_config_dir(directory.path())
        .with_sub_settings(rcman::SubSettingsConfig::singlefile("alerts/rules"))
        .build()
        .unwrap();
    manager
        .sub_settings("alerts/rules")
        .unwrap()
        .set("r1", &json!({"on": true}))
        .unwrap();
    let backups = tempfile::tempdir().unwrap();
    let mut options = BackupOptions::new()
        .output_dir(backups.path())
        .export_type(ExportType::SettingsOnly)
        .include_settings(false);
    options.include_sub_settings = vec!["alerts/rules".into()];
    let path = manager.backup().create(&options).unwrap();
    assert!(
        path.file_name()
            .unwrap()
            .to_string_lossy()
            .ends_with("_alerts_rules.rcman")
    );
}

#[cfg(feature = "backup")]
#[test]
fn restore_rejects_a_tampered_backup_by_default() {
    use rcman::{BackupOptions, RestoreOptions};
    use std::io::{Read, Write};
    use zip::{ZipArchive, ZipWriter, write::SimpleFileOptions};

    let directory = tempfile::tempdir().unwrap();
    let manager = manager::<Themed>(directory.path());
    manager.set("ui.theme", "dark").unwrap();
    let backups = tempfile::tempdir().unwrap();
    let backup = manager
        .backup()
        .create(&BackupOptions::new().output_dir(backups.path()))
        .unwrap();

    // Keep the manifest (and its checksum) but replace the payload.
    let mut manifest = Vec::new();
    ZipArchive::new(std::fs::File::open(&backup).unwrap())
        .unwrap()
        .by_name("manifest.json")
        .unwrap()
        .read_to_end(&mut manifest)
        .unwrap();
    let mut inner = ZipWriter::new(std::io::Cursor::new(Vec::new()));
    inner
        .start_file("settings.json", SimpleFileOptions::default())
        .unwrap();
    inner.write_all(br#"{"ui":{"theme":"tampered"}}"#).unwrap();
    let data = inner.finish().unwrap().into_inner();
    let mut outer = ZipWriter::new(std::fs::File::create(&backup).unwrap());
    for (name, bytes) in [("manifest.json", manifest), ("data.zip", data)] {
        outer
            .start_file(name, SimpleFileOptions::default())
            .unwrap();
        outer.write_all(&bytes).unwrap();
    }
    outer.finish().unwrap();

    let result = manager
        .backup()
        .restore(&RestoreOptions::from_path(&backup).overwrite(true));
    assert!(matches!(result, Err(Error::InvalidBackup(_))), "{result:?}");
    assert_eq!(manager.get::<String>("ui.theme").unwrap(), "dark");

    // Opting out restores the payload as before.
    manager
        .backup()
        .restore(
            &RestoreOptions::from_path(&backup)
                .overwrite(true)
                .verify_checksum(false),
        )
        .unwrap();
    assert_eq!(manager.get::<String>("ui.theme").unwrap(), "tampered");
}
