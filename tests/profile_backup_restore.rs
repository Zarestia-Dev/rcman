#![cfg(feature = "profiles")]

use rcman::{SettingsManager, SettingsConfigBuilder, SubSettingsConfig};
use rcman::{BackupOptions, RestoreOptions};
use tempfile::tempdir;
use std::fs;
use serde_json::json;

#[test]
fn test_profile_backup_restore_full() {
    let temp = tempdir().unwrap();
    let config_dir = temp.path().join("config");
    fs::create_dir_all(&config_dir).unwrap();

    // 1. Setup Manager with Profiles Enabled
    let config = SettingsConfigBuilder::new("test-app", "1.0.0")
        .config_dir(&config_dir)
        .with_profiles()
        .build();

    let manager = SettingsManager::new(config).unwrap();
    manager.register_sub_settings(SubSettingsConfig::new("items").with_profiles());

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
    let backup_path = backup_mgr.create(BackupOptions {
        output_dir: temp.path().join("backups"),
        include_settings: true,
        include_sub_settings: vec!["items".into()],
        include_profiles: vec![], // All
        ..Default::default()
    }).unwrap();

    // 6. Restore to fresh instance (profiled)
    let temp2 = tempdir().unwrap();
    let config2_dir = temp2.path().join("config");
    fs::create_dir_all(&config2_dir).unwrap();

    let config2 = SettingsConfigBuilder::new("test-app", "1.0.0")
        .config_dir(&config2_dir)
        .with_profiles()
        .build();
    
    let manager2 = SettingsManager::new(config2).unwrap();
    manager2.register_sub_settings(SubSettingsConfig::new("items").with_profiles());

    // Restore ALL
    let result = manager2.backup().restore(RestoreOptions {
        backup_path: backup_path.clone(),
        restore_settings: true,
        restore_sub_settings: vec!["items".into()].into_iter().map(|s| (s, vec![])).collect(),
        ..Default::default()
    }).unwrap();

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
