//! Startup must not fail when the credential password env var is absent.
#![cfg(all(feature = "keychain", feature = "encrypted-file"))]

use rcman::SettingsManager;

#[test]
fn missing_secret_env_does_not_fail_startup() {
    let dir = tempfile::tempdir().unwrap();
    let result = SettingsManager::builder("rcman-missing-secret-test", "1.0.0")
        .with_config_dir(dir.path())
        .with_custom_env_credentials("RCMAN_TEST_SECRET_THAT_IS_NEVER_SET")
        .build();
    assert!(result.is_ok(), "{:?}", result.err());
    assert!(!dir.path().join("secrets.enc").exists());
}
