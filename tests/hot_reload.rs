//! Hot-reload integration tests
//!
//! These tests validate the feature-gated watcher runtime using polling mode for
//! deterministic behavior across CI environments.

mod common;

use common::TestFixture;
use rcman::{HotReloadBackend, HotReloadConfig, HotReloadEvent, HotReloadRuntime};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

#[test]
fn test_hot_reload_applies_external_file_change() {
    let fixture = TestFixture::new();
    let manager = Arc::new(fixture.manager);

    let (event_tx, event_rx) = mpsc::channel::<HotReloadEvent>();
    let callback = move |event: HotReloadEvent| {
        let _ = event_tx.send(event);
    };

    let config = HotReloadConfig {
        debounce_ms: 75,
        poll_interval_ms: 50,
        backend: HotReloadBackend::Poll,
    };

    let mut runtime = HotReloadRuntime::start(Arc::clone(&manager), config, callback).unwrap();

    // Give the watcher thread a brief warm-up window before mutating files.
    std::thread::sleep(Duration::from_millis(250));

    let settings_path = manager.config().settings_path();
    std::fs::write(
        &settings_path,
        r#"{"ui":{"theme":"light","font_size":14.0}}"#,
    )
    .unwrap();

    let deadline = Instant::now() + Duration::from_secs(4);
    let mut reloaded = false;

    while Instant::now() < deadline {
        if let Ok(event) = event_rx.recv_timeout(Duration::from_millis(150)) {
            match event {
                HotReloadEvent::Reloaded { .. } => {
                    reloaded = true;
                    break;
                }
                HotReloadEvent::WatchError { reason } => {
                    panic!("watcher emitted setup/runtime error: {reason}");
                }
                HotReloadEvent::ReloadFailed { reason, .. } => {
                    panic!("reload failed unexpectedly: {reason}");
                }
                _ => {}
            }
        }
    }

    assert!(reloaded, "expected at least one Reloaded event");
    assert_eq!(manager.get::<String>("ui.theme").unwrap(), "light");

    runtime.stop();
}

#[test]
fn test_hot_reload_stop_stops_emitting_events() {
    let fixture = TestFixture::new();
    let manager = Arc::new(fixture.manager);

    let (event_tx, event_rx) = mpsc::channel::<HotReloadEvent>();
    let callback = move |event: HotReloadEvent| {
        let _ = event_tx.send(event);
    };

    let config = HotReloadConfig {
        debounce_ms: 50,
        poll_interval_ms: 50,
        backend: HotReloadBackend::Poll,
    };

    let mut runtime = HotReloadRuntime::start(Arc::clone(&manager), config, callback).unwrap();
    runtime.stop();

    let settings_path = manager.config().settings_path();
    std::fs::write(&settings_path, r#"{"ui":{"theme":"solarized"}}"#).unwrap();

    let received = event_rx.recv_timeout(Duration::from_millis(500));
    assert!(received.is_err(), "watcher emitted event after stop");
}

#[test]
fn test_hot_reload_rapid_consecutive_changes_apply_latest_value() {
    let fixture = TestFixture::new();
    let manager = Arc::new(fixture.manager);

    let (event_tx, event_rx) = mpsc::channel::<HotReloadEvent>();
    let callback = move |event: HotReloadEvent| {
        let _ = event_tx.send(event);
    };

    let config = HotReloadConfig {
        debounce_ms: 50,
        poll_interval_ms: 50,
        backend: HotReloadBackend::Poll,
    };

    let mut runtime = HotReloadRuntime::start(Arc::clone(&manager), config, callback).unwrap();

    std::thread::sleep(Duration::from_millis(250));

    let settings_path = manager.config().settings_path();

    std::fs::write(&settings_path, r#"{"ui":{"theme":"light"}}"#).unwrap();
    std::thread::sleep(Duration::from_millis(40));
    std::fs::write(&settings_path, r#"{"ui":{"theme":"dark"}}"#).unwrap();

    let deadline = Instant::now() + Duration::from_secs(4);
    let mut saw_reload = false;
    let mut latest_applied = false;

    while Instant::now() < deadline {
        if let Ok(event) = event_rx.recv_timeout(Duration::from_millis(150)) {
            match event {
                HotReloadEvent::Reloaded { .. } => {
                    saw_reload = true;
                    if manager.get::<String>("ui.theme").unwrap() == "dark" {
                        latest_applied = true;
                        break;
                    }
                }
                HotReloadEvent::WatchError { reason } => {
                    panic!("watcher emitted setup/runtime error: {reason}");
                }
                HotReloadEvent::ReloadFailed { reason, .. } => {
                    panic!("reload failed unexpectedly: {reason}");
                }
                _ => {}
            }
        }
    }

    assert!(saw_reload, "expected at least one Reloaded event");
    assert!(latest_applied, "latest rapid edit was not applied");

    runtime.stop();
}

#[test]
fn test_hot_reload_drops_sub_settings_cache_on_external_change() {
    let directory = tempfile::tempdir().unwrap();
    let manager = Arc::new(
        rcman::SettingsManager::builder("hot-reload-subs", "1")
            .with_config_dir(directory.path())
            .with_sub_settings(rcman::SubSettingsConfig::new("remotes"))
            .with_sub_settings(rcman::SubSettingsConfig::singlefile("backends"))
            .build()
            .unwrap(),
    );
    let remotes = manager.sub_settings("remotes").unwrap();
    let backends = manager.sub_settings("backends").unwrap();
    remotes
        .set("drive", &serde_json::json!({"type": "drive"}))
        .unwrap();
    backends
        .set("main", &serde_json::json!({"port": 1}))
        .unwrap();
    // Fill both caches before the files change behind the manager's back.
    assert_eq!(remotes.get_value("drive").unwrap()["type"], "drive");
    assert_eq!(backends.get_value("main").unwrap()["port"], 1);

    let (event_tx, event_rx) = mpsc::channel::<HotReloadEvent>();
    let config = HotReloadConfig {
        debounce_ms: 75,
        poll_interval_ms: 50,
        backend: HotReloadBackend::Poll,
    };
    let mut runtime = HotReloadRuntime::start(Arc::clone(&manager), config, move |event| {
        let _ = event_tx.send(event);
    })
    .unwrap();
    std::thread::sleep(Duration::from_millis(250));

    // Polling compares modification times; move them clearly forward so the
    // change is seen even when it lands in the same timestamp tick.
    let later = std::time::SystemTime::now() + Duration::from_secs(5);
    let rewrite = |path: &std::path::Path, content: &str| {
        std::fs::write(path, content).unwrap();
        std::fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(later)
            .unwrap();
    };
    rewrite(
        &remotes.directory().unwrap().join("drive.json"),
        r#"{"type":"s3"}"#,
    );
    rewrite(
        &backends.file_path().unwrap().unwrap(),
        r#"{"main":{"port":2}}"#,
    );

    let deadline = Instant::now() + Duration::from_secs(4);
    let mut changed = std::collections::BTreeSet::new();
    while Instant::now() < deadline && changed.len() < 2 {
        if let Ok(event) = event_rx.recv_timeout(Duration::from_millis(150)) {
            match event {
                HotReloadEvent::SubSettingsChanged { name } => {
                    changed.insert(name);
                }
                HotReloadEvent::WatchError { reason } => panic!("watch error: {reason}"),
                _ => {}
            }
        }
    }
    runtime.stop();

    assert_eq!(
        changed.into_iter().collect::<Vec<_>>(),
        ["backends", "remotes"]
    );
    assert_eq!(remotes.get_value("drive").unwrap()["type"], "s3");
    assert_eq!(backends.get_value("main").unwrap()["port"], 2);
}
