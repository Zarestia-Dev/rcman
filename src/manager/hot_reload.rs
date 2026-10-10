use crate::config::{HotReloadBackend, HotReloadConfig, SettingsSchema};
use crate::error::Result;
use crate::manager::SettingsManager;
use crate::storage::StorageBackend;

use notify::{Config, Event, PollWatcher, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

/// Event emitted by the hot-reload runtime.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HotReloadEvent {
    /// Reload completed and cache has been refreshed.
    Reloaded { path: PathBuf },
    /// Reload attempt failed.
    ReloadFailed { path: PathBuf, reason: String },
    /// Watcher setup/runtime error.
    WatchError { reason: String },
    /// Settings file changed on disk but reload was skipped because vault is locked.
    #[cfg(feature = "vault")]
    SkippedLocked { path: PathBuf },
}

enum WatcherKind {
    Recommended(RecommendedWatcher),
    Poll(PollWatcher),
}

impl WatcherKind {
    fn unwatch(&mut self, path: &Path) -> notify::Result<()> {
        match self {
            Self::Recommended(watcher) => watcher.unwatch(path),
            Self::Poll(watcher) => watcher.unwatch(path),
        }
    }

    fn watch(&mut self, path: &Path, recursive_mode: RecursiveMode) -> notify::Result<()> {
        match self {
            Self::Recommended(watcher) => watcher.watch(path, recursive_mode),
            Self::Poll(watcher) => watcher.watch(path, recursive_mode),
        }
    }
}

/// Running hot-reload worker handle.
pub struct HotReloadRuntime {
    stop_tx: Sender<()>,
    join_handle: Option<std::thread::JoinHandle<()>>,
}

impl HotReloadRuntime {
    /// Start hot-reload watching for the manager's active settings file.
    ///
    /// # Errors
    ///
    /// Returns an error if the active settings path cannot be resolved or the watcher
    /// cannot be initialized. Watching is registered before this method returns.
    pub fn start<S, Schema, F>(
        manager: Arc<SettingsManager<S, Schema>>,
        config: HotReloadConfig,
        on_event: F,
    ) -> Result<Self>
    where
        S: StorageBackend + 'static,
        Schema: SettingsSchema + Send + Sync + 'static,
        F: Fn(HotReloadEvent) + Send + Sync + 'static,
    {
        let watched_file = manager.settings_path()?;
        let watch_target = watched_file
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();

        let callback: Arc<dyn Fn(HotReloadEvent) + Send + Sync> = Arc::new(on_event);
        let (stop_tx, stop_rx) = mpsc::channel::<()>();

        let (fs_tx, fs_rx) = mpsc::channel::<notify::Result<Event>>();
        let mut watcher = create_watcher(&config, fs_tx)
            .map_err(|error| crate::Error::Config(format!("Failed to create watcher: {error}")))?;
        watcher
            .watch(&watch_target, RecursiveMode::NonRecursive)
            .map_err(|error| crate::Error::Config(format!("Failed to watch settings: {error}")))?;

        let join_handle = thread::spawn(move || {
            let ctx = ReloadContext {
                manager: &manager,
                config: &config,
                callback: &callback,
            };

            run_reload_loop(&ctx, watched_file, &mut watcher, &fs_rx, &stop_rx);
        });

        Ok(Self {
            stop_tx,
            join_handle: Some(join_handle),
        })
    }

    /// Stop hot-reload worker and join thread.
    pub fn stop(&mut self) {
        if self.stop_tx.send(()).is_err() {
            // Worker already stopped.
        }

        if let Some(handle) = self.join_handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for HotReloadRuntime {
    fn drop(&mut self) {
        self.stop();
    }
}

fn create_watcher(
    config: &HotReloadConfig,
    fs_tx: Sender<notify::Result<Event>>,
) -> notify::Result<WatcherKind> {
    let watcher_config =
        Config::default().with_poll_interval(Duration::from_millis(config.poll_interval_ms));

    match config.backend {
        HotReloadBackend::Auto => {
            RecommendedWatcher::new(fs_tx, watcher_config).map(WatcherKind::Recommended)
        }
        HotReloadBackend::Poll => PollWatcher::new(fs_tx, watcher_config).map(WatcherKind::Poll),
    }
}

struct ReloadContext<'a, S: StorageBackend, Schema: SettingsSchema> {
    manager: &'a Arc<SettingsManager<S, Schema>>,
    config: &'a HotReloadConfig,
    callback: &'a Arc<dyn Fn(HotReloadEvent) + Send + Sync>,
}

fn run_reload_loop<S, Schema>(
    ctx: &ReloadContext<'_, S, Schema>,
    mut watched_file: PathBuf,
    watcher: &mut WatcherKind,
    fs_rx: &Receiver<notify::Result<Event>>,
    stop_rx: &Receiver<()>,
) where
    S: StorageBackend + 'static,
    Schema: SettingsSchema + Send + Sync + 'static,
{
    let debounce_window = Duration::from_millis(ctx.config.debounce_ms);
    let self_write_suppression = Duration::from_millis(150);

    let mut pending_reload = false;
    let mut last_change = Instant::now();
    let mut suppress_until = Instant::now();

    loop {
        match stop_rx.try_recv() {
            Ok(()) | Err(TryRecvError::Disconnected) => break,
            Err(TryRecvError::Empty) => {}
        }

        match ctx.manager.settings_path() {
            Ok(active_file) if active_file != watched_file => {
                let previous = watched_file.parent().unwrap_or_else(|| Path::new("."));
                let target = active_file.parent().unwrap_or_else(|| Path::new("."));
                if previous == target {
                    watched_file = active_file;
                    pending_reload = true;
                    last_change = Instant::now();
                } else if let Err(error) = watcher.watch(target, RecursiveMode::NonRecursive) {
                    (ctx.callback)(HotReloadEvent::WatchError {
                        reason: error.to_string(),
                    });
                } else {
                    if let Err(error) = watcher.unwatch(previous) {
                        (ctx.callback)(HotReloadEvent::WatchError {
                            reason: error.to_string(),
                        });
                    }
                    watched_file = active_file;
                    pending_reload = true;
                    last_change = Instant::now();
                }
            }
            Err(error) => (ctx.callback)(HotReloadEvent::WatchError {
                reason: error.to_string(),
            }),
            _ => {}
        }

        match fs_rx.recv_timeout(Duration::from_millis(100)) {
            Ok(Ok(event)) => {
                if event_touches_file(&event, &watched_file) {
                    pending_reload = true;
                    last_change = Instant::now();
                }
            }
            Ok(Err(err)) => {
                (ctx.callback)(HotReloadEvent::WatchError {
                    reason: err.to_string(),
                });
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }

        if pending_reload
            && Instant::now() >= suppress_until
            && Instant::now().duration_since(last_change) >= debounce_window
        {
            #[cfg(feature = "vault")]
            if ctx.manager.is_locked() {
                ctx.manager.invalidate_cache();
                (ctx.callback)(HotReloadEvent::SkippedLocked {
                    path: watched_file.clone(),
                });
                pending_reload = false;
                suppress_until = Instant::now() + self_write_suppression;
                continue;
            }

            ctx.manager.invalidate_cache();

            match ctx.manager.ensure_cache_populated() {
                Ok(()) => {
                    (ctx.callback)(HotReloadEvent::Reloaded {
                        path: watched_file.clone(),
                    });
                }
                Err(err) => {
                    (ctx.callback)(HotReloadEvent::ReloadFailed {
                        path: watched_file.clone(),
                        reason: err.to_string(),
                    });
                }
            }

            pending_reload = false;
            suppress_until = Instant::now() + self_write_suppression;
        }
    }
}

fn event_touches_file(event: &Event, watched_file: &Path) -> bool {
    event.paths.iter().any(|path| {
        if path == watched_file {
            return true;
        }
        if path.file_name() != watched_file.file_name() {
            return false;
        }
        match (path.parent(), watched_file.parent()) {
            (Some(actual), Some(expected)) => {
                match (actual.canonicalize(), expected.canonicalize()) {
                    (Ok(actual), Ok(expected)) => actual == expected,
                    _ => false,
                }
            }
            _ => false,
        }
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn events_match_symlinked_directory_but_not_other_profiles() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        let alias = dir.path().join("alias");
        let other = dir.path().join("other");
        std::fs::create_dir(&real).unwrap();
        std::fs::create_dir(&other).unwrap();
        std::os::unix::fs::symlink(&real, &alias).unwrap();
        let event = Event::new(notify::EventKind::Any).add_path(real.join("settings.json"));
        assert!(event_touches_file(&event, &alias.join("settings.json")));
        assert!(!event_touches_file(&event, &other.join("settings.json")));
    }
}
