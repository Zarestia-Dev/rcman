use crate::config::{HotReloadBackend, HotReloadConfig, SettingsSchema};
use crate::error::Result;
use crate::manager::SettingsManager;
use crate::storage::StorageBackend;

use notify::{Config, Event, PollWatcher, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

/// Event emitted by the hot-reload runtime.
///
/// New variants may be added in minor releases; match with a wildcard arm.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum HotReloadEvent {
    /// Reload completed and cache has been refreshed.
    Reloaded { path: PathBuf },
    /// Reload attempt failed.
    ReloadFailed { path: PathBuf, reason: String },
    /// Files of a registered sub-settings store changed on disk; its cache was
    /// dropped, so the next read sees the new content.
    SubSettingsChanged { name: String },
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
    /// Start hot-reload watching for the manager's active settings file and
    /// the active files of every registered sub-settings store.
    ///
    /// Stores are looked up again on every poll, so profile switches and stores
    /// registered later are followed. A store directory that does not exist yet
    /// is watched once it appears.
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
        let mut watched_dirs = HashSet::from([watch_target.clone()]);
        let mut subs = Vec::new();
        refresh_sub_targets(&manager, &mut subs);
        let desired: BTreeSet<PathBuf> = std::iter::once(watch_target)
            .chain(subs.iter().map(|sub| sub.directory.clone()))
            .collect();
        sync_watches(&mut watcher, &mut watched_dirs, &desired, &callback);

        let join_handle = thread::spawn(move || {
            let ctx = ReloadContext {
                manager: &manager,
                config: &config,
                callback: &callback,
            };

            run_reload_loop(
                &ctx,
                WatchState {
                    file: watched_file,
                    dirs: watched_dirs,
                    subs,
                },
                &mut watcher,
                &fs_rx,
                &stop_rx,
            );
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

/// What the reload loop watches; refreshed on every poll.
struct WatchState {
    /// The active main settings file.
    file: PathBuf,
    /// Directories currently registered with the watcher.
    dirs: HashSet<PathBuf>,
    /// Registered sub-settings stores.
    subs: Vec<SubTarget>,
}

/// Where a sub-settings store keeps its active entries.
struct SubTarget {
    name: String,
    directory: PathBuf,
    /// The store's file, or `None` when every file in `directory` is an entry.
    file: Option<PathBuf>,
}

impl SubTarget {
    fn touched_by(&self, event: &Event) -> bool {
        match &self.file {
            Some(file) => event_touches_file(event, file),
            None => event.paths.iter().any(|path| {
                path.parent()
                    .is_some_and(|parent| same_dir(parent, &self.directory))
            }),
        }
    }
}

/// Refresh where each registered sub-settings store keeps its active entries.
///
/// A store whose lookup fails for now (for example `Error::Busy` while a
/// backup runs) keeps its previous target, so its watch is not dropped.
fn refresh_sub_targets<S, Schema>(
    manager: &SettingsManager<S, Schema>,
    targets: &mut Vec<SubTarget>,
) where
    S: StorageBackend + 'static,
    Schema: SettingsSchema,
{
    let lookup = |name: &str| {
        let sub = manager.sub_settings(name).ok()?;
        let file = sub.file_path().ok()?;
        let directory = match &file {
            Some(file) => file.parent()?.to_path_buf(),
            None => sub.directory().ok()?,
        };
        Some(SubTarget {
            name: name.to_owned(),
            directory,
            file,
        })
    };
    let mut previous = std::mem::take(targets);
    for name in manager.sub_settings_types() {
        let known = previous
            .iter()
            .position(|target| target.name == name)
            .map(|index| previous.swap_remove(index));
        if let Some(target) = lookup(&name).or(known) {
            targets.push(target);
        }
    }
}

fn same_dir(left: &Path, right: &Path) -> bool {
    left == right
        || matches!(
            (left.canonicalize(), right.canonicalize()),
            (Ok(left), Ok(right)) if left == right
        )
}

/// Watch exactly `desired`, keeping directories that are already watched.
/// A directory that cannot be watched yet (it may not exist) is retried on
/// the next poll; other failures are reported.
fn sync_watches(
    watcher: &mut WatcherKind,
    watched_dirs: &mut HashSet<PathBuf>,
    desired: &BTreeSet<PathBuf>,
    callback: &Arc<dyn Fn(HotReloadEvent) + Send + Sync>,
) {
    for directory in desired {
        if watched_dirs.contains(directory) || !directory.is_dir() {
            continue;
        }
        match watcher.watch(directory, RecursiveMode::NonRecursive) {
            Ok(()) => {
                watched_dirs.insert(directory.clone());
            }
            Err(error) => callback(HotReloadEvent::WatchError {
                reason: error.to_string(),
            }),
        }
    }
    watched_dirs.retain(|directory| {
        if desired.contains(directory) {
            return true;
        }
        if let Err(error) = watcher.unwatch(directory) {
            callback(HotReloadEvent::WatchError {
                reason: error.to_string(),
            });
        }
        false
    });
}

fn run_reload_loop<S, Schema>(
    ctx: &ReloadContext<'_, S, Schema>,
    mut watch: WatchState,
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
    let mut pending_subs = BTreeSet::new();
    let mut last_change = Instant::now();
    let mut suppress_until = Instant::now();
    let parent = |file: &Path| {
        file.parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf()
    };

    loop {
        match stop_rx.try_recv() {
            Ok(()) | Err(TryRecvError::Disconnected) => break,
            Err(TryRecvError::Empty) => {}
        }

        match ctx.manager.settings_path() {
            Ok(active_file) if active_file != watch.file => {
                watch.file = active_file;
                pending_reload = true;
                last_change = Instant::now();
            }
            Err(error) => (ctx.callback)(HotReloadEvent::WatchError {
                reason: error.to_string(),
            }),
            _ => {}
        }
        refresh_sub_targets(ctx.manager, &mut watch.subs);
        let desired: BTreeSet<PathBuf> = std::iter::once(parent(&watch.file))
            .chain(watch.subs.iter().map(|sub| sub.directory.clone()))
            .collect();
        sync_watches(watcher, &mut watch.dirs, &desired, ctx.callback);

        match fs_rx.recv_timeout(Duration::from_millis(100)) {
            Ok(Ok(event)) => {
                if event_touches_file(&event, &watch.file) {
                    pending_reload = true;
                    last_change = Instant::now();
                }
                for sub in watch.subs.iter().filter(|sub| sub.touched_by(&event)) {
                    pending_subs.insert(sub.name.clone());
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

        let settled = Instant::now() >= suppress_until
            && Instant::now().duration_since(last_change) >= debounce_window;
        if settled && !pending_subs.is_empty() {
            for name in std::mem::take(&mut pending_subs) {
                if let Ok(sub) = ctx.manager.sub_settings(&name) {
                    sub.invalidate_cache();
                    (ctx.callback)(HotReloadEvent::SubSettingsChanged { name });
                }
            }
            suppress_until = Instant::now() + self_write_suppression;
        }

        if pending_reload && settled {
            #[cfg(feature = "vault")]
            if ctx.manager.is_locked() {
                ctx.manager.invalidate_cache();
                (ctx.callback)(HotReloadEvent::SkippedLocked {
                    path: watch.file.clone(),
                });
                pending_reload = false;
                suppress_until = Instant::now() + self_write_suppression;
                continue;
            }

            ctx.manager.invalidate_cache();

            match ctx.manager.ensure_cache_populated() {
                Ok(()) => {
                    (ctx.callback)(HotReloadEvent::Reloaded {
                        path: watch.file.clone(),
                    });
                }
                Err(err) => {
                    (ctx.callback)(HotReloadEvent::ReloadFailed {
                        path: watch.file.clone(),
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
