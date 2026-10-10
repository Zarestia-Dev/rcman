//! In-process backup isolation and a restore undo journal. Direct backend access
//! and other processes must be quiesced by the caller.

use crate::{Error, Result};
use std::cell::RefCell;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

// Only the registry is global. Claims on unrelated directories never conflict.
static OPERATIONS: Mutex<Vec<Arc<Claim>>> = Mutex::new(Vec::new());
thread_local! {
    static JOURNAL: RefCell<Option<Journal>> = const { RefCell::new(None) };
}

#[derive(PartialEq, Eq)]
enum Resource {
    Directory(PathBuf),
    #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
    Credentials(String),
}

impl Resource {
    fn overlaps(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Directory(a), Self::Directory(b)) => a.starts_with(b) || b.starts_with(a),
            #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
            _ => self == other,
        }
    }
}

struct Claim {
    resources: Vec<Resource>,
    thread: std::thread::ThreadId,
    exclusive: bool,
}

pub(crate) struct Operation {
    claim: Arc<Claim>,
    // Reentrancy belongs to the acquiring thread.
    _thread: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl Drop for Operation {
    fn drop(&mut self) {
        let mut claims = OPERATIONS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        claims.retain(|claim| !Arc::ptr_eq(claim, &self.claim));
    }
}

// Resolve aliases, including paths whose final directories do not exist yet.
fn directory(path: &Path) -> Result<Resource> {
    let absolute = std::path::absolute(path).map_err(|error| io_error(&error))?;
    let mut existing = absolute.as_path();
    let mut suffix = Vec::new();
    while !existing.exists() {
        if let Some(name) = existing.file_name() {
            suffix.push(name.to_owned());
        }
        existing = existing
            .parent()
            .ok_or_else(|| Error::Config("Invalid configuration path".into()))?;
    }
    let mut resolved = existing.canonicalize().map_err(|error| io_error(&error))?;
    for name in suffix.into_iter().rev() {
        resolved.push(name);
    }
    Ok(Resource::Directory(resolved))
}

fn acquire(resources: Vec<Resource>, exclusive: bool) -> Result<Operation> {
    let thread = std::thread::current().id();
    let mut claims = OPERATIONS.lock().map_err(|_| Error::LockPoisoned)?;
    for claim in claims.iter() {
        if !exclusive && !claim.exclusive {
            continue;
        }
        let mut overlaps = false;
        for resource in &resources {
            for other in &claim.resources {
                overlaps |= match (resource, other) {
                    (Resource::Directory(a), Resource::Directory(b)) => {
                        directory(a)?.overlaps(&directory(b)?)
                    }
                    #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
                    _ => resource.overlaps(other),
                };
            }
        }
        // Reads within this thread's exclusive operation are needed by restore.
        // Reentrant exclusive operations would invalidate the current snapshot.
        if overlaps && (exclusive || (claim.exclusive && claim.thread != thread)) {
            return Err(busy());
        }
    }
    let claim = Arc::new(Claim {
        resources,
        thread,
        exclusive,
    });
    claims.push(Arc::clone(&claim));
    Ok(Operation {
        claim,
        _thread: std::marker::PhantomData,
    })
}

pub(crate) fn enter(path: &Path) -> Result<Operation> {
    let absolute = std::path::absolute(path).map_err(|error| io_error(&error))?;
    acquire(vec![Resource::Directory(absolute)], false)
}

#[cfg(any(feature = "keychain", feature = "encrypted-file"))]
pub(crate) fn enter_credentials(service: &str) -> Result<Operation> {
    acquire(vec![Resource::Credentials(service.to_owned())], false)
}

pub(super) fn exclusive(
    path: &Path,
    #[cfg(any(feature = "keychain", feature = "encrypted-file"))] credentials: Option<&str>,
) -> Result<Operation> {
    let resources = vec![directory(path)?];
    #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
    let resources = {
        let mut resources = resources;
        if let Some(service) = credentials {
            resources.push(Resource::Credentials(service.to_owned()));
        }
        resources
    };
    acquire(resources, true)
}

fn busy() -> Error {
    Error::Config("Another settings operation is in progress; retry after it finishes".into())
}

type Undo = Box<dyn FnOnce() -> Result<()>>;
struct Journal {
    scope: Arc<Claim>,
    files: HashSet<PathBuf>,
    undo: Vec<Undo>,
    notifications: Vec<Box<dyn FnOnce()>>,
}

pub(super) struct Transaction<'a> {
    operation: &'a Operation,
}
impl<'a> Transaction<'a> {
    pub(super) fn begin(operation: &'a Operation) -> Result<Self> {
        JOURNAL.with(|journal| {
            let mut journal = journal.borrow_mut();
            if journal.is_some() {
                return Err(busy());
            }
            *journal = Some(Journal {
                scope: Arc::clone(&operation.claim),
                files: HashSet::new(),
                undo: Vec::new(),
                notifications: Vec::new(),
            });
            Ok(Self { operation })
        })
    }

    pub(super) fn finish(self, result: Result<()>) -> Result<Vec<Box<dyn FnOnce()>>> {
        let journal = JOURNAL
            .with(|journal| journal.borrow_mut().take())
            .ok_or(Error::NotInitialized)?;
        drop(self);
        match result {
            Ok(()) => Ok(journal.notifications),
            Err(original) => {
                let errors = rollback(journal);
                if errors.is_empty() {
                    Err(original)
                } else {
                    Err(Error::RestoreFailed(format!(
                        "{original}; rollback incomplete: {}",
                        errors.join("; ")
                    )))
                }
            }
        }
    }
}

impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        if let Some(journal) = JOURNAL.with(|journal| journal.borrow_mut().take()) {
            debug_assert!(Arc::ptr_eq(&journal.scope, &self.operation.claim));
            for error in rollback(journal) {
                log::error!("Restore rollback: {error}");
            }
        }
    }
}

fn rollback(journal: Journal) -> Vec<String> {
    journal
        .undo
        .into_iter()
        .rev()
        .filter_map(|undo| undo().err().map(|e| e.to_string()))
        .collect()
}

pub(crate) fn defer(path: &Path, notification: Box<dyn FnOnce()>) {
    let notification = JOURNAL.with(|journal| {
        if let Some(journal) = journal.borrow_mut().as_mut()
            && directory(path).is_ok_and(|resource| {
                journal
                    .scope
                    .resources
                    .iter()
                    .any(|scope| scope.overlaps(&resource))
            })
        {
            journal.notifications.push(notification);
            None
        } else {
            Some(notification)
        }
    });
    if let Some(notification) = notification {
        notification();
    }
}

pub(crate) fn capture_file(path: &Path) -> Result<()> {
    JOURNAL.with(|journal| {
        let mut journal = journal.borrow_mut();
        let Some(journal) = journal.as_mut() else {
            return Ok(());
        };
        let resource = directory(path)?;
        if !journal
            .scope
            .resources
            .iter()
            .any(|scope| scope.overlaps(&resource))
        {
            return Ok(());
        }
        let path = std::path::absolute(path).map_err(|error| io_error(&error))?;
        if journal.files.contains(&path) {
            return Ok(());
        }
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_file() => Some(metadata),
            Ok(_) => {
                return Err(Error::RestoreFailed(format!(
                    "Restore target is not a regular file: {}",
                    path.display()
                )));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(io_error(&error)),
        };
        let missing_dirs: Vec<_> = path
            .ancestors()
            .skip(1)
            .take_while(|dir| !dir.exists())
            .map(Path::to_path_buf)
            .collect();
        #[cfg(feature = "sqlite")]
        if let Some(ref metadata) = metadata
            && let Some(undo) = sqlite_undo(&path, metadata.permissions())?
        {
            journal.files.insert(path);
            journal.undo.push(undo);
            return Ok(());
        }
        let snapshot = if let Some(ref metadata) = metadata {
            let mut copy = tempfile::NamedTempFile::new().map_err(|error| io_error(&error))?;
            std::io::copy(
                &mut std::fs::File::open(&path).map_err(|error| io_error(&error))?,
                &mut copy,
            )
            .map_err(|error| io_error(&error))?;
            copy.as_file()
                .sync_all()
                .map_err(|error| io_error(&error))?;
            Some((copy, metadata.permissions()))
        } else {
            None
        };
        journal.files.insert(path.clone());
        journal.undo.push(Box::new(move || {
            if let Some((copy, permissions)) = snapshot {
                let restored = restore_snapshot(&path, copy.path(), permissions);
                if let Err(error) = restored {
                    let recovery = copy
                        .into_temp_path()
                        .keep()
                        .map_err(|e| Error::RestoreFailed(e.to_string()))?;
                    return Err(Error::RestoreFailed(format!(
                        "{error}; original file retained at {}",
                        recovery.display()
                    )));
                }
            } else if path.exists() {
                std::fs::remove_file(&path).map_err(|error| io_error(&error))?;
            }
            remove_created_directories(&missing_dirs)?;
            Ok(())
        }));
        Ok(())
    })
}

fn restore_snapshot(path: &Path, copy: &Path, permissions: std::fs::Permissions) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| Error::RestoreFailed("Missing parent".into()))?;
    let mut staged = tempfile::NamedTempFile::new_in(parent).map_err(|error| io_error(&error))?;
    std::io::copy(
        &mut std::fs::File::open(copy).map_err(|error| io_error(&error))?,
        &mut staged,
    )
    .map_err(|error| io_error(&error))?;
    staged
        .as_file()
        .set_permissions(permissions)
        .map_err(|error| io_error(&error))?;
    staged
        .as_file()
        .sync_all()
        .map_err(|error| io_error(&error))?;
    staged
        .persist(path)
        .map_err(|e| Error::RestoreFailed(e.to_string()))?;
    Ok(())
}

fn remove_created_directories(directories: &[PathBuf]) -> Result<()> {
    for dir in directories {
        match std::fs::remove_dir(dir) {
            Ok(()) => {}
            Err(e)
                if e.kind() == std::io::ErrorKind::NotFound
                    || e.kind() == std::io::ErrorKind::DirectoryNotEmpty => {}
            Err(e) => return Err(io_error(&e)),
        }
    }
    Ok(())
}

#[cfg(feature = "sqlite")]
fn sqlite_undo(path: &Path, permissions: std::fs::Permissions) -> Result<Option<Undo>> {
    use std::io::Read;
    let mut header = [0_u8; 16];
    let read = std::fs::File::open(path)
        .map_err(|error| io_error(&error))?
        .read(&mut header)
        .map_err(|error| io_error(&error))?;
    if read == header.len() && &header == b"SQLite format 3\0" {
        let snapshot = tempfile::NamedTempFile::new().map_err(|error| io_error(&error))?;
        let connection =
            rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .map_err(|e| Error::RestoreFailed(e.to_string()))?;
        connection
            .backup(rusqlite::DatabaseName::Main, snapshot.path(), None)
            .map_err(|e| Error::RestoreFailed(e.to_string()))?;
        let path = path.to_path_buf();
        return Ok(Some(Box::new(move || {
            let restored = (|| -> Result<()> {
                let mut connection = rusqlite::Connection::open(&path)
                    .map_err(|e| Error::RestoreFailed(e.to_string()))?;
                connection
                    .restore(
                        rusqlite::DatabaseName::Main,
                        snapshot.path(),
                        None::<fn(rusqlite::backup::Progress)>,
                    )
                    .map_err(|e| Error::RestoreFailed(e.to_string()))?;
                std::fs::set_permissions(&path, permissions).map_err(|error| io_error(&error))?;
                Ok(())
            })();
            if let Err(error) = restored {
                let recovery = snapshot
                    .into_temp_path()
                    .keep()
                    .map_err(|e| Error::RestoreFailed(e.to_string()))?;
                return Err(Error::RestoreFailed(format!(
                    "{error}; database snapshot retained at {}",
                    recovery.display()
                )));
            }
            Ok(())
        })));
    }
    Ok(None)
}

#[cfg(any(feature = "keychain", feature = "encrypted-file"))]
pub(crate) fn capture_credential(
    backend: std::sync::Arc<dyn crate::credentials::CredentialBackend>,
    key: &str,
    service: &str,
) -> Result<()> {
    if !active(service) {
        return Ok(());
    }
    // Backends are application code and may reenter managed APIs.
    let value = backend.get(key)?;
    let key = key.to_owned();
    JOURNAL.with(|journal| {
        if let Some(journal) = journal.borrow_mut().as_mut() {
            journal.undo.push(Box::new(move || match value {
                Some(value) => backend.store(&key, &value),
                None => backend.remove(&key),
            }));
        }
    });
    Ok(())
}

#[cfg(any(feature = "keychain", feature = "encrypted-file"))]
pub(crate) fn active(service: &str) -> bool {
    JOURNAL.with(|journal| {
        journal.borrow().as_ref().is_some_and(|journal| {
            journal
                .scope
                .resources
                .contains(&Resource::Credentials(service.to_owned()))
        })
    })
}

fn io_error(error: &std::io::Error) -> Error {
    Error::RestoreFailed(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn isolate(path: &Path) -> Operation {
        exclusive(
            path,
            #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
            None,
        )
        .unwrap()
    }

    #[test]
    fn unrelated_managers_and_backups_remain_available() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let output = tempfile::tempdir().unwrap();
        let _operation_guard = isolate(first.path());
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let manager = crate::SettingsManager::builder("independent-backup", "1")
                        .with_config_dir(second.path())
                        .build()
                        .unwrap();
                    manager.get_all_data().unwrap();
                    manager
                        .backup()
                        .create(&crate::BackupOptions::default().output_dir(output.path()))
                        .unwrap();
                })
                .join()
                .unwrap();
        });
    }

    #[test]
    fn shared_and_nested_paths_conflict_but_restore_can_reenter() {
        let dir = tempfile::tempdir().unwrap();
        let _operation_guard = isolate(dir.path());
        let _nested = enter(&dir.path().join("profiles/default")).unwrap();
        assert!(
            exclusive(
                dir.path(),
                #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
                None
            )
            .is_err()
        );
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    assert!(enter(dir.path()).is_err());
                    assert!(enter(&dir.path().join("profiles/default")).is_err());
                })
                .join()
                .unwrap();
        });
        drop(_nested);
        drop(_operation_guard);
        assert!(enter(dir.path()).is_ok());
    }

    #[test]
    fn rollback_does_not_capture_unrelated_callback_writes() {
        let target = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let path = other.path().join("settings.json");
        let operation = isolate(target.path());
        let transaction = Transaction::begin(&operation).unwrap();
        crate::storage::StorageBackend::write(
            &crate::JsonStorage::default(),
            &path,
            &serde_json::json!({"value": 1}),
        )
        .unwrap();
        let notified = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = std::sync::Arc::clone(&notified);
        defer(
            other.path(),
            Box::new(move || {
                flag.store(true, std::sync::atomic::Ordering::Relaxed);
            }),
        );
        assert!(
            transaction
                .finish(Err(Error::RestoreFailed("injected".into())))
                .is_err()
        );
        assert!(path.exists());
        assert!(notified.load(std::sync::atomic::Ordering::Relaxed));
    }

    #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
    #[test]
    fn credential_namespace_is_isolated_across_directories() {
        let dir = tempfile::tempdir().unwrap();
        let service = dir.path().to_string_lossy().into_owned();
        let _operation_guard = exclusive(dir.path(), Some(&service)).unwrap();
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    assert!(enter_credentials(&service).is_err());
                    assert!(enter_credentials("unrelated-service").is_ok());
                })
                .join()
                .unwrap();
        });
    }

    #[cfg(unix)]
    #[test]
    fn symlink_aliases_share_isolation() {
        let dir = tempfile::tempdir().unwrap();
        let aliases = tempfile::tempdir().unwrap();
        let alias = aliases.path().join("alias");
        std::os::unix::fs::symlink(dir.path(), &alias).unwrap();
        let _operation_guard = isolate(dir.path());
        std::thread::spawn(move || assert!(enter(&alias).is_err()))
            .join()
            .unwrap();
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn rollback_restores_committed_wal_pages() {
        let dir = tempfile::tempdir().unwrap();
        let _operation_guard = exclusive(
            dir.path(),
            #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
            None,
        )
        .unwrap();
        let path = dir.path().join("settings.db");
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE settings(value TEXT); INSERT INTO settings VALUES ('before');").unwrap();
        let transaction = Transaction::begin(&_operation_guard).unwrap();
        capture_file(&path).unwrap();
        connection
            .execute("UPDATE settings SET value = 'after'", [])
            .unwrap();
        assert!(
            transaction
                .finish(Err(Error::RestoreFailed("injected".into())))
                .is_err()
        );
        let value: String = connection
            .query_row("SELECT value FROM settings", [], |row| row.get(0))
            .unwrap();
        assert_eq!(value, "before");
    }
}
