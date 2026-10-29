//! Rebind managed identities when a profile is explicitly duplicated or renamed.

use super::VaultState;
use crate::{Error, Result, StorageBackend};
use serde_json::Value;
use std::path::Path;

pub(crate) fn copy_profile<S: StorageBackend>(
    storage: &S,
    vault: &VaultState,
    source: &Path,
    target: &Path,
) -> Result<()> {
    if target.exists() {
        return Err(Error::Config(
            "Profile destination already exists on disk".into(),
        ));
    }
    let _pin = vault.begin_migration()?;
    let result = copy_directory(storage, vault, source, target);
    if let Err(source) = result {
        if target.exists()
            && let Err(error) = std::fs::remove_dir_all(target)
        {
            return Err(Error::TransactionFailed {
                source: Box::new(source),
                rollback_errors: vec![error.to_string()],
            });
        }
        return Err(source);
    }
    Ok(())
}

/// Moves flat data into the default profile of an unlocked vault.
///
/// Ciphertext is bound to its file path, so a plain rename would make it
/// unreadable; every file is decrypted at its old path and encrypted at the new
/// one. Flat data is removed only after every file is copied, and the manifest is
/// written last. A restart at any point therefore sees either the complete flat
/// layout (retried) or the complete profiled one.
pub(crate) fn migrate_to_default_profile<S: StorageBackend>(
    storage: &S,
    vault: &VaultState,
    root_dir: &Path,
    target_name: &str,
    single_file_mode: bool,
) -> Result<()> {
    let extension = storage.extension();
    let manifest_path = root_dir.join(format!(".profiles.{extension}"));
    let profile_dir = root_dir
        .join(crate::profiles::PROFILES_DIR)
        .join(crate::profiles::DEFAULT_PROFILE);

    let mut sources = Vec::new();
    if single_file_mode {
        let flat = root_dir.with_extension(extension);
        if flat.is_file() {
            sources.push((flat, profile_dir.join(format!("{target_name}.{extension}"))));
        }
    } else {
        for entry in crate::error::read_dir(root_dir)? {
            let entry = entry.map_err(|source| Error::DirectoryRead {
                path: root_dir.to_path_buf(),
                source,
            })?;
            let name = entry.file_name();
            if name == crate::profiles::PROFILES_DIR
                || name == format!(".profiles.{extension}").as_str()
                || name == super::metadata::FILE_NAME
            {
                continue;
            }
            sources.push((entry.path(), profile_dir.join(name)));
        }
    }

    let _pin = vault.begin_migration()?;
    let created = !profile_dir.exists();
    let copied = (|| {
        crate::utils::security::ensure_secure_dir(&profile_dir)?;
        for (from, to) in &sources {
            let kind = std::fs::symlink_metadata(from)
                .map_err(|source| Error::FileRead {
                    path: from.clone(),
                    source,
                })?
                .file_type();
            if kind.is_symlink() {
                return Err(Error::Vault(
                    "Cannot relocate vault data containing symbolic links".into(),
                ));
            }
            if kind.is_dir() {
                copy_directory(storage, vault, from, to)?;
            } else {
                relocate_file(storage, vault, from, to)?;
            }
        }
        Ok(())
    })();
    if let Err(error) = copied {
        // The flat data is untouched, so a partial copy is only clutter.
        if created {
            let _ = std::fs::remove_dir_all(&profile_dir);
        }
        return Err(error);
    }

    for (from, _) in &sources {
        let removed = if from.is_dir() {
            std::fs::remove_dir_all(from)
        } else {
            std::fs::remove_file(from)
        };
        removed.map_err(|source| Error::FileWrite {
            path: from.clone(),
            source,
        })?;
    }
    if !manifest_path.exists() {
        storage.write(&manifest_path, &crate::profiles::ProfileManifest::default())?;
    }
    Ok(())
}

fn copy_directory<S: StorageBackend>(
    storage: &S,
    vault: &VaultState,
    source: &Path,
    target: &Path,
) -> Result<()> {
    crate::utils::security::ensure_secure_dir(target)?;
    if !source.exists() {
        return Ok(());
    }
    for entry in crate::error::read_dir(source)? {
        let entry = entry.map_err(|source_error| Error::DirectoryRead {
            path: source.to_path_buf(),
            source: source_error,
        })?;
        let from = entry.path();
        let to = target.join(entry.file_name());
        let kind = entry.file_type().map_err(|source| Error::FileRead {
            path: from.clone(),
            source,
        })?;
        if kind.is_symlink() {
            return Err(Error::Vault(
                "Cannot relocate a vault profile containing symbolic links".into(),
            ));
        }
        if kind.is_dir() {
            copy_directory(storage, vault, &from, &to)?;
            continue;
        }
        relocate_file(storage, vault, &from, &to)?;
    }
    Ok(())
}

/// Rebinds one managed file to the identity of `to`. Unmanaged files are copied as is.
fn relocate_file<S: StorageBackend>(
    storage: &S,
    vault: &VaultState,
    from: &Path,
    to: &Path,
) -> Result<()> {
    #[cfg(feature = "sqlite")]
    if is_sqlite_sidecar(from)? {
        return Ok(());
    }
    #[cfg(feature = "sqlite")]
    if copy_sqlite(vault, from, to)? {
        return Ok(());
    }
    if let Ok(value) = storage.read::<Value>(from)
        && value.get("__rcman_vault__").is_some()
    {
        let plaintext = vault.decrypt_managed(&value, from, storage.vault_entry_id().as_deref())?;
        storage.write(
            to,
            &vault.encrypt_managed(
                plaintext.as_bytes(),
                to,
                storage.vault_entry_id().as_deref(),
            )?,
        )?;
    } else {
        std::fs::copy(from, to).map_err(|source| Error::FileWrite {
            path: to.to_path_buf(),
            source,
        })?;
    }
    crate::utils::security::set_secure_file_permissions(to)
}

#[cfg(feature = "sqlite")]
fn is_sqlite(path: &Path) -> Result<bool> {
    use std::io::Read;
    let mut header = [0; 16];
    let mut file = std::fs::File::open(path).map_err(|error| Error::FileRead {
        path: path.to_path_buf(),
        source: error,
    })?;
    Ok(file.read(&mut header).map_err(|error| Error::FileRead {
        path: path.to_path_buf(),
        source: error,
    })? == 16
        && &header == b"SQLite format 3\0")
}

#[cfg(feature = "sqlite")]
fn is_sqlite_sidecar(path: &Path) -> Result<bool> {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return Ok(false);
    };
    for suffix in ["-wal", "-shm", "-journal"] {
        if let Some(base) = name.strip_suffix(suffix) {
            let database = path.with_file_name(base);
            if database.is_file() && is_sqlite(&database)? {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

#[cfg(feature = "sqlite")]
fn copy_sqlite(vault: &VaultState, source: &Path, target: &Path) -> Result<bool> {
    if !is_sqlite(source)? {
        return Ok(false);
    }
    let sql_error =
        |error: rusqlite::Error| Error::Vault(format!("Cannot relocate SQLite profile: {error}"));
    let original =
        rusqlite::Connection::open_with_flags(source, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(sql_error)?;
    original
        .backup(rusqlite::DatabaseName::Main, target, None)
        .map_err(sql_error)?;
    let mut destination = rusqlite::Connection::open(target).map_err(sql_error)?;
    destination
        .pragma_update(None, "secure_delete", "ON")
        .map_err(sql_error)?;
    let tables = {
        let mut query = destination
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
            .map_err(sql_error)?;
        query
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(sql_error)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(sql_error)?
    };
    let transaction = destination.transaction().map_err(sql_error)?;
    for table in tables {
        let quoted = format!("\"{}\"", table.replace('"', "\"\""));
        let mut schema = transaction
            .prepare(&format!("PRAGMA table_info({quoted})"))
            .map_err(sql_error)?;
        let columns = schema
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(sql_error)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(sql_error)?;
        if !columns.iter().any(|name| name == "key") || !columns.iter().any(|name| name == "data") {
            continue;
        }
        let mut query = transaction
            .prepare(&format!("SELECT key, data FROM {quoted}"))
            .map_err(sql_error)?;
        let rows = query
            .query_map([], |row| {
                let rusqlite::types::ValueRef::Text(content) = row.get_ref(1)? else {
                    return Ok(None);
                };
                let Ok(value) = serde_json::from_slice::<Value>(content) else {
                    return Ok(None);
                };
                if value.get("__rcman_vault__").is_none() {
                    return Ok(None);
                }
                Ok(Some((row.get::<_, String>(0)?, value)))
            })
            .map_err(sql_error)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(sql_error)?;
        // Unrelated application rows retain their original SQLite types and bytes.
        for (key, value) in rows.into_iter().flatten() {
            let entry = crate::storage::sqlite_entry_id(&table, &key);
            let plaintext = vault.decrypt_managed(&value, source, Some(&entry))?;
            let replacement = vault.encrypt_managed(plaintext.as_bytes(), target, Some(&entry))?;
            transaction
                .execute(
                    &format!("UPDATE {quoted} SET data = ?1 WHERE key = ?2"),
                    rusqlite::params![serde_json::to_string(&replacement)?, key],
                )
                .map_err(sql_error)?;
        }
    }
    transaction.commit().map_err(sql_error)?;
    destination.execute_batch("VACUUM").map_err(sql_error)?;
    crate::storage::checkpoint_encrypted(&destination)?;
    crate::utils::security::set_secure_file_permissions(target)?;
    Ok(true)
}
