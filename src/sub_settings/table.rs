use crate::CacheStrategy;
use crate::error::{Error, Result};
use crate::storage::is_valid_sqlite_identifier;
use crate::sub_settings::SubSettingsConfig;
use crate::sub_settings::store::SubSettingsStore;
use crate::utils::security::{ensure_secure_dir, set_secure_file_permissions};
use crate::utils::sync::RwLockExt;
use log::debug;
use rusqlite::Connection;
use serde_json::Value;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

type SubSettingsMigrator = Arc<dyn Fn(Value) -> Value + Send + Sync>;

enum CacheType {
    Full(HashMap<String, Value>),
    Lru(lru::LruCache<String, Value>),
}

struct TableStoreState {
    cache: Option<CacheType>,
}

/// SQLite table storage backend for sub-settings.
///
/// Stores each sub-settings entity as a distinct row (`key`, `data`) in a
/// dedicated table inside a SQLite database file.
pub struct TableStore {
    name: String,
    table_name: String,
    base_dir: PathBuf,
    extension: String,
    migrator: Option<SubSettingsMigrator>,
    cache_strategy: CacheStrategy,
    #[cfg(feature = "vault")]
    vault: crate::vault::SharedVault,
    state: RwLock<TableStoreState>,
}

impl TableStore {
    /// Create a new `TableStore`.
    pub fn new(
        config: &SubSettingsConfig,
        base_dir: PathBuf,
        #[cfg(feature = "vault")] vault: crate::vault::SharedVault,
    ) -> Self {
        let table_name = config
            .table_name
            .clone()
            .unwrap_or_else(|| config.name.clone());
        let extension = config.extension.as_deref().unwrap_or("db").to_string();
        Self {
            name: config.name.clone(),
            table_name,
            base_dir,
            extension,
            migrator: config.migrator.clone(),
            cache_strategy: config.cache_strategy,
            #[cfg(feature = "vault")]
            vault,
            state: RwLock::new(TableStoreState { cache: None }),
        }
    }

    #[cfg(feature = "vault")]
    fn get_vault(&self) -> Result<Option<Arc<crate::vault::VaultState>>> {
        self.vault
            .read()
            .map(|g| g.clone())
            .map_err(|_| Error::LockPoisoned)
    }

    #[cfg(feature = "vault")]
    fn is_locked(&self) -> bool {
        if let Ok(guard) = self.vault.read()
            && let Some(ref vault) = *guard
        {
            return vault.is_locked();
        }
        false
    }

    fn file_path(&self) -> PathBuf {
        self.base_dir
            .join(format!("{}.{}", self.name, self.extension))
    }

    /// Export rows through a read-only connection, without schema setup or migrations.
    #[cfg(feature = "backup")]
    pub(crate) fn backup_entries(&self) -> Result<HashMap<String, Value>> {
        let path = self.file_path();
        if !path.exists() {
            return Ok(HashMap::new());
        }
        if !is_valid_sqlite_identifier(&self.table_name) {
            return Err(Error::Config("Invalid SQLite table name".into()));
        }
        let conn = Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|e| Error::Config(format!("sqlite backup open: {e}")))?;
        let table_exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
                [&self.table_name],
                |row| row.get(0),
            )
            .map_err(|e| Error::Config(format!("sqlite backup schema: {e}")))?;
        if !table_exists {
            return Ok(HashMap::new());
        }
        let mut stmt = conn
            .prepare(&format!("SELECT key, data FROM {}", self.table_name))
            .map_err(|e| Error::Config(format!("sqlite backup query: {e}")))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|e| Error::Config(format!("sqlite backup rows: {e}")))?;
        let mut entries = HashMap::new();
        for row in rows {
            let (name, content) =
                row.map_err(|e| Error::Config(format!("sqlite backup row: {e}")))?;
            let value: Value = serde_json::from_str(&content)?;
            #[cfg(feature = "vault")]
            let value = if crate::vault::is_vault_value(&value) {
                self.get_vault()?
                    .ok_or(Error::ConfigLocked)?
                    .decrypt_value(&value)?
            } else {
                value
            };
            entries.insert(name, value);
        }
        Ok(entries)
    }

    fn connect(&self) -> Result<Connection> {
        if !is_valid_sqlite_identifier(&self.table_name) {
            return Err(Error::Config(format!(
                "invalid SQLite table name: {:?}",
                self.table_name
            )));
        }

        let path = self.file_path();
        #[cfg(feature = "backup")]
        crate::backup::transaction::capture_file(&path)?;
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
            && !parent.exists()
        {
            ensure_secure_dir(parent)?;
        }

        Connection::open(&path)
            .map_err(|e| Error::Config(format!("sqlite open {}: {e}", path.display())))
    }

    fn ensure_schema(&self, conn: &Connection) -> Result<()> {
        let sql = format!(
            "CREATE TABLE IF NOT EXISTS {table} (
                key  TEXT PRIMARY KEY NOT NULL,
                data TEXT NOT NULL
            )",
            table = self.table_name
        );
        conn.execute(&sql, [])
            .map_err(|e| Error::Config(format!("sqlite create table: {e}")))?;
        Ok(())
    }

    fn create_cache(&self) -> CacheType {
        match self.cache_strategy {
            CacheStrategy::Full => CacheType::Full(HashMap::new()),
            CacheStrategy::Lru(size) => {
                let cap = NonZeroUsize::new(size).unwrap_or(NonZeroUsize::new(100).unwrap());
                CacheType::Lru(lru::LruCache::new(cap))
            }
            CacheStrategy::None => {
                unreachable!("Cache should not be initialized if strategy is None")
            }
        }
    }

    fn ensure_cache_populated(&self) -> Result<()> {
        if matches!(self.cache_strategy, CacheStrategy::None) {
            return Ok(());
        }

        if self.state.read_recovered()?.cache.is_some() {
            return Ok(());
        }

        let mut state = self.state.write_recovered()?;
        if state.cache.is_some() {
            return Ok(());
        }

        state.cache = Some(self.create_cache());
        Ok(())
    }
}

impl SubSettingsStore for TableStore {
    fn get(&self, key: &str) -> Result<Value> {
        #[cfg(feature = "vault")]
        if self.is_locked() {
            return Err(Error::ConfigLocked);
        }

        if !matches!(self.cache_strategy, CacheStrategy::None) {
            self.ensure_cache_populated()?;
            let mut state = self.state.write_recovered()?;
            if let Some(cache) = &mut state.cache {
                match cache {
                    CacheType::Full(c) => {
                        if let Some(val) = c.get(key)
                            && !val.is_null()
                        {
                            return Ok(val.clone());
                        }
                    }
                    CacheType::Lru(c) => {
                        if let Some(val) = c.get(key)
                            && !val.is_null()
                        {
                            return Ok(val.clone());
                        }
                    }
                }
            }
        }

        let path = self.file_path();
        if !path.exists() {
            return Err(Error::SubSettingsEntryNotFound(format!(
                "{}/{}",
                self.name, key
            )));
        }

        let conn = self.connect()?;
        self.ensure_schema(&conn)?;

        let sql = format!(
            "SELECT data FROM {table} WHERE key = ?1",
            table = self.table_name
        );
        let row_data: Option<String> = conn
            .query_row(&sql, rusqlite::params![key], |row| row.get(0))
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                _ => Err(e),
            })
            .map_err(|e| Error::Config(format!("sqlite query: {e}")))?;

        let Some(content) = row_data else {
            if !matches!(self.cache_strategy, CacheStrategy::None) {
                let mut state = self.state.write_recovered()?;
                if let Some(cache) = &mut state.cache {
                    match cache {
                        CacheType::Full(c) => {
                            c.remove(key);
                        }
                        CacheType::Lru(c) => {
                            c.pop(key);
                        }
                    }
                }
            }
            return Err(Error::SubSettingsEntryNotFound(format!(
                "{}/{}",
                self.name, key
            )));
        };

        let raw_val: Value = serde_json::from_str(&content).map_err(Error::from)?;

        #[cfg(feature = "vault")]
        let mut value = if crate::vault::is_vault_value(&raw_val) {
            let vault = self.get_vault()?.ok_or(Error::ConfigLocked)?;
            vault.decrypt_value(&raw_val)?
        } else {
            raw_val
        };

        #[cfg(not(feature = "vault"))]
        let mut value = raw_val;

        if let Some(migrator) = &self.migrator {
            let original = value.clone();
            value = migrator(value);
            if value != original {
                debug!("Migrated sub-settings table entry: {key}");
                self.set(key, value.clone())?;
            }
        }

        if !matches!(self.cache_strategy, CacheStrategy::None) {
            let mut state = self.state.write_recovered()?;
            if let Some(cache) = &mut state.cache {
                match cache {
                    CacheType::Full(c) => {
                        c.insert(key.to_string(), value.clone());
                    }
                    CacheType::Lru(c) => {
                        c.put(key.to_string(), value.clone());
                    }
                }
            }
        }

        Ok(value)
    }

    fn set(&self, key: &str, value: Value) -> Result<()> {
        #[cfg(feature = "vault")]
        if self.is_locked() {
            return Err(Error::ConfigLocked);
        }

        if value.is_null() {
            return self.remove(key);
        }

        #[cfg(feature = "vault")]
        let content = if let Some(vault) = self.get_vault()? {
            if vault.is_locked() {
                return Err(Error::ConfigLocked);
            }
            let serialized = serde_json::to_string(&value).map_err(Error::from)?;
            let envelope = vault.encrypt_payload(serialized.as_bytes())?;
            serde_json::to_string(&envelope).map_err(Error::from)?
        } else {
            serde_json::to_string(&value).map_err(Error::from)?
        };

        #[cfg(not(feature = "vault"))]
        let content = serde_json::to_string(&value).map_err(Error::from)?;

        let conn = self.connect()?;
        self.ensure_schema(&conn)?;

        let sql = format!(
            "INSERT INTO {table} (key, data) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET data = excluded.data",
            table = self.table_name
        );
        conn.execute(&sql, rusqlite::params![key, content])
            .map_err(|e| Error::Config(format!("sqlite upsert: {e}")))?;

        let path = self.file_path();
        let _ = set_secure_file_permissions(&path);

        if !matches!(self.cache_strategy, CacheStrategy::None) {
            let mut state = self.state.write_recovered()?;
            if state.cache.is_none() {
                state.cache = Some(self.create_cache());
            }
            if let Some(cache) = &mut state.cache {
                match cache {
                    CacheType::Full(c) => {
                        c.insert(key.to_string(), value);
                    }
                    CacheType::Lru(c) => {
                        c.put(key.to_string(), value);
                    }
                }
            }
        }

        Ok(())
    }

    fn remove(&self, key: &str) -> Result<()> {
        #[cfg(feature = "vault")]
        if self.is_locked() {
            return Err(Error::ConfigLocked);
        }

        let path = self.file_path();
        if !path.exists() {
            return Err(Error::SubSettingsEntryNotFound(format!(
                "{}/{}",
                self.name, key
            )));
        }

        let conn = self.connect()?;
        self.ensure_schema(&conn)?;

        let sql = format!(
            "DELETE FROM {table} WHERE key = ?1",
            table = self.table_name
        );
        let rows = conn
            .execute(&sql, rusqlite::params![key])
            .map_err(|e| Error::Config(format!("sqlite delete: {e}")))?;

        if !matches!(self.cache_strategy, CacheStrategy::None) {
            let mut state = self.state.write_recovered()?;
            if let Some(cache) = &mut state.cache {
                match cache {
                    CacheType::Full(c) => {
                        c.remove(key);
                    }
                    CacheType::Lru(c) => {
                        c.pop(key);
                    }
                }
            }
        }

        if rows == 0 {
            return Err(Error::SubSettingsEntryNotFound(format!(
                "{}/{}",
                self.name, key
            )));
        }

        Ok(())
    }

    fn exists(&self, key: &str) -> Result<bool> {
        #[cfg(feature = "vault")]
        if self.is_locked() {
            return Err(Error::ConfigLocked);
        }

        if !matches!(self.cache_strategy, CacheStrategy::None) {
            let state = self.state.read_recovered()?;
            if let Some(cache) = &state.cache {
                match cache {
                    CacheType::Full(c) => {
                        if let Some(val) = c.get(key)
                            && !val.is_null()
                        {
                            return Ok(true);
                        }
                    }
                    CacheType::Lru(c) => {
                        if let Some(val) = c.peek(key)
                            && !val.is_null()
                        {
                            return Ok(true);
                        }
                    }
                }
            }
        }

        let path = self.file_path();
        if !path.exists() {
            return Ok(false);
        }

        let conn = self.connect()?;
        self.ensure_schema(&conn)?;

        let sql = format!(
            "SELECT 1 FROM {table} WHERE key = ?1",
            table = self.table_name
        );
        let exists: bool = conn
            .query_row(&sql, rusqlite::params![key], |_| Ok(true))
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(false),
                _ => Err(e),
            })
            .map_err(|e| Error::Config(format!("sqlite exists: {e}")))?;

        Ok(exists)
    }

    fn list(&self) -> Result<Vec<String>> {
        #[cfg(feature = "vault")]
        if self.is_locked() {
            return Err(Error::ConfigLocked);
        }

        let path = self.file_path();
        if !path.exists() {
            return Ok(Vec::new());
        }

        let conn = self.connect()?;
        self.ensure_schema(&conn)?;

        let sql = format!(
            "SELECT key FROM {table} ORDER BY key",
            table = self.table_name
        );
        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| Error::Config(format!("sqlite prepare list: {e}")))?;

        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| Error::Config(format!("sqlite query map: {e}")))?;

        let mut keys = Vec::new();
        for key_res in rows {
            let key = key_res.map_err(|e| Error::Config(format!("sqlite row key: {e}")))?;
            keys.push(key);
        }

        Ok(keys)
    }

    fn get_all(&self) -> Result<HashMap<String, Value>> {
        #[cfg(feature = "vault")]
        if self.is_locked() {
            return Err(Error::ConfigLocked);
        }

        let path = self.file_path();
        if !path.exists() {
            return Ok(HashMap::new());
        }

        let conn = self.connect()?;
        self.ensure_schema(&conn)?;

        let sql = format!("SELECT key, data FROM {table}", table = self.table_name);
        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| Error::Config(format!("sqlite prepare get_all: {e}")))?;

        let rows = stmt
            .query_map([], |row| {
                let key: String = row.get(0)?;
                let data: String = row.get(1)?;
                Ok((key, data))
            })
            .map_err(|e| Error::Config(format!("sqlite query map: {e}")))?;

        let mut result = HashMap::new();
        let mut migrations_to_save = Vec::new();

        for row_res in rows {
            let (key, content) =
                row_res.map_err(|e| Error::Config(format!("sqlite row read: {e}")))?;
            let raw_val: Value = serde_json::from_str(&content).map_err(Error::from)?;

            #[cfg(feature = "vault")]
            let mut value = if crate::vault::is_vault_value(&raw_val) {
                let vault = self.get_vault()?.ok_or(Error::ConfigLocked)?;
                if let Some(decrypted_str) = vault.decrypt_vault_value_to_str(&raw_val)? {
                    serde_json::from_str(&decrypted_str).map_err(Error::from)?
                } else {
                    raw_val
                }
            } else {
                raw_val
            };

            #[cfg(not(feature = "vault"))]
            let mut value = raw_val;

            if let Some(migrator) = &self.migrator {
                let original = value.clone();
                value = migrator(value);
                if value != original {
                    #[cfg(feature = "vault")]
                    let new_content = if let Some(vault) = self.get_vault()? {
                        if vault.is_locked() {
                            return Err(Error::ConfigLocked);
                        }
                        let serialized = serde_json::to_string(&value).map_err(Error::from)?;
                        let envelope = vault.encrypt_payload(serialized.as_bytes())?;
                        serde_json::to_string(&envelope).map_err(Error::from)?
                    } else {
                        serde_json::to_string(&value).map_err(Error::from)?
                    };

                    #[cfg(not(feature = "vault"))]
                    let new_content = serde_json::to_string(&value).map_err(Error::from)?;

                    migrations_to_save.push((key.clone(), new_content));
                }
            }

            result.insert(key, value);
        }

        for (key, new_content) in migrations_to_save {
            debug!("Migrated sub-settings table entry during get_all: {key}");
            let upsert_sql = format!(
                "INSERT INTO {table} (key, data) VALUES (?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET data = excluded.data",
                table = self.table_name
            );
            conn.execute(&upsert_sql, rusqlite::params![key, new_content])
                .map_err(|e| Error::Config(format!("sqlite upsert: {e}")))?;
        }

        if matches!(self.cache_strategy, CacheStrategy::Full) {
            let mut state = self.state.write_recovered()?;
            state.cache = Some(CacheType::Full(result.clone()));
        }

        Ok(result)
    }

    fn invalidate_cache(&self) {
        if let Ok(mut state) = self.state.write_recovered() {
            state.cache = None;
        }
    }

    fn base_path(&self) -> PathBuf {
        self.base_dir.clone()
    }

    fn single_file_path(&self) -> Option<PathBuf> {
        Some(self.file_path())
    }
}
