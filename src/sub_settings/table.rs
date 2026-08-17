use crate::CacheStrategy;
use crate::error::{Error, Result};
use crate::storage::is_valid_sqlite_identifier;
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
    state: RwLock<TableStoreState>,
}

impl TableStore {
    /// Create a new `TableStore`.
    pub fn new(
        name: String,
        table_name: String,
        base_dir: PathBuf,
        extension: String,
        migrator: Option<SubSettingsMigrator>,
        cache_strategy: CacheStrategy,
    ) -> Self {
        Self {
            name,
            table_name,
            base_dir,
            extension,
            migrator,
            cache_strategy,
            state: RwLock::new(TableStoreState { cache: None }),
        }
    }

    fn file_path(&self) -> PathBuf {
        self.base_dir
            .join(format!("{}.{}", self.name, self.extension))
    }

    fn connect(&self) -> Result<Connection> {
        if !is_valid_sqlite_identifier(&self.table_name) {
            return Err(Error::Config(format!(
                "invalid SQLite table name: {:?}",
                self.table_name
            )));
        }

        let path = self.file_path();
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

        let content = match row_data {
            Some(data) => data,
            None => {
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
            }
        };

        let mut value: Value = serde_json::from_str(&content).map_err(Error::from)?;

        if let Some(migrator) = &self.migrator {
            let original = value.clone();
            value = migrator(value);
            if value != original {
                debug!("Migrated sub-settings table entry: {key}");
                let new_content = serde_json::to_string(&value).map_err(Error::from)?;
                let upsert_sql = format!(
                    "INSERT INTO {table} (key, data) VALUES (?1, ?2)
                     ON CONFLICT(key) DO UPDATE SET data = excluded.data",
                    table = self.table_name
                );
                conn.execute(&upsert_sql, rusqlite::params![key, new_content])
                    .map_err(|e| Error::Config(format!("sqlite upsert: {e}")))?;
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
        if value.is_null() {
            return self.remove(key);
        }

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
            let mut value: Value = serde_json::from_str(&content).map_err(Error::from)?;

            if let Some(migrator) = &self.migrator {
                let original = value.clone();
                value = migrator(value);
                if value != original {
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
