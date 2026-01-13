use crate::CacheStrategy;
use crate::error::{Error, Result};
use crate::storage::StorageBackend;
use crate::sub_settings::store::SubSettingsStore;
use log::debug;
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

type SubSettingsMigrator = Arc<dyn Fn(Value) -> Value + Send + Sync>;

struct MultiFileStoreState {
    cache: Option<HashMap<String, Value>>,
}

pub struct MultiFileStore<S: StorageBackend> {
    name: String,
    base_dir: PathBuf,
    extension: String,
    storage: S,
    migrator: Option<SubSettingsMigrator>,
    cache_strategy: CacheStrategy,
    state: RwLock<MultiFileStoreState>,
}

impl<S: StorageBackend> MultiFileStore<S> {
    pub fn new(
        name: String,
        base_dir: PathBuf,
        extension: String,
        storage: S,
        migrator: Option<SubSettingsMigrator>,
        cache_strategy: CacheStrategy,
    ) -> Self {
        Self {
            name,
            base_dir,
            extension,
            storage,
            migrator,
            cache_strategy,
            state: RwLock::new(MultiFileStoreState { cache: None }),
        }
    }

    fn file_path(&self, key: &str) -> PathBuf {
        self.base_dir.join(format!("{}.{}", key, self.extension))
    }

    fn ensure_cache_populated(&self) {
        if matches!(self.cache_strategy, CacheStrategy::None) {
            return;
        }

        // Fast path
        if self.state.read().unwrap().cache.is_some() {
            return;
        }

        let mut state = self.state.write().unwrap();
        if state.cache.is_some() {
            return;
        }

        // Initialize empty cache - we load lazily or could load full directory?
        // Original logic was initializing empty map.
        state.cache = Some(HashMap::new());
    }
}

impl<S: StorageBackend> SubSettingsStore for MultiFileStore<S> {
    fn get(&self, key: &str) -> Result<Value> {
        self.ensure_cache_populated();

        // Check cache first
        {
            let state = self.state.read().unwrap();
            if let Some(cache) = &state.cache {
                if let Some(val) = cache.get(key) {
                    return Ok(val.clone());
                }
            }
        }

        // Read from disk
        let path = self.file_path(key);
        if !path.exists() {
            return Err(Error::SubSettingsEntryNotFound(format!(
                "{}/{}",
                self.name, key
            )));
        }

        let mut value: Value = self.storage.read(&path)?;

        // Migration logic
        if let Some(migrator) = &self.migrator {
            let original = value.clone();
            value = migrator(value);
            if value != original {
                debug!("Migrated sub-settings entry: {key}");
                self.storage.write(&path, &value)?;
            }
        }

        // Update cache
        {
            let mut state = self.state.write().unwrap();
            if let Some(cache) = &mut state.cache {
                cache.insert(key.to_string(), value.clone());
            }
        }

        Ok(value)
    }

    fn set(&self, key: &str, value: Value) -> Result<()> {
        // If value is null, treat as removal (TOML doesn't support nulls, and it's cleaner)
        if value.is_null() {
            return self.remove(key);
        }

        let path = self.file_path(key);

        // Ensure directory exists
        if !self.base_dir.exists() {
            crate::security::ensure_secure_dir(&self.base_dir)?;
        }

        self.storage.write(&path, &value)?;

        // Update cache
        if !matches!(self.cache_strategy, CacheStrategy::None) {
            let mut state = self.state.write().unwrap();
            // Initialize cache if needed (though set usually implies we want consistency)
            if state.cache.is_none() {
                state.cache = Some(HashMap::new());
            }
            if let Some(cache) = &mut state.cache {
                cache.insert(key.to_string(), value);
            }
        }

        Ok(())
    }

    fn remove(&self, key: &str) -> Result<()> {
        let path = self.file_path(key);

        if path.exists() {
            std::fs::remove_file(&path).map_err(|e| Error::FileDelete { path, source: e })?;
        }

        // Remove from cache
        let mut state = self.state.write().unwrap();
        if let Some(cache) = &mut state.cache {
            cache.remove(key);
        }

        Ok(())
    }

    fn list(&self) -> Result<Vec<String>> {
        if !self.base_dir.exists() {
            return Ok(Vec::new());
        }

        let mut entries = Vec::new();
        let ext = format!(".{}", self.extension);

        for entry in std::fs::read_dir(&self.base_dir).map_err(|e| Error::DirectoryRead {
            path: self.base_dir.clone(),
            source: e,
        })? {
            let entry = entry.map_err(|e| Error::DirectoryRead {
                path: self.base_dir.clone(),
                source: e,
            })?;
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with(&ext) {
                entries.push(name.trim_end_matches(&ext).to_string());
            }
        }

        entries.sort();
        Ok(entries)
    }

    fn invalidate_cache(&self) {
        let mut state = self.state.write().unwrap();
        state.cache = None;
    }

    fn get_base_path(&self) -> PathBuf {
        self.base_dir.clone()
    }

    fn get_single_file_path(&self) -> Option<PathBuf> {
        None
    }
}
