use crate::CacheStrategy;
use crate::error::{Error, Result};
use crate::storage::StorageBackend;
use crate::sub_settings::store::SubSettingsStore;
use crate::utils::sync::RwLockExt;
use log::debug;
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

type SubSettingsMigrator = Arc<dyn Fn(Value) -> Value + Send + Sync>;

struct MultiFileStoreState {
    cache: Option<HashMap<String, Value>>,
    loaded_from_dir: bool,
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
            state: RwLock::new(MultiFileStoreState {
                cache: None,
                loaded_from_dir: false,
            }),
        }
    }

    fn file_path(&self, key: &str) -> PathBuf {
        self.base_dir.join(format!("{}.{}", key, self.extension))
    }

    fn ensure_cache_populated(&self) -> Result<()> {
        if matches!(self.cache_strategy, CacheStrategy::None) {
            return Ok(());
        }

        // Fast path
        if self.state.read_recovered()?.cache.is_some() {
            return Ok(());
        }

        let mut state = self.state.write_recovered()?;
        if state.cache.is_some() {
            return Ok(());
        }

        state.cache = Some(HashMap::new());
        Ok(())
    }

    fn load_directory_into_cache_keys(&self) -> Result<()> {
        if matches!(self.cache_strategy, CacheStrategy::None) {
            return Ok(());
        }

        if self.state.read_recovered()?.loaded_from_dir {
            return Ok(());
        }

        let mut state = self.state.write_recovered()?;
        if state.loaded_from_dir {
            return Ok(());
        }

        // Make sure cache map exists
        if state.cache.is_none() {
            state.cache = Some(HashMap::new());
        }

        if !self.base_dir.exists() {
            state.loaded_from_dir = true;
            return Ok(());
        }

        let ext = format!(".{}", self.extension);
        if let Some(cache) = &mut state.cache {
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
                    let key = name.trim_end_matches(&ext).to_string();
                    // Insert a null placeholder to indicate the file exists,
                    // without eagerly reading the contents from disk
                    cache.entry(key).or_insert(Value::Null);
                }
            }
        }

        state.loaded_from_dir = true;
        Ok(())
    }
}

impl<S: StorageBackend> SubSettingsStore for MultiFileStore<S> {
    fn get(&self, key: &str) -> Result<Value> {
        self.ensure_cache_populated()?;

        // Check cache first
        {
            let state = self.state.read_recovered()?;
            if let Some(cache) = &state.cache
                && let Some(val) = cache.get(key)
            {
                // If it's not a null placeholder, return it immediately
                if !val.is_null() {
                    return Ok(val.clone());
                }
            }
        }

        // Read from disk
        let path = self.file_path(key);
        if !path.exists() {
            // Remove null placeholder if it incorrectly existed
            if let Ok(mut state) = self.state.write_recovered()
                && let Some(cache) = &mut state.cache
            {
                cache.remove(key);
            }
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
        if !matches!(self.cache_strategy, CacheStrategy::None) {
            let mut state = self.state.write_recovered()?;
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
            crate::utils::security::ensure_secure_dir(&self.base_dir)?;
        }

        self.storage.write(&path, &value)?;

        // Update cache
        if !matches!(self.cache_strategy, CacheStrategy::None) {
            let mut state = self.state.write_recovered()?;
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
        let mut state = self.state.write_recovered()?;
        if let Some(cache) = &mut state.cache {
            cache.remove(key);
        }

        Ok(())
    }

    fn list(&self) -> Result<Vec<String>> {
        if matches!(self.cache_strategy, CacheStrategy::None) {
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
            return Ok(entries);
        }

        // Populate the cache with existing directory entries as lazy placeholders
        self.load_directory_into_cache_keys()?;

        let state = self.state.read_recovered()?;
        if let Some(cache) = &state.cache {
            let mut keys: Vec<String> = cache.keys().cloned().collect();
            keys.sort();
            Ok(keys)
        } else {
            Ok(Vec::new())
        }
    }

    fn invalidate_cache(&self) {
        if let Ok(mut state) = self.state.write_recovered() {
            state.cache = None;
            state.loaded_from_dir = false;
        }
    }

    fn get_base_path(&self) -> PathBuf {
        self.base_dir.clone()
    }

    fn get_single_file_path(&self) -> Option<PathBuf> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::JsonStorage;
    use serde::Serialize;
    use serde::de::DeserializeOwned;
    use serde_json::json;
    use std::path::Path;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Clone)]
    struct CountingStorage {
        inner: JsonStorage,
        writes: Arc<AtomicUsize>,
        reads: Arc<AtomicUsize>,
    }

    impl CountingStorage {
        fn new(writes: Arc<AtomicUsize>, reads: Arc<AtomicUsize>) -> Self {
            Self {
                inner: JsonStorage::new(),
                writes,
                reads,
            }
        }
    }

    impl StorageBackend for CountingStorage {
        fn extension(&self) -> &str {
            self.inner.extension()
        }

        fn serialize<T: Serialize>(&self, data: &T) -> Result<String> {
            self.inner.serialize(data)
        }

        fn deserialize<T: DeserializeOwned>(&self, content: &str) -> Result<T> {
            self.inner.deserialize(content)
        }

        fn read<T: DeserializeOwned>(&self, path: &Path) -> Result<T> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            self.inner.read(path)
        }

        fn write<T: Serialize>(&self, path: &Path, data: &T) -> Result<()> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            self.inner.write(path, data)
        }
    }

    #[test]
    fn test_multifile_caching_eliminates_disk_io() {
        let dir = tempfile::tempdir().unwrap();
        let writes = Arc::new(AtomicUsize::new(0));
        let reads = Arc::new(AtomicUsize::new(0));
        let storage = CountingStorage::new(writes.clone(), reads.clone());

        let store = MultiFileStore::new(
            "remotes".to_string(),
            dir.path().to_path_buf(),
            "json".to_string(),
            storage,
            None,
            CacheStrategy::Full,
        );

        // Pre-create two entities
        store.set("remote1", json!({"type": "gdrive"})).unwrap();
        store.set("remote2", json!({"type": "s3"})).unwrap();
        assert_eq!(writes.load(Ordering::SeqCst), 2);
        assert_eq!(reads.load(Ordering::SeqCst), 0);

        // Clear cache completely (simulate a new instance)
        store.invalidate_cache();

        // 1. List files (should read directory, but NOT read files = 0 file disk reads)
        let keys = store.list().unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(reads.load(Ordering::SeqCst), 0);

        // 2. Get the first entity (should read 1 file from disk)
        let _ = store.get("remote1").unwrap();
        assert_eq!(reads.load(Ordering::SeqCst), 1);

        // 3. Get the first entity AGAIN (should serve from cache = 1 file disk read still)
        let _ = store.get("remote1").unwrap();
        assert_eq!(reads.load(Ordering::SeqCst), 1);

        // 4. Get the second entity (should read 1 file from disk, total = 2)
        let _ = store.get("remote2").unwrap();
        assert_eq!(reads.load(Ordering::SeqCst), 2);
    }
}
