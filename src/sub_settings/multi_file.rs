use crate::CacheStrategy;
use crate::error::{Error, Result};
use crate::storage::StorageBackend;
use crate::sub_settings::SubSettingsConfig;
use crate::sub_settings::store::SubSettingsStore;
use crate::utils::sync::RwLockExt;
use log::debug;
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

struct MultiFileStoreState {
    cache: Option<CacheType>,
    loaded_from_dir: bool,
}

pub struct MultiFileStore<S: StorageBackend> {
    name: String,
    base_dir: PathBuf,
    extension: String,
    storage: S,
    migrator: Option<SubSettingsMigrator>,
    cache_strategy: CacheStrategy,
    #[cfg(feature = "vault")]
    vault: crate::vault::SharedVault,
    state: RwLock<MultiFileStoreState>,
}

impl<S: StorageBackend> MultiFileStore<S> {
    pub fn new(
        config: &SubSettingsConfig,
        base_dir: PathBuf,
        storage: S,
        #[cfg(feature = "vault")] vault: crate::vault::SharedVault,
    ) -> Self {
        let extension = config.extension.as_deref().unwrap_or("json").to_string();
        Self {
            name: config.name.clone(),
            base_dir,
            extension,
            storage,
            migrator: config.migrator.clone(),
            cache_strategy: config.cache_strategy,
            #[cfg(feature = "vault")]
            vault,
            state: RwLock::new(MultiFileStoreState {
                cache: None,
                loaded_from_dir: false,
            }),
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

    fn read_value(&self, path: &std::path::Path) -> Result<Value> {
        let value: Value = self.storage.read(path)?;

        #[cfg(feature = "vault")]
        if crate::vault::is_vault_value(&value) {
            let vault = self.get_vault()?.ok_or(Error::ConfigLocked)?;
            if let Some(decrypted_str) = vault.decrypt_vault_value_to_str(&value)? {
                return self.storage.deserialize(&decrypted_str);
            }
        }

        Ok(value)
    }

    fn write_value<T: serde::Serialize>(&self, path: &std::path::Path, data: &T) -> Result<()> {
        #[cfg(feature = "vault")]
        if let Some(ref vault) = self.get_vault()? {
            if vault.is_locked() {
                return Err(Error::ConfigLocked);
            }
            let serialized = self.storage.serialize(data)?;
            let envelope = vault.encrypt_payload(serialized.as_bytes())?;
            return self.storage.write(path, &envelope);
        }

        self.storage.write(path, data)
    }

    fn file_path(&self, key: &str) -> PathBuf {
        self.base_dir.join(format!("{}.{}", key, self.extension))
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

        if state.cache.is_none() {
            state.cache = Some(self.create_cache());
        }

        if !self.base_dir.exists() {
            state.loaded_from_dir = true;
            return Ok(());
        }

        let ext = format!(".{}", self.extension);
        let mut keys = Vec::new();
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
                keys.push(name.trim_end_matches(&ext).to_string());
            }
        }

        match &mut state.cache {
            Some(CacheType::Full(cache)) => {
                for key in keys {
                    cache.entry(key).or_insert(Value::Null);
                }
            }
            Some(CacheType::Lru(cache)) => {
                for key in keys {
                    if !cache.contains(&key) {
                        cache.put(key, Value::Null);
                    }
                }
            }
            None => {}
        }

        state.loaded_from_dir = true;
        Ok(())
    }
}

impl<S: StorageBackend> SubSettingsStore for MultiFileStore<S> {
    fn get(&self, key: &str) -> Result<Value> {
        #[cfg(feature = "vault")]
        if self.is_locked() {
            return Err(Error::ConfigLocked);
        }

        self.ensure_cache_populated()?;

        {
            if matches!(self.cache_strategy, CacheStrategy::Full) {
                let state = self.state.read_recovered()?;
                if let Some(CacheType::Full(cache)) = &state.cache
                    && let Some(val) = cache.get(key)
                    && !val.is_null()
                {
                    return Ok(val.clone());
                }
            } else if matches!(self.cache_strategy, CacheStrategy::Lru(_)) {
                let mut state = self.state.write_recovered()?;
                if let Some(CacheType::Lru(cache)) = &mut state.cache
                    && let Some(val) = cache.get(key)
                    && !val.is_null()
                {
                    return Ok(val.clone());
                }
            }
        }

        let path = self.file_path(key);
        if !path.exists() {
            if let Ok(mut state) = self.state.write_recovered()
                && let Some(cache) = &mut state.cache
            {
                match cache {
                    CacheType::Full(c) => {
                        c.remove(key);
                    }
                    CacheType::Lru(c) => {
                        c.pop(key);
                    }
                }
            }
            return Err(Error::SubSettingsEntryNotFound(format!(
                "{}/{}",
                self.name, key
            )));
        }

        let mut value: Value = self.read_value(&path)?;

        if let Some(migrator) = &self.migrator {
            let original = value.clone();
            value = migrator(value);
            if value != original {
                debug!("Migrated sub-settings entry: {key}");
                self.write_value(&path, &value)?;
            }
        }

        if !matches!(self.cache_strategy, CacheStrategy::None) {
            let mut state = self.state.write_recovered()?;
            match &mut state.cache {
                Some(CacheType::Full(cache)) => {
                    cache.insert(key.to_string(), value.clone());
                }
                Some(CacheType::Lru(cache)) => {
                    cache.put(key.to_string(), value.clone());
                }
                _ => {}
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

        let path = self.file_path(key);

        if !self.base_dir.exists() {
            crate::utils::security::ensure_secure_dir(&self.base_dir)?;
        }

        self.write_value(&path, &value)?;

        if !matches!(self.cache_strategy, CacheStrategy::None) {
            let mut state = self.state.write_recovered()?;
            if state.cache.is_none() {
                state.cache = Some(self.create_cache());
            }
            match &mut state.cache {
                Some(CacheType::Full(cache)) => {
                    cache.insert(key.to_string(), value);
                }
                Some(CacheType::Lru(cache)) => {
                    cache.put(key.to_string(), value);
                }
                _ => {}
            }
        }

        Ok(())
    }

    fn remove(&self, key: &str) -> Result<()> {
        #[cfg(feature = "vault")]
        if self.is_locked() {
            return Err(Error::ConfigLocked);
        }

        let path = self.file_path(key);

        if path.exists() {
            std::fs::remove_file(&path).map_err(|e| Error::FileDelete { path, source: e })?;
        }

        let mut state = self.state.write_recovered()?;
        match &mut state.cache {
            Some(CacheType::Full(cache)) => {
                cache.remove(key);
            }
            Some(CacheType::Lru(cache)) => {
                cache.pop(key);
            }
            _ => {}
        }

        Ok(())
    }

    fn exists(&self, key: &str) -> Result<bool> {
        #[cfg(feature = "vault")]
        if self.is_locked() {
            return Err(Error::ConfigLocked);
        }

        self.ensure_cache_populated()?;

        {
            let state = self.state.read_recovered()?;
            if let Some(cache) = &state.cache {
                match cache {
                    CacheType::Full(c) => {
                        if c.contains_key(key) {
                            return Ok(true);
                        }
                        if state.loaded_from_dir {
                            return Ok(false);
                        }
                    }
                    CacheType::Lru(c) => {
                        // LRU contains() is read-only and does not affect access order.
                        // But LRU can evict items, so we only return true if it is present.
                        if c.contains(key) {
                            return Ok(true);
                        }
                    }
                }
            }
        }

        Ok(self.file_path(key).exists())
    }

    fn list(&self) -> Result<Vec<String>> {
        #[cfg(feature = "vault")]
        if self.is_locked() {
            return Err(Error::ConfigLocked);
        }

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

        self.load_directory_into_cache_keys()?;

        let state = self.state.read_recovered()?;
        match &state.cache {
            Some(CacheType::Full(cache)) => {
                let mut keys: Vec<String> = cache.keys().cloned().collect();
                keys.sort();
                Ok(keys)
            }
            Some(CacheType::Lru(cache)) => {
                let mut keys: Vec<String> = cache.iter().map(|(k, _)| k.clone()).collect();
                keys.sort();
                Ok(keys)
            }
            _ => Ok(Vec::new()),
        }
    }

    fn get_all(&self) -> Result<HashMap<String, Value>> {
        #[cfg(feature = "vault")]
        if self.is_locked() {
            return Err(Error::ConfigLocked);
        }

        let keys = self.list()?;
        let mut result = HashMap::with_capacity(keys.len());

        for key in keys {
            if let Ok(value) = self.get(key.as_str()) {
                result.insert(key, value);
            }
        }

        Ok(result)
    }

    fn invalidate_cache(&self) {
        if let Ok(mut state) = self.state.write_recovered() {
            state.cache = None;
            state.loaded_from_dir = false;
        }
    }

    fn base_path(&self) -> PathBuf {
        self.base_dir.clone()
    }

    fn single_file_path(&self) -> Option<PathBuf> {
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

        let config = SubSettingsConfig::new("remotes").with_cache(CacheStrategy::Full);
        let store = MultiFileStore::new(
            &config,
            dir.path().to_path_buf(),
            storage,
            #[cfg(feature = "vault")]
            Arc::new(RwLock::new(None)),
        );

        store.set("remote1", json!({"type": "gdrive"})).unwrap();
        store.set("remote2", json!({"type": "s3"})).unwrap();
        assert_eq!(writes.load(Ordering::SeqCst), 2);
        assert_eq!(reads.load(Ordering::SeqCst), 0);

        store.invalidate_cache();

        let keys = store.list().unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(reads.load(Ordering::SeqCst), 0);

        let _ = store.get("remote1").unwrap();
        assert_eq!(reads.load(Ordering::SeqCst), 1);

        let _ = store.get("remote1").unwrap();
        assert_eq!(reads.load(Ordering::SeqCst), 1);

        let _ = store.get("remote2").unwrap();
        assert_eq!(reads.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn test_multifile_lru_eviction() {
        let dir = tempfile::tempdir().unwrap();
        let writes = Arc::new(AtomicUsize::new(0));
        let reads = Arc::new(AtomicUsize::new(0));
        let storage = CountingStorage::new(writes.clone(), reads.clone());

        let config = SubSettingsConfig::new("remotes").with_cache(CacheStrategy::Lru(2));
        let store = MultiFileStore::new(
            &config,
            dir.path().to_path_buf(),
            storage,
            #[cfg(feature = "vault")]
            Arc::new(RwLock::new(None)),
        );

        store.set("a", json!(1)).unwrap();
        store.set("b", json!(2)).unwrap();
        store.set("c", json!(3)).unwrap();

        assert_eq!(reads.load(Ordering::SeqCst), 0);

        store.get("c").unwrap();
        assert_eq!(reads.load(Ordering::SeqCst), 0);

        store.get("b").unwrap();
        assert_eq!(reads.load(Ordering::SeqCst), 0);

        store.get("a").unwrap();
        assert_eq!(reads.load(Ordering::SeqCst), 1);

        store.get("a").unwrap();
        assert_eq!(reads.load(Ordering::SeqCst), 1);
    }
}
