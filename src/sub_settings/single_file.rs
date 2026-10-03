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

struct SingleFileStoreState {
    cache: Option<HashMap<String, Value>>,
    loaded_from_disk: bool,
}

pub struct SingleFileStore<S: StorageBackend> {
    name: String,
    base_dir: PathBuf,
    extension: String,
    storage: S,
    migrator: Option<SubSettingsMigrator>,
    #[cfg(feature = "vault")]
    vault: crate::vault::SharedVault,
    state: RwLock<SingleFileStoreState>,
}

impl<S: StorageBackend> SingleFileStore<S> {
    pub fn new(
        name: String,
        base_dir: PathBuf,
        extension: String,
        storage: S,
        migrator: Option<SubSettingsMigrator>,
        #[cfg(feature = "vault")] vault: crate::vault::SharedVault,
    ) -> Self {
        Self {
            name,
            base_dir,
            extension,
            storage,
            migrator,
            #[cfg(feature = "vault")]
            vault,
            state: RwLock::new(SingleFileStoreState {
                cache: None,
                loaded_from_disk: false,
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

    fn file_path(&self) -> PathBuf {
        self.base_dir
            .join(format!("{}.{}", self.name, self.extension))
    }

    fn ensure_loaded(&self) -> Result<()> {
        if self.state.read_recovered()?.loaded_from_disk {
            return Ok(());
        }

        let mut state = self.state.write_recovered()?;
        if state.loaded_from_disk {
            return Ok(());
        }

        let path = self.file_path();

        let mut file_data = match std::fs::metadata(&path) {
            Ok(_) => self.read_value(&path)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                state.loaded_from_disk = true;
                state.cache = Some(HashMap::new());
                return Ok(());
            }
            Err(e) => return Err(Error::FileRead { path, source: e }),
        };

        if let Some(migrator) = &self.migrator {
            let original = file_data.clone();
            file_data = migrator(file_data);
            if file_data != original {
                debug!("Migrated sub-settings file: {}", self.name);
                self.write_value(&path, &file_data)?;
            }
        }

        let obj = file_data.as_object().ok_or_else(|| {
            Error::InvalidBackup(format!(
                "{}: Single-file sub-settings is not a valid settings object",
                path.display()
            ))
        })?;

        state.cache = Some(obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect());
        state.loaded_from_disk = true;

        Ok(())
    }

    fn save_to_disk(&self, cache: &HashMap<String, Value>) -> Result<()> {
        let path = self.file_path();

        if let Some(parent) = path.parent()
            && !parent.exists()
        {
            crate::utils::security::ensure_secure_dir(parent)?;
        }

        self.write_value(&path, cache)?;
        Ok(())
    }
}

impl<S: StorageBackend> SubSettingsStore for SingleFileStore<S> {
    fn get(&self, key: &str) -> Result<Value> {
        #[cfg(feature = "vault")]
        if self.is_locked() {
            return Err(Error::ConfigLocked);
        }

        self.ensure_loaded()?;

        let state = self.state.read_recovered()?;
        if let Some(cache) = &state.cache
            && let Some(val) = cache.get(key)
        {
            return Ok(val.clone());
        }

        Err(Error::SubSettingsEntryNotFound(format!(
            "{}/{}",
            self.name, key
        )))
    }

    fn set(&self, key: &str, value: Value) -> Result<()> {
        #[cfg(feature = "vault")]
        if self.is_locked() {
            return Err(Error::ConfigLocked);
        }

        self.ensure_loaded()?;

        let mut state = self.state.write_recovered()?;

        if state.cache.is_none() {
            state.cache = Some(HashMap::new());
        }

        if let Some(cache) = &mut state.cache {
            let changed = if value.is_null() {
                cache.remove(key).is_some()
            } else if cache.get(key).is_some_and(|existing| existing == &value) {
                false
            } else {
                cache.insert(key.to_string(), value);
                true
            };

            if changed {
                self.save_to_disk(cache)?;
            }
        }

        Ok(())
    }

    fn remove(&self, key: &str) -> Result<()> {
        #[cfg(feature = "vault")]
        if self.is_locked() {
            return Err(Error::ConfigLocked);
        }

        self.ensure_loaded()?;

        let mut state = self.state.write_recovered()?;
        if let Some(cache) = &mut state.cache
            && cache.remove(key).is_some()
        {
            self.save_to_disk(cache)?;
        }
        Ok(())
    }

    fn exists(&self, key: &str) -> Result<bool> {
        #[cfg(feature = "vault")]
        if self.is_locked() {
            return Err(Error::ConfigLocked);
        }

        self.ensure_loaded()?;

        let state = self.state.read_recovered()?;
        if let Some(cache) = &state.cache {
            Ok(cache.contains_key(key))
        } else {
            Ok(false)
        }
    }

    fn list(&self) -> Result<Vec<String>> {
        #[cfg(feature = "vault")]
        if self.is_locked() {
            return Err(Error::ConfigLocked);
        }

        self.ensure_loaded()?;

        let state = self.state.read_recovered()?;
        if let Some(cache) = &state.cache {
            let mut keys: Vec<String> = cache.keys().cloned().collect();
            keys.sort();
            Ok(keys)
        } else {
            Ok(Vec::new())
        }
    }

    fn get_all(&self) -> Result<HashMap<String, Value>> {
        #[cfg(feature = "vault")]
        if self.is_locked() {
            return Err(Error::ConfigLocked);
        }

        self.ensure_loaded()?;

        let state = self.state.read_recovered()?;
        if let Some(cache) = &state.cache {
            Ok(cache.clone())
        } else {
            Ok(HashMap::new())
        }
    }

    #[cfg(feature = "vault")]
    fn rewrite(&self, entries: HashMap<String, Value>) -> Result<()> {
        let mut state = self.state.write_recovered()?;
        self.save_to_disk(&entries)?;
        state.cache = Some(entries);
        state.loaded_from_disk = true;
        Ok(())
    }

    fn invalidate_cache(&self) {
        if let Ok(mut state) = self.state.write_recovered() {
            state.loaded_from_disk = false;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::JsonStorage;
    use serde::Serialize;
    use serde::de::DeserializeOwned;
    use serde_json::json;
    use std::path::Path;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Clone)]
    struct CountingStorage {
        inner: JsonStorage,
        writes: Arc<AtomicUsize>,
    }

    impl CountingStorage {
        fn new(writes: Arc<AtomicUsize>) -> Self {
            Self {
                inner: JsonStorage::new(),
                writes,
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

        fn write<T: Serialize>(&self, path: &Path, data: &T) -> Result<()> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            self.inner.write(path, data)
        }
    }

    #[test]
    fn test_set_same_value_does_not_rewrite_file() {
        let dir = tempfile::tempdir().unwrap();
        let writes = Arc::new(AtomicUsize::new(0));
        let storage = CountingStorage::new(writes.clone());
        let store = SingleFileStore::new(
            "backends".to_string(),
            dir.path().to_path_buf(),
            "json".to_string(),
            storage,
            None,
            #[cfg(feature = "vault")]
            Arc::new(RwLock::new(None)),
        );

        store.set("remote", json!({"host": "localhost"})).unwrap();
        assert_eq!(writes.load(Ordering::SeqCst), 1);

        store.set("remote", json!({"host": "localhost"})).unwrap();
        assert_eq!(writes.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_set_null_missing_key_does_not_write() {
        let dir = tempfile::tempdir().unwrap();
        let writes = Arc::new(AtomicUsize::new(0));
        let storage = CountingStorage::new(writes.clone());
        let store = SingleFileStore::new(
            "backends".to_string(),
            dir.path().to_path_buf(),
            "json".to_string(),
            storage,
            None,
            #[cfg(feature = "vault")]
            Arc::new(RwLock::new(None)),
        );

        store.set("missing", Value::Null).unwrap();
        assert_eq!(writes.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_scalar_string_value_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let store = SingleFileStore::new(
            "connections".to_string(),
            dir.path().to_path_buf(),
            "json".to_string(),
            JsonStorage::new(),
            None,
            #[cfg(feature = "vault")]
            Arc::new(RwLock::new(None)),
        );

        store.set("_active", json!("Windows")).unwrap();
        let retrieved = store.get("_active").unwrap();
        assert_eq!(retrieved, json!("Windows"));
    }

    #[test]
    fn test_mixed_object_and_scalar_entries_all_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let store = SingleFileStore::new(
            "connections".to_string(),
            dir.path().to_path_buf(),
            "json".to_string(),
            JsonStorage::new(),
            None,
            #[cfg(feature = "vault")]
            Arc::new(RwLock::new(None)),
        );

        store
            .set("Local", json!({"host": "127.0.0.1", "port": 51900}))
            .unwrap();
        store
            .set("Windows", json!({"host": "192.168.0.10", "port": 5572}))
            .unwrap();
        store.set("_active", json!("Windows")).unwrap();

        assert_eq!(store.get("_active").unwrap(), json!("Windows"));
        assert!(store.get("Local").unwrap().is_object());
        assert!(store.get("Windows").unwrap().is_object());

        let mut keys = store.list().unwrap();
        keys.sort();
        assert_eq!(keys, vec!["Local", "Windows", "_active"]);
    }
}
