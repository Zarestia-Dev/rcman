use crate::error::{Error, Result};
use crate::storage::StorageBackend;
use crate::sub_settings::store::SubSettingsStore;

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
    state: RwLock<SingleFileStoreState>,
}

impl<S: StorageBackend> SingleFileStore<S> {
    pub fn new(
        name: String,
        base_dir: PathBuf,
        extension: String,
        storage: S,
        migrator: Option<SubSettingsMigrator>,
    ) -> Self {
        Self {
            name,
            base_dir,
            extension,
            storage,
            migrator,
            state: RwLock::new(SingleFileStoreState {
                cache: None,
                loaded_from_disk: false,
            }),
        }
    }

    fn file_path(&self) -> PathBuf {
        self.base_dir
            .join(format!("{}.{}", self.name, self.extension))
    }

    fn ensure_loaded(&self) -> Result<()> {
        if self.state.read().unwrap().loaded_from_disk {
            return Ok(());
        }

        let mut state = self.state.write().unwrap();
        if state.loaded_from_disk {
            return Ok(());
        }

        let path = self.file_path();

        let mut file_data = match std::fs::metadata(&path) {
            Ok(_) => self.storage.read::<Value>(&path)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Return empty map on new file
                state.loaded_from_disk = true;
                state.cache = Some(HashMap::new());
                return Ok(());
            }
            Err(e) => return Err(Error::FileRead { path, source: e }),
        };

        // Migration
        if let Some(migrator) = &self.migrator {
            let original = file_data.clone();
            file_data = migrator(file_data);
            if file_data != original {
                debug!("Migrated sub-settings file: {}", self.name);
                self.storage.write(&path, &file_data)?;
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

        // Ensure directory exists - base_dir for single file is the config dir itself mostly
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                crate::security::ensure_secure_dir(parent)?;
            }
        }

        let obj: Value = Value::Object(cache.iter().map(|(k, v)| (k.clone(), v.clone())).collect());
        self.storage.write(&path, &obj)?;
        Ok(())
    }
}

impl<S: StorageBackend> SubSettingsStore for SingleFileStore<S> {
    fn get(&self, key: &str) -> Result<Value> {
        self.ensure_loaded()?;

        let state = self.state.read().unwrap();
        if let Some(cache) = &state.cache {
            if let Some(val) = cache.get(key) {
                return Ok(val.clone());
            }
        }

        Err(Error::SubSettingsEntryNotFound(format!(
            "{}/{}",
            self.name, key
        )))
    }

    fn set(&self, key: &str, value: Value) -> Result<()> {
        self.ensure_loaded()?; // Load everything first!

        let mut state = self.state.write().unwrap();

        // Initialize cache if something went wrong, though ensure_loaded should handle it
        if state.cache.is_none() {
            state.cache = Some(HashMap::new());
        }

        if let Some(cache) = &mut state.cache {
            if value.is_null() {
                cache.remove(key);
            } else {
                cache.insert(key.to_string(), value);
            }
            self.save_to_disk(cache)?;
        }

        Ok(())
    }

    fn remove(&self, key: &str) -> Result<()> {
        self.ensure_loaded()?;

        let mut state = self.state.write().unwrap();
        if let Some(cache) = &mut state.cache {
            if cache.remove(key).is_some() {
                self.save_to_disk(cache)?;
            } else {
                // Key didn't exist, fine
            }
        }
        Ok(())
    }

    fn list(&self) -> Result<Vec<String>> {
        self.ensure_loaded()?;

        let state = self.state.read().unwrap();
        if let Some(cache) = &state.cache {
            let mut keys: Vec<String> = cache.keys().cloned().collect();
            keys.sort();
            Ok(keys)
        } else {
            Ok(Vec::new())
        }
    }

    fn invalidate_cache(&self) {
        let mut state = self.state.write().unwrap();
        state.loaded_from_disk = false;
        state.cache = None;
    }

    fn get_base_path(&self) -> PathBuf {
        self.base_dir.clone()
    }

    fn get_single_file_path(&self) -> Option<PathBuf> {
        Some(self.file_path())
    }
}
