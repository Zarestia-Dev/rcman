//! Sub-settings management for per-entity configuration files

use crate::error::{Error, Result};
use crate::storage::StorageBackend;
use log::{debug, info, warn};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::RwLock;

/// Mode of storage for sub-settings
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SubSettingsMode {
    /// Store each entry in a separate file within a directory (default)
    #[default]
    MultiFile,
    /// Store all entries in a single JSON file
    SingleFile,
}

/// Configuration for a sub-settings type
#[derive(Clone)]
pub struct SubSettingsConfig {
    /// Name of this sub-settings type
    /// - Multi-file mode: used as directory name (e.g., "remotes" → config/remotes/)
    /// - Single-file mode: used as file name (e.g., "backends" → config/backends.json)
    pub name: String,

    /// File extension for entries (default: "json")
    pub extension: String,

    /// Optional migration function for schema changes
    pub migrator: Option<Arc<dyn Fn(Value) -> Value + Send + Sync>>,

    /// Storage mode (MultiFile or SingleFile)
    pub mode: SubSettingsMode,
}

impl Default for SubSettingsConfig {
    fn default() -> Self {
        Self {
            name: "items".into(),
            extension: "json".into(),
            migrator: None,
            mode: SubSettingsMode::MultiFile,
        }
    }
}

impl SubSettingsConfig {
    /// Create a new sub-settings config
    ///
    /// # Arguments
    /// * `name` - Name of this sub-settings type (used as directory or file name)
    ///
    /// By default, creates a directory with separate files for each entity.
    /// Use `.single_file()` to store all entities in one JSON file instead.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Default::default()
        }
    }

    /// Set a custom file extension
    pub fn with_extension(mut self, ext: impl Into<String>) -> Self {
        self.extension = ext.into();
        self
    }

    /// Set a migration function for schema changes (lazy migration)
    ///
    /// The migrator function is called automatically when loading.
    ///
    /// # MultiFile Mode
    /// The migrator is called for each entry when loaded.
    /// `value` is the content of the entry.
    ///
    /// # SingleFile Mode
    /// The migrator is called for the ENTIRE file when loaded.
    /// `value` is the root JSON object containing all entries.
    /// Use this to migrate the file structure or iterate over entries to migrate them.
    ///
    /// # Example (MultiFile Mode)
    ///
    /// ```rust
    /// use rcman::SubSettingsConfig;
    /// use serde_json::json;
    ///
    /// // Migrate individual remote configs
    /// let config = SubSettingsConfig::new("remotes")
    ///     .with_migrator(|mut value| {
    ///         // Add version field if missing
    ///         if let Some(obj) = value.as_object_mut() {
    ///             if !obj.contains_key("version") {
    ///                 obj.insert("version".into(), json!(2));
    ///             }
    ///         }
    ///         value
    ///     });
    /// ```
    ///
    /// # Example (SingleFile Mode)
    ///
    /// ```rust
    /// use rcman::SubSettingsConfig;
    /// use serde_json::json;
    ///
    /// // Migrate the entire backends file
    /// let config = SubSettingsConfig::new("backends")
    ///     .single_file()
    ///     .with_migrator(|mut value| {
    ///         // Iterate and update each backend
    ///         if let Some(obj) = value.as_object_mut() {
    ///             for (_name, backend) in obj.iter_mut() {
    ///                 if let Some(b) = backend.as_object_mut() {
    ///                     b.insert("migrated".into(), json!(true));
    ///                 }
    ///             }
    ///         }
    ///         value
    ///     });
    /// ```
    pub fn with_migrator<F>(mut self, migrator: F) -> Self
    where
        F: Fn(Value) -> Value + Send + Sync + 'static,
    {
        self.migrator = Some(Arc::new(migrator));
        self
    }

    /// Enable single-file mode
    ///
    /// Instead of creating a directory with separate files for each entity,
    /// all entities will be stored in one JSON file with entity names as keys.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rcman::SubSettingsConfig;
    ///
    /// // Multi-file mode (default): creates remotes/gdrive.json, remotes/s3.json
    /// let config = SubSettingsConfig::new("remotes");
    ///
    /// // Single-file mode: creates backends.json containing {"gdrive": {...}, "s3": {...}}
    /// let config = SubSettingsConfig::new("backends").single_file();
    /// ```
    pub fn single_file(mut self) -> Self {
        self.mode = SubSettingsMode::SingleFile;
        self
    }
}

use std::collections::HashMap;

/// Handler for a single sub-settings type
pub struct SubSettings<S: StorageBackend> {
    /// Configuration
    config: SubSettingsConfig,

    /// Base directory for this sub-settings type
    base_dir: PathBuf,

    /// Storage backend
    storage: S,

    /// Mutex to serialize save operations (prevents race conditions)
    save_mutex: std::sync::Mutex<()>,

    /// In-memory cache
    /// - None: not loaded (lazy load)
    /// - Some(map): loaded
    cache: RwLock<Option<HashMap<String, Value>>>,

    /// Callback for change notifications
    #[allow(clippy::type_complexity)]
    on_change: RwLock<Option<Arc<dyn Fn(&str, SubSettingsAction) + Send + Sync>>>,
}

/// Action type for change callbacks
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubSettingsAction {
    Created,
    Updated,
    Deleted,
}

impl<S: StorageBackend> SubSettings<S> {
    /// Create a new sub-settings handler
    pub fn new(config_dir: &std::path::Path, config: SubSettingsConfig, storage: S) -> Self {
        // In single-file mode, base_dir is the config dir (file will be {directory}.json)
        // In multi-file mode, base_dir is the directory (files will be {name}.json inside it)
        let base_dir = if matches!(config.mode, SubSettingsMode::SingleFile) {
            config_dir.to_path_buf()
        } else {
            config_dir.join(&config.name)
        };
        Self {
            config,
            base_dir,
            storage,
            save_mutex: std::sync::Mutex::new(()),
            cache: RwLock::new(None),
            on_change: RwLock::new(None),
        }
    }

    /// Get the single-file path (for single-file mode)
    fn single_file_path(&self) -> PathBuf {
        self.base_dir
            .join(format!("{}.{}", self.config.name, self.config.extension))
    }

    /// Get the file path for an entry (multi-file mode only)
    fn entry_path(&self, name: &str) -> PathBuf {
        if self.is_single_file() {
            // In single-file mode, all entries are in the single file
            self.single_file_path()
        } else {
            self.base_dir
                .join(format!("{}.{}", name, self.config.extension))
        }
    }

    /// Check if we're in single-file mode
    pub fn is_single_file(&self) -> bool {
        matches!(self.config.mode, SubSettingsMode::SingleFile)
    }

    /// Invalidate the internal cache
    ///
    /// This forces the next read operation to reload from disk.
    /// Useful if external processes might modify the files.
    pub fn invalidate_cache(&self) {
        if let Ok(mut cache) = self.cache.write() {
            *cache = None;
        }
    }

    /// Set a callback for change notifications
    pub fn set_on_change<F>(&self, callback: F)
    where
        F: Fn(&str, SubSettingsAction) + Send + Sync + 'static,
    {
        let mut guard = self.on_change.write().unwrap();
        *guard = Some(Arc::new(callback));
    }

    /// Notify about a change
    fn notify_change(&self, name: &str, action: SubSettingsAction) {
        let guard = self.on_change.read().unwrap();
        if let Some(callback) = guard.as_ref() {
            callback(name, action);
        }
    }

    /// Ensure cache is populated (loads from disk if needed)
    fn ensure_cache_populated(&self) -> Result<()> {
        // Fast path: check read lock
        if self.cache.read().unwrap().is_some() {
            return Ok(());
        }

        let mut cache_guard = self.cache.write().unwrap();
        if cache_guard.is_some() {
            return Ok(());
        }

        if self.is_single_file() {
            let path = self.single_file_path();
            let mut file_data = match std::fs::metadata(&path) {
                Ok(_) => self.storage.read::<Value>(&path)?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // Start with empty cache
                    *cache_guard = Some(HashMap::new());
                    return Ok(());
                }
                Err(e) => {
                    return Err(Error::FileRead {
                        path: path.display().to_string(),
                        source: e,
                    })
                }
            };

            // Apply migration and persist if changed
            if let Some(migrator) = &self.config.migrator {
                // Optimization: Use hash or just clone if needed.
                // Since we need to write back, we need to know if it changed.
                // Cloning is safe here as it happens only once per load.
                let original = file_data.clone();
                file_data = migrator(file_data);

                if file_data != original {
                    debug!("🔄 Migrated sub-settings file: {}", self.config.name);
                    let _save_guard = self.save_mutex.lock().unwrap();
                    self.storage.write(&path, &file_data)?;
                }
            }

            let obj = file_data.as_object().ok_or_else(|| {
                Error::InvalidBackup("Single-file sub-settings is not a JSON object".to_string())
            })?;

            // Populate cache with all entries
            *cache_guard = Some(obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect());
        } else {
            // MultiFile: just init empty map
            *cache_guard = Some(HashMap::new());
        }

        Ok(())
    }

    /// Load an entry (returns raw JSON Value)
    pub fn get_value(&self, name: &str) -> Result<Value> {
        self.ensure_cache_populated()?;

        // Check cache first
        let mut value = {
            let cache = self.cache.read().unwrap();
            // Cache must be Some(_) because of ensure_cache_populated
            cache.as_ref().and_then(|map| map.get(name).cloned())
        };

        // If not in cache, read from file (for multi-file mode)
        if value.is_none() {
            if self.is_single_file() {
                // In SingleFile mode, if not in cache (and cache is populated), it doesn't exist
                return Err(Error::SubSettingsEntryNotFound {
                    settings_type: self.config.name.clone(),
                    name: name.to_string(),
                });
            }

            // Multi-file mode: read from individual file
            let path = self.entry_path(name);

            if let Err(e) = std::fs::metadata(&path) {
                if e.kind() == std::io::ErrorKind::NotFound {
                    return Err(Error::SubSettingsEntryNotFound {
                        settings_type: self.config.name.clone(),
                        name: name.to_string(),
                    });
                }
                return Err(Error::FileRead {
                    path: path.display().to_string(),
                    source: e,
                });
            }

            value = Some(self.storage.read(&path)?);
        }

        // At this point, value should be Some(_)
        let mut value = value.unwrap();

        // Apply migration if configured
        if let Some(migrator) = &self.config.migrator {
            let original = value.clone();
            value = migrator(value);

            // If migration changed the value, persist it
            if value != original {
                debug!("Migrated sub-settings entry: {}", name);

                // Persist the migrated value
                if self.is_single_file() {
                    // Update cache and persist the whole file
                    {
                        let mut cache = self.cache.write().unwrap();
                        if let Some(map) = cache.as_mut() {
                            map.insert(name.to_string(), value.clone());
                        }
                    }

                    let path = self.single_file_path();
                    let full_obj = {
                        let cache = self.cache.read().unwrap();
                        if let Some(map) = cache.as_ref() {
                            Value::Object(map.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
                        } else {
                            Value::Object(serde_json::Map::new())
                        }
                    };

                    let _save_guard = self.save_mutex.lock().unwrap();
                    self.storage.write(&path, &full_obj)?;
                } else {
                    // Multi-file mode: write individual file
                    let path = self.entry_path(name);
                    let _save_guard = self.save_mutex.lock().unwrap();
                    self.storage.write(&path, &value)?;
                }
            }
        }

        // Update cache
        {
            let mut cache = self.cache.write().unwrap();
            if let Some(map) = cache.as_mut() {
                map.insert(name.to_string(), value.clone());
            }
        }

        Ok(value)
    }

    /// Load a typed entry
    pub fn get<T: DeserializeOwned>(&self, name: &str) -> Result<T> {
        let value = self.get_value(name)?;
        serde_json::from_value(value).map_err(|e| Error::Parse(e.to_string()))
    }

    /// Save an entry
    pub fn set<T: Serialize + Sync>(&self, name: &str, value: &T) -> Result<()> {
        // Ensure cache structure is initialized
        self.ensure_cache_populated()?;

        let json_value = serde_json::to_value(value).map_err(|e| Error::Parse(e.to_string()))?;

        // Acquire save mutex to prevent race conditions
        let _save_guard = self.save_mutex.lock().unwrap();

        let exists = {
            let mut cache = self.cache.write().unwrap();
            if let Some(map) = cache.as_mut() {
                map.insert(name.to_string(), json_value.clone()).is_some()
            } else {
                false // Should not happen due to ensure_cache_populated
            }
        };

        if self.is_single_file() {
            // Single-file mode: Write the current cache state to disk
            // We rely on the cache being the source of truth
            let path = self.single_file_path();

            // Reconstruct the full object from cache
            let full_obj = {
                let cache = self.cache.read().unwrap();
                if let Some(map) = cache.as_ref() {
                    Value::Object(map.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
                } else {
                    Value::Object(serde_json::Map::new())
                }
            };

            // Ensure base directory exists
            if !self.base_dir.exists() {
                std::fs::create_dir_all(&self.base_dir).map_err(|e| Error::DirectoryCreate {
                    path: self.base_dir.display().to_string(),
                    source: e,
                })?;
            }

            self.storage.write(&path, &full_obj)?;
        } else {
            // Multi-file mode: write to individual file
            let path = self.entry_path(name);

            // Ensure directory exists
            std::fs::create_dir_all(&self.base_dir).map_err(|e| Error::DirectoryCreate {
                path: self.base_dir.display().to_string(),
                source: e,
            })?;

            self.storage.write(&path, &json_value)?;
        }

        let action = if exists {
            SubSettingsAction::Updated
        } else {
            SubSettingsAction::Created
        };

        info!(
            "✅ Sub-settings '{}' {} in {}",
            name,
            match action {
                SubSettingsAction::Created => "created",
                SubSettingsAction::Updated => "updated",
                SubSettingsAction::Deleted => "deleted",
            },
            self.config.name
        );

        self.notify_change(name, action);
        Ok(())
    }

    /// Delete an entry
    pub fn delete(&self, name: &str) -> Result<()> {
        self.ensure_cache_populated()?;

        // Acquire save mutex to prevent race conditions
        let _save_guard = self.save_mutex.lock().unwrap();

        // Remove from cache
        let existed = {
            let mut cache = self.cache.write().unwrap();
            if let Some(map) = cache.as_mut() {
                map.remove(name).is_some()
            } else {
                false
            }
        };

        // Even if not in cache (MultiFile), verify file existence later
        // But for SingleFile, cache is source of truth.

        if self.is_single_file() {
            if !existed {
                warn!(
                    "⚠️ Sub-settings entry '{}' not found in {}, nothing to delete",
                    name, self.config.name
                );
                return Ok(());
            }

            // Single-file mode: Write the current cache state to disk
            let path = self.single_file_path();

            // Reconstruct the full object from cache
            let full_obj = {
                let cache = self.cache.read().unwrap();
                if let Some(map) = cache.as_ref() {
                    Value::Object(map.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
                } else {
                    Value::Object(serde_json::Map::new())
                }
            };

            self.storage.write(&path, &full_obj)?;
        } else {
            // Multi-file mode: delete individual file
            let path = self.entry_path(name);

            if let Err(e) = std::fs::metadata(&path) {
                if e.kind() == std::io::ErrorKind::NotFound {
                    if !existed {
                        warn!(
                            "⚠️ Sub-settings entry '{}' not found in {}, nothing to delete",
                            name, self.config.name
                        );
                        return Ok(());
                    }
                    // If existed in cache but not disk, it's weird but cache is cleared now.
                } else {
                    return Err(Error::FileRead {
                        path: path.display().to_string(),
                        source: e,
                    });
                }
            } else {
                std::fs::remove_file(&path).map_err(|e| Error::FileDelete {
                    path: path.display().to_string(),
                    source: e,
                })?;
            }
        }

        info!(
            "✅ Sub-settings '{}' deleted from {}",
            name, self.config.name
        );
        self.notify_change(name, SubSettingsAction::Deleted);
        Ok(())
    }

    /// List all entries
    pub fn list(&self) -> Result<Vec<String>> {
        self.ensure_cache_populated()?;

        if self.is_single_file() {
            // Single-file mode: return keys from cache
            let cache = self.cache.read().unwrap();
            if let Some(map) = cache.as_ref() {
                let mut entries: Vec<String> = map.keys().cloned().collect();
                entries.sort();
                Ok(entries)
            } else {
                Ok(Vec::new())
            }
        } else {
            // Multi-file mode: list files in directory
            // We can't rely on cache as it might be partial
            if let Err(e) = std::fs::metadata(&self.base_dir) {
                if e.kind() == std::io::ErrorKind::NotFound {
                    return Ok(Vec::new());
                }
                return Err(Error::FileRead {
                    path: self.base_dir.display().to_string(),
                    source: e,
                });
            }

            let mut entries = Vec::new();
            let ext = format!(".{}", self.config.extension);

            let read_dir = std::fs::read_dir(&self.base_dir).map_err(|e| Error::FileRead {
                path: self.base_dir.display().to_string(),
                source: e,
            })?;

            for entry in read_dir {
                let entry = entry.map_err(|e| Error::FileRead {
                    path: self.base_dir.display().to_string(),
                    source: e,
                })?;
                let file_name = entry.file_name();
                let name = file_name.to_string_lossy();

                if name.ends_with(&ext) {
                    let entry_name = name.trim_end_matches(&ext).to_string();
                    entries.push(entry_name);
                }
            }

            entries.sort();
            Ok(entries)
        }
    }

    /// Check if an entry exists
    ///
    /// Returns `Ok(true)` if exists, `Ok(false)` if not found.
    /// Returns `Err` for I/O errors (e.g., permission denied).
    pub fn exists(&self, name: &str) -> Result<bool> {
        self.ensure_cache_populated()?;

        // Check cache first
        {
            let cache = self.cache.read().unwrap();
            if let Some(map) = cache.as_ref() {
                if map.contains_key(name) {
                    return Ok(true);
                }
            }
        }

        if self.is_single_file() {
            // In SingleFile mode, cache is authoritative
            Ok(false)
        } else {
            // Multi-file mode: check if file exists
            // Since it wasn't in cache (or cache is partial), check disk
            let path = self.entry_path(name);
            match std::fs::metadata(&path) {
                Ok(_) => Ok(true),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(e) => Err(Error::FileRead {
                    path: path.display().to_string(),
                    source: e,
                }),
            }
        }
    }

    /// Get the directory path for this sub-settings type
    /// In single-file mode, this is the directory containing the single file
    pub fn directory(&self) -> &PathBuf {
        &self.base_dir
    }

    /// Get the single file path (only applicable in single-file mode)
    /// Returns the path to the JSON file containing all entities
    pub fn file_path(&self) -> Option<PathBuf> {
        if self.is_single_file() {
            Some(self.single_file_path())
        } else {
            None
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::JsonStorage;
    use serde_json::json;
    use tempfile::tempdir;

    #[test]
    fn test_sub_settings_crud() {
        let dir = tempdir().unwrap();
        let config = SubSettingsConfig::new("remotes");
        let storage = JsonStorage::new();
        let sub = SubSettings::new(dir.path(), config, storage);

        // Initially empty
        let list = sub.list().unwrap();
        assert!(list.is_empty());

        // Save an entry
        let data = json!({"type": "drive", "path": "/mount/gdrive"});
        sub.set("gdrive", &data).unwrap();

        // Verify it exists
        assert!(sub.exists("gdrive").unwrap());

        // Load it back
        let loaded = sub.get_value("gdrive").unwrap();
        assert_eq!(loaded, data);

        // List should show it
        let list = sub.list().unwrap();
        assert_eq!(list, vec!["gdrive"]);

        // Delete it
        sub.delete("gdrive").unwrap();
        assert!(!sub.exists("gdrive").unwrap());
    }

    #[test]
    fn test_sub_settings_migration() {
        let dir = tempdir().unwrap();

        // Create config with migrator that adds a field
        let config = SubSettingsConfig::new("items").with_migrator(|mut v| {
            if let Some(obj) = v.as_object_mut() {
                if !obj.contains_key("version") {
                    obj.insert("version".into(), json!(2));
                }
            }
            v
        });

        let storage = JsonStorage::new();
        let sub = SubSettings::new(dir.path(), config, storage);

        // Save old format (without version)
        let old_data = json!({"name": "test"});
        sub.set("item1", &old_data).unwrap();

        // Load should apply migration
        let loaded = sub.get_value("item1").unwrap();
        assert_eq!(loaded["version"], json!(2));
        assert_eq!(loaded["name"], json!("test"));
    }

    #[test]
    fn test_sub_settings_not_found() {
        let dir = tempdir().unwrap();
        let config = SubSettingsConfig::new("items");
        let storage = JsonStorage::new();
        let sub = SubSettings::new(dir.path(), config, storage);

        let result = sub.get_value("nonexistent");
        assert!(matches!(
            result,
            Err(Error::SubSettingsEntryNotFound { .. })
        ));
    }

    #[test]
    fn test_sub_settings_single_file_mode() {
        let dir = tempdir().unwrap();

        // Create single-file config
        let config = SubSettingsConfig::new("backends").single_file();
        let storage = JsonStorage::new();
        let sub = SubSettings::new(dir.path(), config, storage);

        // Test create
        sub.set("gdrive", &json!({"type": "drive", "client_id": "123"}))
            .unwrap();
        sub.set("s3", &json!({"type": "s3", "region": "us-east-1"}))
            .unwrap();

        // Verify single file was created (not a directory)
        let file_path = dir.path().join("backends.json");
        assert!(file_path.exists());
        assert!(file_path.is_file());

        // Test list
        let list = sub.list().unwrap();
        assert_eq!(list, vec!["gdrive", "s3"]);

        // Test get
        let gdrive = sub.get::<serde_json::Value>("gdrive").unwrap();
        assert_eq!(gdrive["type"], json!("drive"));
        assert_eq!(gdrive["client_id"], json!("123"));

        // Test update
        sub.set("gdrive", &json!({"type": "drive", "client_id": "456"}))
            .unwrap();
        let gdrive = sub.get::<serde_json::Value>("gdrive").unwrap();
        assert_eq!(gdrive["client_id"], json!("456"));

        // Test exists
        assert!(sub.exists("gdrive").unwrap());
        assert!(sub.exists("s3").unwrap());
        assert!(!sub.exists("dropbox").unwrap());

        // Test delete
        sub.delete("s3").unwrap();
        let list = sub.list().unwrap();
        assert_eq!(list, vec!["gdrive"]);
        assert!(!sub.exists("s3").unwrap());

        // Test file_path()
        assert!(sub.file_path().is_some());
        assert_eq!(sub.file_path().unwrap(), file_path);
    }
}
