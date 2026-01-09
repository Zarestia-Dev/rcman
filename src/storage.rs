//! Storage backend trait and implementations

use crate::error::{Error, Result};
use crate::security::{set_secure_dir_permissions, set_secure_file_permissions};
use serde::{de::DeserializeOwned, Serialize};
use std::path::Path;

/// Trait for storage backend implementations
///
/// This allows swapping JSON for TOML, YAML, or other formats in the future.
pub trait StorageBackend: Clone + Send + Sync {
    /// File extension for this storage format (e.g., "json", "toml")
    ///
    /// # Returns
    ///
    /// * `&str` - File extension for this storage format
    fn extension(&self) -> &str;

    /// Serialize data to string
    ///
    /// # Arguments
    ///
    /// * `data` - Data to serialize
    ///
    /// # Returns
    ///
    /// * `Result<String>` - Serialized data
    ///
    /// # Errors
    ///
    /// * `Error::Io` - If the data cannot be serialized
    fn serialize<T: Serialize>(&self, data: &T) -> Result<String>;

    /// Deserialize data from string
    ///
    /// # Arguments
    ///
    /// * `content` - Data to deserialize
    ///
    /// # Returns
    ///
    /// * `Result<T>` - Deserialized data
    ///
    /// # Errors
    ///
    /// * `Error::Io` - If the data cannot be deserialized
    fn deserialize<T: DeserializeOwned>(&self, content: &str) -> Result<T>;

    /// Read and deserialize from file
    ///
    /// # Arguments
    ///
    /// * `path` - Path to file to read
    ///
    /// # Returns
    ///
    /// * `Result<T>` - Deserialized data
    ///
    /// # Errors
    ///
    /// * `Error::FileRead` - If the file cannot be read
    fn read<T: DeserializeOwned>(&self, path: &Path) -> Result<T> {
        let content = std::fs::read_to_string(path).map_err(|e| Error::FileRead {
            path: path.to_path_buf(),
            source: e,
        })?;
        self.deserialize(&content)
    }

    /// Serialize and write to file
    ///
    /// Uses atomic write: writes to temp file then renames to prevent corruption.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to file to write
    /// * `data` - Data to serialize and write
    ///
    /// # Returns
    ///
    /// * `Result<()>` - Success or error
    ///
    /// # Errors
    ///
    /// * `Error::FileWrite` - If the file cannot be written
    fn write<T: Serialize>(&self, path: &Path, data: &T) -> Result<()> {
        let content = self.serialize(data)?;

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            let dir_existed = parent.exists();
            std::fs::create_dir_all(parent).map_err(|e| Error::DirectoryCreate {
                path: parent.to_path_buf(),
                source: e,
            })?;
            // Only secure the directory if we just created it
            if !dir_existed {
                set_secure_dir_permissions(parent)?;
            }
        }

        // Atomic write: temp file + rename
        // Use .tmp suffix append to preserve original filename fully
        let file_name = path.file_name().ok_or_else(|| {
            Error::Config(format!(
                "Invalid path '{}': must have a filename",
                path.display()
            ))
        })?;
        let mut temp_filename = file_name.to_os_string();
        temp_filename.push(".tmp");
        let temp_path = path.with_file_name(temp_filename);

        std::fs::write(&temp_path, &content).map_err(|e| Error::FileWrite {
            path: temp_path.to_path_buf(),
            source: e,
        })?;

        // Set secure permissions on temp file before rename
        set_secure_file_permissions(&temp_path)?;

        std::fs::rename(&temp_path, path).map_err(|e| Error::FileWrite {
            path: path.to_path_buf(),
            source: e,
        })?;

        // Ensure final file has secure permissions (in case rename didn't preserve)
        set_secure_file_permissions(path)?;

        Ok(())
    }
}

// =============================================================================
// JSON Storage Implementation
// =============================================================================

/// JSON storage backend (default)
///
/// # Example
///
/// ```
/// use rcman::{JsonStorage, StorageBackend};
/// use serde::{Deserialize, Serialize};
///
/// #[derive(Serialize, Deserialize)]
/// struct Config { name: String }
///
/// let storage = JsonStorage::new();
/// let data = Config { name: "test".into() };
/// let json = storage.serialize(&data).unwrap();
/// assert!(json.contains("test"));
/// ```
#[derive(Clone, Default)]
pub struct JsonStorage {
    /// Pretty print JSON output
    pretty: bool,
}

impl JsonStorage {
    /// Create a new JSON storage backend with pretty printing enabled
    #[must_use]
    pub fn new() -> Self {
        Self { pretty: true }
    }

    /// Create a compact JSON storage (no pretty printing)
    #[must_use]
    pub fn compact() -> Self {
        Self { pretty: false }
    }
}

impl StorageBackend for JsonStorage {
    fn extension(&self) -> &'static str {
        "json"
    }

    fn serialize<T: Serialize>(&self, data: &T) -> Result<String> {
        if self.pretty {
            serde_json::to_string_pretty(data).map_err(Error::from)
        } else {
            serde_json::to_string(data).map_err(Error::from)
        }
    }

    fn deserialize<T: DeserializeOwned>(&self, content: &str) -> Result<T> {
        serde_json::from_str(content).map_err(Error::from)
    }
}

// =============================================================================
// TOML Storage Implementation
// =============================================================================

/// TOML storage backend
///
/// Requires the `toml` feature.
#[cfg(feature = "toml")]
#[derive(Clone, Default)]
pub struct TomlStorage;

#[cfg(feature = "toml")]
impl TomlStorage {
    /// Create a new TOML storage backend
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

#[cfg(feature = "toml")]
impl StorageBackend for TomlStorage {
    fn extension(&self) -> &'static str {
        "toml"
    }

    fn serialize<T: Serialize>(&self, data: &T) -> Result<String> {
        toml::to_string(data).map_err(|e| Error::Parse(e.to_string()))
    }

    fn deserialize<T: DeserializeOwned>(&self, content: &str) -> Result<T> {
        toml::from_str(content).map_err(|e| Error::Parse(e.to_string()))
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use tempfile::tempdir;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct TestData {
        name: String,
        value: i32,
    }

    #[test]
    fn test_json_serialize_pretty() {
        let storage = JsonStorage::new();
        let data = TestData {
            name: "test".into(),
            value: 42,
        };

        let json = storage.serialize(&data).unwrap();
        assert!(json.contains('\n')); // Pretty printed
        assert!(json.contains("\"name\": \"test\""));
    }

    #[test]
    fn test_json_serialize_compact() {
        let storage = JsonStorage::compact();
        let data = TestData {
            name: "test".into(),
            value: 42,
        };

        let json = storage.serialize(&data).unwrap();
        assert!(!json.contains('\n')); // Compact
    }

    #[test]
    fn test_json_roundtrip_sync() {
        let storage = JsonStorage::new();
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.json");

        let data = TestData {
            name: "hello".into(),
            value: 123,
        };

        storage.write(&path, &data).unwrap();
        let loaded: TestData = storage.read(&path).unwrap();

        assert_eq!(data, loaded);
    }

    #[test]
    fn test_json_roundtrip_async() {
        let storage = JsonStorage::new();
        let dir = tempdir().unwrap();
        let path = dir.path().join("subdir/test.json");

        let data = TestData {
            name: "async test".into(),
            value: 999,
        };

        storage.write(&path, &data).unwrap();
        let loaded: TestData = storage.read(&path).unwrap();

        assert_eq!(data, loaded);
    }

    #[test]
    fn test_read_nonexistent_file() {
        let storage = JsonStorage::new();
        let result: Result<TestData> = storage.read(Path::new("/nonexistent/file.json"));

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::FileRead { .. }));
    }

    #[test]
    #[cfg(feature = "toml")]
    fn test_toml_roundtrip() {
        let storage = TomlStorage::new();
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.toml");

        let data = TestData {
            name: "toml_test".into(),
            value: 99,
        };

        storage.write(&path, &data).unwrap();
        let loaded: TestData = storage.read(&path).unwrap();

        assert_eq!(data, loaded);

        // Verify content is actually TOML
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("name = \"toml_test\""));
        assert!(content.contains("value = 99"));
    }
}
