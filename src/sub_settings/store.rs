use crate::error::Result;
use serde_json::Value;

/// Storage abstraction for sub-settings
pub trait SubSettingsStore: Send + Sync {
    /// Get an entry by key
    fn get(&self, key: &str) -> Result<Value>;

    /// Set an entry
    fn set(&self, key: &str, value: Value) -> Result<()>;

    /// Remove an entry
    fn remove(&self, key: &str) -> Result<()>;

    /// List all keys
    fn list(&self) -> Result<Vec<String>>;

    /// Invalidate any internal cache
    fn invalidate_cache(&self);

    /// Get the base path (directory) of the store
    fn get_base_path(&self) -> std::path::PathBuf;

    /// Get the single file path if applicable (returns None for `MultiFile`)
    fn get_single_file_path(&self) -> Option<std::path::PathBuf>;
}
