//! Cache logic for `SettingsManager`
//!
//! Encapsulates the double-checked locking and cache invalidation logic.

use crate::error::{Error, Result};
use crate::utils::sync::RwLockExt;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

pub struct CachedSettings {
    /// Stored settings (from disk)
    pub stored: Value,
    /// Merged settings (defaults + stored), lazily computed
    pub merged: Option<Value>,
    /// Default values for quick lookup
    pub defaults: Arc<HashMap<String, Value>>,
}

pub struct SettingsCache {
    /// The actual cache, protected by `RwLock`
    state: RwLock<Option<(std::path::PathBuf, CachedSettings)>>,
}

impl SettingsCache {
    #[cfg(feature = "profiles")]
    pub(crate) fn invalidator(self: &Arc<Self>) -> Arc<dyn Fn() + Send + Sync> {
        let cache = Arc::clone(self);
        Arc::new(move || cache.invalidate())
    }
    pub fn new() -> Self {
        Self {
            state: RwLock::new(None),
        }
    }

    pub fn invalidate(&self) {
        if let Ok(mut guard) = self.state.write_recovered() {
            *guard = None;
        }
    }

    /// Look up a dotted key in the stored settings, then in the schema defaults.
    pub fn get_value(&self, key: &str) -> Result<Option<Value>> {
        let guard = self.state.read_recovered()?;
        Ok(guard.as_ref().and_then(|(_, cached)| {
            crate::utils::value::get_path(&cached.stored, key)
                .or_else(|| cached.defaults.get(key))
                .cloned()
        }))
    }

    /// Compute or retrieve the merged settings value.
    ///
    /// Computes under the write lock so mutations cannot publish a stale result.
    pub fn get_or_compute_merged<F>(&self, computer: F) -> Result<Value>
    where
        F: Fn(&Value) -> Result<Value>,
    {
        // Fast path: read lock, return if merged is already cached
        {
            let guard = self.state.read_recovered()?;
            if let Some((_, cached)) = guard.as_ref() {
                if let Some(ref merged) = cached.merged {
                    return Ok(merged.clone());
                }
            } else {
                return Err(Error::Config("Cache not populated".into()));
            }
        }

        // Slow path: compute under write lock to avoid TOCTOU
        let mut guard = self.state.write_recovered()?;
        let cached = guard
            .as_mut()
            .map(|(_, cached)| cached)
            .ok_or_else(|| Error::Config("Cache not populated".into()))?;

        // Double-check: another thread may have filled it while we waited
        if let Some(ref merged) = cached.merged {
            return Ok(merged.clone());
        }

        let computed_value = computer(&cached.stored)?;
        cached.merged = Some(computed_value.clone());
        Ok(computed_value)
    }

    pub fn get_stored(&self) -> Result<Option<Value>> {
        let guard = self.state.read_recovered()?;
        Ok(guard.as_ref().map(|(_, c)| c.stored.clone()))
    }

    /// Populate the cache if empty.
    ///
    /// Checks the read lock first, then double-checks under the write lock
    /// before loading an empty cache.
    pub fn populate<F>(&self, path: &std::path::Path, factory: F) -> Result<()>
    where
        F: FnOnce() -> Result<CachedSettings>,
    {
        let matches = |cached: &Option<(std::path::PathBuf, CachedSettings)>| {
            cached.as_ref().is_some_and(|(source, _)| source == path)
        };
        if matches(&*self.state.read_recovered()?) {
            return Ok(());
        }
        let mut guard = self.state.write_recovered()?;
        if !matches(&guard) {
            *guard = None;
            *guard = Some((path.to_path_buf(), factory()?));
        }
        Ok(())
    }

    pub fn update_stored(&self, new_stored: Value) -> Result<()> {
        let mut guard = self.state.write_recovered()?;
        if let Some((_, ref mut cached)) = *guard {
            cached.stored = new_stored;
            cached.merged = None; // Invalidate merged — will be recomputed lazily
        }
        Ok(())
    }
}
