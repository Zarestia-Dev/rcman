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
    state: RwLock<Option<CachedSettings>>,
}

impl SettingsCache {
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

    pub fn get_value(
        &self,
        category: &str,
        setting_name: &str,
        key: &str,
    ) -> Result<Option<Value>> {
        let guard = self.state.read_recovered()?;
        if let Some(cached) = guard.as_ref() {
            // Check stored
            let stored = if category.is_empty() {
                cached.stored.get(setting_name)
            } else {
                cached
                    .stored
                    .get(category)
                    .and_then(|cat| cat.get(setting_name))
            };
            if let Some(value) = stored {
                return Ok(Some(value.clone()));
            }
            // Check defaults
            if let Some(value) = cached.defaults.get(key) {
                return Ok(Some(value.clone()));
            }
        }
        Ok(None)
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
            if let Some(cached) = guard.as_ref() {
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
        Ok(guard.as_ref().map(|c| c.stored.clone()))
    }

    /// Populate the cache if empty.
    ///
    /// Checks the read lock first, then double-checks under the write lock
    /// before loading an empty cache.
    pub fn populate<F>(&self, factory: F) -> Result<()>
    where
        F: FnOnce() -> Result<CachedSettings>,
    {
        if self.state.read_recovered()?.is_some() {
            return Ok(());
        }
        let mut guard = self.state.write_recovered()?;
        if guard.is_some() {
            return Ok(());
        }

        *guard = Some(factory()?);
        Ok(())
    }

    pub fn update_stored(&self, new_stored: Value) -> Result<()> {
        let mut guard = self.state.write_recovered()?;
        if let Some(ref mut cached) = *guard {
            cached.stored = new_stored;
            cached.merged = None; // Invalidate merged — will be recomputed lazily
        }
        Ok(())
    }
}
