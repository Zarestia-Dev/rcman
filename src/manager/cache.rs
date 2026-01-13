//! Cache logic for `SettingsManager`
//!
//! Encapsulates the double-checked locking and cache invalidation logic.

use crate::error::{Error, Result};
use crate::sync::RwLockExt;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

pub struct CachedSettings {
    /// Stored settings (from disk)
    pub stored: Value,
    /// Merged settings (defaults + stored)
    pub merged: std::sync::OnceLock<Value>,
    /// Default values for quick lookup
    pub defaults: Arc<HashMap<String, Value>>,
    /// Generation counter
    pub generation: u64,
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
        let mut guard = self.state.write().expect("Lock poisoned");
        *guard = None;
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
            if let Some(value) = cached
                .stored
                .get(category)
                .and_then(|cat| cat.get(setting_name))
            {
                return Ok(Some(value.clone()));
            }
            // Check defaults
            if let Some(value) = cached.defaults.get(key) {
                return Ok(Some(value.clone()));
            }
        }
        Ok(None)
    }

    pub fn get_or_compute_merged<F>(&self, computer: F) -> Result<Value>
    where
        F: Fn(&Value) -> Result<Value>,
    {
        let guard = self.state.read_recovered()?;
        if let Some(cached) = guard.as_ref() {
            if let Some(merged) = cached.merged.get() {
                return Ok(merged.clone());
            }
            // Compute and set
            let computed_val = computer(&cached.stored)?;
            let _ = cached.merged.set(computed_val);
            return Ok(cached.merged.get().unwrap().clone());
        }
        Err(Error::Config("Cache not populated".into()))
    }

    pub fn get_stored(&self) -> Result<Option<Value>> {
        let guard = self.state.read_recovered()?;
        Ok(guard.as_ref().map(|c| c.stored.clone()))
    }

    pub fn is_populated(&self) -> bool {
        self.state.read().unwrap().is_some()
    }

    pub fn populate<F>(&self, factory: F) -> Result<()>
    where
        F: FnOnce() -> Result<CachedSettings>,
    {
        // Double-checked locking
        if self.is_populated() {
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
            cached.merged = std::sync::OnceLock::new(); // Reset merged
            cached.generation += 1;
        }
        Ok(())
    }
}
