//! Credential values retain their persistence state in one shared map.

use crate::{Error, Result};
use std::{collections::HashMap, sync::RwLock};

#[derive(Clone)]
pub(super) enum MemoryEntry {
    Cached(String),
    VolatileWrite(String),
}

#[derive(Default)]
pub(super) struct CredentialMemory {
    entries: RwLock<HashMap<String, MemoryEntry>>,
}

impl CredentialMemory {
    pub(super) fn store(&self, key: &str, value: MemoryEntry) -> Result<()> {
        self.entries
            .write()
            .map_err(|_| Error::LockPoisoned)?
            .insert(key.to_owned(), value);
        Ok(())
    }

    /// A confirmed persistent miss evicts a cached value, but not an unsaved write.
    pub(super) fn read_fallback(&self, key: &str, read_failed: bool) -> Result<Option<String>> {
        {
            let entries = self.entries.read().map_err(|_| Error::LockPoisoned)?;
            match entries.get(key) {
                Some(MemoryEntry::VolatileWrite(value)) => return Ok(Some(value.clone())),
                Some(MemoryEntry::Cached(value)) if read_failed => return Ok(Some(value.clone())),
                None => return Ok(None),
                Some(MemoryEntry::Cached(_)) => {}
            }
        }

        // Recheck after acquiring the write lock to preserve a concurrent unsaved write.
        let mut entries = self.entries.write().map_err(|_| Error::LockPoisoned)?;
        if let Some(MemoryEntry::VolatileWrite(value)) = entries.get(key) {
            Ok(Some(value.clone()))
        } else {
            entries.remove(key);
            Ok(None)
        }
    }

    pub(super) fn remove(&self, key: &str) -> Result<()> {
        self.entries
            .write()
            .map_err(|_| Error::LockPoisoned)?
            .remove(key);
        Ok(())
    }

    pub(super) fn list_keys(&self) -> Result<Vec<String>> {
        Ok(self
            .entries
            .read()
            .map_err(|_| Error::LockPoisoned)?
            .keys()
            .cloned()
            .collect())
    }

    pub(super) fn has_volatile_writes(&self) -> Result<bool> {
        Ok(self
            .entries
            .read()
            .map_err(|_| Error::LockPoisoned)?
            .values()
            .any(|entry| matches!(entry, MemoryEntry::VolatileWrite(_))))
    }

    /// Journal the value and its variant, so rollback cannot change persistence semantics.
    #[cfg(feature = "backup")]
    pub(super) fn capture(self: &std::sync::Arc<Self>, key: &str, service: &str) -> Result<()> {
        crate::backup::transaction::capture_credential_state(service, || {
            let previous = self
                .entries
                .read()
                .map_err(|_| Error::LockPoisoned)?
                .get(key)
                .cloned();
            let memory = self.clone();
            let key = key.to_owned();
            Ok(Box::new(move || {
                let mut entries = memory.entries.write().map_err(|_| Error::LockPoisoned)?;
                if let Some(previous) = previous {
                    entries.insert(key, previous);
                } else {
                    entries.remove(&key);
                }
                Ok(())
            }))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transitions_replace_the_previous_value_and_persistence_state() {
        let memory = CredentialMemory::default();
        memory
            .store("token", MemoryEntry::Cached("old".into()))
            .unwrap();
        memory
            .store("token", MemoryEntry::VolatileWrite("new".into()))
            .unwrap();
        assert_eq!(memory.list_keys().unwrap(), vec!["token"]);
        assert!(memory.has_volatile_writes().unwrap());
        assert_eq!(
            memory.read_fallback("token", false).unwrap().as_deref(),
            Some("new")
        );
        memory
            .store("token", MemoryEntry::Cached("persisted".into()))
            .unwrap();
        assert!(!memory.has_volatile_writes().unwrap());
        assert_eq!(
            memory.read_fallback("token", true).unwrap().as_deref(),
            Some("persisted")
        );
        assert_eq!(memory.read_fallback("token", false).unwrap(), None);
        assert!(memory.list_keys().unwrap().is_empty());
    }

    #[test]
    fn empty_values_and_removal_preserve_the_same_rules() {
        let memory = CredentialMemory::default();
        assert_eq!(memory.read_fallback("missing", true).unwrap(), None);
        memory
            .store("token", MemoryEntry::VolatileWrite(String::new()))
            .unwrap();
        assert_eq!(
            memory.read_fallback("token", false).unwrap().as_deref(),
            Some("")
        );
        memory.remove("token").unwrap();
        assert!(!memory.has_volatile_writes().unwrap());
        assert_eq!(memory.read_fallback("token", true).unwrap(), None);
    }

    #[test]
    fn poisoned_memory_returns_errors() {
        let memory = CredentialMemory::default();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = memory.entries.write().unwrap();
            panic!("poison memory lock");
        }));
        assert!(
            memory
                .store("token", MemoryEntry::Cached("value".into()))
                .is_err()
        );
        assert!(memory.read_fallback("token", true).is_err());
        assert!(memory.remove("token").is_err());
        assert!(memory.list_keys().is_err());
        assert!(memory.has_volatile_writes().is_err());
    }
}
