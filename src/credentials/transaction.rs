//! Compensating writes for manager operations. No silent volatile fallback:
//! inability to snapshot or persist a credential aborts the operation.

use super::{CredentialBackend, CredentialManager};
use crate::{Error, Result};
use std::sync::Arc;

struct Undo {
    backend: Arc<dyn CredentialBackend>,
    key: String,
    value: Option<String>,
}

type SnapshotResult = (Vec<Arc<dyn CredentialBackend>>, Vec<Undo>);

impl CredentialManager {
    pub(crate) fn commit_settings<F>(
        &self,
        changes: &[(String, Option<String>)],
        profile: Option<&str>,
        finish: F,
    ) -> Result<()>
    where
        F: FnOnce() -> Result<()>,
    {
        #[cfg(feature = "backup")]
        let _operation = crate::backup::transaction::enter_credentials(&self.service_name)?;
        if changes.is_empty() {
            return finish();
        }

        let _guard = self.commit_lock.lock().map_err(|_| Error::LockPoisoned)?;
        let updates = self.prepare_updates(changes, profile)?;
        let (backends, mut snapshots) = self.snapshot_backends(&updates, changes)?;

        // Invalidate before mutation, including errors and partial rollback.
        self.invalidate_tracked_secrets_cache()?;
        let mut attempted = 0;
        let result = (|| {
            for (key, value) in &updates {
                for (index, backend) in backends.iter().enumerate() {
                    #[cfg(feature = "backup")]
                    crate::backup::transaction::capture_credential(
                        Arc::clone(backend),
                        key,
                        &self.service_name,
                    )?;
                    attempted += 1;
                    // Write to the first available persistent backend and clear
                    // stale copies. Publish volatile values only after finish succeeds.
                    if index == 0 {
                        match value {
                            Some(value) => backend.store(key, value)?,
                            None => backend.remove(key)?,
                        }
                    } else {
                        backend.remove(key)?;
                    }
                }
            }
            finish()
        })();
        if let Err(source) = result {
            snapshots.truncate(attempted);
            return Err(rollback_snapshots(snapshots, source));
        }
        for (key, value) in updates {
            match value {
                Some(value) => self.volatile.store(&key, &value)?,
                None => self.volatile.remove(&key)?,
            }
        }
        Ok(())
    }

    fn prepare_updates(
        &self,
        changes: &[(String, Option<String>)],
        profile: Option<&str>,
    ) -> Result<Vec<(String, Option<String>)>> {
        let mut updates: Vec<_> = changes
            .iter()
            .map(|(key, value)| (self.make_key_with_profile(key, profile), value.clone()))
            .collect();
        let mut tracked = self.get_tracked_secrets(profile)?;
        for (key, value) in changes {
            if value.is_some() {
                tracked.insert(key.clone());
            } else {
                tracked.remove(key);
            }
        }
        let mut tracked: Vec<_> = tracked.into_iter().collect();
        tracked.sort();
        updates.push((
            self.make_key_with_profile("__rcman_secrets__", profile),
            Some(serde_json::to_string(&tracked)?),
        ));
        #[cfg(feature = "profiles")]
        if let Some(profile) = profile {
            let mut profiles = self.get_tracked_profiles()?;
            profiles.insert(profile.to_owned());
            let mut profiles: Vec<_> = profiles.into_iter().collect();
            profiles.sort();
            updates.push((
                self.make_key_with_profile("__rcman_profiles__", None),
                Some(serde_json::to_string(&profiles)?),
            ));
        }
        Ok(updates)
    }

    fn snapshot_backends(
        &self,
        updates: &[(String, Option<String>)],
        changes: &[(String, Option<String>)],
    ) -> Result<SnapshotResult> {
        let mut backends = vec![Arc::clone(&self.primary)];
        if let Some(fallback) = &self.fallback {
            backends.push(Arc::clone(fallback));
        }
        let mut available = Vec::new();
        let mut snapshots_by_backend = Vec::new();
        for backend in backends {
            let snapshot = updates
                .iter()
                .map(|(key, _)| {
                    Ok(Undo {
                        backend: Arc::clone(&backend),
                        key: key.clone(),
                        value: backend.get(key)?,
                    })
                })
                .collect::<Result<Vec<_>>>();
            match snapshot {
                Ok(snapshot) => {
                    available.push(backend);
                    snapshots_by_backend.push(snapshot);
                }
                Err(error) => {
                    if self.fallback.is_none()
                        || changes.iter().any(|(_, value)| value.is_none())
                        || !Arc::ptr_eq(&backend, &self.primary)
                    {
                        return Err(error);
                    }
                }
            }
        }
        if available.is_empty() {
            return Err(Error::Credential(
                "No persistent credential backend available".into(),
            ));
        }
        let mut snapshots = Vec::new();
        for index in 0..updates.len() {
            for snapshot in &mut snapshots_by_backend {
                let undo = &mut snapshot[index];
                snapshots.push(Undo {
                    backend: Arc::clone(&undo.backend),
                    key: undo.key.clone(),
                    value: undo.value.take(),
                });
            }
        }
        Ok((available, snapshots))
    }
}

fn rollback_snapshots(snapshots: Vec<Undo>, source: Error) -> Error {
    let mut rollback_errors = Vec::new();
    for undo in snapshots.into_iter().rev() {
        let restored = match undo.value {
            Some(value) => undo.backend.store(&undo.key, &value),
            None => undo.backend.remove(&undo.key),
        };
        if let Err(error) = restored {
            rollback_errors.push(error.to_string());
        }
    }
    if rollback_errors.is_empty() {
        source
    } else {
        Error::TransactionFailed {
            source: Box::new(source),
            rollback_errors,
        }
    }
}

// Preserve legacy raw string credentials. Non-string values carry an explicit
// JSON tag so nullable text and strings such as "null" remain distinguishable.
const SETTING_PREFIX: &str = "\u{1e}rcman:json:1:";

pub(crate) fn encode_setting(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(text) if !text.starts_with(SETTING_PREFIX) => text.clone(),
        _ => format!("{SETTING_PREFIX}{value}"),
    }
}

pub(crate) fn decode_setting(
    value: &str,
    metadata: &crate::SettingMetadata,
) -> Result<serde_json::Value> {
    let decoded = if let Some(json) = value.strip_prefix(SETTING_PREFIX) {
        serde_json::from_str(json)?
    } else {
        let text = serde_json::Value::String(value.to_owned());
        let is_text = matches!(metadata.setting_type, crate::SettingType::Text)
            || (matches!(
                metadata.setting_type,
                crate::SettingType::Select | crate::SettingType::Info | crate::SettingType::Object
            ) && metadata.default.is_string());
        if is_text {
            text
        } else {
            serde_json::from_str(value)
                .map_err(|error| Error::Credential(format!("Invalid typed credential: {error}")))?
        }
    };
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::MemoryBackend;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct UnavailableBackend {
        unavailable: AtomicBool,
        memory: MemoryBackend,
    }
    impl CredentialBackend for UnavailableBackend {
        fn store(&self, key: &str, value: &str) -> Result<()> {
            if self.unavailable.load(Ordering::SeqCst) {
                return Err(Error::Credential("offline".into()));
            }
            self.memory.store(key, value)
        }
        fn get(&self, key: &str) -> Result<Option<String>> {
            if self.unavailable.load(Ordering::SeqCst) {
                return Err(Error::Credential("offline".into()));
            }
            self.memory.get(key)
        }
        fn remove(&self, key: &str) -> Result<()> {
            if self.unavailable.load(Ordering::SeqCst) {
                return Err(Error::Credential("offline".into()));
            }
            self.memory.remove(key)
        }
        fn list_keys(&self) -> Result<Vec<String>> {
            self.memory.list_keys()
        }
        fn backend_name(&self) -> &'static str {
            "unavailable"
        }
    }

    #[test]
    fn persistent_fallback_survives_primary_recovery() {
        let primary = Arc::new(UnavailableBackend {
            unavailable: AtomicBool::new(true),
            memory: MemoryBackend::new(),
        });
        primary.memory.store("fallback:key", "old").unwrap();
        let mut manager = CredentialManager::with_backend("fallback", primary.clone());
        manager.fallback = Some(Arc::new(MemoryBackend::new()));
        manager
            .commit_settings(&[("key".into(), Some("new".into()))], None, || Ok(()))
            .unwrap();
        assert_eq!(manager.get("key").unwrap().as_deref(), Some("new"));
        assert!(
            manager
                .commit_settings(&[("key".into(), None)], None, || Ok(()))
                .is_err()
        );
        manager
            .commit_settings(&[("key".into(), Some("new".into()))], None, || Ok(()))
            .unwrap();
        primary.unavailable.store(false, Ordering::SeqCst);
        assert_eq!(manager.get("key").unwrap().as_deref(), Some("new"));
        manager
            .commit_settings(&[("key".into(), None)], None, || Ok(()))
            .unwrap();
        assert_eq!(manager.get("key").unwrap(), None);
    }

    #[test]
    fn failed_finish_restores_fallback_and_tracking() {
        let primary = Arc::new(UnavailableBackend {
            unavailable: AtomicBool::new(true),
            memory: MemoryBackend::new(),
        });
        let mut manager = CredentialManager::with_backend("fallback-rollback", primary);
        manager.fallback = Some(Arc::new(MemoryBackend::new()));
        assert!(
            manager
                .commit_settings(&[("key".into(), Some("new".into()))], None, || Err(
                    Error::Config("file failure".into())
                ))
                .is_err()
        );
        assert_eq!(manager.get("key").unwrap(), None);
        assert!(manager.get_tracked_secrets(None).unwrap().is_empty());
    }
}
