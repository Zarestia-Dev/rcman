//! Compensating writes for manager operations. No silent volatile fallback:
//! inability to snapshot or persist a credential aborts the operation.

use super::{CredentialBackend, CredentialManager, MemoryEntry};
use crate::{Error, Result};
use std::sync::Arc;

struct Undo {
    backend: Arc<dyn CredentialBackend>,
    key: String,
    value: Option<String>,
}

type SnapshotResult = (Vec<Arc<dyn CredentialBackend>>, Vec<Undo>);

/// A target owns declared main keys or a sub-settings credential prefix.
#[cfg(feature = "profiles")]
pub(crate) enum ProfileSecretScope {
    /// Declared main settings, including categories named `sub`.
    Keys(std::collections::HashSet<String>),
    /// Every entry belonging to one sub-settings group.
    Prefix(String),
}

#[cfg(feature = "profiles")]
impl ProfileSecretScope {
    fn owns(&self, key: &str) -> bool {
        match self {
            Self::Keys(keys) => keys.contains(key),
            Self::Prefix(prefix) => key.starts_with(prefix),
        }
    }
}

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
        self.invalidate_tracked_secrets_cache()?;
        let updates = self.prepare_updates(changes, profile)?;
        self.commit_updates(updates, changes, finish)
    }

    #[cfg(feature = "profiles")]
    pub(crate) fn transfer_profile<F>(
        &self,
        source: &str,
        target: &str,
        scope: &ProfileSecretScope,
        remove_source: bool,
        finish: F,
    ) -> Result<()>
    where
        F: FnOnce() -> Result<()>,
    {
        #[cfg(feature = "backup")]
        let _operation = crate::backup::transaction::enter_credentials(&self.service_name)?;
        let _guard = self.commit_lock.lock().map_err(|_| Error::LockPoisoned)?;
        self.invalidate_tracked_secrets_cache()?;
        let owned = |key: &str| scope.owns(key);
        let mut target_changes = self
            .get_tracked_secrets(Some(target))?
            .into_iter()
            .filter(|key| owned(key))
            .map(|key| (key, None))
            .collect::<std::collections::BTreeMap<_, _>>();
        let mut source_changes = Vec::new();
        let source_keys = self.get_tracked_secrets(Some(source))?;
        for key in source_keys.iter().filter(|key| owned(key)).cloned() {
            target_changes.insert(key.clone(), self.get_with_profile(&key, Some(source))?);
            if remove_source {
                source_changes.push((key, None));
            }
        }
        let target_changes: Vec<_> = target_changes.into_iter().collect();
        if source_changes.is_empty() && target_changes.is_empty() {
            return finish();
        }
        let mut updates = self.prepare_updates(&target_changes, Some(target))?;
        if !source_changes.is_empty() {
            updates.extend(self.prepare_updates(&source_changes, Some(source))?);
        }
        // Both namespaces update the same profile index; publish their union once.
        let profile_key = self.make_key_with_profile("__rcman_profiles__", None);
        updates.retain(|(key, _)| key != &profile_key);
        let mut profiles = self.get_tracked_profiles()?;
        if remove_source && source_keys.iter().all(|key| owned(key)) {
            profiles.remove(source);
            let source_marker = self.make_key_with_profile("__rcman_secrets__", Some(source));
            updates.retain(|(key, _)| key != &source_marker);
            updates.push((source_marker, None));
        } else {
            profiles.insert(source.to_owned());
        }
        profiles.insert(target.to_owned());
        let mut profiles: Vec<_> = profiles.into_iter().collect();
        profiles.sort();
        updates.push((profile_key, Some(serde_json::to_string(&profiles)?)));
        let changes: Vec<_> = target_changes.into_iter().chain(source_changes).collect();
        self.commit_updates(updates, &changes, finish)
    }

    #[cfg(feature = "profiles")]
    pub(crate) fn remove_profile_secrets<F>(
        &self,
        profile: &str,
        scope: &ProfileSecretScope,
        finish: F,
    ) -> Result<()>
    where
        F: FnOnce() -> Result<()>,
    {
        #[cfg(feature = "backup")]
        let _operation = crate::backup::transaction::enter_credentials(&self.service_name)?;
        let _guard = self.commit_lock.lock().map_err(|_| Error::LockPoisoned)?;
        self.invalidate_tracked_secrets_cache()?;
        let tracked = self.get_tracked_secrets(Some(profile))?;
        let changes: Vec<_> = tracked
            .iter()
            .filter(|key| scope.owns(key))
            .map(|key| (key.clone(), None))
            .collect();
        if changes.is_empty() {
            return finish();
        }
        let mut updates = self.prepare_updates(&changes, Some(profile))?;
        if changes.len() == tracked.len() {
            let marker = self.make_key_with_profile("__rcman_secrets__", Some(profile));
            updates.retain(|(key, _)| key != &marker);
            updates.push((marker, None));
            let index = self.make_key_with_profile("__rcman_profiles__", None);
            updates.retain(|(key, _)| key != &index);
            let mut profiles: Vec<_> = self
                .get_tracked_profiles()?
                .into_iter()
                .filter(|name| name != profile)
                .collect();
            profiles.sort();
            updates.push((index, Some(serde_json::to_string(&profiles)?)));
        }
        self.commit_updates(updates, &changes, finish)
    }

    fn commit_updates<F>(
        &self,
        updates: Vec<(String, Option<String>)>,
        changes: &[(String, Option<String>)],
        finish: F,
    ) -> Result<()>
    where
        F: FnOnce() -> Result<()>,
    {
        let (backends, mut snapshots) = self.snapshot_backends(&updates, changes)?;

        // Invalidate before mutation, including errors and partial rollback.
        self.invalidate_tracked_secrets_cache()?;
        let mut attempted = 0;
        let result = (|| {
            for (key, value) in &updates {
                #[cfg(feature = "backup")]
                self.memory.capture(key, &self.service_name)?;
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
                Some(value) => self.memory.store(&key, MemoryEntry::Cached(value))?,
                None => self.memory.remove(&key)?,
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
                        || !matches!(&error, Error::CredentialBackendUnavailable(_))
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
                return Err(Error::CredentialBackendUnavailable("offline".into()));
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

    struct CorruptReadBackend {
        memory: MemoryBackend,
    }

    impl CredentialBackend for CorruptReadBackend {
        fn store(&self, key: &str, value: &str) -> Result<()> {
            self.memory.store(key, value)
        }
        fn get(&self, _key: &str) -> Result<Option<String>> {
            Err(Error::Credential("invalid stored credential data".into()))
        }
        fn remove(&self, key: &str) -> Result<()> {
            self.memory.remove(key)
        }
        fn list_keys(&self) -> Result<Vec<String>> {
            self.memory.list_keys()
        }
        fn backend_name(&self) -> &'static str {
            "corrupt_read"
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

    #[test]
    fn managed_commit_does_not_treat_primary_data_errors_as_outages() {
        let fallback = Arc::new(MemoryBackend::new());
        fallback.store("corrupt:__rcman_secrets__", "[]").unwrap();
        let mut manager = CredentialManager::with_backend(
            "corrupt",
            Arc::new(CorruptReadBackend {
                memory: MemoryBackend::new(),
            }),
        );
        manager.fallback = Some(fallback.clone());
        let mut finish_called = false;

        let result = manager.commit_settings(&[("key".into(), Some("value".into()))], None, || {
            finish_called = true;
            Ok(())
        });

        assert!(matches!(result, Err(Error::Credential(_))));
        assert!(!finish_called);
        assert_eq!(fallback.get("corrupt:key").unwrap(), None);
    }

    #[cfg(feature = "profiles")]
    #[test]
    fn failed_profile_transfer_restores_values_and_both_tracking_namespaces() {
        let backend = Arc::new(MemoryBackend::new());
        let manager = CredentialManager::with_backend("profile-rollback", backend.clone());
        manager
            .commit_settings(
                &[("token".into(), Some("original".into()))],
                Some("source"),
                || Ok(()),
            )
            .unwrap();
        manager
            .commit_settings(
                &[("sub.items.one.token".into(), Some("independent".into()))],
                Some("source"),
                || Ok(()),
            )
            .unwrap();
        manager
            .commit_settings(
                &[("sub.items.one.token".into(), Some("target".into()))],
                Some("target"),
                || Ok(()),
            )
            .unwrap();
        let before = backend
            .list_keys()
            .unwrap()
            .into_iter()
            .map(|key| {
                let value = backend.get(&key).unwrap();
                (key, value)
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        assert!(
            manager
                .transfer_profile(
                    "source",
                    "target",
                    &ProfileSecretScope::Keys(["token".to_owned()].into()),
                    true,
                    || Err(Error::Config("manifest write failed".into()))
                )
                .is_err()
        );
        let after = backend
            .list_keys()
            .unwrap()
            .into_iter()
            .map(|key| {
                let value = backend.get(&key).unwrap();
                (key, value)
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(before, after);
        assert_eq!(
            manager
                .get_with_profile("token", Some("source"))
                .unwrap()
                .as_deref(),
            Some("original")
        );
        assert_eq!(
            manager.get_with_profile("token", Some("target")).unwrap(),
            None
        );
        assert_eq!(
            manager.get_tracked_secrets(Some("source")).unwrap().len(),
            2
        );
    }
}
