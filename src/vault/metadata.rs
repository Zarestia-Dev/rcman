//! Root password verifier, stored independently of optional settings files.

use super::{VaultEnvelope, VaultState};
use crate::error::{Error, Result};
use crate::storage::{JsonStorage, StorageBackend};
use std::path::{Path, PathBuf};

pub(crate) const FILE_NAME: &str = ".rcman-vault.json";
const CONTROL: &[u8] = b"rcman vault password verification";

pub(crate) fn path(root: &Path) -> PathBuf {
    root.join(FILE_NAME)
}

pub(crate) fn read(root: &Path) -> Result<Option<VaultEnvelope>> {
    let path = path(root);
    let content = match std::fs::read(&path) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(Error::FileRead { path, source }),
    };
    let envelope: VaultEnvelope = serde_json::from_slice(&content)
        .map_err(|error| Error::InvalidVaultMetadata(error.to_string()))?;
    envelope
        .validate()
        .map_err(|error| Error::InvalidVaultMetadata(error.to_string()))?;
    let expected_context = super::envelope::VaultContext {
        path: FILE_NAME.into(),
        entry: None,
    };
    if envelope.context.as_ref() != Some(&expected_context) {
        return Err(Error::InvalidVaultMetadata(
            "Invalid verifier context".into(),
        ));
    }
    Ok(Some(envelope))
}

pub(crate) fn envelope(
    root: &Path,
    vault: &VaultState,
    timeout: Option<std::time::Duration>,
) -> Result<VaultEnvelope> {
    vault.encrypt_managed_with_timeout(CONTROL, &path(root), timeout)
}

pub(crate) fn unlock(vault: &VaultState, password: &str, envelope: &VaultEnvelope) -> Result<()> {
    let payload = vault.unlock(password, Some(envelope)).map_err(|error| {
        if matches!(error, Error::InvalidPassword) {
            Error::VaultUnlockFailed
        } else {
            error
        }
    })?;
    if payload.as_deref() != Some(CONTROL) {
        vault.lock()?;
        return Err(Error::VaultUnlockFailed);
    }
    Ok(())
}

pub(crate) fn write(root: &Path, envelope: &VaultEnvelope) -> Result<()> {
    JsonStorage::new().write(&path(root), envelope)
}

pub(crate) fn create(root: &Path, envelope: &VaultEnvelope) -> Result<()> {
    use std::io::Write;
    let path = path(root);
    let content = serde_json::to_vec_pretty(envelope)?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&path).map_err(|source| Error::FileWrite {
        path: path.clone(),
        source,
    })?;
    let result = (|| {
        crate::utils::security::set_secure_file_permissions(&path)?;
        file.write_all(&content)
            .and_then(|()| file.sync_all())
            .map_err(|source| Error::FileWrite {
                path: path.clone(),
                source,
            })
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(path);
    }
    result
}

pub(crate) fn remove(root: &Path) -> Result<()> {
    JsonStorage::new().remove(&path(root))
}
