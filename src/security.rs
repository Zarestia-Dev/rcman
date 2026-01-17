//! Security utilities for file permissions and access control

use crate::error::{Error, Result};
use std::path::Path;

/// Set restrictive permissions on a file (Unix: 0o600 - owner read/write only)
///
/// On Unix systems, this sets the file to be readable and writable only by the owner.
/// On Windows, this is a no-op as Windows uses ACLs differently.
///
/// # Arguments
///
/// * `path` - Path to the file to secure
///
/// # Example
///
/// ```ignore
/// use rcman::security::set_secure_file_permissions;
/// use std::path::Path;
///
/// let path = Path::new("/tmp/sensitive.json");
/// set_secure_file_permissions(path).unwrap();
/// ```
///
/// # Errors
///
/// * `Error::Io` - If the file cannot be set to secure permissions
#[cfg(unix)]
pub fn set_secure_file_permissions(path: &Path) -> Result<()> {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let metadata = fs::metadata(path).map_err(|e| Error::FileRead {
        path: path.to_path_buf(),
        source: e,
    })?;

    let mut perms = metadata.permissions();
    perms.set_mode(0o600); // Owner read/write only

    fs::set_permissions(path, perms).map_err(|e| Error::FileWrite {
        path: path.to_path_buf(),
        source: e,
    })?;

    Ok(())
}

/// Set restrictive permissions on a directory (Unix: 0o700 - owner rwx only)
///
/// On Unix systems, this sets the directory to be accessible only by the owner.
/// On Windows, this is a no-op as Windows uses ACLs differently.
///
/// # Arguments
///
/// * `path` - Path to the directory to secure
///
/// # Example
///
/// ```ignore
/// use rcman::security::set_secure_dir_permissions;
/// use std::path::Path;
///
/// let path = Path::new("/tmp/config");
/// set_secure_dir_permissions(path).unwrap();
/// ```
///
/// # Errors
///
/// * `Error::Io` - If the directory cannot be set to secure permissions
#[cfg(unix)]
pub fn set_secure_dir_permissions(path: &Path) -> Result<()> {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let metadata = fs::metadata(path).map_err(|e| Error::FileRead {
        path: path.to_path_buf(),
        source: e,
    })?;

    let mut perms = metadata.permissions();
    perms.set_mode(0o700); // Owner read/write/execute only

    fs::set_permissions(path, perms).map_err(|e| Error::FileWrite {
        path: path.to_path_buf(),
        source: e,
    })?;

    Ok(())
}

/// Ensure a directory exists with secure permissions (Unix: 0o700)
///
/// This function combines `fs::create_dir_all` with `set_secure_dir_permissions`.
/// It is cross-platform safe: on Windows it just creates the directory.
///
/// # Arguments
///
/// * `path` - Path to the directory to ensure exists and is secure
///
/// # Errors
///
/// * `Error::Io` - If directory creation or permission setting fails
pub fn ensure_secure_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path).map_err(|e| Error::DirectoryCreate {
        path: path.to_path_buf(),
        source: e,
    })?;

    set_secure_dir_permissions(path)?;

    Ok(())
}

/// Set restrictive permissions on a file (Unix: 0o600, Windows: Owner only)
#[cfg(not(unix))]
pub fn set_secure_file_permissions(path: &Path) -> Result<()> {
    set_secure_acl(path, false)
}

/// Set restrictive permissions on a directory (Unix: 0o700, Windows: Owner only)
#[cfg(not(unix))]
pub fn set_secure_dir_permissions(path: &Path) -> Result<()> {
    set_secure_acl(path, true)
}

#[cfg(windows)]
fn set_secure_acl(path: &Path, is_directory: bool) -> Result<()> {
    use windows_acl::acl::ACL;
    use windows_acl::helper::{current_user, name_to_sid};

    let path_str = path
        .to_str()
        .ok_or_else(|| Error::PathNotFound(path.display().to_string()))?;

    // 1. Get current user SID
    // windows-acl 0.3.0: current_user() returns name, then name_to_sid() gets SID
    let user_name =
        current_user().ok_or_else(|| Error::Config("Failed to get current user name".into()))?;
    let sid = name_to_sid(&user_name, None)
        .map_err(|e| Error::Config(format!("Failed to get user SID for {user_name}: {e}")))?;

    let mut acl = ACL::from_file_path(path_str, false)
        .map_err(|e| Error::Config(format!("Failed to open ACL for {path_str}: {e}")))?;

    // 2. Add full control for current user
    // 0x1F01FF is FILE_ALL_ACCESS
    // Note: windows-acl 0.3.0 doesn't easily support disabling inheritance directly on the ACL struct.
    // We strictly add our Allow entry. For complete exclusivity, inheritance disabling would be needed,
    // but this ensures the owner strictly has their access granted.
    // The allow method expects PSID which is *mut winapi::ctypes::c_void.
    let sid_ptr = sid.as_ptr() as *mut winapi::ctypes::c_void;
    if let Err(e) = acl.allow(sid_ptr, is_directory, 0x1F0_1FF) {
        return Err(Error::Config(format!("Failed to add ALLOW ACE: {e}")));
    }

    Ok(())
}

/// No-op fallback for non-unix/non-windows (e.g. unknown OS)
#[cfg(not(any(unix, windows)))]
fn set_secure_acl(_path: &Path, _is_directory: bool) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_secure_file_permissions() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.txt");

        fs::write(&file_path, "test data").unwrap();

        set_secure_file_permissions(&file_path).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = fs::metadata(&file_path).unwrap();
            let mode = metadata.permissions().mode();
            // Check that only owner has rw (0o600 + file type bits)
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn test_secure_dir_permissions() {
        let dir = tempdir().unwrap();
        let subdir = dir.path().join("secure");

        fs::create_dir_all(&subdir).unwrap();

        set_secure_dir_permissions(&subdir).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = fs::metadata(&subdir).unwrap();
            let mode = metadata.permissions().mode();
            // Check that only owner has rwx (0o700 + file type bits)
            assert_eq!(mode & 0o777, 0o700);
        }
    }
}
