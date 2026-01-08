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
/// ```no_run
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
        path: path.display().to_string(),
        source: e,
    })?;

    let mut perms = metadata.permissions();
    perms.set_mode(0o600); // Owner read/write only

    fs::set_permissions(path, perms).map_err(|e| Error::FileWrite {
        path: path.display().to_string(),
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
/// ```no_run
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
        path: path.display().to_string(),
        source: e,
    })?;

    let mut perms = metadata.permissions();
    perms.set_mode(0o700); // Owner read/write/execute only

    fs::set_permissions(path, perms).map_err(|e| Error::FileWrite {
        path: path.display().to_string(),
        source: e,
    })?;

    Ok(())
}

/// No-op on Windows (permissions managed via ACLs)
#[cfg(not(unix))]
pub fn set_secure_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

/// No-op on Windows (permissions managed via ACLs)
#[cfg(not(unix))]
pub fn set_secure_dir_permissions(_path: &Path) -> Result<()> {
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
