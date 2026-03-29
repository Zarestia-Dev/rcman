use crate::error::{Error, Result};
use std::path::Path;

#[cfg(unix)]
/// Set permission bits so directories are owner read-write-execute only.
///
/// # Errors
///
/// Returns `Error::FileRead` if metadata lookup fails, or `Error::FileWrite` if setting permissions fails.
pub fn set_secure_dir_permissions(path: &Path) -> Result<()> {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let mut perms = fs::metadata(path)
        .map_err(|e| Error::FileRead {
            path: path.to_path_buf(),
            source: e,
        })?
        .permissions();

    perms.set_mode(0o700);

    fs::set_permissions(path, perms).map_err(|e| Error::FileWrite {
        path: path.to_path_buf(),
        source: e,
    })
}

// On non-Unix platforms, set permissions using ACLs to grant access only to the current user
/// Ensure the directory exists and has secure permissions for the current user only.
///
/// # Errors
///
/// Returns `Error::DirectoryCreate` if directory creation fails, or any error returned
/// by `set_secure_dir_permissions`.
pub fn ensure_secure_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path).map_err(|e| Error::DirectoryCreate {
        path: path.to_path_buf(),
        source: e,
    })?;
    set_secure_dir_permissions(path)
}

#[cfg(unix)]
/// Set permission bits so files are owner read-write only.
///
/// # Errors
///
/// Returns `Error::FileRead` if metadata lookup fails, or `Error::FileWrite` if setting permissions fails.
pub fn set_secure_file_permissions(path: &Path) -> Result<()> {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let mut perms = fs::metadata(path)
        .map_err(|e| Error::FileRead {
            path: path.to_path_buf(),
            source: e,
        })?
        .permissions();

    perms.set_mode(0o600);

    fs::set_permissions(path, perms).map_err(|e| Error::FileWrite {
        path: path.to_path_buf(),
        source: e,
    })
}

#[cfg(not(unix))]
/// Set ACL-based permissions on files for non-Unix platforms.
///
/// # Errors
///
/// Returns an `Error` if the ACL update fails.
pub fn set_secure_file_permissions(path: &Path) -> Result<()> {
    set_secure_acl(path)
}

#[cfg(not(unix))]
/// Set ACL-based permissions on directories for non-Unix platforms.
///
/// # Errors
///
/// Returns an `Error` if the ACL update fails.
pub fn set_secure_dir_permissions(path: &Path) -> Result<()> {
    set_secure_acl(path)
}

#[cfg(windows)]
fn set_secure_acl(path: &Path) -> Result<()> {
    use std::mem::MaybeUninit;
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::{
        EXPLICIT_ACCESS_W, SE_FILE_OBJECT, SET_ACCESS, SetEntriesInAclW, SetNamedSecurityInfoW,
        TRUSTEE_IS_SID, TRUSTEE_W,
    };
    use windows::Win32::Security::{
        ACL, DACL_SECURITY_INFORMATION, NO_INHERITANCE, PROTECTED_DACL_SECURITY_INFORMATION,
    };
    use windows::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows::core::PWSTR;

    let mut path_wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();

    // 1. Open process token
    let mut token = HANDLE::default();
    // SAFETY: GetCurrentProcess() always returns a valid pseudo-handle
    unsafe {
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token)
            .map_err(|e| Error::Config(format!("OpenProcessToken failed: {e}")))?;
    }

    // 2. Get TOKEN_USER buffer
    let token_user_buf = {
        let mut needed = 0u32;
        // SAFETY: null buffer intentionally passed to query required size
        unsafe {
            let _ = GetTokenInformation(token, TokenUser, None, 0, &raw mut needed);
        }

        let mut buf = vec![0u8; needed as usize];
        // SAFETY: buf is sized from the query above
        unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                Some(buf.as_mut_ptr().cast()),
                needed,
                &raw mut needed,
            )
            .map_err(|e| {
                let _ = CloseHandle(token);
                Error::Config(format!("GetTokenInformation failed: {e}"))
            })?;
        }
        buf
    };

    // SAFETY: buf was filled by GetTokenInformation, copy to aligned stack repr before field access.
    let user_sid = unsafe {
        let mut token_user = MaybeUninit::<TOKEN_USER>::uninit();
        std::ptr::copy_nonoverlapping(
            token_user_buf.as_ptr(),
            token_user.as_mut_ptr().cast::<u8>(),
            std::mem::size_of::<TOKEN_USER>(),
        );

        let token_user = token_user.assume_init();
        token_user.User.Sid
    };

    // SAFETY: token is valid and we're done with it
    unsafe {
        let _ = CloseHandle(token);
    }

    // 3. Build DACL
    let access = EXPLICIT_ACCESS_W {
        grfAccessPermissions: 0x001F_01FF, // FILE_ALL_ACCESS
        grfAccessMode: SET_ACCESS,
        grfInheritance: NO_INHERITANCE,
        Trustee: TRUSTEE_W {
            TrusteeForm: TRUSTEE_IS_SID,
            ptstrName: PWSTR(user_sid.0.cast::<u16>()),
            ..Default::default()
        },
    };

    let mut acl: *mut ACL = std::ptr::null_mut();
    // SAFETY: access entry is well-formed
    unsafe {
        SetEntriesInAclW(Some(&[access]), None, &raw mut acl)
            .ok()
            .map_err(|e| Error::Config(format!("SetEntriesInAclW failed: {e:?}")))?;
    }

    // 4. Apply DACL
    // SAFETY: path_wide is null-terminated UTF-16, acl is valid
    let result = unsafe {
        SetNamedSecurityInfoW(
            PWSTR(path_wide.as_mut_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(acl),
            None,
        )
    };

    // SAFETY: acl was allocated by SetEntriesInAclW
    unsafe {
        let _ = LocalFree(Some(HLOCAL(acl.cast())));
    }

    result
        .ok()
        .map_err(|e| Error::Config(format!("SetNamedSecurityInfoW failed: {e:?}")))
}

#[cfg(not(any(unix, windows)))]
fn set_secure_acl(_path: &Path) -> Result<()> {
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
        let path = dir.path().join("test.txt");
        fs::write(&path, "test").unwrap();
        set_secure_file_permissions(&path).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn test_secure_dir_permissions() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("secure");
        fs::create_dir_all(&path).unwrap();
        set_secure_dir_permissions(&path).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
    }
}
