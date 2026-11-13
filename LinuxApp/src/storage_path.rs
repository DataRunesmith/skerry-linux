//! Central contract for LinuxApp persistent storage paths.
//!
//! All app-owned persistent files remain below `~/.skerry`. Path
//! resolution is fallible: a process without a resolvable home directory
//! must receive an actionable error instead of terminating.

use std::io;
use std::path::{Path, PathBuf};

const SKERRY_DIR: &str = ".skerry";

fn missing_home_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        "Skerry kan inte hitta användarens hemkatalog; persistent lagring under ~/.skerry är inte tillgänglig",
    )
}

fn normalize_path(path: &Path) -> io::Result<PathBuf> {
    use std::path::Component;

    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if matches!(normalized.components().next_back(), Some(Component::Normal(_))) {
                    normalized.pop();
                } else if !path.is_absolute() {
                    normalized.push("..");
                }
            }
            Component::Normal(part) => normalized.push(part),
        }
    }
    Ok(normalized)
}

fn resolve_from_home(home: Option<PathBuf>, relative: &Path) -> io::Result<PathBuf> {
    use std::path::Component;

    let home = home.ok_or_else(missing_home_error)?;
    if relative.is_absolute()
        || relative.components().any(|component| {
            matches!(component, Component::ParentDir | Component::RootDir | Component::Prefix(_))
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "storage path must be relative and must not contain parent components",
        ));
    }

    let home = normalize_path(&home)?;
    normalize_path(&home.join(SKERRY_DIR).join(relative))
}

/// Reject parent traversal and every existing symlink component in a storage path.
///
/// The path may not exist yet; existing ancestors are still checked. The caller
/// must run this before reads and both before and after creating parent directories.
pub fn validate_storage_path(path: &Path) -> io::Result<()> {
    use std::path::Component;

    if path.components().any(|component| component == Component::ParentDir) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("storage path contains a parent-directory component: {}", path.display()),
        ));
    }

    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let absolute = normalize_path(&absolute)?;
    let mut current = PathBuf::new();

    for component in absolute.components() {
        current.push(component.as_os_str());
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("storage path traverses a symbolic link: {}", current.display()),
                ));
            }
            Ok(metadata) if current != absolute && !metadata.is_dir() => {
                return Err(io::Error::new(
                    io::ErrorKind::NotADirectory,
                    format!("storage path parent is not a directory: {}", current.display()),
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Resolve a path below `~/.skerry` without creating anything.
///
/// The result is validated, so every store that obtains its file through this
/// resolver rejects symlinked storage files and symlinked ancestors.
pub fn path(relative: impl AsRef<Path>) -> io::Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(missing_home_error)?;
    // Canonicalize the original HOME first: the kernel resolves symlinks and
    // ".." in the right order. Normalizing lexically beforehand could change
    // which directory a "symlink/.." HOME refers to.
    let home = std::fs::canonicalize(home)?;
    let resolved = resolve_from_home(Some(home), relative.as_ref())?;
    validate_storage_path(&resolved)?;
    Ok(resolved)
}

/// Directory-handle based file access. Every component is opened with
/// `O_NOFOLLOW` relative to the previous handle, and the final file operation
/// is performed relative to the last handle, so a parent swapped for a symlink
/// after validation cannot redirect the operation.
#[cfg(unix)]
mod anchored {
    use std::ffi::CString;
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Component, Path};

    fn cstr(bytes: &[u8]) -> io::Result<CString> {
        CString::new(bytes)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))
    }

    fn map_errno(error: io::Error) -> io::Error {
        match error.raw_os_error() {
            Some(libc::ELOOP) | Some(libc::ENOTDIR) => io::Error::new(
                io::ErrorKind::InvalidInput,
                "storage path traverses a symbolic link or non-directory",
            ),
            _ => error,
        }
    }

    fn openat(dir: libc::c_int, name: &CString, flags: libc::c_int, mode: libc::mode_t) -> io::Result<OwnedFd> {
        // SAFETY: `name` is a valid NUL-terminated string; the fd is owned on success.
        let fd = unsafe { libc::openat(dir, name.as_ptr(), flags | libc::O_CLOEXEC, mode as libc::c_uint) };
        if fd < 0 {
            Err(map_errno(io::Error::last_os_error()))
        } else {
            Ok(unsafe { OwnedFd::from_raw_fd(fd) })
        }
    }

    /// Open (and optionally create, mode 0700) the directory at the absolute
    /// `path` without following any symlink.
    pub fn open_dir(path: &Path, create: bool) -> io::Result<OwnedFd> {
        if !path.is_absolute() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "storage path must be absolute"));
        }
        let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW;
        let mut current = openat(libc::AT_FDCWD, &cstr(b"/")?, flags, 0)?;
        for component in path.components() {
            let name = match component {
                Component::RootDir => continue,
                Component::Normal(name) => cstr(name.as_bytes())?,
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "storage path must be normalized and absolute",
                    ))
                }
            };
            let next = match openat(current.as_raw_fd(), &name, flags, 0) {
                Err(e) if create && e.kind() == io::ErrorKind::NotFound => {
                    // SAFETY: valid dir fd and NUL-terminated name.
                    let rc = unsafe { libc::mkdirat(current.as_raw_fd(), name.as_ptr(), 0o700) };
                    if rc < 0 && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists {
                        return Err(io::Error::last_os_error());
                    }
                    openat(current.as_raw_fd(), &name, flags, 0)?
                }
                other => other?,
            };
            current = next;
        }
        Ok(current)
    }

    fn split(path: &Path) -> io::Result<(&Path, CString)> {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent directory"))?;
        let name = path
            .file_name()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
        Ok((parent, cstr(name.as_bytes())?))
    }

    pub fn read(path: &Path) -> io::Result<String> {
        use std::io::Read as _;
        let (parent, name) = split(path)?;
        let dir = open_dir(parent, false)?;
        let fd = openat(dir.as_raw_fd(), &name, libc::O_RDONLY | libc::O_NOFOLLOW, 0)?;
        let mut contents = String::new();
        std::fs::File::from(fd).read_to_string(&mut contents)?;
        Ok(contents)
    }

    pub fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
        use std::io::Write as _;
        let (parent, name) = split(path)?;
        let dir = open_dir(parent, true)?;
        // SAFETY: valid dir fd; fchmod acts on the handle, not on a path.
        if unsafe { libc::fchmod(dir.as_raw_fd(), 0o700) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let tmp = cstr(
            format!(".{}.tmp.{}", name.to_string_lossy(), uuid::Uuid::new_v4()).as_bytes(),
        )?;
        let fd = openat(
            dir.as_raw_fd(),
            &tmp,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
            0o600,
        )?;
        let mut file = std::fs::File::from(fd);
        let result = file.write_all(data).and_then(|_| file.sync_all()).and_then(|_| {
            // SAFETY: both names are relative to the same valid dir fd.
            let rc = unsafe { libc::renameat(dir.as_raw_fd(), tmp.as_ptr(), dir.as_raw_fd(), name.as_ptr()) };
            if rc < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
        });
        if result.is_err() {
            // SAFETY: valid dir fd and name; failure to clean up is ignored.
            unsafe { libc::unlinkat(dir.as_raw_fd(), tmp.as_ptr(), 0) };
        }
        result
    }
}

/// Read a storage file without re-resolving its parents or following links.
pub fn read_file(path: &Path) -> io::Result<String> {
    validate_storage_path(path)?;
    #[cfg(unix)]
    return anchored::read(path);
    #[cfg(not(unix))]
    return std::fs::read_to_string(path);
}

/// Atomically write a storage file, creating its directory with mode 0700.
pub fn write_file_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    validate_storage_path(path)?;
    #[cfg(unix)]
    return anchored::write_atomic(path, data);
    #[cfg(not(unix))]
    return {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        crate::fsutil::atomic_write(path, data)
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `TMPDIR` may itself be a symlink; fixtures must start below its target.
    fn canonical_temp() -> PathBuf {
        std::fs::canonicalize(std::env::temp_dir()).unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn anchored_write_creates_private_dir_and_round_trips() {
        let root = canonical_temp().join(format!("skerry-anchored-{}", uuid::Uuid::new_v4()));
        let file = root.join("a").join("hosts.json");
        write_file_atomic(&file, b"hej").unwrap();
        assert_eq!(read_file(&file).unwrap(), "hej");
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(file.parent().unwrap()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn anchored_open_rejects_a_symlinked_parent_even_without_prior_validation() {
        use std::os::unix::fs::symlink;
        let root = canonical_temp().join(format!("skerry-anchored-{}", uuid::Uuid::new_v4()));
        let outside = root.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        symlink(&outside, root.join("linked")).unwrap();
        // Bypasses validate_storage_path: simulates a swap after validation.
        let err = anchored::write_atomic(&root.join("linked").join("hosts.json"), b"x").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(!outside.join("hosts.json").exists());
        let err = anchored::read(&root.join("linked").join("hosts.json")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn resolves_existing_storage_layout_from_home() {
        let home = PathBuf::from("/home/example");
        let resolved = resolve_from_home(Some(home), Path::new("hosts.json")).unwrap();
        assert_eq!(resolved, PathBuf::from("/home/example/.skerry/hosts.json"));
    }

    #[test]
    fn missing_home_is_an_actionable_error() {
        let err = resolve_from_home(None, Path::new("hosts.json")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(err.to_string().contains("hemkatalog"));
        assert!(err.to_string().contains("~/.skerry"));
    }

    #[test]
    fn nested_paths_keep_the_existing_layout() {
        let home = PathBuf::from("/home/example");
        let resolved = resolve_from_home(Some(home), Path::new("keys/id")).unwrap();
        assert_eq!(resolved, PathBuf::from("/home/example/.skerry/keys/id"));
    }

    #[test]
    fn normalizes_parent_components_in_the_trusted_home_path() {
        let home = PathBuf::from("/home/alice/../alice");
        let resolved = resolve_from_home(Some(home), Path::new("hosts.json")).unwrap();
        assert_eq!(resolved, PathBuf::from("/home/alice/.skerry/hosts.json"));
    }

    #[test]
    fn preserves_unresolved_parents_in_relative_paths() {
        for (input, expected) in [
            ("../..", "../.."),
            ("../../foo", "../../foo"),
            ("../foo/../../bar", "../../bar"),
            ("foo/../../bar", "../bar"),
            ("foo/../bar", "bar"),
        ] {
            assert_eq!(normalize_path(Path::new(input)).unwrap(), PathBuf::from(expected), "{input}");
        }
    }

    #[test]
    fn absolute_paths_cannot_traverse_above_root() {
        for (input, expected) in [("/../..", "/"), ("/foo/../../../bar", "/bar")] {
            assert_eq!(normalize_path(Path::new(input)).unwrap(), PathBuf::from(expected), "{input}");
        }
    }

    #[test]
    fn rejects_parent_components_in_the_untrusted_relative_path() {
        let home = PathBuf::from("/home/alice");
        let err = resolve_from_home(Some(home), Path::new("../outside/hosts.json")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_storage_ancestors() {
        use std::os::unix::fs::symlink;

        let root = canonical_temp().join(format!("skerry-path-test-{}", uuid::Uuid::new_v4()));
        let outside = root.join("outside");
        let link = root.join("linked");
        std::fs::create_dir_all(&outside).unwrap();
        symlink(&outside, &link).unwrap();

        let err = validate_storage_path(&link.join("hosts.json")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        std::fs::remove_dir_all(root).unwrap();
    }
}
