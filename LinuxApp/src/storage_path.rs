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
                if !normalized.pop() && !path.is_absolute() {
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
pub fn path(relative: impl AsRef<Path>) -> io::Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(missing_home_error)?;
    // Resolve the trusted home directory first. This accepts legitimate HOME
    // values containing ".." and avoids treating a symlinked home alias as an
    // untrusted storage-path component.
    let home = std::fs::canonicalize(home)?;
    resolve_from_home(Some(home), relative.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn rejects_parent_components_in_the_untrusted_relative_path() {
        let home = PathBuf::from("/home/alice");
        let err = resolve_from_home(Some(home), Path::new("../outside/hosts.json")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_storage_ancestors() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!("skerry-path-test-{}", uuid::Uuid::new_v4()));
        let outside = root.join("outside");
        let link = root.join("linked");
        std::fs::create_dir_all(&outside).unwrap();
        symlink(&outside, &link).unwrap();

        let err = validate_storage_path(&link.join("hosts.json")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        std::fs::remove_dir_all(root).unwrap();
    }
}
