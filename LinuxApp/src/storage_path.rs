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

fn resolve_from_home(home: Option<PathBuf>, relative: &Path) -> io::Result<PathBuf> {
    let home = home.ok_or_else(missing_home_error)?;
    Ok(home.join(SKERRY_DIR).join(relative))
}

/// Resolve a path below `~/.skerry` without creating anything.
pub fn path(relative: impl AsRef<Path>) -> io::Result<PathBuf> {
    resolve_from_home(dirs::home_dir(), relative.as_ref())
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
}
