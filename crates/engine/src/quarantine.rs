//! Quarantine: moves suspicious files, folders or extensions into ~/.tsuba/quarantine, from where they can be restored or deleted.
//!
//! Items are only moved, never changed, so a false positive can be put back exactly as it was.

use crate::store;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::Path;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QuarantineItem {
    pub id: String,
    pub original: String,
    pub stored: String,
    pub time: String,
    pub reason: String,
}

fn load() -> Vec<QuarantineItem> {
    serde_json::from_value(store::load_json("quarantine.json")).unwrap_or_default()
}

fn save(list: &[QuarantineItem]) {
    store::save_json("quarantine.json", &json!(list));
}

pub fn list() -> Vec<QuarantineItem> {
    load()
}

/// Moves a path. Across disks (files on an external drive) a rename fails, so fall back to copy and delete.
fn move_path(from: &Path, to: &Path) -> std::io::Result<()> {
    match std::fs::rename(from, to) {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(libc::EXDEV) => {
            copy_recursive(from, to)?;
            remove(from)
        }
        Err(e) => Err(e),
    }
}

fn copy_recursive(from: &Path, to: &Path) -> std::io::Result<()> {
    let meta = std::fs::symlink_metadata(from)?;
    if meta.is_dir() {
        std::fs::create_dir_all(to)?;
        for entry in std::fs::read_dir(from)?.flatten() {
            copy_recursive(&entry.path(), &to.join(entry.file_name()))?;
        }
    } else if meta.file_type().is_symlink() {
        std::os::unix::fs::symlink(std::fs::read_link(from)?, to)?;
    } else {
        std::fs::copy(from, to)?;
    }
    Ok(())
}

fn remove(p: &Path) -> std::io::Result<()> {
    if std::fs::symlink_metadata(p)?.is_dir() { std::fs::remove_dir_all(p) } else { std::fs::remove_file(p) }
}

/// Moves a file or folder into quarantine.
pub fn quarantine(path: &Path, reason: &str) -> std::io::Result<QuarantineItem> {
    let qdir = store::home().join("quarantine");
    std::fs::create_dir_all(&qdir)?;
    let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "item".into());
    let id = format!("{}-{name}", chrono::Utc::now().timestamp_millis());
    let stored = qdir.join(&id);
    move_path(path, &stored)?;
    let item = QuarantineItem {
        id,
        original: path.to_string_lossy().to_string(),
        stored: stored.to_string_lossy().to_string(),
        time: store::now(),
        reason: reason.to_string(),
    };
    let mut list = load();
    list.push(item.clone());
    save(&list);
    Ok(item)
}

/// Puts an item back. Refuses when something already exists at the original path, to avoid overwriting it.
pub fn restore(id: &str) -> Result<(), String> {
    let mut list = load();
    let i = list.iter().position(|q| q.id == id).ok_or_else(|| tr!("This item is no longer in quarantine"))?;
    let item = &list[i];
    let original = Path::new(&item.original);
    if original.exists() {
        return Err(tr!("{path} already exists, so it wasn't overwritten", path = item.original));
    }
    if let Some(parent) = original.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    move_path(Path::new(&item.stored), original).map_err(|e| e.to_string())?;
    list.remove(i);
    save(&list);
    Ok(())
}

/// Permanently deletes an item from quarantine.
pub fn delete(id: &str) -> Result<(), String> {
    let mut list = load();
    let i = list.iter().position(|q| q.id == id).ok_or_else(|| tr!("This item is no longer in quarantine"))?;
    let stored = Path::new(&list[i].stored);
    if stored.exists() {
        remove(stored).map_err(|e| e.to_string())?;
    }
    list.remove(i);
    save(&list);
    Ok(())
}

/// The user clicked "Delete File" on a check record: delete it directly, without quarantine.
///
/// The path comes from the record title, and a record may come from scanning a whole folder (like ~/Downloads).
/// So only concrete files or projects may be deleted; the home folder itself, its top-level folders and system folders are always refused.
pub fn delete_path(path: &Path) -> Result<(), String> {
    if !is_safe_to_delete(path, &crate::home_dir()) {
        return Err(tr!("{path} is a top-level system or personal folder, so Tsuba won't delete it. Handle it yourself in Finder.", path = path.display()));
    }
    if std::fs::symlink_metadata(path).is_err() {
        return Err(tr!("The file is no longer there; it may have been moved or deleted"));
    }
    remove(path).map_err(|e| tr!("Couldn't delete it: {error}", error = e))
}

fn is_safe_to_delete(path: &Path, home: &Path) -> bool {
    const SYSTEM_ROOTS: [&str; 7] = ["/System", "/usr", "/bin", "/sbin", "/private", "/etc", "/Library"];
    if !path.is_absolute() || path.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
        return false;
    }
    if SYSTEM_ROOTS.iter().any(|r| path.starts_with(r)) || home.starts_with(path) {
        return false;
    }
    // Top-level folders like ~/Downloads and ~/code are the user's own space; one misclick would cost too much
    if path.parent() == Some(home) {
        return false;
    }
    // Top-level folders like /Applications and /Volumes are refused too, but a Zeff.app inside them is fine
    path.components().count() >= 3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_top_level_and_system_paths() {
        let home = Path::new("/Users/alice");
        for p in ["/", "/Users", "/Users/alice", "/Users/alice/Downloads", "/Applications", "/System/Library/x", "/usr/local/bin/node", "relative/x", "/Users/alice/Downloads/../.ssh"] {
            assert!(!is_safe_to_delete(Path::new(p), home), "{p} must not be deletable");
        }
    }

    #[test]
    fn allows_concrete_files_and_projects() {
        let home = Path::new("/Users/alice");
        for p in ["/Users/alice/Downloads/Zeff.dmg", "/Users/alice/code/interview-task", "/Applications/Zeff.app", "/Users/alice/.vscode/extensions/evil-1.0.0"] {
            assert!(is_safe_to_delete(Path::new(p), home), "{p} should be deletable");
        }
    }
}
