//! 隔离区：把可疑的文件、目录或扩展挪进 ~/.tsuba/quarantine，可以恢复或彻底删除。
//!
//! 只是挪走，不改内容：用户确认是误报时能原样放回。

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

/// 挪动；跨磁盘（外接硬盘上的文件）不能直接改名，退回到复制后删除。
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

/// 把一个文件或目录挪进隔离区。
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

/// 放回原处。原位置已经有同名文件时拒绝，避免覆盖。
pub fn restore(id: &str) -> Result<(), String> {
    let mut list = load();
    let i = list.iter().position(|q| q.id == id).ok_or("隔离区里没有这一项")?;
    let item = &list[i];
    let original = Path::new(&item.original);
    if original.exists() {
        return Err(format!("{} 已经存在，没有覆盖", item.original));
    }
    if let Some(parent) = original.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    move_path(Path::new(&item.stored), original).map_err(|e| e.to_string())?;
    list.remove(i);
    save(&list);
    Ok(())
}

/// 彻底删除隔离区里的一项。
pub fn delete(id: &str) -> Result<(), String> {
    let mut list = load();
    let i = list.iter().position(|q| q.id == id).ok_or("隔离区里没有这一项")?;
    let stored = Path::new(&list[i].stored);
    if stored.exists() {
        remove(stored).map_err(|e| e.to_string())?;
    }
    list.remove(i);
    save(&list);
    Ok(())
}

/// 用户在检查记录里点了“删除文件”：不进隔离区，直接删掉。
///
/// 删除来自记录标题里的路径，而记录可能是扫描整个文件夹留下的（比如 ~/Downloads）。
/// 所以只允许删具体的文件或项目，家目录本身、家目录下的一级目录和系统目录一律拒绝。
pub fn delete_path(path: &Path) -> Result<(), String> {
    if !is_safe_to_delete(path, &crate::home_dir()) {
        return Err(format!("{} 是系统或个人的顶层目录，Tsuba 不会删除它。请在 Finder 里自己处理。", path.display()));
    }
    if std::fs::symlink_metadata(path).is_err() {
        return Err("文件已经不在了，可能已被移动或删除".into());
    }
    remove(path).map_err(|e| format!("删除失败：{e}"))
}

fn is_safe_to_delete(path: &Path, home: &Path) -> bool {
    const SYSTEM_ROOTS: [&str; 7] = ["/System", "/usr", "/bin", "/sbin", "/private", "/etc", "/Library"];
    if !path.is_absolute() || path.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
        return false;
    }
    if SYSTEM_ROOTS.iter().any(|r| path.starts_with(r)) || home.starts_with(path) {
        return false;
    }
    // ~/Downloads、~/code 这类一级目录是用户自己的地盘，误点一下的代价太大
    if path.parent() == Some(home) {
        return false;
    }
    // /Applications、/Volumes 这样的顶层目录也不行，但里面的 Zeff.app 可以
    path.components().count() >= 3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_top_level_and_system_paths() {
        let home = Path::new("/Users/alice");
        for p in ["/", "/Users", "/Users/alice", "/Users/alice/Downloads", "/Applications", "/System/Library/x", "/usr/local/bin/node", "relative/x", "/Users/alice/Downloads/../.ssh"] {
            assert!(!is_safe_to_delete(Path::new(p), home), "{p} 不应该允许删除");
        }
    }

    #[test]
    fn allows_concrete_files_and_projects() {
        let home = Path::new("/Users/alice");
        for p in ["/Users/alice/Downloads/Zeff.dmg", "/Users/alice/code/interview-task", "/Applications/Zeff.app", "/Users/alice/.vscode/extensions/evil-1.0.0"] {
            assert!(is_safe_to_delete(Path::new(p), home), "{p} 应该允许删除");
        }
    }
}
