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
