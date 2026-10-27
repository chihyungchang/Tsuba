//! 后台监控：下载目录里新出现的安装包、编辑器扩展目录里新装或更新的扩展。

use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::{AppHandle, Emitter};
use tsuba_engine::rules::Verdict;
use tsuba_engine::store::{self, Config, LogEntry};
use tsuba_engine::{extension, home_dir};

const DOWNLOAD_EXT: &[&str] = &["dmg", "pkg", "mpkg", "vsix"];

pub struct Watchers {
    _watchers: Vec<RecommendedWatcher>,
}

/// 记住已经见过的文件和扩展，App 重启后不重复检查。
#[derive(Clone, Default)]
struct Seen(Arc<Mutex<HashSet<String>>>);

impl Seen {
    fn load() -> Seen {
        let v = store::load_json("seen.json");
        let set: HashSet<String> = v.as_array().map(|a| a.iter().filter_map(|s| s.as_str().map(String::from)).collect()).unwrap_or_default();
        Seen(Arc::new(Mutex::new(set)))
    }

    /// 第一次见到返回 true。
    fn insert(&self, key: &str) -> bool {
        let mut set = self.0.lock().unwrap();
        let fresh = set.insert(key.to_string());
        if fresh {
            store::save_json("seen.json", &json!(set.iter().collect::<Vec<_>>()));
        }
        fresh
    }

    fn contains(&self, key: &str) -> bool {
        self.0.lock().unwrap().contains(key)
    }
}

pub fn downloads_dir() -> PathBuf {
    home_dir().join("Downloads")
}

fn paused() -> bool {
    store::home().join("paused").exists()
}

/// 用 macOS 系统通知提醒。
fn notify_user(title: &str, body: &str) {
    let esc = |s: &str| s.replace('\\', "\\\\").replace('"', "'");
    let body: String = body.chars().take(240).collect();
    let script = format!("display notification \"{}\" with title \"{}\"", esc(&body), esc(title));
    let _ = std::process::Command::new("osascript").args(["-e", &script]).output();
}

fn report_entry(app: &AppHandle, mut entry: LogEntry) {
    let r = &entry.report;
    let name = Path::new(&entry.title).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| entry.title.clone());
    match r.verdict {
        Verdict::Allow => entry.action = "allowed".into(),
        Verdict::Warn | Verdict::Block => {
            let what = if entry.action == "quarantined" { "已移入隔离区" } else { "先不要打开它" };
            let label = if r.verdict == Verdict::Block { "建议拦截" } else { "需要注意" };
            notify_user(&format!("Tsuba：{name} {label}"), &format!("{} {what}。", r.summary));
            if entry.action.is_empty() {
                entry.action = "notified".into();
            }
        }
    }
    store::append_log(&entry);
    let _ = app.emit("history-updated", ());
    if entry.report.verdict == Verdict::Block {
        crate::show_window(app);
        let _ = app.emit("focus-entry", entry.id.clone());
    }
}

/// 等文件写完（大小连续两次不变）。浏览器下载大文件可能要几分钟。
fn wait_stable(p: &Path) -> bool {
    let mut last = u64::MAX;
    for _ in 0..300 {
        let size = std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
        if size > 0 && size == last {
            return true;
        }
        last = size;
        std::thread::sleep(Duration::from_secs(2));
    }
    false
}

fn on_download(app: AppHandle, cfg: Arc<Mutex<Config>>, seen: Seen, p: PathBuf) {
    let ext = p.extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default();
    if !DOWNLOAD_EXT.contains(&ext.as_str()) || p.parent() != Some(downloads_dir().as_path()) {
        return;
    }
    let key = format!("download:{}", p.display());
    if !p.is_file() || !seen.insert(&key) {
        return;
    }
    std::thread::spawn(move || {
        if !wait_stable(&p) || paused() {
            return;
        }
        let cfg = cfg.lock().unwrap().clone();
        let (_, _, report) = tsuba_engine::evaluate_path(&cfg, &p);
        report_entry(&app, LogEntry::new("download", &p.to_string_lossy(), "", report));
    });
}

fn on_extension(app: AppHandle, cfg: Arc<Mutex<Config>>, seen: Seen, root: PathBuf, p: PathBuf) {
    if p.parent() != Some(root.as_path()) {
        return;
    }
    let key = format!("extension:{}", p.display());
    if seen.contains(&key) {
        return;
    }
    std::thread::spawn(move || {
        // 编辑器解压扩展需要几秒，等它写完 package.json
        std::thread::sleep(Duration::from_secs(4));
        if !extension::is_extension_dir(&p) || !seen.insert(&key) || paused() {
            return;
        }
        let cfg = cfg.lock().unwrap().clone();
        let (_, report) = tsuba_engine::evaluate_extension(&cfg, &p);
        let mut entry = LogEntry::new("extension", &p.to_string_lossy(), "", report);
        if entry.report.verdict == Verdict::Block && cfg.auto_quarantine
            && let Ok(item) = extension::quarantine(&p, &entry.report.summary) {
                entry.action = "quarantined".into();
                entry.quarantine_id = Some(item.id);
            }
        report_entry(&app, entry);
    });
}

/// 第一次运行时，把已有的文件和扩展记为“见过”，只检查之后新出现的。
/// 已装扩展可以在“体检”里手动扫描。
fn baseline(seen: &Seen) {
    if store::home().join("seen.json").exists() {
        return;
    }
    if let Ok(rd) = std::fs::read_dir(downloads_dir()) {
        for e in rd.flatten() {
            seen.insert(&format!("download:{}", e.path().display()));
        }
    }
    for root in extension::extension_dirs() {
        if let Ok(rd) = std::fs::read_dir(&root) {
            for e in rd.flatten() {
                seen.insert(&format!("extension:{}", e.path().display()));
            }
        }
    }
    store::save_json("seen.json", &Value::Array(seen.0.lock().unwrap().iter().map(|s| json!(s)).collect()));
}

pub fn start(app: &AppHandle, cfg: Arc<Mutex<Config>>) -> Watchers {
    let seen = Seen::load();
    baseline(&seen);
    let c = cfg.lock().unwrap().clone();
    let mut watchers = Vec::new();

    if c.watch_downloads {
        let (app2, cfg2, seen2) = (app.clone(), cfg.clone(), seen.clone());
        if let Ok(mut w) = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
            if let Ok(ev) = res {
                for p in ev.paths {
                    on_download(app2.clone(), cfg2.clone(), seen2.clone(), p);
                }
            }
        })
            && w.watch(&downloads_dir(), RecursiveMode::NonRecursive).is_ok() {
                watchers.push(w);
            }
    }

    if c.watch_extensions {
        for root in extension::extension_dirs() {
            let (app2, cfg2, seen2, root2) = (app.clone(), cfg.clone(), seen.clone(), root.clone());
            if let Ok(mut w) = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
                if let Ok(ev) = res {
                    for p in ev.paths {
                        on_extension(app2.clone(), cfg2.clone(), seen2.clone(), root2.clone(), p);
                    }
                }
            })
                && w.watch(&root, RecursiveMode::NonRecursive).is_ok() {
                    watchers.push(w);
                }
        }
    }
    Watchers { _watchers: watchers }
}
