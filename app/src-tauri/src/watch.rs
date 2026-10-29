//! Background watchers: new installers in Downloads, disk images being opened, and extensions installed or updated
//! in editor extension folders. AI coding tools are watched in watch_ai.rs.

use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::{AppHandle, Emitter};
use tsuba_engine::rules::{self, Verdict};
use tsuba_engine::store::{self, Config, LogEntry};
use tsuba_engine::{extension, home_dir, macos};

const DOWNLOAD_EXT: &[&str] = &["dmg", "pkg", "mpkg", "vsix"];

pub struct Watchers {
    _watchers: Vec<RecommendedWatcher>,
}

/// Files and extensions already seen, so they are not checked again after the App restarts.
#[derive(Clone, Default)]
struct Seen(Arc<Mutex<HashSet<String>>>);

impl Seen {
    fn load() -> Seen {
        let v = store::load_json("seen.json");
        let set: HashSet<String> = v.as_array().map(|a| a.iter().filter_map(|s| s.as_str().map(String::from)).collect()).unwrap_or_default();
        Seen(Arc::new(Mutex::new(set)))
    }

    /// True the first time a key is seen.
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

pub(crate) fn paused() -> bool {
    store::home().join("paused").exists()
}

/// Shows a macOS notification. Callers build the text with `tr!` right before calling, so it is in the language
/// current at send time even when sent from a background watcher.
pub(crate) fn notify_user(title: &str, body: &str) {
    let esc = |s: &str| s.replace('\\', "\\\\").replace('"', "'");
    let body: String = body.chars().take(240).collect();
    let script = format!("display notification \"{}\" with title \"{}\"", esc(&body), esc(title));
    let _ = std::process::Command::new("osascript").args(["-e", &script]).output();
}

fn file_name(p: &str) -> String {
    Path::new(p).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| p.to_string())
}

/// Records a check, notifies when it is risky and brings up the window on Block.
/// `previous` is the earlier verdict of the same record (second phase of a two-phase check); no repeat notification unless it got worse.
pub(crate) fn report_entry(app: &AppHandle, mut entry: LogEntry, previous: Option<Verdict>) {
    let r = &entry.report;
    let name = file_name(&entry.title);
    let escalated = previous.is_none_or(|p| r.verdict > p);
    match r.verdict {
        Verdict::Allow if entry.action.is_empty() => entry.action = "allowed".into(),
        // Warn notifications can be turned off in Settings; the entry still goes to history
        Verdict::Warn if escalated && !Config::load().notify_warn => {}
        Verdict::Warn | Verdict::Block if escalated => {
            let next_step = match entry.action.as_str() {
                "quarantined" => tr!("It has been moved to quarantine."),
                "ejected" => tr!("Tsuba stopped it from opening."),
                _ => tr!("Don't open it yet."),
            };
            let title = if r.verdict == Verdict::Block { tr!("Tsuba: block recommended for {name}", name = name) } else { tr!("Tsuba: {name} needs attention", name = name) };
            notify_user(&title, &format!("{} {next_step}", r.summary));
            if entry.action.is_empty() {
                entry.action = "notified".into();
            }
        }
        _ => {}
    }
    store::append_log(&entry);
    let _ = app.emit("history-updated", ());
    if entry.report.verdict == Verdict::Block && escalated {
        crate::show_window(app);
        let _ = app.emit("focus-entry", entry.id.clone());
    }
}

/// Two-phase check: offline rules decide in under a second and warn right away; the AI's judgment follows and updates the same record.
pub(crate) fn two_phase(app: &AppHandle, cfg: &Config, source: &str, title: &str, check: impl Fn(&Config) -> tsuba_engine::Report) -> Verdict {
    // Phase one uses only local rules and lists, no network, done in under a second
    let offline_cfg = cfg.offline_only();
    let first = LogEntry::new(source, title, "", check(&offline_cfg));
    let offline = first.report.verdict;
    let id = first.id.clone();
    report_entry(app, first, None);
    if !tsuba_engine::judge::available(cfg) && cfg.intel.virustotal_key.is_empty() {
        return offline;
    }
    let mut second = LogEntry::new(source, title, "", check(cfg));
    second.id = id;
    let verdict = second.report.verdict;
    report_entry(app, second, Some(offline));
    verdict
}

/// Waits until the file is fully written: the size stops changing and the browser's temporary file is gone.
/// Chrome and Safari rename to the final name when done; Firefox creates an empty final file first and writes into .part.
fn wait_complete(p: &Path) -> bool {
    let part = |ext: &str| PathBuf::from(format!("{}.{ext}", p.display())).exists();
    let mut last = u64::MAX;
    for _ in 0..6000 {
        let size = std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
        if size > 0 && size == last && !part("part") && !part("crdownload") && !part("download") {
            return true;
        }
        if !p.exists() {
            return false;
        }
        last = size;
        std::thread::sleep(Duration::from_millis(300));
    }
    false
}

/// Disk image → verdict for images already judged. When the user opens one, act on it right away without waiting.
#[derive(Clone, Default)]
struct Verdicts(Arc<Mutex<HashMap<PathBuf, Verdict>>>);

fn on_download(app: AppHandle, cfg: Arc<Mutex<Config>>, seen: Seen, verdicts: Verdicts, p: PathBuf) {
    let ext = p.extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default();
    if !DOWNLOAD_EXT.contains(&ext.as_str()) || p.parent() != Some(downloads_dir().as_path()) {
        return;
    }
    let key = format!("download:{}", p.display());
    if !p.is_file() || !seen.insert(&key) {
        return;
    }
    std::thread::spawn(move || {
        if !wait_complete(&p) || paused() {
            return;
        }
        let cfg = cfg.lock().unwrap().clone();
        let v = two_phase(&app, &cfg, "download", &p.to_string_lossy(), |c| tsuba_engine::evaluate_path(c, &p).2);
        verdicts.0.lock().unwrap().insert(p.clone(), v);
    });
}

/// Ejects a mounted image. A fresh volume may still be held by Finder or Spotlight, so only report success once it is really gone.
fn eject(mount_point: &Path) -> bool {
    for _ in 0..5 {
        macos::run(&["hdiutil", "detach", "-force", &mount_point.to_string_lossy()], 15);
        if !macos::mounted_images().iter().any(|(mp, _)| mp == mount_point) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    false
}

/// The user opened (mounted) a disk image. This is the moment it can really be stopped: if it is high risk,
/// eject it at once, before the user double-clicks anything inside. Offline rules only, done in under a second.
fn on_mount(app: AppHandle, verdicts: Verdicts, mounted: Arc<Mutex<HashSet<PathBuf>>>, p: PathBuf) {
    if p.parent() != Some(Path::new("/Volumes")) {
        return;
    }
    if !p.is_dir() {
        mounted.lock().unwrap().remove(&p);
        return;
    }
    if !mounted.lock().unwrap().insert(p.clone()) {
        return;
    }
    std::thread::spawn(move || {
        // hdiutil takes a moment to register the mount
        let mut image = None;
        for _ in 0..10 {
            image = macos::mounted_images().into_iter().find(|(mp, _)| *mp == p).map(|(_, img)| img);
            if image.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(150));
        }
        // Not a disk image (USB stick, external drive): ignore
        let Some(image) = image else { return };
        if paused() {
            return;
        }
        let label = file_name(&image.to_string_lossy());
        let mut findings = Vec::new();
        macos::inspect_volume(&p, &label, &mut findings);
        let mut verdict = rules::offline_verdict(&findings);
        if verdicts.0.lock().unwrap().get(&image) == Some(&Verdict::Block) {
            verdict = Verdict::Block;
        }
        if verdict == Verdict::Allow {
            return;
        }
        let summary = if verdict == Verdict::Block {
            tr!("{name} has clear signs of a malicious installer. Tsuba ejected it before it could be opened.", name = label)
        } else {
            tr!("{name} looks suspicious. Look at the evidence before opening anything inside.", name = label)
        };
        let mut entry = LogEntry::new(
            "mount",
            &image.to_string_lossy(),
            "",
            tsuba_engine::Report {
                verdict,
                summary,
                reasons: vec![],
                advice: tr!("Don't force open anything in the image from the terminal or the right-click menu. If someone asked you to install it as meeting software or an interview tool, delete it and check with their company."),
                source: "offline".into(),
                model: String::new(),
                findings,
            },
        );
        if verdict == Verdict::Block && eject(&p) {
            entry.action = "ejected".into();
        }
        report_entry(&app, entry, None);
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
        // The editor takes a few seconds to unpack an extension; wait for package.json
        std::thread::sleep(Duration::from_secs(4));
        if !extension::is_extension_dir(&p) || !seen.insert(&key) || paused() {
            return;
        }
        let cfg = cfg.lock().unwrap().clone();
        let (_, report) = tsuba_engine::evaluate_extension(&cfg, &p);
        let mut entry = LogEntry::new("extension", &p.to_string_lossy(), "", report);
        if entry.report.verdict == Verdict::Block && cfg.auto_quarantine
            && let Ok(item) = tsuba_engine::quarantine::quarantine(&p, &entry.report.summary) {
                entry.action = "quarantined".into();
                entry.quarantine_id = Some(item.id);
            }
        report_entry(&app, entry, None);
    });
}

/// On the first run, mark existing files and extensions as seen and only check what appears later.
/// Installed extensions can be scanned by hand in Health Check.
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
        let verdicts = Verdicts::default();
        let (app2, cfg2, seen2, verdicts2) = (app.clone(), cfg.clone(), seen.clone(), verdicts.clone());
        if let Ok(mut w) = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
            if let Ok(ev) = res {
                for p in ev.paths {
                    on_download(app2.clone(), cfg2.clone(), seen2.clone(), verdicts2.clone(), p);
                }
            }
        })
            && w.watch(&downloads_dir(), RecursiveMode::NonRecursive).is_ok() {
                watchers.push(w);
            }

        // Volumes already mounted are not checked, only ones mounted later
        let mounted: Arc<Mutex<HashSet<PathBuf>>> = Arc::new(Mutex::new(
            std::fs::read_dir("/Volumes").map(|rd| rd.flatten().map(|e| e.path()).collect()).unwrap_or_default(),
        ));
        let app2 = app.clone();
        if let Ok(mut w) = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
            if let Ok(ev) = res {
                for p in ev.paths {
                    on_mount(app2.clone(), verdicts.clone(), mounted.clone(), p);
                }
            }
        })
            && w.watch(Path::new("/Volumes"), RecursiveMode::NonRecursive).is_ok() {
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
    if c.watch_ai_tools {
        crate::watch_ai::start(app, cfg.clone(), &mut watchers);
    }
    Watchers { _watchers: watchers }
}
