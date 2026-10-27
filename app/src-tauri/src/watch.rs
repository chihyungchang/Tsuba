//! 后台监控：下载目录里新出现的安装包、编辑器扩展目录里新装或更新的扩展。

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

fn file_name(p: &str) -> String {
    Path::new(p).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| p.to_string())
}

/// 记一条检查记录，有风险时发通知；拦截时把窗口调出来。
/// `previous` 是同一条记录之前的结论（两段式检查的第二段），结论没有变得更严重时不重复提醒。
fn report_entry(app: &AppHandle, mut entry: LogEntry, previous: Option<Verdict>) {
    let r = &entry.report;
    let name = file_name(&entry.title);
    let escalated = previous.is_none_or(|p| r.verdict > p);
    match r.verdict {
        Verdict::Allow if entry.action.is_empty() => entry.action = "allowed".into(),
        Verdict::Warn | Verdict::Block if escalated => {
            let what = match entry.action.as_str() {
                "quarantined" => "已移入隔离区",
                "ejected" => "已阻止打开",
                _ => "先不要打开它",
            };
            let label = if r.verdict == Verdict::Block { "建议拦截" } else { "需要注意" };
            notify_user(&format!("Tsuba：{name} {label}"), &format!("{} {what}。", r.summary));
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

/// 两段式检查：离线规则不到一秒就出结论，有风险马上提醒；AI 的判断随后补上，更新同一条记录。
fn two_phase(app: &AppHandle, cfg: &Config, source: &str, title: &str, check: impl Fn(&Config) -> tsuba_engine::Report) -> Verdict {
    let offline_cfg = Config { provider: store::Provider::Offline, ..cfg.clone() };
    let first = LogEntry::new(source, title, "", check(&offline_cfg));
    let offline = first.report.verdict;
    let id = first.id.clone();
    report_entry(app, first, None);
    if !tsuba_engine::judge::available(cfg) {
        return offline;
    }
    let mut second = LogEntry::new(source, title, "", check(cfg));
    second.id = id;
    let verdict = second.report.verdict;
    report_entry(app, second, Some(offline));
    verdict
}

/// 等文件写完：大小连续不变，而且浏览器的临时文件已经没了。
/// Chrome 和 Safari 下载完才改成最终文件名；Firefox 先建一个空的最终文件，边下边写 .part。
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

/// 已经判断过的镜像文件 → 结论。用户打开它时直接按这个处理，不用再等。
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

/// 弹出一个已挂载的镜像。刚挂载的卷可能还被 Finder 或 Spotlight 占着，确认真的卸载了才算成功。
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

/// 用户打开（挂载）了一个安装镜像。这是真正能拦住的时刻：判为高危就立刻把它弹出，
/// 赶在用户双击里面的东西之前。只用离线规则，不到一秒出结果。
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
        // hdiutil 登记挂载信息要一点时间
        let mut image = None;
        for _ in 0..10 {
            image = macos::mounted_images().into_iter().find(|(mp, _)| *mp == p).map(|(_, img)| img);
            if image.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(150));
        }
        // 不是磁盘镜像（U 盘、移动硬盘），不管
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
            format!("{label} 带有明显的恶意安装包特征，Tsuba 已经把它弹出，没有让它打开")
        } else {
            format!("{label} 有可疑之处，打开里面的东西之前先看看证据")
        };
        let mut entry = LogEntry::new(
            "mount",
            &image.to_string_lossy(),
            "",
            tsuba_engine::Report {
                verdict,
                summary,
                reasons: vec![],
                advice: "不要从终端或右键强制打开镜像里的任何文件。如果是别人让你装的会议软件或面试工具，直接删除，并向对方的公司核实。".into(),
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
        report_entry(&app, entry, None);
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

        // 已经挂载着的卷不检查，只看之后新挂载的
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
    Watchers { _watchers: watchers }
}
