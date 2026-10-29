//! Tsuba's menu bar app: tray menu, main window, background watchers and the commands the UI calls.

/// User-facing text in the App backend: `tr!("Found {n} files", n = count)`. Defined before the modules so they can use it.
macro_rules! tr {
    ($($args:tt)*) => { tsuba_engine::tr_in!(crate::ZH_HANS, $($args)*) };
}

mod shell_hook;
mod update;
mod watch;
mod watch_ai;

use serde::Serialize;
use serde_json::json;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{ActivationPolicy, AppHandle, Emitter, Manager, State, WindowEvent};
use tsuba_engine::rules::{Finding, Verdict};
use tsuba_engine::store::{self, Config, LogEntry};
use tsuba_engine::{doctor, extension, judge, quarantine, scan, trust};

static ZH_HANS: tsuba_engine::i18n::Catalog = tsuba_engine::i18n::Catalog::new(|| tsuba_engine::i18n::parse_catalog(include_str!("../locales/zh-Hans.json")));

struct AppState {
    config: Arc<Mutex<Config>>,
    watchers: Mutex<Option<watch::Watchers>>,
    pause_item: Mutex<Option<MenuItem<tauri::Wry>>>,
}

/// While the window is open, show the Dock icon and menu bar (copy and paste shortcuts need the menu bar); once closed, only the tray icon stays.
pub fn show_window(app: &AppHandle) {
    let _ = app.set_activation_policy(ActivationPolicy::Regular);
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

fn is_paused() -> bool {
    store::home().join("paused").exists()
}

fn set_paused_flag(app: &AppHandle, paused: bool) -> Result<(), String> {
    let flag = store::home().join("paused");
    if paused {
        std::fs::create_dir_all(store::home()).map_err(|e| e.to_string())?;
        std::fs::write(&flag, "").map_err(|e| e.to_string())?;
    } else if flag.exists() {
        std::fs::remove_file(&flag).map_err(|e| e.to_string())?;
    }
    if let Some(item) = app.state::<AppState>().pause_item.lock().unwrap().as_ref() {
        let _ = item.set_text(pause_label(paused));
    }
    if let Some(tray) = app.tray_by_id("tsuba") {
        if let Ok(icon) = tray_icon(paused) {
            let _ = tray.set_icon(Some(icon));
            // Replacing the image drops the template flag, which would draw it black on a dark menu bar
            let _ = tray.set_icon_as_template(true);
        }
        let _ = tray.set_tooltip(Some(tray_tooltip(paused)));
    }
    let _ = app.emit("status-changed", ());
    Ok(())
}

fn restart_watchers(app: &AppHandle) {
    let state = app.state::<AppState>();
    let w = watch::start(app, state.config.clone());
    *state.watchers.lock().unwrap() = Some(w);
}

#[derive(Serialize)]
struct Overview {
    paused: bool,
    shell_hook: shell_hook::HookStatus,
    watch_downloads: bool,
    watch_extensions: bool,
    watch_ai_tools: bool,
    downloads_dir: String,
    extension_dirs: Vec<String>,
    provider: store::Provider,
    /// The OpenAI-compatible preset ID (openai, gemini, deepseek…), so the UI can show the right logo without parsing the label
    provider_preset: String,
    provider_label: String,
    ai_available: bool,
    sandbox_available: bool,
    recent: RecentCounts,
    quarantined: usize,
    trusted: usize,
}

#[derive(Serialize)]
struct RecentCounts {
    total: usize,
    warned: usize,
    blocked: usize,
}

#[tauri::command]
fn get_overview(state: State<AppState>) -> Overview {
    let cfg = state.config.lock().unwrap().clone();
    let log = store::read_log(500);
    Overview {
        paused: is_paused(),
        shell_hook: shell_hook::status(),
        watch_downloads: cfg.watch_downloads,
        watch_extensions: cfg.watch_extensions,
        watch_ai_tools: cfg.watch_ai_tools,
        downloads_dir: watch::downloads_dir().to_string_lossy().to_string(),
        extension_dirs: extension::extension_dirs().iter().map(|p| p.to_string_lossy().to_string()).collect(),
        provider: cfg.provider,
        provider_preset: cfg.openai_compatible.preset.clone(),
        provider_label: match cfg.provider {
            store::Provider::ClaudeCli => tr!("Claude Code account · {model}", model = cfg.claude.model),
            store::Provider::CodexCli => {
                if cfg.codex.model.is_empty() { tr!("Codex account") } else { tr!("Codex account · {model}", model = cfg.codex.model) }
            }
            store::Provider::Claude => format!("Claude API · {}", cfg.claude.model),
            store::Provider::OpenaiCompatible => format!("{} · {}", cfg.openai_compatible.preset, cfg.openai_compatible.model),
            store::Provider::Offline => tr!("Offline rules only"),
        },
        ai_available: judge::available(&cfg),
        sandbox_available: sandbox_available(),
        recent: RecentCounts {
            total: log.len(),
            warned: log.iter().filter(|e| e.report.verdict == Verdict::Warn && !e.dismissed).count(),
            blocked: log.iter().filter(|e| e.report.verdict == Verdict::Block && !e.dismissed).count(),
        },
        quarantined: quarantine::list().len(),
        trusted: trust::list().len(),
    }
}

#[tauri::command]
fn set_paused(app: AppHandle, paused: bool) -> Result<(), String> {
    set_paused_flag(&app, paused)
}

#[tauri::command]
fn install_shell_hook() -> Result<(), String> {
    shell_hook::install()
}

#[tauri::command]
fn uninstall_shell_hook() -> Result<(), String> {
    shell_hook::uninstall()
}

#[tauri::command]
fn get_history(limit: usize) -> Vec<LogEntry> {
    store::read_log(limit)
}

#[tauri::command]
fn clear_history(app: AppHandle) {
    store::clear_log();
    let _ = app.emit("history-updated", ());
}

#[tauri::command]
fn get_config(state: State<AppState>) -> Config {
    state.config.lock().unwrap().clone()
}

#[tauri::command]
fn save_config(app: AppHandle, state: State<AppState>, mut config: Config) -> Result<(), String> {
    // The language belongs to set_lang: a settings page loaded before a language switch must not write the old one back
    config.language = state.config.lock().unwrap().language.clone();
    config.save().map_err(|e| e.to_string())?;
    *state.config.lock().unwrap() = config;
    restart_watchers(&app);
    let _ = app.emit("status-changed", ());
    Ok(())
}

/// Tries the model once on harmless sample evidence to confirm the configuration works.
#[tauri::command]
async fn test_ai(config: Config) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        if !judge::available(&config) {
            return Err(tr!("The configuration is incomplete"));
        }
        let evidence = json!({ "command": "brew install wget", "cwd": "~", "targets": [], "findings": [] });
        let start = std::time::Instant::now();
        let j = judge::ask(&config, &evidence)?;
        let verdict = match j.verdict {
            Verdict::Allow => tr!("Allow"),
            Verdict::Warn => tr!("Warn"),
            Verdict::Block => tr!("Block"),
        };
        Ok(tr!("Connected to {model} in {seconds} s. The sample was judged: {verdict}", model = j.model, seconds = format!("{:.1}", start.elapsed().as_secs_f64()), verdict = verdict))
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Location of the local claude command, None if not found.
#[tauri::command]
fn detect_claude_cli(configured: String) -> Option<String> {
    judge::find_claude_cli(&configured).map(|p| p.to_string_lossy().to_string())
}

/// Location of the local codex command (including the copy inside the ChatGPT app), None if not found.
#[tauri::command]
fn detect_codex_cli(configured: String) -> Option<String> {
    judge::find_codex_cli(&configured).map(|p| p.to_string_lossy().to_string())
}

/// Scans MCP servers, skills and plugin hooks of every local AI tool (offline rules only, takes a few seconds).
#[tauri::command]
async fn scan_ai_tools(state: State<'_, AppState>) -> Result<Vec<tsuba_engine::agents::ScanItem>, String> {
    let online = state.config.lock().unwrap().intel.online_lookup;
    tauri::async_runtime::spawn_blocking(move || tsuba_engine::agents::scan_all(online)).await.map_err(|e| e.to_string())
}

#[tauri::command]
fn intel_status() -> tsuba_engine::intel::Manifest {
    tsuba_engine::intel::Manifest::load()
}

/// Updates threat intel now, pushing each step to the UI as progress.
#[tauri::command]
async fn intel_update(app: AppHandle, state: State<'_, AppState>) -> Result<tsuba_engine::intel::Manifest, String> {
    let cfg = state.config.lock().unwrap().clone();
    tauri::async_runtime::spawn_blocking(move || {
        tsuba_engine::intel::update(&cfg, false, |step| {
            let _ = app.emit("intel-progress", step.to_string());
        })
    })
    .await
    .map_err(|e| e.to_string())
}

/// Updates threat intel once a day (checked once when the App starts).
fn start_intel_updater(app: AppHandle, config: Arc<Mutex<Config>>) {
    std::thread::spawn(move || loop {
        let cfg = config.lock().unwrap().clone();
        if cfg.intel.auto_update && tsuba_engine::intel::needs_update(std::time::Duration::from_secs(24 * 3600)) {
            tsuba_engine::intel::update(&cfg, false, |step| {
                let _ = app.emit("intel-progress", step.to_string());
            });
            let _ = app.emit("intel-updated", ());
        }
        std::thread::sleep(std::time::Duration::from_secs(3600));
    });
}

#[tauri::command]
async fn list_models(base_url: String, api_key: String) -> Result<Vec<String>, String> {
    tauri::async_runtime::spawn_blocking(move || judge::list_models(&base_url, &api_key)).await.map_err(|e| e.to_string())?
}

#[derive(Serialize)]
struct DoctorResult {
    findings: Vec<Finding>,
    advice: String,
}

#[tauri::command]
async fn run_doctor() -> DoctorResult {
    let findings = tauri::async_runtime::spawn_blocking(doctor::run).await.unwrap_or_default();
    DoctorResult { advice: if findings.is_empty() { String::new() } else { doctor::advice() }, findings }
}

#[derive(Serialize)]
struct ExtensionScan {
    id: String,
    path: String,
    verdict: Verdict,
    findings: Vec<Finding>,
}

/// Scans all installed extensions. There can be dozens, so offline rules only and no model; suspicious ones get a deep check on their own.
#[tauri::command]
async fn scan_installed_extensions() -> Vec<ExtensionScan> {
    tauri::async_runtime::spawn_blocking(|| {
        let mut out = Vec::new();
        for root in extension::extension_dirs() {
            let Ok(rd) = std::fs::read_dir(&root) else { continue };
            for p in rd.flatten().map(|e| e.path()).filter(|p| extension::is_extension_dir(p)) {
                let (info, findings) = extension::scan_extension(&p);
                out.push(ExtensionScan {
                    id: info["id"].as_str().unwrap_or("").to_string(),
                    path: p.to_string_lossy().to_string(),
                    verdict: tsuba_engine::rules::offline_verdict(&findings),
                    findings,
                });
            }
        }
        out.sort_by(|a, b| b.verdict.cmp(&a.verdict).then(a.id.cmp(&b.id)));
        out
    })
    .await
    .unwrap_or_default()
}

/// Checks one file or folder the user dropped in or picked (with AI judgment) and records it in the check history.
#[tauri::command]
async fn scan_path(app: AppHandle, state: State<'_, AppState>, path: String) -> Result<LogEntry, String> {
    let cfg = state.config.lock().unwrap().clone();
    let entry = tauri::async_runtime::spawn_blocking(move || {
        let p = PathBuf::from(&path);
        if !p.exists() {
            return Err(tr!("Not found: {path}", path = path));
        }
        let (_, _, report) = tsuba_engine::evaluate_path(&cfg, &p);
        let mut entry = LogEntry::new("scan", &path, "", report);
        entry.action = "scanned".into();
        store::append_log(&entry);
        Ok(entry)
    })
    .await
    .map_err(|e| e.to_string())??;
    let _ = app.emit("history-updated", ());
    Ok(entry)
}

#[tauri::command]
fn quarantine_list() -> Vec<quarantine::QuarantineItem> {
    quarantine::list()
}

/// Moves any file, folder or extension into quarantine; if it has a check record, the record is marked as quarantined.
#[tauri::command]
fn quarantine_path(app: AppHandle, path: String, reason: String, entry_id: Option<String>) -> Result<(), String> {
    let item = quarantine::quarantine(std::path::Path::new(&path), &reason).map_err(|e| e.to_string())?;
    if let Some(id) = entry_id
        && let Some(mut entry) = store::read_log(2000).into_iter().find(|e| e.id == id)
    {
        entry.action = "quarantined".into();
        entry.quarantine_id = Some(item.id);
        store::append_log(&entry);
        let _ = app.emit("history-updated", ());
    }
    let _ = app.emit("status-changed", ());
    Ok(())
}

#[tauri::command]
fn restore_quarantine(app: AppHandle, id: String) -> Result<(), String> {
    quarantine::restore(&id)?;
    let _ = app.emit("status-changed", ());
    Ok(())
}

#[tauri::command]
fn delete_quarantine(app: AppHandle, id: String) -> Result<(), String> {
    quarantine::delete(&id)?;
    let _ = app.emit("status-changed", ());
    Ok(())
}

/// "Delete File" in the check history: the path is looked up by record id, so the UI cannot name an arbitrary path.
/// Only things on disk (downloads, disk images, extensions, manual checks) can be deleted; the record is marked afterwards.
#[tauri::command]
fn delete_entry_file(app: AppHandle, entry_id: String) -> Result<(), String> {
    let mut entry = store::read_log(2000).into_iter().find(|e| e.id == entry_id).ok_or_else(|| tr!("This check record no longer exists"))?;
    if !["download", "mount", "extension", "scan"].contains(&entry.source.as_str()) {
        return Err(tr!("This record is not a file on disk"));
    }
    quarantine::delete_path(std::path::Path::new(&entry.title))?;
    entry.action = "deleted".into();
    store::append_log(&entry);
    let _ = app.emit("history-updated", ());
    let _ = app.emit("status-changed", ());
    Ok(())
}

/// "Ignore" in the check history: the record stays, but it no longer counts as risky. `dismissed: false` undoes it.
#[tauri::command]
fn set_entry_dismissed(app: AppHandle, entry_id: String, dismissed: bool) -> Result<(), String> {
    let mut entry = store::read_log(2000).into_iter().find(|e| e.id == entry_id).ok_or_else(|| tr!("This check record no longer exists"))?;
    entry.dismissed = dismissed;
    store::append_log(&entry);
    let _ = app.emit("history-updated", ());
    let _ = app.emit("status-changed", ());
    Ok(())
}

/// "Don't Warn Again" for a terminal command: the next time the same command turns up the same findings, it runs without asking.
/// Looked up by record id so the UI can't invent a command, and refused for Block, which should keep asking every time.
#[tauri::command]
fn ignore_command_warning(app: AppHandle, entry_id: String) -> Result<(), String> {
    let mut entry = store::read_log(2000).into_iter().find(|e| e.id == entry_id).ok_or_else(|| tr!("This check record no longer exists"))?;
    if !["terminal", "paste"].contains(&entry.source.as_str()) || entry.report.verdict != Verdict::Warn {
        return Err(tr!("Only warnings about terminal commands can be ignored"));
    }
    trust::ignore_command(&entry.title, &entry.report.findings);
    entry.dismissed = true;
    store::append_log(&entry);
    let _ = app.emit("history-updated", ());
    let _ = app.emit("status-changed", ());
    Ok(())
}

#[tauri::command]
fn trusted_list() -> Vec<trust::TrustItem> {
    trust::list()
}

/// Mark as safe: a path or mcp:<key>. Recorded by content fingerprint, so a change triggers a new check.
#[tauri::command]
fn trust_item(app: AppHandle, key: String) -> Result<(), String> {
    trust::trust(&key)?;
    let _ = app.emit("status-changed", ());
    Ok(())
}

#[tauri::command]
fn untrust_item(app: AppHandle, key: String) {
    trust::remove(&key);
    let _ = app.emit("status-changed", ());
}

/// The system folder picker; None when cancelled.
#[tauri::command]
async fn choose_folder() -> Option<String> {
    let prompt = tr!("Choose a folder to scan").replace('\\', "").replace('"', "'");
    tauri::async_runtime::spawn_blocking(move || {
        let out = std::process::Command::new("osascript")
            .args(["-e", &format!("POSIX path of (choose folder with prompt \"{prompt}\")")])
            .output()
            .ok()?;
        let p = String::from_utf8_lossy(&out.stdout).trim().trim_end_matches('/').to_string();
        (out.status.success() && !p.is_empty()).then_some(p)
    })
    .await
    .ok()
    .flatten()
}

/// Scans a folder: only installers, scripts, extensions and projects, with offline rules; unchanged items reuse the last result.
#[tauri::command]
async fn scan_folder(app: AppHandle, state: State<'_, AppState>, path: String) -> Result<scan::FolderScan, String> {
    let cfg = state.config.lock().unwrap().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let root = scan::expand(&path);
        if !root.exists() {
            return Err(tr!("Not found: {path}", path = path));
        }
        Ok(scan::scan_folder(&cfg, &root, |p| {
            let _ = app.emit("scan-progress", p.to_string());
        }))
    })
    .await
    .map_err(|e| e.to_string())?
}

#[derive(Serialize)]
struct ScheduleStatus {
    last: Option<String>,
}

#[tauri::command]
fn scan_schedule_status() -> ScheduleStatus {
    ScheduleStatus { last: scan::last_scheduled_run() }
}

/// Scheduled scan: when due, rescan the configured folders with the latest rules; new problems go into the check history with a notification.
fn start_scan_scheduler(app: AppHandle, config: Arc<Mutex<Config>>) {
    std::thread::spawn(move || loop {
        // Leave the machine alone right after startup; begin a few minutes later
        std::thread::sleep(std::time::Duration::from_secs(300));
        let cfg = config.lock().unwrap().clone();
        if cfg.scan.scheduled && !is_paused() && scan::schedule_due(cfg.scan.interval_days) {
            let mut found = 0;
            for folder in &cfg.scan.folders {
                let root = scan::expand(folder);
                if !root.exists() {
                    continue;
                }
                let r = scan::scan_folder(&cfg, &root, |_| {});
                for hit in r.hits.into_iter().filter(|h| h.fresh) {
                    let report = tsuba_engine::Report {
                        verdict: hit.verdict,
                        summary: hit.summary,
                        reasons: vec![],
                        advice: String::new(),
                        source: "offline".into(),
                        model: String::new(),
                        findings: hit.findings,
                    };
                    let mut entry = LogEntry::new("scan", &hit.path, "", report);
                    entry.action = "scanned".into();
                    store::append_log(&entry);
                    found += 1;
                }
            }
            scan::mark_scheduled_run();
            if found > 0 {
                if Config::load().notify_scheduled_scan {
                    watch::notify_user(&tr!("Tsuba: the scheduled scan found problems"), &tr!("{count} files need a look. Open Check History in Tsuba to see them.", count = found));
                }
                let _ = app.emit("history-updated", ());
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(3300));
    });
}

#[tauri::command]
fn reveal_in_finder(path: String) {
    let _ = std::process::Command::new("open").args(["-R", &path]).spawn();
}

/// Opens a help or sign-up page in the browser. Only https: `open` would also launch apps and local files,
/// and nothing the UI links to needs that.
#[tauri::command]
fn open_link(url: String) -> Result<(), String> {
    if !url.starts_with("https://") {
        return Err(tr!("Only https links can be opened"));
    }
    std::process::Command::new("open").arg(&url).spawn().map(|_| ()).map_err(|e| e.to_string())
}

#[derive(Serialize)]
struct SandboxResult {
    behavior: tsuba_engine::sandbox::Behavior,
    findings: Vec<Finding>,
    verdict: Verdict,
}

/// Tries a script file or project folder in the sandbox to see what it actually does (no real internet access).
/// With install set, tries installing the project's dependencies to see what install scripts do (only the npm registry is reachable).
#[tauri::command]
async fn sandbox_script(path: String, install: Option<bool>) -> Result<SandboxResult, String> {
    if !tsuba_engine::sandbox::available() {
        return Err(tr!("This system has no sandbox-exec, so the sandbox isn't available"));
    }
    tauri::async_runtime::spawn_blocking(move || {
        let p = std::path::Path::new(&path);
        let timeout = std::time::Duration::from_secs(60);
        let b = if p.is_dir() && install == Some(true) {
            tsuba_engine::sandbox::run_install(p, std::time::Duration::from_secs(90)).map_err(|e| e.to_string())?
        } else if p.is_dir() {
            let argv = tsuba_engine::sandbox::project_start_argv(p);
            tsuba_engine::sandbox::run_project(p, &argv, timeout).map_err(|e| e.to_string())?
        } else {
            let script = std::fs::read_to_string(&path).map_err(|e| tr!("Can't read {path}: {error}", path = path, error = e))?;
            tsuba_engine::sandbox::run_script(&script, "/bin/bash", timeout).map_err(|e| e.to_string())?
        };
        let findings = tsuba_engine::sandbox::findings(&b);
        let verdict = tsuba_engine::rules::offline_verdict(&findings);
        Ok(SandboxResult { behavior: b, findings, verdict })
    })
    .await
    .map_err(|e| e.to_string())?
}

pub fn sandbox_available() -> bool {
    tsuba_engine::sandbox::available()
}

fn pause_label(paused: bool) -> String {
    if paused { tr!("Resume Protection") } else { tr!("Pause Protection") }
}

/// Built again when the language changes, so the menu is always in the window's language.
fn tray_menu(app: &AppHandle) -> tauri::Result<Menu<tauri::Wry>> {
    let open = MenuItem::with_id(app, "open", tr!("Open Tsuba"), true, None::<&str>)?;
    let history = MenuItem::with_id(app, "history", tr!("Check History"), true, None::<&str>)?;
    let pause = MenuItem::with_id(app, "pause", pause_label(is_paused()), true, None::<&str>)?;
    let doctor = MenuItem::with_id(app, "doctor", tr!("Health Check"), true, None::<&str>)?;
    let updates = MenuItem::with_id(app, "updates", tr!("Check for Updates…"), true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", tr!("Quit Tsuba"), true, None::<&str>)?;
    let sep1 = PredefinedMenuItem::separator(app)?;
    let sep2 = PredefinedMenuItem::separator(app)?;
    let menu = Menu::with_items(app, &[&open, &history, &sep1, &pause, &doctor, &sep2, &updates, &quit])?;
    *app.state::<AppState>().pause_item.lock().unwrap() = Some(pause);
    Ok(menu)
}

/// The window's language setting. `preference` is "system", "en" or "zh-Hans"; `lang` is what the window resolved it to.
/// It is saved to the config so the terminal check and every AI answer use it too, not only this process.
#[tauri::command]
fn set_lang(app: AppHandle, state: State<AppState>, preference: String, lang: String) -> Result<(), String> {
    let stored = if preference == "system" { String::new() } else { preference };
    {
        let mut config = state.config.lock().unwrap();
        if config.language != stored {
            config.language = stored;
            config.save().map_err(|e| e.to_string())?;
        }
    }
    let lang = tsuba_engine::i18n::Lang::parse(&lang);
    if lang == tsuba_engine::i18n::lang() {
        return Ok(());
    }
    tsuba_engine::i18n::set_lang(lang);
    if let Some(tray) = app.tray_by_id("tsuba") {
        tray.set_menu(Some(tray_menu(&app).map_err(|e| e.to_string())?)).map_err(|e| e.to_string())?;
        let _ = tray.set_tooltip(Some(tray_tooltip(is_paused())));
    }
    Ok(())
}

/// Monochrome template icons: the system tints them for light and dark menu bars, and the colored App icon looks out of
/// place there. Paused shows the sword sheathed and dimmed, so the state is visible without opening anything.
fn tray_icon(paused: bool) -> tauri::Result<tauri::image::Image<'static>> {
    if paused {
        tauri::image::Image::from_bytes(include_bytes!("../icons/tray-template-paused.png"))
    } else {
        tauri::image::Image::from_bytes(include_bytes!("../icons/tray-template.png"))
    }
}

fn tray_tooltip(paused: bool) -> String {
    if paused { tr!("Tsuba · Protection paused") } else { tr!("Tsuba · Guarding") }
}

fn build_tray(app: &tauri::App) -> tauri::Result<()> {
    let menu = tray_menu(app.handle())?;
    let paused = is_paused();
    TrayIconBuilder::with_id("tsuba")
        .icon(tray_icon(paused)?)
        .icon_as_template(true)
        .tooltip(tray_tooltip(paused))
        .menu(&menu)
        .show_menu_on_left_click(true)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "open" => show_window(app),
            "history" | "doctor" => {
                show_window(app);
                let _ = app.emit("navigate", event.id.as_ref());
            }
            // Opens Settings › About & Updates, which checks as soon as it shows
            "updates" => {
                show_window(app);
                let _ = app.emit("open-settings", "about");
            }
            "pause" => {
                let _ = set_paused_flag(app, !is_paused());
            }
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::DoubleClick { button: MouseButton::Left, .. } | TrayIconEvent::Click { button: MouseButton::Right, button_state: MouseButtonState::Up, .. } = event {
                show_window(tray.app_handle());
            }
        })
        .build(app)?;
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(update::PendingUpdate::default())
        .manage(AppState {
            config: Arc::new(Mutex::new(Config::load())),
            watchers: Mutex::new(None),
            pause_item: Mutex::new(None),
        })
        .setup(|app| {
            // The saved choice, until the window reports its setting
            tsuba_engine::i18n::set_lang(app.state::<AppState>().config.lock().unwrap().lang());
            build_tray(app)?;
            shell_hook::refresh_if_installed();
            restart_watchers(app.handle());
            start_intel_updater(app.handle().clone(), app.state::<AppState>().config.clone());
            start_scan_scheduler(app.handle().clone(), app.state::<AppState>().config.clone());
            // Show the window when the user opens the App; closing it later only hides it and protection continues in the background
            show_window(app.handle());
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
                let _ = window.app_handle().set_activation_policy(ActivationPolicy::Accessory);
            }
        })
        .invoke_handler(tauri::generate_handler![
            set_lang,
            get_overview,
            set_paused,
            install_shell_hook,
            uninstall_shell_hook,
            get_history,
            clear_history,
            get_config,
            save_config,
            test_ai,
            list_models,
            detect_claude_cli,
            detect_codex_cli,
            intel_status,
            scan_ai_tools,
            intel_update,
            run_doctor,
            scan_installed_extensions,
            scan_path,
            quarantine_list,
            quarantine_path,
            restore_quarantine,
            delete_quarantine,
            delete_entry_file,
            trusted_list,
            trust_item,
            untrust_item,
            choose_folder,
            scan_folder,
            scan_schedule_status,
            reveal_in_finder,
            open_link,
            update::app_version,
            update::check_update,
            update::install_update,
            set_entry_dismissed,
            ignore_command_warning,
            sandbox_script,
        ])
        .build(tauri::generate_context!())
        .expect("failed to start Tsuba")
        .run(|_app, event| {
            // Closing the last window doesn't quit; protection continues from the menu bar
            if let tauri::RunEvent::ExitRequested { api, code: None, .. } = event {
                api.prevent_exit();
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zh_hans_catalog_matches_sources() {
        let sources = tsuba_engine::i18n::read_sources(concat!(env!("CARGO_MANIFEST_DIR"), "/src"));
        let sources: Vec<&str> = sources.iter().map(String::as_str).collect();
        if let Err(e) = tsuba_engine::i18n::check_catalog(&ZH_HANS, &sources, &[]) {
            panic!("{e}");
        }
    }
}
