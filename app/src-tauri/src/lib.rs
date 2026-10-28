//! Tsuba 菜单栏应用：托盘菜单、主窗口、后台监控，以及给界面调用的命令。

/// User-facing text in the App backend: `tr!("Found {n} files", n = count)`. Defined before the modules so they can use it.
macro_rules! tr {
    ($($args:tt)*) => { tsuba_engine::tr_in!(crate::ZH_HANS, $($args)*) };
}

mod shell_hook;
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

/// 窗口打开时显示 Dock 图标和菜单栏（复制粘贴快捷键要靠菜单栏），关掉后只留托盘图标。
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
        provider_label: match cfg.provider {
            store::Provider::ClaudeCli => format!("Claude Code 账号 · {}", cfg.claude.model),
            store::Provider::Claude => format!("Claude API · {}", cfg.claude.model),
            store::Provider::OpenaiCompatible => format!("{} · {}", cfg.openai_compatible.preset, cfg.openai_compatible.model),
            store::Provider::Offline => "仅离线规则".into(),
        },
        ai_available: judge::available(&cfg),
        sandbox_available: sandbox_available(),
        recent: RecentCounts {
            total: log.len(),
            warned: log.iter().filter(|e| e.report.verdict == Verdict::Warn).count(),
            blocked: log.iter().filter(|e| e.report.verdict == Verdict::Block).count(),
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
fn save_config(app: AppHandle, state: State<AppState>, config: Config) -> Result<(), String> {
    config.save().map_err(|e| e.to_string())?;
    *state.config.lock().unwrap() = config;
    restart_watchers(&app);
    let _ = app.emit("status-changed", ());
    Ok(())
}

/// 用一段无害的样例证据试一次模型，确认配置能用。
#[tauri::command]
async fn test_ai(config: Config) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        if !judge::available(&config) {
            return Err("配置不完整".to_string());
        }
        let evidence = json!({ "command": "brew install wget", "cwd": "~", "targets": [], "findings": [] });
        let start = std::time::Instant::now();
        let j = judge::ask(&config, &evidence)?;
        Ok(format!("连接成功：{}，用时 {:.1} 秒，样例判断为 {:?}", j.model, start.elapsed().as_secs_f64(), j.verdict))
    })
    .await
    .map_err(|e| e.to_string())?
}

/// 本机 claude 命令的位置，找不到返回 None。
#[tauri::command]
fn detect_claude_cli(configured: String) -> Option<String> {
    judge::find_claude_cli(&configured).map(|p| p.to_string_lossy().to_string())
}

/// 扫描本机所有 AI 工具的 MCP server、skill、插件 hooks（只用离线规则，几秒钟）。
#[tauri::command]
async fn scan_ai_tools(state: State<'_, AppState>) -> Result<Vec<tsuba_engine::agents::ScanItem>, String> {
    let online = state.config.lock().unwrap().intel.online_lookup;
    tauri::async_runtime::spawn_blocking(move || tsuba_engine::agents::scan_all(online)).await.map_err(|e| e.to_string())
}

#[tauri::command]
fn intel_status() -> tsuba_engine::intel::Manifest {
    tsuba_engine::intel::Manifest::load()
}

/// 立即更新威胁情报。更新时把当前步骤推给界面显示进度。
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

/// 每天自动更新一次威胁情报（App 启动时先检查一次）。
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

/// 批量扫描已装扩展。扩展可能有几十个，只用离线规则，不调模型；可疑的再单独深度检查。
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

/// 检查用户拖进来或选中的一个文件或目录（带 AI 判断），并记进检查记录。
#[tauri::command]
async fn scan_path(app: AppHandle, state: State<'_, AppState>, path: String) -> Result<LogEntry, String> {
    let cfg = state.config.lock().unwrap().clone();
    let entry = tauri::async_runtime::spawn_blocking(move || {
        let p = PathBuf::from(&path);
        if !p.exists() {
            return Err(format!("找不到：{path}"));
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

/// 把任意文件、目录或扩展移入隔离区；有检查记录的，记录上标明已隔离。
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

/// 检查记录里的“删除文件”：按记录 id 找路径，前端不能指定任意路径。
/// 只有磁盘上的东西（下载、安装镜像、扩展、手动检查）才能删；删完在记录上标明。
#[tauri::command]
fn delete_entry_file(app: AppHandle, entry_id: String) -> Result<(), String> {
    let mut entry = store::read_log(2000).into_iter().find(|e| e.id == entry_id).ok_or("找不到这条检查记录")?;
    if !["download", "mount", "extension", "scan"].contains(&entry.source.as_str()) {
        return Err("这条记录不是磁盘上的文件".into());
    }
    quarantine::delete_path(std::path::Path::new(&entry.title))?;
    entry.action = "deleted".into();
    store::append_log(&entry);
    let _ = app.emit("history-updated", ());
    let _ = app.emit("status-changed", ());
    Ok(())
}

#[tauri::command]
fn trusted_list() -> Vec<trust::TrustItem> {
    trust::list()
}

/// 标记为安全：路径或 mcp:<key>。按内容指纹记录，内容变了会重新检查。
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

/// 用系统的选择文件夹对话框，取消时返回 None。
#[tauri::command]
async fn choose_folder() -> Option<String> {
    tauri::async_runtime::spawn_blocking(|| {
        let out = std::process::Command::new("osascript")
            .args(["-e", "POSIX path of (choose folder with prompt \"选择要扫描的文件夹\")"])
            .output()
            .ok()?;
        let p = String::from_utf8_lossy(&out.stdout).trim().trim_end_matches('/').to_string();
        (out.status.success() && !p.is_empty()).then_some(p)
    })
    .await
    .ok()
    .flatten()
}

/// 扫描一个文件夹：只挑安装包、脚本、扩展和项目，用离线规则；扫过且没变的沿用上次结果。
#[tauri::command]
async fn scan_folder(app: AppHandle, state: State<'_, AppState>, path: String) -> Result<scan::FolderScan, String> {
    let cfg = state.config.lock().unwrap().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let root = scan::expand(&path);
        if !root.exists() {
            return Err(format!("找不到：{path}"));
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

/// 计划扫描：到期时用最新规则重扫配置里的文件夹，新发现的问题记进检查记录并通知。
fn start_scan_scheduler(app: AppHandle, config: Arc<Mutex<Config>>) {
    std::thread::spawn(move || loop {
        // 刚开机时让出资源，过几分钟再开始
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
                watch::notify_user("Tsuba：定期扫描发现问题", &format!("有 {found} 个文件需要看一下，打开 Tsuba 的检查记录查看。"));
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

#[derive(Serialize)]
struct SandboxResult {
    behavior: tsuba_engine::sandbox::Behavior,
    findings: Vec<Finding>,
    verdict: Verdict,
}

/// 把一个脚本文件或项目目录放进沙箱试运行，看它实际做了什么（不联真实外网）。
/// install 为 true 时试装项目依赖，看安装脚本做了什么（只放行 npm 官方源）。
#[tauri::command]
async fn sandbox_script(path: String, install: Option<bool>) -> Result<SandboxResult, String> {
    if !tsuba_engine::sandbox::available() {
        return Err("当前系统没有 sandbox-exec，无法使用沙箱".into());
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
            let script = std::fs::read_to_string(&path).map_err(|e| format!("读不到 {path}：{e}"))?;
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
    let quit = MenuItem::with_id(app, "quit", tr!("Quit Tsuba"), true, None::<&str>)?;
    let sep1 = PredefinedMenuItem::separator(app)?;
    let sep2 = PredefinedMenuItem::separator(app)?;
    let menu = Menu::with_items(app, &[&open, &history, &sep1, &pause, &doctor, &sep2, &quit])?;
    *app.state::<AppState>().pause_item.lock().unwrap() = Some(pause);
    Ok(menu)
}

/// The window's language setting; the engine's findings, notifications and the tray menu follow it.
#[tauri::command]
fn set_lang(app: AppHandle, lang: String) -> Result<(), String> {
    let lang = tsuba_engine::i18n::Lang::parse(&lang);
    if lang == tsuba_engine::i18n::lang() {
        return Ok(());
    }
    tsuba_engine::i18n::set_lang(lang);
    if let Some(tray) = app.tray_by_id("tsuba") {
        tray.set_menu(Some(tray_menu(&app).map_err(|e| e.to_string())?)).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn build_tray(app: &tauri::App) -> tauri::Result<()> {
    let menu = tray_menu(app.handle())?;
    TrayIconBuilder::with_id("tsuba")
        // 菜单栏用单色的模板图标：系统按浅色 / 深色菜单栏自动着色，彩色 App 图标在菜单栏里会显得突兀
        .icon(tauri::image::Image::from_bytes(include_bytes!("../icons/tray-template.png"))?)
        .icon_as_template(true)
        .tooltip("Tsuba")
        .menu(&menu)
        .show_menu_on_left_click(true)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "open" => show_window(app),
            "history" | "doctor" => {
                show_window(app);
                let _ = app.emit("navigate", event.id.as_ref());
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
        .manage(AppState {
            config: Arc::new(Mutex::new(Config::load())),
            watchers: Mutex::new(None),
            pause_item: Mutex::new(None),
        })
        .setup(|app| {
            // Until the window reports its setting, follow the system language
            tsuba_engine::i18n::set_lang(tsuba_engine::i18n::system_lang());
            build_tray(app)?;
            shell_hook::refresh_if_installed();
            restart_watchers(app.handle());
            start_intel_updater(app.handle().clone(), app.state::<AppState>().config.clone());
            start_scan_scheduler(app.handle().clone(), app.state::<AppState>().config.clone());
            // 用户主动打开 App 时显示窗口；之后关窗只是隐藏，后台继续守护
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
            sandbox_script,
        ])
        .build(tauri::generate_context!())
        .expect("Tsuba 启动失败")
        .run(|_app, event| {
            // 关掉最后一个窗口不退出，继续在菜单栏守护
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
