//! Tsuba 菜单栏应用：托盘菜单、主窗口、后台监控，以及给界面调用的命令。

mod shell_hook;
mod watch;

use serde::Serialize;
use serde_json::json;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{ActivationPolicy, AppHandle, Emitter, Manager, State, WindowEvent};
use tsuba_engine::rules::{Finding, Verdict};
use tsuba_engine::store::{self, Config, LogEntry};
use tsuba_engine::{doctor, extension, judge};

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
        let _ = item.set_text(if paused { "恢复守护" } else { "暂停守护" });
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
    downloads_dir: String,
    extension_dirs: Vec<String>,
    provider: store::Provider,
    provider_label: String,
    ai_available: bool,
    recent: RecentCounts,
    quarantined: usize,
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
        recent: RecentCounts {
            total: log.len(),
            warned: log.iter().filter(|e| e.report.verdict == Verdict::Warn).count(),
            blocked: log.iter().filter(|e| e.report.verdict == Verdict::Block).count(),
        },
        quarantined: extension::quarantined().len(),
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
    DoctorResult { advice: if findings.is_empty() { String::new() } else { doctor::ADVICE.into() }, findings }
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
fn quarantine_list() -> Vec<extension::QuarantineItem> {
    extension::quarantined()
}

#[tauri::command]
fn quarantine_extension(app: AppHandle, path: String, reason: String) -> Result<(), String> {
    extension::quarantine(std::path::Path::new(&path), &reason).map_err(|e| e.to_string())?;
    let _ = app.emit("status-changed", ());
    Ok(())
}

#[tauri::command]
fn restore_quarantine(app: AppHandle, id: String) -> Result<(), String> {
    extension::restore(&id)?;
    let _ = app.emit("status-changed", ());
    Ok(())
}

#[tauri::command]
fn delete_quarantine(app: AppHandle, id: String) -> Result<(), String> {
    extension::delete(&id)?;
    let _ = app.emit("status-changed", ());
    Ok(())
}

#[tauri::command]
fn reveal_in_finder(path: String) {
    let _ = std::process::Command::new("open").args(["-R", &path]).spawn();
}

fn build_tray(app: &tauri::App) -> tauri::Result<()> {
    let open = MenuItem::with_id(app, "open", "打开 Tsuba", true, None::<&str>)?;
    let history = MenuItem::with_id(app, "history", "检查记录", true, None::<&str>)?;
    let pause = MenuItem::with_id(app, "pause", if is_paused() { "恢复守护" } else { "暂停守护" }, true, None::<&str>)?;
    let doctor = MenuItem::with_id(app, "doctor", "体检", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "退出 Tsuba", true, None::<&str>)?;
    let sep1 = PredefinedMenuItem::separator(app)?;
    let sep2 = PredefinedMenuItem::separator(app)?;
    let menu = Menu::with_items(app, &[&open, &history, &sep1, &pause, &doctor, &sep2, &quit])?;
    *app.state::<AppState>().pause_item.lock().unwrap() = Some(pause);

    TrayIconBuilder::with_id("tsuba")
        .icon(app.default_window_icon().cloned().expect("缺少应用图标"))
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
            build_tray(app)?;
            shell_hook::refresh_if_installed();
            restart_watchers(app.handle());
            start_intel_updater(app.handle().clone(), app.state::<AppState>().config.clone());
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
            intel_update,
            run_doctor,
            scan_installed_extensions,
            scan_path,
            quarantine_list,
            quarantine_extension,
            restore_quarantine,
            delete_quarantine,
            reveal_in_finder,
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

