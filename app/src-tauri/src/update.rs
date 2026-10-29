//! Updates from GitHub Releases through Tauri's updater. The latest published release carries latest.json, which names
//! the version and a package per architecture; a package is installed only if its signature matches the public key in
//! tauri.conf.json, so a tampered download or release page can't push code onto this Mac. The update channel is a
//! supply chain too.
//!
//! Drafts aren't served by releases/latest, so a release is only offered once it has been reviewed and published.

use serde::Serialize;
use std::sync::Mutex;
use tauri::{AppHandle, Emitter, State};
use tauri_plugin_updater::{Update, UpdaterExt};

/// The update found by the last check, kept so installing uses exactly what was shown to the user
#[derive(Default)]
pub struct PendingUpdate(Mutex<Option<Update>>);

#[derive(Serialize)]
pub struct UpdateInfo {
    version: String,
    current: String,
}

#[tauri::command]
pub fn app_version(app: AppHandle) -> String {
    app.package_info().version.to_string()
}

/// None when this is the latest version
#[tauri::command]
pub async fn check_update(app: AppHandle, pending: State<'_, PendingUpdate>) -> Result<Option<UpdateInfo>, String> {
    let updater = app.updater().map_err(|e| e.to_string())?;
    let update = updater.check().await.map_err(|e| tr!("Couldn't check for updates: {error}", error = e))?;
    let info = update.as_ref().map(|u| UpdateInfo { version: u.version.clone(), current: u.current_version.clone() });
    *pending.0.lock().unwrap() = update;
    Ok(info)
}

/// Downloads, verifies and installs the update found by `check_update`, then restarts into it.
/// Progress goes out as "update-progress" events: (bytes so far, total bytes if known).
#[tauri::command]
pub async fn install_update(app: AppHandle, pending: State<'_, PendingUpdate>) -> Result<(), String> {
    let update = pending.0.lock().unwrap().take().ok_or_else(|| tr!("No update to install. Check for updates first."))?;
    let progress = app.clone();
    let mut downloaded = 0usize;
    update
        .download_and_install(
            move |chunk, total| {
                downloaded += chunk;
                let _ = progress.emit("update-progress", (downloaded, total));
            },
            || {},
        )
        .await
        .map_err(|e| tr!("The update couldn't be installed: {error}", error = e))?;
    app.restart()
}
