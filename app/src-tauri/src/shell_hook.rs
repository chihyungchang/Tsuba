//! Installs the terminal checker and zsh hook into ~/.tsuba and adds a line to ~/.zshrc.

use serde::Serialize;
use std::path::PathBuf;
use tsuba_engine::{home_dir, store};

const ZSH_SCRIPT: &str = include_str!("../../../crates/cli/shell/tsuba.zsh");
const RC_LINE: &str = "[[ -f ~/.tsuba/tsuba.zsh ]] && source ~/.tsuba/tsuba.zsh";
const RC_COMMENT: &str = "# Tsuba: check dangerous commands before they run";
/// The comment older versions wrote into ~/.zshrc; still removed on uninstall.
const LEGACY_RC_COMMENT: &str = "# Tsuba：在危险命令执行前检查";

#[derive(Serialize)]
pub struct HookStatus {
    pub installed: bool,
    pub cli_found: bool,
    pub cli_path: String,
}

/// The checker sits next to the App binary: target/debug in development, Tsuba.app/Contents/MacOS when bundled.
pub fn bundled_cli() -> Option<PathBuf> {
    let p = std::env::current_exe().ok()?.parent()?.join("tsuba");
    p.is_file().then_some(p)
}

fn zshrc() -> PathBuf {
    home_dir().join(".zshrc")
}

pub fn status() -> HookStatus {
    let rc = std::fs::read_to_string(zshrc()).unwrap_or_default();
    let cli = store::home().join("bin/tsuba");
    HookStatus {
        installed: rc.contains(RC_LINE) && cli.is_file(),
        cli_found: bundled_cli().is_some(),
        cli_path: cli.to_string_lossy().to_string(),
    }
}

/// Copied rather than linked, so moving or deleting the App doesn't suddenly break the terminal.
fn copy_files() -> Result<(), String> {
    let src = bundled_cli().ok_or_else(|| tr!("Can't find the Tsuba checker. Reinstall Tsuba."))?;
    let home = store::home();
    std::fs::create_dir_all(home.join("bin")).map_err(|e| e.to_string())?;
    let dest = home.join("bin/tsuba");
    let tmp = home.join("bin/.tsuba.new");
    std::fs::copy(&src, &tmp).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, &dest).map_err(|e| e.to_string())?;
    std::fs::write(home.join("tsuba.zsh"), ZSH_SCRIPT).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn install() -> Result<(), String> {
    copy_files()?;
    let rc_path = zshrc();
    let rc = std::fs::read_to_string(&rc_path).unwrap_or_default();
    if !rc.contains(RC_LINE) {
        let mut new = rc;
        if !new.is_empty() && !new.ends_with('\n') {
            new.push('\n');
        }
        new.push_str(&format!("\n{RC_COMMENT}\n{RC_LINE}\n"));
        std::fs::write(&rc_path, new).map_err(|e| tr!("Couldn't write ~/.zshrc: {error}", error = e))?;
    }
    Ok(())
}

pub fn uninstall() -> Result<(), String> {
    let rc_path = zshrc();
    let rc = std::fs::read_to_string(&rc_path).unwrap_or_default();
    if rc.contains(RC_LINE) {
        let kept: Vec<&str> = rc.lines().filter(|l| *l != RC_LINE && *l != RC_COMMENT && *l != LEGACY_RC_COMMENT).collect();
        std::fs::write(&rc_path, kept.join("\n") + "\n").map_err(|e| tr!("Couldn't write ~/.zshrc: {error}", error = e))?;
    }
    let home = store::home();
    let _ = std::fs::remove_file(home.join("bin/tsuba"));
    let _ = std::fs::remove_file(home.join("tsuba.zsh"));
    Ok(())
}

/// After the App is upgraded, update the terminal checker to the same version.
pub fn refresh_if_installed() {
    if status().installed {
        let _ = copy_files();
    }
}
