//! 把终端检查程序和 zsh 钩子装到 ~/.tsuba，并在 ~/.zshrc 里加一行。

use serde::Serialize;
use std::path::PathBuf;
use tsuba_engine::{home_dir, store};

const ZSH_SCRIPT: &str = include_str!("../../../crates/cli/shell/tsuba.zsh");
const RC_LINE: &str = "[[ -f ~/.tsuba/tsuba.zsh ]] && source ~/.tsuba/tsuba.zsh";
const RC_COMMENT: &str = "# Tsuba：在危险命令执行前检查";

#[derive(Serialize)]
pub struct HookStatus {
    pub installed: bool,
    pub cli_found: bool,
    pub cli_path: String,
}

/// 检查程序和 App 主程序放在同一个目录：开发时是 target/debug，打包后是 Tsuba.app/Contents/MacOS。
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

/// 复制而不是链接：App 被挪动或删除时，终端里不会突然找不到程序报错。
fn copy_files() -> Result<(), String> {
    let src = bundled_cli().ok_or("找不到 Tsuba 检查程序，请重新安装 Tsuba")?;
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
        std::fs::write(&rc_path, new).map_err(|e| format!("无法写入 ~/.zshrc：{e}"))?;
    }
    Ok(())
}

pub fn uninstall() -> Result<(), String> {
    let rc_path = zshrc();
    let rc = std::fs::read_to_string(&rc_path).unwrap_or_default();
    if rc.contains(RC_LINE) {
        let kept: Vec<&str> = rc.lines().filter(|l| *l != RC_LINE && *l != RC_COMMENT).collect();
        std::fs::write(&rc_path, kept.join("\n") + "\n").map_err(|e| format!("无法写入 ~/.zshrc：{e}"))?;
    }
    let home = store::home();
    let _ = std::fs::remove_file(home.join("bin/tsuba"));
    let _ = std::fs::remove_file(home.join("tsuba.zsh"));
    Ok(())
}

/// App 升级后，把终端里用的检查程序也更新到同一版本。
pub fn refresh_if_installed() {
    if status().installed {
        let _ = copy_files();
    }
}
