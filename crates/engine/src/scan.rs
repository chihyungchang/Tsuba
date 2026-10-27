//! 主动扫描一个文件夹：下载目录、外接硬盘、代码目录。
//!
//! 不是全盘杀毒：只挑陌生代码会藏身的东西——安装包、脚本、扩展、带自动执行入口的项目，
//! 照片视频这类文件直接跳过。批量扫描只用本机的离线规则和名单（不联网、不调模型），
//! 可疑的再由用户单独做一次带 AI 的检查。扫过且没变的不重复扫。

use crate::rules::{Finding, Verdict};
use crate::store::{self, Config};
use crate::{extension, intel};
use serde::{Deserialize, Serialize};
use serde_json::{Map, json};
use std::path::{Path, PathBuf};

/// 单个文件按扩展名挑：安装包、扩展包、脚本。
const FILE_EXT: &[&str] = &[
    "dmg", "pkg", "mpkg", "vsix", "sh", "bash", "zsh", "command", "tool", "py", "js", "mjs", "cjs", "ts", "scpt", "applescript",
];

/// 这些目录不往里走：依赖、版本库、系统和照片库，里面不是用户拿到的“陌生代码”入口。
const SKIP_DIRS: &[&str] = &[
    "node_modules", ".git", ".hg", ".svn", ".Trash", ".cache", ".npm", ".pnpm-store", ".cargo", ".rustup", "target", "dist", "build",
    "__pycache__", ".venv", "venv", "Library", ".Spotlight-V100", ".fseventsd", ".DocumentRevisions-V100", ".TemporaryItems",
];

const MAX_DEPTH: usize = 8;
const MAX_ITEMS: usize = 3000;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScanHit {
    pub path: String,
    /// installer / extension / project / file
    pub kind: String,
    pub verdict: Verdict,
    pub summary: String,
    pub findings: Vec<Finding>,
    /// 这次扫描是新检查的（false 表示内容没变，沿用上次的结果）
    #[serde(default)]
    pub fresh: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct FolderScan {
    pub root: String,
    pub checked: usize,
    pub unchanged: usize,
    /// 需要注意和建议拦截的，严重的在前
    pub hits: Vec<ScanHit>,
    /// 东西太多没扫完时为 true
    pub truncated: bool,
}

/// 一个目录是不是值得作为整体检查的项目：有包清单、编辑器自动执行配置或 AI 工具配置。
fn is_project(dir: &Path) -> bool {
    ["package.json", ".vscode/tasks.json", ".mcp.json", ".claude/settings.json", "CLAUDE.md"].iter().any(|f| dir.join(f).is_file())
}

fn is_candidate_file(p: &Path) -> bool {
    let ext = p.extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default();
    FILE_EXT.contains(&ext.as_str())
}

/// 找出要检查的东西：项目、扩展、.app 作为整体，不再往里走；其他目录继续往下找单个文件。
pub fn candidates(root: &Path) -> (Vec<PathBuf>, bool) {
    let mut out = Vec::new();
    if root.is_file() {
        return (vec![root.to_path_buf()], false);
    }
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        let is_unit = extension::looks_like_extension(&dir) || is_project(&dir) || crate::macos::looks_like_volume(&dir) || dir.extension().is_some_and(|e| e == "app");
        if dir != root && is_unit {
            out.push(dir);
        } else if let Ok(rd) = std::fs::read_dir(&dir) {
            if dir == root && is_project(&dir) {
                out.push(dir.clone());
            }
            for e in rd.flatten() {
                let Ok(ft) = e.file_type() else { continue };
                let p = e.path();
                if ft.is_dir() {
                    let name = e.file_name().to_string_lossy().to_string();
                    let skip = SKIP_DIRS.contains(&name.as_str()) || name.ends_with(".photoslibrary") || name.ends_with(".musiclibrary");
                    if !skip && depth < MAX_DEPTH {
                        stack.push((p, depth + 1));
                    }
                } else if ft.is_file() && is_candidate_file(&p) {
                    out.push(p);
                }
            }
        }
        if out.len() >= MAX_ITEMS {
            out.truncate(MAX_ITEMS);
            return (out, true);
        }
    }
    out.sort();
    (out, false)
}

/// 便宜的“变没变”标记：只看文件大小和修改时间，不读内容。目录取里面最新的修改时间和文件数。
fn quick_stamp(p: &Path) -> String {
    let mtime = |m: &std::fs::Metadata| m.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs()).unwrap_or(0);
    let Ok(meta) = p.metadata() else { return String::new() };
    if meta.is_file() {
        return format!("{}:{}", meta.len(), mtime(&meta));
    }
    let files = crate::walk_files(p, 20_000);
    let newest = files.iter().filter_map(|f| f.metadata().ok()).map(|m| mtime(&m)).max().unwrap_or(0);
    format!("{}:{newest}:{}", files.len(), mtime(&meta))
}

/// 规则或情报更新后，老文件要用新规则重扫一遍（PRD 7.6：把规则更新后才认出来的老文件找出来）。
fn rules_version() -> String {
    format!("{}|{}", env!("CARGO_PKG_VERSION"), intel::Manifest::load().updated)
}

/// 扫描一个文件夹（或单个文件）。progress 收到当前正在看的路径。
pub fn scan_folder(cfg: &Config, root: &Path, mut progress: impl FnMut(&str)) -> FolderScan {
    // 批量扫描只用本机数据：不联网、不调模型
    let cfg = cfg.offline_only();
    let version = rules_version();
    let mut cache = store::load_json("scan_cache.json");
    if !cache.is_object() || cache["version"] != json!(version) {
        cache = json!({ "version": version, "items": {} });
    }
    let (items, truncated) = candidates(root);
    let mut result = FolderScan { root: root.display().to_string(), truncated, ..Default::default() };
    let mut fresh_items = Map::new();
    for p in items {
        let key = p.display().to_string();
        let stamp = quick_stamp(&p);
        let cached = &cache["items"][&key];
        let hit = if cached["stamp"] == json!(stamp) && let Ok(h) = serde_json::from_value::<ScanHit>(cached["hit"].clone()) {
            result.unchanged += 1;
            ScanHit { fresh: false, ..h }
        } else {
            progress(&key);
            result.checked += 1;
            let (kind, _, report) = crate::evaluate_path(&cfg, &p);
            // 离线结论的摘要只是“未启用 AI”，列表里换成最严重的那条证据
            let summary = report.findings.iter().max_by_key(|f| f.severity).map(|f| f.message.clone()).unwrap_or(report.summary);
            ScanHit { path: key.clone(), kind: kind.into(), verdict: report.verdict, summary, findings: report.findings, fresh: true }
        };
        fresh_items.insert(key, json!({ "stamp": stamp, "hit": hit }));
        if hit.verdict != Verdict::Allow {
            result.hits.push(hit);
        }
    }
    // 只保留这次还在的条目，其他文件夹的缓存原样留着
    if let Some(old) = cache["items"].as_object_mut() {
        let prefix = format!("{}/", root.display());
        old.retain(|k, _| !k.starts_with(&prefix) && k != &result.root);
        old.extend(fresh_items);
    }
    store::save_json("scan_cache.json", &cache);
    result.hits.sort_by(|a, b| b.verdict.cmp(&a.verdict).then(a.path.cmp(&b.path)));
    result
}

/// 计划扫描是否到期。
pub fn schedule_due(interval_days: u32) -> bool {
    let last = store::load_json("scan_schedule.json")["last"].as_str().map(String::from).unwrap_or_default();
    let Ok(t) = chrono::NaiveDateTime::parse_from_str(&last, "%Y-%m-%dT%H:%M:%S") else { return true };
    chrono::Local::now().naive_local().signed_duration_since(t) >= chrono::Duration::days(interval_days.max(1) as i64)
}

pub fn mark_scheduled_run() {
    store::save_json("scan_schedule.json", &json!({ "last": store::now() }));
}

pub fn last_scheduled_run() -> Option<String> {
    store::load_json("scan_schedule.json")["last"].as_str().map(String::from)
}

/// 配置里的文件夹路径，支持 ~/ 开头。
pub fn expand(p: &str) -> PathBuf {
    match p.strip_prefix("~/") {
        Some(rest) => crate::home_dir().join(rest),
        None if p == "~" => crate::home_dir(),
        None => PathBuf::from(p),
    }
}

