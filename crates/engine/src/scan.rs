//! Scans a folder on demand: Downloads, external drives, code folders.
//!
//! Not a full antivirus sweep: it only picks the places unfamiliar code hides in (installers, scripts, extensions, AI tool
//! skills, projects with auto-run entry points) and skips photos, videos and the like. Batch scans use only the local offline
//! rules and lists (no network, no model); the user can then run a full check with AI on anything suspicious. Items already
//! scanned and unchanged aren't scanned again.

use crate::rules::{Finding, Verdict};
use crate::store::{self, Config};
use crate::{extension, intel};
use serde::{Deserialize, Serialize};
use serde_json::{Map, json};
use std::path::{Path, PathBuf};

/// Single files are picked by extension: installers, extension packages, scripts.
const FILE_EXT: &[&str] = &[
    "dmg", "pkg", "mpkg", "vsix", "sh", "bash", "zsh", "command", "tool", "py", "js", "mjs", "cjs", "ts", "scpt", "applescript",
];

/// Directories not entered: dependencies, version control, system and photo libraries are not where unfamiliar code reaches the user.
const SKIP_DIRS: &[&str] = &[
    "node_modules", ".git", ".hg", ".svn", ".Trash", ".cache", ".npm", ".pnpm-store", ".cargo", ".rustup", "target", "dist", "build",
    "__pycache__", ".venv", "venv", "Library", ".Spotlight-V100", ".fseventsd", ".DocumentRevisions-V100", ".TemporaryItems",
];

const MAX_DEPTH: usize = 8;
const MAX_ITEMS: usize = 3000;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScanHit {
    pub path: String,
    /// installer / extension / skill / project / file
    pub kind: String,
    pub verdict: Verdict,
    pub summary: String,
    pub findings: Vec<Finding>,
    /// Checked fresh in this scan (false means unchanged, reusing the previous result)
    #[serde(default)]
    pub fresh: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct FolderScan {
    pub root: String,
    pub checked: usize,
    pub unchanged: usize,
    /// Items to look at or block, most severe first
    pub hits: Vec<ScanHit>,
    /// True when there was too much to scan everything
    pub truncated: bool,
}

/// Whether a directory is a project worth checking as a whole: it has a package manifest, an editor auto-run config or an AI tool config.
fn is_project(dir: &Path) -> bool {
    ["package.json", ".vscode/tasks.json", ".mcp.json", ".claude/settings.json", "CLAUDE.md"].iter().any(|f| dir.join(f).is_file())
}

fn is_candidate_file(p: &Path) -> bool {
    let ext = p.extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default();
    FILE_EXT.contains(&ext.as_str())
}

/// Finds what to check: projects, extensions and .app bundles as a whole, without going inside; other directories are searched for single files.
pub fn candidates(root: &Path) -> (Vec<PathBuf>, bool) {
    let mut out = Vec::new();
    if root.is_file() {
        return (vec![root.to_path_buf()], false);
    }
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        // A skill is checked as a whole: SKILL.md isn't on the single-file extension list, so walking into it would skip it entirely
        let is_skill = dir.join("SKILL.md").is_file();
        let is_unit = extension::looks_like_extension(&dir) || is_skill || is_project(&dir) || crate::macos::looks_like_volume(&dir) || dir.extension().is_some_and(|e| e == "app");
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

/// A cheap "has it changed" stamp: file size and modification time only, without reading contents. For directories, the newest modification time and the file count.
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

/// After a rule or intel update, old files are rescanned with the new rules (PRD 7.6: catch old files only the updated rules recognize).
/// The language is part of it too, because cached results hold finding messages in the language they were scanned in.
fn rules_version() -> String {
    format!("{}|{}|{}", env!("CARGO_PKG_VERSION"), intel::Manifest::load().updated, crate::i18n::lang().code())
}

/// Scans a folder (or a single file). `progress` receives the path being looked at.
pub fn scan_folder(cfg: &Config, root: &Path, mut progress: impl FnMut(&str)) -> FolderScan {
    // Batch scans use local data only: no network, no model
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
            // An offline report's summary only says AI review is off, so the list shows the most severe finding instead
            let summary = report.findings.iter().max_by_key(|f| f.severity).map(|f| f.message.clone()).unwrap_or(report.summary);
            ScanHit { path: key.clone(), kind: kind.into(), verdict: report.verdict, summary, findings: report.findings, fresh: true }
        };
        fresh_items.insert(key, json!({ "stamp": stamp, "hit": hit }));
        if hit.verdict != Verdict::Allow {
            result.hits.push(hit);
        }
    }
    // Keep only the entries still present; cache entries for other folders stay as they are
    if let Some(old) = cache["items"].as_object_mut() {
        let prefix = format!("{}/", root.display());
        old.retain(|k, _| !k.starts_with(&prefix) && k != &result.root);
        old.extend(fresh_items);
    }
    store::save_json("scan_cache.json", &cache);
    result.hits.sort_by(|a, b| b.verdict.cmp(&a.verdict).then(a.path.cmp(&b.path)));
    result
}

/// Whether the scheduled scan is due.
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

/// A folder path from the config; may start with ~/.
pub fn expand(p: &str) -> PathBuf {
    match p.strip_prefix("~/") {
        Some(rest) => crate::home_dir().join(rest),
        None if p == "~" => crate::home_dir(),
        None => PathBuf::from(p),
    }
}

