//! Allowlist: files, projects, extensions, skills and MCP servers the user confirmed as safe no longer raise warnings.
//!
//! Entries are keyed by content fingerprint, not by name: an attacker can reuse a trusted path or name,
//! but once the content changes the fingerprint no longer matches and it is checked again.

use crate::agents::McpServer;
use crate::{collect, extension, net, sha256_file, store};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrustItem {
    /// path:<absolute path>, mcp:<client|config|name> or command:<command line>
    pub key: String,
    pub fingerprint: String,
    /// Name for people to read
    pub label: String,
    pub time: String,
}

fn load() -> Vec<TrustItem> {
    serde_json::from_value(store::load_json("trusted.json")).unwrap_or_default()
}

fn save(list: &[TrustItem]) {
    store::save_json("trusted.json", &json!(list));
}

pub fn list() -> Vec<TrustItem> {
    load()
}

fn path_key(path: &Path) -> String {
    let p = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    format!("path:{}", p.display())
}

/// Content fingerprint. Projects use package.json + git state (node_modules is not hashed);
/// other folders (extensions, skills) include every file's relative path and content.
pub fn fingerprint(path: &Path) -> Option<String> {
    if path.is_file() {
        return sha256_file(path);
    }
    if !path.is_dir() {
        return None;
    }
    if path.join("package.json").is_file() && !extension::looks_like_extension(path) {
        return Some(collect::project_fingerprint(path));
    }
    let mut files = crate::walk_files(path, 20_000);
    files.sort();
    let mut h = Sha256::new();
    for f in files {
        h.update(f.strip_prefix(path).unwrap_or(&f).to_string_lossy().as_bytes());
        h.update(sha256_file(&f).unwrap_or_else(|| format!("size:{}", f.metadata().map(|m| m.len()).unwrap_or(0))));
    }
    Some(net::hex(&h.finalize()))
}

fn upsert(item: TrustItem) {
    let mut list = load();
    list.retain(|t| t.key != item.key);
    list.push(item);
    save(&list);
}

fn matches(key: &str, fingerprint: impl FnOnce() -> Option<String>) -> bool {
    let list = load();
    let Some(item) = list.iter().find(|t| t.key == key) else { return false };
    fingerprint().is_some_and(|fp| fp == item.fingerprint)
}

pub fn trust_path(path: &Path) -> Result<TrustItem, String> {
    let fp = fingerprint(path).ok_or_else(|| tr!("Couldn't read {path}", path = path.display()))?;
    let item = TrustItem { key: path_key(path), fingerprint: fp, label: path.display().to_string(), time: store::now() };
    upsert(item.clone());
    Ok(item)
}

/// The user marked it safe and its content hasn't changed.
pub fn is_trusted_path(path: &Path) -> bool {
    matches(&path_key(path), || fingerprint(path))
}

pub fn trust_mcp(server: &McpServer) -> TrustItem {
    let item = TrustItem {
        key: format!("mcp:{}", server.key()),
        fingerprint: server.fingerprint(),
        label: format!("{} · {} (MCP server)", server.client, server.name),
        time: store::now(),
    };
    upsert(item.clone());
    item
}

pub fn is_trusted_mcp(server: &McpServer) -> bool {
    matches(&format!("mcp:{}", server.key()), || Some(server.fingerprint()))
}

/// What a command's warning consisted of. Ignoring a warning means ignoring exactly these findings:
/// when the remote script, package or project changes and something new turns up, it warns again.
fn findings_fingerprint(findings: &[crate::rules::Finding]) -> String {
    let mut parts: Vec<String> = findings.iter().map(|f| format!("{:?}\u{1f}{}\u{1f}{}\u{1f}{}", f.severity, f.rule, f.location, f.snippet)).collect();
    parts.sort();
    net::hex(&Sha256::digest(parts.join("\u{1e}").as_bytes()))
}

/// "Don't warn again" for a terminal command the user has looked at. Only Warn can be ignored; the caller enforces that,
/// because a Block should keep asking every time.
pub fn ignore_command(command: &str, findings: &[crate::rules::Finding]) -> TrustItem {
    let item = TrustItem { key: format!("command:{command}"), fingerprint: findings_fingerprint(findings), label: command.to_string(), time: store::now() };
    upsert(item.clone());
    item
}

/// The user chose to ignore this command's warning, and the check found the same things again.
pub fn is_ignored_command(command: &str, findings: &[crate::rules::Finding]) -> bool {
    matches(&format!("command:{command}"), || Some(findings_fingerprint(findings)))
}

pub fn remove(key: &str) {
    let mut list = load();
    list.retain(|t| t.key != key);
    save(&list);
}

/// Marks an item as safe: mcp:<key> is an MCP server, anything else (optionally prefixed with path:) is a path.
pub fn trust(key: &str) -> Result<TrustItem, String> {
    match key.strip_prefix("mcp:") {
        Some(k) => crate::agents::user_mcp_servers().iter().find(|s| s.key() == k).map(trust_mcp).ok_or_else(|| tr!("Couldn't find this MCP server; it may have been removed")),
        None => trust_path(Path::new(key.strip_prefix("path:").unwrap_or(key))),
    }
}
