//! 白名单：用户确认安全的文件、项目、扩展、skill、MCP server 不再提醒。
//!
//! 按内容指纹记录，而不是按名字：攻击者可以沿用一个被信任过的路径或名字，
//! 但内容一变指纹就对不上，会重新检查。

use crate::agents::McpServer;
use crate::{collect, extension, net, sha256_file, store};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrustItem {
    /// path:<绝对路径> 或 mcp:<客户端|配置|名字>
    pub key: String,
    pub fingerprint: String,
    /// 给人看的名字
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

/// 内容指纹。项目用 package.json + git 状态（不去哈希 node_modules）；
/// 其他目录（扩展、skill）把每个文件的相对路径和内容都算进去。
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
    let fp = fingerprint(path).ok_or_else(|| format!("读不到 {}", path.display()))?;
    let item = TrustItem { key: path_key(path), fingerprint: fp, label: path.display().to_string(), time: store::now() };
    upsert(item.clone());
    Ok(item)
}

/// 用户标记过安全，而且内容没变。
pub fn is_trusted_path(path: &Path) -> bool {
    matches(&path_key(path), || fingerprint(path))
}

pub fn trust_mcp(server: &McpServer) -> TrustItem {
    let item = TrustItem {
        key: format!("mcp:{}", server.key()),
        fingerprint: server.fingerprint(),
        label: format!("{} · {}（MCP server）", server.client, server.name),
        time: store::now(),
    };
    upsert(item.clone());
    item
}

pub fn is_trusted_mcp(server: &McpServer) -> bool {
    matches(&format!("mcp:{}", server.key()), || Some(server.fingerprint()))
}

pub fn remove(key: &str) {
    let mut list = load();
    list.retain(|t| t.key != key);
    save(&list);
}

/// 把列表里的一项标记为安全：mcp:<key> 是 MCP server，其他（可带 path: 前缀）当作路径。
pub fn trust(key: &str) -> Result<TrustItem, String> {
    match key.strip_prefix("mcp:") {
        Some(k) => crate::agents::user_mcp_servers().iter().find(|s| s.key() == k).map(trust_mcp).ok_or_else(|| "找不到这个 MCP server，可能已经被删掉".into()),
        None => trust_path(Path::new(key.strip_prefix("path:").unwrap_or(key))),
    }
}
