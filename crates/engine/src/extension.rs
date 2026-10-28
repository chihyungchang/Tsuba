//! VS Code 及其衍生编辑器（Cursor、Windsurf、VSCodium）的扩展：扫描。隔离和恢复见 quarantine.rs。
//!
//! 在扩展商店里装扩展不经过 shell，只能在文件写进扩展目录后马上检查。
//! 发现高危时把扩展目录挪进隔离区，赶在编辑器下次加载它之前。

use crate::rules::{self, CHILD_PROCESS_RULE, Finding, Severity};
use crate::{home_dir, macos, read_limited};
use serde_json::{Map, Value, json};
use std::path::{Path, PathBuf};

const SCAN_EXT: &[&str] = &["js", "cjs", "mjs", "sh", "py", "ps1", "command"];
const MAX_FILES: usize = 1500;

/// 已存在的扩展目录。
pub fn extension_dirs() -> Vec<PathBuf> {
    [".vscode/extensions", ".vscode-insiders/extensions", ".cursor/extensions", ".windsurf/extensions", ".vscode-oss/extensions"]
        .iter()
        .map(|d| home_dir().join(d))
        .filter(|p| p.is_dir())
        .collect()
}

/// 扩展目录里的一个子目录是否像一个已安装的扩展（publisher.name-version）。
pub fn is_extension_dir(p: &Path) -> bool {
    let name = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    !name.starts_with('.') && p.join("package.json").is_file()
}

fn installed_metadata(dir: &Path) -> Option<Value> {
    let list: Value = serde_json::from_str(&read_limited(&dir.parent()?.join("extensions.json"), 5_000_000)).ok()?;
    let name = dir.file_name()?.to_string_lossy().to_string();
    list.as_array()?.iter().find(|e| e["relativeLocation"].as_str() == Some(&name)).map(|e| e["metadata"].clone())
}

/// 扩展自带的 node_modules 里，依赖包的测试和示例代码不会被加载，里面的“可疑写法”多是测试数据。
fn is_dependency_test(root: &Path, p: &Path) -> bool {
    let rel = p.strip_prefix(root).unwrap_or(p).to_string_lossy();
    if !rel.contains("node_modules/") {
        return false;
    }
    let lower = rel.to_lowercase();
    ["/test/", "/tests/", "/__tests__/", "/spec/", "/example/", "/examples/", "/benchmark/"].iter().any(|d| lower.contains(d))
        || [".test.js", ".spec.js", "/test.js"].iter().any(|s| lower.ends_with(s))
}

pub fn scan_extension(dir: &Path) -> (Value, Vec<Finding>) {
    let mut findings = Vec::new();
    let pkg: Value = serde_json::from_str(&read_limited(&dir.join("package.json"), 500_000)).unwrap_or(Value::Null);
    let id = format!("{}.{}", pkg["publisher"].as_str().unwrap_or("?"), pkg["name"].as_str().unwrap_or("?"));
    let mut info = Map::new();
    info.insert("path".into(), json!(dir.to_string_lossy()));
    info.insert("id".into(), json!(id));
    for k in ["displayName", "version", "description", "main", "browser", "activationEvents", "repository", "extensionDependencies", "extensionPack"] {
        if !pkg[k].is_null() {
            info.insert(k.into(), pkg[k].clone());
        }
    }
    info.insert("engines".into(), pkg["engines"].clone());

    if crate::intel::feeds::vscode_malicious(&id) {
        findings.push(Finding::new(Severity::High, format!("VS Code 官方已经把 {id} 列为恶意扩展并下架"), &id).with_source(crate::intel::VSCODE));
    }
    let events: Vec<&str> = pkg["activationEvents"].as_array().map(|a| a.iter().filter_map(|v| v.as_str()).collect()).unwrap_or_default();
    if events.contains(&"*") {
        findings.push(Finding::new(Severity::Low, "扩展在编辑器一启动就激活（activationEvents: *），不管你有没有用到它", &id));
    } else if events.contains(&"onStartupFinished") {
        findings.push(Finding::new(Severity::Low, "扩展在编辑器启动完成后自动激活", &id));
    }

    if let Some(meta) = installed_metadata(dir) {
        if meta["source"].as_str() == Some("vsix") {
            findings.push(Finding::new(Severity::Low, "这个扩展是用 .vsix 文件手动安装的，不是从扩展商店装的", &id));
        }
        info.insert("install_metadata".into(), meta);
    }

    let mut scanned = 0usize;
    let mut hit_files = Map::new();
    for p in crate::walk_files(dir, 20_000) {
        if !p.extension().is_some_and(|x| SCAN_EXT.contains(&x.to_string_lossy().as_ref())) {
            continue;
        }
        if p.metadata().map(|m| m.len() > 5_000_000).unwrap_or(true) || is_dependency_test(dir, &p) {
            continue;
        }
        scanned += 1;
        let rel = p.strip_prefix(dir).unwrap_or(&p).to_string_lossy().to_string();
        let bytes = std::fs::read(&p).unwrap_or_default();
        let loc = format!("{id}/{rel}");
        let mut fs = rules::scan_text(&String::from_utf8_lossy(&bytes), &loc);
        fs.extend(crate::intel::yara::scan(&bytes, &loc));
        // 扩展调用系统命令很常见（语言服务器、git 工具），单独出现不说明问题
        for f in fs.iter_mut().filter(|f| f.rule == CHILD_PROCESS_RULE) {
            f.severity = Severity::Low;
        }
        if !fs.is_empty() {
            hit_files.insert(rel, json!(fs.len()));
            findings.extend(fs);
        }
        if scanned >= MAX_FILES {
            info.insert("scan_truncated".into(), json!(true));
            break;
        }
    }
    info.insert("files_scanned".into(), json!(scanned));
    let heads: Map<String, Value> = hit_files.keys().take(3).map(|rel| (rel.clone(), json!(read_limited(&dir.join(rel), 3000)))).collect();
    if !heads.is_empty() {
        info.insert("suspicious_file_heads".into(), Value::Object(heads));
    }
    info.insert("files_with_hits".into(), Value::Object(hit_files));
    (Value::Object(info), findings)
}

/// .vsix 是 zip 包，解到临时目录后按已安装扩展的方式检查。
pub fn scan_vsix(path: &Path) -> (Value, Vec<Finding>) {
    let Ok(tmp) = tempfile::Builder::new().prefix("tsuba-vsix-").tempdir() else {
        return (json!({ "path": path.to_string_lossy(), "error": "无法创建临时目录" }), vec![]);
    };
    let (code, out) = macos::run(&["ditto", "-x", "-k", &path.to_string_lossy(), &tmp.path().to_string_lossy()], 60);
    if code != 0 {
        return (json!({ "path": path.to_string_lossy(), "error": format!("无法解压：{out}") }), vec![]);
    }
    let (mut info, findings) = scan_extension(&tmp.path().join("extension"));
    info["path"] = json!(path.to_string_lossy());
    (info, findings)
}

/// 编辑器配置目录本身是不是“扩展”：用于 `tsuba scan <目录>` 时自动判断。
pub fn looks_like_extension(dir: &Path) -> bool {
    let pkg: Value = serde_json::from_str(&read_limited(&dir.join("package.json"), 500_000)).unwrap_or(Value::Null);
    !pkg["engines"]["vscode"].is_null()
}
