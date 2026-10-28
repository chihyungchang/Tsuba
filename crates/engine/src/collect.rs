//! 针对每个识别出的危险动作，收集判断所需的上下文和离线规则命中。

use crate::detect::{Kind, Target};
use crate::rules::{self, Finding, Severity};
use crate::intel::{self, packages};
use crate::store::Config;
use crate::{extension, macos, net, read_limited};
use regex::Regex;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::LazyLock;

pub const SKIP_DIRS: &[&str] = &["node_modules", ".git", "dist", "build", ".next", "coverage", ".turbo", ".cache", "vendor", "__pycache__", ".venv", "venv"];
const SRC_EXT: &[&str] = &["js", "cjs", "mjs", "ts", "jsx", "tsx", "sh", "py", "command"];
const MAX_FILES: usize = 800;
const MAX_FILE_BYTES: usize = 2_000_000;


const RELEASE_COOLDOWN: &str = "release_cooldown";
fn git(root: &Path, args: &[&str]) -> String {
    Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

pub fn find_project_root(cwd: &Path) -> Option<PathBuf> {
    let mut p = cwd.canonicalize().ok()?;
    for _ in 0..6 {
        if p.join("package.json").is_file() {
            return Some(p);
        }
        if !p.pop() {
            break;
        }
    }
    None
}

pub fn project_fingerprint(root: &Path) -> String {
    let mut h = Sha256::new();
    h.update(read_limited(&root.join("package.json"), 200_000));
    h.update(read_limited(&root.join(".vscode/tasks.json"), 200_000));
    h.update(git(root, &["rev-parse", "HEAD"]));
    h.update(git(root, &["status", "--porcelain"]));
    net::hex(&h.finalize())
}

static FOLDER_OPEN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#""runOn"\s*:\s*"folderOpen""#).unwrap());

/// 编辑器配置里的自动执行入口：VS Code 打开文件夹时就会运行的任务。
/// 假面试项目会让人“用 VS Code 打开看看”，不需要敲任何命令就能执行。
pub fn editor_config_findings(root: &Path, ctx: &mut Map<String, Value>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let tasks = root.join(".vscode/tasks.json");
    if tasks.is_file() {
        let text = read_limited(&tasks, 300_000);
        if FOLDER_OPEN.is_match(&text) {
            findings.push(
                Finding::new(Severity::Medium, "VS Code 打开这个文件夹时会自动执行任务（runOn: folderOpen），不需要你敲任何命令", ".vscode/tasks.json")
                    .with_snippet(rules::snippet(&text, 0, text.len().min(300), 0)),
            );
        }
        findings.extend(rules::scan_text(&text, ".vscode/tasks.json"));
        ctx.insert("vscode_tasks".into(), json!(text.chars().take(6000).collect::<String>()));
    }
    for rel in [".vscode/settings.json", ".vscode/launch.json", ".devcontainer/devcontainer.json"] {
        let p = root.join(rel);
        if p.is_file() {
            findings.extend(rules::scan_text(&read_limited(&p, 300_000), rel));
        }
    }
    findings.extend(crate::agents::project_findings(root, ctx));
    findings
}

pub fn project_context(root: &Path, entry: Option<&str>) -> (Value, Vec<Finding>) {
    let mut findings = Vec::new();
    let pkg_text = read_limited(&root.join("package.json"), 30_000);
    let mut ctx = Map::new();
    ctx.insert("root".into(), json!(root.to_string_lossy()));
    ctx.insert("package_json".into(), json!(pkg_text));
    let pkg: Value = serde_json::from_str(&pkg_text).unwrap_or(Value::Null);
    let mut lifecycle = Map::new();
    if let Some(scripts) = pkg["scripts"].as_object() {
        for k in ["preinstall", "install", "postinstall", "prepare", "prestart", "predev"] {
            if let Some(v) = scripts.get(k) {
                lifecycle.insert(k.into(), v.clone());
            }
        }
    }
    if !lifecycle.is_empty() {
        let s = serde_json::to_string(&lifecycle).unwrap_or_default();
        findings.push(Finding::new(Severity::Low, "项目带有安装/启动前自动执行的脚本", "package.json").with_snippet(s.chars().take(300).collect::<String>()));
        for (k, v) in &lifecycle {
            findings.extend(rules::scan_text(v.as_str().unwrap_or(""), &format!("package.json scripts.{k}")));
        }
        ctx.insert("lifecycle_scripts".into(), Value::Object(lifecycle));
    }

    let has_head = !git(root, &["rev-parse", "HEAD"]).is_empty();
    ctx.insert("git".into(), json!({
        "remote": git(root, &["remote", "get-url", "origin"]),
        "commits": git(root, &["rev-list", "--count", "HEAD"]),
        "first_commit": if has_head { git(root, &["log", "--reverse", "--format=%ci %an"]).lines().next().unwrap_or("").to_string() } else { String::new() },
        "last_commit": git(root, &["log", "-1", "--format=%ci %an %s"]),
    }));

    findings.extend(editor_config_findings(root, &mut ctx));

    let mut hit_files = Map::new();
    let files = walk_src(root);
    let truncated = files.len() >= MAX_FILES;
    for p in &files {
        let rel = p.strip_prefix(root).unwrap_or(p).to_string_lossy().to_string();
        let bytes = std::fs::read(p).unwrap_or_default();
        let mut fs = rules::scan_text(&String::from_utf8_lossy(&bytes), &rel);
        fs.extend(intel::yara::scan(&bytes, &rel));
        if !fs.is_empty() {
            hit_files.insert(rel, json!(fs.len()));
            findings.extend(fs);
        }
    }
    if truncated {
        ctx.insert("scan_truncated".into(), json!(true));
    }
    ctx.insert("files_scanned".into(), json!(files.len()));

    // 入口文件内容给模型看（比如 npm start 实际运行的 server.js）
    if let Some(entry) = entry {
        let ep = if Path::new(entry).is_absolute() { PathBuf::from(entry) } else { root.join(entry) };
        if ep.is_file() {
            ctx.insert("entry_file".into(), json!({ "path": entry, "head": read_limited(&ep, 6000) }));
        }
    }
    let heads: Map<String, Value> = hit_files.keys().take(3).map(|rel| (rel.clone(), json!(read_limited(&root.join(rel), 3000)))).collect();
    if !heads.is_empty() {
        ctx.insert("suspicious_file_heads".into(), Value::Object(heads));
    }
    ctx.insert("files_with_hits".into(), Value::Object(hit_files));

    let mut deps: Vec<String> = Vec::new();
    for key in ["dependencies", "devDependencies"] {
        if let Some(o) = pkg[key].as_object() {
            deps.extend(o.keys().cloned());
        }
    }
    deps.truncate(80);
    ctx.insert("dependencies".into(), json!(deps));

    // lockfile 里的间接依赖：大部分投毒藏在这里，package.json 里看不到
    let locked = lockfile_packages(root);
    if !locked.is_empty() {
        ctx.insert("locked_packages".into(), json!(locked.len()));
        let items: Vec<(String, Option<String>)> = locked.into_iter().map(|(n, v)| (n, Some(v))).collect();
        known_malicious("npm", &items, false, &mut findings);
    }
    (Value::Object(ctx), findings)
}

/// 读 lockfile 里锁定的全部包（含间接依赖）：package-lock.json、yarn.lock、pnpm-lock.yaml。
pub fn lockfile_packages(root: &Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let lock: Value = serde_json::from_str(&read_limited(&root.join("package-lock.json"), 50_000_000)).unwrap_or(Value::Null);
    if let Some(pkgs) = lock["packages"].as_object() {
        // v2 / v3：键是 node_modules/a/node_modules/@scope/b
        for (k, v) in pkgs {
            if let (Some(i), Some(ver)) = (k.rfind("node_modules/"), v["version"].as_str()) {
                out.push((k[i + "node_modules/".len()..].to_string(), ver.to_string()));
            }
        }
    } else if lock["dependencies"].is_object() {
        // v1：嵌套的 dependencies
        fn walk(deps: &Value, out: &mut Vec<(String, String)>) {
            for (name, d) in deps.as_object().into_iter().flatten() {
                if let Some(v) = d["version"].as_str() {
                    out.push((name.clone(), v.to_string()));
                }
                walk(&d["dependencies"], out);
            }
        }
        walk(&lock["dependencies"], &mut out);
    }
    // yarn.lock：`"name@^1.0.0", name@^1.2.0:` 下一行是 `  version "1.2.3"`
    let yarn = read_limited(&root.join("yarn.lock"), 50_000_000);
    let mut names: Vec<String> = Vec::new();
    for line in yarn.lines() {
        if !line.starts_with(' ') && line.ends_with(':') && !line.starts_with('#') {
            names = line.trim_end_matches(':').split(", ").map(|s| {
                let s = s.trim_matches('"');
                let at = if let Some(rest) = s.strip_prefix('@') { rest.find('@').map(|i| i + 1) } else { s.find('@') };
                at.map(|i| s[..i].to_string()).unwrap_or_else(|| s.to_string())
            }).collect();
        } else if let Some(v) = line.trim().strip_prefix("version ") {
            let v = v.trim_matches(|c| c == '"' || c == ' ');
            if let Some(n) = names.first() {
                out.push((n.clone(), v.to_string()));
            }
        }
    }
    // pnpm-lock.yaml：packages 下的 `  /name@1.2.3:` 或 `  name@1.2.3:`
    let pnpm = read_limited(&root.join("pnpm-lock.yaml"), 50_000_000);
    for c in PNPM_ENTRY.captures_iter(&pnpm) {
        out.push((c[1].to_string(), c[2].to_string()));
    }
    out.sort();
    out.dedup();
    out
}

static PNPM_ENTRY: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?m)^  '?/?(@?[^@\s'/][^@\s']*)@([0-9][^:('\s]*)'?(?:\([^)]*\))*:\s*$"#).unwrap());

/// `requests==2.31.0`、`flask>=2`、`numpy` → (包名, 确切版本)
fn split_pip(spec: &str) -> (String, Option<String>) {
    let name_end = spec.find(|c: char| "=<>!~[; ".contains(c)).unwrap_or(spec.len());
    let version = spec.split_once("==").map(|(_, v)| v.trim().to_string());
    (spec[..name_end].to_string(), version)
}

/// 包是否在恶意包名单里：先查本地的 OpenSSF 名单，online 时再在线查 OSV.dev（更新更快）。
pub fn known_malicious(ecosystem: &str, items: &[(String, Option<String>)], online: bool, findings: &mut Vec<Finding>) {
    let mut flagged = std::collections::HashSet::new();
    for (name, ver) in items {
        if let Some(hit) = packages::lookup(ecosystem, name, ver.as_deref()) {
            let v = ver.as_deref().map(|v| format!("@{v}")).unwrap_or_default();
            let summary = if hit.summary.is_empty() { String::new() } else { format!("：{}", hit.summary) };
            findings.push(Finding::new(Severity::High, format!("{name}{v} 在开源恶意包名单里（{}）{summary}", hit.id), name.as_str()).with_source(intel::OSSF));
            flagged.insert(name.clone());
        }
    }
    if online && !items.is_empty() {
        let rest: Vec<(String, Option<String>)> = items.iter().filter(|(n, _)| !flagged.contains(n)).take(2000).cloned().collect();
        for (name, ids) in packages::osv_query(ecosystem, &rest) {
            findings.push(Finding::new(Severity::High, format!("{name} 被 OSV.dev 收录为恶意包（{}）", ids.join("、")), name.as_str()).with_source(intel::OSV));
        }
    }
}

fn walk_src(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        let mut entries: Vec<_> = rd.flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let p = e.path();
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_dir() {
                if !SKIP_DIRS.contains(&e.file_name().to_string_lossy().as_ref()) {
                    stack.push(p);
                }
            } else if ft.is_file()
                && p.extension().is_some_and(|x| SRC_EXT.contains(&x.to_string_lossy().as_ref()))
                && e.metadata().map(|m| m.len() as usize <= MAX_FILE_BYTES).unwrap_or(false)
            {
                out.push(p);
                if out.len() >= MAX_FILES {
                    return out;
                }
            }
        }
    }
    out
}

static ASKS_PASSWORD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)password|administrator privileges|display dialog").unwrap());
static ENTRY_FROM_SCRIPT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bnode(?:mon)?\s+(?:--\S+\s+)*([^\s&|;]+\.(?:c|m)?js)\b").unwrap());

fn check_packages(specs: &[String], online: bool, findings: &mut Vec<Finding>) -> Vec<Map<String, Value>> {
    let specs = &specs[..specs.len().min(15)];
    let items: Vec<(String, Option<String>)> = specs.iter().map(|s| net::split_spec(s)).collect();
    known_malicious("npm", &items, online, findings);
    let infos: Vec<Map<String, Value>> = std::thread::scope(|s| {
        let hs: Vec<_> = specs.iter().map(|spec| s.spawn(move || net::npm_package_info(spec))).collect();
        hs.into_iter().map(|h| h.join().unwrap_or_default()).collect()
    });
    for info in &infos {
        let name = info.get("name").and_then(|v| v.as_str()).unwrap_or("");
        if info.get("error").and_then(|v| v.as_str()) == Some("npm 上不存在这个包") {
            findings.push(Finding::new(Severity::High, format!("{name} 在 npm 上不存在（可能是拼写错误或依赖混淆）"), name));
            continue;
        }
        let num = |k: &str| info.get(k).and_then(|v| v.as_i64());
        if let Some(age) = num("created_days_ago").filter(|a| *a < 30) {
            findings.push(Finding::new(Severity::Medium, format!("{name} 是 {age} 天前才创建的新包"), name));
        } else if let Some(age) = num("version_published_days_ago").filter(|a| *a < 7) {
            // 发布冷却期：被盗号的热门包通常几小时到几天内就会被发现并撤下
            let ver = info.get("version").and_then(|v| v.as_str()).unwrap_or("");
            findings.push(Finding::new(Severity::Medium, format!("{name}@{ver} 发布才 {age} 天，还在 7 天冷却期内（被盗号投毒的版本通常在这段时间内被发现）"), name).with_rule(RELEASE_COOLDOWN));
        }
        if let Some(scripts) = info.get("install_scripts").and_then(|v| v.as_object()) {
            for (k, v) in scripts {
                let v = v.as_str().unwrap_or("");
                findings.push(Finding::new(Severity::Low, format!("{name} 安装时会自动执行 {k} 脚本"), name).with_snippet(v.chars().take(200).collect::<String>()));
                findings.extend(rules::scan_text(v, &format!("{name} scripts.{k}")));
            }
        }
    }
    infos
}

fn resolve(cwd: &Path, p: &str) -> PathBuf {
    let expanded = match p.strip_prefix("~/") {
        Some(rest) => crate::home_dir().join(rest),
        None => PathBuf::from(p),
    };
    if expanded.is_absolute() { expanded } else { cwd.join(expanded) }
}

pub fn collect(cfg: &Config, cmd: &str, cwd: &Path, targets: &[Target]) -> (Value, Vec<Finding>) {
    let online = cfg.intel.online_lookup;
    let mut findings = Vec::new();
    let mut items = Vec::new();

    for t in targets {
        let mut item = Map::new();
        item.insert("kind".into(), json!(t.kind));
        if let Value::Object(d) = &t.detail {
            item.extend(d.clone());
        }

        match t.kind {
            Kind::RemoteScript => {
                let mut fetched = Vec::new();
                for url in t.strs("urls").iter().take(2) {
                    let mut f = net::fetch(url, 300_000, 8.0);
                    let host = net::host_of(f.get("final_url").and_then(|v| v.as_str()).unwrap_or(url));
                    let known = net::is_well_known(&host);
                    let age = if known { None } else { net::domain_age_days(&host) };
                    f.insert("host".into(), json!(host));
                    f.insert("well_known_host".into(), json!(known));
                    f.insert("domain_age_days".into(), json!(age));
                    if net::is_ip(&host) {
                        findings.push(Finding::new(Severity::High, format!("脚本直接从 IP 地址 {host} 下载"), url.as_str()));
                    }
                    let ioc = intel::feeds::ioc("urls", url)
                        .or_else(|| intel::feeds::ioc(if net::is_ip(&host) { "ips" } else { "domains" }, &host))
                        .or_else(|| intel::feeds::ioc("domains", &net::registered_domain(&host)));
                    if let Some(family) = ioc {
                        findings.push(Finding::new(Severity::High, format!("下载地址在 abuse.ch 恶意地址名单里（{family}）"), url.as_str()).with_source(intel::ABUSECH));
                    }
                    if let Some(age) = age.filter(|a| *a < 90) {
                        let sev = if age < 30 { Severity::High } else { Severity::Medium };
                        findings.push(Finding::new(sev, format!("下载域名 {} 注册仅 {age} 天", net::registered_domain(&host)), url.as_str()));
                    }
                    if let Some(text) = f.get("text").and_then(|v| v.as_str()).map(String::from) {
                        findings.extend(rules::scan_text(&text, url));
                        findings.extend(intel::yara::scan(text.as_bytes(), url));
                        // 再往下追一层：脚本里引用的其他脚本
                        let nested_urls: Vec<String> = crate::detect::urls_in(&text).into_iter().filter(|u| u != url).take(3).collect();
                        let mut nested = Vec::new();
                        for nu in nested_urls {
                            let mut nf = net::fetch(&nu, 60_000, 5.0);
                            if let Some(nt) = nf.get("text").and_then(|v| v.as_str()).map(String::from) {
                                findings.extend(rules::scan_text(&nt, &nu));
                                nf.insert("text".into(), json!(nt.chars().take(6000).collect::<String>()));
                            }
                            nested.push(Value::Object(nf));
                        }
                        f.insert("nested".into(), json!(nested));
                        f.insert("text".into(), json!(text.chars().take(40_000).collect::<String>()));
                    }
                    fetched.push(Value::Object(f));
                }
                if fetched.is_empty() {
                    findings.push(Finding::new(Severity::Medium, "命令会执行远程脚本，但无法确定脚本地址", cmd));
                }
                item.insert("fetched".into(), json!(fetched));
            }
            Kind::ObfuscatedExec => {
                findings.push(Finding::new(Severity::High, "命令把一段 base64 解码后直接交给 shell 执行，你看不到它真正要做什么（ClickFix 类攻击的典型写法）", cmd));
            }
            Kind::PkgInstall => {
                let pkgs = t.strs("packages");
                if !pkgs.is_empty() {
                    item.insert("packages_info".into(), json!(check_packages(&pkgs, online, &mut findings)));
                } else if let Some(root) = find_project_root(cwd) {
                    let (ctx, fs) = project_context(&root, None);
                    findings.extend(fs);
                    // 依赖里的“新包、不存在的包”是供应链投毒的高发点。
                    // 这里只能看到 package.json 声明的名字，不知道锁定的版本，所以不套用发布冷却期
                    let deps: Vec<String> = ctx["dependencies"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default();
                    let mut dep_findings = Vec::new();
                    if online {
                        let locked: Vec<(String, Option<String>)> = lockfile_packages(&root).into_iter().map(|(n, v)| (n, Some(v))).collect();
                        let mut online_findings = Vec::new();
                        for (name, ids) in packages::osv_query("npm", &locked[..locked.len().min(2000)]) {
                            online_findings.push(Finding::new(Severity::High, format!("lockfile 里的 {name} 被 OSV.dev 收录为恶意包（{}）", ids.join("、")), name.as_str()).with_source(intel::OSV));
                        }
                        // 本地名单已经报过的不重复报
                        online_findings.retain(|f| !findings.iter().any(|x| x.location == f.location && x.severity == Severity::High));
                        findings.extend(online_findings);
                    }
                    let checks: Vec<Value> = check_packages(&deps, false, &mut dep_findings)
                        .into_iter()
                        .filter(|i| i.contains_key("error") || i.get("created_days_ago").and_then(|v| v.as_i64()).unwrap_or(9999) < 30 || i.get("install_scripts").and_then(|v| v.as_object()).is_some_and(|o| !o.is_empty()))
                        .map(Value::Object)
                        .collect();
                    findings.extend(dep_findings.into_iter().filter(|f| f.rule != RELEASE_COOLDOWN));
                    item.insert("project".into(), ctx);
                    item.insert("dependency_checks".into(), json!(checks));
                }
            }
            Kind::PipInstall => {
                let items: Vec<(String, Option<String>)> = t.strs("packages").iter().map(|s| split_pip(s)).collect();
                known_malicious("pypi", &items, online, &mut findings);
                item.insert("packages".into(), json!(items.iter().map(|(n, _)| n).collect::<Vec<_>>()));
            }
            Kind::PkgExec => {
                item.insert("packages_info".into(), json!(check_packages(&t.strs("packages"), online, &mut findings)));
            }
            Kind::ProjectRun => {
                let scan_mode = t.str("manager") == "scan";
                let root = find_project_root(cwd).or_else(|| scan_mode.then(|| cwd.to_path_buf()));
                if let Some(root) = root {
                    let mut entry = None;
                    if t.str("manager") == "node" {
                        entry = Some(t.str("script").to_string());
                    } else if !scan_mode {
                        let pkg: Value = serde_json::from_str(&read_limited(&root.join("package.json"), 30_000)).unwrap_or(Value::Null);
                        let s = t.str("script");
                        let fallback = if s == "run" || s.is_empty() { "start" } else { s };
                        let target_script = pkg["scripts"][s].as_str().or(pkg["scripts"][fallback].as_str()).unwrap_or("").to_string();
                        entry = ENTRY_FROM_SCRIPT.captures(&target_script).map(|c| c[1].to_string());
                        findings.extend(rules::scan_text(&target_script, &format!("package.json scripts.{s}")));
                        item.insert("script_command".into(), json!(target_script));
                    }
                    let (ctx, fs) = project_context(&root, entry.as_deref());
                    findings.extend(fs);
                    item.insert("project".into(), ctx);
                    item.insert("fingerprint".into(), json!(project_fingerprint(&root)));
                }
            }
            Kind::EditorOpen => {
                let dir = resolve(cwd, t.str("path"));
                let dir = dir.canonicalize().unwrap_or(dir);
                if dir.is_dir() {
                    let mut ctx = Map::new();
                    ctx.insert("root".into(), json!(dir.to_string_lossy()));
                    findings.extend(editor_config_findings(&dir, &mut ctx));
                    item.insert("project".into(), Value::Object(ctx));
                    item.insert("fingerprint".into(), json!(project_fingerprint(&dir)));
                }
            }
            Kind::McpAdd => {
                let cmd = t.strs("command");
                let server = crate::agents::McpServer {
                    client: t.str("tool").to_string(),
                    scope: "命令行添加".into(),
                    name: t.str("name").to_string(),
                    command: cmd.first().cloned().unwrap_or_default(),
                    args: cmd.iter().skip(1).cloned().collect(),
                    url: t.str("url").to_string(),
                    env_keys: vec![],
                };
                findings.extend(crate::agents::scan_mcp_server(&server, online));
                item.insert("server".into(), json!(server));
            }
            Kind::ExtensionInstall => {
                let mut scans = Vec::new();
                for ext in t.strs("extensions") {
                    if ext.to_lowercase().ends_with(".vsix") {
                        let (info, fs) = extension::scan_vsix(&resolve(cwd, &ext));
                        findings.extend(fs);
                        scans.push(info);
                    } else if intel::feeds::vscode_malicious(&ext) {
                        findings.push(Finding::new(Severity::High, format!("VS Code 官方已经把 {ext} 列为恶意扩展并下架"), ext.as_str()).with_source(intel::VSCODE));
                        scans.push(json!({ "id": ext, "malicious": true }));
                    } else {
                        // 商店里的扩展要装完才能看到代码；装好后扩展目录监控会马上检查
                        scans.push(json!({ "id": ext, "note": "从扩展商店安装，安装完成后由扩展目录监控检查" }));
                    }
                }
                item.insert("extensions_info".into(), json!(scans));
            }
            Kind::Installer => {
                let mut inspections = Vec::new();
                for p in t.strs("paths").iter().take(2) {
                    let (info, fs) = macos::inspect_path(&resolve(cwd, p).to_string_lossy());
                    findings.extend(fs);
                    inspections.push(info);
                }
                item.insert("inspections".into(), json!(inspections));
            }
            Kind::Quarantine => {
                findings.push(Finding::new(Severity::High, "手动删除隔离标记会让 macOS 跳过 Gatekeeper 检查；正规软件几乎不会要求你这么做", cmd));
            }
            Kind::Gatekeeper => {
                findings.push(Finding::new(Severity::High, "关闭或绕过 Gatekeeper 会让系统放行任何未签名程序", cmd));
            }
            Kind::Osascript => {
                if ASKS_PASSWORD.is_match(cmd) {
                    findings.push(Finding::new(Severity::Medium, "AppleScript 弹窗索要密码或管理员权限，常被用来骗取系统密码", cmd));
                }
            }
        }
        items.push(Value::Object(item));
    }

    let evidence = json!({
        "command": cmd,
        "cwd": cwd.to_string_lossy(),
        "targets": items,
        "findings": findings,
    });
    (evidence, findings)
}
