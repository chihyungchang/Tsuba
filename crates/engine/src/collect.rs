//! For each risky action detected, gathers the context needed to judge it plus the offline rule matches.

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

/// Whether npm_package_info found no such package on npm.
// TODO(net.rs): net.rs only reports this as error text; compare a structural field once it has one, so the check
// survives that text being translated.
pub fn is_missing_on_npm(info: &Map<String, Value>) -> bool {
    info.get("error").and_then(|v| v.as_str()) == Some("npm 上不存在这个包")
}

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

/// Auto-run entry points in editor configs: tasks VS Code runs as soon as the folder is opened.
/// Fake interview projects ask you to "just open it in VS Code", which runs code without typing any command.
pub fn editor_config_findings(root: &Path, ctx: &mut Map<String, Value>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let tasks = root.join(".vscode/tasks.json");
    if tasks.is_file() {
        let text = read_limited(&tasks, 300_000);
        if FOLDER_OPEN.is_match(&text) {
            findings.push(
                Finding::new(Severity::Medium, tr!("VS Code runs a task automatically when this folder is opened (runOn: folderOpen), without you typing any command"), ".vscode/tasks.json")
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
        findings.push(Finding::new(Severity::Low, tr!("The project has scripts that run automatically on install or before start"), "package.json").with_snippet(s.chars().take(300).collect::<String>()));
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

    // Show the model the entry file (for example the server.js that npm start actually runs)
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

    // Indirect dependencies in the lockfile: most poisoning hides here, out of sight in package.json
    let locked = lockfile_packages(root);
    if !locked.is_empty() {
        ctx.insert("locked_packages".into(), json!(locked.len()));
        let items: Vec<(String, Option<String>)> = locked.into_iter().map(|(n, v)| (n, Some(v))).collect();
        known_malicious("npm", &items, false, &mut findings);
    }
    (Value::Object(ctx), findings)
}

/// Reads every package locked in the lockfile (indirect dependencies included): package-lock.json, yarn.lock, pnpm-lock.yaml.
pub fn lockfile_packages(root: &Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let lock: Value = serde_json::from_str(&read_limited(&root.join("package-lock.json"), 50_000_000)).unwrap_or(Value::Null);
    if let Some(pkgs) = lock["packages"].as_object() {
        // v2 / v3: keys look like node_modules/a/node_modules/@scope/b
        for (k, v) in pkgs {
            if let (Some(i), Some(ver)) = (k.rfind("node_modules/"), v["version"].as_str()) {
                out.push((k[i + "node_modules/".len()..].to_string(), ver.to_string()));
            }
        }
    } else if lock["dependencies"].is_object() {
        // v1: nested dependencies
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
    // yarn.lock: `"name@^1.0.0", name@^1.2.0:` followed by a line `  version "1.2.3"`
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
    // pnpm-lock.yaml: `  /name@1.2.3:` or `  name@1.2.3:` under packages
    let pnpm = read_limited(&root.join("pnpm-lock.yaml"), 50_000_000);
    for c in PNPM_ENTRY.captures_iter(&pnpm) {
        out.push((c[1].to_string(), c[2].to_string()));
    }
    out.sort();
    out.dedup();
    out
}

static PNPM_ENTRY: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?m)^  '?/?(@?[^@\s'/][^@\s']*)@([0-9][^:('\s]*)'?(?:\([^)]*\))*:\s*$"#).unwrap());

/// `requests==2.31.0`, `flask>=2`, `numpy` → (name, exact version)
fn split_pip(spec: &str) -> (String, Option<String>) {
    let name_end = spec.find(|c: char| "=<>!~[; ".contains(c)).unwrap_or(spec.len());
    let version = spec.split_once("==").map(|(_, v)| v.trim().to_string());
    (spec[..name_end].to_string(), version)
}

/// Whether packages are on a malicious package list: the local OpenSSF list first, then OSV.dev online (updated faster) when `online`.
pub fn known_malicious(ecosystem: &str, items: &[(String, Option<String>)], online: bool, findings: &mut Vec<Finding>) {
    let mut flagged = std::collections::HashSet::new();
    for (name, ver) in items {
        if let Some(hit) = packages::lookup(ecosystem, name, ver.as_deref()) {
            let v = ver.as_deref().map(|v| format!("@{v}")).unwrap_or_default();
            let message = if hit.summary.is_empty() {
                tr!("{package} is on the open-source malicious package list ({id})", package = format!("{name}{v}"), id = hit.id)
            } else {
                tr!("{package} is on the open-source malicious package list ({id}): {summary}", package = format!("{name}{v}"), id = hit.id, summary = hit.summary)
            };
            findings.push(Finding::new(Severity::High, message, name.as_str()).with_source(intel::OSSF));
            flagged.insert(name.clone());
        }
    }
    if online && !items.is_empty() {
        let rest: Vec<(String, Option<String>)> = items.iter().filter(|(n, _)| !flagged.contains(n)).take(2000).cloned().collect();
        for (name, ids) in packages::osv_query(ecosystem, &rest) {
            findings.push(Finding::new(Severity::High, tr!("OSV.dev lists {name} as a malicious package ({ids})", name = name, ids = ids.join(", ")), name.as_str()).with_source(intel::OSV));
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
        if is_missing_on_npm(info) {
            findings.push(Finding::new(Severity::High, tr!("{name} doesn't exist on npm (possibly a typo or dependency confusion)", name = name), name));
            continue;
        }
        let num = |k: &str| info.get(k).and_then(|v| v.as_i64());
        if let Some(age) = num("created_days_ago").filter(|a| *a < 30) {
            findings.push(Finding::new(Severity::Medium, tr!("{name} is a new package, created only {age} days ago", name = name, age = age), name));
        } else if let Some(age) = num("version_published_days_ago").filter(|a| *a < 7) {
            // Release cooldown: hijacked popular packages are usually caught and pulled within hours to days
            let ver = info.get("version").and_then(|v| v.as_str()).unwrap_or("");
            findings.push(Finding::new(Severity::Medium, tr!("{package} was published only {age} days ago and is still inside the 7-day cooldown (poisoned versions from hijacked accounts are usually caught in this window)", package = format!("{name}@{ver}"), age = age), name).with_rule(RELEASE_COOLDOWN));
        }
        if let Some(scripts) = info.get("install_scripts").and_then(|v| v.as_object()) {
            for (k, v) in scripts {
                let v = v.as_str().unwrap_or("");
                findings.push(Finding::new(Severity::Low, tr!("{name} runs its {script} script automatically on install", name = name, script = k), name).with_snippet(v.chars().take(200).collect::<String>()));
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
                        findings.push(Finding::new(Severity::High, tr!("The script downloads straight from the IP address {host}", host = host), url.as_str()));
                    }
                    let ioc = intel::feeds::ioc("urls", url)
                        .or_else(|| intel::feeds::ioc(if net::is_ip(&host) { "ips" } else { "domains" }, &host))
                        .or_else(|| intel::feeds::ioc("domains", &net::registered_domain(&host)));
                    if let Some(family) = ioc {
                        findings.push(Finding::new(Severity::High, tr!("The download address is on the abuse.ch malicious address list ({family})", family = family), url.as_str()).with_source(intel::ABUSECH));
                    }
                    if let Some(age) = age.filter(|a| *a < 90) {
                        let sev = if age < 30 { Severity::High } else { Severity::Medium };
                        findings.push(Finding::new(sev, tr!("The download domain {domain} was registered only {age} days ago", domain = net::registered_domain(&host), age = age), url.as_str()));
                    }
                    if let Some(text) = f.get("text").and_then(|v| v.as_str()).map(String::from) {
                        findings.extend(rules::scan_text(&text, url));
                        findings.extend(intel::yara::scan(text.as_bytes(), url));
                        // Follow one level further: other scripts the script refers to
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
                    findings.push(Finding::new(Severity::Medium, tr!("The command runs a remote script, but its address can't be determined"), cmd));
                }
                item.insert("fetched".into(), json!(fetched));
            }
            Kind::ObfuscatedExec => {
                findings.push(Finding::new(Severity::High, tr!("The command decodes a base64 blob and hands it straight to the shell, so you can't see what it really does (the classic ClickFix pattern)"), cmd));
            }
            Kind::PkgInstall => {
                let pkgs = t.strs("packages");
                if !pkgs.is_empty() {
                    item.insert("packages_info".into(), json!(check_packages(&pkgs, online, &mut findings)));
                } else if let Some(root) = find_project_root(cwd) {
                    let (ctx, fs) = project_context(&root, None);
                    findings.extend(fs);
                    // New and nonexistent packages among the dependencies are hot spots for supply-chain poisoning.
                    // Only the names declared in package.json are known here, not the locked versions, so the release cooldown doesn't apply
                    let deps: Vec<String> = ctx["dependencies"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default();
                    let mut dep_findings = Vec::new();
                    if online {
                        let locked: Vec<(String, Option<String>)> = lockfile_packages(&root).into_iter().map(|(n, v)| (n, Some(v))).collect();
                        let mut online_findings = Vec::new();
                        for (name, ids) in packages::osv_query("npm", &locked[..locked.len().min(2000)]) {
                            online_findings.push(Finding::new(Severity::High, tr!("OSV.dev lists {name} from the lockfile as a malicious package ({ids})", name = name, ids = ids.join(", ")), name.as_str()).with_source(intel::OSV));
                        }
                        // Don't repeat what the local list already reported
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
                    scope: "added from the command line".into(),
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
                        findings.push(Finding::new(Severity::High, tr!("Microsoft has listed {id} as a malicious VS Code extension and removed it from the Marketplace", id = ext), ext.as_str()).with_source(intel::VSCODE));
                        scans.push(json!({ "id": ext, "malicious": true }));
                    } else {
                        // A Marketplace extension's code is only visible once installed; the extension folder watcher checks it right after
                        scans.push(json!({ "id": ext, "note": "installed from the Marketplace; the extension folder watcher checks it once installed" }));
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
                findings.push(Finding::new(Severity::High, tr!("Removing the quarantine flag by hand makes macOS skip its Gatekeeper check; legitimate software almost never asks you to do this"), cmd));
            }
            Kind::Gatekeeper => {
                findings.push(Finding::new(Severity::High, tr!("Turning off or bypassing Gatekeeper lets any unsigned program run"), cmd));
            }
            Kind::Osascript => {
                if ASKS_PASSWORD.is_match(cmd) {
                    findings.push(Finding::new(Severity::Medium, tr!("An AppleScript dialog asks for a password or administrator privileges, a common trick to steal the system password"), cmd));
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
