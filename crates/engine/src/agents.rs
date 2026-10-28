//! Add-ons for AI coding tools: MCP servers, skills, hooks in plugins, and rule files in projects meant for the AI.
//!
//! They carry the same kind of risk as editor extensions, with more power:
//! - An MCP server is a local program the AI tool starts on its own (often `npx -y some-package`, which pulls the latest
//!   version on every start), and it often gets secrets such as a GitHub token
//! - The AI follows a skill's instructions and runs the scripts that come with it
//! - Plugins can register hooks that run arbitrary commands at various points in the AI tool
//! - A cloned repository can ship its own .mcp.json, .claude/settings.json (hooks), CLAUDE.md or .cursorrules, which may take
//!   effect as soon as the project is opened in an AI tool, just like VS Code's folderOpen tasks

use crate::collect::known_malicious;
use crate::detect::{self, Kind};
use crate::rules::{self, Finding, Severity, Verdict};
use crate::{home_dir, intel, net, read_limited};
use serde::Serialize;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize)]
pub struct McpServer {
    /// Claude Code / Claude Desktop / Cursor / VS Code / Windsurf / Codex / the project
    pub client: String,
    /// Config file path; per-project entries also carry the project name (see `scope_label`)
    pub scope: String,
    pub name: String,
    pub command: String,
    pub args: Vec<String>,
    pub url: String,
    /// Only the names of environment variables, never their values (they often hold secrets)
    pub env_keys: Vec<String>,
}

impl McpServer {
    pub fn command_line(&self) -> String {
        if !self.url.is_empty() {
            return self.url.clone();
        }
        std::iter::once(self.command.as_str()).chain(self.args.iter().map(String::as_str)).collect::<Vec<_>>().join(" ")
    }

    /// Identity of the server. Saved in trusted.json and ai_seen.json, so its format (scope included) must not change.
    pub fn key(&self) -> String {
        format!("{}|{}|{}", self.client, self.scope, self.name)
    }

    /// Content fingerprint: an unchanged config isn't checked again
    pub fn fingerprint(&self) -> String {
        net::hex(&<sha2::Sha256 as sha2::Digest>::digest(format!("{}|{:?}", self.command_line(), self.env_keys)))
    }

    /// The scope for display, with the project marker translated.
    pub fn scope_label(&self) -> String {
        match self.scope.strip_suffix(PROJECT_SCOPE_CLOSE).and_then(|s| s.rsplit_once(PROJECT_SCOPE_OPEN)) {
            Some((config, project)) => tr!("{config} (project {project})", config = config, project = project),
            None => self.scope.clone(),
        }
    }
}

/// Marks the per-project servers in ~/.claude.json: "<config>（项目 <name>）". The scope is part of the key saved on disk,
/// so this text stays fixed whatever the language; `scope_label` translates it for display.
const PROJECT_SCOPE_OPEN: &str = "（项目 ";
const PROJECT_SCOPE_CLOSE: &str = "）";

fn server_from(client: &str, scope: &str, name: &str, s: &Value) -> McpServer {
    McpServer {
        client: client.into(),
        scope: scope.into(),
        name: name.into(),
        command: s["command"].as_str().unwrap_or("").into(),
        args: s["args"].as_array().into_iter().flatten().filter_map(|a| a.as_str().map(String::from)).collect(),
        url: s["url"].as_str().or(s["serverUrl"].as_str()).unwrap_or("").into(),
        env_keys: s["env"].as_object().map(|o| o.keys().cloned().collect()).unwrap_or_default(),
    }
}

/// MCP servers in a JSON config. Each client writes them differently: mcpServers (Claude, Cursor, Windsurf),
/// servers (VS Code's mcp.json), mcp.servers (VS Code's settings.json), and Claude Code's ~/.claude.json also keeps
/// per-project ones under projects.<path>.mcpServers.
fn json_servers(client: &str, scope: &str, v: &Value, out: &mut Vec<McpServer>) {
    for key in ["mcpServers", "servers"] {
        for (name, s) in v[key].as_object().into_iter().flatten() {
            if s.is_object() {
                out.push(server_from(client, scope, name, s));
            }
        }
    }
    if v["mcp"].is_object() {
        json_servers(client, scope, &v["mcp"], out);
    }
    for (proj, pv) in v["projects"].as_object().into_iter().flatten() {
        let name = Path::new(proj).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| proj.clone());
        json_servers(client, &format!("{scope}{PROJECT_SCOPE_OPEN}{name}{PROJECT_SCOPE_CLOSE}"), pv, out);
    }
}

fn read_json_file(p: &Path) -> Option<Value> {
    serde_json::from_str(&read_limited(p, 20_000_000)).ok()
}

/// User-level MCP config files: (client, path)
pub fn user_mcp_configs() -> Vec<(&'static str, PathBuf)> {
    let h = home_dir();
    let app = h.join("Library/Application Support");
    vec![
        ("Claude Code", h.join(".claude.json")),
        ("Claude Desktop", app.join("Claude/claude_desktop_config.json")),
        ("Cursor", h.join(".cursor/mcp.json")),
        ("VS Code", app.join("Code/User/mcp.json")),
        ("VS Code", app.join("Code/User/settings.json")),
        ("Windsurf", h.join(".codeium/windsurf/mcp_config.json")),
        ("Codex", h.join(".codex/config.toml")),
    ]
}

pub fn parse_mcp_config(client: &str, path: &Path) -> Vec<McpServer> {
    let mut out = Vec::new();
    let scope = path.to_string_lossy().replace(&*home_dir().to_string_lossy(), "~");
    if path.extension().is_some_and(|e| e == "toml") {
        // Codex: [mcp_servers.<name>] command / args / env / url
        let Ok(v) = read_limited(path, 5_000_000).parse::<toml::Table>() else { return out };
        for (name, s) in v.get("mcp_servers").and_then(|t| t.as_table()).into_iter().flatten() {
            let Ok(s) = serde_json::to_value(s) else { continue };
            out.push(server_from(client, &scope, name, &s));
        }
    } else if let Some(v) = read_json_file(path) {
        json_servers(client, &scope, &v, &mut out);
    }
    out
}

pub fn user_mcp_servers() -> Vec<McpServer> {
    user_mcp_configs().iter().filter(|(_, p)| p.is_file()).flat_map(|(c, p)| parse_mcp_config(c, p)).collect()
}

/// MCP configs that ship inside a project
pub fn project_mcp_servers(root: &Path) -> Vec<McpServer> {
    [".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json"]
        .iter()
        .map(|rel| root.join(rel))
        .filter(|p| p.is_file())
        .flat_map(|p| parse_mcp_config(&tr!("Project"), &p))
        .collect()
}

const LAUNCHERS_NPM: &[&str] = &["npx", "pnpx", "bunx"];
const LAUNCHERS_PYPI: &[&str] = &["uvx", "pipx"];

/// `npx -y @scope/pkg@1.2 --flag` → package spec
fn launched_package(command: &str, args: &[String]) -> Option<(&'static str, String)> {
    let prog = command.rsplit('/').next().unwrap_or(command);
    let (eco, rest): (&str, &[String]) = if LAUNCHERS_NPM.contains(&prog) {
        ("npm", args)
    } else if LAUNCHERS_PYPI.contains(&prog) {
        ("pypi", if prog == "pipx" && args.first().is_some_and(|a| a == "run") { &args[1..] } else { args })
    } else if (matches!(prog, "pnpm" | "yarn" | "bun") && args.first().is_some_and(|a| a == "dlx" || a == "x"))
        || (prog == "npm" && args.first().is_some_and(|a| a == "exec"))
    {
        ("npm", &args[1..])
    } else {
        return None;
    };
    // Skip options such as -y, --yes and --from xxx
    let mut skip = false;
    for a in rest {
        if skip {
            skip = false;
        } else if matches!(a.as_str(), "--from" | "-p" | "--package" | "--python") {
            skip = true;
        } else if !a.starts_with('-') {
            return Some((eco, a.clone()));
        }
    }
    None
}

/// Checks how an MCP server is launched. With `online`, also queries the npm registry and OSV.dev.
pub fn scan_mcp_server(s: &McpServer, online: bool) -> Vec<Finding> {
    let loc = format!("{} · {}", s.client, s.name);
    let line = s.command_line();
    let mut findings = rules::scan_text(&line, &loc);

    if !s.url.is_empty() {
        let host = net::host_of(&s.url);
        if let Some(family) = intel::feeds::ioc("domains", &host).or_else(|| intel::feeds::ioc("ips", &host)) {
            findings.push(Finding::new(Severity::High, tr!("The MCP server connects to an address on the abuse.ch malicious address list ({family})", family = family), &loc).with_source(intel::ABUSECH));
        }
        if net::is_ip(&host) && !host.starts_with("127.") && !host.starts_with("10.") && !host.starts_with("192.168.") {
            findings.push(Finding::new(Severity::Medium, tr!("The MCP server connects straight to a public IP ({host}) with no domain name", host = host), &loc));
        }
        return findings;
    }

    // Programs launched from a temporary or hidden directory
    let cmd = &s.command;
    if cmd.starts_with("/tmp/") || cmd.starts_with("/private/tmp/") || cmd.starts_with("/var/tmp/") || cmd.contains("/.") && !cmd.contains("/.local/") && !cmd.contains("/.cargo/") && !cmd.contains("/.nvm/") && !cmd.contains("/.bun/") {
        findings.push(Finding::new(Severity::High, tr!("The MCP server is launched from a temporary or hidden directory: {command}", command = cmd), &loc));
    }
    // sh -c "...": check the launch command as a shell command
    for t in detect::detect(&line) {
        if matches!(t.kind, Kind::RemoteScript | Kind::ObfuscatedExec) {
            findings.push(Finding::new(Severity::High, tr!("The MCP server's launch command downloads or decodes a script and runs it directly"), &loc).with_snippet(line.chars().take(300).collect::<String>()));
        }
    }
    if let Some((eco, spec)) = launched_package(&s.command, &s.args) {
        let (name, version) = if eco == "npm" { net::split_spec(&spec) } else { (spec.split(['=', '<', '>', '[']).next().unwrap_or(&spec).to_string(), spec.split_once("==").map(|(_, v)| v.to_string())) };
        known_malicious(eco, &[(name.clone(), version.clone())], online, &mut findings);
        if version.is_none() {
            findings.push(Finding::new(Severity::Low, tr!("{name} isn't pinned to a version, so the AI tool downloads the latest one on every start; if the package is hijacked and poisoned, you get it right away", name = name), &loc));
        }
        if online && eco == "npm" {
            let info = net::npm_package_info(&spec);
            if net::is_missing_package(&info) {
                findings.push(Finding::new(Severity::High, tr!("{name} doesn't exist on npm (possibly a typo or a squatted name)", name = name), &loc));
            } else if let Some(age) = info.get("created_days_ago").and_then(|v| v.as_i64()).filter(|a| *a < 30) {
                findings.push(Finding::new(Severity::Medium, tr!("{name} is a new package, created only {age} days ago", name = name, age = age), &loc));
            }
        }
    }
    let secrets: Vec<&String> = s.env_keys.iter().filter(|k| ["TOKEN", "KEY", "SECRET", "PASSWORD"].iter().any(|w| k.to_uppercase().contains(w))).collect();
    if !secrets.is_empty() {
        findings.push(Finding::new(Severity::Low, tr!("This server is given secrets: {names}", names = secrets.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")), &loc));
    }
    findings
}

/// Directories that hold skills and plugins
pub fn skill_roots() -> Vec<PathBuf> {
    let h = home_dir();
    // Installed ones only: ~/.claude/plugins/marketplaces and ~/.codex/.tmp are just plugin store caches, not enabled
    [".claude/skills", ".claude/plugins/cache", ".claude/plugins/synced", ".claude/commands", ".claude/agents", ".cursor/skills-cursor", ".cursor/rules", ".codex/skills", ".codex/plugins", ".agents/skills"]
        .iter()
        .map(|d| h.join(d))
        .filter(|p| p.is_dir())
        .collect()
}

const SKIP: &[&str] = &["node_modules", ".git", "__pycache__", ".venv", "venv", "extensions", ".trash"];

/// Finds every skill (a directory with SKILL.md) and plugin hooks config under root.
pub fn find_units(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![(root.to_path_buf(), 0)];
    while let Some((dir, depth)) = stack.pop() {
        if dir.join("SKILL.md").is_file() {
            out.push(dir);
            continue;
        }
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            let name = e.file_name().to_string_lossy().to_string();
            if e.file_type().is_ok_and(|t| t.is_dir()) && depth < 8 && !SKIP.contains(&name.as_str()) {
                stack.push((p, depth + 1));
            } else if name == "hooks.json" {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

const TEXT_EXT: &[&str] = &["md", "txt", "py", "sh", "bash", "zsh", "js", "mjs", "cjs", "ts", "json", "yaml", "yml", "toml", "rb", "ps1", "command"];

/// Checks a skill directory or a plugin's hooks.json.
pub fn scan_unit(path: &Path) -> (Value, Vec<Finding>) {
    let mut findings = Vec::new();
    let label = path.strip_prefix(home_dir()).map(|p| format!("~/{}", p.display())).unwrap_or_else(|_| path.display().to_string());
    if path.is_file() {
        // hooks.json: {"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "..."}]}]}}
        let v = read_json_file(path).unwrap_or(Value::Null);
        let mut commands = Vec::new();
        collect_commands(&v, &mut commands);
        for c in &commands {
            findings.extend(rules::scan_text(c, &label));
            for t in detect::detect(c) {
                if matches!(t.kind, Kind::RemoteScript | Kind::ObfuscatedExec) {
                    findings.push(Finding::new(Severity::High, tr!("The plugin's hook downloads or decodes a script and runs it directly"), &label).with_snippet(c.chars().take(300).collect::<String>()));
                }
            }
        }
        return (json!({ "path": label, "kind": "hooks", "commands": commands }), findings);
    }
    let mut files = 0;
    for p in crate::walk_files(path, 400) {
        if !p.extension().is_some_and(|x| TEXT_EXT.contains(&x.to_string_lossy().as_ref())) || p.metadata().map(|m| m.len() > 2_000_000).unwrap_or(true) {
            continue;
        }
        files += 1;
        let bytes = std::fs::read(&p).unwrap_or_default();
        let rel = format!("{label}/{}", p.strip_prefix(path).unwrap_or(&p).display());
        let mut fs = rules::scan_text(&String::from_utf8_lossy(&bytes), &rel);
        fs.extend(intel::yara::scan(&bytes, &rel));
        if rules::is_doc(&rel) {
            rules::soften_for_docs(&mut fs);
        }
        findings.extend(fs);
    }
    // The AI running a skill's scripts is normal, so running system commands is only low risk
    for f in findings.iter_mut().filter(|f| f.rule == rules::CHILD_PROCESS_RULE) {
        f.severity = Severity::Low;
    }
    let name = read_limited(&path.join("SKILL.md"), 4000).lines().find_map(|l| l.strip_prefix("name:").map(|n| n.trim().to_string())).unwrap_or_else(|| path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default());
    (json!({ "path": label, "kind": "skill", "name": name, "files": files }), findings)
}

fn collect_commands(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::Object(o) => {
            if let Some(c) = o.get("command").and_then(|c| c.as_str()) {
                out.push(c.to_string());
            }
            o.values().for_each(|x| collect_commands(x, out));
        }
        Value::Array(a) => a.iter().for_each(|x| collect_commands(x, out)),
        _ => {}
    }
}

/// Files in a project meant for AI tools: read or run automatically when the project is opened in an AI tool.
pub fn project_findings(root: &Path, ctx: &mut serde_json::Map<String, Value>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let servers = project_mcp_servers(root);
    for s in &servers {
        findings.push(Finding::new(Severity::Medium, tr!("The project ships its own MCP server ({name}); Claude Code, Cursor and similar tools will ask you to enable it when you open the project", name = s.name), &s.scope).with_snippet(s.command_line().chars().take(200).collect::<String>()));
        findings.extend(scan_mcp_server(s, false));
    }
    if !servers.is_empty() {
        ctx.insert("project_mcp_servers".into(), json!(servers));
    }
    // Hooks in .claude/settings.json: once the folder is trusted, Claude Code runs them on every tool call
    for rel in [".claude/settings.json", ".claude/settings.local.json"] {
        let p = root.join(rel);
        let Some(v) = read_json_file(&p) else { continue };
        let mut commands = Vec::new();
        collect_commands(&v["hooks"], &mut commands);
        if !commands.is_empty() {
            findings.push(Finding::new(Severity::Medium, tr!("The project configures {count} hooks for Claude Code that run automatically once you trust this folder", count = commands.len()), rel).with_snippet(commands.join(" ; ").chars().take(300).collect::<String>()));
            for c in &commands {
                findings.extend(rules::scan_text(c, rel));
            }
            ctx.insert("claude_hooks".into(), json!(commands));
        }
    }
    // Rule files, commands and skills: the AI takes their contents as instructions
    let mut docs = vec![];
    for rel in ["CLAUDE.md", "AGENTS.md", ".cursorrules", ".windsurfrules", ".github/copilot-instructions.md"] {
        if root.join(rel).is_file() {
            docs.push(root.join(rel));
        }
    }
    for dir in [".claude/skills", ".claude/commands", ".claude/agents", ".cursor/rules"] {
        if root.join(dir).is_dir() {
            docs.extend(crate::walk_files(&root.join(dir), 200));
        }
    }
    for p in docs {
        let rel = p.strip_prefix(root).unwrap_or(&p).to_string_lossy().to_string();
        let mut fs = rules::scan_text(&read_limited(&p, 1_000_000), &rel);
        if rules::is_doc(&rel) {
            rules::soften_for_docs(&mut fs);
        }
        findings.extend(fs);
    }
    findings
}

/// When a file changes, finds which skill (nearest parent with SKILL.md) or plugin hooks.json it belongs to.
pub fn unit_of(path: &Path) -> Option<PathBuf> {
    if path.file_name().is_some_and(|n| n == "hooks.json") {
        return Some(path.to_path_buf());
    }
    let roots = skill_roots();
    let mut p = path.to_path_buf();
    loop {
        if p.join("SKILL.md").is_file() {
            return Some(p);
        }
        if roots.contains(&p) || !p.pop() {
            return None;
        }
    }
}

/// A skill's content fingerprint: file list, sizes and modification times. Unchanged skills aren't checked again.
pub fn unit_fingerprint(path: &Path) -> String {
    let files = if path.is_file() { vec![path.to_path_buf()] } else { crate::walk_files(path, 400) };
    let mut parts: Vec<String> = files
        .iter()
        .map(|f| {
            let m = f.metadata().ok();
            format!("{}:{}:{:?}", f.display(), m.as_ref().map_or(0, |m| m.len()), m.and_then(|m| m.modified().ok()))
        })
        .collect();
    parts.sort();
    net::hex(&<sha2::Sha256 as sha2::Digest>::digest(parts.join("\n")))
}

/// Locations of every skill and plugin hooks config on this Mac (deduplicated)
pub fn all_units() -> Vec<PathBuf> {
    let mut seen = std::collections::HashSet::new();
    skill_roots().iter().flat_map(|r| find_units(r)).filter(|u| seen.insert(u.canonicalize().unwrap_or(u.clone()))).collect()
}

#[derive(Serialize)]
pub struct ScanItem {
    pub kind: &'static str,
    pub title: String,
    pub detail: String,
    pub verdict: Verdict,
    pub findings: Vec<Finding>,
    /// Used when marking as safe: mcp:<key>, or the skill / hooks path
    pub trust_key: String,
}

/// Health Check: scans the MCP servers, skills and plugin hooks of every AI tool on this Mac. Items marked safe and unchanged aren't reported again.
pub fn scan_all(online: bool) -> Vec<ScanItem> {
    let mut items = Vec::new();
    for s in user_mcp_servers() {
        let findings = if crate::trust::is_trusted_mcp(&s) { vec![] } else { scan_mcp_server(&s, online) };
        items.push(ScanItem {
            kind: "mcp",
            title: format!("{} · {}", s.client, s.name),
            detail: format!("{}  [{}]", s.command_line().chars().take(160).collect::<String>(), s.scope_label()),
            verdict: rules::offline_verdict(&findings),
            findings,
            trust_key: format!("mcp:{}", s.key()),
        });
    }
    for unit in all_units() {
        let (info, findings) = scan_unit(&unit);
        let findings = if crate::trust::is_trusted_path(&unit) { vec![] } else { findings };
        items.push(ScanItem {
            kind: if info["kind"] == "hooks" { "hooks" } else { "skill" },
            title: info["name"].as_str().unwrap_or("hooks").to_string(),
            detail: info["path"].as_str().unwrap_or("").to_string(),
            verdict: rules::offline_verdict(&findings),
            findings,
            trust_key: unit.to_string_lossy().to_string(),
        });
    }
    items.sort_by(|a, b| b.verdict.cmp(&a.verdict).then(a.kind.cmp(b.kind)).then(a.title.cmp(&b.title)));
    items
}
