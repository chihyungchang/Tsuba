//! AI 编程工具的扩展：MCP server、skills、插件里的 hooks，以及项目里给 AI 看的规则文件。
//!
//! 它们和编辑器扩展是同一类风险，而且权限更大：
//! - MCP server 是 AI 工具自动启动的本地程序（常见写法是 `npx -y 某个包`，每次启动都拉最新版本），
//!   还经常拿到 GitHub Token 之类的密钥
//! - skill 里的说明会被 AI 当成指令执行，附带的脚本也会被 AI 运行
//! - 插件可以注册 hooks，在 AI 工具的各个时机执行任意命令
//! - clone 下来的仓库可以自带 .mcp.json、.claude/settings.json（hooks）、CLAUDE.md、.cursorrules，
//!   用 AI 工具打开项目就可能生效，和 VS Code 的 folderOpen 任务一样

use crate::collect::known_malicious;
use crate::detect::{self, Kind};
use crate::rules::{self, Finding, Severity, Verdict};
use crate::{home_dir, intel, net, read_limited};
use serde::Serialize;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize)]
pub struct McpServer {
    /// Claude Code / Claude Desktop / Cursor / VS Code / Windsurf / Codex / 项目
    pub client: String,
    /// 配置文件路径，按项目配置的还带上项目名
    pub scope: String,
    pub name: String,
    pub command: String,
    pub args: Vec<String>,
    pub url: String,
    /// 只记录环境变量的名字，不记录值（里面常有密钥）
    pub env_keys: Vec<String>,
}

impl McpServer {
    pub fn command_line(&self) -> String {
        if !self.url.is_empty() {
            return self.url.clone();
        }
        std::iter::once(self.command.as_str()).chain(self.args.iter().map(String::as_str)).collect::<Vec<_>>().join(" ")
    }

    /// 内容指纹：配置没变就不重复检查
    pub fn key(&self) -> String {
        format!("{}|{}|{}", self.client, self.scope, self.name)
    }

    pub fn fingerprint(&self) -> String {
        net::hex(&<sha2::Sha256 as sha2::Digest>::digest(format!("{}|{:?}", self.command_line(), self.env_keys)))
    }
}

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

/// JSON 配置里的 MCP server。各家写法不同：mcpServers（Claude、Cursor、Windsurf）、
/// servers（VS Code 的 mcp.json）、mcp.servers（VS Code 的 settings.json），
/// Claude Code 的 ~/.claude.json 还按项目分开放在 projects.<路径>.mcpServers 里。
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
        json_servers(client, &format!("{scope}（项目 {name}）"), pv, out);
    }
}

fn read_json_file(p: &Path) -> Option<Value> {
    serde_json::from_str(&read_limited(p, 20_000_000)).ok()
}

/// 用户级 MCP 配置文件：(客户端, 路径)
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
        // Codex：[mcp_servers.<名字>] command / args / env / url
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

/// 项目里自带的 MCP 配置
pub fn project_mcp_servers(root: &Path) -> Vec<McpServer> {
    [".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json"]
        .iter()
        .map(|rel| root.join(rel))
        .filter(|p| p.is_file())
        .flat_map(|p| parse_mcp_config("项目", &p))
        .collect()
}

const LAUNCHERS_NPM: &[&str] = &["npx", "pnpx", "bunx"];
const LAUNCHERS_PYPI: &[&str] = &["uvx", "pipx"];

/// `npx -y @scope/pkg@1.2 --flag` → 包名规格
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
    // 跳过 -y、--yes、--from xxx 之类的参数
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

/// 检查一个 MCP server 的启动方式。online 时会查 npm registry 和 OSV.dev。
pub fn scan_mcp_server(s: &McpServer, online: bool) -> Vec<Finding> {
    let loc = format!("{} · {}", s.client, s.name);
    let line = s.command_line();
    let mut findings = rules::scan_text(&line, &loc);

    if !s.url.is_empty() {
        let host = net::host_of(&s.url);
        if let Some(family) = intel::feeds::ioc("domains", &host).or_else(|| intel::feeds::ioc("ips", &host)) {
            findings.push(Finding::new(Severity::High, format!("MCP server 连接的地址在 abuse.ch 恶意地址名单里（{family}）"), &loc));
        }
        if net::is_ip(&host) && !host.starts_with("127.") && !host.starts_with("10.") && !host.starts_with("192.168.") {
            findings.push(Finding::new(Severity::Medium, format!("MCP server 直接连接一个公网 IP（{host}），没有域名"), &loc));
        }
        return findings;
    }

    // 从临时目录或隐藏目录启动的程序
    let cmd = &s.command;
    if cmd.starts_with("/tmp/") || cmd.starts_with("/private/tmp/") || cmd.starts_with("/var/tmp/") || cmd.contains("/.") && !cmd.contains("/.local/") && !cmd.contains("/.cargo/") && !cmd.contains("/.nvm/") && !cmd.contains("/.bun/") {
        findings.push(Finding::new(Severity::High, format!("MCP server 从临时目录或隐藏目录启动：{cmd}"), &loc));
    }
    // sh -c "..."：把启动命令当成一条 shell 命令来查
    for t in detect::detect(&line) {
        if matches!(t.kind, Kind::RemoteScript | Kind::ObfuscatedExec) {
            findings.push(Finding::new(Severity::High, "MCP server 的启动命令会下载或解码一段脚本直接执行", &loc).with_snippet(line.chars().take(300).collect::<String>()));
        }
    }
    if let Some((eco, spec)) = launched_package(&s.command, &s.args) {
        let (name, version) = if eco == "npm" { net::split_spec(&spec) } else { (spec.split(['=', '<', '>', '[']).next().unwrap_or(&spec).to_string(), spec.split_once("==").map(|(_, v)| v.to_string())) };
        known_malicious(eco, &[(name.clone(), version.clone())], online, &mut findings);
        if version.is_none() {
            findings.push(Finding::new(Severity::Low, format!("没有固定 {name} 的版本，AI 工具每次启动都会下载最新版；包被盗号投毒时会直接中招"), &loc));
        }
        if online && eco == "npm" {
            let info = net::npm_package_info(&spec);
            if info.get("error").and_then(|v| v.as_str()) == Some("npm 上不存在这个包") {
                findings.push(Finding::new(Severity::High, format!("{name} 在 npm 上不存在（可能是拼写错误或名字被抢注）"), &loc));
            } else if let Some(age) = info.get("created_days_ago").and_then(|v| v.as_i64()).filter(|a| *a < 30) {
                findings.push(Finding::new(Severity::Medium, format!("{name} 是 {age} 天前才创建的新包"), &loc));
            }
        }
    }
    let secrets: Vec<&String> = s.env_keys.iter().filter(|k| ["TOKEN", "KEY", "SECRET", "PASSWORD"].iter().any(|w| k.to_uppercase().contains(w))).collect();
    if !secrets.is_empty() {
        findings.push(Finding::new(Severity::Low, format!("这个 server 拿到了密钥：{}", secrets.iter().map(|s| s.as_str()).collect::<Vec<_>>().join("、")), &loc));
    }
    findings
}

/// skill 和插件所在的目录
pub fn skill_roots() -> Vec<PathBuf> {
    let h = home_dir();
    // 只看已安装的：~/.claude/plugins/marketplaces、~/.codex/.tmp 只是插件商店的缓存，没有启用
    [".claude/skills", ".claude/plugins/cache", ".claude/plugins/synced", ".claude/commands", ".claude/agents", ".cursor/skills-cursor", ".cursor/rules", ".codex/skills", ".codex/plugins", ".agents/skills"]
        .iter()
        .map(|d| h.join(d))
        .filter(|p| p.is_dir())
        .collect()
}

const SKIP: &[&str] = &["node_modules", ".git", "__pycache__", ".venv", "venv", "extensions", ".trash"];

/// 找出 root 下所有 skill（含 SKILL.md 的目录）和插件 hooks 配置。
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

/// 检查一个 skill 目录，或一个插件的 hooks.json。
pub fn scan_unit(path: &Path) -> (Value, Vec<Finding>) {
    let mut findings = Vec::new();
    let label = path.strip_prefix(home_dir()).map(|p| format!("~/{}", p.display())).unwrap_or_else(|_| path.display().to_string());
    if path.is_file() {
        // hooks.json：{"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "..."}]}]}}
        let v = read_json_file(path).unwrap_or(Value::Null);
        let mut commands = Vec::new();
        collect_commands(&v, &mut commands);
        for c in &commands {
            findings.extend(rules::scan_text(c, &label));
            for t in detect::detect(c) {
                if matches!(t.kind, Kind::RemoteScript | Kind::ObfuscatedExec) {
                    findings.push(Finding::new(Severity::High, "插件的 hook 会下载或解码一段脚本直接执行", &label).with_snippet(c.chars().take(300).collect::<String>()));
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
    // skill 里的脚本被 AI 运行很正常，调用系统命令只算低风险
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

/// 项目里给 AI 工具看的文件：用 AI 工具打开项目时会被自动读取或执行。
pub fn project_findings(root: &Path, ctx: &mut serde_json::Map<String, Value>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let servers = project_mcp_servers(root);
    for s in &servers {
        findings.push(Finding::new(Severity::Medium, format!("项目自带一个 MCP server（{}），用 Claude Code、Cursor 等打开时会提示你启用它", s.name), &s.scope).with_snippet(s.command_line().chars().take(200).collect::<String>()));
        findings.extend(scan_mcp_server(s, false));
    }
    if !servers.is_empty() {
        ctx.insert("project_mcp_servers".into(), json!(servers));
    }
    // .claude/settings.json 里的 hooks：信任这个目录后，Claude Code 每次调用工具都会执行
    for rel in [".claude/settings.json", ".claude/settings.local.json"] {
        let p = root.join(rel);
        let Some(v) = read_json_file(&p) else { continue };
        let mut commands = Vec::new();
        collect_commands(&v["hooks"], &mut commands);
        if !commands.is_empty() {
            findings.push(Finding::new(Severity::Medium, format!("项目给 Claude Code 配置了 {} 个 hook，信任这个目录后它们会自动执行", commands.len()), rel).with_snippet(commands.join(" ; ").chars().take(300).collect::<String>()));
            for c in &commands {
                findings.extend(rules::scan_text(c, rel));
            }
            ctx.insert("claude_hooks".into(), json!(commands));
        }
    }
    // 规则文件、命令、skill：内容会被 AI 当成指令
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

/// 文件变动时，找出它属于哪个 skill（最近的含 SKILL.md 的上级目录）或哪个插件 hooks.json。
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

/// 一个 skill 的内容指纹：文件列表、大小、修改时间。没变就不重复检查。
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

/// 本机所有 skill 和插件 hooks 的位置（去重）
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
}

/// 体检：扫描本机所有 AI 工具的 MCP server、skill 和插件 hooks。
pub fn scan_all(online: bool) -> Vec<ScanItem> {
    let mut items = Vec::new();
    for s in user_mcp_servers() {
        let findings = scan_mcp_server(&s, online);
        items.push(ScanItem {
            kind: "mcp",
            title: format!("{} · {}", s.client, s.name),
            detail: format!("{}  [{}]", s.command_line().chars().take(160).collect::<String>(), s.scope),
            verdict: rules::offline_verdict(&findings),
            findings,
        });
    }
    for unit in all_units() {
        let (info, findings) = scan_unit(&unit);
        items.push(ScanItem {
            kind: if info["kind"] == "hooks" { "hooks" } else { "skill" },
            title: info["name"].as_str().unwrap_or("hooks").to_string(),
            detail: info["path"].as_str().unwrap_or("").to_string(),
            verdict: rules::offline_verdict(&findings),
            findings,
        });
    }
    items.sort_by(|a, b| b.verdict.cmp(&a.verdict).then(a.kind.cmp(b.kind)).then(a.title.cmp(&b.title)));
    items
}
