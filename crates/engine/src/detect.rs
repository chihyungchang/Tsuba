//! 识别一条 shell 命令里有哪些需要检查的危险动作。
//!
//! 只做语法层面的识别，不联网、不读文件，保证足够快。

use regex::Regex;
use serde::Serialize;
use serde_json::{Value, json};
use std::sync::LazyLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    RemoteScript,
    ObfuscatedExec,
    PkgInstall,
    PkgExec,
    PipInstall,
    ProjectRun,
    EditorOpen,
    McpAdd,
    ExtensionInstall,
    Installer,
    Quarantine,
    Gatekeeper,
    Osascript,
}

#[derive(Clone, Debug, Serialize)]
pub struct Target {
    pub kind: Kind,
    pub detail: Value,
}

impl Target {
    pub fn new(kind: Kind, detail: Value) -> Self {
        Target { kind, detail }
    }

    pub fn strs(&self, key: &str) -> Vec<String> {
        self.detail[key].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default()
    }

    pub fn str(&self, key: &str) -> &str {
        self.detail[key].as_str().unwrap_or("")
    }
}

// 远程脚本直接交给解释器执行：curl ... | bash、bash <(curl ...)、sh -c "$(curl ...)"
const INTERP: &str = r"(?:sudo\s+(?:-\S+\s+)*)?(?:env\s+)?(?:/\S*/)?(?:ba|z|da|k|fi)?sh|python3?|node|perl|ruby|osascript";

fn rx(s: &str) -> Regex {
    Regex::new(s).expect("detect 正则无效")
}

static PIPE_TO_SHELL: LazyLock<Regex> = LazyLock::new(|| rx(&format!(r"\b(?:curl|wget|fetch)\b[^|;&]*\|\s*(?:{INTERP})\b")));
static PROCESS_SUBST: LazyLock<Regex> = LazyLock::new(|| rx(&format!(r"(?:{INTERP}|source|\.)\s+<\(\s*(?:curl|wget)\b")));
static CMD_SUBST: LazyLock<Regex> = LazyLock::new(|| rx(&format!(r#"(?:{INTERP}|eval)\s+(?:-c\s+)?["']?\$\(\s*(?:curl|wget)\b"#)));
// echo xxx | base64 -d | bash、bash -c "$(echo xxx | base64 --decode)"：ClickFix 页面最常让人粘贴的形态
static B64_PIPE: LazyLock<Regex> = LazyLock::new(|| rx(&format!(r"base64\s+(?:-\w*[dD]\w*|--decode)\b[^;&]*\|\s*(?:{INTERP})\b")));
static B64_SUBST: LazyLock<Regex> = LazyLock::new(|| rx(&format!(r#"(?:{INTERP}|eval)\s+(?:-c\s+)?["']?\$\([^)]*base64\s+(?:-\w*[dD]|--decode)"#)));
static URL: LazyLock<Regex> = LazyLock::new(|| rx(r#"https?://[^\s'"|;&)]+"#));
static SPLIT: LazyLock<Regex> = LazyLock::new(|| rx(r"\s*(?:;|&&|\|\||\|)\s*"));
static ASSIGN: LazyLock<Regex> = LazyLock::new(|| rx(r"^[A-Za-z_][A-Za-z0-9_]*="));
static INSTALLER_FILE: LazyLock<Regex> = LazyLock::new(|| rx(r"(?i)\.(?:dmg|pkg|mpkg|app)/?$"));

const PKG_MANAGERS: &[&str] = &["npm", "pnpm", "yarn", "bun"];
const INSTALL_SUBCMDS: &[&str] = &["install", "i", "ci", "add", "isntall", "in"];
const RUN_SUBCMDS: &[&str] = &["start", "run", "dev", "test", "exec", "serve"];
const EDITORS: &[&str] = &["code", "code-insiders", "cursor", "windsurf", "codium"];
/// 在当前目录启动就会读取项目里的 MCP 配置、hooks、CLAUDE.md 的 AI 编程工具
const AI_CLIS: &[&str] = &["claude", "codex", "gemini"];

/// 按 ; && || | 切成多段，每段用 shell 规则分词。分词失败时退回空格切分。
fn split_commands(cmd: &str) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    for part in SPLIT.split(cmd) {
        if part.trim().is_empty() {
            continue;
        }
        let mut toks = shlex::split(part).unwrap_or_else(|| part.split_whitespace().map(String::from).collect());
        // 去掉前面的环境变量赋值和 sudo
        while let Some(t) = toks.first() {
            if ASSIGN.is_match(t) || matches!(t.as_str(), "sudo" | "command" | "exec" | "time" | "nohup") {
                toks.remove(0);
            } else {
                break;
            }
        }
        if !toks.is_empty() {
            out.push(toks);
        }
    }
    out
}

fn positional(args: &[String]) -> Vec<String> {
    args.iter().filter(|a| !a.starts_with('-')).cloned().collect()
}

pub fn detect(cmd: &str) -> Vec<Target> {
    let mut targets = Vec::new();
    let cmd = cmd.trim();
    if cmd.is_empty() {
        return targets;
    }

    if PIPE_TO_SHELL.is_match(cmd) || PROCESS_SUBST.is_match(cmd) || CMD_SUBST.is_match(cmd) {
        let urls: Vec<&str> = URL.find_iter(cmd).map(|m| m.as_str()).collect();
        targets.push(Target::new(Kind::RemoteScript, json!({ "urls": urls })));
    }
    if B64_PIPE.is_match(cmd) || B64_SUBST.is_match(cmd) {
        targets.push(Target::new(Kind::ObfuscatedExec, json!({})));
    }

    for toks in split_commands(cmd) {
        let prog = toks[0].rsplit('/').next().unwrap_or("").to_string();
        let args = &toks[1..];

        if PKG_MANAGERS.contains(&prog.as_str()) {
            let sub_idx = args.iter().position(|a| !a.starts_with('-'));
            let sub = sub_idx.map(|i| args[i].as_str()).unwrap_or("");
            let rest = sub_idx.map(|i| positional(&args[i + 1..])).unwrap_or_default();
            if INSTALL_SUBCMDS.contains(&sub) || (prog == "yarn" && sub.is_empty()) {
                targets.push(Target::new(Kind::PkgInstall, json!({ "manager": prog, "packages": rest })));
            } else if RUN_SUBCMDS.contains(&sub) || (prog == "yarn" && !sub.is_empty()) {
                if (prog == "npm" || prog == "pnpm") && sub == "exec" {
                    targets.push(Target::new(Kind::PkgExec, json!({ "manager": prog, "packages": &rest[..rest.len().min(1)] })));
                } else {
                    targets.push(Target::new(Kind::ProjectRun, json!({ "manager": prog, "script": sub })));
                }
            } else if prog == "bun" && sub == "x" {
                targets.push(Target::new(Kind::PkgExec, json!({ "manager": "bunx", "packages": &rest[..rest.len().min(1)] })));
            }
        } else if let Some(pkgs) = pip_install(&prog, args) {
            targets.push(Target::new(Kind::PipInstall, json!({ "packages": pkgs })));
        } else if matches!(prog.as_str(), "npx" | "pnpx" | "bunx") {
            let p = positional(args);
            targets.push(Target::new(Kind::PkgExec, json!({ "manager": prog, "packages": &p[..p.len().min(1)] })));
        } else if prog == "node" && args.first().is_some_and(|a| !a.starts_with('-')) {
            targets.push(Target::new(Kind::ProjectRun, json!({ "manager": "node", "script": args[0] })));
        } else if AI_CLIS.contains(&prog.as_str()) && args.first().map(String::as_str) == Some("mcp") && args.get(1).map(String::as_str) == Some("add") {
            // claude mcp add [选项] <名字> -- <命令...>，或 claude mcp add --transport http <名字> <网址>
            let (before, after) = match args.iter().position(|a| a == "--") {
                Some(i) => (&args[2..i], args[i + 1..].to_vec()),
                None => (&args[2..], vec![]),
            };
            let pos = positional(before);
            let url = pos.iter().find(|a| a.starts_with("http")).cloned().unwrap_or_default();
            targets.push(Target::new(Kind::McpAdd, json!({ "tool": prog, "name": pos.first().cloned().unwrap_or_default(), "command": after, "url": url })));
        } else if AI_CLIS.contains(&prog.as_str()) && args.is_empty() {
            targets.push(Target::new(Kind::EditorOpen, json!({ "editor": prog, "path": "." })));
        } else if EDITORS.contains(&prog.as_str()) {
            if let Some(i) = args.iter().position(|a| a == "--install-extension") {
                let ext: Vec<&String> = args.get(i + 1).into_iter().collect();
                targets.push(Target::new(Kind::ExtensionInstall, json!({ "editor": prog, "extensions": ext })));
            } else {
                let dirs = positional(args);
                if let Some(d) = dirs.first() {
                    targets.push(Target::new(Kind::EditorOpen, json!({ "editor": prog, "path": d })));
                }
            }
        } else if prog == "open" {
            let files: Vec<&String> = args.iter().filter(|a| INSTALLER_FILE.is_match(a)).collect();
            if !files.is_empty() {
                targets.push(Target::new(Kind::Installer, json!({ "paths": files })));
            }
        } else if prog == "hdiutil" && args.first().map(String::as_str) == Some("attach") {
            let files: Vec<&String> = args[1..].iter().filter(|a| a.to_lowercase().ends_with(".dmg")).collect();
            targets.push(Target::new(Kind::Installer, json!({ "paths": files })));
        } else if prog == "installer" && args.iter().any(|a| a == "-pkg") {
            let i = args.iter().position(|a| a == "-pkg").unwrap();
            let paths: Vec<&String> = args.get(i + 1).into_iter().collect();
            targets.push(Target::new(Kind::Installer, json!({ "paths": paths })));
        } else if prog == "xattr"
            && args.iter().any(|a| matches!(a.as_str(), "-c" | "-cr" | "-rc") || a.contains("quarantine"))
        {
            targets.push(Target::new(Kind::Quarantine, json!({ "args": args })));
        } else if prog == "spctl" && args.iter().any(|a| matches!(a.as_str(), "--master-disable" | "--global-disable" | "--add")) {
            targets.push(Target::new(Kind::Gatekeeper, json!({ "args": args })));
        } else if prog == "osascript" {
            targets.push(Target::new(Kind::Osascript, json!({ "args": args })));
        }
    }
    targets
}

/// pip install x、pip3 install x、python -m pip install x、uv pip install x、uv add x
fn pip_install(prog: &str, args: &[String]) -> Option<Vec<String>> {
    let rest: &[String] = match prog {
        "pip" | "pip3" => args,
        p if p.starts_with("python") => args.strip_prefix(&["-m".to_string(), "pip".to_string()][..])?,
        "uv" => match args.first().map(String::as_str) {
            Some("pip") => &args[1..],
            Some("add") => return Some(positional(&args[1..])),
            _ => return None,
        },
        _ => return None,
    };
    if rest.first().map(String::as_str) != Some("install") {
        return None;
    }
    // -r requirements.txt 这种不是包名
    let mut pkgs = Vec::new();
    let mut skip = false;
    for a in &rest[1..] {
        if skip {
            skip = false;
        } else if matches!(a.as_str(), "-r" | "-c" | "-e" | "--requirement" | "--index-url" | "-i" | "--extra-index-url" | "-t" | "--target") {
            skip = true;
        } else if !a.starts_with('-') && !a.contains('/') {
            pkgs.push(a.clone());
        }
    }
    Some(pkgs)
}

/// 文本里出现的所有 http(s) 网址。
pub fn urls_in(text: &str) -> Vec<String> {
    URL.find_iter(text).map(|m| m.as_str().to_string()).collect()
}
