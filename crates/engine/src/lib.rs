//! Tsuba 检测引擎：在陌生代码第一次运行之前，先替你看一眼。
//!
//! 流程：detect（识别命令里的危险动作）→ collect（收集证据 + 离线规则）→ judge（可选的 AI 判断）→ Report。
//! App 和终端检查程序共用这一套。

pub mod agents;
pub mod collect;
pub mod detect;
pub mod doctor;
pub mod extension;
pub mod intel;
pub mod judge;
pub mod macos;
pub mod net;
pub mod rules;
pub mod store;

use detect::{Kind, Target};
use rules::{Finding, Severity, Verdict};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::io::Read;
use std::path::{Path, PathBuf};
use store::Config;

pub fn home_dir() -> PathBuf {
    std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/"))
}

/// 读文件开头最多 limit 字节，按 UTF-8 宽松解码。读不了返回空串。
pub fn read_limited(path: &Path, limit: usize) -> String {
    let mut buf = Vec::new();
    if let Ok(f) = std::fs::File::open(path) {
        let _ = f.take(limit as u64).read_to_end(&mut buf);
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// 递归列出目录下的普通文件（不跟随符号链接），最多 max 个。
pub fn walk_files(dir: &Path, max: usize) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_dir() {
                if e.file_name() != ".git" {
                    stack.push(e.path());
                }
            } else if ft.is_file() {
                out.push(e.path());
                if out.len() >= max {
                    return out;
                }
            }
        }
    }
    out
}

/// 一次检查的结论。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Report {
    pub verdict: Verdict,
    pub summary: String,
    #[serde(default)]
    pub reasons: Vec<String>,
    #[serde(default)]
    pub advice: String,
    /// ai / offline
    pub source: String,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub findings: Vec<Finding>,
}

/// 把证据交给 AI（如果启用了），再和离线规则的结论合并。
pub fn judge_evidence(cfg: &Config, evidence: &Value, findings: Vec<Finding>) -> Report {
    let offline = rules::offline_verdict(&findings);
    let offline_report = |summary: String| Report {
        verdict: offline,
        summary,
        reasons: vec![],
        advice: String::new(),
        source: "offline".into(),
        model: String::new(),
        findings: findings.clone(),
    };
    if !judge::available(cfg) {
        return offline_report("未启用 AI 判断，以下为离线规则结果".into());
    }
    match judge::ask(cfg, evidence) {
        Err(e) => offline_report(format!("AI 判断不可用（{e}），以下为离线规则结果")),
        Ok(j) => {
            let mut r = Report {
                verdict: j.verdict,
                summary: j.summary,
                reasons: j.reasons,
                advice: j.advice,
                source: "ai".into(),
                model: j.model,
                findings: findings.clone(),
            };
            match judge::trust(cfg) {
                judge::Trust::Frontier => {
                    // 离线规则有高危命中时，AI 不能直接放行，至少提醒
                    if r.verdict == Verdict::Allow && offline == Verdict::Block {
                        r.verdict = Verdict::Warn;
                        r.reasons.push("离线规则命中高危特征，已从“放行”升级为“提醒”，请看下方证据".into());
                    }
                }
                judge::Trust::Limited => {
                    let ai = r.verdict;
                    r.verdict = ai.min(Verdict::Warn).max(offline);
                    if ai == Verdict::Block && offline < Verdict::Block {
                        r.reasons.push("这个模型认为应该拦截。本地和自定义模型的结论最多只给“提醒”，请看下方证据自己判断".into());
                    } else if ai < offline {
                        r.reasons.push("这个模型的结论不能降低离线规则判出的风险，已按离线规则的结果处理".into());
                    }
                }
            }
            r
        }
    }
}

/// 检查一条即将执行的命令。pasted 表示命令是粘贴进终端的。
pub fn evaluate_command(cfg: &Config, cmd: &str, cwd: &Path, targets: &[Target], pasted: bool) -> (Value, Report) {
    let (mut evidence, mut findings) = collect::collect(cfg, cmd, cwd, targets);
    if pasted {
        evidence["pasted"] = json!(true);
        if targets.iter().any(|t| matches!(t.kind, Kind::RemoteScript | Kind::ObfuscatedExec | Kind::Osascript)) {
            findings.push(Finding::new(Severity::Low, "这条命令是粘贴进终端的。网页让你“复制这条命令到终端运行”是 ClickFix 攻击的典型话术", ""));
            evidence["findings"] = json!(findings);
        }
    }
    let report = judge_evidence(cfg, &evidence, findings);
    (evidence, report)
}

/// 粘贴时的快速检查：只看命令本身，不联网、不调模型，几毫秒内给出提醒。
/// 真正的完整检查在按回车时进行。
pub fn quick_check(cmd: &str) -> Vec<Finding> {
    let mut findings = rules::scan_text(cmd, "粘贴的内容");
    for t in detect::detect(cmd) {
        let msg = match t.kind {
            Kind::RemoteScript => "会下载远程脚本并直接执行",
            Kind::ObfuscatedExec => "会把一段 base64 解码后直接执行，你看不到它真正要做什么",
            Kind::Quarantine => "会删除 macOS 隔离标记，绕过 Gatekeeper 检查",
            Kind::Gatekeeper => "会关闭或绕过 Gatekeeper",
            Kind::Osascript => "会运行 AppleScript，可能弹出伪造的密码框",
            _ => continue,
        };
        findings.push(Finding::new(Severity::High, msg, ""));
    }
    findings
}

/// 检查磁盘上的一个东西：安装包、扩展、项目目录或单个脚本。
/// 返回（来源类别，证据，结论）。
pub fn evaluate_path(cfg: &Config, path: &Path) -> (&'static str, Value, Report) {
    let p = path.to_string_lossy().to_lowercase();
    let p = p.trim_end_matches('/');
    let title = format!("(扫描) {}", path.display());
    let parent = path.parent().unwrap_or(Path::new("/"));
    if [".dmg", ".pkg", ".mpkg", ".app"].iter().any(|e| p.ends_with(e)) {
        let t = Target::new(Kind::Installer, json!({ "paths": [path.to_string_lossy()] }));
        let (ev, r) = evaluate_command(cfg, &title, parent, &[t], false);
        ("installer", ev, r)
    } else if p.ends_with(".vsix") {
        let (info, findings) = extension::scan_vsix(path);
        let ev = json!({ "command": title, "targets": [{ "kind": "extension", "extension": info }], "findings": findings });
        ("extension", ev.clone(), judge_evidence(cfg, &ev, findings))
    } else if path.is_dir() && extension::looks_like_extension(path) {
        let (ev, r) = evaluate_extension(cfg, path);
        ("extension", ev, r)
    } else if path.is_dir() {
        let t = Target::new(Kind::ProjectRun, json!({ "manager": "scan", "script": "" }));
        let (ev, r) = evaluate_command(cfg, &title, path, &[t], false);
        ("project", ev, r)
    } else {
        let text = read_limited(path, 2_000_000);
        let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        let mut findings = rules::scan_text(&text, &name);
        findings.extend(intel::yara::scan_file(path, &name));
        let content: String = text.chars().take(40_000).collect();
        let ev = json!({ "command": title, "targets": [{ "kind": "file", "path": path.to_string_lossy(), "content": content }], "findings": findings });
        ("file", ev.clone(), judge_evidence(cfg, &ev, findings))
    }
}

/// 检查一个已安装的编辑器扩展目录。
pub fn evaluate_extension(cfg: &Config, dir: &Path) -> (Value, Report) {
    let (info, findings) = extension::scan_extension(dir);
    let ev = json!({ "command": format!("(新安装的编辑器扩展) {}", dir.display()), "targets": [{ "kind": "extension", "extension": info }], "findings": findings });
    let r = judge_evidence(cfg, &ev, findings);
    (ev, r)
}
