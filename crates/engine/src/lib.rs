//! Tsuba's detection engine: takes a look on your behalf before unfamiliar code runs for the first time.
//!
//! Flow: detect (spot risky actions in a command) → collect (gather evidence + offline rules) → judge (optional AI review) → Report.
//! The App and the terminal check share it.

/// User-facing text in this crate: `tr!("Found {n} files", n = count)`. Defined before the modules so they can all use it.
macro_rules! tr {
    ($($args:tt)*) => { $crate::tr_in!($crate::i18n_catalog::CATALOG, $($args)*) };
}

pub mod agents;
pub mod collect;
pub mod detect;
pub mod doctor;
pub mod evaluation;
pub mod extension;
pub mod intel;
pub mod i18n;
pub mod judge;
pub mod macos;
pub mod net;
pub mod quarantine;
pub mod rules;
pub mod sandbox;
pub mod scan;
pub mod store;
pub mod trust;

mod i18n_catalog {
    pub static CATALOG: crate::i18n::Catalog = crate::catalog!("../locales");

    #[test]
    fn catalogs_match_sources() {
        let sources = crate::i18n::read_sources(concat!(env!("CARGO_MANIFEST_DIR"), "/src"));
        let sources: Vec<&str> = sources.iter().map(String::as_str).collect();
        if let Err(e) = crate::i18n::check_catalog(&CATALOG, &sources, &[]) {
            panic!("{e}");
        }
    }
}

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

/// SHA-256 of a file (skipped for very large files so the check doesn't stall)
pub fn sha256_file(path: &Path) -> Option<String> {
    use sha2::Digest;
    if path.metadata().ok()?.len() > 300 * 1024 * 1024 {
        return None;
    }
    let mut f = std::fs::File::open(path).ok()?;
    let mut h = sha2::Sha256::new();
    std::io::copy(&mut f, &mut h).ok()?;
    Some(net::hex(&h.finalize()))
}

/// Reads up to `limit` bytes from the start of a file, decoded as lossy UTF-8. Returns an empty string if it can't be read.
pub fn read_limited(path: &Path, limit: usize) -> String {
    let mut buf = Vec::new();
    if let Ok(f) = std::fs::File::open(path) {
        let _ = f.take(limit as u64).read_to_end(&mut buf);
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// Lists regular files under a directory recursively (without following symlinks), at most `max`.
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

/// The verdict of one check.
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

/// Hands the evidence to the AI (if enabled) and merges its verdict with the offline rules' verdict.
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
        return offline_report(tr!("AI review is off. Showing offline rule results"));
    }
    match judge::ask(cfg, evidence) {
        Err(e) => offline_report(tr!("AI review is unavailable ({error}). Showing offline rule results", error = e)),
        Ok(j) => merge_judgement(offline, findings, j, judge::trust(cfg)),
    }
}

/// Merges the model's verdict with the offline rules' verdict. The evidence may be an attack aimed at the AI, and the model may be fooled:
/// a frontier model can't turn an offline "Block" straight into "Allow" (it stays at least "Warn"); local and other models can't
/// lower the offline verdict, and on their own give at most "Warn".
pub fn merge_judgement(offline: Verdict, findings: Vec<Finding>, j: judge::Judgement, trust: judge::Trust) -> Report {
    let mut r = Report {
        verdict: j.verdict,
        summary: j.summary,
        reasons: j.reasons,
        advice: j.advice,
        source: "ai".into(),
        model: j.model,
        findings,
    };
    match trust {
        judge::Trust::Frontier => {
            // With a high-risk offline match the AI can't allow outright; it stays at least a warning
            if r.verdict == Verdict::Allow && offline == Verdict::Block {
                r.verdict = Verdict::Warn;
                r.reasons.push(tr!("Offline rules found a high-risk sign, so this was raised from Allow to Warn. See the evidence below"));
            }
        }
        judge::Trust::Limited => {
            let ai = r.verdict;
            r.verdict = ai.min(Verdict::Warn).max(offline);
            if ai == Verdict::Block && offline < Verdict::Block {
                r.reasons.push(tr!("This model thinks it should be blocked. Local and custom models can give at most a warning, so check the evidence below and decide for yourself"));
            } else if ai < offline {
                r.reasons.push(tr!("This model's verdict can't lower the risk the offline rules found, so the offline result stands"));
            }
        }
    }
    r
}

/// Checks a command that is about to run. `pasted` means the command was pasted into the terminal.
pub fn evaluate_command(cfg: &Config, cmd: &str, cwd: &Path, targets: &[Target], pasted: bool) -> (Value, Report) {
    let (mut evidence, mut findings) = collect::collect(cfg, cmd, cwd, targets);
    intel::virustotal::enrich(&cfg.intel.virustotal_key, &mut evidence, &mut findings);
    if pasted {
        evidence["pasted"] = json!(true);
        if targets.iter().any(|t| matches!(t.kind, Kind::RemoteScript | Kind::ObfuscatedExec | Kind::Osascript)) {
            findings.push(Finding::new(Severity::Low, tr!("This command was pasted into the terminal. A web page telling you to copy a command into the terminal and run it is the classic ClickFix pitch"), ""));
            evidence["findings"] = json!(findings);
        }
    }
    let report = judge_evidence(cfg, &evidence, findings);
    (evidence, report)
}

/// The quick check on paste: looks only at the command itself, with no network and no model, and warns within milliseconds.
/// The full check runs when Return is pressed.
pub fn quick_check(cmd: &str) -> Vec<Finding> {
    let mut findings = rules::scan_text(cmd, &tr!("Pasted text"));
    for t in detect::detect(cmd) {
        let msg = match t.kind {
            Kind::RemoteScript => tr!("Downloads a remote script and runs it directly"),
            Kind::ObfuscatedExec => tr!("Decodes a base64 blob and runs it directly, so you can't see what it really does"),
            Kind::Quarantine => tr!("Removes the macOS quarantine flag to get around Gatekeeper"),
            Kind::Gatekeeper => tr!("Turns off or bypasses Gatekeeper"),
            Kind::Osascript => tr!("Runs AppleScript, which can show a fake password prompt"),
            _ => continue,
        };
        findings.push(Finding::new(Severity::High, msg, ""));
    }
    findings
}

/// Something the user marked as safe whose contents haven't changed is allowed right away.
fn trusted_report() -> Report {
    Report {
        verdict: Verdict::Allow,
        summary: tr!("You marked this as safe earlier, and it hasn't changed"),
        reasons: vec![],
        advice: String::new(),
        source: "trusted".into(),
        model: String::new(),
        findings: vec![],
    }
}

/// The title of a check on a path, shown in the history and passed to the model as the command
fn scan_title(path: &Path) -> String {
    tr!("(Scan) {path}", path = path.display())
}

fn extension_title(dir: &Path) -> String {
    tr!("(Newly installed editor extension) {path}", path = dir.display())
}

/// Checks something on disk: an installer, an extension, a project directory or a single script.
/// Returns (source kind, evidence, report).
pub fn evaluate_path(cfg: &Config, path: &Path) -> (&'static str, Value, Report) {
    if trust::is_trusted_path(path) {
        return ("trusted", json!({ "command": scan_title(path) }), trusted_report());
    }
    evaluate_path_untrusted(cfg, path)
}

/// Like evaluate_path, but ignores the allowlist (for sample set evaluation).
pub fn evaluate_path_untrusted(cfg: &Config, path: &Path) -> (&'static str, Value, Report) {
    let p = path.to_string_lossy().to_lowercase();
    let p = p.trim_end_matches('/');
    let title = scan_title(path);
    let parent = path.parent().unwrap_or(Path::new("/"));
    if [".dmg", ".pkg", ".mpkg", ".app"].iter().any(|e| p.ends_with(e)) {
        let t = Target::new(Kind::Installer, json!({ "paths": [path.to_string_lossy()] }));
        let (ev, r) = evaluate_command(cfg, &title, parent, &[t], false);
        ("installer", ev, r)
    } else if p.ends_with(".vsix") {
        let (info, mut findings) = extension::scan_vsix(path);
        let mut ev = json!({ "command": title, "targets": [{ "kind": "extension", "extension": info, "sha256": sha256_file(path) }], "findings": findings });
        intel::virustotal::enrich(&cfg.intel.virustotal_key, &mut ev, &mut findings);
        ("extension", ev.clone(), judge_evidence(cfg, &ev, findings))
    } else if path.is_dir() && extension::looks_like_extension(path) {
        let (ev, r) = evaluate_extension(cfg, path);
        ("extension", ev, r)
    } else if path.is_dir() && path.join("SKILL.md").is_file() {
        // An AI coding tool skill: the AI follows SKILL.md as instructions and runs the bundled scripts, so check it by the AI tool rules (matches in docs count too)
        let (info, findings) = agents::scan_unit(path);
        let ev = json!({ "command": title, "targets": [{ "kind": "skill", "skill": info }], "findings": findings });
        ("skill", ev.clone(), judge_evidence(cfg, &ev, findings))
    } else if macos::looks_like_volume(path) {
        let label = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        let mut findings = Vec::new();
        let info = macos::inspect_volume(path, &label, &mut findings);
        let ev = json!({ "command": title, "targets": [{ "kind": "installer_volume", "path": path.to_string_lossy(), "volume": info }], "findings": findings });
        ("installer", ev.clone(), judge_evidence(cfg, &ev, findings))
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
        let mut ev = json!({ "command": title, "targets": [{ "kind": "file", "path": path.to_string_lossy(), "content": content, "sha256": sha256_file(path) }], "findings": findings });
        intel::virustotal::enrich(&cfg.intel.virustotal_key, &mut ev, &mut findings);
        ("file", ev.clone(), judge_evidence(cfg, &ev, findings))
    }
}

/// Checks an installed editor extension directory.
pub fn evaluate_extension(cfg: &Config, dir: &Path) -> (Value, Report) {
    if trust::is_trusted_path(dir) {
        return (json!({ "command": extension_title(dir) }), trusted_report());
    }
    let (info, findings) = extension::scan_extension(dir);
    let ev = json!({ "command": extension_title(dir), "targets": [{ "kind": "extension", "extension": info }], "findings": findings });
    let r = judge_evidence(cfg, &ev, findings);
    (ev, r)
}
